//! One bounded HTTP/1.1 exchange on a pn-wallet-owned connection through the shared HTTP stack.
//!
//! hyper parses the response; the connection adapter keeps the raw-wire predicates a parser
//! does not keep: CRLF-only lines without folds, the head's byte and field bounds on every
//! status, an exact HTTP/1.1 status line, refused interim responses and no body byte read
//! before the head is admitted.
use crate::rpc::{RpcLimits, RpcRefusal};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::{
    Request, Response, Version,
    body::{Bytes, Incoming},
    client::conn::http1,
    header,
};
use hyper_util::rt::TokioIo;
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io,
    pin::{Pin, pin},
    rc::Rc,
    task::{Context, Poll, Waker, ready},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) fn remaining(deadline: Instant) -> Result<Duration, RpcRefusal> {
    let now = Instant::now();
    #[cfg(test)]
    let now = now + clock::SKEW.with(std::cell::Cell::get);
    deadline
        .checked_duration_since(now)
        .filter(|duration| !duration.is_zero())
        .ok_or(RpcRefusal::Deadline)
}

/// A controlled clock for deadline regressions: a test names one synchronous stage, and when
/// the read reaches it this thread's view of the time jumps past any admitted deadline.
#[cfg(test)]
pub(crate) mod clock {
    use std::{cell::Cell, time::Duration};

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub(crate) enum Stage {
        /// After cookie acquisition returns, whatever its outcome.
        Cookie,
        /// After the HTTP exchange returns a response, before JSON decoding.
        Response,
        /// After JSON decoding and the envelope, on success or refusal, before the closing check.
        Decoded,
        /// At the start of typed projection.
        Projection,
    }

    thread_local! {
        pub(crate) static SKEW: Cell<Duration> = const { Cell::new(Duration::ZERO) };
        static PAUSE: Cell<Option<Stage>> = const { Cell::new(None) };
    }

    /// Expire this thread's deadline at `stage`, or with `None`, run on the real clock.
    pub(crate) fn expire_at(stage: Option<Stage>) {
        PAUSE.with(|pause| pause.set(stage));
        SKEW.with(|skew| skew.set(Duration::ZERO));
    }

    /// Expire every deadline on this thread now.
    pub(crate) fn expire_now() {
        SKEW.with(|skew| skew.set(Duration::from_secs(11)));
    }

    pub(crate) fn reach(stage: Stage) {
        if PAUSE.with(Cell::get) == Some(stage) {
            expire_now();
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Head,
    Held,
    Body,
}

/// Raw-wire state of one exchange, shared by the connection adapter and the exchange. The
/// received head is public service data under (´[ROOT-amend:devnet:rpc-bounds]´), held as
/// ordinary bytes within the head bound.
pub(crate) struct Watch {
    limits: RpcLimits,
    refusal: Option<RpcRefusal>,
    head: Vec<u8>,
    line: usize,
    fields: usize,
    status: u16,
    phase: Phase,
    waker: Option<Waker>,
    written: usize,
}

impl Watch {
    pub(crate) fn new(limits: RpcLimits) -> Self {
        Self {
            limits,
            refusal: None,
            head: Vec::with_capacity(limits.header_bytes),
            line: 0,
            fields: 0,
            status: 0,
            phase: Phase::Head,
            waker: None,
            written: 0,
        }
    }

    /// Bytes that cannot pass the head terminator, whatever they are.
    fn want(&self) -> usize {
        let matched = [b"\r\n\r".as_slice(), b"\r\n", b"\r"]
            .iter()
            .find(|suffix| self.head.ends_with(suffix))
            .map_or(0, |suffix| suffix.len());
        4 - matched
    }

    /// Admit one head byte; returns whether the head is complete.
    pub(crate) fn admit(&mut self, byte: u8) -> Result<bool, RpcRefusal> {
        if self.head.len() >= self.limits.header_bytes {
            return Err(RpcRefusal::HeaderBytes);
        }
        let previous = self.head.last().copied();
        let start = self.head.len() == self.line;
        self.head.push(byte);
        if (byte == b'\n') != (previous == Some(b'\r')) {
            return Err(RpcRefusal::Http);
        }
        if start && self.line > 0 && byte != b'\r' {
            if byte == b' ' || byte == b'\t' {
                return Err(RpcRefusal::Http);
            }
            self.fields += 1;
            if self.fields > self.limits.header_count {
                return Err(RpcRefusal::HeaderCount);
            }
        }
        // A full head buffer that does not end here cannot finish within the bound; refusing
        // now keeps the cause ahead of the parser's own buffer ceiling.
        let full = self.head.len() == self.limits.header_bytes;
        if byte != b'\n' {
            return if full { Err(RpcRefusal::HeaderBytes) } else { Ok(false) };
        }
        let end = self.head.len();
        let line = &self.head[self.line..end - 2];
        std::str::from_utf8(line).map_err(|_| RpcRefusal::Http)?;
        if self.line == 0 {
            self.status = status(line)?;
        } else if overflowing_length(line) {
            // The parser would refuse this as malformed; the declared length is a
            // resource excess, so it keeps the length refusal, before any status.
            return Err(RpcRefusal::ResponseBytes);
        }
        let complete = line.is_empty();
        self.line = end;
        if complete && (100..200).contains(&self.status) {
            return Err(RpcRefusal::Status(self.status));
        }
        if full && !complete {
            return Err(RpcRefusal::HeaderBytes);
        }
        Ok(complete)
    }

    fn release(&mut self) {
        self.phase = Phase::Body;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// A digit-only Content-Length field whose value does not fit the platform length.
fn overflowing_length(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return false;
    };
    let value = line[colon + 1..].trim_ascii();
    line[..colon].eq_ignore_ascii_case(b"content-length")
        && !value.is_empty()
        && value.iter().all(u8::is_ascii_digit)
        && value
            .iter()
            .try_fold(0_usize, |total, digit| {
                total.checked_mul(10)?.checked_add(usize::from(digit - b'0'))
            })
            .is_none()
}

/// An exact HTTP/1.1 status line: three digits, a space and a reason without controls.
fn status(line: &[u8]) -> Result<u16, RpcRefusal> {
    let rest = line.strip_prefix(b"HTTP/1.1 ").ok_or(RpcRefusal::Http)?;
    if rest.len() < 4
        || rest[3] != b' '
        || !rest[..3].iter().all(u8::is_ascii_digit)
        || rest[4..].iter().any(|byte| *byte < 32 || *byte == 127)
    {
        return Err(RpcRefusal::Http);
    }
    Ok(rest[..3].iter().fold(0, |code, digit| code * 10 + u16::from(digit - b'0')))
}

/// The connected stream as hyper sees it: head bytes pass only through the watch.
struct Wire {
    stream: tokio::net::TcpStream,
    watch: Rc<RefCell<Watch>>,
}

fn refused() -> io::Error {
    io::Error::other("wire refusal")
}

impl AsyncRead for Wire {
    /// Justified: Connection plumbing inside the instrumented RPC read; per-read observation would record transport fragments rather than public outcomes.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut watch = this.watch.borrow_mut();
        if watch.refusal.is_some() {
            return Poll::Ready(Err(refused()));
        }
        match watch.phase {
            Phase::Body => Pin::new(&mut this.stream).poll_read(cx, buf),
            Phase::Held => {
                watch.waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Phase::Head if buf.remaining() == 0 => Poll::Ready(Ok(())),
            Phase::Head => {
                let mut bytes = [0; 4];
                let want = watch.want().min(buf.remaining());
                let mut head = ReadBuf::new(&mut bytes[..want]);
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut head))?;
                for byte in head.filled() {
                    match watch.admit(*byte) {
                        Ok(false) => {}
                        Ok(true) => watch.phase = Phase::Held,
                        Err(refusal) => {
                            watch.refusal = Some(refusal);
                            return Poll::Ready(Err(refused()));
                        }
                    }
                }
                buf.put_slice(head.filled());
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for Wire {
    /// Justified: Connection plumbing inside the instrumented RPC read; the request byte bound is accounted here without observing request bytes.
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut watch = this.watch.borrow_mut();
        if watch.written + buf.len() > watch.limits.request_bytes {
            watch.refusal = Some(RpcRefusal::RequestBytes);
            return Poll::Ready(Err(refused()));
        }
        let count = ready!(Pin::new(&mut this.stream).poll_write(cx, buf))?;
        watch.written += count;
        Poll::Ready(Ok(count))
    }

    /// Justified: Connection plumbing inside the instrumented RPC read; flushing has no public payload.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    /// Justified: Connection plumbing inside the instrumented RPC read; shutdown has no public payload.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

type Connection = http1::Connection<TokioIo<Wire>, Full<Bytes>>;
type Reply = Pin<Box<dyn Future<Output = Result<Response<Incoming>, hyper::Error>>>>;

/// The one connection as a tower service, so timeout and concurrency limit compose around it.
struct Exchange(http1::SendRequest<Full<Bytes>>);

impl tower::Service<Request<Full<Bytes>>> for Exchange {
    type Response = Response<Incoming>;
    type Error = hyper::Error;
    type Future = Reply;

    /// Justified: Service plumbing inside the instrumented RPC read; readiness has no public payload.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), hyper::Error>> {
        self.0.poll_ready(cx)
    }

    /// Justified: Service plumbing inside the instrumented RPC read, which records the public outcome.
    fn call(&mut self, request: Request<Full<Bytes>>) -> Reply {
        Box::pin(self.0.send_request(request))
    }
}

/// A refusal recorded at the wire wins; otherwise hyper's error maps to a typed cause.
fn cause(watch: &RefCell<Watch>, error: &(dyn std::error::Error + 'static)) -> RpcRefusal {
    if let Some(refusal) = watch.borrow_mut().refusal.take() {
        return refusal;
    }
    if error.is::<tower::timeout::error::Elapsed>() {
        return RpcRefusal::Deadline;
    }
    let mut source = Some(error);
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<hyper::Error>()
            && (error.is_parse() || error.is_incomplete_message())
        {
            return RpcRefusal::Http;
        }
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return if error.kind() == io::ErrorKind::UnexpectedEof {
                RpcRefusal::Http
            } else {
                RpcRefusal::Transport
            };
        }
        source = error.source();
    }
    RpcRefusal::Http
}

/// Poll the connection while the exchange waits on one of its futures.
async fn drive<T>(connection: &mut Connection, done: &mut bool, future: impl Future<Output = T>) -> Result<T, hyper::Error> {
    let mut future = pin!(future);
    poll_fn(|cx| {
        if let Poll::Ready(output) = future.as_mut().poll(cx) {
            return Poll::Ready(Ok(output));
        }
        if !*done {
            match connection.poll_without_shutdown(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => *done = true,
                Poll::Pending => {}
            }
        }
        Poll::Pending
    })
    .await
}

/// Admit the parsed head: framing fields, then status, then the declared length.
fn admit_head<B>(response: &Response<B>, limits: RpcLimits) -> Result<(u16, usize), RpcRefusal> {
    let headers = response.headers();
    if response.version() != Version::HTTP_11
        || [header::TRANSFER_ENCODING, header::CONTENT_ENCODING, header::LOCATION]
            .iter()
            .any(|name| headers.contains_key(name))
    {
        return Err(RpcRefusal::Http);
    }
    let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
    let length = lengths.next().map(header::HeaderValue::as_bytes);
    if lengths.next().is_some() || length.is_some_and(|value| value.is_empty() || !value.iter().all(u8::is_ascii_digit)) {
        return Err(RpcRefusal::Http);
    }
    let length = length
        .map(|value| {
            value.iter().try_fold(0_usize, |total, digit| {
                total.checked_mul(10)?.checked_add(usize::from(digit - b'0'))
            })
        })
        .map(|value| value.ok_or(RpcRefusal::ResponseBytes))
        .transpose()?;
    let status = response.status().as_u16();
    if status == 401 {
        return Err(RpcRefusal::Authentication);
    }
    if !matches!(status, 200 | 400 | 404 | 500) {
        return Err(RpcRefusal::Status(status));
    }
    let length = length.ok_or(RpcRefusal::Http)?;
    if length > limits.response_bytes {
        return Err(RpcRefusal::ResponseBytes);
    }
    Ok((status, length))
}

async fn run(
    stream: std::net::TcpStream,
    request: Request<Full<Bytes>>,
    limits: RpcLimits,
    deadline: Instant,
    observed_status: &mut Option<u16>,
) -> Result<(u16, Vec<u8>), RpcRefusal> {
    stream.set_nonblocking(true).map_err(|_| RpcRefusal::Transport)?;
    let stream = tokio::net::TcpStream::from_std(stream).map_err(|_| RpcRefusal::Transport)?;
    let watch = Rc::new(RefCell::new(Watch::new(limits)));
    let wire = Wire {
        stream,
        watch: Rc::clone(&watch),
    };
    let (sender, mut connection) = http1::Builder::new()
        .max_headers(limits.header_count)
        .max_header_size(limits.header_bytes)
        .max_buf_size(8192)
        .handshake(TokioIo::new(wire))
        .await
        .map_err(|error| cause(&watch, &error))?;
    let mut done = false;
    let mut service =
        tower::limit::ConcurrencyLimit::new(tower::timeout::Timeout::new(Exchange(sender), remaining(deadline)?), 1);
    drive(
        &mut connection,
        &mut done,
        poll_fn(|cx| tower::Service::poll_ready(&mut service, cx)),
    )
    .await
    .map_err(|error| cause(&watch, &error))?
    .map_err(|error| cause(&watch, &*error))?;
    let reply = tower::Service::call(&mut service, request);
    let response = drive(&mut connection, &mut done, reply)
        .await
        .map_err(|error| cause(&watch, &error))?
        .map_err(|error| cause(&watch, &*error))?;
    let (status, length) = admit_head(&response, limits).inspect_err(|error| match error {
        RpcRefusal::Authentication => *observed_status = Some(401),
        RpcRefusal::Status(code) => *observed_status = Some(*code),
        _ => {}
    })?;
    *observed_status = Some(status);
    watch.borrow_mut().release();
    let mut body = Limited::new(response.into_body(), length);
    // The body is public service data under (´[ROOT-amend:devnet:rpc-bounds]´), collected as
    // ordinary bytes within its declared, admitted length.
    let mut buffer = Vec::with_capacity(length);
    while let Some(frame) = drive(&mut connection, &mut done, body.frame())
        .await
        .map_err(|error| cause(&watch, &error))?
    {
        let frame = frame.map_err(|error| cause(&watch, &*error))?;
        if let Ok(data) = frame.into_data() {
            if data.len() > length - buffer.len() {
                return Err(RpcRefusal::ResponseBytes);
            }
            buffer.extend_from_slice(&data);
        }
    }
    drop(body);
    drop(service);
    if buffer.len() != length {
        return Err(RpcRefusal::Http);
    }
    let parts = connection.into_parts();
    if !parts.read_buf.is_empty() {
        return Err(RpcRefusal::Http);
    }
    let mut wire = parts.io.into_inner();
    let extra = poll_fn(|cx| {
        let mut byte = [0; 1];
        let mut read = ReadBuf::new(&mut byte);
        ready!(Pin::new(&mut wire.stream).poll_read(cx, &mut read))?;
        Poll::Ready(Ok::<_, io::Error>(read.filled().len()))
    })
    .await
    .map_err(|_| RpcRefusal::Transport)?;
    if extra != 0 {
        return Err(RpcRefusal::Http);
    }
    Ok((status, buffer))
}

/// One exchange on a wallet-owned thread and current-thread runtime, so a caller inside a
/// Tokio context never nests a runtime. The connection future is driven with the request and
/// never spawned; the one deadline encloses request write, head, whole body and the trailing
/// check, and the scoped thread joins after the runtime drops, so neither outlives the call.
pub(crate) fn exchange(
    stream: std::net::TcpStream,
    request: Request<Full<Bytes>>,
    limits: RpcLimits,
    deadline: Instant,
    observed_status: &mut Option<u16>,
) -> Result<(u16, Vec<u8>), RpcRefusal> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("pn-wallet-rpc".into())
            .spawn_scoped(scope, move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .map_err(|_| RpcRefusal::Transport)?;
                let result = runtime.block_on(async {
                    tokio::time::timeout_at(
                        tokio::time::Instant::from_std(deadline),
                        run(stream, request, limits, deadline, observed_status),
                    )
                    .await
                    .unwrap_or(Err(RpcRefusal::Deadline))
                });
                drop(runtime);
                result
            })
            .map_err(|_| RpcRefusal::Transport)?
            .join()
            .unwrap_or(Err(RpcRefusal::Transport))
    })
}

/// The status of a complete raw head, or the wire refusal it meets first.
#[cfg(test)]
pub(crate) fn head(wire: &[u8], limits: RpcLimits) -> Result<u16, RpcRefusal> {
    let mut watch = Watch::new(limits);
    for byte in wire {
        if watch.admit(*byte)? {
            return Ok(watch.status);
        }
    }
    Err(RpcRefusal::Http)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    fn exchange_bytes(bytes: &'static [u8], drip: bool) -> Result<(u16, Vec<u8>), RpcRefusal> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let count = stream.read(&mut request).unwrap_or(0);
            assert!(count <= request.len());
            for byte in bytes {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                if drip {
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        });
        let stream = std::net::TcpStream::connect(address).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header(header::HOST, "localhost")
            .header(header::CONNECTION, "close")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
        let result = exchange(
            stream,
            request,
            RpcLimits::default(),
            Instant::now() + Duration::from_millis(100),
            &mut None,
        );
        server.join().unwrap();
        result
    }

    /// Claim: Response acquisition refuses truncation and trailing bytes, closes a 401 before its body, and slow progress cannot renew the one monotonic exchange deadline.
    /// ´claim:wallet:rpc-http-acquisition-is-bounded´
    /// ´test:unit:acquisition-cases´
    #[test]
    fn acquisition_cases() {
        assert_eq!(
            exchange_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnull", false)
                .unwrap()
                .1,
            b"null"
        );
        for bytes in [
            b"HTTP/1.1 200 OK\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnul",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnullx",
        ] {
            assert!(matches!(exchange_bytes(bytes, false), Err(RpcRefusal::Http)));
        }
        assert!(matches!(
            exchange_bytes(b"HTTP/1.1 401 no\r\nContent-Length: 999999999\r\n\r\n", false),
            Err(RpcRefusal::Authentication)
        ));
        assert!(matches!(
            exchange_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnull", true),
            Err(RpcRefusal::Deadline)
        ));
    }

    /// Claim: Strict HTTP framing accepts the four admitted status classes and refuses malformed lines, missing or duplicate lengths, transfer encodings, compression, redirects and declared header or body excesses.
    /// ´claim:wallet:rpc-http-framing-is-bounded´
    /// ´test:unit:framing-cases´
    #[test]
    fn framing_cases() {
        let limits = RpcLimits::default();
        for status in [200, 400, 401, 404, 500, 503] {
            assert_eq!(
                head(
                    format!("HTTP/1.1 {status} OK\r\nContent-Length: 4\r\n\r\n").as_bytes(),
                    limits
                ),
                Ok(status)
            );
        }
        for wire in [
            "HTTP/1.1 200 OK\nContent-Length: 4\n\n",
            "HTTP/1.1 200 OK\r\n X: y\r\nContent-Length: 4\r\n\r\n",
            "HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n",
            "HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\n",
            "HTTP/1.1 20 OK\r\n\r\n",
            "HTTP/1.1 200\r\n\r\n",
        ] {
            assert_eq!(head(wire.as_bytes(), limits), Err(RpcRefusal::Http), "{wire:?}");
        }
        assert_eq!(head(b"HTTP/1.1 200 OK\r\nX: \xff\r\n\r\n", limits), Err(RpcRefusal::Http));
        for status in [200, 401] {
            assert_eq!(
                head(
                    format!("HTTP/1.1 {status} no\r\ncontent-length: 99999999999999999999999\r\n\r\n").as_bytes(),
                    limits
                ),
                Err(RpcRefusal::ResponseBytes)
            );
        }
        for code in [100, 101, 103] {
            assert_eq!(
                head(format!("HTTP/1.1 {code} no\r\n\r\n").as_bytes(), limits),
                Err(RpcRefusal::Status(code))
            );
        }
        let few = RpcLimits {
            header_count: 1,
            ..limits
        };
        for status in [100, 401, 503] {
            assert_eq!(
                head(format!("HTTP/1.1 {status} no\r\nX: a\r\nY: b\r\n\r\n").as_bytes(), few),
                Err(RpcRefusal::HeaderCount)
            );
        }
        let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX: y\r\n\r\n";
        assert_eq!(
            head(
                valid,
                RpcLimits {
                    header_bytes: valid.len(),
                    ..limits
                }
            ),
            Ok(200)
        );
        assert_eq!(
            head(
                valid,
                RpcLimits {
                    header_bytes: valid.len() - 1,
                    ..limits
                }
            ),
            Err(RpcRefusal::HeaderBytes)
        );
        let mut watch = Watch::new(limits);
        assert_eq!(watch.want(), 4);
        for byte in b"HTTP/1.1 200 OK\r\n\r" {
            watch.admit(*byte).unwrap();
        }
        assert_eq!(watch.want(), 1);
        admission_cases(limits);
    }

    /// The parsed-head admission: framing fields, then status, then the declared length.
    fn admission_cases(limits: RpcLimits) {
        let parsed = |status: u16, fields: &[(&str, &str)]| {
            let mut builder = Response::builder().status(status);
            for (name, value) in fields {
                builder = builder.header(*name, *value);
            }
            admit_head(&builder.body(()).unwrap(), limits)
        };
        assert_eq!(parsed(200, &[("content-length", "4")]), Ok((200, 4)));
        let refused: [&[(&str, &str)]; 7] = [
            &[],
            &[("content-length", "4"), ("content-length", "4")],
            &[("content-length", "4, 4")],
            &[("content-length", "+4")],
            &[("content-length", "4"), ("transfer-encoding", "chunked")],
            &[("content-length", "4"), ("content-encoding", "gzip")],
            &[("content-length", "4"), ("location", "/")],
        ];
        for fields in refused {
            assert_eq!(parsed(200, fields), Err(RpcRefusal::Http), "{fields:?}");
        }
        assert_eq!(
            parsed(401, &[("content-length", "999999999")]),
            Err(RpcRefusal::Authentication)
        );
        assert_eq!(parsed(503, &[]), Err(RpcRefusal::Status(503)));
        assert_eq!(parsed(302, &[("location", "/")]), Err(RpcRefusal::Http));
        assert_eq!(parsed(200, &[("content-length", "8001025")]), Err(RpcRefusal::ResponseBytes));
        assert_eq!(
            parsed(200, &[("content-length", "99999999999999999999999")]),
            Err(RpcRefusal::ResponseBytes)
        );
    }
}
