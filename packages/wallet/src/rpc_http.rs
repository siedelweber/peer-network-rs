//! One bounded HTTP/1.1 response, with no body acquisition on authentication refusal.
use crate::{
    rpc::{RpcLimits, RpcRefusal},
    rpc_secret::Buffer,
};
use std::{
    io::Read as _,
    net::TcpStream,
    time::{Duration, Instant},
};

pub(crate) fn remaining(deadline: Instant) -> Result<Duration, RpcRefusal> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(RpcRefusal::Deadline)
}

pub(crate) fn framing(bytes: &[u8], limits: RpcLimits) -> Result<(u16, usize), RpcRefusal> {
    if bytes.len() > limits.header_bytes {
        return Err(RpcRefusal::HeaderBytes);
    }
    let bytes = bytes.strip_suffix(b"\r\n\r\n").ok_or(RpcRefusal::Http)?;
    let text = std::str::from_utf8(bytes).map_err(|_| RpcRefusal::Http)?;
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or(RpcRefusal::Http)?;
    let status = status.strip_prefix("HTTP/1.1 ").ok_or(RpcRefusal::Http)?;
    if status.len() < 4
        || status.as_bytes()[3] != b' '
        || !status.as_bytes()[..3].iter().all(u8::is_ascii_digit)
        || status.as_bytes()[4..].iter().any(|byte| *byte < 32 || *byte == 127)
    {
        return Err(RpcRefusal::Http);
    }
    let status = status[..3].parse::<u16>().map_err(|_| RpcRefusal::Http)?;
    let mut length = None;
    let mut count = 0;
    for line in lines {
        if line.is_empty() {
            return Err(RpcRefusal::Http);
        }
        count += 1;
        if count > limits.header_count {
            return Err(RpcRefusal::HeaderCount);
        }
        let (name, value) = line.split_once(':').ok_or(RpcRefusal::Http)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || value.bytes().any(|byte| byte < 32 && byte != b'\t' || byte == 127)
        {
            return Err(RpcRefusal::Http);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(RpcRefusal::Http);
            }
            length = Some(value.parse::<usize>().map_err(|_| RpcRefusal::ResponseBytes)?);
        }
        if ["transfer-encoding", "content-encoding", "location"]
            .iter()
            .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
        {
            return Err(RpcRefusal::Http);
        }
    }
    // Every status obeys header syntax and count bounds. Authentication and
    // unadmitted statuses are then refused before consuming any body byte.
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

fn read(stream: &mut TcpStream, bytes: &mut [u8], deadline: Instant) -> Result<usize, RpcRefusal> {
    stream
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|_| RpcRefusal::Transport)?;
    let result = stream.read(bytes).map_err(|error| match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => RpcRefusal::Deadline,
        _ => RpcRefusal::Transport,
    });
    remaining(deadline)?;
    result
}

pub(crate) fn response(
    stream: &mut TcpStream,
    limits: RpcLimits,
    deadline: Instant,
    observed_status: &mut Option<u16>,
) -> Result<(u16, Buffer), RpcRefusal> {
    let mut headers = Buffer::new(limits.header_bytes);
    loop {
        if headers.vacant().is_empty() {
            return Err(RpcRefusal::HeaderBytes);
        }
        if read(stream, &mut headers.vacant()[..1], deadline)? != 1 {
            return Err(RpcRefusal::Http);
        }
        headers.advance(1);
        let bytes = headers.bytes();
        if bytes.ends_with(b"\n") && !bytes.ends_with(b"\r\n") {
            return Err(RpcRefusal::Http);
        }
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let (status, length) = framing(headers.bytes(), limits).inspect_err(|error| {
        if matches!(error, RpcRefusal::Authentication) {
            *observed_status = Some(401);
        }
        if let RpcRefusal::Status(code) = error {
            *observed_status = Some(*code);
        }
    })?;
    *observed_status = Some(status);
    let mut body = Buffer::new(length);
    while !body.vacant().is_empty() {
        let count = read(stream, body.vacant(), deadline)?;
        if count == 0 {
            return Err(RpcRefusal::Http);
        }
        body.advance(count);
    }
    let mut extra = Buffer::new(1);
    if read(stream, extra.vacant(), deadline)? != 0 {
        return Err(RpcRefusal::Http);
    }
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write as _, net::TcpListener, thread};

    /// Claim: Strict HTTP framing accepts the four admitted status classes and refuses malformed lines, missing or duplicate lengths, transfer encodings, compression, redirects and declared header or body excesses.
    /// ´claim:wallet:rpc-http-framing-is-bounded´
    /// ´test:unit:framing-cases´
    #[test]
    fn framing_cases() {
        let limits = RpcLimits::default();
        for status in [200, 400, 404, 500] {
            assert_eq!(
                framing(
                    format!("HTTP/1.1 {status} OK\r\nContent-Length: 4\r\n\r\n").as_bytes(),
                    limits
                ),
                Ok((status, 4))
            );
        }
        for wire in [
            "HTTP/1.1 200 OK\nContent-Length: 4\n\n",
            "HTTP/1.1 200 OK\r\n X: y\r\nContent-Length: 4\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\n",
            "HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: +4\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Encoding: gzip\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nLocation: /\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\nContent-Length: 4\r\n\r\n",
        ] {
            assert_eq!(framing(wire.as_bytes(), limits), Err(RpcRefusal::Http), "{wire:?}");
        }
        for code in [100, 101, 201, 301, 302, 403, 503] {
            assert_eq!(
                framing(format!("HTTP/1.1 {code} no\r\n\r\n").as_bytes(), limits),
                Err(RpcRefusal::Status(code))
            );
        }
        assert_eq!(framing(b"HTTP/1.1 401 no\r\n\r\n", limits), Err(RpcRefusal::Authentication));
        for status in [401, 503] {
            assert_eq!(
                framing(
                    format!("HTTP/1.1 {status} no\r\nX: a\r\nY: b\r\n\r\n").as_bytes(),
                    RpcLimits {
                        header_count: 1,
                        ..limits
                    }
                ),
                Err(RpcRefusal::HeaderCount)
            );
        }
        let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX: y\r\n\r\n";
        assert_eq!(
            framing(
                valid,
                RpcLimits {
                    header_bytes: valid.len() - 1,
                    ..limits
                }
            ),
            Err(RpcRefusal::HeaderBytes)
        );
        assert_eq!(
            framing(
                valid,
                RpcLimits {
                    header_count: 1,
                    ..limits
                }
            ),
            Err(RpcRefusal::HeaderCount)
        );
        assert_eq!(
            framing(
                valid,
                RpcLimits {
                    response_bytes: 3,
                    ..limits
                }
            ),
            Err(RpcRefusal::ResponseBytes)
        );
    }

    fn exchange(bytes: &'static [u8], drip: bool) -> Result<(u16, Buffer), RpcRefusal> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in bytes {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                if drip {
                    thread::sleep(Duration::from_millis(25));
                }
            }
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let result = response(
            &mut stream,
            RpcLimits::default(),
            Instant::now() + Duration::from_millis(100),
            &mut None,
        );
        drop(stream);
        server.join().unwrap();
        result
    }

    /// Claim: Response acquisition refuses truncation and trailing bytes, closes a 401 before its body, and slow progress cannot renew the one monotonic exchange deadline.
    /// ´claim:wallet:rpc-http-acquisition-is-bounded´
    /// ´test:unit:acquisition-cases´
    #[test]
    fn acquisition_cases() {
        assert_eq!(
            exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnull", false)
                .unwrap()
                .1
                .bytes(),
            b"null"
        );
        for bytes in [
            b"HTTP/1.1 200 OK\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnul",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnullx",
        ] {
            assert!(matches!(exchange(bytes, false), Err(RpcRefusal::Http)));
        }
        assert!(matches!(
            exchange(b"HTTP/1.1 401 no\r\nContent-Length: 999999999\r\n\r\n", false),
            Err(RpcRefusal::Authentication)
        ));
        assert!(matches!(
            exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnull", true),
            Err(RpcRefusal::Deadline)
        ));
    }
}
