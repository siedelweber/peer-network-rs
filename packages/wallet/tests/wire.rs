//! Wire compatibility fixtures: a scripted local server answers each case with exact bytes,
//! driven only through the public reader interface, so one case list witnesses any transport.
use pn_wallet::{Limits, Provisioning, Read, ReadResult, RpcClient, RpcConfig, RpcLimits, RpcLink, RpcRefusal};
use secrecy::{SecretBox, SecretString};
use std::{
    fmt::Write as _,
    fs::File,
    io::{ErrorKind, Read as _, Write as _},
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::PathBuf,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

const GENESIS: [u8; 32] = [7; 32];
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn decoder() -> Limits {
    Limits {
        bytes: 4_000_000,
        items: 4096,
        script: 10_000,
        witness: 65_536,
        allocation: 134_217_728,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}

/// The Basic credential the server expects, computed independently of the client.
fn basic(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::new();
    for part in bytes.chunks(3) {
        let a = part[0];
        let b = part.get(1).copied().unwrap_or(0);
        let c = part.get(2).copied().unwrap_or(0);
        text.push(char::from(DIGITS[usize::from(a >> 2)]));
        text.push(char::from(DIGITS[usize::from(((a & 3) << 4) | (b >> 4))]));
        text.push(if part.len() > 1 {
            char::from(DIGITS[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        text.push(if part.len() > 2 {
            char::from(DIGITS[usize::from(c & 63)])
        } else {
            '='
        });
    }
    text
}

/// A private cookie directory accepted by descriptor acquisition, removed on drop.
struct Cookie {
    directory: PathBuf,
    secret: String,
}

impl Cookie {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "pn-wallet-wire-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let secret = format!("__cookie__:{}", "5e".repeat(32));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("cookie"))
            .unwrap()
            .write_all(secret.as_bytes())
            .unwrap();
        Self { directory, secret }
    }

    fn config(&self, port: u16) -> RpcConfig {
        RpcConfig::new(
            RpcLink::HostSecured,
            SecretString::from("127.0.0.1"),
            SecretBox::new(Box::new(port)),
            File::open(&self.directory).unwrap(),
            SecretString::from("cookie"),
            SecretBox::new(Box::new(std::fs::metadata(&self.directory).unwrap().uid())),
        )
    }
}

impl Drop for Cookie {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

/// How the client left the case connection, seen from the server after its last byte.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Peer {
    /// The client consumed everything and closed.
    Eof,
    /// The client closed with unread bytes, so the kernel reset the connection.
    Reset,
    /// The client neither closed nor reset within the observation window.
    Open,
}

struct Exchange {
    requests: Vec<Vec<u8>>,
    peer: Peer,
}

fn field(request: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(request);
    let head = text.split("\r\n\r\n").next()?;
    head.split("\r\n").skip(1).find_map(|line| {
        line.split_once(':')
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_owned())
    })
}

fn request(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut byte = [0; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            return bytes;
        }
        bytes.push(byte[0]);
    }
    let length = field(&bytes, "content-length").map_or(0, |value| value.parse().unwrap());
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    bytes.extend(body);
    bytes
}

fn observe(stream: &mut TcpStream) -> Peer {
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut sink = [0; 256];
    loop {
        match stream.read(&mut sink) {
            Ok(0) => return Peer::Eof,
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::ConnectionReset => return Peer::Reset,
            Err(_) => return Peer::Open,
        }
    }
}

fn accept(listener: &TcpListener) -> Option<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                return Some(stream);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
            Err(error) => panic!("accept failed: {error}"),
        }
    }
    None
}

/// Answer the two provisioning reads, then the case connection with its exact segments.
fn serve(listener: TcpListener, genesis: Vec<Vec<u8>>, wire: Vec<(u64, Vec<u8>)>, hold: bool) -> thread::JoinHandle<Exchange> {
    thread::spawn(move || {
        let mut requests = Vec::new();
        for answer in genesis {
            let Some(mut stream) = accept(&listener) else {
                return Exchange {
                    requests,
                    peer: Peer::Open,
                };
            };
            requests.push(request(&mut stream));
            stream.write_all(&answer).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            observe(&mut stream);
        }
        let Some(mut stream) = accept(&listener) else {
            return Exchange {
                requests,
                peer: Peer::Open,
            };
        };
        requests.push(request(&mut stream));
        for (delay, bytes) in wire {
            thread::sleep(Duration::from_millis(delay));
            if stream.write_all(&bytes).is_err() {
                break;
            }
        }
        if !hold {
            stream.shutdown(Shutdown::Write).ok();
        }
        Exchange {
            requests,
            peer: observe(&mut stream),
        }
    })
}

fn body(id: u64, member: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},{member}}}")
}

fn response(status: &str, headers: &str, body: &str) -> String {
    format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\n\r\n{body}", body.len())
}

fn valid() -> String {
    response("200 OK", "", &body(3, "\"result\":7"))
}

fn headers(count: usize) -> String {
    let mut text = String::new();
    for index in 0..count {
        text.push_str("X-");
        text.push_str(&index.to_string());
        text.push_str(": v\r\n");
    }
    text
}

fn bytes(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

struct Case {
    name: &'static str,
    wire: Vec<(u64, Vec<u8>)>,
    hold: bool,
    limits: RpcLimits,
    expected: Result<u64, RpcRefusal>,
    peer: Option<Peer>,
}

fn case(name: &'static str, wire: impl Into<Vec<u8>>, expected: Result<u64, RpcRefusal>) -> Case {
    Case {
        name,
        wire: vec![(0, wire.into())],
        hold: false,
        limits: RpcLimits::default(),
        expected,
        peer: None,
    }
}

fn remote(code: i64) -> RpcRefusal {
    RpcRefusal::Remote {
        code,
        message: "m".into(),
        data: None,
    }
}

fn status_cases() -> Vec<Case> {
    let error = body(3, "\"error\":{\"code\":-8,\"message\":\"m\"}");
    vec![
        Case {
            peer: Some(Peer::Eof),
            ..case("200 result", valid(), Ok(7))
        },
        case("200 error", response("200 OK", "", &error), Err(remote(-8))),
        case("400 error", response("400 Bad Request", "", &error), Err(remote(-8))),
        case("404 error", response("404 Not Found", "", &error), Err(remote(-8))),
        case(
            "500 error",
            response("500 Internal Server Error", "", &error),
            Err(remote(-8)),
        ),
        case(
            "500 result",
            response("500 Internal Server Error", "", &body(3, "\"result\":7")),
            Err(RpcRefusal::Status(500)),
        ),
        case(
            "interim 100 before 200",
            format!("HTTP/1.1 100 Continue\r\n\r\n{}", valid()),
            Err(RpcRefusal::Status(100)),
        ),
        case(
            "interim 103 before 200",
            format!("HTTP/1.1 103 Early Hints\r\nLink: x\r\n\r\n{}", valid()),
            Err(RpcRefusal::Status(103)),
        ),
        case(
            "101 switching",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\n",
            Err(RpcRefusal::Status(101)),
        ),
        case(
            "interim with 65 fields",
            format!("HTTP/1.1 100 Continue\r\n{}\r\n{}", headers(65), valid()),
            Err(RpcRefusal::HeaderCount),
        ),
    ]
}

fn refused_cases() -> Vec<Case> {
    let body401 = "private-sentinel-body-".repeat(3);
    vec![
        Case {
            peer: Some(Peer::Reset),
            ..case(
                "401 read-ahead across the header boundary",
                format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\n\r\n{body401}",
                    body401.len()
                ),
                Err(RpcRefusal::Authentication),
            )
        },
        Case {
            peer: Some(Peer::Reset),
            ..case(
                "401 with an excessive declared body",
                format!("HTTP/1.1 401 Unauthorized\r\nContent-Length: 999999999\r\n\r\n{body401}"),
                Err(RpcRefusal::Authentication),
            )
        },
        case(
            "401 with 65 fields",
            format!("HTTP/1.1 401 Unauthorized\r\n{}Content-Length: 0\r\n\r\n", headers(65)),
            Err(RpcRefusal::HeaderCount),
        ),
        Case {
            peer: Some(Peer::Reset),
            ..case(
                "503 before its body",
                response("503 Service Unavailable", "", &body401),
                Err(RpcRefusal::Status(503)),
            )
        },
        case(
            "503 with 65 fields",
            response("503 Service Unavailable", &headers(65), ""),
            Err(RpcRefusal::HeaderCount),
        ),
        case(
            "503 with a malformed field",
            "HTTP/1.1 503 Service Unavailable\r\nbad field\r\nContent-Length: 0\r\n\r\n",
            Err(RpcRefusal::Http),
        ),
        case("204", "HTTP/1.1 204 No Content\r\n\r\n", Err(RpcRefusal::Status(204))),
        case(
            "201",
            response("201 Created", "", &body(3, "\"result\":7")),
            Err(RpcRefusal::Status(201)),
        ),
        case(
            "301 without location",
            response("301 Moved", "", ""),
            Err(RpcRefusal::Status(301)),
        ),
        case(
            "302 redirect",
            response("302 Found", "Location: /x\r\n", ""),
            Err(RpcRefusal::Http),
        ),
        case(
            "200 with location",
            response("200 OK", "Location: /x\r\n", &body(3, "\"result\":7")),
            Err(RpcRefusal::Http),
        ),
        case("403", response("403 Forbidden", "", ""), Err(RpcRefusal::Status(403))),
    ]
}

fn line_cases() -> Vec<Case> {
    let json = body(3, "\"result\":7");
    let length = format!("Content-Length: {}", json.len());
    let http = || Err(RpcRefusal::Http);
    vec![
        case("bare LF everywhere", format!("HTTP/1.1 200 OK\n{length}\n\n{json}"), http()),
        case(
            "bare LF in one field",
            format!("HTTP/1.1 200 OK\r\nX: y\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "bare LF terminator",
            format!("HTTP/1.1 200 OK\r\n{length}\r\n\n{json}"),
            http(),
        ),
        case(
            "lone CR in a value",
            format!("HTTP/1.1 200 OK\r\nX: a\rb\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "folded field",
            format!("HTTP/1.1 200 OK\r\nX: a\r\n b\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "tab-folded field",
            format!("HTTP/1.1 200 OK\r\nX: a\r\n\tb\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case("HTTP/1.0", format!("HTTP/1.0 200 OK\r\n{length}\r\n\r\n{json}"), http()),
        case(
            "lowercase version",
            format!("http/1.1 200 OK\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "two-digit status",
            format!("HTTP/1.1 20 OK\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "nondigit status",
            format!("HTTP/1.1 2x0 OK\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "status without reason separator",
            format!("HTTP/1.1 200\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
    ]
}

fn field_cases() -> Vec<Case> {
    let json = body(3, "\"result\":7");
    let length = format!("Content-Length: {}", json.len());
    let http = || Err(RpcRefusal::Http);
    vec![
        case(
            "control byte in reason",
            bytes(&[b"HTTP/1.1 200 O\x01K\r\n", length.as_bytes(), b"\r\n\r\n", json.as_bytes()]),
            http(),
        ),
        case(
            "invalid UTF-8 in a value",
            bytes(&[
                b"HTTP/1.1 200 OK\r\nX: \xff\r\n",
                length.as_bytes(),
                b"\r\n\r\n",
                json.as_bytes(),
            ]),
            http(),
        ),
        case(
            "DEL in a value",
            bytes(&[
                b"HTTP/1.1 200 OK\r\nX: a\x7fb\r\n",
                length.as_bytes(),
                b"\r\n\r\n",
                json.as_bytes(),
            ]),
            http(),
        ),
        case(
            "space in a name",
            format!("HTTP/1.1 200 OK\r\nX Y: z\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "space before colon",
            format!("HTTP/1.1 200 OK\r\nX : z\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "field without colon",
            format!("HTTP/1.1 200 OK\r\nXyz\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "empty name",
            format!("HTTP/1.1 200 OK\r\n: z\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "separator in a name",
            format!("HTTP/1.1 200 OK\r\nX(y): z\r\n{length}\r\n\r\n{json}"),
            http(),
        ),
    ]
}

fn length_cases() -> Vec<Case> {
    let json = body(3, "\"result\":7");
    let size = json.len();
    let http = || Err(RpcRefusal::Http);
    vec![
        case("close-delimited body", format!("HTTP/1.1 200 OK\r\n\r\n{json}"), http()),
        case(
            "duplicate equal lengths",
            format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nContent-Length: {size}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "comma-joined equal lengths",
            format!("HTTP/1.1 200 OK\r\nContent-Length: {size}, {size}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "conflicting lengths",
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nContent-Length: {}\r\n\r\n{json}",
                size + 1
            ),
            http(),
        ),
        case(
            "signed length",
            format!("HTTP/1.1 200 OK\r\nContent-Length: +{size}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "hexadecimal length",
            format!("HTTP/1.1 200 OK\r\nContent-Length: 0x{size:x}\r\n\r\n{json}"),
            http(),
        ),
        case(
            "padded length",
            format!("HTTP/1.1 200 OK\r\nContent-Length:  {size} \r\n\r\n{json}"),
            Ok(7),
        ),
        case(
            "overflowing length",
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{json}", "9".repeat(40)),
            Err(RpcRefusal::ResponseBytes),
        ),
        case(
            "chunked with length",
            response("200 OK", "Transfer-Encoding: chunked\r\n", &json),
            http(),
        ),
        case(
            "chunked without length",
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n{json}\r\n0\r\n\r\n"),
            http(),
        ),
        case(
            "identity transfer coding",
            response("200 OK", "Transfer-Encoding: identity\r\n", &json),
            http(),
        ),
        case(
            "gzip content coding",
            response("200 OK", "Content-Encoding: gzip\r\n", &json),
            http(),
        ),
        case(
            "identity content coding",
            response("200 OK", "Content-Encoding: identity\r\n", &json),
            http(),
        ),
    ]
}

fn bound_cases(ceiling: usize) -> Vec<Case> {
    let json = body(3, "\"result\":7");
    let base = format!("HTTP/1.1 200 OK\r\nX: \r\nContent-Length: {}\r\n\r\n", json.len());
    let pad = |extra: usize| "a".repeat(8192 - base.len() + extra);
    let exact = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":7{}}}",
        " ".repeat(ceiling - json.len())
    );
    let lowered = RpcLimits {
        response_bytes: ceiling,
        ..RpcLimits::default()
    };
    vec![
        case("64 fields", response("200 OK", &headers(63), &json), Ok(7)),
        case(
            "65 fields",
            response("200 OK", &headers(64), &json),
            Err(RpcRefusal::HeaderCount),
        ),
        case(
            "8192-byte head",
            response("200 OK", &format!("X: {}\r\n", pad(0)), &json),
            Ok(7),
        ),
        case(
            "8193-byte head",
            response("200 OK", &format!("X: {}\r\n", pad(1)), &json),
            Err(RpcRefusal::HeaderBytes),
        ),
        case(
            "503 with an 8193-byte head",
            response("503 Service Unavailable", &format!("X: {}\r\n", pad(1)), ""),
            Err(RpcRefusal::HeaderBytes),
        ),
        Case {
            limits: lowered,
            peer: Some(Peer::Eof),
            ..case("body at the lowered ceiling", response("200 OK", "", &exact), Ok(7))
        },
        Case {
            limits: lowered,
            peer: Some(Peer::Reset),
            ..case(
                "body one byte over the lowered ceiling",
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{exact}", ceiling + 1),
                Err(RpcRefusal::ResponseBytes),
            )
        },
        Case {
            peer: Some(Peer::Reset),
            ..case(
                "body over the default ceiling",
                format!("HTTP/1.1 200 OK\r\nContent-Length: 8001025\r\n\r\n{json}"),
                Err(RpcRefusal::ResponseBytes),
            )
        },
    ]
}

fn acquisition_cases() -> Vec<Case> {
    let full = valid();
    let head = full.len() - body(3, "\"result\":7").len();
    let short = RpcLimits {
        deadline: Duration::from_secs(2),
        ..RpcLimits::default()
    };
    vec![
        case("closed before any byte", "", Err(RpcRefusal::Http)),
        case("closed inside the status line", "HTTP/1.1 20", Err(RpcRefusal::Http)),
        case(
            "closed inside the head",
            "HTTP/1.1 200 OK\r\nContent-Len",
            Err(RpcRefusal::Http),
        ),
        case("truncated body", &full.as_bytes()[..full.len() - 3], Err(RpcRefusal::Http)),
        case("trailing byte", format!("{full}x"), Err(RpcRefusal::Http)),
        case(
            "second response after the body",
            format!("{full}{full}"),
            Err(RpcRefusal::Http),
        ),
        Case {
            wire: vec![(0, full.clone().into_bytes()), (50, b"x".to_vec())],
            ..case("delayed trailing byte", "", Err(RpcRefusal::Http))
        },
        Case {
            wire: full.bytes().map(|byte| (40, vec![byte])).collect(),
            limits: short,
            ..case("slow drip past the deadline", "", Err(RpcRefusal::Deadline))
        },
        // A timed-out exchange closes its connection: the held server sees the close.
        Case {
            hold: true,
            limits: short,
            peer: Some(Peer::Eof),
            ..case(
                "held open after the head",
                &full.as_bytes()[..head],
                Err(RpcRefusal::Deadline),
            )
        },
        Case {
            hold: true,
            limits: short,
            peer: Some(Peer::Eof),
            ..case("held open before any byte", "", Err(RpcRefusal::Deadline))
        },
    ]
}

/// The request the server received: one bounded HTTP/1.1 POST whose only private bytes are the Basic credential.
fn request_findings(request: &[u8], secret: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let credential = format!("Basic {}", basic(secret.as_bytes()));
    let lossy = String::from_utf8_lossy(request);
    let text: &str = &lossy;
    let (head, json) = text.split_once("\r\n\r\n").unwrap_or((text, ""));
    let expected = [
        ("host", "localhost".to_owned()),
        ("connection", "close".to_owned()),
        ("content-type", "application/json".to_owned()),
        ("authorization", credential.clone()),
        ("content-length", json.len().to_string()),
    ];
    for (name, value) in &expected {
        if field(request, name).as_deref() != Some(value.as_str()) {
            findings.push(format!("request field {name} differs"));
        }
    }
    let names: Vec<_> = head
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    if names.len() != expected.len() || !head.starts_with("POST / HTTP/1.1\r\n") || request.len() > 4096 {
        findings.push(format!("request line or field set differs: {names:?}"));
    }
    if text.matches(&credential).count() != 1 || text.contains(secret) {
        findings.push("private credential left the Basic field".to_owned());
    }
    let value: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
    if value != serde_json::json!({"jsonrpc":"2.0","id":3,"method":"getblockcount","params":[]}) {
        findings.push(format!("request body differs: {json}"));
    }
    findings
}

/// Threads of this process carrying the wallet's exchange name.
fn wallet_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter(|entry| {
            std::fs::read_to_string(entry.as_ref().unwrap().path().join("comm")).is_ok_and(|name| name.trim() == "pn-wallet-rpc")
        })
        .count()
}

/// Bound on kernel teardown of a joined thread's task. A join returns once the exiting thread
/// clears its thread identifier, which the kernel does before it unhashes the task from
/// `/proc`, so a joined thread's entry may remain briefly; under load that window is visible.
const TEARDOWN: Duration = Duration::from_secs(5);
/// Longest teardown wait observed, in microseconds, reported with any failure.
static TEARDOWN_WAIT: AtomicU64 = AtomicU64::new(0);

/// Wait within `bound` until `settled` holds, on the given clock. Each observation is timed after
/// the predicate returns, and the bound applies to successful observations too: Ok with the
/// wait only when `settled` held within the bound, otherwise Err with the elapsed time.
fn settle(
    bound: Duration,
    elapsed: impl Fn() -> Duration,
    pause: impl Fn(),
    settled: impl Fn() -> bool,
) -> Result<Duration, Duration> {
    loop {
        let done = settled();
        let waited = elapsed();
        if waited > bound {
            return Err(waited);
        }
        if done {
            return Ok(waited);
        }
        pause();
    }
}

/// The teardown wait on the real clock, recording the longest successful wait.
fn after_teardown(settled: impl Fn() -> bool) -> Result<Duration, Duration> {
    let started = Instant::now();
    let waited = settle(
        TEARDOWN,
        || started.elapsed(),
        || thread::sleep(Duration::from_millis(1)),
        settled,
    )?;
    TEARDOWN_WAIT.fetch_max(u64::try_from(waited.as_micros()).unwrap_or(u64::MAX), Ordering::Relaxed);
    Ok(waited)
}

/// One controlled-clock case: its name, the clock at the first observation, the predicate and
/// the expected outcome.
type Settle<'a> = (&'static str, Duration, &'a dyn Fn() -> bool, Result<Duration, Duration>);

/// The bounded wait on a controlled clock: a wake past the bound fails even when the predicate
/// then holds, a predicate that itself runs past the bound fails with the time after it, and
/// waits within the bound report their measured duration.
fn settle_cases() -> Vec<String> {
    use std::cell::Cell;
    let mut findings = Vec::new();
    let second = Duration::from_secs(1);
    let clock = Cell::new(Duration::ZERO);
    let now = || clock.get();
    let tick = || clock.set(clock.get() + second);
    let cases: [Settle<'_>; 4] = [
        ("settled within the bound", Duration::ZERO, &|| true, Ok(Duration::ZERO)),
        ("late wake", 6 * second, &|| true, Err(6 * second)),
        (
            "late success",
            Duration::ZERO,
            &|| {
                clock.set(clock.get() + 6 * second);
                true
            },
            Err(6 * second),
        ),
        ("never settled", Duration::ZERO, &|| false, Err(6 * second)),
    ];
    for (name, start, settled, expected) in cases {
        clock.set(start);
        let outcome = settle(5 * second, now, tick, settled);
        if outcome != expected {
            findings.push(format!("bounded wait, {name}: expected {expected:?}, got {outcome:?}"));
        }
    }
    clock.set(Duration::ZERO);
    if settle(5 * second, now, tick, || clock.get() >= 2 * second) != Ok(2 * second) {
        findings.push("bounded wait, settled after two ticks: wrong measured wait".to_owned());
    }
    findings
}

fn tasks() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

/// Run one case through a fresh reader and return its differences from the expectation.
fn run_case(case: &Case, genesis: &[Vec<u8>], declaration: &Provisioning) -> Vec<String> {
    let mut findings = Vec::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let cookie = Cookie::new();
    let server = serve(listener, genesis.to_vec(), case.wire.clone(), case.hold);
    let result = RpcClient::new(cookie.config(port), case.limits, decoder(), declaration, "wallet-genesis-1")
        .and_then(|client| client.read(Read::BlockCount))
        .map(|value| match value {
            ReadResult::Count(count) => count,
            other => panic!("count expected: {other:?}"),
        });
    let name = case.name;
    // The reader joins its scoped exchange thread before returning, timed out or not; once
    // the kernel has torn the joined task down, no exchange task of this read remains.
    if let Err(elapsed) = after_teardown(|| wallet_threads() == 0) {
        findings.push(format!(
            "{name}: an exchange thread task remained {elapsed:?} after its read returned"
        ));
    }
    let exchange = server.join().unwrap();
    if result != case.expected {
        findings.push(format!("{name}: expected {:?}, got {result:?}", case.expected));
    }
    if case.peer.is_some_and(|peer| peer != exchange.peer) {
        findings.push(format!("{name}: expected peer {:?}, got {:?}", case.peer, exchange.peer));
    }
    match exchange.requests.get(2) {
        Some(request) => findings.extend(
            request_findings(request, &cookie.secret)
                .into_iter()
                .map(|finding| format!("{name}: {finding}")),
        ),
        None => findings.push(format!("{name}: no case request reached the server")),
    }
    if let Err(error) = &result {
        let formatted = format!("{error:?} {error}");
        if formatted.contains(&cookie.secret)
            || formatted.contains(&basic(cookie.secret.as_bytes()))
            || formatted.contains("127.0.0.1")
            || formatted.contains(&port.to_string())
        {
            findings.push(format!("{name}: refusal formats a private sentinel"));
        }
    }
    findings
}

/// Claim: Through the public reader, a scripted server's exact bytes witness every strict predicate of the transport: CRLF-only lines without folds, refused interim and unadmitted statuses, missing, duplicate, comma-joined, conflicting or overflowing lengths, transfer and content codings, redirects, header syntax, count and byte bounds even on refused statuses, response-byte ceilings before any body byte, truncation, trailing bytes, socket closure and the single deadline; a 401 or refused status closes with its read-ahead body unread, a timed-out exchange closes its connection, which the held server observes, no task of a read's exchange thread remains once the kernel has torn its joined thread down within a bounded wait, and the process returns to its starting task count within the same bound after every exchange and server joined, the bounded wait refusing on a controlled clock a wake or a success that falls past its bound, a caller inside a Tokio runtime reads unchanged, and the request carries its only private bytes in the Basic field while refusals format no private sentinel.
/// ´claim:wallet:rpc-wire-fixtures-keep-strict-framing´
/// ´test:integration:wire-compatibility´
#[test]
fn wire_compatibility() {
    let header = pn_wallet::decode_block(include_bytes!("../fuzz/seeds/dynafed-block"), decoder())
        .unwrap()
        .header;
    let mut declaration: serde_json::Value = serde_json::from_str(include_str!("../provisioning.json")).unwrap();
    declaration["genesis"] = serde_json::json!(GENESIS);
    declaration["header"] = serde_json::json!(header);
    let declaration: Provisioning = serde_json::from_value(declaration).unwrap();
    let answers = [
        body(1, &format!("\"result\":\"{}\"", hex(&GENESIS))),
        body(2, &format!("\"result\":\"{}\"", hex(&header))),
    ];
    let ceiling = answers.iter().map(String::len).max().unwrap() + 64;
    let genesis: Vec<_> = answers.iter().map(|json| response("200 OK", "", json).into_bytes()).collect();
    let mut cases = status_cases();
    cases.extend(refused_cases());
    cases.extend(line_cases());
    cases.extend(field_cases());
    cases.extend(length_cases());
    cases.extend(bound_cases(ceiling));
    cases.extend(acquisition_cases());
    let threads = tasks();
    let mut findings: Vec<_> = cases.iter().flat_map(|case| run_case(case, &genesis, &declaration)).collect();
    findings.extend(settle_cases());
    // A caller already inside a Tokio runtime: the reader runs its exchange on its own
    // thread and runtime instead of nesting one, for a success and for a timed-out read.
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    for case in cases
        .iter()
        .filter(|case| matches!(case.name, "200 result" | "held open after the head"))
    {
        let inside = runtime.block_on(async { run_case(case, &genesis, &declaration) });
        findings.extend(inside.into_iter().map(|finding| format!("inside a Tokio runtime: {finding}")));
    }
    drop(runtime);
    // Every exchange and server thread is joined by now; after teardown the process is back
    // to the tasks it started with.
    if let Err(elapsed) = after_teardown(|| tasks() == threads) {
        findings.push(format!(
            "{} tasks remain {elapsed:?} after every exchange and server joined; {threads} at the start",
            tasks()
        ));
    }
    assert!(
        findings.is_empty(),
        "{} of {} wire cases differ (longest teardown wait {} us):\n{}",
        findings.len(),
        cases.len(),
        TEARDOWN_WAIT.load(Ordering::Relaxed),
        findings.join("\n")
    );
}
