//! Secret-terminating transport under (´[ROOT-dec:storage:secret-shim]´).
//! Persistence remains disabled pending independent integration review.

mod config;
mod scram;
mod secret;
mod wire;

pub use config::Configuration;

use secret::Buffer;
use std::{
    fmt,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Instrument;

// A bridge owns its forwarding task even when the bridge future is cancelled.
struct ForwardingTask(tokio::task::JoinHandle<()>);
impl Drop for ForwardingTask {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Bounded refusal causes contain no service-supplied strings or source errors.
/// (´def:host:refusal´)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// No public store-link case was declared.
    MissingCase,
    /// The public case vocabulary does not contain this declaration.
    UnknownCase,
    /// Guarded transport remains held.
    HeldCase,
    /// Private acquisition failed.
    ConfigurationIo,
    /// The connection-only JSON did not satisfy its schema.
    ConfigurationSyntax,
    /// A fixed protocol representation bound was exceeded.
    RepresentationLimit,
    /// This route avoids ordinary hostname storage in a resolver.
    NumericEndpointRequired,
    /// Transport failure; the operating-system error is not retained.
    Transport,
    /// Invalid framing or message order.
    Protocol,
    /// Password authentication failed inside the secret boundary.
    ServerAuthentication,
    /// Cleartext password requests are forbidden.
    Cleartext,
    /// MD5 authentication is forbidden.
    Md5,
    /// GSS authentication is forbidden.
    Gss,
    /// SSPI authentication is forbidden.
    Sspi,
    /// Kerberos authentication is forbidden.
    Kerberos,
    /// `AuthenticationOk` preceded a verified SCRAM server signature.
    PrematureAuthenticationOk,
    /// No supported authentication mechanism was offered.
    UnsupportedAuthentication,
    /// Invalid SCRAM attribute encoding.
    ScramFormat,
    /// The declared iteration count exceeds the reviewed work bound.
    ScramIterations,
    /// The server did not extend the client nonce.
    ServerNonce,
    /// The server proof does not authenticate the transcript.
    ServerSignature,
    /// The operating system could not supply a fresh nonce.
    Entropy,
    /// The public placeholder driver handoff failed.
    DriverHandoff,
    /// A server diagnostic remains private and terminates the driver stream.
    PrivateDiagnostic,
    /// Cancellation lacks an authenticated backend capability.
    Cancellation,
}
impl Refusal {
    fn authentication(code: u32) -> Self {
        match code {
            0 => Self::PrematureAuthenticationOk,
            2 => Self::Kerberos,
            3 => Self::Cleartext,
            5 => Self::Md5,
            7 | 8 => Self::Gss,
            9 => Self::Sspi,
            _ => Self::UnsupportedAuthentication,
        }
    }
}
impl fmt::Display for Refusal {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "store link refused: {self:?}")
    }
}
impl std::error::Error for Refusal {}

/// A whole, secret-typed server diagnostic; no string or serialization accessor.
/// (´def:host:private-server-diagnostic´)
pub struct PrivateDiagnostic(Buffer);
impl fmt::Debug for PrivateDiagnostic {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Borrow the buffer only through its role-only formatter.
        f.debug_tuple("PrivateDiagnostic").field(&self.0).finish()
    }
}

/// A transport-only connection; this package defines no persistence operation.
/// (´def:host:session´)
/// Queries must concern public data. Service metadata is not public query data.
/// Unclassified server diagnostics stay secret-typed and close this stream.
pub struct Session {
    client: tokio_postgres::Client,
    config: Arc<Configuration>,
    backend_key: Arc<Mutex<Option<Buffer>>>,
    diagnostics: Arc<Mutex<Vec<PrivateDiagnostic>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl fmt::Debug for Session {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Session { store_link_case: host-secured, private_state: [REDACTED], persistence: disabled }")
    }
}
impl Drop for Session {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Session {
    /// Authenticate the real service before constructing a public driver session.
    /// (´sig:host:connect´)
    /// # Errors
    /// Returns only bounded causes; authentication and transport errors retain no
    /// printable private context. Guarded transport is not implemented.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "Session::connect"
        ),
        ret
    )]
    pub async fn connect(config: Configuration) -> Result<Self, Refusal> {
        let result = Self::connect_inner(config).await;
        if let Err(cause) = &result {
            tracing::warn!(
                cause = ?cause,
                outcome = if matches!(cause, Refusal::Transport | Refusal::Entropy) {
                    "error"
                } else {
                    "refusal"
                }
            );
        }
        result
    }
    async fn connect_inner(config: Configuration) -> Result<Self, Refusal> {
        let mut socket = wire::Socket::open(&config).await?;
        scram::login(&mut socket, &config).await?;
        let key = Arc::new(Mutex::new(None));
        let diagnostics = Arc::new(Mutex::new(Vec::new()));
        let mut startup = Vec::new();
        loop {
            let frame = wire::read(&mut socket).await?;
            if frame.kind == b'Z' {
                if frame.payload.bytes() != b"I" {
                    return Err(Refusal::Protocol);
                }
                break;
            }
            if let Some(frame) = filter(frame, &key, &diagnostics)? {
                startup.push(frame);
            }
        }
        if key.lock().map_err(|_| Refusal::Cancellation)?.is_none() {
            return Err(Refusal::Cancellation);
        }
        let (driver, shim) = tokio::io::duplex(65_536);
        let bridge_key = Arc::clone(&key);
        let bridge_diagnostics = Arc::clone(&diagnostics);
        let bridge = tokio::spawn(
            async move {
                let _result = forward(shim, socket, startup, bridge_key, bridge_diagnostics).await;
            }
            .instrument(tracing::Span::current()),
        );
        let mut placeholder = tokio_postgres::Config::new();
        placeholder
            .user("pn_public_placeholder")
            .dbname("pn_public_placeholder")
            .ssl_mode(tokio_postgres::config::SslMode::Disable)
            .channel_binding(tokio_postgres::config::ChannelBinding::Disable);
        let Ok((client, connection)) = placeholder.connect_raw(driver, tokio_postgres::NoTls).await else {
            bridge.abort();
            return Err(Refusal::DriverHandoff);
        };
        let connection = tokio::spawn(
            async move {
                let _result = connection.await;
            }
            .instrument(tracing::Span::current()),
        );
        Ok(Self {
            client,
            config: Arc::new(config),
            backend_key: key,
            diagnostics,
            tasks: vec![bridge, connection],
        })
    }
    /// Borrow the placeholder-only upstream client for public statement evidence.
    /// (´sig:host:public-client´)
    #[must_use]
    pub fn client(&self) -> &tokio_postgres::Client {
        let operation = cli_common::observation::scope("HOST", "sig:design:storage", "Session::client", &self);
        let result = &self.client;
        operation.finish(&"public placeholder client");
        result
    }
    /// Cancel through the real secret-owned capability on a new shim transport.
    /// (´sig:host:cancel´)
    /// # Errors
    /// Refuses an unavailable capability or failed private transport.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "Session::cancel"
        ),
        ret
    )]
    pub async fn cancel(&self) -> Result<(), Refusal> {
        let result = self.cancel_inner().await;
        if let Err(cause) = &result {
            tracing::warn!(outcome = "error", cause = ?cause, "store cancellation failed");
        }
        result
    }
    async fn cancel_inner(&self) -> Result<(), Refusal> {
        let mut packet = Buffer::new();
        packet.append(&16_u32.to_be_bytes())?;
        packet.append(&80_877_102_u32.to_be_bytes())?;
        {
            let capability = self.backend_key.lock().map_err(|_| Refusal::Cancellation)?;
            packet.append(capability.as_ref().ok_or(Refusal::Cancellation)?.bytes())?;
        }
        let mut socket = wire::Socket::open(&self.config).await?;
        socket.write_all(packet.bytes()).await.map_err(|_| Refusal::Transport)?;
        socket.shutdown().await.map_err(|_| Refusal::Transport)
    }
    /// Take quarantined whole diagnostics without exposing their private bytes.
    /// (´sig:host:private-diagnostics´)
    /// # Errors
    /// Refuses poisoned diagnostic ownership instead of formatting its contents.
    pub fn private_diagnostics(&self) -> Result<Vec<PrivateDiagnostic>, Refusal> {
        let operation = cli_common::observation::scope("HOST", "sig:design:storage", "Session::private_diagnostics", &self);
        let result = self
            .diagnostics
            .lock()
            .map(|mut values| std::mem::take(&mut *values))
            .map_err(|_| Refusal::PrivateDiagnostic);
        operation.finish(&result);
        result
    }
}

async fn forward(
    mut shim: tokio::io::DuplexStream,
    socket: wire::Socket,
    startup: Vec<wire::Frame>,
    bridge_key: Arc<Mutex<Option<Buffer>>>,
    bridge_diagnostics: Arc<Mutex<Vec<PrivateDiagnostic>>>,
) -> Result<(), Refusal> {
    let length = shim.read_u32().await.map_err(|_| Refusal::DriverHandoff)?;
    let mut placeholder = Buffer::new();
    let length = usize::try_from(length).map_err(|_| Refusal::DriverHandoff)?;
    if !(4..=1024).contains(&length) {
        return Err(Refusal::DriverHandoff);
    }
    shim.read_exact(&mut placeholder.storage()[..length - 4])
        .await
        .map_err(|_| Refusal::DriverHandoff)?;
    placeholder.set_length(length - 4)?;
    if placeholder.bytes() != b"\0\x03\0\0client_encoding\0UTF8\0user\0pn_public_placeholder\0database\0pn_public_placeholder\0\0"
    {
        return Err(Refusal::DriverHandoff);
    }
    wire::send(&mut shim, b'R', &0_u32.to_be_bytes()).await?;
    for frame in startup {
        wire::send(&mut shim, frame.kind, frame.payload.bytes()).await?;
    }
    wire::send(&mut shim, b'Z', b"I").await?;
    let (mut client_read, mut client_write) = tokio::io::split(shim);
    let (mut server_read, mut server_write) = tokio::io::split(socket);
    let outbound = ForwardingTask(tokio::spawn(
        async move {
            loop {
                let Ok(frame) = wire::read(&mut client_read).await else {
                    break;
                };
                observe_public_frame(&frame);
                if wire::send(&mut server_write, frame.kind, frame.payload.bytes())
                    .await
                    .is_err()
                    || frame.kind == b'X'
                {
                    break;
                }
            }
        }
        .instrument(tracing::Span::current()),
    ));
    loop {
        let Ok(frame) = wire::read(&mut server_read).await else {
            break;
        };
        match filter(frame, &bridge_key, &bridge_diagnostics) {
            Ok(Some(frame)) => {
                observe_public_frame(&frame);
                if wire::send(&mut client_write, frame.kind, frame.payload.bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(None) => (),
            Err(_) => break,
        }
    }
    drop(outbound);
    Ok::<(), Refusal>(())
}

fn observe_public_frame(frame: &wire::Frame) {
    let operation = cli_common::observation::scope(
        "HOST",
        "sig:design:storage",
        "observe_public_frame",
        &if cli_common::observation::trace_enabled() {
            Some((frame.kind, cli_common::observation::public_bytes(frame.payload.bytes())))
        } else {
            None
        },
    );
    let result = ();
    operation.finish(&result);
}

fn filter(
    mut frame: wire::Frame,
    key: &Mutex<Option<Buffer>>,
    diagnostics: &Mutex<Vec<PrivateDiagnostic>>,
) -> Result<Option<wire::Frame>, Refusal> {
    match frame.kind {
        b'K' => {
            if frame.payload.bytes().len() != 8 {
                return Err(Refusal::Protocol);
            }
            *key.lock().map_err(|_| Refusal::Cancellation)? = Some(frame.payload);
            frame.payload = Buffer::from_bytes(&[0, 0, 0, 1, 0, 0, 0, 2])?;
        }
        b'S' if frame.payload.bytes().starts_with(b"session_authorization\0") => return Ok(None),
        b'S' if !public_parameter(frame.payload.bytes()) => {
            diagnostics
                .lock()
                .map_err(|_| Refusal::PrivateDiagnostic)?
                .push(PrivateDiagnostic(frame.payload));
            return Err(Refusal::PrivateDiagnostic);
        }
        b'E' | b'N' if !public_diagnostic(frame.payload.bytes()) => {
            diagnostics
                .lock()
                .map_err(|_| Refusal::PrivateDiagnostic)?
                .push(PrivateDiagnostic(frame.payload));
            return Err(Refusal::PrivateDiagnostic);
        }
        _ => (),
    }
    Ok(Some(frame))
}

// Startup GUCs can inherit private per-role configuration. Admit only a bounded
// public vocabulary before the driver allocates ordinary parameter strings.
fn public_parameter(bytes: &[u8]) -> bool {
    let Some(split) = bytes.iter().position(|value| *value == 0) else {
        return false;
    };
    let Some(value) = bytes[split + 1..].strip_suffix(&[0]) else {
        return false;
    };
    match &bytes[..split] {
        b"server_version" => value == b"19rc1",
        b"client_encoding" | b"server_encoding" => value == b"UTF8",
        b"application_name" => value.is_empty(),
        b"TimeZone" => matches!(value, b"UTC" | b"Etc/UTC" | b"GMT"),
        b"DateStyle" => value == b"ISO, MDY",
        b"IntervalStyle" => value == b"postgres",
        b"search_path" => value == br#""$user", public"#,
        b"scram_iterations" => std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|value| (1..=100_000).contains(&value)),
        b"integer_datetimes"
        | b"standard_conforming_strings"
        | b"is_superuser"
        | b"in_hot_standby"
        | b"default_transaction_read_only" => matches!(value, b"on" | b"off"),
        _ => false,
    }
}

// Declassification is structural and deliberately closed: no searching for or
// replacing private substrings. Other diagnostics stay whole and secret-owned.
fn public_diagnostic(bytes: &[u8]) -> bool {
    let mut code: Option<&[u8]> = None;
    let mut message: Option<&[u8]> = None;
    let mut rest = bytes;
    while let Some((&field, tail)) = rest.split_first() {
        if field == 0 {
            return tail.is_empty()
                && matches!(
                    (code, message),
                    (Some(b"22012"), Some(b"division by zero"))
                        | (Some(b"57014"), Some(b"canceling statement due to user request"))
                        | (Some(b"40001"), Some(b"could not serialize access due to concurrent update"))
                );
        }
        let Some(end) = tail.iter().position(|v| *v == 0) else {
            return false;
        };
        let value = &tail[..end];
        match field {
            b'C' if code.is_none() => code = Some(value),
            b'M' if message.is_none() => message = Some(value),
            b'S' | b'V' if matches!(value, b"ERROR" | b"NOTICE") => (),
            b'F' | b'R' if value.iter().all(|v| v.is_ascii_alphanumeric() || *v == b'_' || *v == b'.') => (),
            b'L' if value.iter().all(u8::is_ascii_digit) => (),
            _ => return false,
        }
        rest = &tail[end + 1..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{Buffer, Refusal, filter};
    use std::sync::Mutex;

    /// Claim: Backend keys and private session parameters are intercepted before driver allocation; an unclassified parameter or diagnostic is retained whole behind role-only Debug, while fixed public diagnostics retain their exact bytes.
    /// ´claim:host:wire-filter-precedes-ordinary-driver-storage´
    /// ´test:unit:wire-filter-boundary´
    #[test]
    fn wire_filter_boundary() {
        let key = Mutex::new(None);
        let diagnostics = Mutex::new(Vec::new());
        let frame = |kind, bytes: &[u8]| crate::wire::Frame {
            kind,
            payload: Buffer::from_bytes(bytes).unwrap(),
        };
        let dummy = filter(frame(b'K', b"private!"), &key, &diagnostics).unwrap().unwrap();
        assert_eq!(dummy.payload.bytes(), [0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(key.lock().unwrap().as_ref().unwrap().bytes(), b"private!");
        assert!(
            filter(frame(b'S', b"session_authorization\0private_role\0"), &key, &diagnostics)
                .unwrap()
                .is_none()
        );
        for (kind, bytes) in [
            (b'S', b"application_name\0private_application\0".as_slice()),
            (b'E', b"Mprivate_error\0\0"),
        ] {
            assert!(matches!(
                filter(frame(kind, bytes), &key, &diagnostics),
                Err(Refusal::PrivateDiagnostic)
            ));
        }
        let retained = diagnostics.lock().unwrap();
        assert_eq!(retained[0].0.bytes(), b"application_name\0private_application\0");
        assert_eq!(retained[1].0.bytes(), b"Mprivate_error\0\0");
        assert!(!format!("{retained:?}").contains("private_application"));
        assert!(!format!("{retained:?}").contains("private_error"));
        drop(retained);
        let public = [b"SERROR\0VERROR\0C".as_slice(), b"22012\0Mdivision by zero\0\0"].concat();
        assert_eq!(
            filter(frame(b'E', &public), &key, &diagnostics)
                .unwrap()
                .unwrap()
                .payload
                .bytes(),
            public
        );
    }
}
