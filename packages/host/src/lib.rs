//! Secret-terminating transport under (´[ROOT-dec:storage:secret-shim]´).
//! Persistence remains disabled pending independent integration review.

#[cfg(test)]
#[path = "storage/admitted_tests.rs"]
mod admitted_carrier_tests;
mod admitted_result;
/// Explicit binary64 fragments, without publication or admission integration.
/// (´[ROOT-rule:design:binary64-evidence]´)
pub mod binary64;
/// Budgeted positions computed only from borrowed admitted packages.
/// (´[ROOT-amend:identity:result-position-recipe]´)
pub use admitted_result::position;
mod config;
#[cfg(test)]
mod credential_fixture;
pub mod publication;
mod scram;
mod secret;
pub mod storage;
mod storage_payload;
mod wire;

pub use config::Configuration;

use secret::Buffer;
use std::{
    fmt,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// A bridge owns its forwarding task even when the bridge future is cancelled.
struct ForwardingTask(tokio::task::JoinHandle<Result<(), Refusal>>);
impl Drop for ForwardingTask {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A server answer contains only a form and a closed cause, with no diagnostic content.
/// (´def:host:server-error´)
/// Failed denotes no effect; Uncertain requires an equality-checked operation before repetition.
/// The type is implemented independently of the designed diagnostic translator and store mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerError {
    /// The server reported a definite failure of the request.
    Failed(Cause),
    /// The request may have taken effect.
    Uncertain(Cause),
}

/// Closed meanings of server failures under (´def:host:server-error´).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cause {
    /// A rule declared on the store (no duplicate, every reference present, every value within its declared check, no required value missing) refused a change.
    ConstraintViolation,
    /// The request collided with other sessions' work at the same moment (a serialization failure or a deadlock).
    Conflict,
    /// A cancellation, or a time limit set on the server for a statement, a lock wait, an idle session or a transaction, stopped it.
    Cancelled,
    /// An administrator ended the session, shut the server down, or dropped the database.
    Terminated,
    /// The server is starting, stopping or recovering from a crash, or the connection to it failed.
    Unavailable,
    /// The server ran out of disk space, memory or connections, or hit a configured limit.
    Resources,
    /// The server is a standby, or set to accept only reads.
    ReadOnly,
    /// The server refused the login: wrong password, or its access rules do not admit the role from this host.
    LoginRejected,
    /// The role lacks a privilege the request needs.
    PermissionDenied,
    /// A database, schema or role the configuration names is missing, or the server is not in the state the request needs.
    Misconfigured,
    /// The server refused the host's own statement or a value it carried (a syntax, type, object, state or value error).
    StatementRejected,
    /// The server reported an internal or system failure, such as a disk read or write error.
    ServerFault,
    /// The server found the stored data or an index physically damaged.
    StorageDamaged,
    /// The server reported something this host does not know; this is kept rare by mapping every kind the declared server documents.
    Unrecognized,
}

/// When repeating can help under (´def:host:server-error´), not permission to repeat an uncertain operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retry {
    /// Repeating the whole transaction can succeed at once.
    Immediately,
    /// A wait may allow the condition to pass.
    AfterWait,
    /// A configuration, input, implementation or data change is needed.
    AfterChange,
}

/// The owner of a condition under (´def:host:server-error´).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Concern {
    /// Retained data or the validation that admitted it.
    StoredData,
    /// The host's implementation.
    Host,
    /// Concurrent sessions.
    OtherSessions,
    /// The server operator.
    Operator,
    /// Deployment configuration.
    Deployment,
    /// Resources available to the server.
    ServerResources,
    /// The server itself.
    Server,
    /// No recognized owner.
    Unknown,
}

impl ServerError {
    /// Return the closed cause under (´def:host:server-error´).
    #[must_use]
    pub fn cause(self) -> Cause {
        let operation = cli_common::observation::scope("HOST", "sig:design:storage", "ServerError::cause", &self);
        let result = match self {
            Self::Failed(cause) | Self::Uncertain(cause) => cause,
        };
        operation.finish(&result);
        result
    }

    /// Whether the server reported no effect, under (´def:host:server-error´).
    #[must_use]
    pub fn took_no_effect(self) -> bool {
        let operation = cli_common::observation::scope("HOST", "sig:design:storage", "ServerError::took_no_effect", &self);
        let result = matches!(self, Self::Failed(_));
        operation.finish(&result);
        result
    }

    /// When repeating can help under (´def:host:server-error´); uncertainty still requires equality-checked repetition.
    #[must_use]
    pub fn retry(self) -> Retry {
        let operation = cli_common::observation::scope("HOST", "sig:design:storage", "ServerError::retry", &self);
        let cause = match self {
            Self::Failed(cause) | Self::Uncertain(cause) => cause,
        };
        let result = match cause {
            Cause::Conflict => Retry::Immediately,
            Cause::Cancelled | Cause::Terminated | Cause::Unavailable | Cause::Resources | Cause::ServerFault => Retry::AfterWait,
            Cause::ConstraintViolation
            | Cause::ReadOnly
            | Cause::LoginRejected
            | Cause::PermissionDenied
            | Cause::Misconfigured
            | Cause::StatementRejected
            | Cause::StorageDamaged
            | Cause::Unrecognized => Retry::AfterChange,
        };
        operation.finish(&result);
        result
    }

    /// The concern owner under (´def:host:server-error´).
    #[must_use]
    pub fn concern(self) -> Concern {
        let operation = cli_common::observation::scope("HOST", "sig:design:storage", "ServerError::concern", &self);
        let cause = match self {
            Self::Failed(cause) | Self::Uncertain(cause) => cause,
        };
        let result = match cause {
            Cause::ConstraintViolation | Cause::StorageDamaged => Concern::StoredData,
            Cause::Conflict => Concern::OtherSessions,
            Cause::Cancelled | Cause::Terminated => Concern::Operator,
            Cause::Unavailable | Cause::ServerFault => Concern::Server,
            Cause::Resources => Concern::ServerResources,
            Cause::ReadOnly | Cause::LoginRejected | Cause::PermissionDenied | Cause::Misconfigured => Concern::Deployment,
            Cause::StatementRejected => Concern::Host,
            Cause::Unrecognized => Concern::Unknown,
        };
        operation.finish(&result);
        result
    }
}

impl fmt::Display for ServerError {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (form, cause) = match self {
            Self::Failed(cause) => ("The request failed and took no effect.", cause),
            Self::Uncertain(cause) => (
                "The request may have taken effect: the server ended the session or did not report the outcome.",
                cause,
            ),
        };
        let sentence = match cause {
            Cause::ConstraintViolation => {
                "A constraint declared on the store refused the change; the stored data or the host's own validation is in question."
            }
            Cause::Conflict => {
                "It conflicted with another session's concurrent work; repeating the whole transaction can succeed."
            }
            Cause::Cancelled => "A cancellation or a time limit configured on the server stopped it.",
            Cause::Terminated => "An administrator ended the session or is shutting the server down.",
            Cause::Unavailable => "The server is starting, stopping or recovering from a failure, or its connection failed.",
            Cause::Resources => "The server ran short of a resource such as disk space, memory or connections.",
            Cause::ReadOnly => "The server accepts only reads: it is a standby or set read-only.",
            Cause::LoginRejected => "The server did not admit the login under its credentials or access rules.",
            Cause::PermissionDenied => "The role lacks a privilege the request needs.",
            Cause::Misconfigured => {
                "The server is not set up as the host's configuration declares: a database, schema, role or state it needs is missing or not ready."
            }
            Cause::StatementRejected => {
                "The server rejected the host's statement or a value it carried; the host's statements are fixed, so this is a defect of the host or a change to the store's schema made outside it."
            }
            Cause::ServerFault => "The server reported an internal or system failure, such as an input or output error.",
            Cause::StorageDamaged => "The server found its stored data or an index damaged.",
            Cause::Unrecognized => "The server reported a condition this host does not recognize.",
        };
        write!(f, "{form} {sentence} The server's own log holds the detail.")
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
    /// The declared iteration count is outside the reviewed security and work bounds.
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
    /// A server parameter is outside the declared public configuration.
    UnclassifiedParameter,
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

/// A secret-terminating connection owned by the closed storage vocabulary.
/// (´def:host:session´)
/// Only the storage module may select statements; no public method yields a raw client.
/// ```compile_fail
/// fn raw(session: &pn_host::Session) { let _ = session.client(); }
/// ```
/// Unclassified server diagnostics stay secret-typed and close this stream.
pub struct Session {
    client: storage::StatementClient,
    config: Arc<Configuration>,
    backend_key: Arc<Mutex<Option<Buffer>>>,
    diagnostics: Arc<Mutex<Vec<PrivateDiagnostic>>>,
    last_refusal: Arc<Mutex<Option<Refusal>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl fmt::Debug for Session {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("store_link_case", &"host-secured")
            .field("connected", &!self.client.is_closed())
            .field("private_state", &"[REDACTED]")
            .field("persistence", &"disabled")
            .finish_non_exhaustive()
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
            source_item = "Session::connect",
            asynchronous = true
        ),
        ret
    )]
    // Caveat: Private startup-frame bytes are borrowed only for the ready-state check until comparison returns; the protocol check requires a slice.
    // (´[ROOT-cav:observe:secret-host-lib-connect-buffer-1]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    pub async fn connect(config: Configuration) -> Result<Self, Refusal> {
        let result = async {
            let mut socket = wire::Socket::open(&config).await?;
            scram::login(&mut socket, &config).await?;
            let key = Arc::new(Mutex::new(None));
            let diagnostics = Arc::new(Mutex::new(Vec::new()));
            let last_refusal = Arc::new(Mutex::new(None));
            let mut startup = Vec::new();
            loop {
                let frame = wire::read(&mut socket).await?;
                if frame.kind == b'Z' {
                    if frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-connect-buffer-1]´) */) != b"I" {
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
            let bridge_refusal = Arc::clone(&last_refusal);
            let bridge = tokio::spawn(async move {
                let _result = relay(Relay {
                    shim,
                    socket,
                    startup,
                    key: bridge_key,
                    diagnostics: bridge_diagnostics,
                    refusal: bridge_refusal,
                })
                .await;
            });
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
            let connection = tokio::spawn(async move {
                let _result = connection.await;
            });
            Ok(Self {
                client: storage::StatementClient::new(client),
                config: Arc::new(config),
                backend_key: key,
                diagnostics,
                last_refusal,
                tasks: vec![bridge, connection],
            })
        }
        .await;
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

    /// Borrow the placeholder-only upstream client for public statement evidence.
    /// (´sig:host:public-client´)
    #[must_use]
    #[cfg(test)]
    pub(crate) fn client(&self) -> &tokio_postgres::Client {
        let operation = cli_common::observation::scope("HOST", "sig:design:storage", "Session::client", &self);
        let result = self.client.fixture();
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
            source_item = "Session::cancel",
            asynchronous = true
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
    // Caveat: The retained cancellation capability is lent to packet.append while its mutex guard is held; the borrow ends when append returns because protected packet assembly accepts bytes.
    // (´[ROOT-cav:observe:secret-host-lib-cancel-inner-buffer-1]´)
    // Caveat: The encoded cancellation packet is lent to Socket::write_all on the cancellation connection; the borrow ends when the awaited write completes because the socket API requires bytes.
    // (´[ROOT-cav:observe:secret-host-lib-cancel-inner-buffer-2]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    async fn cancel_inner(&self) -> Result<(), Refusal> {
        let mut packet = Buffer::new();
        packet.append(&16_u32.to_be_bytes())?;
        packet.append(&80_877_102_u32.to_be_bytes())?;
        {
            let capability = self.backend_key.lock().map_err(|_| Refusal::Cancellation)?;
            packet.append(capability.as_ref().ok_or(Refusal::Cancellation)?.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-cancel-inner-buffer-1]´) */))?;
        }
        let mut socket = wire::Socket::open(&self.config).await?;
        socket
            .write_all(packet.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-cancel-inner-buffer-2]´) */))
            .await
            .map_err(|_| Refusal::Transport)?;
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

    /// Read the last bounded relay refusal without exposing a driver diagnostic.
    /// (´sig:host:last-refusal´)
    #[must_use]
    pub fn last_refusal(&self) -> Option<Refusal> {
        let operation = cli_common::observation::scope("HOST", "sig:design:storage", "Session::last_refusal", &self);
        let result = *self.last_refusal.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        operation.finish(&result);
        result
    }
}

// Caveat: The placeholder buffer storage is lent to the shim read_exact for the bounded startup read; the mutable borrow ends when that awaited read completes because the reader requires a slice.
// (´[ROOT-cav:observe:secret-host-lib-forward-buffer-1]´)
// Caveat: The captured startup placeholder is lent to the exact public-placeholder equality check; the borrow ends at comparison because validating the driver handoff requires bytes.
// (´[ROOT-cav:observe:secret-host-lib-forward-buffer-2]´)
// Caveat: The retained classified-public startup frame is lent to wire::send toward the shim; the borrow ends when that awaited startup-frame send completes because wire framing requires bytes.
// (´[ROOT-cav:observe:secret-host-lib-forward-buffer-3]´)
// Caveat: The classified-public inbound frame is lent to wire::send toward the client after filtering; the borrow ends when that awaited relay send completes because wire framing requires bytes.
// (´[ROOT-cav:observe:secret-host-lib-forward-buffer-4]´)
// Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
#[allow(clippy::disallowed_methods)]
async fn forward(
    mut shim: tokio::io::DuplexStream,
    socket: wire::Socket,
    startup: Vec<wire::Frame>,
    bridge_key: Arc<Mutex<Option<Buffer>>>,
    bridge_diagnostics: Arc<Mutex<Vec<PrivateDiagnostic>>>,
    refusal: Arc<Mutex<Option<Refusal>>>,
) -> Result<(), Refusal> {
    let length = shim.read_u32().await.map_err(|_| Refusal::DriverHandoff)?;
    let mut placeholder = Buffer::new();
    let length = usize::try_from(length).map_err(|_| Refusal::DriverHandoff)?;
    if !(4..=1024).contains(&length) {
        return Err(Refusal::DriverHandoff);
    }
    shim.read_exact(&mut placeholder.expose_storage(/* (´[ROOT-cav:observe:secret-host-lib-forward-buffer-1]´) */)[..length - 4])
        .await
        .map_err(|_| Refusal::DriverHandoff)?;
    placeholder.set_length(length - 4)?;
    if placeholder.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-forward-buffer-2]´) */)
        != b"\0\x03\0\0client_encoding\0UTF8\0user\0pn_public_placeholder\0database\0pn_public_placeholder\0\0"
    {
        return Err(Refusal::DriverHandoff);
    }
    wire::send(&mut shim, b'R', &0_u32.to_be_bytes()).await?;
    for frame in startup {
        wire::send(
            &mut shim,
            frame.kind,
            frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-forward-buffer-3]´) */),
        )
        .await?;
    }
    wire::send(&mut shim, b'Z', b"I").await?;
    let (client_read, mut client_write) = tokio::io::split(shim);
    let (mut server_read, server_write) = tokio::io::split(socket);
    let mut outbound = ForwardingTask(tokio::spawn(relay_outbound(Outbound {
        client: client_read,
        server: server_write,
        refusal: Arc::clone(&refusal),
    })));
    let inbound = async {
        loop {
            let frame = wire::read(&mut server_read).await?;
            if let Some(frame) = filter(frame, &bridge_key, &bridge_diagnostics)? {
                observe_public_frame(&frame);
                wire::send(
                    &mut client_write,
                    frame.kind,
                    frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-forward-buffer-4]´) */),
                )
                .await?;
            }
        }
    };
    let mut inbound = std::pin::pin!(inbound);
    let mut outbound_finished = false;
    let result = std::future::poll_fn(|cx| {
        use std::future::Future as _;
        if let std::task::Poll::Ready(result) = std::pin::Pin::new(&mut outbound.0).poll(cx) {
            outbound_finished = true;
            return std::task::Poll::Ready(result.unwrap_or(Err(Refusal::Transport)));
        }
        inbound.as_mut().poll(cx)
    })
    .await;
    if let Err(cause) = result {
        *refusal.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cause);
    }
    if !outbound_finished {
        outbound.0.abort();
        let _completion = (&mut outbound.0).await;
    }
    // Both stream halves are dropped before returning. An outbound refusal
    // cannot leave the inbound half waiting on an idle server transaction.
    result
}

// Each task creates its own span when first polled, outside the connect future.
// Public frames are recorded at their checked boundary; task state is private.
struct Relay {
    shim: tokio::io::DuplexStream,
    socket: wire::Socket,
    startup: Vec<wire::Frame>,
    key: Arc<Mutex<Option<Buffer>>>,
    diagnostics: Arc<Mutex<Vec<PrivateDiagnostic>>>,
    refusal: Arc<Mutex<Option<Refusal>>>,
}
impl fmt::Debug for Relay {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Relay { role: store-session, value: [REDACTED] }")
    }
}
struct Outbound {
    client: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    server: tokio::io::WriteHalf<wire::Socket>,
    refusal: Arc<Mutex<Option<Refusal>>>,
}
impl fmt::Debug for Outbound {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Outbound { role: store-session, value: [REDACTED] }")
    }
}

#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        source_item = "relay",
        operation = "relay",
        asynchronous = true
    ),
    ret
)]
async fn relay(state: Relay) -> Result<(), Refusal> {
    let Relay {
        shim,
        socket,
        startup,
        key,
        diagnostics,
        refusal,
    } = state;
    let result = forward(shim, socket, startup, key, diagnostics, refusal).await;
    if let Err(cause) = &result {
        tracing::warn!(cause = ?cause, outcome = if matches!(cause, Refusal::Transport) { "error" } else { "refusal" }, "store relay refused");
    }
    result
}

#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        source_item = "relay_outbound",
        operation = "relay-outbound",
        asynchronous = true
    ),
    ret
)]
// Caveat: Private outbound frame storage is borrowed for the authenticated socket write until it completes; the socket API requires a slice.
// (´[ROOT-cav:observe:secret-host-lib-relay-outbound-buffer-1]´)
// Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
#[allow(clippy::disallowed_methods)]
async fn relay_outbound(state: Outbound) -> Result<(), Refusal> {
    let Outbound {
        mut client,
        mut server,
        refusal,
    } = state;
    let result = async {
        loop {
            let frame = wire::read(&mut client).await?;
            observe_public_frame(&frame);
            wire::send(
                &mut server,
                frame.kind,
                frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-relay-outbound-buffer-1]´) */),
            )
            .await?;
            if frame.kind == b'X' {
                return Ok(());
            }
        }
    }
    .await;
    if let Err(cause) = &result {
        // Publish before either outbound half is dropped and EOF becomes visible.
        *refusal.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(*cause);
        tracing::warn!(cause = ?cause, outcome = if matches!(cause, Refusal::Transport) { "error" } else { "refusal" }, "store outbound relay refused");
    }
    result
}

// Caveat: Classified-public frame bytes are borrowed only to construct the full public observation after classification, ending when public_bytes returns; that representation API requires a slice.
// (´[ROOT-cav:observe:secret-host-lib-observe-public-frame-buffer-1]´)
// Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
#[allow(clippy::disallowed_methods)]
fn observe_public_frame(frame: &wire::Frame) {
    let operation = cli_common::observation::scope(
        "HOST",
        "sig:design:storage",
        "observe_public_frame",
        &if cli_common::observation::trace_enabled() {
            Some((
                frame.kind,
                cli_common::observation::public_bytes(
                    frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-observe-public-frame-buffer-1]´) */),
                ),
            ))
        } else {
            None
        },
    );
    let result = ();
    operation.finish(&result);
}

// Caveat: The parameter frame is lent to the session_authorization prefix predicate; the borrow ends when starts_with returns because private-role classification requires bytes.
// (´[ROOT-cav:observe:secret-host-lib-filter-buffer-2]´)
// Caveat: The parameter frame is lent to public_parameter for classification against its declared public forms; the borrow ends when that predicate returns because classification requires bytes.
// (´[ROOT-cav:observe:secret-host-lib-filter-buffer-3]´)
// Caveat: The diagnostic frame is lent to public_diagnostic for classification against its declared public fields; the borrow ends when that predicate returns because classification requires bytes.
// (´[ROOT-cav:observe:secret-host-lib-filter-buffer-4]´)
// Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
#[allow(clippy::disallowed_methods)]
fn filter(
    mut frame: wire::Frame,
    key: &Mutex<Option<Buffer>>,
    diagnostics: &Mutex<Vec<PrivateDiagnostic>>,
) -> Result<Option<wire::Frame>, Refusal> {
    match frame.kind {
        b'K' => {
            if frame.payload.len() != 8 {
                return Err(Refusal::Protocol);
            }
            *key.lock().map_err(|_| Refusal::Cancellation)? = Some(frame.payload);
            frame.payload = Buffer::from_bytes(&[0, 0, 0, 1, 0, 0, 0, 2])?;
        }
        b'S' if frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-filter-buffer-2]´) */).starts_with(b"session_authorization\0") =>
        {
            return Ok(None);
        }
        b'S' if !public_parameter(frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-filter-buffer-3]´) */)) => {
            diagnostics
                .lock()
                .map_err(|_| Refusal::PrivateDiagnostic)?
                .push(PrivateDiagnostic(frame.payload));
            return Err(Refusal::UnclassifiedParameter);
        }
        b'E' | b'N'
            if !public_diagnostic(frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-filter-buffer-4]´) */)) =>
        {
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
        b"server_version" => value == include_str!("../postgresql-target.txt").trim().as_bytes(),
        b"client_encoding" | b"server_encoding" => value == b"UTF8",
        b"application_name" => value.is_empty(),
        b"TimeZone" => matches!(value, b"UTC" | b"Etc/UTC" | b"GMT"),
        b"DateStyle" => value == b"ISO, MDY",
        b"IntervalStyle" => value == b"postgres",
        b"search_path" => value == br#""$user", public"#,
        b"scram_iterations" => std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|value| scram::ITERATIONS.contains(&value)),
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
    // Fixture-only secret boundary: Only this test constructs and consumes these fixture secrets.
    // Caveat: The replacement backend-key fixture is lent to the assertion against the fixed public dummy bytes; the borrow ends at that assertion because exact equality requires a slice.
    // (´[ROOT-cav:observe:secret-host-lib-wire-filter-boundary-buffer-1]´)
    // Caveat: The retained backend-key fixture is lent to the assertion against private! while its fixture mutex guard is held; the borrow ends at that assertion because exact equality requires a slice.
    // (´[ROOT-cav:observe:secret-host-lib-wire-filter-boundary-buffer-2]´)
    // Caveat: The retained application-name fixture is lent to its exact preservation assertion; the borrow ends at that assertion because equality requires a slice.
    // (´[ROOT-cav:observe:secret-host-lib-wire-filter-boundary-buffer-3]´)
    // Caveat: The retained error-message fixture is lent to its exact preservation assertion; the borrow ends at that assertion because equality requires a slice.
    // (´[ROOT-cav:observe:secret-host-lib-wire-filter-boundary-buffer-4]´)
    // Caveat: The classified-public error fixture is lent to the assertion against its original public packet; the borrow ends at that assertion because exact equality requires a slice.
    // (´[ROOT-cav:observe:secret-host-lib-wire-filter-boundary-buffer-5]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    fn wire_filter_boundary() {
        let key = Mutex::new(None);
        let diagnostics = Mutex::new(Vec::new());
        let frame = |kind, bytes: &[u8]| crate::wire::Frame {
            kind,
            payload: Buffer::from_bytes(bytes).unwrap(),
        };
        let dummy = filter(frame(b'K', b"private!"), &key, &diagnostics).unwrap().unwrap();
        assert_eq!(
            dummy.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-wire-filter-boundary-buffer-1]´) */),
            [0, 0, 0, 1, 0, 0, 0, 2]
        );
        assert_eq!(
            key.lock().unwrap().as_ref().unwrap().expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-wire-filter-boundary-buffer-2]´) */),
            b"private!"
        );
        assert!(
            filter(frame(b'S', b"session_authorization\0private_role\0"), &key, &diagnostics)
                .unwrap()
                .is_none()
        );
        for (kind, bytes, expected) in [
            (
                b'S',
                b"application_name\0private_application\0".as_slice(),
                Refusal::UnclassifiedParameter,
            ),
            (b'E', b"Mprivate_error\0\0", Refusal::PrivateDiagnostic),
        ] {
            assert_eq!(filter(frame(kind, bytes), &key, &diagnostics).err(), Some(expected));
        }
        let retained = diagnostics.lock().unwrap();
        assert_eq!(
            retained[0].0.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-wire-filter-boundary-buffer-3]´) */),
            b"application_name\0private_application\0"
        );
        assert_eq!(
            retained[1].0.expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-wire-filter-boundary-buffer-4]´) */),
            b"Mprivate_error\0\0"
        );
        assert!(!format!("{retained:?}").contains("private_application"));
        assert!(!format!("{retained:?}").contains("private_error"));
        drop(retained);
        let public = [b"SERROR\0VERROR\0C".as_slice(), b"22012\0Mdivision by zero\0\0"].concat();
        assert_eq!(
            filter(frame(b'E', &public), &key, &diagnostics)
                .unwrap()
                .unwrap()
                .payload
                .expose_bytes(/* (´[ROOT-cav:observe:secret-host-lib-wire-filter-boundary-buffer-5]´) */),
            public
        );
    }

    pub(super) async fn relay_refusal_fixtures() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for cause in [
            Refusal::RepresentationLimit,
            Refusal::Transport,
            Refusal::Protocol,
            Refusal::PrivateDiagnostic,
        ] {
            let (socket, mut server) = crate::wire::fixture_pair();
            let (mut driver, shim) = tokio::io::duplex(1024);
            let key = std::sync::Arc::new(Mutex::new(None));
            let diagnostics = std::sync::Arc::new(Mutex::new(Vec::new()));
            let task = tokio::spawn(super::relay(super::Relay {
                shim,
                socket,
                startup: Vec::new(),
                key,
                diagnostics,
                refusal: std::sync::Arc::new(Mutex::new(None)),
            }));
            let startup = b"\0\x03\0\0client_encoding\0UTF8\0user\0pn_public_placeholder\0database\0pn_public_placeholder\0\0";
            driver.write_u32(u32::try_from(startup.len()).unwrap() + 4).await.unwrap();
            driver.write_all(startup).await.unwrap();
            assert_eq!(crate::wire::read(&mut driver).await.unwrap().kind, b'R');
            assert_eq!(crate::wire::read(&mut driver).await.unwrap().kind, b'Z');
            match cause {
                Refusal::RepresentationLimit => server.write_all(&[b'D', 0, 16, 0, 5]).await.unwrap(),
                Refusal::Protocol => crate::wire::send(&mut server, b'K', b"bad").await.unwrap(),
                Refusal::PrivateDiagnostic => crate::wire::send(&mut server, b'E', b"Mprivate_relay_fixture\0\0")
                    .await
                    .unwrap(),
                Refusal::Transport => server.shutdown().await.unwrap(),
                _ => unreachable!(),
            }
            assert_eq!(task.await.unwrap(), Err(cause));
            let mut byte = [0];
            assert_eq!(driver.read(&mut byte).await.unwrap(), 0);
        }
    }

    /// Claim: Every relay-time framing, transport and private-diagnostic refusal closes the driver with its exact bounded cause, rather than discarding the forwarding result.
    /// ´claim:host:relay-refusals-retain-their-bounded-cause´
    /// ´test:unit:relay-refusals´
    #[test]
    fn relay_refusals() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(relay_refusal_fixtures());
    }
}

#[cfg(test)]
mod postgresql;
#[cfg(test)]
mod transport_evidence;

#[cfg(test)]
mod server_error_value_tests {
    use super::{Cause, Concern, Retry, ServerError};
    const TABLE: [(Cause, Retry, Concern, &str); 14] = [
        (
            Cause::ConstraintViolation,
            Retry::AfterChange,
            Concern::StoredData,
            "A constraint declared on the store refused the change; the stored data or the host's own validation is in question.",
        ),
        (
            Cause::Conflict,
            Retry::Immediately,
            Concern::OtherSessions,
            "It conflicted with another session's concurrent work; repeating the whole transaction can succeed.",
        ),
        (
            Cause::Cancelled,
            Retry::AfterWait,
            Concern::Operator,
            "A cancellation or a time limit configured on the server stopped it.",
        ),
        (
            Cause::Terminated,
            Retry::AfterWait,
            Concern::Operator,
            "An administrator ended the session or is shutting the server down.",
        ),
        (
            Cause::Unavailable,
            Retry::AfterWait,
            Concern::Server,
            "The server is starting, stopping or recovering from a failure, or its connection failed.",
        ),
        (
            Cause::Resources,
            Retry::AfterWait,
            Concern::ServerResources,
            "The server ran short of a resource such as disk space, memory or connections.",
        ),
        (
            Cause::ReadOnly,
            Retry::AfterChange,
            Concern::Deployment,
            "The server accepts only reads: it is a standby or set read-only.",
        ),
        (
            Cause::LoginRejected,
            Retry::AfterChange,
            Concern::Deployment,
            "The server did not admit the login under its credentials or access rules.",
        ),
        (
            Cause::PermissionDenied,
            Retry::AfterChange,
            Concern::Deployment,
            "The role lacks a privilege the request needs.",
        ),
        (
            Cause::Misconfigured,
            Retry::AfterChange,
            Concern::Deployment,
            "The server is not set up as the host's configuration declares: a database, schema, role or state it needs is missing or not ready.",
        ),
        (
            Cause::StatementRejected,
            Retry::AfterChange,
            Concern::Host,
            "The server rejected the host's statement or a value it carried; the host's statements are fixed, so this is a defect of the host or a change to the store's schema made outside it.",
        ),
        (
            Cause::ServerFault,
            Retry::AfterWait,
            Concern::Server,
            "The server reported an internal or system failure, such as an input or output error.",
        ),
        (
            Cause::StorageDamaged,
            Retry::AfterChange,
            Concern::StoredData,
            "The server found its stored data or an index damaged.",
        ),
        (
            Cause::Unrecognized,
            Retry::AfterChange,
            Concern::Unknown,
            "The server reported a condition this host does not recognize.",
        ),
    ];

    /// Claim: Both forms return each of fourteen constructed causes unchanged.
    /// ´claim:host:server-error-cause´
    /// ´test:unit:server-error-cause´
    #[test]
    fn server_error_cause() {
        for (cause, _, _, _) in TABLE {
            assert_eq!(ServerError::Failed(cause).cause(), cause, "failed preserves cause");
            assert_eq!(ServerError::Uncertain(cause).cause(), cause, "uncertain preserves cause");
        }
    }

    /// Claim: Across all fourteen causes only Failed reports that the request took no effect.
    /// ´claim:host:server-error-effect´
    /// ´test:unit:server-error-effect´
    #[test]
    fn server_error_effect() {
        for (cause, _, _, _) in TABLE {
            assert!(ServerError::Failed(cause).took_no_effect(), "failed reports no effect");
            assert!(
                !ServerError::Uncertain(cause).took_no_effect(),
                "uncertain never reports no effect"
            );
        }
    }

    /// Claim: The retry answer for each of fourteen causes agrees with the timing table in both forms.
    /// ´claim:host:server-error-retry´
    /// ´test:unit:server-error-retry´
    #[test]
    fn server_error_retry() {
        for (cause, expected, _, _) in TABLE {
            for value in [ServerError::Uncertain(cause), ServerError::Failed(cause)] {
                assert_eq!(value.retry(), expected, "cause fixes retry timing independently of form");
            }
        }
    }

    /// Claim: Each of fourteen causes names the approved concern owner in both forms.
    /// ´claim:host:server-error-concern´
    /// ´test:unit:server-error-concern´
    #[test]
    fn server_error_concern() {
        for (cause, _, expected, _) in TABLE {
            for value in [ServerError::Uncertain(cause), ServerError::Failed(cause)] {
                assert_eq!(value.concern(), expected, "cause fixes concern independently of form");
            }
        }
    }

    /// Claim: All twenty-eight server-error values display exactly their fixed form sentence, approved cause sentence and fixed log sentence, without a diagnostic payload.
    /// ´claim:host:server-error-sentences´
    /// ´test:unit:server-error-sentences´
    #[test]
    fn server_error_sentences() {
        for (cause, _, _, sentence) in TABLE {
            for (value, form) in [
                (ServerError::Failed(cause), "The request failed and took no effect."),
                (
                    ServerError::Uncertain(cause),
                    "The request may have taken effect: the server ended the session or did not report the outcome.",
                ),
            ] {
                assert_eq!(
                    value.to_string(),
                    format!("{form} {sentence} The server's own log holds the detail."),
                    "exact three-part operator sentence"
                );
            }
        }
    }
}
