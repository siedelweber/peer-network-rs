//! Secret-owning wire framing and socket boundary.
use crate::{
    Configuration, Refusal,
    secret::{Buffer, LIMIT},
};
use std::{
    fmt,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, UnixStream},
};

enum Transport {
    Unix(UnixStream),
    Tcp(TcpStream),
}
pub(crate) struct Socket(Transport);
#[cfg(test)]
pub(crate) fn fixture_pair() -> (Socket, UnixStream) {
    let (socket, peer) = UnixStream::pair().unwrap();
    (Socket(Transport::Unix(socket)), peer)
}
impl fmt::Debug for Socket {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Socket { role: store-transport, value: [REDACTED] }")
    }
}
impl Socket {
    // Caveat: The transport discriminant is lent to the Unix-or-TCP match; its borrow ends at selection because byte-pattern matching requires a slice.
    // (´[ROOT-cav:observe:secret-host-wire-open-field-1]´)
    // Caveat: The Unix socket endpoint is lent to UnixStream::connect; the borrow and its ordinary OS socket-address representation last through the awaited connect because the socket API cannot consume a carrier.
    // (´[ROOT-cav:observe:secret-host-wire-open-text-1]´)
    // Caveat: The numeric TCP endpoint text is lent to IpAddr parsing; the text borrow ends at parse return and the ordinary address lasts through the awaited connect because the network API requires an address value.
    // (´[ROOT-cav:observe:secret-host-wire-open-text-2]´)
    // Caveat: The private port leaves as an ordinary u16 in the TCP connect tuple until the awaited connect completes; the socket API cannot accept a protected port.
    // (´[ROOT-cav:observe:secret-host-wire-open-port-1]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    pub(crate) async fn open(config: &Configuration) -> Result<Self, Refusal> {
        match config.expose_field(/* (´[ROOT-cav:observe:secret-host-wire-open-field-1]´) */ 0) {
            b"unix" => UnixStream::connect(config.expose_text(/* (´[ROOT-cav:observe:secret-host-wire-open-text-1]´) */ 1)?)
                .await
                .map(|s| Self(Transport::Unix(s)))
                .map_err(|_| Refusal::Transport),
            b"tcp" => {
                // Name resolution would copy the private hostname into Tokio's
                // blocking resolver. This first route accepts numeric endpoints.
                let address = config
                    .expose_text(/* (´[ROOT-cav:observe:secret-host-wire-open-text-2]´) */ 1)?
                    .parse::<IpAddr>()
                    .map_err(|_| Refusal::NumericEndpointRequired)?;
                let socket = TcpStream::connect((
                    address,
                    config.expose_port(/* (´[ROOT-cav:observe:secret-host-wire-open-port-1]´) */)?,
                ))
                .await
                .map_err(|_| Refusal::Transport)?;
                socket.set_nodelay(true).map_err(|_| Refusal::Transport)?;
                Ok(Self(Transport::Tcp(socket)))
            }
            _ => Err(Refusal::ConfigurationSyntax),
        }
    }
}
impl AsyncRead for Socket {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().0 {
            Transport::Unix(s) => Pin::new(s).poll_read(cx, bytes),
            Transport::Tcp(s) => Pin::new(s).poll_read(cx, bytes),
        }
    }
}
impl AsyncWrite for Socket {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<std::io::Result<usize>> {
        match &mut self.get_mut().0 {
            Transport::Unix(s) => Pin::new(s).poll_write(cx, bytes),
            Transport::Tcp(s) => Pin::new(s).poll_write(cx, bytes),
        }
    }
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().0 {
            Transport::Unix(s) => Pin::new(s).poll_flush(cx),
            Transport::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().0 {
            Transport::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Transport::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub(crate) struct Frame {
    pub(crate) kind: u8,
    pub(crate) payload: Buffer,
}
// Caveat: Incoming private frame bytes are acquired directly into protected storage until the socket read completes; the read API requires a mutable slice.
// (´[ROOT-cav:observe:secret-host-wire-read-buffer-1]´)
// Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
#[allow(clippy::disallowed_methods)]
pub(crate) async fn read(stream: &mut (impl AsyncRead + Unpin)) -> Result<Frame, Refusal> {
    let kind = stream.read_u8().await.map_err(|_| Refusal::Transport)?;
    let length = stream.read_u32().await.map_err(|_| Refusal::Transport)?;
    let length = usize::try_from(length).map_err(|_| Refusal::RepresentationLimit)?;
    if !(4..=LIMIT + 4).contains(&length) {
        return Err(Refusal::RepresentationLimit);
    }
    let mut payload = Buffer::with_capacity(length - 4);
    stream
        .read_exact(&mut payload.expose_storage(/* (´[ROOT-cav:observe:secret-host-wire-read-buffer-1]´) */)[..length - 4])
        .await
        .map_err(|_| Refusal::Transport)?;
    payload.set_length(length - 4)?;
    Ok(Frame { kind, payload })
}
// Caveat: Private encoded frame bytes are borrowed only for the socket write until it completes; the socket API requires a slice.
// (´[ROOT-cav:observe:secret-host-wire-send-buffer-1]´)
// Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
#[allow(clippy::disallowed_methods)]
pub(crate) async fn send(stream: &mut (impl AsyncWrite + Unpin), kind: u8, payload: &[u8]) -> Result<(), Refusal> {
    if payload.len() > LIMIT {
        return Err(Refusal::RepresentationLimit);
    }
    let length = u32::try_from(payload.len() + 4).map_err(|_| Refusal::RepresentationLimit)?;
    let mut frame = Buffer::with_capacity(payload.len() + 5);
    frame.append(&[kind])?;
    frame.append(&length.to_be_bytes())?;
    frame.append(payload)?;
    stream
        .write_all(frame.expose_bytes(/* (´[ROOT-cav:observe:secret-host-wire-send-buffer-1]´) */))
        .await
        .map_err(|_| Refusal::Transport)?;
    stream.flush().await.map_err(|_| Refusal::Transport)
}
// Caveat: The configured user is lent to the startup field loop and copied by payload.append into protected packet storage; the borrow ends with that loop because byte framing requires slices.
// (´[ROOT-cav:observe:secret-host-wire-startup-field-3]´)
// Caveat: The configured database is lent to the startup field loop and copied by payload.append into protected packet storage; the borrow ends with that loop because byte framing requires slices.
// (´[ROOT-cav:observe:secret-host-wire-startup-field-5]´)
// Caveat: The private startup packet is lent to Socket::write_all; the borrow ends when the awaited write completes because the socket API requires a byte slice.
// (´[ROOT-cav:observe:secret-host-wire-startup-buffer-2]´)
// Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
#[allow(clippy::disallowed_methods)]
pub(crate) async fn startup(stream: &mut Socket, config: &Configuration) -> Result<(), Refusal> {
    let mut payload = Buffer::new();
    payload.append(&196_608_u32.to_be_bytes())?;
    for (name, value) in [
        (
            b"user".as_slice(),
            config.expose_field(/* (´[ROOT-cav:observe:secret-host-wire-startup-field-3]´) */ 3),
        ),
        (
            b"database",
            config.expose_field(/* (´[ROOT-cav:observe:secret-host-wire-startup-field-5]´) */ 5),
        ),
        (b"client_encoding", b"UTF8"),
        (b"TimeZone", b"UTC"),
        (b"DateStyle", b"ISO, MDY"),
        (b"IntervalStyle", b"postgres"),
        (b"application_name", b""),
        (b"search_path", b"\"$user\", public"),
    ] {
        payload.append(name)?;
        payload.append(&[0])?;
        payload.append(value)?;
        payload.append(&[0])?;
    }
    payload.append(&[0])?;
    stream
        .write_u32(u32::try_from(payload.len() + 4).map_err(|_| Refusal::RepresentationLimit)?)
        .await
        .map_err(|_| Refusal::Transport)?;
    stream
        .write_all(payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-wire-startup-buffer-2]´) */))
        .await
        .map_err(|_| Refusal::Transport)?;
    stream.flush().await.map_err(|_| Refusal::Transport)
}
