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
impl fmt::Debug for Socket {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Socket { role: store-transport, value: [REDACTED] }")
    }
}
impl Socket {
    pub(crate) async fn open(config: &Configuration) -> Result<Self, Refusal> {
        match config.field(0) {
            b"unix" => UnixStream::connect(config.text(1)?)
                .await
                .map(|s| Self(Transport::Unix(s)))
                .map_err(|_| Refusal::Transport),
            b"tcp" => {
                // Name resolution would copy the private hostname into Tokio's
                // blocking resolver. This first route accepts numeric endpoints.
                let address = config
                    .text(1)?
                    .parse::<IpAddr>()
                    .map_err(|_| Refusal::NumericEndpointRequired)?;
                TcpStream::connect((address, config.port()?))
                    .await
                    .map(|s| Self(Transport::Tcp(s)))
                    .map_err(|_| Refusal::Transport)
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
pub(crate) async fn read(stream: &mut (impl AsyncRead + Unpin)) -> Result<Frame, Refusal> {
    let kind = stream.read_u8().await.map_err(|_| Refusal::Transport)?;
    let length = stream.read_u32().await.map_err(|_| Refusal::Transport)?;
    let length = usize::try_from(length).map_err(|_| Refusal::RepresentationLimit)?;
    if !(4..=LIMIT + 4).contains(&length) {
        return Err(Refusal::RepresentationLimit);
    }
    let mut payload = Buffer::new();
    stream
        .read_exact(&mut payload.storage()[..length - 4])
        .await
        .map_err(|_| Refusal::Transport)?;
    payload.set_length(length - 4)?;
    Ok(Frame { kind, payload })
}
pub(crate) async fn send(stream: &mut (impl AsyncWrite + Unpin), kind: u8, payload: &[u8]) -> Result<(), Refusal> {
    let length = u32::try_from(payload.len() + 4).map_err(|_| Refusal::RepresentationLimit)?;
    stream.write_u8(kind).await.map_err(|_| Refusal::Transport)?;
    stream.write_u32(length).await.map_err(|_| Refusal::Transport)?;
    stream.write_all(payload).await.map_err(|_| Refusal::Transport)?;
    stream.flush().await.map_err(|_| Refusal::Transport)
}
pub(crate) async fn startup(stream: &mut Socket, config: &Configuration) -> Result<(), Refusal> {
    let mut payload = Buffer::new();
    payload.append(&196_608_u32.to_be_bytes())?;
    for (name, value) in [
        (b"user".as_slice(), config.field(3)),
        (b"database", config.field(5)),
        (b"client_encoding", b"UTF8"),
    ] {
        payload.append(name)?;
        payload.append(&[0])?;
        payload.append(value)?;
        payload.append(&[0])?;
    }
    payload.append(&[0])?;
    stream
        .write_u32(u32::try_from(payload.bytes().len() + 4).map_err(|_| Refusal::RepresentationLimit)?)
        .await
        .map_err(|_| Refusal::Transport)?;
    stream.write_all(payload.bytes()).await.map_err(|_| Refusal::Transport)?;
    stream.flush().await.map_err(|_| Refusal::Transport)
}
