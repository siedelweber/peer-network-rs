//! Public acquisition and authentication refusals under (´[ROOT-rule:storage:configuration]´).
use pn_host::{Configuration, Refusal, Session};
use std::io::Read;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}
fn fixture(port: u16) -> Vec<u8> {
    format!(r#"{{"transport":"tcp","endpoint":"127.0.0.1","port":"{port}","user":"private_role_fixture","password":"private_password_fixture","database":"private_database_fixture"}}"#).into_bytes()
}

/// Claim: The store case is explicit and checked before acquisition reads any private input, so no address can silently choose a held transport.
/// ´claim:host:case-precedes-private-acquisition´
/// ´test:integration:case-before-input´
#[test]
fn case_before_input() {
    struct Unread;
    impl Read for Unread {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("case refusal must precede input");
        }
    }
    for (case, expected) in [
        (None, Refusal::MissingCase),
        (Some("guarded"), Refusal::HeldCase),
        (Some("guessed"), Refusal::UnknownCase),
    ] {
        assert_eq!(Configuration::acquire(case, &mut Unread).unwrap_err(), expected);
    }
}

/// Claim: A complete private JSON configuration and malformed sentinel input have only role-marked Debug or bounded errors, including their source chains.
/// ´claim:host:configuration-never-formats-private-input´
/// ´test:integration:configuration-carrier´
#[test]
fn configuration_carrier() {
    let bytes = fixture(42101);
    let config = Configuration::acquire(Some("host-secured"), &mut bytes.as_slice()).unwrap();
    let rendered = format!("{config:?}");
    assert!(rendered.contains("[REDACTED]"));
    for sentinel in [
        "127.0.0.1",
        "42101",
        "private_role_fixture",
        "private_password_fixture",
        "private_database_fixture",
    ] {
        assert!(!rendered.contains(sentinel));
    }
    for bytes in [
        b"{\"private_parser_sentinel\":".as_slice(),
        b"{\"user\":\"private_parser_sentinel\",\"user\":\"duplicate\"}",
    ] {
        let error = Configuration::acquire(Some("host-secured"), &mut &*bytes).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private_parser_sentinel"));
        assert!(std::error::Error::source(&error).is_none());
    }
}

/// Claim: An impostor cannot obtain a cleartext, MD5, GSS, SSPI or Kerberos response or bypass SCRAM by sending `AuthenticationOk` before a verified server proof.
/// ´claim:host:only-scram-can-authenticate-the-service´
/// ´test:integration:impostor-authentication´
#[test]
fn impostor_authentication() {
    runtime().block_on(async {
        for (code, expected) in [
            (3_u32, Refusal::Cleartext),
            (5, Refusal::Md5),
            (7, Refusal::Gss),
            (8, Refusal::Gss),
            (9, Refusal::Sspi),
            (2, Refusal::Kerberos),
            (0, Refusal::PrematureAuthenticationOk),
            (99, Refusal::UnsupportedAuthentication),
        ] {
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 42101))
                .await
                .unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u32().await.unwrap();
                let mut startup = vec![0; usize::try_from(length).unwrap() - 4];
                stream.read_exact(&mut startup).await.unwrap();
                stream.write_all(b"R\0\0\0\x08").await.unwrap();
                stream.write_all(&code.to_be_bytes()).await.unwrap();
                let mut response = [0];
                assert_eq!(
                    stream.read(&mut response).await.unwrap(),
                    0,
                    "forbidden authentication received a response"
                );
            });
            let bytes = fixture(42101);
            let config = Configuration::acquire(Some("host-secured"), &mut bytes.as_slice()).unwrap();
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(10), Session::connect(config))
                    .await
                    .unwrap()
                    .unwrap_err(),
                expected
            );
            server.await.unwrap();
        }
    });
}

/// Claim: Closing the service during startup yields a bounded transport refusal rather than retaining the endpoint, role or password in an error.
/// ´claim:host:authentication-disconnect-retains-no-reachability´
/// ´test:integration:authentication-disconnect´
#[test]
fn authentication_disconnect() {
    runtime().block_on(async {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 42102))
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket);
        });
        let bytes = fixture(42102);
        let config = Configuration::acquire(Some("host-secured"), &mut bytes.as_slice()).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), Session::connect(config))
            .await
            .unwrap();
        assert_eq!(result.unwrap_err(), Refusal::Transport);
        server.await.unwrap();
    });
}

/// Claim: The sentinel check detects private retained configuration in the unmodified driver, so role-only shim formatting is checked against a leaking positive control.
/// ´claim:host:stock-configuration-is-a-sensitive-positive-control´
/// ´test:integration:stock-configuration-control´
#[test]
fn stock_configuration_control() {
    let mut stock = tokio_postgres::Config::new();
    stock
        .host("private_endpoint_control")
        .user("private_role_control")
        .dbname("private_database_control");
    let retained = format!("{stock:?}");
    for sentinel in ["private_endpoint_control", "private_role_control", "private_database_control"] {
        assert!(retained.contains(sentinel));
    }
}

/// Claim: An impostor that offers SCRAM and extends the nonce still cannot authenticate without the server's transcript proof; a false proof refuses before placeholder handoff.
/// ´claim:host:scram-requires-the-server-transcript-proof´
/// ´test:integration:impostor-server-proof´
#[test]
fn impostor_server_proof() {
    async fn authentication(stream: &mut tokio::net::TcpStream, code: u32, data: &[u8]) {
        stream.write_u8(b'R').await.unwrap();
        stream.write_u32(u32::try_from(data.len()).unwrap() + 8).await.unwrap();
        stream.write_u32(code).await.unwrap();
        stream.write_all(data).await.unwrap();
    }
    runtime().block_on(async {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 42103))
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u32().await.unwrap();
            let mut startup = vec![0; usize::try_from(length).unwrap() - 4];
            stream.read_exact(&mut startup).await.unwrap();
            authentication(&mut stream, 10, b"SCRAM-SHA-256\0\0").await;
            assert_eq!(stream.read_u8().await.unwrap(), b'p');
            let length = stream.read_u32().await.unwrap();
            let mut initial = vec![0; usize::try_from(length).unwrap() - 4];
            stream.read_exact(&mut initial).await.unwrap();
            let nonce = initial.windows(2).position(|s| s == b"r=").unwrap() + 2;
            let mut continuation = b"r=".to_vec();
            continuation.extend_from_slice(&initial[nonce..]);
            continuation.extend_from_slice(b"server,s=cHVibGljX2ZpeHR1cmVfc2FsdA==,i=4096");
            authentication(&mut stream, 11, &continuation).await;
            assert_eq!(stream.read_u8().await.unwrap(), b'p');
            let length = stream.read_u32().await.unwrap();
            let mut proof = vec![0; usize::try_from(length).unwrap() - 4];
            stream.read_exact(&mut proof).await.unwrap();
            let mut false_signature = b"v=".to_vec();
            false_signature.extend(std::iter::repeat_n(b'A', 43));
            false_signature.push(b'=');
            authentication(&mut stream, 12, &false_signature).await;
            let mut response = [0];
            assert_eq!(stream.read(&mut response).await.unwrap(), 0);
        });
        let bytes = fixture(42103);
        let config = Configuration::acquire(Some("host-secured"), &mut bytes.as_slice()).unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(10), Session::connect(config))
                .await
                .unwrap()
                .unwrap_err(),
            Refusal::ServerSignature
        );
        server.await.unwrap();
    });
}
