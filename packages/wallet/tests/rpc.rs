//! Real daemon genesis reads; fixture production and credentials live outside the crate.
use pn_wallet::{Limits, Provisioning, Read, ReadResult, RpcClient, RpcConfig, RpcLimits, RpcLink, RpcRefusal};
use secrecy::{SecretBox, SecretString};
use std::{fs::File, io::Read as _, path::PathBuf};

fn root() -> PathBuf {
    std::env::var_os("PN_WALLET_TEST_ROOT")
        .map(PathBuf::from)
        .expect("real Elements fixture is required")
}
fn limits() -> Limits {
    Limits {
        bytes: 4_000_000,
        items: 4096,
        script: 10_000,
        witness: 65_536,
        allocation: 134_217_728,
    }
}
fn declaration() -> Provisioning {
    serde_json::from_slice(&std::fs::read(root().join("provisioning.json")).unwrap()).unwrap()
}

fn config() -> RpcConfig {
    config_for("cookie", None)
}

fn config_for(cookie: &str, endpoint: Option<&str>) -> RpcConfig {
    use secrecy::{ExposeSecret as _, ExposeSecretMut as _};
    #[derive(serde::Deserialize)]
    struct Bootstrap {
        endpoint: String,
        port: u16,
        uid: u32,
    }
    // Private fixture bootstrap is acquired into an erasing carrier before parsing.
    let mut bytes = SecretBox::new(vec![0; 4096].into_boxed_slice());
    let mut file = File::open(root().join("reader.json")).unwrap();
    let length = file.read(bytes.expose_secret_mut()).unwrap();
    let value: Bootstrap = serde_json::from_slice(&bytes.expose_secret()[..length]).unwrap();
    RpcConfig::new(
        RpcLink::HostSecured,
        SecretString::from(endpoint.map_or(value.endpoint, String::from)),
        SecretBox::new(Box::new(value.port)),
        File::open(root()).unwrap(),
        SecretString::from(cookie),
        SecretBox::new(Box::new(value.uid)),
    )
}

/// Claim: The real declared Elements daemon supplies count zero and matching raw genesis header and block through the cookie reader, while a separately credentialed external harness records the same genesis without admitting producer methods into the client.
/// ´claim:wallet:rpc-genesis-reads-match-provisioning´
/// ´test:integration:genesis-reads´
#[test]
fn genesis_reads() {
    let declaration = declaration();
    let client = RpcClient::new(config(), RpcLimits::default(), limits(), &declaration, "wallet-genesis-1").unwrap();
    assert!(matches!(client.read(Read::BlockCount).unwrap(), ReadResult::Count(0)));
    assert!(matches!(client.read(Read::BlockHash(0)).unwrap(),ReadResult::Hash(hash) if hash==declaration.genesis));
    assert!(
        matches!(client.read(Read::BlockHeader(declaration.genesis)).unwrap(),ReadResult::Header(header) if header==declaration.header)
    );
    let ReadResult::Block(block) = client.read(Read::Block(declaration.genesis)).unwrap() else {
        panic!("typed block required");
    };
    assert_eq!(block.header, declaration.header);
    assert_ne!(block.transactions.len(), 0);
    let separation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("credential-separation.json")).unwrap()).unwrap();
    assert_eq!(
        separation,
        serde_json::json!({"separate":true,"producer_cookie":false,"reader_cookie":true,"chain":"elementsregtest"})
    );
    let error = client.read(Read::BlockHash(u64::MAX)).unwrap_err();
    assert!(matches!(error, RpcRefusal::Remote { .. }));
}

/// Claim: Checked provisioning refuses wrong binary, chain, run, launch parameters, trivial challenge and raw genesis identity before exposing a ready reader.
/// ´claim:wallet:rpc-provisioning-rejects-mismatches´
/// ´test:integration:provisioning-refusals´
#[test]
fn provisioning_refusals() {
    let original = declaration();
    let mut cases = Vec::new();
    let mut changed = original.clone();
    changed.binary.push('x');
    cases.push(changed);
    let mut changed = original.clone();
    changed.chain = "regtest".into();
    cases.push(changed);
    let mut changed = original.clone();
    changed.run = "other-run".into();
    cases.push(changed);
    let mut changed = original.clone();
    changed.parameters.insert("con_signed_blocks".into(), "0".into());
    cases.push(changed);
    let mut changed = original.clone();
    changed.challenge = vec![81];
    cases.push(changed);
    let mut changed = original.clone();
    changed.genesis[0] ^= 1;
    cases.push(changed);
    let mut changed = original;
    changed.header[4] ^= 1;
    cases.push(changed);
    for declaration in cases {
        assert_eq!(
            RpcClient::new(config(), RpcLimits::default(), limits(), &declaration, "wallet-genesis-1").unwrap_err(),
            RpcRefusal::Provisioning
        );
    }
    assert_eq!(
        RpcClient::new(
            config_for("cookie", Some("127.0.0.2")),
            RpcLimits::default(),
            limits(),
            &declaration(),
            "wallet-genesis-1"
        )
        .unwrap_err(),
        RpcRefusal::Transport
    );
}

/// Claim: The real daemon rejects a well-formed wrong cookie with a typed authentication refusal; missing, partial and ACL-exposed cookies refuse locally without a password fallback or private error source.
/// ´claim:wallet:rpc-authentication-failures-are-secret-safe´
/// ´test:integration:authentication-refusals´
#[test]
fn authentication_refusals() {
    for (cookie, expected) in [
        ("wrong-cookie", RpcRefusal::Authentication),
        ("missing-cookie", RpcRefusal::Cookie),
        ("partial-cookie", RpcRefusal::Cookie),
        ("acl-cookie", RpcRefusal::Cookie),
        ("acl-parent/cookie", RpcRefusal::Cookie),
    ] {
        let error = RpcClient::new(
            config_for(cookie, None),
            RpcLimits::default(),
            limits(),
            &declaration(),
            "wallet-genesis-1",
        )
        .unwrap_err();
        assert_eq!(error, expected);
        assert!(std::error::Error::source(&error).is_none());
    }
}

/// Claim: Real genesis reads and public service diagnostics survive default and trace observation unchanged, while retained output and content artifacts contain neither the endpoint nor cookie identity, bytes or private fixture path.
/// ´claim:wallet:rpc-observation-retains-public-results-only´
/// ´test:integration:observations´
#[test]
fn observations() {
    if std::env::var_os("PN_WALLET_OBSERVATION_CHILD").is_some() {
        let guard = cli_common::observation::bootstrap(true, false, tracing::Level::INFO).unwrap();
        genesis_reads();
        authentication_refusals();
        drop(guard);
        return;
    }
    let bootstrap: serde_json::Value = serde_json::from_slice(&std::fs::read(root().join("reader.json")).unwrap()).unwrap();
    let cookie = std::fs::read_to_string(root().join("cookie")).unwrap();
    for level in ["default", "trace"] {
        let artifact = root().with_file_name(format!("wallet-observation-{level}"));
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "observations", "--nocapture"])
            .env("PN_WALLET_OBSERVATION_CHILD", "1")
            .env("PN_OBSERVE_LEVEL", level)
            .env("PN_OBSERVE_ARTIFACT_DIR", &artifact)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let mut captured = String::from_utf8(output.stderr).unwrap();
        captured.push_str(&String::from_utf8(output.stdout).unwrap());
        if artifact.exists() {
            for entry in std::fs::read_dir(&artifact).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_file() {
                    captured.push_str(&String::from_utf8_lossy(&std::fs::read(entry.path()).unwrap()));
                }
            }
        }
        for (role, private) in [
            ("endpoint", bootstrap["endpoint"].as_str().unwrap()),
            ("cookie", cookie.as_str()),
            ("username", "__cookie__"),
            ("path", root().to_str().unwrap()),
        ] {
            assert!(!captured.contains(private), "private {role} reached observation");
        }
        let private_port = bootstrap["port"].as_u64().unwrap().to_string();
        assert!(
            !captured
                .split(|character: char| !character.is_ascii_digit() && character != '.')
                .any(|token| token == private_port),
            "private port reached observation"
        );
        assert!(captured.contains("metric_summary"));
        assert!(captured.contains("Remote"));
        if level == "trace" {
            for public in [
                "getblockcount",
                "getblockhash",
                "getblockheader",
                "getblock",
                "elapsed_ns",
                "result_bytes",
                "Count",
                "Header",
                "Block",
            ] {
                assert!(captured.contains(public), "public field missing: {public}");
            }
        }
    }
}

/// Claim: An unmodified standard TCP client retains the private endpoint and port in its Debug representation, demonstrating why its socket must remain behind the wallet's non-formatting bootstrap boundary.
/// ´claim:wallet:generic-rpc-socket-retains-private-reachability´
/// ´test:integration:generic-negative´
#[test]
fn generic_negative() {
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(root().join("reader.json")).unwrap()).unwrap();
    let endpoint = value["endpoint"].as_str().unwrap();
    let port = u16::try_from(value["port"].as_u64().unwrap()).unwrap();
    let stream = std::net::TcpStream::connect((endpoint, port)).unwrap();
    let retained = format!("{stream:?}");
    assert!(retained.contains(endpoint));
    assert!(retained.contains(&port.to_string()));
}

fn harness(action: &str, directory: &std::path::Path) -> std::process::Output {
    std::process::Command::new("python3")
        .args(["-B", "ci/wallet_elements.py", action, "--root"])
        .arg(directory)
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .unwrap()
}

struct Running(PathBuf);
impl Drop for Running {
    fn drop(&mut self) {
        assert!(harness("stop", &self.0).status.success(), "fixture shutdown failed");
    }
}

/// Claim: One reader acquires the daemon's rotated cookie after a real restart, returns a single authentication refusal for restored stale bytes, and succeeds only on a later explicit call after the fresh cookie is restored.
/// ´claim:wallet:rpc-cookie-rotation-has-no-replay´
/// ´test:integration:rotation´
#[test]
fn rotation() {
    if std::env::var_os("PN_WALLET_ROTATION_CHILD").is_some() {
        let client = RpcClient::new(config(), RpcLimits::default(), limits(), &declaration(), "wallet-genesis-1").unwrap();
        let old = std::fs::read(root().join("cookie")).unwrap();
        assert!(matches!(client.read(Read::BlockCount), Ok(ReadResult::Count(0))));
        assert!(harness("restart", &root()).status.success(), "fixture restart failed");
        let fresh = std::fs::read(root().join("cookie")).unwrap();
        assert_ne!(old, fresh);
        assert!(matches!(client.read(Read::BlockCount), Ok(ReadResult::Count(0))));
        std::fs::write(root().join("cookie"), old).unwrap();
        assert_eq!(client.read(Read::BlockCount).unwrap_err(), RpcRefusal::Authentication);
        std::fs::write(root().join("cookie"), fresh).unwrap();
        assert!(matches!(client.read(Read::BlockCount), Ok(ReadResult::Count(0))));
        return;
    }
    let directory = root().with_file_name(format!("wallet-rotation-{}", std::process::id()));
    let running = Running(directory.clone());
    assert!(harness("start", &directory).status.success(), "fixture start failed");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "rotation", "--nocapture"])
        .env("PN_WALLET_ROTATION_CHILD", "1")
        .env("PN_WALLET_TEST_ROOT", &directory)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    drop(running);
}
