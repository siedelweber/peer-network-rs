//! Real daemon genesis reads; fixture production and credentials live outside the crate.
mod oracle;
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

/// Claim: Checked provisioning refuses an undeclared harness binary directory, wrong binary, chain, run, launch parameters, trivial challenge and raw genesis identity before exposing a ready reader; refused and unreachable peers return the transport refusal within the single exchange budget.
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
    // TEST-NET-1 is never routed to a peer: the bounded connect spends at most
    // the one exchange budget and returns the transport refusal.
    let budget = RpcLimits {
        deadline: std::time::Duration::from_secs(2),
        ..RpcLimits::default()
    };
    let started = std::time::Instant::now();
    let unreachable = RpcClient::new(
        config_for("cookie", Some("192.0.2.1")),
        budget,
        limits(),
        &declaration(),
        "wallet-genesis-1",
    );
    assert_eq!(unreachable.unwrap_err(), RpcRefusal::Transport);
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    let unset = std::process::Command::new("python3")
        .args(["-B", "ci/wallet_elements.py", "start", "--root"])
        .arg(root().with_file_name(format!("wallet-unset-{}", std::process::id())))
        .env_remove("PN_ELEMENTS_BIN")
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .unwrap();
    assert_eq!(unset.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unset.stderr).contains("PN_ELEMENTS_BIN"));
    assert!(!root().with_file_name(format!("wallet-unset-{}", std::process::id())).exists());
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
    producer(action, directory, &[])
}

fn producer(action: &str, directory: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    std::process::Command::new("python3")
        .args(["-B", "ci/wallet_elements.py", action, "--root"])
        .arg(directory)
        .args(arguments)
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .unwrap()
}

/// Require a successful harness action; a failure names the exit status and the harness's public cause line.
fn require(output: std::process::Output, action: &str) -> std::process::Output {
    assert!(
        output.status.success(),
        "{action} failed: {} {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    output
}

struct Running(PathBuf);
impl Drop for Running {
    fn drop(&mut self) {
        require(harness("stop", &self.0), "fixture shutdown");
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
        require(harness("restart", &root()), "fixture restart");
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
    require(harness("start", &directory), "fixture start");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "rotation", "--nocapture"])
        .env("PN_WALLET_ROTATION_CHILD", "1")
        .env("PN_WALLET_TEST_ROOT", &directory)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    drop(running);
}

fn compare(actual: &pn_wallet::Transaction, expected: &oracle::Transaction) {
    let actual = actual.fields();
    assert_eq!(actual.version, expected.version);
    assert_eq!(actual.lock_time, expected.lock_time);
    assert_eq!(actual.inputs.len(), expected.inputs.len());
    assert_eq!(actual.outputs.len(), expected.outputs.len());
    for (a, b) in actual.inputs.iter().zip(&expected.inputs) {
        assert_eq!(a.outpoint, b.outpoint);
        assert_eq!(a.pegin, b.pegin);
        assert_eq!(a.script, b.script);
        assert_eq!(a.sequence, b.sequence);
        assert_eq!(a.issuance, b.issuance);
        assert_eq!(a.witness, b.witness);
        assert_eq!(a.has_issuance, b.issuance != vec![0; 66]);
    }
    for (a, b) in actual.outputs.iter().zip(&expected.outputs) {
        assert_eq!(a.asset, b.asset);
        assert_eq!(a.value, b.value);
        assert_eq!(a.nonce, b.nonce);
        assert_eq!(a.script, b.script);
        assert_eq!(a.witness, b.witness);
    }
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn locator(value: &serde_json::Value) -> [u8; 32] {
    hex(value.as_str().unwrap()).try_into().unwrap()
}

fn client() -> RpcClient {
    RpcClient::new(config(), RpcLimits::default(), limits(), &declaration(), "wallet-genesis-1").unwrap()
}

fn genesis_funding(evidence: &serde_json::Value) {
    let raw = hex(&std::fs::read_to_string(root().join("genesis-block.hex")).unwrap());
    let (header, transactions) = oracle::block(&raw).unwrap();
    let ReadResult::Block(actual) = client().read(Read::Block(declaration().genesis)).unwrap() else {
        panic!("typed genesis required");
    };
    assert_eq!(actual.header, header);
    assert_eq!(actual.transactions.len(), transactions.len());
    let mut asset = hex(evidence["fee_asset"].as_str().unwrap());
    asset.reverse();
    asset.insert(0, 1);
    let mut funding = 0u64;
    for (actual, expected) in actual.transactions.iter().zip(&transactions) {
        compare(actual, expected);
        for input in expected.inputs.iter().filter(|input| input.issuance != vec![0; 66]) {
            assert_eq!(input.issuance.last(), Some(&0), "genesis carries no reissuance token");
        }
        for output in &expected.outputs {
            assert_eq!(output.value[0], 1, "genesis amounts are explicit");
            let amount = u64::from_be_bytes(output.value[1..].try_into().unwrap());
            if amount == 0 {
                // The unfunded coinbase output carries the explicit null asset.
                let mut null = vec![1];
                null.extend([0; 32]);
                assert!(output.asset == asset || output.asset == null, "no other genesis asset");
            } else {
                assert_eq!(output.asset, asset, "genesis funds only the pegged fee asset");
                assert_eq!(output.script, [0x51], "genesis funding is anyone-can-spend");
                funding += amount;
            }
        }
    }
    assert_eq!(funding, 1_000_000_000_000);
}

fn outpoint(transaction: &serde_json::Value, index: u32) -> Vec<u8> {
    let mut bytes = hex(transaction.as_str().unwrap());
    bytes.reverse();
    bytes.extend(index.to_le_bytes());
    bytes
}

/// The whole genesis output moves to one producer-owned reserve in block 1,
/// and the stock issuance spends that reserve: no genesis value is unaccounted.
fn reserve_funding(evidence: &serde_json::Value, first: &[oracle::Transaction]) {
    let genesis = evidence["genesis"]["tx"].as_array().unwrap();
    let mut funded = Vec::new();
    for tx in genesis {
        for output in tx["vout"].as_array().unwrap() {
            if output["scriptPubKey"]["hex"] == "51" && output["value"].as_f64().is_some_and(|value| value > 0.0) {
                funded.push((tx, output));
            }
        }
    }
    assert_eq!(funded.len(), 1);
    let (tx, output) = funded[0];
    let source = outpoint(&tx["txid"], u32::try_from(output["n"].as_u64().unwrap()).unwrap());
    let raw = hex(&std::fs::read_to_string(root().join("reserve.hex")).unwrap());
    let reserve = oracle::transaction(&raw).unwrap();
    assert_eq!(first.len(), 2, "block 1 carries the coinbase and the reserve");
    assert_eq!(first[1].inputs.len(), reserve.inputs.len());
    assert_eq!(first[1].outputs.len(), reserve.outputs.len());
    assert_eq!(reserve.inputs.len(), 1);
    assert_eq!(reserve.inputs[0].outpoint, source);
    assert_eq!(first[1].inputs[0].outpoint, source);
    let mut asset = hex(evidence["fee_asset"].as_str().unwrap());
    asset.reverse();
    asset.insert(0, 1);
    let mut total = 0u64;
    for output in &reserve.outputs {
        assert_eq!(output.asset, asset);
        assert_eq!(output.value[0], 1);
        total += u64::from_be_bytes(output.value[1..].try_into().unwrap());
    }
    assert_eq!(total, 1_000_000_000_000, "the reserve carries the whole genesis funding");
    assert_eq!(reserve.outputs.iter().filter(|output| output.script.is_empty()).count(), 1);
    let raw = hex(&std::fs::read_to_string(root().join("issuance.hex")).unwrap());
    let issuance = oracle::transaction(&raw).unwrap();
    let spent = outpoint(&evidence["transactions"]["reserve"], 0);
    assert!(issuance.inputs.iter().any(|input| input.outpoint[..32] == spent[..32]));
}

/// Claim: The real BDB daemon accepts five signed blocks and refuses an invalid signature and a solved trivial replacement challenge; typed raw reads agree field-for-field with the independent oracle; the single anyone-can-spend genesis output moves whole to a producer-owned reserve funding one explicit, token-free issuance of the declared stock to a producer-owned destination, with zero explicit destruction in grants, fees and transfers and exactly one token destroyed.
/// ´claim:wallet:rpc-signed-fixtures-match-independent-layouts´
/// ´test:integration:signed-reads´
#[test]
fn signed_reads() {
    if std::env::var_os("PN_WALLET_SIGNED_CHILD").is_none() {
        let directory = root().with_file_name(format!("wallet-signed-{}", std::process::id()));
        let running = Running(directory.clone());
        let produced = require(harness("signed", &directory), "signed fixture production");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "signed_reads", "--nocapture"])
            .env("PN_WALLET_SIGNED_CHILD", "1")
            .env("PN_WALLET_TEST_ROOT", &directory)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        std::fs::write(directory.join("route-summary.log"), &produced.stdout).unwrap();
        drop(running);
        return;
    }
    let evidence: serde_json::Value = serde_json::from_slice(&std::fs::read(root().join("signed.json")).unwrap()).unwrap();
    assert_eq!(evidence["invalid_signature"], "block-proof-invalid");
    assert_eq!(evidence["trivial_challenge"], "invalid-dyna-fed");
    assert_eq!(evidence["producer_descriptors"], false);
    assert_ne!(evidence["asset"], evidence["fee_asset"]);
    assert_eq!(evidence["stock_owned"], true);
    assert_eq!(evidence["initial_units"], 1_000_000_000_000u64);
    genesis_funding(&evidence);
    let separation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("credential-separation.json")).unwrap()).unwrap();
    assert_eq!(separation["separate"], true);
    assert_eq!(separation["producer_cookie"], false);
    let blocks = evidence["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 5);
    let reader = client();
    assert!(matches!(reader.read(Read::BlockCount).unwrap(), ReadResult::Count(5)));
    for (index, hash) in blocks.iter().enumerate() {
        let raw = hex(&std::fs::read_to_string(root().join(format!("block-{}.hex", index + 1))).unwrap());
        let (header, transactions) = oracle::block(&raw).unwrap();
        let ReadResult::Block(block) = reader.read(Read::Block(locator(hash))).unwrap() else {
            panic!("typed block required");
        };
        assert_eq!(block.header, header);
        assert_eq!(block.transactions.len(), transactions.len());
        for (actual, expected) in block.transactions.iter().zip(&transactions) {
            compare(actual, expected);
        }
        if index == 0 {
            reserve_funding(&evidence, &transactions);
        }
    }
    let mut asset = hex(evidence["asset"].as_str().unwrap());
    asset.reverse();
    asset.insert(0, 1);
    for (index, role) in ["issuance", "grant", "transfer", "destruction"].into_iter().enumerate() {
        let raw = hex(&std::fs::read_to_string(root().join(format!("{role}.hex"))).unwrap());
        let expected = oracle::transaction(&raw).unwrap();
        let reader = client();
        let ReadResult::Transaction(actual) = reader
            .read(Read::Transaction {
                transaction: locator(&evidence["transactions"][role]),
                block: locator(&blocks[index + 1]),
            })
            .unwrap()
        else {
            panic!("typed transaction required");
        };
        compare(&actual, &expected);
        let mut destroyed = 0u64;
        let mut supply = 0u64;
        for output in &expected.outputs {
            if output.script.first() == Some(&0x6a) {
                assert_eq!(output.asset, asset, "destruction asset must be explicit");
                assert_eq!(output.value.len(), 9, "destruction amount must be explicit");
            }
            if output.asset == asset {
                assert_eq!(output.value.len(), 9, "fixture asset amounts must be explicit");
                assert_eq!(output.value[0], 1);
                let amount = u64::from_be_bytes(output.value[1..].try_into().unwrap());
                supply += amount;
                if role == "issuance" {
                    assert_eq!(output.script, hex(evidence["stock_script"].as_str().unwrap()));
                }
                if output.script.first() == Some(&0x6a) {
                    destroyed += amount;
                }
            }
            if output.script.is_empty() {
                assert_ne!(output.asset, asset, "fees must use the separate fee asset");
            }
        }
        assert_eq!(destroyed, if role == "destruction" { 100_000_000 } else { 0 });
        if role == "issuance" {
            stock_issuance(&expected, supply);
        }
    }
}

/// The stock is one fresh explicit issuance of the declared units, with no reissuance token.
fn stock_issuance(expected: &oracle::Transaction, supply: u64) {
    assert_eq!(supply, 1_000_000_000_000);
    assert_eq!(
        expected.inputs.iter().filter(|input| input.issuance != vec![0; 66]).count(),
        1
    );
    let issuance = expected.inputs.iter().find(|input| input.issuance != vec![0; 66]).unwrap();
    assert_eq!(issuance.issuance.len(), 74);
    assert_eq!(
        &issuance.issuance[..64],
        &[0; 64],
        "fresh issuance, no blinding nonce or contract hash"
    );
    assert_eq!(issuance.issuance[64], 1);
    assert_eq!(
        u64::from_be_bytes(issuance.issuance[65..73].try_into().unwrap()),
        1_000_000_000_000
    );
    assert_eq!(issuance.issuance.last(), Some(&0), "no reissuance token amount");
}

/// Claim: A real genesis block exceeding a declared decoder byte limit or a lowered response-byte ceiling holds the reader with that block and Bytes cause, and later count or different-block requests return the same hold without advancing past it.
/// ´claim:wallet:rpc-real-block-limit-holds-reader´
/// ´test:integration:reader-limit-hold´
#[test]
fn reader_limit_hold() {
    let declaration = declaration();
    let raw = hex(&std::fs::read_to_string(root().join("genesis-block.hex")).unwrap());
    let mut decode = limits();
    decode.bytes = raw.len() - 1;
    assert!(decode.bytes > declaration.header.len());
    let reader = RpcClient::new(config(), RpcLimits::default(), decode, &declaration, "wallet-genesis-1").unwrap();
    let expected = RpcRefusal::Held {
        block: declaration.genesis,
        limit: pn_wallet::Refusal::Bytes,
    };
    assert_eq!(reader.read(Read::Block(declaration.genesis)).unwrap_err(), expected);
    assert_eq!(reader.read(Read::BlockCount).unwrap_err(), expected);
    assert_eq!(reader.read(Read::Block([42; 32])).unwrap_err(), expected);
    // A ceiling admitting the hex header and its envelope but not the block.
    assert!(raw.len() > declaration.header.len() + 256);
    let ceiling = RpcLimits {
        response_bytes: 2 * declaration.header.len() + 256,
        ..RpcLimits::default()
    };
    let reader = RpcClient::new(config(), ceiling, limits(), &declaration, "wallet-genesis-1").unwrap();
    assert_eq!(reader.read(Read::Block(declaration.genesis)).unwrap_err(), expected);
    assert_eq!(reader.read(Read::BlockCount).unwrap_err(), expected);
    assert_eq!(reader.read(Read::Block([42; 32])).unwrap_err(), expected);
}

fn advance(arguments: &[&str]) {
    require(producer("advance", &root(), arguments), "producer advance");
}

fn tip() -> u64 {
    let ReadResult::Count(count) = client().read(Read::BlockCount).unwrap() else {
        panic!("typed count required");
    };
    count
}

fn chain_hash(height: u64) -> [u8; 32] {
    let ReadResult::Hash(hash) = client().read(Read::BlockHash(height)).unwrap() else {
        panic!("typed hash required");
    };
    hash
}

struct Burn {
    transaction: [u8; 32],
    output: u32,
    binding: [[u8; 32]; 3],
}

fn burns() -> Vec<Burn> {
    let rows: serde_json::Value = serde_json::from_slice(&std::fs::read(root().join("burns.json")).unwrap()).unwrap();
    rows.as_array()
        .unwrap()
        .iter()
        .map(|row| Burn {
            transaction: locator(&row["transaction"]),
            output: u32::try_from(row["output"].as_u64().unwrap()).unwrap(),
            binding: ["run", "target", "request"].map(|key| locator(&row[key])),
        })
        .collect()
}

fn read_transaction(burn: &Burn, block: [u8; 32]) -> pn_wallet::Transaction {
    let ReadResult::Transaction(transaction) = client()
        .read(Read::Transaction {
            transaction: burn.transaction,
            block,
        })
        .unwrap()
    else {
        panic!("typed transaction required");
    };
    transaction
}

fn read_block(block: [u8; 32]) -> pn_wallet::Block {
    let ReadResult::Block(block) = client().read(Read::Block(block)).unwrap() else {
        panic!("typed block required");
    };
    block
}

/// The cookie reader's transaction at the claimed block, with its explicit amount selected by the decoder.
fn located(burn: &Burn, height: u64, block: [u8; 32], asset: &[u8; 32]) -> pn_wallet::Evidence {
    let [run, target, request] = &burn.binding;
    let output = usize::try_from(burn.output).unwrap();
    let amount = pn_wallet::evidence_amount(&read_transaction(burn, block), output, asset, run, target, request).unwrap();
    pn_wallet::Evidence {
        transaction: burn.transaction,
        output: burn.output,
        block,
        height,
        amount,
    }
}

/// Active-chain hashes at every height the decision needs: the located evidence and the last pinned floor.
fn observation(evidence: Vec<pn_wallet::Evidence>, last: Option<&pn_wallet::View>) -> pn_wallet::Observation {
    let tip = tip();
    let mut heights: Vec<u64> = evidence.iter().map(|evidence| evidence.height).collect();
    heights.extend(last.and_then(|view| view.floor).map(|(height, _)| height));
    let hashes = heights
        .into_iter()
        .filter(|height| *height <= tip)
        .map(|height| (height, chain_hash(height)))
        .collect();
    pn_wallet::Observation { tip, hashes, evidence }
}

/// Observe after a change that keeps the pinned block: the total, the floor and the pinned reads are unchanged.
fn kept(
    settlement: &mut pn_wallet::Settlement,
    moved: &[pn_wallet::Evidence],
    last: &pn_wallet::View,
    reads: (&Burn, &pn_wallet::Transaction, &pn_wallet::Block),
) -> pn_wallet::View {
    let view = settlement.observe(&observation(moved.to_vec(), Some(last))).unwrap();
    assert_eq!(
        (view.pinned_total, view.pinned.len(), view.floor),
        (300_000_000, 2, last.floor)
    );
    let (burn, transaction, block) = reads;
    let (_, pinned) = view.floor.unwrap();
    assert_eq!(&read_transaction(burn, pinned), transaction);
    assert_eq!(&read_block(pinned), block);
    view
}

/// Claim: On the real signed chain, two explicit burn outputs stay pending with four and five successors, set no floor, and pin at six with their block as the floor; a shallow replacement made with invalidateblock and freshly signed blocks changes only pending evidence and refuses the replaced locator, although the node still serves that transaction; the same outpoints re-mined in a new block and reported repeatedly count once; the pinned total, floor and pinned reads stay unchanged after later blocks, a replacement of the newest blocks and a replacement reaching below the tip-minus-six cutoff above the pinned block; and a replacement of the pinned block is a run fault that retains the pinned total. Epoch snapshot derivation is not performed here; it remains with bite 5.
/// ´claim:wallet:rpc-settlement-forks-keep-the-pinned-floor´
/// ´test:integration:settlement-forks´
#[test]
fn settlement_forks() {
    use pn_wallet::SettlementRefusal;
    if std::env::var_os("PN_WALLET_SETTLEMENT_CHILD").is_none() {
        let directory = root().with_file_name(format!("wallet-settlement-{}", std::process::id()));
        let running = Running(directory.clone());
        require(harness("settlement", &directory), "settlement fixture production");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "settlement_forks", "--nocapture"])
            .env("PN_WALLET_SETTLEMENT_CHILD", "1")
            .env("PN_WALLET_TEST_ROOT", &directory)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        drop(running);
        return;
    }
    let signed: serde_json::Value = serde_json::from_slice(&std::fs::read(root().join("signed.json")).unwrap()).unwrap();
    let mut asset = locator(&signed["asset"]);
    asset.reverse();
    assert_eq!(tip(), 6);
    for units in ["100000000", "200000000"] {
        require(producer("burn", &root(), &["--units", units]), "producer burn");
    }
    advance(&["--blocks", "1"]);
    let burns = burns();
    let original = chain_hash(7);
    let first: Vec<_> = burns.iter().map(|burn| located(burn, 7, original, &asset)).collect();
    assert_eq!(
        first.iter().map(|evidence| evidence.amount).collect::<Vec<_>>(),
        [100_000_000, 200_000_000]
    );
    advance(&["--blocks", "4"]);
    let mut settlement = pn_wallet::Settlement::default();
    let view = settlement.observe(&observation(first.clone(), None)).unwrap();
    assert_eq!(
        view.pending.iter().map(|pending| pending.successors).collect::<Vec<_>>(),
        [4, 4]
    );
    assert_eq!((view.pinned.len(), view.pinned_total, view.floor), (0, 0, None));
    // Shallow replacement: the replacing branch leaves both burns in the mempool.
    advance(&["--replace", "5", "--blocks", "5", "--exclude"]);
    assert_eq!(tip(), 11);
    assert_ne!(chain_hash(7), original);
    assert_eq!(read_transaction(&burns[0], original).fields().outputs.len(), 4);
    let stale = SettlementRefusal::Stale {
        transaction: burns[0].transaction,
        output: 0,
    };
    assert_eq!(settlement.observe(&observation(first.clone(), Some(&view))), Err(stale));
    let view = settlement.observe(&observation(vec![], Some(&view))).unwrap();
    assert_eq!((view.pinned.len(), view.pending.len(), view.pinned_total), (0, 0, 0));
    // The same outpoints in a new block, reported repeatedly, count once each.
    advance(&["--blocks", "1"]);
    let moved_block = chain_hash(12);
    let moved: Vec<_> = burns.iter().map(|burn| located(burn, 12, moved_block, &asset)).collect();
    let repeated = vec![moved[0], moved[0], moved[1], moved[0]];
    assert_eq!(
        settlement.observe(&observation(vec![moved[0], first[0]], Some(&view))),
        Err(stale)
    );
    let view = settlement.observe(&observation(repeated.clone(), Some(&view))).unwrap();
    assert_eq!(view.pending.len(), 2);
    advance(&["--blocks", "5"]);
    let view = settlement.observe(&observation(repeated.clone(), Some(&view))).unwrap();
    assert_eq!(
        view.pending.iter().map(|pending| pending.successors).collect::<Vec<_>>(),
        [5, 5]
    );
    assert_eq!(view.pinned_total, 0);
    advance(&["--blocks", "1"]);
    let view = settlement.observe(&observation(repeated, Some(&view))).unwrap();
    assert_eq!(
        (view.pinned.len(), view.pending.len(), view.pinned_total),
        (2, 0, 300_000_000)
    );
    assert_eq!(view.floor, Some((12, moved_block)));
    let (transaction, block) = (read_transaction(&burns[0], moved_block), read_block(moved_block));
    let reads = (&burns[0], &transaction, &block);
    // Later blocks, then replacements above the pinned block 12, keep the pinned evidence and its reads.
    advance(&["--blocks", "3"]);
    let view = kept(&mut settlement, &moved, &view, reads);
    advance(&["--replace", "3", "--blocks", "4", "--exclude"]);
    let view = kept(&mut settlement, &moved, &view, reads);
    // At tip 22 the cutoff 22 - 6 is 16; heights 14 to 22 are replaced, yet block 12 stays.
    let replaced = chain_hash(14);
    advance(&["--replace", "9", "--blocks", "10", "--exclude"]);
    assert_eq!(tip(), 23);
    assert_ne!(chain_hash(14), replaced);
    let view = kept(&mut settlement, &moved, &view, reads);
    // A replacement of the pinned block itself is a realization fault for the run.
    advance(&["--replace", "12", "--blocks", "13", "--exclude"]);
    assert_eq!(tip(), 24);
    assert_ne!(chain_hash(12), moved_block);
    let fault = SettlementRefusal::Fault {
        height: 12,
        retained: 300_000_000,
    };
    assert_eq!(settlement.observe(&observation(moved.clone(), Some(&view))), Err(fault));
    assert_eq!(settlement.observe(&observation(vec![], Some(&view))), Err(fault));
}
