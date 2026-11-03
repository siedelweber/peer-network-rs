//! Test-only daemon capability study; no production RPC vocabulary is extended.
#[path = "recovery/replay_safe.rs"]
mod replay_safe;
use secrecy::{SecretBox, SecretString};
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

const METHODS: &str = "getblockcount,getwalletinfo,getnewaddress,getaddressinfo,createwallet,createrawtransaction,fundrawtransaction,signrawtransactionwithwallet,decoderawtransaction,gettransaction,getmempoolentry,listtransactions,listsinceblock,sendtoaddress,abandontransaction,help";

struct Identity(SecretString);
struct Node {
    root: PathBuf,
    port: SecretBox<u16>,
}
impl Drop for Node {
    fn drop(&mut self) {
        super::require(super::harness("stop", &self.root), "capability fixture shutdown");
    }
}

// Caveat: Study entropy is filled directly in protected storage until the operating-system read returns; the input API requires a mutable slice.
// (´[ROOT-cav:observe:secret-study-entropy-fill]´)
// Caveat: Study entropy is borrowed solely to construct the secret-owned fixture credential; hexadecimal formatting requires ordinary bytes for that call.
// (´[ROOT-cav:observe:secret-study-entropy-format]´)
// Fixture-only secret boundary: This helper reaches only the isolated regtest study, never deployment credentials.
// Justified: The isolated test identity is acquired into erasing carriers with no deployment credential accepted.
#[allow(clippy::disallowed_methods)]
fn identity() -> Identity {
    use secrecy::{ExposeSecret as _, ExposeSecretMut as _};
    let mut entropy = SecretBox::new(vec![0; 32].into_boxed_slice());
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(entropy.expose_secret_mut(/* (´[ROOT-cav:observe:secret-study-entropy-fill]´) */))
        .unwrap();
    let mut text = String::from("capability:");
    for byte in entropy.expose_secret(/* (´[ROOT-cav:observe:secret-study-entropy-format]´) */) {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    Identity(SecretString::from(text))
}

// Caveat: The port-only study endpoint is acquired directly into protected bytes until read returns; its descriptor API requires a mutable buffer and the file contains no producer credential.
// (´[ROOT-cav:observe:secret-study-bootstrap-read]´)
// Caveat: Port-only endpoint bytes are borrowed to extract the fixture port into its secret carrier; unknown fields refuse and no producer credential is acquired.
// (´[ROOT-cav:observe:secret-study-bootstrap-parse]´)
// Fixture-only secret boundary: This helper reaches only the isolated regtest study, never deployment credentials.
// Justified: Only the selected test node's private bootstrap is accepted, with no deployment configuration route.
#[allow(clippy::disallowed_methods)]
fn node(action: &str) -> Node {
    use secrecy::{ExposeSecret as _, ExposeSecretMut as _};
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Bootstrap {
        port: u16,
    }
    let root = super::root()
        .parent()
        .unwrap()
        .join(format!("wallet-signed-{action}-capability-{}", std::process::id()));
    super::require(super::harness(action, &root), "capability fixture production");
    let mut bytes = SecretBox::new(vec![0; 4096].into_boxed_slice());
    let count = std::fs::File::open(root.join("study-endpoint.json"))
        .unwrap()
        .read(bytes.expose_secret_mut(/* (´[ROOT-cav:observe:secret-study-bootstrap-read]´) */))
        .unwrap();
    let value: Bootstrap =
        serde_json::from_slice(&bytes.expose_secret(/* (´[ROOT-cav:observe:secret-study-bootstrap-parse]´) */)[..count]).unwrap();
    Node {
        root,
        port: SecretBox::new(Box::new(value.port)),
    }
}

// Caveat: The protected study credential leaves its carrier only through the private stdin pipe to the external fixture configurator; that producer uses temporary ordinary bytes to derive rpcauth and writes only the verifier into the restricted daemon configuration, then exits.
// (´[ROOT-cav:observe:secret-study-config-producer]´)
// Fixture-only secret boundary: This helper reaches only the isolated regtest study, never deployment credentials.
// Justified: The existing external producer owns daemon configuration; this test-only exit avoids a second cryptographic implementation or a codec-confinement exception.
#[allow(clippy::disallowed_methods)]
fn configure(node: &Node, identity: &Identity, intersection: bool, methods: &str) {
    use secrecy::ExposeSecret as _;
    let mut command = std::process::Command::new("python3");
    command
        .args(["-B", "ci/wallet_elements.py", "study-auth", "--root"])
        .arg(&node.root)
        .args(["--study-methods", methods])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if intersection {
        command.arg("--study-intersection");
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(identity.0.expose_secret(/* (´[ROOT-cav:observe:secret-study-config-producer]´) */).as_bytes())
        .unwrap();
    assert!(
        child.wait_with_output().unwrap().status.success(),
        "private study configuration refused"
    );
    super::require(super::harness("restart", &node.root), "study identity restart");
}

fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for part in bytes.chunks(3) {
        let a = part[0];
        let b = part.get(1).copied().unwrap_or(0);
        let c = part.get(2).copied().unwrap_or(0);
        out.push(char::from(DIGITS[usize::from(a >> 2)]));
        out.push(char::from(DIGITS[usize::from(((a & 3) << 4) | (b >> 4))]));
        out.push(if part.len() > 1 {
            char::from(DIGITS[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        out.push(if part.len() > 2 {
            char::from(DIGITS[usize::from(c & 63)])
        } else {
            '='
        });
    }
    out
}

// Caveat: The fixture endpoint port is borrowed for a loopback socket connection; the networking API requires its scalar address and no original connection error is retained.
// (´[ROOT-cav:observe:secret-study-port-connect]´)
// Caveat: The isolated credential is borrowed to form a protected Basic-auth request; the encoding routine requires bytes and the temporary wire buffer is not observed.
// (´[ROOT-cav:observe:secret-study-auth-encode]´)
// Caveat: The protected authorization spelling is borrowed only to construct the secret-owned request; formatting cannot consume the secret carrier directly.
// (´[ROOT-cav:observe:secret-study-auth-format]´)
// Caveat: The secret-owned HTTP request leaves its carrier only at the test daemon socket write; the daemon is the intended credential consumer.
// (´[ROOT-cav:observe:secret-study-request-write]´)
// Fixture-only secret boundary: This helper reaches only the isolated regtest study, never deployment credentials.
// Justified: This closed test client reaches only its isolated loopback daemon and is not pn-wallet's production client.
#[allow(clippy::disallowed_methods)]
fn rpc(node: &Node, identity: &Identity, wallet: &str, method: &str, params: Value) -> (u16, Value) {
    use secrecy::ExposeSecret as _;
    let address = std::net::SocketAddr::from((
        [127, 0, 0, 1],
        *node.port.expose_secret(/* (´[ROOT-cav:observe:secret-study-port-connect]´) */),
    ));
    let mut socket =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).unwrap_or_else(|_| panic!("study connection refused"));
    socket.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut body = json!({"jsonrpc":"2.0","id":1,"method":method});
    body["params"] = params;
    let body = body.to_string();
    let auth = SecretString::from(base64(
        identity.0.expose_secret(/* (´[ROOT-cav:observe:secret-study-auth-encode]´) */).as_bytes(),
    ));
    let auth = auth.expose_secret(/* (´[ROOT-cav:observe:secret-study-auth-format]´) */);
    let request = SecretString::from(format!(
        "POST /wallet/{wallet} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ));
    socket
        .write_all(request.expose_secret(/* (´[ROOT-cav:observe:secret-study-request-write]´) */).as_bytes())
        .unwrap_or_else(|_| panic!("study write refused"));
    let mut response = Vec::new();
    socket
        .take(1_048_577)
        .read_to_end(&mut response)
        .unwrap_or_else(|_| panic!("study response refused"));
    assert!(response.len() <= 1_048_576);
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP response head");
    let head = std::str::from_utf8(&response[..split]).unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let value = serde_json::from_slice(&response[split + 4..]).unwrap_or(Value::Null);
    (status, value)
}

fn call(node: &Node, identity: &Identity, method: &str, params: Value) -> Value {
    let (status, body) = rpc(node, identity, "producer", method, params);
    assert_eq!(status, 200, "public method {method}: {body}");
    assert!(body.get("error").is_none(), "public method {method}: {body}");
    body["result"].clone()
}

fn lookup(node: &Node, identity: &Identity, txid: &Value) -> Value {
    call(node, identity, "gettransaction", json!([txid]))
}

fn send(node: &Node, identity: &Identity, address: &Value, request: &str, amount: &str) -> Value {
    call(
        node,
        identity,
        "sendtoaddress",
        json!({"address":address,"amount":amount,"comment":request,"comment_to":format!("intent:{amount}"),"fee_rate":1}),
    )
}

fn raw_signing(node: &Node, identity: &Identity, address: &Value) -> Value {
    let outputs = json!([{address.as_str().unwrap():"0.001"}]);
    let raw = call(node, identity, "createrawtransaction", json!([[], outputs]));
    let funded = call(node, identity, "fundrawtransaction", json!([raw,{"fee_rate":1}]));
    let unsigned = call(node, identity, "decoderawtransaction", json!([funded["hex"]]));
    assert_eq!(
        rpc(node, identity, "producer", "gettransaction", json!([unsigned["txid"]])).1["error"]["code"],
        -5
    );
    let signed = call(node, identity, "signrawtransactionwithwallet", json!([funded["hex"]]));
    assert_eq!(signed["complete"], true);
    let decoded = call(node, identity, "decoderawtransaction", json!([signed["hex"]]));
    let (_, missing) = rpc(node, identity, "producer", "gettransaction", json!([decoded["txid"]]));
    assert_eq!(missing["error"]["code"], -5, "a returned signed draft is not a wallet record");
    decoded["txid"].clone()
}

/// Claim: The real regtest daemon intersects per-user method whitelists, refuses stale credentials after rotation, preserves nonbroadcast wallet-created bytes across restart, and accepts distinct transactions with the same request comment; raw signed drafts are absent from wallet lookup, so these primitives do not establish the required request-unique recovery contract.
/// ´claim:wallet:daemon-recovery-study-retains-capability-boundaries´
/// ´test:integration:daemon-capabilities´
#[test]
fn daemon_capabilities() {
    let node = node("study-start");
    let first = identity();
    configure(&node, &first, true, METHODS);
    assert!(call(&node, &first, "getblockcount", json!([])).as_u64().is_some());
    for method in ["help", "stop", "sendrawtransaction"] {
        assert_eq!(rpc(&node, &first, "producer", method, json!([])).0, 403);
    }
    configure(&node, &first, false, METHODS);
    let help = call(&node, &first, "help", json!(["sendtoaddress"]));
    assert!(help.as_str().unwrap().contains("comment"));
    assert_eq!(rpc(&node, &first, "producer", "stop", json!([])).0, 403);
    assert_eq!(
        rpc(&node, &first, "missing-wallet", "getwalletinfo", json!([])).1["error"]["code"],
        -18
    );
    call(
        &node,
        &first,
        "createwallet",
        json!(["other-study", false, false, "", false, false]),
    );
    assert_eq!(
        rpc(&node, &first, "other-study", "getwalletinfo", json!([])).1["result"]["walletname"],
        "other-study"
    );
    let confidential = call(&node, &first, "getnewaddress", json!(["capability-study", "bech32"]));
    let address = call(&node, &first, "getaddressinfo", json!([confidential]))["unconfidential"].clone();
    let draft = raw_signing(&node, &first, &address);
    let stored = send(&node, &first, &address, "study-restart", "0.001");
    let before = lookup(&node, &first, &stored);
    assert!(before["hex"].as_str().is_some());
    assert_eq!(before["comment"], "study-restart");
    assert_eq!(before["confirmations"], 0);
    assert_eq!(
        rpc(&node, &first, "producer", "getmempoolentry", json!([stored])).1["error"]["code"],
        -5
    );
    let rotated = identity();
    configure(&node, &rotated, false, METHODS);
    assert_eq!(rpc(&node, &first, "producer", "getwalletinfo", json!([])).0, 401);
    let after = lookup(&node, &rotated, &stored);
    assert_eq!(after["hex"], before["hex"]);
    assert_eq!(after["comment"], before["comment"]);
    assert_eq!(
        rpc(&node, &rotated, "producer", "gettransaction", json!([draft])).1["error"]["code"],
        -5
    );
    call(&node, &rotated, "abandontransaction", json!([stored]));
    let abandoned = lookup(&node, &rotated, &stored);
    assert!(
        abandoned["details"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["abandoned"] == true)
    );
    let page = call(&node, &rotated, "listtransactions", json!(["*", 1, 0, true]));
    assert_eq!(page.as_array().unwrap().len(), 1);
    let (same, different) = std::thread::scope(|scope| {
        let a = scope.spawn(|| send(&node, &rotated, &address, "same-request", "0.001"));
        let b = scope.spawn(|| send(&node, &rotated, &address, "same-request", "0.001"));
        let c = scope.spawn(|| send(&node, &rotated, &address, "same-request", "0.002"));
        ([a.join().unwrap(), b.join().unwrap()], c.join().unwrap())
    });
    assert_ne!(same[0], same[1], "request comments do not enforce uniqueness");
    assert_ne!(same[0], different);
    assert_ne!(same[1], different);
    let changed_intent = lookup(&node, &rotated, &different);
    assert_eq!(changed_intent["comment"], "same-request");
    assert!(
        changed_intent["details"]
            .as_array()
            .unwrap()
            .iter()
            .any(|detail| detail["category"] == "send" && detail["amount"] == json!(-0.002))
    );
    for txid in &same {
        assert_eq!(lookup(&node, &rotated, txid)["comment"], "same-request");
    }
    // The missing request-uniqueness contract stops further spending experiments.
    std::fs::write(
        node.root.join("capability-observation.json"),
        json!({
            "broadcast_enabled":false,"whitelist_intersection":true,"stale_credential_refused":true,
            "cross_wallet_method_authority":true,"signed_draft_lookup_code":-5,"stored_hex_survives_restart":true,
            "abandoned_lookup":true,"one_entry_page_is_not_complete":true,"duplicate_request_transactions":same,
        "changed_intent_transaction":different,"decision":"spending unsupported: no request-unique daemon association"
        })
        .to_string(),
    )
    .unwrap();
}
