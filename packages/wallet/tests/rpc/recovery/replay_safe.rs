//! Finite consensus-conflict controls; no production spending entry point.
use super::{Identity, Node, configure, identity, node, rpc};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};

const METHODS: &str = "getwalletinfo,getnewaddress,getaddressinfo,listunspent,createrawtransaction,converttopsbt,walletprocesspsbt,finalizepsbt,decoderawtransaction,sendrawtransaction,getblockcount,getblockhash,getblock,getrawmempool,getrawtransaction,gettxout,help";
type Coin = (String, u64);
type Notes = BTreeMap<u8, Vec<BTreeSet<Coin>>>;
static SIGN_CALLS: AtomicUsize = AtomicUsize::new(0);

fn call(node: &Node, identity: &Identity, method: &str, params: Value) -> Value {
    let (status, body) = rpc(node, identity, "descriptor-study", method, params);
    assert_eq!(status, 200, "public method {method}: {body}");
    assert!(body.get("error").is_none(), "public method {method}: {body}");
    body["result"].clone()
}

fn key(value: &Value) -> Coin {
    (value["txid"].as_str().unwrap().to_owned(), value["vout"].as_u64().unwrap())
}

fn admit(notes: &mut Notes, request: u8, inputs: BTreeSet<Coin>) -> bool {
    if inputs.is_empty()
        || notes
            .iter()
            .any(|(other, attempts)| *other != request && attempts.iter().any(|old| !old.is_disjoint(&inputs)))
    {
        return false;
    }
    let common = notes
        .get(&request)
        .into_iter()
        .flatten()
        .fold(inputs.clone(), |set, old| set.intersection(old).cloned().collect());
    if common.is_empty() {
        return false;
    }
    notes.entry(request).or_default().push(inputs);
    true
}

fn commitment(request: u8) -> String {
    format!(
        "6a20{}20{}20{}",
        "11".repeat(32),
        "22".repeat(32),
        format!("{request:02x}").repeat(32)
    )
}

fn mine(node: &Node, blocks: u64, replace: u64, exclude: bool) {
    let count = blocks.to_string();
    let replaced = replace.to_string();
    let mut args = vec!["--blocks", &count, "--replace", &replaced];
    if exclude {
        args.push("--exclude");
    }
    super::super::require(
        super::super::producer("advance", &node.root, &args),
        "descriptor study block transition",
    );
}

fn sign(node: &Node, identity: &Identity, stock: &Value, fee: &Value, request: u8, amount: u64, fee_units: u64) -> Value {
    SIGN_CALLS.fetch_add(1, Ordering::SeqCst);
    let asset = stock["asset"].as_str().unwrap();
    let mut change = call(node, identity, "getnewaddress", json!(["change", "bech32"]));
    if request == 4 {
        change = call(node, identity, "getaddressinfo", json!([change]))["confidential"].clone();
        assert!(change.is_string(), "descriptor exposes a public confidential address");
    }
    let fee_change = call(node, identity, "getnewaddress", json!(["fee-change", "bech32"]));
    let decimal = |units: u64| format!("0.{units:08}");
    // The fixture gives each selected input exactly one million base units.
    assert_eq!(stock["amount"], json!(0.01));
    assert_eq!(fee["amount"], json!(0.01));
    let inputs = json!([{"txid":stock["txid"],"vout":stock["vout"]},{"txid":fee["txid"],"vout":fee["vout"]}]);
    let raw = call(
        node,
        identity,
        "createrawtransaction",
        json!([inputs,[
            {"burn":decimal(amount),"asset":asset},
            {change.as_str().unwrap():decimal(1_000_000-amount),"asset":asset},
            {fee_change.as_str().unwrap():decimal(1_000_000-fee_units)},
            {"fee":decimal(fee_units)}
        ]]),
    );
    let reversed = asset
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .rev()
        .map(|pair| std::str::from_utf8(pair).unwrap())
        .collect::<String>();
    let prefix = format!("01{reversed}01{amount:016x}00");
    let needle = format!("{prefix}016a");
    let script = commitment(request);
    let replacement = format!("{prefix}64{script}");
    let raw = raw.as_str().unwrap();
    assert_eq!(raw.matches(&needle).count(), 1, "one exact explicit burn output");
    let raw = raw.replacen(&needle, &replacement, 1);
    let pset = call(node, identity, "converttopsbt", json!([raw]));
    let signed = call(node, identity, "walletprocesspsbt", json!([pset]));
    assert_eq!(signed["complete"], true);
    let finalised = call(node, identity, "finalizepsbt", json!([signed["psbt"]]));
    assert_eq!(finalised["complete"], true);
    let decoded = call(node, identity, "decoderawtransaction", json!([finalised["hex"]]));
    if request == 4 {
        assert!(
            decoded["vout"]
                .as_array()
                .unwrap()
                .iter()
                .any(|out| out.get("valuecommitment").is_some())
        );
    }
    assert!(
        decoded["vout"]
            .as_array()
            .unwrap()
            .iter()
            .any(|out| out["scriptPubKey"]["hex"] == script)
    );
    assert_eq!(
        decoded["vin"].as_array().unwrap().iter().map(key).collect::<BTreeSet<_>>(),
        [key(stock), key(fee)].into_iter().collect()
    );
    json!({"hex":finalised["hex"],"txid":decoded["txid"]})
}

fn attempt(
    node: &Node,
    identity: &Identity,
    notes: &Mutex<Notes>,
    request: u8,
    stock: &Value,
    fee: &Value,
    amounts: (u64, u64),
) -> Option<Value> {
    let (amount, fee_units) = amounts;
    let mut locked = notes.lock().unwrap();
    if !admit(&mut locked, request, [key(stock), key(fee)].into_iter().collect()) {
        return None;
    }
    // Persist the selected outputs before invoking the external signer: a lost
    // signing reply still leaves this possibly signed spend in the intersection.
    std::fs::write(
        node.root.join("spent-output-notes.json"),
        serde_json::to_vec(&*locked).unwrap(),
    )
    .unwrap();
    Some(sign(node, identity, stock, fee, request, amount, fee_units))
}

fn broadcast(node: &Node, identity: &Identity, signed: &Value) -> Value {
    rpc(
        node,
        identity,
        "descriptor-study",
        "sendrawtransaction",
        json!([signed["hex"], 0.1, "0.01"]),
    )
    .1
}

fn overlapping_writers(node: &Node, identity: &Identity, notes: &Mutex<Notes>, stock: &Value, fee: &Value) {
    // Both writers propose the same unused inputs before either is admitted.
    // Admission, not preselected disjoint coins, must exclude the losing writer.
    let barrier = Barrier::new(2);
    let calls = SIGN_CALLS.load(Ordering::SeqCst);
    let overlapping = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            attempt(node, identity, notes, 5, stock, fee, (1000, 1000))
        });
        let second = scope.spawn(|| {
            barrier.wait();
            attempt(node, identity, notes, 6, stock, fee, (2000, 2000))
        });
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(overlapping.iter().filter(|attempt| attempt.is_some()).count(), 1);
    assert_eq!(SIGN_CALLS.load(Ordering::SeqCst), calls + 1);
    let locked = notes.lock().unwrap();
    assert_ne!(locked.contains_key(&5), locked.contains_key(&6));
}

fn recover(node: &Node, identity: &Identity, request: u8, scripts: &BTreeSet<String>) -> Vec<(String, u64)> {
    let tip = call(node, identity, "getblockcount", json!([])).as_u64().unwrap();
    let mut owned = BTreeSet::new();
    let mut found = Vec::new();
    let mut scan = |tx: &Value, depth| {
        let spends = tx["vin"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v.get("txid").is_some())
            .any(|v| owned.contains(&key(v)));
        if spends
            && tx["vout"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["scriptPubKey"]["hex"] == commitment(request))
        {
            found.push((tx["txid"].as_str().unwrap().to_owned(), depth));
        }
        for out in tx["vout"].as_array().unwrap() {
            if scripts.contains(out["scriptPubKey"]["hex"].as_str().unwrap()) {
                owned.insert((tx["txid"].as_str().unwrap().to_owned(), out["n"].as_u64().unwrap()));
            }
        }
    };
    for height in 0..=tip {
        let hash = call(node, identity, "getblockhash", json!([height]));
        let block = call(node, identity, "getblock", json!([hash, 2]));
        for tx in block["tx"].as_array().unwrap() {
            scan(tx, tip - height + 1);
        }
    }
    for txid in call(node, identity, "getrawmempool", json!([])).as_array().unwrap() {
        scan(&call(node, identity, "getrawtransaction", json!([txid, true])), 0);
    }
    found
}

fn funded_inputs(node: &Node, identity: &Identity) -> (Value, BTreeSet<String>, Vec<Value>, Vec<Value>) {
    let public: Value = serde_json::from_slice(&std::fs::read(node.root.join("descriptor-public.json")).unwrap()).unwrap();
    let scripts: BTreeSet<String> = public["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|address| {
            call(node, identity, "getaddressinfo", json!([address]))["scriptPubKey"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    let coins = call(node, identity, "listunspent", json!([]));
    let stocks = coins
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["asset"] == public["asset"])
        .cloned()
        .collect::<Vec<_>>();
    let fees = coins
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["asset"] == public["fee_asset"])
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(stocks.len(), 8);
    assert_eq!(fees.len(), 8);
    (public, scripts, stocks, fees)
}

/// Claim: On the real regtest descriptor wallet, PSET-signed request attempts with a nonempty common input set remain mutually exclusive across differing amounts, fees, lost replies, abandonment and a shallow reorg; the finite history recovers committed request ids from descriptor spends without wallet history, and serialized distinct requests reserve disjoint inputs.
/// ´claim:wallet:descriptor-attempts-retain-common-input-conflict´
/// ´test:integration:descriptor-conflicts´
#[test]
fn descriptor_conflicts() {
    let node = node("descriptor-start");
    let identity = identity();
    configure(&node, &identity, false, METHODS);
    assert_eq!(call(&node, &identity, "getwalletinfo", json!([]))["descriptors"], true);
    let (public, scripts, stocks, fees) = funded_inputs(&node, &identity);
    let notes = Mutex::new(Notes::new());
    let first = attempt(&node, &identity, &notes, 1, &stocks[0], &fees[0], (1000, 1000)).unwrap();
    let second = attempt(&node, &identity, &notes, 1, &stocks[0], &fees[1], (2000, 2000)).unwrap();
    // Shares with the last attempt, but empties the all-attempt intersection.
    let before = std::fs::read(node.root.join("spent-output-notes.json")).unwrap();
    let calls = SIGN_CALLS.load(Ordering::SeqCst);
    assert!(attempt(&node, &identity, &notes, 1, &stocks[1], &fees[1], (3000, 3000)).is_none());
    assert_eq!(SIGN_CALLS.load(Ordering::SeqCst), calls);
    assert_eq!(std::fs::read(node.root.join("spent-output-notes.json")).unwrap(), before);
    let third = attempt(&node, &identity, &notes, 1, &stocks[0], &fees[2], (3000, 3000)).unwrap();
    let _lost_reply = broadcast(&node, &identity, &first);
    // Lost response: remake on the retained outputs, without selecting new ones.
    let lost = attempt(&node, &identity, &notes, 1, &stocks[0], &fees[0], (1000, 1000)).unwrap();
    drop(broadcast(&node, &identity, &lost));
    for other in [&second, &third] {
        let reply = broadcast(&node, &identity, other);
        assert!(reply.get("result").is_some() || reply.get("error").is_some());
        assert_eq!(recover(&node, &identity, 1, &scripts).len(), 1);
    }
    let pending = recover(&node, &identity, 1, &scripts);
    assert_eq!(pending.len(), 1);
    assert!(
        [&first, &second, &third, &lost]
            .iter()
            .any(|attempt| attempt["txid"] == pending[0].0)
    );
    mine(&node, 1, 0, false);
    let original = recover(&node, &identity, 1, &scripts);
    assert_eq!(original, vec![(pending[0].0.clone(), 1)]);
    assert!(original.iter().all(|(_, depth)| *depth <= pn_wallet::PINNING_SUCCESSORS));
    // A replacement block excludes pending transactions, clearing the old branch.
    mine(&node, 1, 1, true);
    super::super::require(super::super::harness("restart", &node.root), "reorg pool reset");
    assert_eq!(call(&node, &identity, "getrawmempool", json!([])), json!([]));
    let alternate = if original[0].0 == second["txid"] { &first } else { &second };
    assert!(broadcast(&node, &identity, alternate).get("result").is_some());
    mine(&node, 1, 0, false);
    let changed = recover(&node, &identity, 1, &scripts);
    assert_eq!(changed, vec![(alternate["txid"].as_str().unwrap().to_owned(), 1)]);
    assert_ne!(original[0].0, changed[0].0);
    mine(&node, pn_wallet::PINNING_SUCCESSORS, 0, false);
    // Wipe request notes and every retained attempt; only descriptor discovery
    // and chain/pool data are supplied to the recovery function.
    drop(notes);
    drop(first);
    drop(second);
    drop(third);
    drop(lost);
    std::fs::remove_file(node.root.join("spent-output-notes.json")).unwrap();
    let recovered = recover(&node, &identity, 1, &scripts);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].1, pn_wallet::PINNING_SUCCESSORS + 1);
    let notes = Mutex::new(Notes::new());
    let prior = attempt(&node, &identity, &notes, 2, &stocks[3], &fees[3], (1000, 1000)).unwrap();
    let prior_other = attempt(&node, &identity, &notes, 2, &stocks[3], &fees[6], (2000, 2000)).unwrap();
    let calls = SIGN_CALLS.load(Ordering::SeqCst);
    assert!(attempt(&node, &identity, &notes, 3, &stocks[3], &fees[3], (2000, 1000)).is_none());
    assert_eq!(SIGN_CALLS.load(Ordering::SeqCst), calls);
    // A return-to-wallet spend of the common stock input cancels every signed
    // variant, regardless of whether it was ever in the pending pool.
    let destination = call(&node, &identity, "getnewaddress", json!(["abandon", "bech32"]));
    let fee_destination = call(&node, &identity, "getnewaddress", json!(["abandon-fee", "bech32"]));
    let raw = call(
        &node,
        &identity,
        "createrawtransaction",
        json!([[{"txid":stocks[3]["txid"],"vout":stocks[3]["vout"]},{"txid":fees[3]["txid"],"vout":fees[3]["vout"]}], [{destination.as_str().unwrap():"0.01","asset":public["asset"]},{fee_destination.as_str().unwrap():"0.0099"},{"fee":"0.0001"}]]),
    );
    let pset = call(&node, &identity, "converttopsbt", json!([raw]));
    let signed = call(&node, &identity, "walletprocesspsbt", json!([pset]));
    assert_eq!(signed["complete"], true);
    let cancel = call(&node, &identity, "finalizepsbt", json!([signed["psbt"]]));
    assert!(broadcast(&node, &identity, &cancel).get("result").is_some());
    mine(&node, 1, 0, false);
    assert!(broadcast(&node, &identity, &prior).get("error").is_some());
    assert!(broadcast(&node, &identity, &prior_other).get("error").is_some());
    assert_eq!(recover(&node, &identity, 2, &scripts), Vec::<(String, u64)>::new());
    overlapping_writers(&node, &identity, &notes, &stocks[7], &fees[7]);
    let (concurrent_first, concurrent_second) = std::thread::scope(|scope| {
        let concurrent_first = scope.spawn(|| attempt(&node, &identity, &notes, 3, &stocks[4], &fees[4], (1000, 1000)).unwrap());
        let concurrent_second = scope.spawn(|| attempt(&node, &identity, &notes, 4, &stocks[5], &fees[5], (2000, 1000)).unwrap());
        (concurrent_first.join().unwrap(), concurrent_second.join().unwrap())
    });
    {
        let locked = notes.lock().unwrap();
        assert!(locked[&3][0].is_disjoint(&locked[&4][0]));
    }
    for tx in [&concurrent_first, &concurrent_second] {
        assert!(broadcast(&node, &identity, tx).get("result").is_some());
    }
    mine(&node, pn_wallet::PINNING_SUCCESSORS + 1, 0, false);
    for request in [3, 4] {
        let result = recover(&node, &identity, request, &scripts);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, pn_wallet::PINNING_SUCCESSORS + 1);
    }
}
