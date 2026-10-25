//! Public-surface layout witnesses; the byte oracle has no codec dependency.
mod oracle;

use pn_testkit::proptest::{self, prelude::*};
use pn_wallet::{Limits, Refusal, decode_block, decode_transaction, evidence_amount};

fn limits() -> Limits {
    Limits {
        bytes: 1_048_576,
        items: 1024,
        script: 10_000,
        witness: 65_536,
        allocation: 134_217_728,
    }
}

fn target() -> Vec<u8> {
    let mut script = vec![0x6a];
    for value in [3, 4, 5] {
        script.push(32);
        script.extend([value; 32]);
    }
    script
}

fn transaction((confidential, issuance, pegin): (bool, bool, bool), witness: bool, amount: u64) -> Vec<u8> {
    let mut bytes = vec![2, 0, 0, 0, u8::from(witness), 1];
    bytes.extend([1; 32]);
    let index = if issuance {
        0x8000_0000u32
    } else if pegin {
        0x4000_0000
    } else {
        0
    };
    bytes.extend(index.to_le_bytes());
    bytes.push(0);
    bytes.extend([255; 4]);
    if issuance {
        bytes.extend([0; 32]);
        bytes.extend([6; 32]);
        bytes.push(1);
        bytes.extend(1u64.to_be_bytes());
        bytes.push(0);
    }
    bytes.push(1);
    if confidential {
        let x = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0xb, 0x7, 0x2, 0x9b, 0xfc, 0xdb,
            0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        for prefix in [10, 8, 2] {
            bytes.push(prefix);
            bytes.extend(&x);
        }
    } else {
        bytes.push(1);
        bytes.extend([2; 32]);
        bytes.push(1);
        bytes.extend(amount.to_be_bytes());
        bytes.push(0);
    }
    let script = target();
    bytes.push(u8::try_from(script.len()).unwrap());
    bytes.extend(script);
    bytes.extend([0; 4]);
    if witness {
        bytes.extend([0, 0, 1, 1, 7, 0, 0, 0]);
    }
    bytes
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

/// Claim: The maintained adapter and an independent byte-only oracle agree on every exposed field of explicit, confidential, issuance, peg-in and explicit-nonce layouts, retaining all five transactions and the evidence beside a non-evidence explicit nonce.
/// ´claim:wallet:full-layouts-preserve-nonevidence-transactions´
/// ´test:integration:full-layouts´
#[test]
fn full_layouts() {
    let cases = [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ];
    let mut block = vec![0; 76];
    block[0] = 1;
    block.extend([1, 0x51, 1, 0x51, 5]);
    for (confidential, issuance, pegin) in cases {
        let bytes = transaction((confidential, issuance, pegin), true, 17);
        let decoded = decode_transaction(&bytes, limits()).unwrap();
        compare(&decoded, &oracle::transaction(&bytes).unwrap());
        block.extend(bytes);
    }
    let mut explicit_nonce = transaction((false, false, false), true, 17);
    assert_eq!(explicit_nonce[90], 0);
    explicit_nonce.splice(90..91, std::iter::once(1).chain([9; 32]));
    let nonce_tx = decode_transaction(&explicit_nonce, limits()).unwrap();
    compare(&nonce_tx, &oracle::transaction(&explicit_nonce).unwrap());
    block.extend(explicit_nonce);
    let decoded = decode_block(&block, limits()).unwrap();
    let (header, transactions) = oracle::block(&block).unwrap();
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.transactions.len(), 5);
    assert_eq!(
        evidence_amount(&decoded.transactions[0], 0, &[2; 32], &[3; 32], &[4; 32], &[5; 32]),
        Ok(17)
    );
    assert_eq!(
        evidence_amount(&decoded.transactions[4], 0, &[2; 32], &[3; 32], &[4; 32], &[5; 32]),
        Err(Refusal::EvidenceOutput)
    );
    for (a, b) in decoded.transactions.iter().zip(&transactions) {
        compare(a, b);
    }
}

/// Claim: Only positive explicit amounts in the named asset and exact run, permanent target and request commitment qualify; issuance, peg-in, confidential outputs, wrong assets and changed or absent commitments refuse.
/// ´claim:wallet:explicit-evidence-binds-target-run-and-request´
/// ´test:integration:explicit-evidence´
#[test]
fn explicit_evidence() {
    let bytes = transaction((false, false, false), false, 17);
    let tx = decode_transaction(&bytes, limits()).unwrap();
    assert_eq!(evidence_amount(&tx, 0, &[2; 32], &[3; 32], &[4; 32], &[5; 32]), Ok(17));
    assert_eq!(
        evidence_amount(&tx, 0, &[8; 32], &[3; 32], &[4; 32], &[5; 32]),
        Err(Refusal::EvidenceOutput)
    );
    for (run, target, request) in [(8, 4, 5), (3, 8, 5), (3, 4, 8)] {
        assert_eq!(
            evidence_amount(&tx, 0, &[2; 32], &[run; 32], &[target; 32], &[request; 32]),
            Err(Refusal::Target)
        );
    }
    assert_eq!(
        evidence_amount(&tx, 1, &[2; 32], &[3; 32], &[4; 32], &[5; 32]),
        Err(Refusal::EvidenceOutput)
    );
    let zero = decode_transaction(&transaction((false, false, false), false, 0), limits()).unwrap();
    assert_eq!(
        evidence_amount(&zero, 0, &[2; 32], &[3; 32], &[4; 32], &[5; 32]),
        Err(Refusal::EvidenceOutput)
    );
    for (confidential, issuance, pegin, cause) in [
        (true, false, false, Refusal::EvidenceOutput),
        (false, true, false, Refusal::EvidenceInput),
        (false, false, true, Refusal::EvidenceInput),
    ] {
        let bytes = transaction((confidential, issuance, pegin), false, 17);
        let tx = decode_transaction(&bytes, limits()).unwrap();
        assert_eq!(evidence_amount(&tx, 0, &[2; 32], &[3; 32], &[4; 32], &[5; 32]), Err(cause));
    }
    let mut absent = bytes.clone();
    let script_start = absent.len() - 105;
    absent[script_start] = 0;
    absent.drain(script_start + 1..script_start + 101);
    let absent = decode_transaction(&absent, limits()).unwrap();
    assert_eq!(
        evidence_amount(&absent, 0, &[2; 32], &[3; 32], &[4; 32], &[5; 32]),
        Err(Refusal::Target)
    );
}

/// Claim: Hostile length prefixes refuse before their requested contents are available; truncation, trailing bytes, nonminimal counts, invalid flags and script/witness limits remain distinct bounded refusals.
/// ´claim:wallet:hostile-prefixes-refuse-before-codec-allocation´
/// ´test:integration:hostile-prefixes´
#[test]
fn hostile_prefixes() {
    let valid = transaction((false, false, false), false, 17);
    for end in 0..valid.len() {
        assert!(decode_transaction(&valid[..end], limits()).is_err());
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(decode_transaction(&trailing, limits()), Err(Refusal::Trailing));
    for tag in [253, 254, 255] {
        let mut hostile = vec![2, 0, 0, 0, 0, tag];
        hostile.extend(vec![
            255;
            if tag == 253 {
                2
            } else if tag == 254 {
                4
            } else {
                8
            }
        ]);
        assert_eq!(decode_transaction(&hostile, limits()), Err(Refusal::Items));
    }
    let mut nonminimal = vec![2, 0, 0, 0, 0, 253, 1, 0];
    nonminimal.extend(&valid[6..]);
    assert_eq!(decode_transaction(&nonminimal, limits()), Err(Refusal::Count));
    let mut flags = valid.clone();
    flags[4] = 2;
    assert_eq!(decode_transaction(&flags, limits()), Err(Refusal::Flag));
    let mut limited = limits();
    limited.script = 99;
    assert_eq!(decode_transaction(&valid, limited), Err(Refusal::Script));
    let mut limited = limits();
    limited.bytes = valid.len() - 1;
    assert_eq!(decode_transaction(&valid, limited), Err(Refusal::Bytes));
    let mut witnessed = transaction((false, false, false), true, 17);
    witnessed.truncate(witnessed.len() - 8);
    witnessed.extend([0, 0, 1, 2, 7, 7, 0, 0, 0]);
    let mut limited = limits();
    limited.witness = 1;
    assert_eq!(decode_transaction(&witnessed, limited), Err(Refusal::Witness));
}

/// Claim: Prefix-correct but invalid generator, Pedersen commitment and public-key encodings, and malformed range/surjection proof encodings, reach the maintained codec and refuse without a cryptographic verification claim.
/// ´claim:wallet:invalid-curve-encodings-refuse´
/// ´test:integration:invalid-curve-encodings´
#[test]
fn invalid_curve_encodings() {
    let valid = transaction((true, false, false), false, 17);
    for start in [49, 82, 115] {
        let mut bad = valid.clone();
        bad[start..start + 32].fill(255);
        assert_eq!(decode_transaction(&bad, limits()), Err(Refusal::Codec));
    }
    for tail in [vec![1, 255, 0], vec![0, 1, 255]] {
        let mut bad = transaction((false, false, false), true, 17);
        bad.truncate(bad.len() - 2);
        bad.extend(tail);
        assert_eq!(decode_transaction(&bad, limits()), Err(Refusal::Codec));
    }
}

proptest! {
    #![proptest_config(pn_testkit::property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/layout.txt")))]
    /// Claim: Generated explicit and non-evidence layouts agree field by field with the independent oracle, while arbitrary bounded bytes and mutated curve coordinates either decode completely or return a bounded refusal without panic.
    /// ´claim:wallet:bounded-decoder-campaign-retains-layouts´
    /// ´test:integration:decoder-campaign´
    #[test]
    fn decoder_campaign(amount in 1u64..u64::MAX, mode in 0u8..4, noise in proptest::collection::vec(any::<u8>(),0..1024), x in any::<[u8;32]>()) {
        let bytes = transaction((mode==1,mode==2,mode==3),true,amount);
        let decoded = decode_transaction(&bytes,limits()).unwrap();
        compare(&decoded,&oracle::transaction(&bytes).unwrap());
        let _result = decode_transaction(&noise,limits());
        for start in [49,82,115] {
            let mut changed = transaction((true,false,false),false,17);
            changed[start..start+32].copy_from_slice(&x);
            if let Ok(decoded) = decode_transaction(&changed,limits()) {
                compare(&decoded,&oracle::transaction(&changed).unwrap());
            }
        }
    }
}
