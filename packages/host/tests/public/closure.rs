//! Independent carrier values at the caller-selected successor codec.

use pn_act_authentication::v3 as authentication;
use pn_host::publication::closure::{self as codec, ActExpectation, OpeningAnchor, ProofComparison};
use pn_records::closure::{ClosureAct, ClosureDependencyOpener, SuppliedOpening};
use serde_json::Value;

fn golden() -> Value {
    serde_json::from_str(include_str!("../../../act-authentication/tests/carrier-golden.json")).unwrap()
}

fn refusals() -> Value {
    serde_json::from_str(include_str!("../../../act-authentication/tests/carrier-refusals.json")).unwrap()
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn field(row: &Value, name: &str) -> Vec<u8> {
    hex(row[name].as_str().unwrap())
}

fn context(row: &Value) -> ([u8; 32], &str) {
    (field(row, "run").try_into().unwrap(), row["host"].as_str().unwrap())
}

fn expectation(row: &Value) -> ActExpectation {
    let (selected_run, expected_host) = context(row);
    let header = authentication::decode_header(&field(row, "header")).unwrap();
    let material_context = authentication::MaterialContext {
        selected_run,
        act: header.parts().body.id.clone(),
        expected_host: expected_host.to_owned(),
        header_version: [3, 0, 0],
    };
    let material = authentication::decode_material(&field(row, "material"), &material_context).unwrap();
    ActExpectation {
        selected_run,
        expected_host: expected_host.to_owned(),
        header: header.parts().clone(),
        material,
        host_seal: field(row, "seal").try_into().unwrap(),
        actor_approval: field(row, "approval").try_into().unwrap(),
        epoch: row["epoch"].as_u64().unwrap(),
        position: row["position"].as_u64().unwrap(),
        logical_time: row["logical_time"].as_u64().unwrap(),
    }
}

fn operand(row: &Value) -> Vec<u8> {
    if let Some(hex_value) = row["input"].as_str() {
        return hex(hex_value);
    }
    vec![0; usize::try_from(row["construction"]["zero_bytes"].as_u64().unwrap()).unwrap()]
}

fn cause(value: impl std::fmt::Debug) -> String {
    format!("{value:?}").replace('(', ":").replace(')', "")
}

fn rows_by_site(site: &str) -> Vec<Value> {
    let corpus = refusals();
    let mut names = std::collections::BTreeSet::new();
    let rows: Vec<_> = corpus["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["site"] == site)
        .cloned()
        .collect();
    for row in &rows {
        assert!(names.insert(row["id"].as_str().unwrap()));
    }
    rows
}

/// Selected act producer and contextual comparison agree with the independent admitted complete values.
/// ´claim:publication:closure-fragment-values´
/// ´test:integration:act-values´
#[test]
fn act_values() {
    for row in golden()["rows"].as_array().unwrap() {
        let (run, host) = context(row);
        let bytes = field(row, "closure");
        let act = codec::decode_act(&bytes, run, host).unwrap();
        assert_eq!(codec::encode_act(&act, run, host).unwrap(), bytes);
        let compared = codec::compare_act(&bytes, &expectation(row)).unwrap();
        assert_eq!(compared.id(), act.id());
        assert_eq!(compared.epoch(), row["anchor"]["epoch"].as_u64().unwrap());
        assert_eq!(compared.position(), row["anchor"]["position"].as_u64().unwrap());
    }
}

/// Selected proof producer and supplied-anchor comparison agree with the independent complete values.
/// ´claim:publication:dependency-proof-fragment-values´
/// ´test:integration:proof-values´
#[test]
fn proof_values() {
    for row in golden()["rows"].as_array().unwrap() {
        let (run, host) = context(row);
        let act = codec::decode_act(&field(row, "closure"), run, host).unwrap();
        let bytes = field(row, "proof");
        let proof = codec::decode_proof(&bytes).unwrap();
        assert_eq!(&codec::encode_proof(&proof).unwrap(), &bytes);
        let result = codec::compare_proof(Some(&bytes), Some(OpeningAnchor { act: &act })).unwrap();
        let ProofComparison::Matches(compared) = result else {
            panic!("fixture anchor must match");
        };
        assert_eq!(&codec::encode_proof(compared.as_ref()).unwrap(), &bytes);
        let adapter = codec::ComparedProofs::from_comparisons(vec![ProofComparison::Matches(compared)]);
        let expected_dependencies: Vec<_> = row["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| pn_records::ActId {
                author: item[1].as_str().unwrap().to_owned(),
                sequence: item[2].as_u64().unwrap(),
                family: item[3].as_str().unwrap().to_owned(),
            })
            .collect();
        assert!(matches!(adapter.opening(&act), SuppliedOpening::Available(ids) if ids == expected_dependencies.as_slice()));
        let shifted = ClosureAct::new(
            act.header().clone(),
            act.material().to_vec(),
            *act.host_seal(),
            *act.actor_approval(),
            act.epoch(),
            act.position() + 1,
            act.logical_time(),
        );
        assert!(matches!(adapter.opening(&shifted), SuppliedOpening::Unavailable));
        assert!(matches!(
            codec::compare_proof::<authentication::VerifiedHeader>(None, None).unwrap(),
            ProofComparison::UnavailableOpening
        ));
        assert!(matches!(
            codec::compare_proof::<authentication::VerifiedHeader>(Some(&bytes), None).unwrap(),
            ProofComparison::UnavailableAnchor
        ));
    }
    for row in rows_by_site("proof-structural") {
        assert_eq!(row["expected"], "Valid");
        let bytes = operand(&row);
        assert!(codec::decode_proof(&bytes).is_ok(), "{}", row["id"]);
    }
    assert_eq!(rows_by_site("proof-structural").len(), 1);
}

/// Every act corpus input returns its admitted first cause, with every descriptor executed once.
/// ´claim:publication:closure-fragment-refusal-order´
/// ´test:integration:act-order´
#[test]
fn act_order() {
    let corpus = golden();
    let rows = rows_by_site("act");
    let applicable: Vec<_> = rows.iter().map(|row| row["id"].as_str().unwrap().to_owned()).collect();
    let mut executed = Vec::new();
    for descriptor in rows {
        let case = descriptor["base_case"].as_u64().unwrap();
        let base = corpus["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["case"] == case)
            .unwrap();
        let error = codec::compare_act(&operand(&descriptor), &expectation(base)).unwrap_err();
        assert_eq!(cause(error), descriptor["expected"].as_str().unwrap(), "{}", descriptor["id"]);
        executed.push(descriptor["id"].as_str().unwrap().to_owned());
    }
    assert_eq!(executed, applicable);
}

/// Every proof corpus input returns its first structural, absence or association cause.
/// ´claim:publication:dependency-proof-fragment-refusal-order´
/// ´test:integration:proof-order´
#[test]
fn proof_order() {
    let corpus = golden();
    let rows = rows_by_site("proof");
    let applicable: Vec<_> = rows.iter().map(|row| row["id"].as_str().unwrap().to_owned()).collect();
    let mut executed = Vec::new();
    for descriptor in rows {
        let case = descriptor["base_case"].as_u64().unwrap();
        let base = corpus["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["case"] == case)
            .unwrap();
        let (run, host) = context(base);
        let act = codec::decode_act(&field(base, "closure"), run, host).unwrap();
        let bytes = operand(&descriptor);
        let error = codec::compare_proof(Some(&bytes), Some(OpeningAnchor { act: &act })).unwrap_err();
        assert_eq!(cause(error), descriptor["expected"].as_str().unwrap(), "{}", descriptor["id"]);
        match codec::compare_proof::<authentication::VerifiedHeader>(Some(&bytes), None) {
            Err(error) => assert_eq!(cause(error), descriptor["expected"].as_str().unwrap(), "{}", descriptor["id"]),
            Ok(ProofComparison::UnavailableAnchor) => {
                assert!(matches!(
                    descriptor["expected"].as_str().unwrap(),
                    "AnchorIdentity"
                        | "AnchorEpoch"
                        | "AnchorPosition"
                        | "AnchorProposal"
                        | "AnchorCommitment"
                        | "OpeningMismatch"
                ));
            }
            other => panic!("unexpected no-anchor outcome for {}: {other:?}", descriptor["id"]),
        }
        executed.push(descriptor["id"].as_str().unwrap().to_owned());
    }
    assert_eq!(executed, applicable);
}

/// The frozen historical publication remains byte-equal and rejects the successor carrier in its act slot.
/// ´claim:publication:historical-carrier-bytes´
/// ´test:integration:historical-bytes´
#[test]
fn historical_bytes() {
    let bytes = super::publication::frozen_bytes();
    let decoded = super::publication::read_bytes(&bytes).unwrap();
    let encoded = pn_host::publication::encode(
        &decoded,
        &mut super::publication::historical_numeric(),
        super::publication::historical_limits(),
    )
    .unwrap();
    assert_eq!(encoded, bytes);
    let descriptors = rows_by_site("historical");
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0]["id"], "new-act-as-historical");
    let carrier = operand(&descriptors[0]);
    let marker = [2_u8, 0x83, 0x80, 0x80];
    let at = bytes.windows(marker.len()).position(|window| window == marker).unwrap();
    let mut malformed = bytes.clone();
    malformed.splice(at + 2..at + 3, std::iter::once(0x81).chain(carrier));
    assert!(matches!(
        super::publication::read_bytes(&malformed),
        Err(pn_host::publication::Error::Shape)
    ));
}
