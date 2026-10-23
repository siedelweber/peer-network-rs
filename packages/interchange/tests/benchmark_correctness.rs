#[path = "support/benchmark_workloads.rs"]
mod workloads;

use pn_interchange::Value;

/// Claim: The encode workload produces independently declared canonical array bytes, not merely a successful timing.
/// ´claim:vectors:benchmark-encode-oracle´
/// ´test:integration:encode-workload´
#[test]
fn encode_workload() {
    assert_eq!(workloads::value().to_canonical_bytes(), workloads::BYTES);
}

/// Claim: The decode workload yields the declared typed value and refuses its trailing-byte mutation.
/// ´claim:vectors:benchmark-decode-oracle´
/// ´test:integration:decode-workload´
#[test]
fn decode_workload() {
    assert_eq!(
        Value::from_canonical_bytes(workloads::BYTES).expect("canonical array"),
        workloads::value()
    );
    let mut invalid = workloads::BYTES.to_vec();
    invalid.push(0);
    assert!(Value::from_canonical_bytes(&invalid).is_err());
}
