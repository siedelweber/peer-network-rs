#[path = "support/benchmark_workloads.rs"]
mod workloads;

#[path = "support/transport_workloads.rs"]
mod transport_workloads;

/// Claim: Byte workload grids decode to their deterministic payload through strict and chunked transport paths, while strict rejects chunked spellings and transport refuses the declared input-byte limit before allocation.
/// ´claim:vectors:transport-workload-controls´
/// ´test:integration:transport-workload´
#[test]
fn transport_workload() {
    for size in [256, 1024, 4096, 16384] {
        for chunked in [false, true] {
            let (value, bytes, mut limits) = transport_workloads::input(size, chunked);
            assert_eq!(
                Value::from_transport_bytes(&bytes, limits, &mut pn_interchange::TransportUsage::default()).unwrap(),
                value
            );
            if chunked {
                assert!(Value::from_canonical_bytes(&bytes).is_err());
            } else {
                assert_eq!(Value::from_canonical_bytes(&bytes).unwrap(), value);
            }
            limits.input_bytes = bytes.len() - 1;
            let mut usage = pn_interchange::TransportUsage::default();
            assert!(Value::from_transport_bytes(&bytes, limits, &mut usage).is_err());
            assert_eq!(usage.allocation_calls, 0);
        }
    }
}

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
