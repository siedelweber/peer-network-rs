#[path = "../benches/support/mod.rs"]
mod inputs;

/// Claim: Seeded whole-act partition recipes retain requested sizes and independently predicted covers, blocks and intersections.
/// ´claim:membership:workload-partition-inputs-retain-counts-and-cover´
/// ´test:integration:partition-inputs´
#[test]
fn partition_inputs() {
    for seed in [inputs::SEED, 1, 2] {
        for shape in 0..3 {
            inputs::check_partition(seed, 8, shape);
        }
    }
}

/// Claim: Singleton endpoint transport agrees with exact transport and an independent regular-column mean, while a zero cell ceiling refuses.
/// ´claim:numerics:workload-transport-inputs-agree-with-column-oracle´
/// ´test:integration:transport-inputs´
#[test]
fn transport_inputs() {
    for seed in [inputs::SEED, 1, 2] {
        for dense in [false, true] {
            inputs::check_transport(seed, 2, dense).unwrap();
        }
    }
}

/// Claim: Generated title histories retain exact act counts and alternating owners; a wrong-party handshake binds no transfer.
/// ´claim:formation:workload-title-inputs-retain-transfer-oracle´
/// ´test:integration:workload-title-inputs´
#[test]
fn workload_title_inputs() {
    for seed in [inputs::SEED, 1, 2] {
        inputs::check_title(seed, 4);
    }
}

/// Claim: The separately bounded dense sixteen-Actor oracle agrees with the exact operation; the former oracle allowance still refuses with its exhausted Work cause.
/// ´claim:numerics:scaling-transport-oracle-retains-limit-control´
/// ´test:integration:scaling-transport-oracle´
#[test]
fn scaling_transport_oracle() {
    inputs::check_transport(0, 16, true).unwrap();
    let input = inputs::enclosed(&inputs::transport(0, 16, true));
    let mut b = nrz_cas::limits::Budget::new(nrz_cas::limits::Limits::default()).unwrap();
    let error = pn_graph::transport::enclosed::evaluate(&input, &mut b, inputs::CELLS).unwrap_err();
    let pn_records::transport::KernelError::Arithmetic(message) = error else {
        panic!("unexpected refusal: {error:?}");
    };
    assert!(message.contains("Work"));
    assert!(message.contains("2000000"));
    assert!(message.contains("2000021"));
}
