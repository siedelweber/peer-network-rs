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
