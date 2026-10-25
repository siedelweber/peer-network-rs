#[path = "common/graph_checks.rs"]
mod graph_checks;

/// Claim: Six shared word-vector cases execute the records-level partition through the public API with independently owned expectations and complete per-case results; both consumers observe one implementation rather than asserting independent implementations.
/// ´claim:verification:shared-partitions-retain-complete-results´
/// ´test:integration:graph-shared-cases´
#[test]
fn graph_shared_cases() {
    let cases: Vec<_> = pn_testkit::GRAPH_PARTITION_CASES
        .iter()
        .map(|(id, words)| pn_testkit::Case {
            id: (*id).into(),
            input: *words,
        })
        .collect();
    let results = pn_testkit::run(
        "graph-partition-verification",
        "graph-partition-1",
        &cases,
        &["pn-graph-rust"],
        |_, name| {
            std::panic::catch_unwind(|| {
                graph_checks::check(name);
            })
            .map_err(|payload| {
                payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_else(|| "non-text predicate panic".into())
            })
        },
    )
    .unwrap();
    if let Ok(directory) = std::env::var("PN_CONTRACT_RESULTS") {
        let source = std::env::var("PN_HARNESS_SOURCE").unwrap();
        let configuration = std::env::var("PN_HARNESS_CONFIGURATION").unwrap();
        let utc = std::env::var("PN_HARNESS_UTC").unwrap();
        let rows: Vec<_> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "operation": format!("contract::graph-partition-1::graph-partition-verification::{}", r.case),
                    "implementation": r.implementation, "contract_edition": r.edition,
                    "outcome": if r.outcome.is_ok() { "passed" } else { "failed" },
                    "duration_ms": r.elapsed.as_secs_f64()*1000.0,
                    "source": source, "configuration": configuration, "utc": utc,
                    "owner": "graph partition implementer"
                })
            })
            .collect();
        std::fs::write(
            std::path::Path::new(&directory).join("graph-partition-verification.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
    let failures: Vec<_> = results.iter().filter(|r| r.outcome.is_err()).collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(results.len(), cases.len());
}

use pn_testkit::proptest::{self, prelude::*};

fn configuration() -> proptest::test_runner::Config {
    let mut config = pn_testkit::property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/graph.txt"));
    match std::env::var("PN_PROPERTY_SEED_PN_VERIFICATION") {
        Ok(seed) => config.rng_seed = proptest::test_runner::RngSeed::Fixed(seed.parse().unwrap()),
        Err(std::env::VarError::NotPresent) => assert!(
            std::env::var_os("PN_HARNESS_SOURCE").is_none(),
            "missing consumer seed in gated run"
        ),
        Err(error) => panic!("invalid consumer seed: {error}"),
    }
    config
}

proptest! {
    #![proptest_config(configuration())]
    /// Claim: Consumer-qualified recorded inputs yield exactly the blocks independently derived from direct causal-parent incidence, in original, reversed and shuffled presentations, without using the implementation's principal-closure intersection graph as an oracle.
    /// ´claim:verification:generated-partitions-match-parent-incidence´
    /// ´test:integration:generated-partitions´
    #[test]
    fn generated_partitions(words in proptest::collection::vec(any::<u64>(), 0..9)) { graph_checks::check(&words); }
}
