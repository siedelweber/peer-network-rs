#[path = "common/title_checks.rs"]
mod title_checks;

/// Claim: Every one of the 512 two-boundary histories in the declared title alphabet agrees with an independent boundary truth table for owner, consumption, derived premises and transfer or conflict events in both input orders. The bounded alphabet contains absence, consent, withdrawal, partner mismatch and original or prior buyer authorization; faulted histories remain outside scope.
/// ´claim:verification:small-title-histories-match-independent-table´
/// ´test:integration:title-exhaustive´
#[test]
fn title_exhaustive() {
    for first in 0..16 {
        for second in 0..32 {
            title_checks::check(&[first, second]);
        }
    }
}

use pn_testkit::proptest::{self, prelude::*};

fn configuration() -> proptest::test_runner::Config {
    let mut config = pn_testkit::property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/title.txt"));
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
    /// Claim: Consumer-qualified recorded word cases, including empty and single-boundary histories, agree with the independent title truth table in original and reversed presentations. Recorded generation exercises the shared compliant public suite without claiming faulted-chain coverage or a second implementation.
    /// ´claim:verification:recorded-title-cases-match-independent-table´
    /// ´test:integration:title-generated´
    #[test]
    fn title_generated(words in proptest::collection::vec(any::<u64>(), 0..3)) { title_checks::check(&words); }
}

/// Claim: Eight named compliant title cases execute one public implementation with complete per-case results against an independent word-table oracle, retaining conflict, cancellation, party mismatch, retry and resale outcomes; both consumers share the suite, not an independent implementation.
/// ´claim:verification:shared-title-cases-retain-complete-results´
/// ´test:integration:title-shared-cases´
#[test]
fn title_shared_cases() {
    let cases: Vec<_> = pn_testkit::TITLE_CASES
        .iter()
        .map(|(id, words)| pn_testkit::Case {
            id: (*id).into(),
            input: *words,
        })
        .collect();
    let results = pn_testkit::run(
        "graph-title-verification",
        "graph-title-1",
        &cases,
        &["pn-graph-rust"],
        |_, name| {
            std::panic::catch_unwind(|| {
                title_checks::check(name);
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
                    "operation": format!("contract::graph-title-1::graph-title-verification::{}", r.case),
                    "implementation": r.implementation, "contract_edition": r.edition,
                    "outcome": if r.outcome.is_ok() { "passed" } else { "failed" },
                    "duration_ms": r.elapsed.as_secs_f64()*1000.0,
                    "source": source, "configuration": configuration, "utc": utc,
                    "owner": "graph partition implementer"
                })
            })
            .collect();
        std::fs::write(
            std::path::Path::new(&directory).join("graph-title-verification.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
    let failures: Vec<_> = results.iter().filter(|r| r.outcome.is_err()).collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(results.len(), cases.len());
}
