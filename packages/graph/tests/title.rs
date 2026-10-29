#[path = "../../verification/tests/common/title_checks.rs"]
mod title_checks;

/// Claim: Eight named title cases and their five replay variations execute one public implementation with complete per-case results against an independent word-table oracle, retaining conflict, cancellation, party mismatch, retry and resale outcomes; both consumers share the suite, not an independent implementation.
/// ´claim:formation:shared-title-cases-retain-complete-results´
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
    let results = pn_testkit::run("graph-title-graph", "graph-title-1", &cases, &["pn-graph-rust"], |_, name| {
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
    })
    .unwrap();
    if let Ok(directory) = std::env::var("PN_CONTRACT_RESULTS") {
        let source = std::env::var("PN_HARNESS_SOURCE").unwrap();
        let configuration = std::env::var("PN_HARNESS_CONFIGURATION").unwrap();
        let utc = std::env::var("PN_HARNESS_UTC").unwrap();
        let rows: Vec<_> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "operation": format!("contract::graph-title-1::graph-title-graph::{}", r.case),
                    "implementation": r.implementation, "contract_edition": r.edition,
                    "outcome": if r.outcome.is_ok() { "passed" } else { "failed" },
                    "duration_ms": r.elapsed.as_secs_f64()*1000.0,
                    "source": source, "configuration": configuration, "utc": utc,
                    "owner": "graph partition implementer"
                })
            })
            .collect();
        std::fs::write(
            std::path::Path::new(&directory).join("graph-title-graph.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
    let failures: Vec<_> = results.iter().filter(|r| r.outcome.is_err()).collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(results.len(), cases.len());
}
