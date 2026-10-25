mod common;

/// Claim: Six shared word-vector cases execute the records-level partition through the public API with independently owned expectations and complete per-case results; both consumers observe one implementation rather than asserting independent implementations.
/// ´claim:membership:shared-partitions-retain-complete-results´
/// ´test:integration:shared-cases´
#[test]
fn shared_cases() {
    let cases: Vec<_> = pn_testkit::GRAPH_PARTITION_CASES
        .iter()
        .map(|(id, words)| pn_testkit::Case {
            id: (*id).into(),
            input: *words,
        })
        .collect();
    let results = pn_testkit::run(
        "graph-partition-graph",
        "graph-partition-1",
        &cases,
        &["pn-graph-rust"],
        |_, name| {
            std::panic::catch_unwind(|| {
                common::check(&pn_records::test_support::generate(name));
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
                    "operation": format!("contract::graph-partition-1::graph-partition-graph::{}", r.case),
                    "implementation": r.implementation, "contract_edition": r.edition,
                    "outcome": if r.outcome.is_ok() { "passed" } else { "failed" },
                    "duration_ms": r.elapsed.as_secs_f64()*1000.0,
                    "source": source, "configuration": configuration, "utc": utc,
                    "owner": "graph partition implementer"
                })
            })
            .collect();
        std::fs::write(
            std::path::Path::new(&directory).join("graph-partition-graph.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
    let failures: Vec<_> = results.iter().filter(|r| r.outcome.is_err()).collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(results.len(), cases.len());
}
