#[path = "common/checks.rs"]
mod checks;

/// Claim: The shared inputs satisfy the outer consumer's fixed-point closure oracle and independently owned exact-cause table, retaining one observation per case through the records public surface without treating this consumer as another implementation.
/// ´claim:verification:shared-conformance-preserves-whole-acts´
/// ´test:integration:shared-cases´
#[test]
fn shared_cases() {
    let mut cases: Vec<_> = pn_records::test_support::CORRUPTIONS
        .iter()
        .map(|name| pn_testkit::Case {
            id: (*name).into(),
            input: *name,
        })
        .collect();
    cases.push(pn_testkit::Case {
        id: "overlapping-closures".into(),
        input: "overlapping-closures",
    });
    let results = pn_testkit::run(
        "records-verification",
        "records-dag-1",
        &cases,
        &["pn-records-rust"],
        |_, name| {
            std::panic::catch_unwind(|| {
                if *name == "overlapping-closures" {
                    checks::closures(&[u64::MAX; 8]);
                } else {
                    checks::refusal(&[u64::MAX; 8], name);
                }
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
                    "operation": format!("contract::records-dag-1::records-verification::{}", r.case),
                    "implementation": r.implementation, "contract_edition": r.edition,
                    "outcome": if r.outcome.is_ok() { "passed" } else { "failed" },
                    "duration_ms": r.elapsed.as_secs_f64()*1000.0,
                    "source": source, "configuration": configuration, "utc": utc,
                    "owner": "records conformance implementer"
                })
            })
            .collect();
        std::fs::write(
            std::path::Path::new(&directory).join("records-verification.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
    let failures: Vec<_> = results.iter().filter(|r| r.outcome.is_err()).collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(results.len(), cases.len());
}

/// Claim: The six shared numeric cases retain separate consumer observations of exact coordinate laws, charged values and typed sign, unit and floor refusals through the records public surface.
/// ´claim:verification:shared-numeric-cases-preserve-exact-contracts´
/// ´test:integration:numeric-cases´
#[test]
fn numeric_cases() {
    let cases: Vec<_> = pn_records::test_support::NUMERIC_CASES
        .iter()
        .map(|(id, words)| pn_testkit::Case {
            id: (*id).into(),
            input: *words,
        })
        .collect();
    let results = pn_testkit::run(
        "numerics-verification",
        "records-numerics-1",
        &cases,
        &["pn-records-rust"],
        |_, name| {
            std::panic::catch_unwind(|| {
                checks::numeric(name);
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
                    "operation": format!("contract::records-numerics-1::numerics-verification::{}", r.case),
                    "implementation": r.implementation, "contract_edition": r.edition,
                    "outcome": if r.outcome.is_ok() { "passed" } else { "failed" },
                    "duration_ms": r.elapsed.as_secs_f64()*1000.0,
                    "source": source, "configuration": configuration, "utc": utc,
                    "owner": "records conformance implementer"
                })
            })
            .collect();
        std::fs::write(
            std::path::Path::new(&directory).join("numerics-verification.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
    let failures: Vec<_> = results.iter().filter(|r| r.outcome.is_err()).collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(results.len(), cases.len());
}
