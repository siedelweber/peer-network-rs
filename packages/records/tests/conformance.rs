#[path = "../../documents/src/pins.rs"]
pub mod pins;
use pins::NumberId as N;

#[path = "common/checks.rs"]
mod checks;

fn fixture_quantities() {
    assert_eq!(
        pn_records::test_support::CORRUPTIONS.len(),
        usize::try_from(N::NumbersRecordsDagCorruptionCount.integer()).unwrap()
    );
    assert_eq!(
        pn_records::test_support::CORRUPTIONS
            .iter()
            .filter(|name| name.ends_with("-bound"))
            .count(),
        usize::try_from(N::NumbersRecordsDagOverBoundCount.integer()).unwrap()
    );
    let capacity = usize::try_from(N::NumbersRecordsDagWordCapacity.integer()).unwrap();
    for (words, expected) in [
        (vec![], N::NumbersRecordsDagProposalMinimum),
        (vec![u64::MAX; capacity], N::NumbersRecordsDagProposalMaximum),
        (vec![u64::MAX; capacity + 1], N::NumbersRecordsDagProposalMaximum),
    ] {
        let scenario = pn_records::test_support::generate(&words);
        assert_eq!(
            scenario.history.len(),
            usize::try_from(N::NumbersRecordsDagHistoryCount.integer()).unwrap()
        );
        assert_eq!(scenario.proposals.len(), usize::try_from(expected.integer()).unwrap());
        assert!(
            scenario
                .history
                .iter()
                .all(|act| act.finalization_epoch == N::NumbersRecordsDagHistoryEpoch.integer())
        );
        assert!(
            scenario
                .proposals
                .iter()
                .all(|act| act.finalization_epoch == N::NumbersRecordsDagProposalEpoch.integer())
        );
        assert_eq!(scenario.boundary.0, N::NumbersRecordsDagProposalEpoch.integer());
    }
}

/// Claim: The declared conformance roster executes whole-act overlap and every typed corruption through the public surface, retaining a result per case and implementation rather than counting legs as acts.
/// ´claim:acts:shared-conformance-preserves-whole-acts´
/// ´test:integration:shared-cases´
#[test]
fn shared_cases() {
    fixture_quantities();
    let words = vec![u64::MAX; usize::try_from(N::NumbersRecordsDagWordCapacity.integer()).unwrap()];
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
    let results = pn_testkit::run("records-records", "records-dag-1", &cases, &["pn-records-rust"], |_, name| {
        std::panic::catch_unwind(|| {
            if *name == "overlapping-closures" {
                checks::closures(&words);
            } else {
                checks::refusal(&words, name);
            }
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
                    "operation": format!("contract::records-dag-1::records-records::{}", r.case),
                    "implementation": r.implementation, "contract_edition": r.edition,
                    "outcome": if r.outcome.is_ok() { "passed" } else { "failed" },
                    "duration_ms": r.elapsed.as_secs_f64()*1000.0,
                    "source": source, "configuration": configuration, "utc": utc,
                    "owner": "records conformance implementer"
                })
            })
            .collect();
        std::fs::write(
            std::path::Path::new(&directory).join("records-records.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
    let failures: Vec<_> = results.iter().filter(|r| r.outcome.is_err()).collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(results.len(), cases.len());
}

/// Claim: The six shared numeric cases retain separate consumer observations of exact coordinate laws, charged values, action-count door outlays and typed sign, unit and floor refusals through the records public surface.
/// ´claim:numerics:shared-numeric-cases-preserve-exact-contracts´
/// ´test:integration:numeric-cases´
#[test]
fn numeric_cases() {
    assert_eq!(
        pn_records::test_support::NUMERIC_CASES.len(),
        usize::try_from(N::NumbersRecordsNumericCaseCount.integer()).unwrap()
    );
    let cases: Vec<_> = pn_records::test_support::NUMERIC_CASES
        .iter()
        .map(|(id, words)| pn_testkit::Case {
            id: (*id).into(),
            input: *words,
        })
        .collect();
    let results = pn_testkit::run(
        "numerics-records",
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
                    "operation": format!("contract::records-numerics-1::numerics-records::{}", r.case),
                    "implementation": r.implementation, "contract_edition": r.edition,
                    "outcome": if r.outcome.is_ok() { "passed" } else { "failed" },
                    "duration_ms": r.elapsed.as_secs_f64()*1000.0,
                    "source": source, "configuration": configuration, "utc": utc,
                    "owner": "records conformance implementer"
                })
            })
            .collect();
        std::fs::write(
            std::path::Path::new(&directory).join("numerics-records.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
    let failures: Vec<_> = results.iter().filter(|r| r.outcome.is_err()).collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(results.len(), cases.len());
}

#[path = "common/burn_checks.rs"]
mod burn_checks;

/// Claim: A valid three-marker history and every named single-premise corruption have their declared exact typed causes and retained prefixes (none for validation refusals), preserving complete acceptance and one representative per consistent destruction alias through the public surface; fixture proofs do not establish chain validity.
/// ´claim:burn:shared-marker-cases-preserve-recognition-contracts´
/// ´test:integration:burn-cases´
#[test]
fn burn_cases() {
    assert_eq!(
        pn_records::test_support::burn::CORRUPTIONS.len(),
        usize::try_from(N::NumbersRecordsBurnCorruptionCount.integer()).unwrap()
    );
    assert_eq!(
        pn_records::test_support::burn::generate(&[7]).history.markers.len(),
        usize::try_from(N::NumbersRecordsBurnMarkerCount.integer()).unwrap()
    );
    let cases: Vec<_> = pn_records::test_support::burn::CORRUPTIONS
        .iter()
        .copied()
        .chain(std::iter::once("valid"))
        .map(|id| pn_testkit::Case {
            id: id.into(),
            input: id,
        })
        .collect();
    let results = pn_testkit::run("burn-records", "records-burn-1", &cases, &["pn-records-rust"], |_, name| {
        std::panic::catch_unwind(|| {
            burn_checks::case(&[7], name);
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
                    "operation": format!("contract::records-burn-1::burn-records::{}", r.case),
                    "implementation": r.implementation, "contract_edition": r.edition,
                    "outcome": if r.outcome.is_ok() { "passed" } else { "failed" },
                    "duration_ms": r.elapsed.as_secs_f64()*1000.0,
                    "source": source, "configuration": configuration, "utc": utc,
                    "owner": "records conformance implementer"
                })
            })
            .collect();
        std::fs::write(
            std::path::Path::new(&directory).join("burn-records.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
    let failures: Vec<_> = results.iter().filter(|r| r.outcome.is_err()).collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(results.len(), cases.len());
}
