use pn_testkit::{Case, run};

/// Claim: Across two named implementations, a rejected case precedes a passing case in each result sequence and all retain suite and edition, preventing failure from hiding later cases.
/// ´claim:testkit:all-predicates-retain-identity´
/// ´test:integration:runner-results´
#[test]
fn runner_results() {
    let cases = [
        Case {
            id: "reject".into(),
            input: false,
        },
        Case {
            id: "accept".into(),
            input: true,
        },
    ];
    let results = run("contract", "1", &cases, &["a", "b"], |_, accepted| {
        if *accepted { Ok(()) } else { Err("predicate") }
    })
    .expect("distinct roster");
    let actual: Vec<_> = results
        .iter()
        .map(|r| (r.case.as_str(), r.implementation.as_str(), r.outcome.is_ok()))
        .collect();
    assert_eq!(
        actual,
        [
            ("reject", "a", false),
            ("accept", "a", true),
            ("reject", "b", false),
            ("accept", "b", true)
        ]
    );
    assert!(results.iter().all(|r| r.suite == "contract" && r.edition == "1"));
}
