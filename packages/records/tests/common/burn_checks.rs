use pn_records::burn::{BurnError, Disclosure};
use pn_records::test_support::burn;
pub fn expected(name: &str) -> BurnError {
    match name {
        "history-mix" | "policy-mix" | "policy-identity" | "policy-sequence" => BurnError::HistoryPolicy,
        "alias-address" | "alias-amount" => BurnError::InconsistentAlias,
        "empty-name" | "selected-name" | "skipped-index" | "duplicate-index" | "lost-predecessor" | "predecessor-name"
        | "successor-snapshot" => BurnError::Succession,
        "late-policy" | "closed-placement" => BurnError::Policy,
        "missing-provenance" => BurnError::Publication(Disclosure::Provenance),
        "missing-finality" => BurnError::Publication(Disclosure::Finality),
        "missing-costs" => BurnError::Publication(Disclosure::RecordingCosts),
        "missing-operator" | "unexplained-operator" => BurnError::Publication(Disclosure::Operator),
        "empty-bootstrap" => BurnError::Bootstrap,
        "burn-unit" | "cost-unit" | "operator-unit" => BurnError::Units,
        "sample-gap" => BurnError::SampleCoverage,
        "buffer" => BurnError::Buffer,
        "wrong-profile" => BurnError::Verifier,
        "duplicate-record" => BurnError::RecordIdentity,
        "initial" | "initial-index" => BurnError::Initial,
        "lost-lineage" => BurnError::MissingLineage,
        "regressed-lineage" => BurnError::RegressedLineage,
        "regressed-acceptance" => BurnError::RegressedAcceptance,
        "out-of-lineage" => BurnError::OutOfLineage,
        "invalid-member" => BurnError::InvalidMember,
        "wrong-encoding" => BurnError::Encoding,
        "missing-opening" => BurnError::MissingOpening,
        "ambiguous-opening" => BurnError::AmbiguousOpening,
        "invalid-opening" => BurnError::InvalidOpening,
        _ => panic!("unknown case {name}"),
    }
}
pub fn case(words: &[u64], name: &str) {
    let mut input = burn::generate(words);
    let valid = burn::recognize(input.clone()).unwrap();
    let last = valid.markers().last().unwrap();
    assert_eq!(
        last.accepted(),
        &std::collections::BTreeSet::from(["r0".into(), "r1".into(), "alias".into()])
    );
    assert_eq!(
        last.destructions().keys().cloned().collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from(["d0".into(), "d1".into()])
    );
    if name == "valid" {
        input.history.records.reverse();
        input.history.markers.reverse();
        assert_eq!(burn::recognize(input).unwrap(), valid);
    } else {
        burn::corrupt(&mut input, name);
        let retained = match name {
            "initial" | "initial-index" => Some(0),
            "duplicate-index" | "lost-predecessor" | "lost-lineage" | "out-of-lineage" | "invalid-member" | "wrong-encoding" => {
                Some(1)
            }
            "skipped-index"
            | "regressed-lineage"
            | "regressed-acceptance"
            | "alias-address"
            | "alias-amount"
            | "history-mix"
            | "policy-mix"
            | "missing-opening"
            | "ambiguous-opening"
            | "invalid-opening"
            | "predecessor-name"
            | "successor-snapshot"
            | "policy-identity"
            | "policy-sequence"
            | "empty-name"
            | "selected-name" => Some(2),
            _ => None,
        };
        for reverse in [false, true] {
            if reverse {
                input.history.records.reverse();
                input.history.markers.reverse();
            }
            match (burn::recognize(input.clone()), retained) {
                (Ok(result), Some(count)) => {
                    assert_eq!(result.first_refusal().map(|f| &f.cause), Some(&expected(name)), "{name}");
                    assert_eq!(
                        result
                            .markers()
                            .iter()
                            .map(|m| m.identity().name.as_str())
                            .collect::<Vec<_>>(),
                        ["m0", "m1", "m2"][..count],
                        "prefix {name}"
                    );
                    for (actual, original) in result.markers().iter().zip(valid.markers()) {
                        assert_eq!(actual.accepted(), original.accepted(), "accepted {name}");
                        assert_eq!(actual.destructions(), original.destructions(), "destructions {name}");
                    }
                }
                (Err(cause), None) => assert_eq!(cause, expected(name), "validation {name}"),
                (result, count) => panic!("wrong prefix class {name}: {result:?} expected {count:?}"),
            }
        }
    }
}
