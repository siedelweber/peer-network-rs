use pn_records::burn::{BurnError, Disclosure};
use pn_records::test_support::burn;
pub fn expected(name: &str) -> BurnError {
    match name {
        "history-mix" | "policy-mix" => BurnError::HistoryPolicy,
        "alias-address" | "alias-amount" => BurnError::InconsistentAlias,
        "skipped-index" | "duplicate-index" | "lost-predecessor" => BurnError::Succession,
        "late-policy" | "closed-placement" => BurnError::Policy,
        "missing-provenance" => BurnError::Publication(Disclosure::Provenance),
        "missing-finality" => BurnError::Publication(Disclosure::Finality),
        "missing-costs" => BurnError::Publication(Disclosure::RecordingCosts),
        "missing-operator" => BurnError::Publication(Disclosure::Operator),
        "empty-bootstrap" => BurnError::Bootstrap,
        "sample-gap" => BurnError::SampleCoverage,
        "buffer" => BurnError::Buffer,
        "wrong-profile" => BurnError::Verifier,
        "duplicate-record" => BurnError::RecordIdentity,
        "initial" => BurnError::Initial,
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
        assert_eq!(burn::recognize(input.clone()), Err(expected(name)), "{name}");
        input.history.records.reverse();
        input.history.markers.reverse();
        assert_eq!(burn::recognize(input), Err(expected(name)), "reversed {name}");
    }
}
