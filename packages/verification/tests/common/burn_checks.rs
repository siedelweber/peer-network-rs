use pn_records::burn::{AcceptedSet, BurnError, Disclosure, OperatorEvidence};
use pn_records::test_support::burn::{self, BurnCase};
use std::collections::{BTreeMap, BTreeSet};

// This consumer derives expected data from the input, not the inner tier's roster answers.
fn accepted(case: &BurnCase) -> BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> {
    case.history
        .markers
        .iter()
        .map(|marker| {
            let AcceptedSet::CompleteList(members) = &marker.accepted else {
                panic!("valid generator declares lists")
            };
            let destructions = case
                .history
                .records
                .iter()
                .filter(|record| members.contains(&record.identity))
                .map(|record| record.destruction.clone())
                .collect();
            (marker.name.clone(), (members.clone(), destructions))
        })
        .collect()
}

// Each shared corruption changes one premise. Read that premise from the changed carrier;
// neither a corruption name nor the inner tier's expected-cause table selects this answer.
fn changed_premise(base: &BurnCase, changed: &BurnCase) -> BurnError {
    let b = &changed.burn;
    if b.evidence.provenance.is_none() {
        return BurnError::Publication(Disclosure::Provenance);
    }
    if b.evidence.finality_assumptions.is_none() {
        return BurnError::Publication(Disclosure::Finality);
    }
    if b.evidence.recording_costs.is_none() {
        return BurnError::Publication(Disclosure::RecordingCosts);
    }
    if b.evidence.operator.is_none()
        || matches!(&b.evidence.operator, Some(OperatorEvidence::Absent { explanation }) if explanation.trim().is_empty())
    {
        return BurnError::Publication(Disclosure::Operator);
    }
    if b.bootstrap != base.burn.bootstrap {
        return BurnError::Bootstrap;
    }
    if b.amounts.keys().collect::<BTreeSet<_>>() != base.burn.amounts.keys().collect() {
        return BurnError::SampleCoverage;
    }
    if b.amounts
        .values()
        .any(|a| a.unit() != base.burn.bootstrap.as_ref().unwrap().bound.unit())
    {
        return BurnError::Units;
    }
    let p = &changed.policy;
    if p.published_at >= p.genesis_at || !p.open_placement {
        return BurnError::Policy;
    }
    if p.stability_buffer <= b.evidence.settlement_depth.unwrap() {
        return BurnError::Buffer;
    }
    if p.verification_profile != base.policy.verification_profile {
        return BurnError::Verifier;
    }
    if changed.history.records.len() > base.history.records.len() {
        return BurnError::RecordIdentity;
    }
    if changed.history.records.len() < base.history.records.len() {
        return BurnError::MissingLineage;
    }
    for record in &changed.history.records {
        let original = base.history.records.iter().find(|r| r.identity == record.identity).unwrap();
        if record.address != original.address || record.amount != original.amount {
            return BurnError::InconsistentAlias;
        }
        if record.evidence != original.evidence {
            return BurnError::InvalidMember;
        }
    }
    marker_premise(base, changed)
}

fn marker_premise(base: &BurnCase, changed: &BurnCase) -> BurnError {
    if changed.history.markers.len() != base.history.markers.len() {
        return BurnError::Succession;
    }
    for marker in &changed.history.markers {
        let original = base.history.markers.iter().find(|m| m.name == marker.name).unwrap();
        if marker.history != original.history
            || marker.policy_identity != original.policy_identity
            || marker.policy_edition != original.policy_edition
            || marker.sequence != original.sequence
        {
            return BurnError::HistoryPolicy;
        }
        if original.index == 0 && (marker.index != 0 || marker.initial_snapshot != original.initial_snapshot) {
            return BurnError::Initial;
        }
        if marker.index != original.index
            || marker.predecessor != original.predecessor
            || marker.initial_snapshot != original.initial_snapshot
        {
            return BurnError::Succession;
        }
        if marker.lineage != original.lineage {
            return BurnError::RegressedLineage;
        }
        match &marker.accepted {
            AcceptedSet::WholePrefix => return BurnError::Encoding,
            AcceptedSet::Commitment { openings, .. } => {
                if openings.is_empty() {
                    return BurnError::MissingOpening;
                }
                if openings.len() > 1 {
                    return BurnError::AmbiguousOpening;
                }
                let mut bytes = b"set:".to_vec();
                bytes.extend(openings[0].members.iter().cloned().collect::<Vec<_>>().join("|").bytes());
                if openings[0].proof != bytes {
                    return BurnError::InvalidOpening;
                }
            }
            AcceptedSet::CompleteList(members) => {
                if !members.is_subset(&marker.lineage) {
                    return BurnError::OutOfLineage;
                }
                if marker.accepted != original.accepted {
                    return BurnError::RegressedAcceptance;
                }
            }
        }
    }
    panic!("no changed refusal premise")
}

pub fn case(words: &[u64], name: &str) {
    let base = burn::generate(words);
    let expected_sets = accepted(&base);
    let valid = burn::recognize(base.clone()).unwrap();
    assert!(valid.first_refusal().is_none());
    assert_eq!(valid.markers().len(), expected_sets.len());
    for marker in valid.markers() {
        let (members, destructions) = &expected_sets[&marker.identity().name];
        assert_eq!(marker.accepted(), members);
        assert_eq!(&marker.destructions().keys().cloned().collect::<BTreeSet<_>>(), destructions);
    }
    let mut input = base.clone();
    if name == "valid" {
        input.history.records.reverse();
        input.history.markers.reverse();
        assert_eq!(burn::recognize(input).unwrap(), valid);
    } else {
        burn::corrupt(&mut input, name);
        let expected = changed_premise(&base, &input);
        for reverse in [false, true] {
            if reverse {
                input.history.records.reverse();
                input.history.markers.reverse();
            }
            let actual = burn::recognize(input.clone()).map_or_else(Some, |r| r.first_refusal().map(|f| f.cause.clone()));
            assert_eq!(actual, Some(expected.clone()), "{name} reversed={reverse}");
        }
    }
}
