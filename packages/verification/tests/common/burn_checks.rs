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
fn changed_premise(base: &BurnCase, changed: &BurnCase) -> (BurnError, Option<u64>) {
    let b = &changed.burn;
    if b.evidence.provenance.is_none() {
        return (BurnError::Publication(Disclosure::Provenance), None);
    }
    if b.evidence.finality_assumptions.is_none() {
        return (BurnError::Publication(Disclosure::Finality), None);
    }
    if b.evidence.recording_costs.is_none() {
        return (BurnError::Publication(Disclosure::RecordingCosts), None);
    }
    if b.evidence.operator.is_none()
        || matches!(&b.evidence.operator, Some(OperatorEvidence::Absent { explanation }) if explanation.trim().is_empty())
    {
        return (BurnError::Publication(Disclosure::Operator), None);
    }
    if b.bootstrap != base.burn.bootstrap {
        return (BurnError::Bootstrap, None);
    }
    if b.amounts.keys().collect::<BTreeSet<_>>() != base.burn.amounts.keys().collect() {
        return (BurnError::SampleCoverage, None);
    }
    let unit = base.burn.bootstrap.as_ref().unwrap().bound.unit();
    if b.unit_cost.as_ref().unwrap().burn_unit() != unit
        || matches!(&b.evidence.operator, Some(OperatorEvidence::Bound { amount, .. }) if amount.unit() != unit)
    {
        return (BurnError::Units, None);
    }
    if b.amounts
        .values()
        .any(|a| a.unit() != base.burn.bootstrap.as_ref().unwrap().bound.unit())
    {
        return (BurnError::Units, None);
    }
    let p = &changed.policy;
    if p.published_at >= p.genesis_at || !p.open_placement {
        return (BurnError::Policy, None);
    }
    if p.stability_buffer <= b.evidence.settlement_depth.unwrap() {
        return (BurnError::Buffer, None);
    }
    if p.verification_profile != base.policy.verification_profile {
        return (BurnError::Verifier, None);
    }
    if changed.history.records.len() > base.history.records.len() {
        return (BurnError::RecordIdentity, None);
    }
    if changed.history.records.len() < base.history.records.len() {
        let missing = base
            .history
            .records
            .iter()
            .find(|r| !changed.history.records.iter().any(|c| c.identity == r.identity))
            .unwrap();
        let index = base
            .history
            .markers
            .iter()
            .filter(|m| m.lineage.contains(&missing.identity))
            .map(|m| m.index)
            .min()
            .unwrap();
        return (BurnError::MissingLineage, Some(index));
    }
    for record in &changed.history.records {
        let original = base.history.records.iter().find(|r| r.identity == record.identity).unwrap();
        let first_acceptance = base
            .history
            .markers
            .iter()
            .filter(|m| matches!(&m.accepted, AcceptedSet::CompleteList(ids) if ids.contains(&record.identity)))
            .map(|m| m.index)
            .min()
            .unwrap();
        if record.address != original.address || record.amount != original.amount {
            return (BurnError::InconsistentAlias, Some(first_acceptance));
        }
        if record.evidence != original.evidence {
            return (BurnError::InvalidMember, Some(first_acceptance));
        }
    }
    marker_premise(base, changed)
}

fn marker_premise(base: &BurnCase, changed: &BurnCase) -> (BurnError, Option<u64>) {
    if changed.history.markers.len() != base.history.markers.len() {
        let missing = base
            .history
            .markers
            .iter()
            .find(|m| {
                !changed
                    .history
                    .markers
                    .iter()
                    .any(|c| c.history_position == m.history_position)
            })
            .unwrap();
        return (BurnError::Succession, Some(missing.index));
    }
    for marker in &changed.history.markers {
        let original = base
            .history
            .markers
            .iter()
            .find(|m| m.history_position == marker.history_position)
            .unwrap();
        let affected = original.index.min(marker.index);
        if marker.name != original.name {
            return (BurnError::Succession, Some(affected));
        }
        if marker.history != original.history
            || marker.policy_identity != original.policy_identity
            || marker.policy_edition != original.policy_edition
            || marker.sequence != original.sequence
        {
            return (BurnError::HistoryPolicy, Some(affected));
        }
        if original.index == 0 && (marker.index != 0 || marker.initial_snapshot != original.initial_snapshot) {
            return (BurnError::Initial, Some(affected));
        }
        if marker.index != original.index
            || marker.predecessor != original.predecessor
            || marker.initial_snapshot != original.initial_snapshot
        {
            return (BurnError::Succession, Some(affected));
        }
        if marker.lineage != original.lineage {
            return (BurnError::RegressedLineage, Some(affected));
        }
        match &marker.accepted {
            AcceptedSet::WholePrefix => return (BurnError::Encoding, Some(affected)),
            AcceptedSet::Commitment { openings, .. } => {
                if openings.is_empty() {
                    return (BurnError::MissingOpening, Some(affected));
                }
                if openings.len() > 1 {
                    return (BurnError::AmbiguousOpening, Some(affected));
                }
                let mut bytes = b"set:".to_vec();
                bytes.extend(openings[0].members.iter().cloned().collect::<Vec<_>>().join("|").bytes());
                if openings[0].proof != bytes {
                    return (BurnError::InvalidOpening, Some(affected));
                }
            }
            AcceptedSet::CompleteList(members) => {
                if !members.is_subset(&marker.lineage) {
                    return (BurnError::OutOfLineage, Some(affected));
                }
                if marker.accepted != original.accepted {
                    return (BurnError::RegressedAcceptance, Some(affected));
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
        let (expected, cutoff) = changed_premise(&base, &input);
        for reverse in [false, true] {
            if reverse {
                input.history.records.reverse();
                input.history.markers.reverse();
            }
            match (burn::recognize(input.clone()), cutoff) {
                (Ok(result), Some(index)) => {
                    assert_eq!(
                        result.first_refusal().map(|f| &f.cause),
                        Some(&expected),
                        "{name} reversed={reverse}"
                    );
                    let expected_names: Vec<_> = base
                        .history
                        .markers
                        .iter()
                        .filter(|m| m.index < index)
                        .map(|m| m.name.as_str())
                        .collect();
                    assert_eq!(
                        result
                            .markers()
                            .iter()
                            .map(|m| m.identity().name.as_str())
                            .collect::<Vec<_>>(),
                        expected_names,
                        "prefix {name} reversed={reverse}"
                    );
                    for marker in result.markers() {
                        let (members, destructions) = &expected_sets[&marker.identity().name];
                        assert_eq!(marker.accepted(), members);
                        assert_eq!(&marker.destructions().keys().cloned().collect::<BTreeSet<_>>(), destructions);
                    }
                }
                (Err(cause), None) => assert_eq!(cause, expected, "validation has no prefix: {name}"),
                (result, index) => panic!("wrong prefix class {name}: {result:?} expected {index:?}"),
            }
        }
    }
}
