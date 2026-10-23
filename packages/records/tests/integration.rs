mod common;
use common::{act, named, resolved};
use pn_records::{DependencyProjection, Layout, assemble_boundary_inputs, validate_history, validate_record};

/// Claim: The local whole-act fixtures retain each structural act once with all its legs and unchanged quantities, units, vintages and host metadata, including a paired ancestor shared by overlapping closures; this is structural input accounting, not a partition or ledger verdict.
/// ´claim:acts:complete-acts-are-counted-once´
/// ´test:integration:complete-acts-count-once´
#[test]
fn complete_acts_count_once() {
    let records = [act(1, Layout::Binary), act(2, Layout::Paired)];
    let validated = validate_record(&records, &resolved(), &[]).unwrap();
    assert_eq!(validated.acts().len(), 2);
    assert_eq!(validated.acts().iter().map(|a| a.legs.len()).sum::<usize>(), 3);
    for (view, candidate) in validated.acts().iter().zip(&records) {
        assert_eq!(view.id, candidate.id);
        assert_eq!(view.body, candidate.body);
        assert_eq!(view.protocol_references, candidate.protocol_references);
        assert_eq!(view.authentication_evidence, candidate.authentication_evidence);
        assert_eq!(view.finalization_epoch, candidate.finalization_epoch);
        assert_eq!(view.authoritative_position, candidate.authoritative_position);
        for (leg, original) in view.legs.iter().zip(&candidate.legs) {
            assert_eq!(leg.id, original.id);
            assert_eq!(leg.source, original.source);
            assert_eq!(leg.target, original.target);
        }
    }
    assert_eq!(validated.acts()[1].body.quantities[0].1.vintage, 2);
    assert_eq!(validated.acts()[1].finalization_epoch, 5);
}

/// (´claim:acts:complete-acts-are-counted-once´)
/// ´test:integration:shared-ancestor-counts-once´
#[test]
fn shared_ancestor_counts_once() {
    let mut shared = act(1, Layout::Paired);
    shared.authoritative_position = 1;
    let history = validate_history(&[shared.clone()], &[named("left"), named("right")]).unwrap();
    let mut roots = [act(2, Layout::Binary), act(3, Layout::Paired)];
    for root in &mut roots {
        root.projections.dependency = DependencyProjection::Full(vec![shared.id.clone()]);
    }
    let view = validate_record(&roots, &history, &[]).unwrap();
    let inputs = assemble_boundary_inputs(&view, 8).unwrap();
    assert_eq!(inputs.closures.len(), 2);
    assert!(inputs.closures.iter().all(|closure| closure.members.contains(&shared.id)));
    assert_eq!(inputs.acts.len(), 3);
    assert_eq!(inputs.acts.iter().filter(|act| act.id == shared.id).count(), 1);
    assert_eq!(inputs.acts.iter().map(|act| act.legs.len()).sum::<usize>(), 5);
    for (actual, expected) in inputs.acts.iter().zip([&shared, &roots[0], &roots[1]]) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.body, expected.body);
        assert_eq!(actual.authoritative_position, expected.authoritative_position);
        assert_eq!(actual.finalization_epoch, expected.finalization_epoch);
    }
}
