use super::{act, assert_retained, named};
use pn_records::{
    CandidateAct, DependencyCause, DependencyProjection, Layout, ParentCause, RecomputedTime, Removal, TimeVerdict,
    ValidationError, assemble_boundary_inputs, validate_history, validate_record,
};

/// Claim: Epoch-zero act placement refuses structurally as `FinalizationEpoch` on candidate admission and finalized replay, while boundary zero remains an empty cut. Epoch-major placement admits a prior-epoch parent despite a smaller current position, uses epoch-qualified cuts and removal facts, and refuses a candidate predecessor that is late in published placement independently of its stamp while retaining dependency violations on replay.
/// ´claim:acts:epoch-qualified-placement-retains-causal-checks´
/// ´test:integration:epoch-placement´
#[test]
fn epoch_placement() {
    let names = [named("left"), named("right")];
    let mut zero = act(1, Layout::Binary);
    zero.finalization_epoch = 0;
    let empty = validate_history(&[], &names).unwrap();
    let expected = ValidationError::InvalidRepresentation {
        act: zero.id.clone(),
        cause: pn_records::InvalidCause::FinalizationEpoch,
    };
    assert_eq!(validate_history(&[zero.clone()], &names).unwrap_err(), expected);
    assert_eq!(validate_record(&[zero], &empty, &[]).unwrap_err(), expected);
    let records = validate_record(&[], &empty, &[]).unwrap();
    let no_acts: &[&pn_records::ValidatedAct] = &[];
    assert_eq!(assemble_boundary_inputs(&records, (0, 0)).unwrap().acts(), no_acts);

    let mut parent = act(1, Layout::Binary);
    parent.finalization_epoch = 1;
    parent.authoritative_position = 2;
    parent.logical_time = 10;
    let mut child = act(2, Layout::Paired);
    child.finalization_epoch = 2;
    child.authoritative_position = 1;
    child.logical_time = 11;
    child.body.asserted_parents = vec![parent.id.clone()];
    child.projections.dependency = DependencyProjection::Full(vec![parent.id.clone()]);
    parent.projections.content = Removal::Tombstoned((2, 1));
    let history = validate_history(&[parent.clone()], &names).unwrap();
    let records = validate_record(&[child.clone()], &history, &[]).unwrap();
    assert_eq!(
        assemble_boundary_inputs(&records, (2, 1)).unwrap().acts()[0].position(),
        (2, 1)
    );
    assert!(assemble_boundary_inputs(&records, (1, 2)).is_err());
    parent.projections.content = Removal::Tombstoned((1, 1));
    assert!(validate_history(&[parent.clone()], &names).is_err());
    parent.projections.content = Removal::Live;
    parent.finalization_epoch = 2;
    child.body.asserted_parents.clear();
    let empty = validate_history(&[], &names).unwrap();
    for (position, time) in [(2, 10), (3, 12)] {
        parent.authoritative_position = position;
        parent.logical_time = time;
        let acts = [parent.clone(), child.clone()];
        assert_eq!(
            validate_record(&acts, &empty, &[]).unwrap_err(),
            ValidationError::Dependency {
                act: child.id.clone(),
                dependency: Some(parent.id.clone()),
                cause: DependencyCause::NotEarlier,
            }
        );
        let replay = validate_history(&acts, &names).unwrap();
        assert_eq!(replay.non_compliance()[0].cause, DependencyCause::NotEarlier);
        assert_eq!(replay.acts()[1].logical_time(), 11);
        assert_eq!(
            replay.time_evidence().iter().find(|row| row.act == child.id).unwrap().verdict,
            TimeVerdict::Mismatch {
                attached: 11,
                expected: 1
            }
        );
    }
}

fn history_case() -> (Vec<CandidateAct>, Vec<pn_records::PublicReference>) {
    let names = vec![
        named("left"),
        named("middle"),
        named("right"),
        named("remote-left"),
        named("remote-right"),
        named("fresh"),
    ];
    let mut first = act(1, Layout::Binary);
    first.authoritative_position = 1;
    first.logical_time = 1;
    let mut second = act(2, Layout::Paired);
    second.authoritative_position = 2;
    second.logical_time = 2;
    second.legs[0].target = named("middle");
    second.legs[1].source = named("middle");
    second.projections.dependency = DependencyProjection::Full(vec![first.id.clone()]);
    let mut third = act(3, Layout::Binary);
    third.finalization_epoch = 6;
    third.authoritative_position = 1;
    third.logical_time = 3;
    third.body.asserted_parents = vec![second.id.clone()];
    let mut disjoint = act(4, Layout::Binary);
    disjoint.finalization_epoch = 6;
    disjoint.authoritative_position = 2;
    disjoint.logical_time = 1;
    disjoint.legs[0].source = named("remote-left");
    disjoint.legs[0].target = named("remote-right");
    let mut unchanged = act(5, Layout::Binary);
    unchanged.finalization_epoch = 6;
    unchanged.authoritative_position = 3;
    unchanged.logical_time = 4;
    unchanged.legs[0].source = named("right");
    unchanged.legs[0].target = named("fresh");
    (vec![first, second, third, disjoint, unchanged], names)
}

fn independent_time(acts: &[CandidateAct], index: usize) -> u128 {
    let act = &acts[index];
    let endpoint_time = act
        .legs
        .iter()
        .flat_map(|leg| [&leg.source, &leg.target])
        .map(|endpoint| {
            acts[..index]
                .iter()
                .rev()
                .find(|previous| {
                    previous
                        .legs
                        .iter()
                        .any(|leg| &leg.source == endpoint || &leg.target == endpoint)
                })
                .map_or(0, |previous| previous.logical_time)
        })
        .max()
        .unwrap_or(0);
    let mut prior_time = 0;
    for previous in &acts[..index] {
        if act.body.asserted_parents.contains(&previous.id)
            || matches!(&act.projections.dependency, DependencyProjection::Full(ids) if ids.contains(&previous.id))
        {
            prior_time = prior_time.max(previous.logical_time);
        }
    }
    u128::from(endpoint_time.max(prior_time)) + 1
}

/// Claim: Complete binary and three-endpoint paired fixtures recompute times matching an independent backward incidence search and retain matching published stamps, including disjoint incidence below the global maximum and a later read of an unchanged frontier; every paired projection reads its single owning act's time, and reversing input presentation preserves the ordered recurrence evidence.
/// ´claim:acts:attached-times-match-scoped-incidence-replay´
/// ´test:integration:attached-times´
#[test]
fn attached_times() {
    let (acts, names) = history_case();
    for (index, act) in acts.iter().enumerate() {
        assert_eq!(u128::from(act.logical_time), independent_time(&acts, index));
    }
    let empty = validate_history(&[], &names).unwrap();
    assert!(validate_record(&acts, &empty, &[]).is_ok());
    let global_expected = acts[..3].iter().map(|act| act.logical_time).max().unwrap() + 1;
    assert_eq!(global_expected, 4);
    assert_eq!(acts[3].logical_time, 1);
    assert_ne!(acts[3].logical_time, global_expected);
    assert_eq!(independent_time(&acts, 4), 4);
    assert_ne!(u128::from(acts[3].logical_time) + 1, independent_time(&acts, 4));
    let forward = validate_history(&acts, &names).unwrap();
    assert!(forward.time_evidence().iter().all(|row| row.verdict == TimeVerdict::Matches));
    for (index, row) in forward.time_evidence().iter().enumerate() {
        assert_eq!(row.recomputed, RecomputedTime::Available(independent_time(&acts, index)));
    }
    for leg in forward.acts()[1].legs() {
        let owner = forward.acts().iter().find(|act| act.id() == &leg.id().act).unwrap();
        assert_eq!(owner.logical_time(), 2);
    }
    let reversed: Vec<_> = acts.into_iter().rev().collect();
    assert_eq!(
        validate_history(&reversed, &names).unwrap().time_evidence(),
        forward.time_evidence()
    );
}

/// Claim: Finalized replay checks asserted-parent placement independently of attached time, retaining a correctly placed time inversion as an exact recurrence mismatch without rewriting acts; missing, self and later parents become retained placement faults, candidate placement refusal remains, and earlier epochs precede smaller current positions.
/// ´claim:acts:parent-replay-separates-placement-from-stamping´
/// ´test:integration:parent-replay´
#[test]
fn parent_replay() {
    let names = [named("left"), named("right")];
    let empty = validate_history(&[], &names).unwrap();
    let mut parent = act(1, Layout::Binary);
    parent.authoritative_position = 1;
    parent.logical_time = 5;
    let mut child = act(2, Layout::Binary);
    child.authoritative_position = 2;
    child.logical_time = 3;
    child.body.asserted_parents = vec![parent.id.clone()];
    let inputs = [parent.clone(), child.clone()];
    let replay = validate_history(&inputs, &names).unwrap();
    assert_retained(&replay, &inputs);
    assert_eq!(
        replay.time_evidence()[1].verdict,
        TimeVerdict::Mismatch {
            attached: 3,
            expected: 2
        }
    );
    assert!(validate_record(&inputs, &empty, &[]).is_ok());
    let missing = validate_history(&[child.clone()], &names).unwrap();
    assert_eq!(missing.parent_faults()[0].cause, ParentCause::Missing);
    assert_eq!(missing.parent_faults()[0].parent, parent.id);
    let mut self_parent = child.clone();
    self_parent.body.asserted_parents = vec![self_parent.id.clone()];
    let replay = validate_history(&[self_parent.clone()], &names).unwrap();
    assert_eq!(replay.parent_faults()[0].cause, ParentCause::SelfParent);
    assert_eq!(replay.time_evidence()[0].recomputed, RecomputedTime::Available(1));
    assert_retained(&replay, &[self_parent]);
    for position in [2, 3] {
        parent.authoritative_position = position;
        let inputs = [parent.clone(), child.clone()];
        let replay = validate_history(&inputs, &names).unwrap();
        assert_retained(&replay, &inputs);
        assert_eq!(replay.parent_faults()[0].cause, ParentCause::NotEarlier);
        assert_eq!(
            validate_record(&inputs, &empty, &[]).unwrap_err(),
            ValidationError::Parent {
                act: child.id.clone(),
                parent: Some(parent.id.clone()),
                cause: ParentCause::NotEarlier,
            }
        );
    }
    parent.finalization_epoch = 1;
    parent.authoritative_position = 2;
    child.finalization_epoch = 2;
    child.authoritative_position = 1;
    child.logical_time = 2;
    let inputs = [parent, child];
    let replay = validate_history(&inputs, &names).unwrap();
    assert_retained(&replay, &inputs);
    assert_eq!(replay.time_evidence()[1].verdict, TimeVerdict::Matches);
    assert!(validate_record(&inputs, &empty, &[]).is_ok());
}

/// Claim: Recurrence mismatches retain the attached time and exact expected value, without trusting even a maximal published stamp; tombstoned openings propagate their missing identities through incidence and causal predecessors, independent acts remain available, non-compliant dependencies still permit recomputation, and ambiguous placement yields no time verdict, and none rewrites finalization metadata.
/// ´claim:acts:time-evidence-never-rewrites-finalization´
/// ´test:integration:retained-time-evidence´
#[test]
fn retained_time_evidence() {
    let (mut acts, names) = history_case();
    acts[1].logical_time = 7;
    let replay = validate_history(&acts, &names).unwrap();
    assert_eq!(
        replay.time_evidence()[1].verdict,
        TimeVerdict::Mismatch {
            attached: 7,
            expected: 2
        }
    );
    assert_eq!(replay.acts()[1].logical_time(), 7);
    acts[1].projections.dependency = DependencyProjection::Tombstoned((6, 1));
    let replay = validate_history(&acts, &names).unwrap();
    assert_eq!(replay.time_evidence()[1].verdict, TimeVerdict::UnavailableOpening);
    let missing = RecomputedTime::Unavailable(std::collections::BTreeSet::from([acts[1].id.clone()]));
    assert_eq!(replay.time_evidence()[1].recomputed, missing);
    assert_eq!(replay.time_evidence()[2].recomputed, missing);
    assert_eq!(replay.time_evidence()[3].recomputed, RecomputedTime::Available(1));
    assert_eq!(replay.time_evidence()[4].recomputed, missing);
    assert_eq!(
        replay.unavailable_dependencies(),
        &std::collections::BTreeSet::from([acts[1].id.clone()])
    );
    assert_retained(&replay, &acts);
    five_one_six();
    assert_eq!(replay.acts()[1].logical_time(), 7);
    acts[0].logical_time = u64::MAX;
    acts[1].projections.dependency = DependencyProjection::FullEmpty;
    acts[2].body.asserted_parents.clear();
    let replay = validate_history(&acts, &names).unwrap();
    assert_eq!(
        replay.time_evidence()[1].verdict,
        TimeVerdict::Mismatch {
            attached: 7,
            expected: 2
        }
    );
    acts[1].projections.dependency = DependencyProjection::Full(vec![acts[1].id.clone()]);
    let replay = validate_history(&acts, &names).unwrap();
    assert_eq!(replay.time_evidence()[1].recomputed, RecomputedTime::Available(2));
    acts[1].authoritative_position = 1;
    let replay = validate_history(&acts, &names).unwrap();
    assert!(
        replay
            .time_evidence()
            .iter()
            .all(|row| row.verdict == TimeVerdict::AmbiguousPlacement)
    );
}

fn five_one_six() {
    let mut chain: Vec<_> = (1..=5)
        .map(|id| {
            let mut value = act(id, Layout::Binary);
            value.authoritative_position = id;
            value.logical_time = id;
            value
        })
        .collect();
    let mut last = act(6, Layout::Binary);
    last.authoritative_position = 6;
    last.logical_time = 1;
    last.legs[0].source = named("separate-left");
    last.legs[0].target = named("separate-right");
    let names = [
        named("left"),
        named("right"),
        named("separate-left"),
        named("separate-right"),
        named("dependent-left"),
        named("dependent-right"),
    ];
    chain.push(last);
    assert_eq!(
        validate_history(&chain, &names).unwrap().time_evidence()[5].recomputed,
        RecomputedTime::Available(1)
    );
    chain[5].projections.dependency = DependencyProjection::Full(vec![chain[4].id.clone()]);
    assert_eq!(
        validate_history(&chain, &names).unwrap().time_evidence()[5].recomputed,
        RecomputedTime::Available(6)
    );
    chain[5].projections.dependency = DependencyProjection::Tombstoned((6, 10));
    let replay = validate_history(&chain, &names).unwrap();
    assert_eq!(replay.time_evidence()[4].recomputed, RecomputedTime::Available(5));
    assert_eq!(
        replay.time_evidence()[5].recomputed,
        RecomputedTime::Unavailable(std::collections::BTreeSet::from([chain[5].id.clone()]))
    );
    assert_eq!(replay.time_evidence()[5].verdict, TimeVerdict::UnavailableOpening);
    assert_retained(&replay, &chain);
    for declared in [false, true] {
        let mut dependent = act(7, Layout::Binary);
        dependent.authoritative_position = 7;
        dependent.legs[0].source = named("dependent-left");
        dependent.legs[0].target = named("dependent-right");
        if declared {
            dependent.projections.dependency = DependencyProjection::Full(vec![chain[5].id.clone()]);
        } else {
            dependent.body.asserted_parents = vec![chain[5].id.clone()];
        }
        let mut extended = chain.clone();
        extended.push(dependent);
        let replay = validate_history(&extended, &names).unwrap();
        assert_eq!(replay.time_evidence()[6].recomputed, replay.time_evidence()[5].recomputed);
        assert_eq!(replay.time_evidence()[6].verdict, TimeVerdict::UnavailableOpening);
        assert_retained(&replay, &extended);
    }
}
