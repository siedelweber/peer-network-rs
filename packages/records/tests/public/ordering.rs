use super::{act, named};
use pn_records::{
    CandidateAct, DependencyCause, DependencyProjection, Layout, Removal, TimeVerdict, ValidationError, assemble_boundary_inputs,
    validate_history, validate_record,
};

/// Claim: Epoch-major placement admits a prior-epoch parent despite a smaller current position, uses epoch-qualified cuts and removal facts, and refuses a candidate predecessor that is late in either published placement or the within-epoch causal key while retaining dependency violations on replay.
/// ´claim:acts:epoch-qualified-placement-retains-causal-checks´
/// ´test:integration:epoch-placement´
#[test]
fn epoch_placement() {
    let names = [named("left"), named("right")];
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
    for (position, time) in [(2, 10), (0, 12)] {
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
            TimeVerdict::NonCompliant
        );
    }
}

fn history_case() -> (Vec<CandidateAct>, Vec<pn_records::PublicReference>) {
    let names = vec![named("left"), named("middle"), named("right")];
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
    (vec![first, second, third], names)
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

/// Claim: Complete binary and three-endpoint paired fixtures retain host-attached times matching an independent backward incidence search; every paired projection reads its single owning act's time, and reversing input presentation preserves the ordered recurrence evidence.
/// ´claim:acts:attached-times-match-scoped-incidence-replay´
/// ´test:integration:attached-times´
#[test]
fn attached_times() {
    let (acts, names) = history_case();
    for (index, act) in acts.iter().enumerate() {
        assert_eq!(u128::from(act.logical_time), independent_time(&acts, index));
    }
    let forward = validate_history(&acts, &names).unwrap();
    assert!(forward.time_evidence().iter().all(|row| row.verdict == TimeVerdict::Matches));
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

/// Claim: Recurrence mismatches retain the attached time and exact expected value, including a value beyond u64; tombstoned openings, non-compliant dependencies and ambiguous placement yield no time verdict, and none rewrites finalization metadata.
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
    assert_eq!(replay.acts()[1].logical_time(), 7);
    acts[0].logical_time = u64::MAX;
    acts[1].projections.dependency = DependencyProjection::FullEmpty;
    acts[2].body.asserted_parents.clear();
    let replay = validate_history(&acts, &names).unwrap();
    assert_eq!(
        replay.time_evidence()[1].verdict,
        TimeVerdict::Mismatch {
            attached: 7,
            expected: u128::from(u64::MAX) + 1
        }
    );
    acts[1].projections.dependency = DependencyProjection::Full(vec![acts[1].id.clone()]);
    let replay = validate_history(&acts, &names).unwrap();
    assert_eq!(replay.time_evidence()[1].verdict, TimeVerdict::NonCompliant);
    acts[1].authoritative_position = 1;
    let replay = validate_history(&acts, &names).unwrap();
    assert!(
        replay
            .time_evidence()
            .iter()
            .all(|row| row.verdict == TimeVerdict::AmbiguousPlacement)
    );
}
