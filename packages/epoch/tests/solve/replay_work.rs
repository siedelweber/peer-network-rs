use super::*;

/// Claim: The conserved solve refuses invented faults and changed outcomes on attachment-bearing fence primitives, while the original fence remains replayable.
/// ´claim:numerics:conserved-fence-binds-fault-assertions´
/// ´test:integration:fence-faults´
#[test]
fn fence_faults() {
    let state = conserved_state();
    let p = conserved_policy(&state, NumberId::NumbersSplitEndpointGrid.value());
    let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
    let search = pn_epoch::fence::search(&bound, None).unwrap();
    pn_epoch::conserved::solve(&bound, &search).unwrap();
    let index = search
        .evidence
        .primitives
        .iter()
        .position(|p| p.evidence.attachment.is_some())
        .unwrap();
    assert!(search.evidence.primitives[index].evidence.resource_fault.is_none());
    for field in 0..3 {
        let mut changed = search.clone();
        changed.evidence.primitives[index].evidence.resource_fault = Some(pn_records::primitive::FaultAssertion {
            kind: nrz_cas::FaultKind::Invalid(if field == 2 {
                nrz_cas::InvalidCode::DecisionOptionMismatch
            } else {
                nrz_cas::InvalidCode::UnsupportedCertificate
            }),
            operation: if field == 0 { "changed" } else { "invented" }.into(),
            logical_id: if field == 1 { Some(1) } else { None },
        });
        assert!(matches!(
            pn_epoch::conserved::solve(&bound, &changed),
            Err(pn_epoch::conserved::Error::Scope)
        ));
    }
    let mut changed = search;
    changed.evidence.primitives[index].evidence.outcome = pn_records::primitive::Outcome::Fail;
    assert!(pn_epoch::conserved::solve(&bound, &changed).is_err());
}

/// Claim: On the frozen four-Actor fixture, mandatory solve replay retains its measured cumulative solve-budget Work; independent replay agrees, succeeds at that allowance and refuses one Work below it. Production also refuses that insufficient replay allowance, and a changed reported count refuses. Separately bounded fence validation is outside this count.
/// ´claim:numerics:mandatory-replay-retains-its-measured-work´
/// ´test:integration:solve-replay-work´
#[test]
fn solve_replay_work() {
    let state = conserved_state();
    let p = conserved_policy(&state, NumberId::NumbersSplitEndpointGrid.value());
    let bound = bind_procedure(&state, p.clone(), &Published(p.clone()), Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    let result = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    let checked = pn_epoch::conserved::replay(&bound, &result).unwrap();
    assert_eq!(result.replay_work, checked.work);
    assert_eq!(checked.replay_work, checked.work);
    for cap in [result.replay_work, result.replay_work - 1] {
        let mut p = p.clone();
        p.maximum_replay_work = cap;
        let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
        assert_eq!(
            pn_epoch::conserved::replay(&bound, &result).is_ok(),
            cap == result.replay_work
        );
        assert_eq!(pn_epoch::conserved::solve(&bound, &fence).is_ok(), cap == result.replay_work);
    }
    let mut changed = result;
    changed.replay_work += 1;
    assert!(matches!(
        pn_epoch::conserved::replay(&bound, &changed),
        Err(pn_epoch::conserved::Error::ReplayWork)
    ));
}
