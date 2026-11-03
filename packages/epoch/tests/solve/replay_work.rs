use super::*;

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
