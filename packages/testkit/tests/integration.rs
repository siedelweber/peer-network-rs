use pn_testkit::{Case, FaultPlan, Seeded, run};

/// Claim: Replaying a seed and logical fault plan reproduces inputs and failures without a clock.
/// ´claim:testkit:seed-and-fault-replay´
/// ´test:integration:controlled-replay´
#[test]
fn controlled_replay() {
    let replay = || {
        let mut generator = Seeded::new(42);
        let plan = FaultPlan::new([1, 3]);
        let cases: Vec<_> = (0..4)
            .map(|step| Case {
                id: step.to_string(),
                input: (step, generator.next_u64()),
            })
            .collect();
        let results = run("faults", "1", &cases, &["controlled"], |_, (step, value)| {
            if plan.fails_at(*step) { Err(*value) } else { Ok(()) }
        })
        .expect("declared cases");
        results
            .into_iter()
            .map(|result| (result.case, result.outcome))
            .collect::<Vec<_>>()
    };
    assert_eq!(replay(), replay());
    assert_eq!(
        replay().iter().map(|(_, result)| result.is_err()).collect::<Vec<_>>(),
        [false, true, false, true]
    );
}
