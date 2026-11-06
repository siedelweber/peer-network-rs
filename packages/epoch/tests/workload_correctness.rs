pub use inputs::{pins, scalar::pins as graph_pins};
#[path = "../benches/support/mod.rs"]
mod inputs;
use inputs::{Published, candidate, compile, procedure};
use nrz_cas::limits::Limits;
use pn_epoch::solve::bind_procedure;

/// Claim: Constructor-backed compile recipes retain observed complete acts, Actor counts and debits from an independent history count.
/// ´claim:compiler:workload-compiled-inputs-retain-complete-counts´
/// ´test:integration:compiled-inputs´
#[test]
fn compiled_inputs() {
    for shape in ["ring", "dense", "parallel", "mixed"] {
        let c = candidate(inputs::SEED, 2, Some(8), shape, "pass");
        let s = compile(&c).unwrap();
        inputs::check_compilation(&c, &s);
        assert!(inputs::dimensions(&c, &s).contains("M=8"));
    }
}

/// Claim: The solve record and replay share one frozen candidate and produced transcript; proposal counts and replay Work agree, and an altered replay count refuses.
/// ´claim:numerics:workload-solve-replay-share-produced-transcripts´
/// ´test:integration:solve-replay-inputs´
#[test]
fn solve_replay_inputs() {
    let candidate = candidate(inputs::SEED, 2, None, "ring", "equal");
    let state = compile(&candidate).unwrap();
    let procedure = procedure(&state, 8);
    let bound = bind_procedure(&state, procedure.clone(), &Published(procedure.clone()), Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    assert_eq!(fence.selected.as_deref(), Some("1"));
    let record = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    inputs::check_solve(&state, &procedure, &record);
    assert!(inputs::solve_counters(&record).contains("K="));
}

/// Claim: Each finite admission fixture has its separately constructed passing control and the intended own, individual or epoch-policy refusal.
/// ´claim:admission:workload-admission-recipes-distinguish-gates´
/// ´test:integration:admission-inputs´
#[test]
fn admission_inputs() {
    for outcome in ["pass", "own", "individual", "policy"] {
        let c = candidate(inputs::SEED, 2, Some(4), "self", outcome);
        let control = candidate(inputs::SEED, 2, Some(4), "self", "pass");
        let s = compile(&control).unwrap();
        let p = procedure(&s, 8);
        let plan = pn_epoch::admission::FinalProcedure {
            solve: p.clone(),
            arithmetic: Limits::default(),
            maximum_products: inputs::PRODUCTS,
        };
        let schedule = inputs::schedule(&c, if outcome == "policy" { "1000" } else { "2" });
        let result = pn_epoch::admission::admit(&c.context, &schedule, &plan, &c.approval, &Published(p), inputs::numeric());
        match outcome {
            "pass" => assert!(result.is_ok(), "{result:?}"),
            "own" => assert!(
                matches!(
                    result,
                    Err(pn_epoch::admission::FinalRefusal::Refused(
                        pn_epoch::admission::AdmissionRefusal::Failed(pn_epoch::admission::Gate::OwnSolvency)
                    ))
                ),
                "{result:?}"
            ),
            other => {
                let expected = if other == "individual" {
                    pn_epoch::admission::Gate::IndividualSafety
                } else {
                    pn_epoch::admission::Gate::EpochPolicy
                };
                assert!(
                    matches!(result, Err(pn_epoch::admission::FinalRefusal::Refused(pn_epoch::admission::AdmissionRefusal::Failed(gate))) if gate == expected),
                    "{result:?}"
                );
            }
        }
    }
}

/// Claim: Both rational-controller and defining-ridge replay retain exactly their produced inputs; substituted declarations refuse.
/// ´claim:numerics:workload-scalar-replay-inputs-retain-defining-routes´
/// ´test:integration:scalar-inputs´
#[test]
fn scalar_inputs() {
    let c = candidate(inputs::SEED, 2, None, "ring", "equal");
    let s = compile(&c).unwrap();
    inputs::scalar::check(&procedure(&s, 16));
}

/// Claim: The declared fence recipes distinguish a first-rung pass, a later-rung pass and a retained work refusal over constructor-backed complete histories.
/// ´claim:rungs:workload-fence-recipes-retain-distinct-outcomes´
/// ´test:integration:fence-inputs´
#[test]
fn fence_inputs() {
    for bits in [8, 16] {
        for outcome in ["equal", "late", "limited"] {
            let c = candidate(0, 2, None, "ring", if outcome == "limited" { "late" } else { outcome });
            let state = compile(&c).unwrap();
            let mut p = procedure(&state, bits);
            if outcome == "limited" {
                p.maximum_work = 100_000;
                p.enclosure.as_mut().unwrap().operation.work = 100_000;
            }
            let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
            let found = pn_epoch::fence::search(&bound, None).unwrap();
            match outcome {
                "equal" => assert_eq!(found.selected.as_deref(), Some("1")),
                "late" => {
                    assert!(found.selected.is_some());
                    assert_ne!(found.selected.as_deref(), Some("1"));
                }
                _ => {
                    assert!(found.selected.is_none());
                    assert!(found.operational_stop.is_some());
                }
            }
        }
    }
}

/// Claim: Each serial-trial input is a separately verified complete context with one dependency-closed four-act block; changing the seed changes that block without changing its counts.
/// ´claim:admission:workload-trial-inputs-retain-whole-blocks´
/// ´test:integration:trial-inputs´
#[test]
fn trial_inputs() {
    let first = candidate(0, 2, Some(4), "trials", "pass");
    let second = candidate(1, 2, Some(4), "trials", "pass");
    for input in [&first, &second] {
        let blocks = pn_epoch::closure::partition(&input.context).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), 4);
        check_trial_compile(input);
    }
    assert_ne!(
        first.context.input().causes.history.acts(),
        second.context.input().causes.history.acts()
    );
}
fn check_trial_compile(input: &inputs::Candidate) {
    inputs::check_compilation(input, &compile(input).unwrap());
}

/// Claim: A producing solve retains an exhausted Work request's typed budget, limit, needed charge and operation; a changed activation declaration still refuses as Declaration, and the separately bounded fixture procedure completes and replays the same candidate.
/// ´claim:numerics:workload-solve-retains-resource-causes´
/// ´test:integration:solve-resource-cause´
#[test]
fn solve_resource_cause() {
    let input = candidate(0, 4, None, "ring", "pass");
    let state = compile(&input).unwrap();
    let p = procedure(&state, 16);
    let published = Published(p.clone());
    let bound = bind_procedure(&state, p.clone(), &published, Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    let error = pn_epoch::conserved::solve(&bound, &fence).unwrap_err();
    let pn_epoch::conserved::Error::Primitive(pn_graph::numeric::Error::Resource(fault)) = error else {
        panic!("Work exhaustion lost its typed cause: {error:?}");
    };
    let nrz_cas::FaultKind::Exhausted {
        budget, limit, needed, ..
    } = fault.kind
    else {
        panic!("not an exhausted resource: {fault:?}");
    };
    assert_eq!(budget, nrz_cas::limits::BudgetKind::Work);
    assert!(limit > 0 && limit < p.maximum_solve_work);
    assert!(needed > limit);
    assert_eq!(fault.operation, "rational multiplication");
    assert_eq!(fault.logical_id, None);
    let mut session = pn_graph::numeric::activation::sharing::Session::new(&p, "1/400").unwrap();
    let changed = pn_graph::numeric::activation::Request {
        standing: pn_records::primitive::Range {
            lower: "10".into(),
            upper: "10".into(),
        },
        bleed_squared: "1/100".into(),
        wall: Some("2".into()),
        wall_enclosure: None,
        quantity: pn_graph::numeric::activation::Quantity::Clamped,
    };
    assert_eq!(session.evaluate(&changed), Err(pn_graph::numeric::Error::Declaration));
    let p = inputs::scaling_procedure(&state, 16);
    let published = Published(p.clone());
    let bound = bind_procedure(&state, p.clone(), &published, Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    let record = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    assert!(record.work > 0 && record.replay_work > 0);
    inputs::check_solve(&state, &p, &record);
}

/// Claim: The rational fixture completes at its first sufficient five-step cap and independently replays with positive Work; caps one and two retain the inverse stopping refusal.
/// ´claim:numerics:scaling-controller-fixture-retains-stopping-controls´
/// ´test:integration:scaling-scalar-procedure´
#[test]
fn scaling_scalar_procedure() {
    let candidate = candidate(0, 2, None, "ring", "equal");
    let state = compile(&candidate).unwrap();
    let procedure = inputs::scalar::rational_procedure(&procedure(&state, 16));
    for cap in [1, 2] {
        assert!(matches!(
            inputs::scalar::rational(&procedure, cap),
            Err(pn_graph::numeric::controller::Error::Inverse(
                pn_graph::numeric::wall::Error::Iterations
            ))
        ));
    }
    let (input, record) = inputs::scalar::rational(&procedure, 5).unwrap();
    assert_eq!(record.verdict, pn_records::controller::Verdict::Delivered);
    let (checked, work) = pn_graph::numeric::controller::replay_with_work(&procedure, &input, None, &record).unwrap();
    assert_eq!(checked, record);
    assert!(work > 0 && work <= input.maximum_replay_work);
    assert_eq!(
        pn_graph::numeric::controller::replay(&procedure, &input, None, &record).unwrap(),
        checked
    );
}
