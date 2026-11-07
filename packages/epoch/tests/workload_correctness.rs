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
    check_solve(&state, &procedure, &record);
    assert!(solve_counters(&record).contains("K="));
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
    let p = scaling_procedure(&state, 16);
    let published = Published(p.clone());
    let bound = bind_procedure(&state, p.clone(), &published, Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    let record = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    assert!(record.work > 0 && record.replay_work > 0);
    check_solve(&state, &p, &record);
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

/// Claim: Prepared revision one and legacy solves independently certify overlapping standing enclosures on the same small frozen cases; revision and replay-counter substitutions refuse.
/// ´claim:numerics:prepared-solves-retain-certified-scope´
/// ´test:integration:prepared-solve-agreement´
#[test]
fn prepared_solve_agreement() {
    use nrz_cas::{Rational, limits::Budget};
    use pn_epoch::conserved::{self, prepared};
    for shape in ["ring", "dense"] {
        let c = candidate(inputs::SEED, 2, None, shape, "pass");
        let state = compile(&c).unwrap();
        let p = scaling_procedure(&state, 16);
        let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
        let fence = pn_epoch::fence::search(&bound, None).unwrap();
        let legacy = conserved::solve(&bound, &fence).unwrap();
        let old_checked = conserved::replay(&bound, &legacy).unwrap();
        let fresh = prepared::solve(&bound, &fence).unwrap();
        let checked = prepared::replay(&bound, &fresh).unwrap();
        assert_eq!(legacy.fence, fresh.solve.fence);
        assert_eq!(checked.solve.rounds.len(), old_checked.rounds.len());
        let mut budget = Budget::new(Limits::default()).unwrap();
        for (old, new) in old_checked.rounds.iter().zip(&checked.solve.rounds) {
            assert_eq!(
                old.standing.keys().collect::<Vec<_>>(),
                new.standing.keys().collect::<Vec<_>>()
            );
            for (actor, a) in &old.standing {
                let b = &new.standing[actor];
                let al = Rational::parse(&a.lower, &mut budget).unwrap();
                let au = Rational::parse(&a.upper, &mut budget).unwrap();
                let bl = Rational::parse(&b.lower, &mut budget).unwrap();
                let bu = Rational::parse(&b.upper, &mut budget).unwrap();
                assert!(!al.compare(&bu, &mut budget).unwrap().is_gt());
                assert!(!bl.compare(&au, &mut budget).unwrap().is_gt());
            }
        }
        for (a, total) in [
            (&fresh.production, fresh.solve.work),
            (&fresh.mandatory_replay, fresh.solve.replay_work),
        ] {
            assert!(a.setup > 0);
            assert_eq!(
                a.setup + a.driver_work + a.map_passes.iter().sum::<u64>() + a.final_checks.iter().sum::<u64>(),
                total
            );
        }
        let mut wrong = fresh.clone();
        let primitives = &mut wrong.solve.rounds[0].proposals[0].primitives;
        assert_eq!(primitives[2].query, primitives[3].query);
        primitives[3].evidence.bounds = None;
        assert!(matches!(
            prepared::replay(&bound, &wrong),
            Err(conserved::Error::Primitive(pn_graph::numeric::Error::Declaration))
        ));
        let mut wrong = fresh.clone();
        wrong.revision = "unknown".into();
        assert!(matches!(prepared::replay(&bound, &wrong), Err(conserved::Error::Scope)));
        let mut wrong = fresh.clone();
        wrong.solve.replay_work += 1;
        assert!(matches!(prepared::replay(&bound, &wrong), Err(conserved::Error::ReplayWork)));
        let mut wrong = fresh.clone();
        wrong.solve.rounds[0].certified.point.values_mut().next().unwrap().push('0');
        assert!(prepared::replay(&bound, &wrong).is_err());
    }
}

fn check_solve(s: &pn_epoch::compiler::CompiledState, p: &pn_records::solve::Procedure, r: &pn_records::conserved::SolveRecord) {
    let bound = bind_procedure(s, p.clone(), &Published(p.clone()), Limits::default()).unwrap();
    let replay = pn_epoch::conserved::replay(&bound, r).unwrap();
    assert_eq!(replay.rounds.len(), r.rounds.len());
    for (checked, produced) in replay.rounds.iter().zip(&r.rounds) {
        assert_eq!(checked.standing, produced.standing);
        assert_eq!(checked.residual, produced.residual);
        assert_eq!(checked.radius, produced.radius);
        assert_eq!(checked.certified.point, produced.certified.point);
        assert_eq!(checked.proposals.len(), produced.proposals.len());
    }
    assert_eq!(replay.fence, r.fence);
    assert_eq!(replay.work, r.replay_work);
    for round in &r.rounds {
        assert_eq!(round.certified.image.len(), s.view().base.rows.len());
        assert!(round.proposals.len() <= usize::try_from(p.maximum_iterations).unwrap());
    }
    let mut wrong = r.clone();
    wrong.replay_work += 1;
    assert!(matches!(
        pn_epoch::conserved::replay(&bound, &wrong),
        Err(pn_epoch::conserved::Error::ReplayWork)
    ));
}

/// Claim: Compact revision two independently reproduces exact contributing extrema, certifies overlapping standing with revision one and checks a claimed point with one map; altered replay counts and undeclared precision refuse, and threshold straddles remain indecisive, and thresholds above certified upper bounds fail.
/// ´claim:numerics:compact-solves-retain-certified-scope´
/// ´test:integration:compact-solve-agreement´
#[test]
fn compact_solve_agreement() {
    use nrz_cas::{Rational, limits::Budget};
    use pn_epoch::{
        compiler,
        conserved::{compact, prepared},
        solve,
    };
    for (n, shape) in [(2, "ring"), (3, "dense")] {
        let fixture = candidate(inputs::SEED, n, None, shape, "pass");
        let old = compile(&fixture).unwrap();
        let fresh = compiler::compact::compile_candidate(
            &fixture.context,
            &fixture.approval,
            &mut inputs::numeric(),
            Limits::default(),
            inputs::PRODUCTS,
        )
        .unwrap();
        assert_eq!(old.view().support.sources, fresh.view().support.sources);
        assert_eq!(old.view().support.ranges, fresh.view().support.ranges);
        assert_eq!(fresh.view().support.extrema_slots, 3 * n);
        let procedure = inputs::compact_scaling_procedure(&fresh, 16);
        assert_eq!(procedure, scaling_procedure(&old, 16));
        let old_bound = bind_procedure(&old, procedure.clone(), &Published(procedure.clone()), Limits::default()).unwrap();
        let new_bound =
            solve::compact::bind_procedure(&fresh, procedure.clone(), &Published(procedure.clone()), Limits::default()).unwrap();
        let af = pn_epoch::fence::search(&old_bound, None).unwrap();
        let bf = pn_epoch::fence::compact::search(&new_bound, None).unwrap();
        assert_eq!(af.evidence, bf.evidence);
        let old_record = prepared::solve(&old_bound, &af).unwrap();
        let old_checked = prepared::replay(&old_bound, &old_record).unwrap();
        let record = compact::solve(&new_bound, &bf).unwrap();
        let checked = compact::replay(&new_bound, &record).unwrap();
        assert!(compact_counters(&record.solve).contains("K="));
        let limits = Limits {
            work: 100_000_000,
            ..Limits::default()
        };
        let mut budget = Budget::new(limits).unwrap();
        for (old, new) in old_checked.solve.rounds.iter().zip(&checked.solve.rounds) {
            for (actor, r) in &old.standing {
                let interval = &new.standing[actor];
                assert!(
                    !Rational::parse(&r.lower, &mut budget)
                        .unwrap()
                        .compare(&Rational::parse(&interval.upper, &mut budget).unwrap(), &mut budget)
                        .unwrap()
                        .is_gt()
                );
                assert!(
                    !Rational::parse(&interval.lower, &mut budget)
                        .unwrap()
                        .compare(&Rational::parse(&r.upper, &mut budget).unwrap(), &mut budget)
                        .unwrap()
                        .is_gt()
                );
            }
            let thresholds = new
                .standing
                .iter()
                .map(|(old_bound, r)| (old_bound.clone(), r.lower.clone()))
                .collect();
            let check = compact::check_claim(&new_bound, &bf, &new.certified.point, 16, &thresholds).unwrap();
            assert_eq!(check.residual.proposals, Vec::new());
            assert_eq!(check.residual.standing, new.standing);
            assert!(check.thresholds.values().all(|v| *v == compact::Threshold::Pass));
            assert!(compact::check_claim(&new_bound, &bf, &new.certified.point, 17, &thresholds).is_err());
            let middle = new
                .standing
                .iter()
                .map(|(old_bound, r)| {
                    (
                        old_bound.clone(),
                        Rational::parse(&r.lower, &mut budget)
                            .unwrap()
                            .add(&Rational::parse(&r.upper, &mut budget).unwrap(), &mut budget)
                            .unwrap()
                            .div(&Rational::parse("2", &mut budget).unwrap(), &mut budget)
                            .unwrap()
                            .exact_string(&mut budget)
                            .unwrap(),
                    )
                })
                .collect();
            let check = compact::check_claim(&new_bound, &bf, &new.certified.point, 16, &middle).unwrap();
            assert!(check.thresholds.values().any(|v| *v == compact::Threshold::Indecisive));
            fail_thresholds(&new_bound, &bf, new, &mut budget);
        }
        let mut bad = record.clone();
        bad.solve.replay_work += 1;
        assert!(matches!(
            compact::replay(&new_bound, &bad),
            Err(pn_epoch::conserved::Error::ReplayWork)
        ));
        let mut bad = record.clone();
        bad.revision = "prepared-rational-v1".into();
        assert!(matches!(
            compact::replay(&new_bound, &bad),
            Err(pn_epoch::conserved::Error::Scope)
        ));
    }
}

/// Claim: Bounded activation replay reconstructs its scalar results and Work and refuses a changed plan, revision or scalar result; independent revision-two residual enclosures overlap on the declared small fixtures.
/// ´claim:numerics:bounded-activation-solves-replay´
/// ´test:integration:bounded-activation-solves´
#[test]
fn bounded_activation_solves() {
    use nrz_cas::{Rational, limits::Budget};
    use pn_epoch::{
        compiler,
        conserved::{bounded, compact},
        solve,
    };
    for (n, shape) in [(3, "dense"), (2, "ring")] {
        let fixture = candidate(inputs::SEED, n, None, shape, "pass");
        let state = compiler::compact::compile_candidate(
            &fixture.context,
            &fixture.approval,
            &mut inputs::numeric(),
            Limits::default(),
            inputs::PRODUCTS,
        )
        .unwrap();
        let procedure = inputs::compact_scaling_procedure(&state, 16);
        let bound = solve::compact::bind_procedure(&state, procedure.clone(), &Published(procedure), Limits::default()).unwrap();
        let fence = pn_epoch::fence::compact::search(&bound, None).unwrap();
        let old = compact::solve(&bound, &fence).unwrap();
        compact::replay(&bound, &old).unwrap();
        let plan = bounded::Plan { working_precision: 32 };
        let result = bounded::solve(plan, &bound, &fence).unwrap();
        let checked = bounded::replay(plan, &bound, &result).unwrap();
        assert!(bounded_counters(&result.solve).contains("K="));
        assert_eq!(checked.solve.rounds.len(), result.solve.rounds.len());
        for (a, b) in checked.solve.rounds.iter().zip(&result.solve.rounds) {
            assert_eq!(a.standing, b.standing);
            assert_eq!(a.residual, b.residual);
            assert_eq!(a.radius, b.radius);
            assert_eq!(a.certified.bounded, b.certified.bounded);
            assert_eq!(a.proposals.len(), b.proposals.len());
            for (a, b) in a.proposals.iter().zip(&b.proposals) {
                assert_eq!(a.bounded, b.bounded);
                assert_eq!(a.image, b.image);
            }
        }
        assert_eq!(
            result.solve.work,
            result.production.setup
                + result.production.driver_work
                + result.production.map_passes.iter().sum::<u64>()
                + result.production.final_checks.iter().sum::<u64>()
        );
        assert_eq!(
            result.solve.replay_work,
            result.mandatory_replay.setup
                + result.mandatory_replay.driver_work
                + result.mandatory_replay.map_passes.iter().sum::<u64>()
                + result.mandatory_replay.final_checks.iter().sum::<u64>()
        );
        let mut budget = Budget::new(Limits::default()).unwrap();
        for (a, b) in old.solve.rounds.iter().zip(&checked.solve.rounds) {
            for (actor, a) in &a.standing {
                let b = &b.standing[actor];
                assert!(
                    !Rational::parse(&a.lower, &mut budget)
                        .unwrap()
                        .compare(&Rational::parse(&b.upper, &mut budget).unwrap(), &mut budget)
                        .unwrap()
                        .is_gt()
                );
                assert!(
                    !Rational::parse(&b.lower, &mut budget)
                        .unwrap()
                        .compare(&Rational::parse(&a.upper, &mut budget).unwrap(), &mut budget)
                        .unwrap()
                        .is_gt()
                );
            }
        }
        assert!(
            result
                .solve
                .rounds
                .iter()
                .any(|r| r.certified.bounded.iter().any(|s| s.result.is_ok()))
        );
        bounded_refusals(&bound, &old, &result, &fence);
        if n == 2 {
            bounded_non_dyadic(&state);
        }
    }
}
fn bounded_non_dyadic(state: &pn_epoch::compiler::compact::CompiledState) {
    use pn_epoch::{conserved::bounded, solve};
    let mut procedure = inputs::compact_scaling_procedure(state, 16);
    procedure.grid = vec!["1/3".into(), "0".into()];
    let bound = solve::compact::bind_procedure(state, procedure.clone(), &Published(procedure), Limits::default()).unwrap();
    let fence = pn_epoch::fence::compact::search(&bound, None).unwrap();
    assert_eq!(fence.selected.as_deref(), Some("1/3"));
    let plan = bounded::Plan { working_precision: 32 };
    let record = bounded::solve(plan, &bound, &fence).unwrap();
    bounded::replay(plan, &bound, &record).unwrap();
    assert!(record.solve.rounds.iter().any(|r| {
        r.certified
            .bounded
            .iter()
            .any(|s| s.result == Err(pn_graph::numeric::activation::bounded::Refusal::NonDyadicExponent))
    }));
    assert!(record.solve.rounds.iter().any(|r| r.certified.primitives.iter().any(|s| {
        s.query
            .nodes
            .iter()
            .any(|n| matches!(n, pn_records::primitive::Node::PositivePower(_, exponent) if exponent == "1/3"))
    })));
}
fn bounded_refusals(
    bound: &pn_epoch::solve::compact::BoundProcedure<'_>,
    old: &pn_epoch::conserved::compact::Record,
    result: &pn_epoch::conserved::bounded::Record,
    fence: &pn_epoch::fence::Search,
) {
    use pn_epoch::conserved::{bounded, compact};
    let plan = result.plan;
    let mut changed = result.clone();
    changed.revision.clone_from(&old.revision);
    assert!(matches!(
        bounded::replay(plan, bound, &changed),
        Err(pn_epoch::conserved::Error::Scope)
    ));
    let mut changed_old = old.clone();
    changed_old.revision.clone_from(&result.revision);
    assert!(matches!(
        compact::replay(bound, &changed_old),
        Err(pn_epoch::conserved::Error::Scope)
    ));
    assert!(matches!(
        bounded::replay(bounded::Plan { working_precision: 48 }, bound, result),
        Err(pn_epoch::conserved::Error::Scope)
    ));
    let mut changed = result.clone();
    changed.solve.rounds[0].certified.bounded[0].work += 1;
    assert!(matches!(
        bounded::replay(plan, bound, &changed),
        Err(pn_epoch::conserved::Error::Map)
    ));
    let mut changed = result.clone();
    changed.solve.rounds[0].certified.bounded[0].result = Err(pn_graph::numeric::activation::bounded::Refusal::OutsideDomain);
    assert!(matches!(
        bounded::replay(plan, bound, &changed),
        Err(pn_epoch::conserved::Error::Map)
    ));
    let fallback_plan = bounded::Plan { working_precision: 16 };
    let fallback = bounded::solve(fallback_plan, bound, fence).unwrap();
    bounded::replay(fallback_plan, bound, &fallback).unwrap();
    assert!(fallback.solve.rounds.iter().any(|r| {
        r.certified
            .bounded
            .iter()
            .any(|s| s.result == Err(pn_graph::numeric::activation::bounded::Refusal::TargetNotCertifiable))
    }));
    assert!(fallback.solve.rounds.iter().any(|r| r.certified.primitives.len() > 2));
}

/// Claim: On explicit chain and hub support over a checked ledger, compact extrema equal the independent reachability oracle and visit only HZ edges with three N-sized buffers; one fewer permitted edge visit refuses.
/// ´claim:compiler:compact-width-retains-two-buffer-extrema´
/// ´test:integration:compact-width-support´
#[test]
fn compact_width_support() {
    use pn_epoch::{
        base::{BaseEntry, BaseScore},
        support,
    };
    use std::collections::{BTreeMap, BTreeSet};
    for n in [4, 16] {
        let c = candidate(0, n, None, "ring", "pass");
        let state = compile(&c).unwrap();
        let input = state.package().input();
        let declarations = width_inputs(input.inputs.last().unwrap(), n);
        let price = input.prices.last().unwrap();
        let actors: Vec<_> = state.view().base.rows.keys().cloned().collect();
        for hub in [false, true] {
            let mut base = state.view().base.clone();
            base.rows = actors
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    let targets: Vec<_> = if hub && i == 0 {
                        (0..n).collect()
                    } else if hub {
                        vec![i, 0]
                    } else if i + 1 < n {
                        vec![i, i + 1]
                    } else {
                        vec![i]
                    };
                    let row = targets
                        .into_iter()
                        .map(|j| {
                            (
                                actors[j].clone(),
                                BaseEntry {
                                    score: BaseScore::Exact("1".into()),
                                    cells: BTreeSet::new(),
                                },
                            )
                        })
                        .collect::<BTreeMap<_, _>>();
                    (a.clone(), row)
                })
                .collect();
            let old = support::compile_support(
                &declarations,
                price,
                &state.view().ledger,
                &base,
                &mut inputs::numeric(),
                Limits::default(),
                inputs::PRODUCTS,
            )
            .unwrap();
            let fresh = support::compact::compile_support(
                &declarations,
                price,
                &state.view().ledger,
                &base,
                &mut inputs::numeric(),
                Limits::default(),
                inputs::PRODUCTS,
            )
            .unwrap();
            assert_eq!(fresh.sources, old.sources);
            assert_eq!(fresh.ranges, old.ranges);
            let z = base.rows.values().map(BTreeMap::len).sum::<usize>();
            assert_eq!(
                fresh.support_visits,
                u64::try_from(declarations.parameters().depth_mass.len() * z).unwrap()
            );
            assert_eq!(fresh.extrema_slots, 3 * n);
            assert!(
                old.by_depth
                    .values()
                    .any(|rows| rows.values().map(BTreeSet::len).sum::<usize>() > z)
            );
            assert!(matches!(
                support::compact::compile_support(
                    &declarations,
                    price,
                    &state.view().ledger,
                    &base,
                    &mut inputs::numeric(),
                    Limits::default(),
                    fresh.support_visits - 1
                ),
                Err(support::SupportError::Products)
            ));
        }
    }
}

fn width_inputs(original: &pn_epoch::CompilerInputs, depth: usize) -> pn_epoch::CompilerInputs {
    let declaration = pn_records::Declaration {
        id: original.parameters().edition.clone(),
        announced_at: 0,
        effective_at: 1,
        content: pn_records::DeclarationContent::Opaque,
    };
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let records = pn_records::validate_record(&[], &history, &[declaration]).unwrap();
    let mut edition = original.constants().content().clone();
    for constant in &mut edition.constants {
        if let pn_records::constants::ConstantDefinition::Literal { name, value } = constant
            && name == &original.parameters().hop_limit
        {
            *value = inputs::numeric().literal(&depth.to_string()).unwrap();
        }
    }
    let constants = pn_records::constants::bind_constants(&records, vec![edition]).unwrap();
    let mut parameters = original.parameters().clone();
    parameters.depth_mass = vec!["zero".into(); depth];
    *parameters.depth_mass.last_mut().unwrap() = "one".into();
    pn_epoch::bind_inputs(&constants, parameters, Limits::default()).unwrap()
}

fn solve_counters(r: &pn_records::conserved::SolveRecord) -> String {
    let k: usize = r.rounds.iter().map(|r| r.proposals.len()).sum();
    let primitive_count: usize = r
        .rounds
        .iter()
        .map(|r| r.certified.primitives.len() + r.proposals.iter().map(|p| p.primitives.len()).sum::<usize>())
        .sum();
    let transcript = format!("{r:?}");
    format!(
        "K={k} precision_rounds={} primitive_count={primitive_count} solve_work={} replay_work={} diagnostic_transcript_bytes={} retained_heap_bytes=unavailable-no-allocator-counter residuals={:?}",
        r.rounds.len(),
        r.work,
        r.replay_work,
        transcript.len(),
        r.rounds.iter().map(|r| &r.residual).collect::<Vec<_>>()
    )
}
fn scaling_procedure(state: &pn_epoch::compiler::CompiledState, bits: u32) -> pn_records::solve::Procedure {
    let mut p = procedure(state, bits);
    let work = 20_000_000_000;
    p.maximum_work = work;
    p.maximum_solve_work = work;
    p.maximum_replay_work = work;
    let e = p.enclosure.as_mut().unwrap();
    e.operation.work = work;
    e.operation.arithmetic_steps = 1_000_000_000;
    e.store = e.operation.clone();
    p
}

fn compact_counters(r: &pn_epoch::conserved::compact::records::SolveRecord) -> String {
    let k: usize = r.rounds.iter().map(|r| r.proposals.len()).sum();
    let primitive_count: usize = r
        .rounds
        .iter()
        .map(|r| r.certified.primitives.len() + r.proposals.iter().map(|p| p.primitives.len()).sum::<usize>())
        .sum();
    let transcript = format!("{r:?}");
    format!(
        "K={k} precision_rounds={} primitive_count={primitive_count} solve_work={} replay_work={} diagnostic_transcript_bytes={} retained_heap_bytes=unavailable-no-allocator-counter residuals={:?}",
        r.rounds.len(),
        r.work,
        r.replay_work,
        transcript.len(),
        r.rounds.iter().map(|r| &r.residual).collect::<Vec<_>>()
    )
}

/// Claim: Previous-pass memoization independently replays identical scalar evidence, reduces charged Work on two small histories, and refuses altered hit counters and revision substitutions.
/// ´claim:numerics:memoized-solves-retain-exact-request-evidence´
/// ´test:integration:memoized-solve-agreement´
#[test]
fn memoized_solve_agreement() {
    use pn_epoch::{
        compiler,
        conserved::{bounded, memoized},
        solve,
    };
    for (n, shape) in [(4, "ring"), (3, "dense")] {
        let c = candidate(inputs::SEED, n, None, shape, "pass");
        let state = compiler::compact::compile_candidate(
            &c.context,
            &c.approval,
            &mut inputs::numeric(),
            Limits::default(),
            inputs::PRODUCTS,
        )
        .unwrap();
        let p = inputs::compact_scaling_procedure(&state, 16);
        let bound = solve::compact::bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
        let fence = pn_epoch::fence::compact::search(&bound, None).unwrap();
        let old = bounded::solve(bounded::Plan { working_precision: 32 }, &bound, &fence).unwrap();
        let plan = memoized::Plan { working_precision: 32 };
        let fresh = memoized::solve(plan, &bound, &fence).unwrap();
        assert!(inputs::memoized_counters(&fresh.solve).contains("K="));
        let checked = memoized::replay(plan, &bound, &fresh).unwrap();
        assert!(fresh.solve.work < old.solve.work);
        if n == 4 {
            assert!(
                fresh
                    .solve
                    .rounds
                    .iter()
                    .flat_map(|r| &r.proposals)
                    .any(|m| m.memo.previous_hits > 0)
            );
        }
        for (a, b) in old.solve.rounds.iter().zip(&checked.solve.rounds) {
            assert_eq!(a.standing, b.standing);
            for (a, b) in a
                .proposals
                .iter()
                .chain([&a.certified])
                .zip(b.proposals.iter().chain([&b.certified]))
            {
                assert_eq!(a.image, b.image);
                assert_eq!(a.bounded.len(), b.bounded.len());
                for (a, b) in a.bounded.iter().zip(&b.bounded) {
                    assert_eq!(format!("{:?}", a.input), format!("{:?}", b.input));
                    assert_eq!(a.result, b.result);
                    assert_eq!(a.work, b.work);
                }
                assert_eq!(b.memo.hits + b.memo.misses, u64::try_from(b.bounded.len()).unwrap());
                assert!(b.memo.retained <= 3 * n);
            }
        }
        if n == 3 {
            let fallback_plan = memoized::Plan { working_precision: 16 };
            let fallback = memoized::solve(fallback_plan, &bound, &fence).unwrap();
            memoized::replay(fallback_plan, &bound, &fallback).unwrap();
            assert!(fallback.solve.rounds.iter().any(|r| r.certified.primitives.len() > 2));
            let old_fallback = bounded::solve(bounded::Plan { working_precision: 16 }, &bound, &fence).unwrap();
            assert_fallback_equivalence(&old_fallback.solve, &fallback.solve);
        }
        let mut bad = fresh.clone();
        bad.solve.rounds[0].proposals[0].memo.hits += 1;
        assert!(matches!(
            memoized::replay(plan, &bound, &bad),
            Err(pn_epoch::conserved::Error::Map)
        ));
        let mut bad = fresh.clone();
        bad.revision = old.revision.clone();
        assert!(matches!(
            memoized::replay(plan, &bound, &bad),
            Err(pn_epoch::conserved::Error::Scope)
        ));
        let mut bad = old.clone();
        bad.revision = fresh.revision.clone();
        assert!(matches!(
            bounded::replay(bad.plan, &bound, &bad),
            Err(pn_epoch::conserved::Error::Scope)
        ));
    }
}

fn bounded_counters(r: &pn_epoch::conserved::bounded::records::SolveRecord) -> String {
    let k: usize = r.rounds.iter().map(|r| r.proposals.len()).sum();
    let primitive_count: usize = r
        .rounds
        .iter()
        .map(|r| r.certified.primitives.len() + r.proposals.iter().map(|p| p.primitives.len()).sum::<usize>())
        .sum();
    let transcript = format!("{r:?}");
    format!(
        "K={k} precision_rounds={} primitive_count={primitive_count} solve_work={} replay_work={} diagnostic_transcript_bytes={} retained_heap_bytes=unavailable-no-allocator-counter residuals={:?}",
        r.rounds.len(),
        r.work,
        r.replay_work,
        transcript.len(),
        r.rounds.iter().map(|r| &r.residual).collect::<Vec<_>>()
    )
}

fn fail_thresholds(
    bound: &pn_epoch::solve::compact::BoundProcedure<'_>,
    fence: &pn_epoch::fence::Search,
    new: &pn_epoch::conserved::compact::records::ResidualRound,
    budget: &mut nrz_cas::limits::Budget,
) {
    use nrz_cas::Rational;
    use pn_epoch::conserved::compact;
    let above = new
        .standing
        .iter()
        .map(|(actor, r)| {
            let upper = Rational::parse(&r.upper, budget).unwrap();
            let one = Rational::parse("1", budget).unwrap();
            (actor.clone(), upper.add(&one, budget).unwrap().exact_string(budget).unwrap())
        })
        .collect();
    let check = compact::check_claim(bound, fence, &new.certified.point, 16, &above).unwrap();
    assert!(check.thresholds.values().all(|v| *v == compact::Threshold::Fail));
}

/// Claim: Revision five retains independent replay and certified images under its strict power domain, records zero-exponent exact fallback, and refuses substitutions with revision four in both directions.
/// ´claim:numerics:domain-solves-retain-versioned-fallback´
/// ´test:integration:domain-solve-agreement´
#[test]
fn domain_solve_agreement() {
    use pn_epoch::{compiler, conserved::memoized, solve};
    for zero in [false, true] {
        let c = candidate(inputs::SEED, 2, None, "ring", "pass");
        let state = compiler::compact::compile_candidate(
            &c.context,
            &c.approval,
            &mut inputs::numeric(),
            Limits::default(),
            inputs::PRODUCTS,
        )
        .unwrap();
        let mut p = inputs::compact_scaling_procedure(&state, 16);
        if zero {
            p.fence.as_mut().unwrap().shape.fill("zero".into());
        }
        let bound = solve::compact::bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
        let fence = pn_epoch::fence::compact::search(&bound, None).unwrap();
        assert_ne!(fence.selected.as_deref(), Some("0"));
        let plan = memoized::Plan { working_precision: 32 };
        let old = memoized::solve(plan, &bound, &fence).unwrap();
        let fresh = memoized::domain_solve(plan, &bound, &fence).unwrap();
        memoized::replay(plan, &bound, &old).unwrap();
        memoized::domain_replay(plan, &bound, &fresh).unwrap();
        assert!(matches!(
            memoized::replay(plan, &bound, &fresh),
            Err(pn_epoch::conserved::Error::Scope)
        ));
        assert!(matches!(
            memoized::domain_replay(plan, &bound, &old),
            Err(pn_epoch::conserved::Error::Scope)
        ));
        assert_ne!(fresh.solve.work, old.solve.work);
        assert_eq!(old.solve.rounds.len(), fresh.solve.rounds.len());
        let mut refusals = 0;
        for (old, new) in old.solve.rounds.iter().zip(&fresh.solve.rounds) {
            assert_eq!(old.standing, new.standing);
            for (a, b) in old
                .proposals
                .iter()
                .chain([&old.certified])
                .zip(new.proposals.iter().chain([&new.certified]))
            {
                assert_eq!(a.image, b.image);
                for scalar in &b.bounded {
                    if let memoized::records::ScalarInput::Power { exponent, .. } = &scalar.input {
                        if zero {
                            assert_eq!(exponent, "0");
                            assert_eq!(
                                scalar.result,
                                Err(pn_graph::numeric::activation::bounded::Refusal::OutsideDomain)
                            );
                            refusals += 1;
                        } else {
                            assert!(scalar.result.is_ok());
                        }
                    }
                }
            }
        }
        if zero {
            assert!(refusals > 0);
        }
    }
}

fn assert_fallback_equivalence(
    old_fallback: &pn_epoch::conserved::bounded::records::SolveRecord,
    fallback: &pn_epoch::conserved::memoized::records::SolveRecord,
) {
    assert_eq!(old_fallback.rounds.len(), fallback.rounds.len());
    for (a, b) in old_fallback.rounds.iter().zip(&fallback.rounds) {
        assert_eq!(a.proposals.len(), b.proposals.len());
        for (a, b) in a
            .proposals
            .iter()
            .chain([&a.certified])
            .zip(b.proposals.iter().chain([&b.certified]))
        {
            assert_eq!(a.primitives.len(), b.primitives.len());
            for (a, b) in a.primitives.iter().zip(&b.primitives) {
                assert_eq!(a.query, b.query);
                assert_eq!(a.evidence.bounds, b.evidence.bounds);
                assert_eq!(a.evidence.outcome, b.evidence.outcome);
                assert_eq!(a.evidence.attachment, b.evidence.attachment);
            }
        }
    }
}
