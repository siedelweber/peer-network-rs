use super::*;
use pn_epoch::{
    admission::{self, AdmissionRefusal, FinalProcedure, FinalRefusal, Gate},
    package, schedules,
};

#[derive(Debug)]
struct Causes(package::CandidateInput);
impl package::CandidateVerifier for Causes {
    fn candidate_causes(&self, input: &package::CandidateInput) -> bool {
        input.causes.bindings == self.0.causes.bindings
            && input.causes.history.acts() == self.0.causes.history.acts()
            && input.causes.inputs == self.0.causes.inputs
            && input.causes.prices == self.0.causes.prices
    }
}
impl package::ClosureVerifier for Causes {
    fn host_determination(&self, input: &package::CandidateInput) -> bool {
        input.closure == self.0.closure
    }
}

fn candidate(acts: &[pn_records::CandidateAct], boundary: u64, burns: &[(&str, &str)]) -> package::CandidateContext {
    let source = joined::package_at_numeraires(acts, boundary, burns, NumberId::NumbersAdmissionWall.value(), &["1", "1"]);
    let input = package::CandidateInput {
        causes: source.input().clone(),
        closure: package::ClosureStatement {
            policy: package::ClosurePolicy {
                target: NumberId::NumbersAdmissionTarget.integer(),
                minimum_ticks: 0,
                maximum_ticks: NumberId::NumbersAdmissionMaximumTicks.integer(),
                clock: "fixture-clock".into(),
            },
            opened_at: 0,
            determined_at: NumberId::NumbersAdmissionMaximumTicks.integer(),
            cause: package::ClosureCause::MaximumDuration,
            attestation: "fixture-determination".into(),
        },
    };
    let verifier = Causes(input.clone());
    package::verify_candidate(input, &verifier, &verifier).unwrap()
}

fn compiled(context: &package::CandidateContext) -> pn_epoch::compiler::CompiledState {
    pn_epoch::compiler::compile_candidate(
        context,
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        NumberId::NumbersAdmissionProductCeiling.integer(),
    )
    .unwrap()
}

fn procedure(context: &package::CandidateContext) -> FinalProcedure {
    let state = compiled(context);
    assert!(matches!(state.package(), pn_epoch::compiler::CompiledSource::Candidate(_)));
    let bits = u32::try_from(NumberId::NumbersAdmissionScopePrecision.integer()).unwrap();
    let mut plan = fence_procedure(&state);
    plan.precision = Precision::AbsoluteWidthBits(vec![bits]);
    plan.enclosure.as_mut().unwrap().refinement.precision = bits;
    plan.endpoint_grid = NumberId::NumbersAdmissionEndpointGrid.value().into();
    FinalProcedure {
        solve: plan,
        arithmetic: Limits::default(),
        maximum_products: NumberId::NumbersAdmissionProductCeiling.integer(),
    }
}

fn schedule(context: &package::CandidateContext, policy: &str) -> schedules::CheckedSchedule {
    let binding = context.input().causes.bindings.last().unwrap();
    let d = admission::declare_schedule(
        admission::ScheduleInput {
            controller: "canonical-interim-v1".into(),
            announced_at: binding.marker.index - 1,
            initialization: admission::InitializationInput {
                floor: Some(binding.inputs.constants().content().floor),
                wall: Some(binding.price.wall().exact().into()),
                policy_floor: Some(policy.into()),
                effective_boundary: Some(binding.marker.index),
                parameters: Some(admission::ControllerParameters {
                    absolute_cap: NumberId::NumbersEffectiveScheduleAbsoluteCap.value().into(),
                    relative_cap: NumberId::NumbersEffectiveScheduleRelativeCap.value().into(),
                    deadband: "0".into(),
                    margin: NumberId::NumbersReferenceMargin.value().into(),
                }),
            },
            numeraire: binding.price.numeraire().clone(),
            delivery: admission::Delivery::ExactRational,
            refinement: admission::Refinement {
                precision_bits: vec![u32::try_from(NumberId::NumbersAdmissionScopePrecision.integer()).unwrap()],
                maximum_work: NumberId::NumbersControllerTestWork.integer(),
                maximum_replay_work: NumberId::NumbersControllerTestWork.integer(),
            },
        },
        Limits::default(),
    )
    .unwrap();
    let r = schedules::evaluate(&d, &[], None, Limits::default()).unwrap();
    schedules::replay(&d, &[], None, Limits::default(), &r).unwrap()
}

fn run(
    context: &package::CandidateContext,
    plan: &FinalProcedure,
    led_schedule: &schedules::CheckedSchedule,
) -> Result<package::AdmittedBoundary, FinalRefusal> {
    admission::admit(
        context,
        led_schedule,
        plan,
        &joined::Verifier,
        &Published(plan.solve.clone()),
        joined::numeric(),
    )
}

fn self_acts() -> Vec<pn_records::CandidateAct> {
    let mut opinion = joined::act("Opinion", "a", 2, 1);
    opinion.legs[0].target = joined::named("prof", "a");
    vec![opinion, joined::act("Registration", "a", 1, 1)]
}

/// Claim: The finite self-supported candidate checks Registration and a repeated author's complete act at one effective rational price, retains post-debit standing exactly at the safety and policy equalities, counts each stamp once, and constructs immutable admission only after the independently replayed final solve; no persistence or deployment authority is asserted.
/// ´claim:admission:final-gates-retain-debits-and-frozen-stamps´
/// ´test:integration:admission-equalities´
#[test]
fn admission_equalities() {
    let context = candidate(&self_acts(), 1, &[("a", NumberId::NumbersAdmissionRepeatedBurn.value())]);
    let mut input = context.input().clone();
    input.closure.policy.target = u64::try_from(self_acts().len()).unwrap();
    let verifier = Causes(input.clone());
    let context = package::verify_candidate(input, &verifier, &verifier).unwrap();
    let plan = procedure(&context);
    let led_schedule = schedule(&context, NumberId::NumbersAdmissionWall.value());
    let before = format!("{:?}", context.input());
    let admitted = run(&context, &plan, &led_schedule).unwrap();
    let evidence = admitted.evidence();
    assert_eq!(evidence.standing.as_ref().unwrap().rounds.last().unwrap().certified.rung, "1");
    let wall = Fraction::parse(NumberId::NumbersAdmissionWall.value());
    let burn = Fraction::parse(NumberId::NumbersAdmissionRepeatedBurn.value());
    for (i, debit) in evidence.solvency.iter().enumerate() {
        let count = Fraction::new(i128::try_from(i).unwrap(), 1);
        assert_eq!(Fraction::parse(&debit.before), burn.minus(wall.times(count)));
        assert_eq!(Fraction::parse(&debit.debit), wall);
        assert_eq!(
            Fraction::parse(&debit.after),
            burn.minus(wall.times(count.plus(Fraction(1, 1))))
        );
    }
    let final_round = evidence.rounds.last().unwrap();
    assert_eq!(final_round.stamps.len(), self_acts().len());
    for stamp in final_round.stamps.values() {
        assert_eq!(Fraction::parse(&stamp.lower), wall);
        assert_eq!(Fraction::parse(&stamp.upper), wall);
    }
    assert_eq!(Fraction::parse(&final_round.epoch.lower), wall);
    assert_eq!(Fraction::parse(&final_round.epoch.upper), wall);
    assert_eq!(final_round.headroom.lower, "0");
    assert_eq!(final_round.headroom.upper, "0");
    assert_eq!(format!("{:?}", context.input()), before);
    let mut low = plan.clone();
    low.solve.precision = Precision::AbsoluteWidthBits(vec![1]);
    low.solve.enclosure.as_mut().unwrap().refinement.precision = 1;
    assert!(matches!(
        run(&context, &low, &led_schedule),
        Err(FinalRefusal::Solve(error)) if matches!(*error, pn_epoch::conserved::Error::Scope)
    ));
}

/// Claim: The finite two-author candidate refuses an individual deficit despite a passing act-weighted mean; own insolvency and a failing epoch policy remain separate refusals, and rejected attempts do not change candidate causes or the checked schedule.
/// ´claim:admission:individual-and-own-gates-cannot-be-averaged´
/// ´test:integration:admission-refusals´
#[test]
fn admission_refusals() {
    let acts = vec![joined::act("Registration", "b", 2, 1), joined::act("Registration", "a", 1, 1)];
    let context = candidate(
        &acts,
        1,
        &[
            ("b", NumberId::NumbersAdmissionRichBurn.value()),
            ("a", NumberId::NumbersAdmissionPoorBurn.value()),
        ],
    );
    let plan = procedure(&context);
    let led_schedule = schedule(&context, NumberId::NumbersAdmissionWall.value());
    let before = format!("{:?}", context.input());
    let checked_schedule = led_schedule.record().clone();
    let state = compiled(&context);
    let verifier = Published(plan.solve.clone());
    let bound = bind_procedure(&state, plan.solve.clone(), &verifier, Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    let solved = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    let ranges = &solved.rounds.last().unwrap().standing;
    let mean = Fraction::parse(&ranges["a"].lower)
        .plus(Fraction::parse(&ranges["b"].lower))
        .over(Fraction(2, 1));
    let wall = Fraction::parse(NumberId::NumbersAdmissionWall.value());
    assert!(mean.minus(wall).0 > 0);
    assert!(matches!(
        run(&context, &plan, &led_schedule),
        Err(FinalRefusal::Refused(AdmissionRefusal::Failed(Gate::IndividualSafety)))
    ));
    let poor = candidate(
        &acts,
        1,
        &[
            ("b", NumberId::NumbersAdmissionRichBurn.value()),
            ("a", NumberId::NumbersAdmissionInsolventBurn.value()),
        ],
    );
    assert!(matches!(
        run(&poor, &plan, &led_schedule),
        Err(FinalRefusal::Refused(AdmissionRefusal::Failed(Gate::OwnSolvency)))
    ));
    let equal = candidate(&self_acts(), 1, &[("a", NumberId::NumbersAdmissionRepeatedBurn.value())]);
    let pp = procedure(&equal);
    let high = schedule(&equal, NumberId::NumbersAdmissionRefusedPolicy.value());
    assert!(matches!(
        run(&equal, &pp, &high),
        Err(FinalRefusal::Refused(AdmissionRefusal::Failed(Gate::EpochPolicy)))
    ));
    assert_eq!(format!("{:?}", context.input()), before);
    assert_eq!(led_schedule.record(), &checked_schedule);
}

/// Claim: The empty final epoch has vacuous stamp and average gates, adds no debit or count and emits no fabricated mean or headroom; the admitted result retains the same checked historical causes.
/// ´claim:admission:empty-final-set-has-no-stamp-or-debit´
/// ´test:integration:admission-empty´
#[test]
fn admission_empty() {
    let context = candidate(
        &[joined::act("Registration", "a", 1, 1)],
        2,
        &[("a", NumberId::NumbersAdmissionRepeatedBurn.value())],
    );
    let plan = procedure(&context);
    let led_schedule = schedule(&context, NumberId::NumbersAdmissionWall.value());
    let state = compiled(&context);
    assert_eq!(
        state.view().ledger.counts[&pn_records::burn::Address("a".into())],
        pn_records::numerics::ActionCount(1)
    );
    assert_eq!(state.view().ledger.debits.len(), 1);
    let result = run(&context, &plan, &led_schedule).unwrap();
    assert_eq!(result.evidence().solvency.as_slice(), &[]);
    assert_eq!(result.evidence().rounds.as_slice(), &[]);
    assert!(result.evidence().standing.is_none());
    assert_eq!(
        result.candidate().input().causes.history.acts(),
        context.input().causes.history.acts()
    );
}

fn coupled() -> Vec<pn_records::CandidateAct> {
    let mut opinion = joined::act("Opinion", "b", 3, 1);
    opinion.legs[0].target = joined::named("prof", "a");
    vec![
        opinion,
        joined::act("Registration", "b", 2, 1),
        joined::act("Registration", "a", 1, 1),
    ]
}

/// Claim: The finite coupled candidate keeps full own emission distinct from post-transport safety and refuses relational funding of own solvency; the separately declared positive-rung policy threshold remains unresolved when the certified mean straddles it, rather than publishing an inferred equality.
/// ´claim:admission:relational-support-and-uncertainty-do-not-waive-gates´
/// ´test:integration:admission-boundaries´
#[test]
fn admission_boundaries() {
    let context = candidate(
        &coupled(),
        1,
        &[
            ("b", NumberId::NumbersAdmissionSupportingBurn.value()),
            ("a", NumberId::NumbersAdmissionSupportedBurn.value()),
        ],
    );
    let mut plan = procedure(&context);
    plan.solve.grid = vec!["0".into()];
    let led_schedule = schedule(&context, NumberId::NumbersAdmissionWall.value());
    let state = compiled(&context);
    let amount = Fraction::parse(state.view().ledger.balances[&pn_records::burn::Address("a".into())].exact());
    let wall = Fraction::parse(NumberId::NumbersAdmissionWall.value());
    assert!(amount.minus(wall).0 > 0);
    assert_eq!(state.view().support.sources["a"].emission, "1");
    let verifier = Published(plan.solve.clone());
    let bound = bind_procedure(&state, plan.solve.clone(), &verifier, Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    assert_eq!(fence.selected.as_deref(), Some(plan.solve.grid[0].as_str()));
    let solved = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    assert!(
        Fraction::parse(&solved.rounds.last().unwrap().standing["a"].upper)
            .minus(wall)
            .0
            < 0
    );
    assert!(matches!(
        run(&context, &plan, &led_schedule),
        Err(FinalRefusal::Refused(AdmissionRefusal::Failed(Gate::IndividualSafety)))
    ));
    let insolvent = candidate(
        &coupled(),
        1,
        &[
            ("b", NumberId::NumbersAdmissionRichBurn.value()),
            ("a", NumberId::NumbersAdmissionInsolventBurn.value()),
        ],
    );
    assert!(matches!(
        run(&insolvent, &plan, &led_schedule),
        Err(FinalRefusal::Refused(AdmissionRefusal::Failed(Gate::OwnSolvency)))
    ));
    let straddle = candidate(
        &coupled(),
        1,
        &[
            ("b", NumberId::NumbersAdmissionStraddleSourceBurn.value()),
            ("a", NumberId::NumbersAdmissionStraddleTargetBurn.value()),
        ],
    );
    let mut plan = procedure(&straddle);
    plan.solve.grid = vec![NumberId::NumbersAdmissionPositiveStrength.value().into(), "0".into()];
    let led_schedule = schedule(&straddle, NumberId::NumbersAdmissionStraddlePolicy.value());
    let state = compiled(&straddle);
    let verifier = Published(plan.solve.clone());
    let bound = bind_procedure(&state, plan.solve.clone(), &verifier, Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    assert_eq!(fence.selected.as_deref(), Some(plan.solve.grid[0].as_str()));
    let solved = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    let mut lower = Fraction(0, 1);
    let mut upper = Fraction(0, 1);
    let sequence = &straddle.input().causes.bindings.last().unwrap().sequence;
    for act in sequence {
        let range = &solved.rounds.last().unwrap().standing[&act.id().author];
        lower = lower.plus(Fraction::parse(&range.lower));
        upper = upper.plus(Fraction::parse(&range.upper));
    }
    let count = Fraction::new(i128::try_from(sequence.len()).unwrap(), 1);
    let threshold = Fraction::parse(NumberId::NumbersAdmissionStraddlePolicy.value());
    assert!(lower.over(count).minus(threshold).0 < 0);
    assert!(upper.over(count).minus(threshold).0 > 0);
    let result = run(&straddle, &plan, &led_schedule);
    assert!(matches!(
        result,
        Err(FinalRefusal::Refused(AdmissionRefusal::Indecisive(
            admission::Comparison::EpochPolicy
        )))
    ));
    let mut exhausted = plan.clone();
    exhausted.solve.maximum_solve_work = NumberId::NumbersAdmissionRefusedWork.integer();
    assert!(matches!(
        run(&straddle, &exhausted, &led_schedule),
        Err(FinalRefusal::Solve(error)) if matches!(*error,
            pn_epoch::conserved::Error::Arithmetic(nrz_cas::Fault { kind: nrz_cas::FaultKind::Exhausted { .. }, .. }))
    ));
}

/// Claim: The finite positive-rung candidate with a declared policy separates above that policy at its measured precision; its failing neighbour withholds admission as INDECISIVE, and the declared two-attempt sequence retains the unresolved round before the certified pass. No monotonic improvement with precision is asserted.
/// ´claim:admission:final-policy-refines-without-guessing´
/// ´test:integration:admission-refinement´
#[test]
fn admission_refinement() {
    let context = candidate(
        &coupled(),
        1,
        &[
            ("b", NumberId::NumbersAdmissionStraddleSourceBurn.value()),
            ("a", NumberId::NumbersAdmissionStraddleTargetBurn.value()),
        ],
    );
    let mut plan = procedure(&context);
    plan.solve.grid = vec![NumberId::NumbersAdmissionPositiveStrength.value().into(), "0".into()];
    let low = u32::try_from(NumberId::NumbersAdmissionPolicyFailedPrecision.integer()).unwrap();
    let high = u32::try_from(NumberId::NumbersAdmissionPolicyPrecision.integer()).unwrap();
    let led_schedule = schedule(&context, NumberId::NumbersAdmissionStraddlePolicy.value());
    plan.solve.precision = Precision::AbsoluteWidthBits(vec![low]);
    plan.solve.enclosure.as_mut().unwrap().refinement.precision = low;
    assert!(matches!(
        run(&context, &plan, &led_schedule),
        Err(FinalRefusal::Refused(AdmissionRefusal::Indecisive(
            admission::Comparison::EpochPolicy
        )))
    ));
    plan.solve.precision = Precision::AbsoluteWidthBits(vec![high]);
    plan.solve.enclosure.as_mut().unwrap().refinement.precision = high;
    let admitted = run(&context, &plan, &led_schedule).unwrap();
    assert!(Fraction::parse(&admitted.evidence().rounds.last().unwrap().headroom.lower).0 > 0);
    plan.solve.maximum_solve_work = NumberId::NumbersAdmissionRefinementWorkCeiling.integer();
    plan.solve.maximum_replay_work = NumberId::NumbersAdmissionRefinementWorkCeiling.integer();
    plan.solve.precision = Precision::AbsoluteWidthBits(vec![low, high]);
    plan.solve.enclosure.as_mut().unwrap().refinement.precision = low;
    let refined = run(&context, &plan, &led_schedule).unwrap();
    assert_eq!(
        refined.evidence().rounds.iter().map(|r| r.precision).collect::<Vec<_>>(),
        vec![low, high]
    );
    assert!(Fraction::parse(&refined.evidence().rounds.last().unwrap().headroom.lower).0 > 0);
}

/// The candidate cannot drive the completed-epoch controller; a rejected policy
/// attempt leaves the subsequent admitted evidence identical to the clean run.
/// (´claim:admission:individual-and-own-gates-cannot-be-averaged´)
/// ´test:integration:admission-quarantine´
#[test]
fn admission_quarantine() {
    let context = candidate(&self_acts(), 1, &[("a", NumberId::NumbersAdmissionRepeatedBurn.value())]);
    let plan = procedure(&context);
    let led_schedule = schedule(&context, NumberId::NumbersAdmissionWall.value());
    let expected = run(&context, &plan, &led_schedule).unwrap();
    let later = candidate(
        &[joined::act("Registration", "a", 1, 1)],
        2,
        &[("a", NumberId::NumbersAdmissionRepeatedBurn.value())],
    );
    let old_insolvent = candidate(
        &[joined::act("Registration", "a", 1, 1)],
        2,
        &[("a", NumberId::NumbersAdmissionInsolventBurn.value())],
    );
    assert!(
        matches!(run(&old_insolvent, &plan, &schedule(&later, NumberId::NumbersAdmissionWall.value())),
        Err(FinalRefusal::Compile(error)) if matches!(*error,
            pn_epoch::compiler::CompileError::Ledger(pn_epoch::ledger::LedgerError::InsufficientBalance { boundary: 1, .. })))
    );
    let wrong_boundary = schedule(&later, NumberId::NumbersAdmissionWall.value());
    assert!(matches!(
        run(&context, &plan, &wrong_boundary),
        Err(FinalRefusal::Refused(AdmissionRefusal::ScheduleValidity))
    ));
    let exact_debit = candidate(
        &[joined::act("Registration", "a", 1, 1)],
        1,
        &[("a", NumberId::NumbersAdmissionWall.value())],
    );
    let zero = procedure(&exact_debit);
    assert!(matches!(
        run(&exact_debit, &zero, &led_schedule),
        Err(FinalRefusal::Refused(AdmissionRefusal::Failed(Gate::IndividualSafety)))
    ));
    let invalid = schedule(&context, NumberId::NumbersAdmissionRefusedPolicy.value());
    assert!(matches!(
        run(&context, &plan, &invalid),
        Err(FinalRefusal::Refused(AdmissionRefusal::Failed(Gate::EpochPolicy)))
    ));
    assert_eq!(run(&context, &plan, &led_schedule).unwrap().evidence(), expected.evidence());
    let state = compiled(&context);
    let verifier = Published(plan.solve.clone());
    let bound = bind_procedure(&state, plan.solve.clone(), &verifier, Limits::default()).unwrap();
    let search = pn_epoch::controller::InverseSearch {
        bracket: pn_records::primitive::Range {
            lower: NumberId::NumbersControllerTestBracketLower.value().into(),
            upper: NumberId::NumbersControllerTestBracketUpper.value().into(),
        },
        stopping_width: NumberId::NumbersControllerTestStoppingWidth.value().into(),
        maximum_steps: NumberId::NumbersControllerTestSteps.integer(),
    };
    assert!(matches!(
        pn_epoch::controller::evaluate(
            &bound,
            &admission::declare_schedule(led_schedule.record().declaration.clone(), Limits::default()).unwrap(),
            &search,
            None
        ),
        Err(pn_epoch::controller::Error::Refused(AdmissionRefusal::Evidence))
    ));
}

use pn_epoch::closure::{self, ClosedBoundary, ClosureError, ClosureInput};

fn close(context: &package::CandidateContext, previous: Option<&ClosedBoundary>) -> ClosedBoundary {
    let plan = procedure(context);
    let led = if let Some(prior) = previous {
        let acts: Vec<_> = prior.record().bindings[0].sequence.iter().map(test_raw).collect();
        let names: std::collections::BTreeSet<_> = acts.iter().map(|a| a.id.author.as_str()).collect();
        let burns: Vec<_> = names
            .into_iter()
            .rev()
            .map(|a| (a, NumberId::NumbersClosureBurn.value()))
            .collect();
        next_schedule_for(&acts, &burns)
    } else {
        closure_initial(context)
    };
    let blocks = closure::partition(context).unwrap();
    let input = ClosureInput {
        candidate: context,
        partition: &blocks,
        schedule: &led,
        previous,
    };
    let result = closure::close(
        &input,
        &plan,
        &joined::Verifier,
        &Published(plan.solve.clone()),
        joined::numeric(),
    )
    .unwrap();
    assert_eq!(
        closure::replay(
            &input,
            &plan,
            &joined::Verifier,
            &Published(plan.solve.clone()),
            joined::numeric(),
            result.record()
        )
        .unwrap()
        .record(),
        result.record()
    );
    result
}

fn interleaved() -> Vec<pn_records::CandidateAct> {
    let a = joined::act("Registration", "a", 1, 1);
    let b = joined::act("Registration", "b", 2, 1);
    let mut acts = vec![a.clone(), b.clone()];
    for (author, position, parent) in [("a", 3, &a), ("b", 4, &b), ("a", 5, &a)] {
        let mut act = joined::act("Opinion", author, position, 1);
        act.legs[0].target = joined::named("prof", author);
        act.body.asserted_parents = vec![parent.id.clone()];
        acts.push(act);
    }
    acts.reverse();
    acts
}

/// Claim: At the declared finite interleaved complete history, current shared parents merge whole acts against fixed prior history; independent closure replay retains the exact cover and final gates, while omitted, duplicated or separated blocks are refused without changing prior evidence. No inference of earliest host determination or deployment publication is made.
/// ´claim:admission:closure-consumes-whole-dependent-blocks´
/// ´test:integration:closure-membership´
#[test]
fn closure_membership() {
    let acts = interleaved();
    let context = candidate(
        &acts,
        1,
        &[
            ("b", NumberId::NumbersClosureBurn.value()),
            ("a", NumberId::NumbersClosureBurn.value()),
        ],
    );
    let result = close(&context, None);
    let blocks = closure::partition(&context).unwrap();
    assert_eq!(
        blocks,
        vec![
            vec![acts[4].id.clone(), acts[2].id.clone(), acts[0].id.clone()],
            vec![acts[3].id.clone(), acts[1].id.clone()]
        ]
    );
    let plan = procedure(&context);
    let led = closure_initial(&context);
    let input = ClosureInput {
        candidate: &context,
        partition: &blocks,
        schedule: &led,
        previous: None,
    };
    assert!(
        matches!(closure::close(&input, &plan, &NoApproval, &Published(plan.solve.clone()), joined::numeric()), Err(ClosureError::Admission(e)) if matches!(&*e, FinalRefusal::Compile(e) if matches!(e.as_ref(), pn_epoch::compiler::CompileError::Ledger(pn_epoch::ledger::LedgerError::Formation(pn_graph::registration::RegistrationError::Unapproved)))))
    );
    let mut omitted = blocks.clone();
    omitted[0].pop();
    let mut duplicated = blocks.clone();
    duplicated[1].push(blocks[0][0].clone());
    let split = blocks.iter().flatten().map(|act| vec![act.clone()]).collect();
    for invalid in [omitted, duplicated, split] {
        let input = ClosureInput {
            candidate: &context,
            partition: &invalid,
            schedule: &led,
            previous: None,
        };
        assert!(matches!(
            closure::close(
                &input,
                &plan,
                &joined::Verifier,
                &Published(plan.solve.clone()),
                joined::numeric()
            ),
            Err(ClosureError::Membership)
        ));
    }
    assert_eq!(close(&context, None).record(), result.record());
    let mut missing = acts.clone();
    missing.retain(|act| act.id != acts[4].id);
    let absent = candidate(
        &missing,
        1,
        &[
            ("b", NumberId::NumbersClosureBurn.value()),
            ("a", NumberId::NumbersClosureBurn.value()),
        ],
    );
    assert!(matches!(closure::partition(&absent), Err(ClosureError::Records(_))));
    let mut paired = joined::act("Reference", "a", 6, 1);
    paired.legs[1].target = joined::named("prof", "a");
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    paired.legs.retain(|leg| leg.id.role != pn_records::Role::T);
    assert_eq!(
        pn_records::validate_record(&[paired.clone()], &empty, &[]).unwrap_err(),
        pn_records::ValidationError::MissingCoLeg {
            act: paired.id,
            role: pn_records::Role::T
        }
    );
    let mut low = plan.clone();
    low.solve.precision = Precision::AbsoluteWidthBits(vec![1]);
    low.solve.enclosure.as_mut().unwrap().refinement.precision = 1;
    let input = ClosureInput {
        candidate: &context,
        partition: &blocks,
        schedule: &led,
        previous: None,
    };
    assert!(
        matches!(closure::close(&input, &low, &joined::Verifier, &Published(low.solve.clone()), joined::numeric()), Err(ClosureError::Admission(e)) if matches!(&*e, FinalRefusal::Solve(e) if matches!(e.as_ref(), pn_epoch::conserved::Error::Scope)))
    );
}

/// Claim: The finite local marker chain registers only consecutive recognized boundaries, retaining pending markers without closing them; repeated and skipped registration and a changed predecessor context are refused. Historical shared parents do not merge new blocks. This does not establish host halt, recovery or offline-history admission.
/// ´claim:admission:closure-registers-consecutive-recognized-markers´
/// ´test:integration:closure-markers´
#[test]
fn closure_markers() {
    let a = joined::act("Registration", "a", 1, 1);
    let b = joined::act("Registration", "b", 2, 1);
    let first = candidate(
        &[b.clone(), a.clone()],
        1,
        &[
            ("b", NumberId::NumbersClosureBurn.value()),
            ("a", NumberId::NumbersClosureBurn.value()),
        ],
    );
    let prior = close(&first, None);
    assert!(first.input().causes.markers.markers().len() > prior.record().bindings.len() + 1);
    let mut acts = vec![a.clone(), b];
    for (author, position) in [("a", 3), ("b", 4)] {
        let mut act = joined::act("Opinion", author, position, 2);
        act.legs[0].target = joined::named("prof", author);
        act.body.asserted_parents = vec![a.id.clone()];
        acts.push(act);
    }
    acts.reverse();
    let next = candidate(
        &acts,
        2,
        &[
            ("b", NumberId::NumbersClosureBurn.value()),
            ("a", NumberId::NumbersClosureBurn.value()),
        ],
    );
    let mut input = next.input().clone();
    input.closure.opened_at = prior.record().statement.determined_at;
    input.closure.determined_at += input.closure.opened_at;
    let verifier = Causes(input.clone());
    let next = package::verify_candidate(input, &verifier, &verifier).unwrap();
    let blocks = closure::partition(&next).unwrap();
    assert_eq!(blocks, vec![vec![acts[1].id.clone()], vec![acts[0].id.clone()]]);
    let mut accumulator = next.input().clone();
    accumulator.causes.bindings.last_mut().unwrap().marker.name = "unrecognized-accumulator".into();
    let verifier = Causes(accumulator.clone());
    assert!(matches!(
        package::verify_candidate(accumulator, &verifier, &verifier),
        Err(package::PackageError::Alignment)
    ));
    let next_result = close(&next, Some(&prior));
    assert_eq!(next_result.record().bindings.len(), 2);
    marker_controls(&first, &next, &prior, &acts);
}

/// Claim: At the declared target and duration boundaries, a verifier-bound cause and determination permit closure exactly at the minimum target time or maximum duration; earlier, substituted and unattested determinations refuse. Numerical bounds alone do not reconstruct the earliest host opportunity.
/// ´claim:admission:closure-requires-attested-cause-and-duration´
/// ´test:integration:closure-duration´
#[test]
fn closure_duration() {
    let base = candidate(&self_acts(), 1, &[("a", NumberId::NumbersClosureBurn.value())]);
    for cause in [
        package::ClosureCause::TargetAfterMinimum,
        package::ClosureCause::MaximumDuration,
    ] {
        let mut input = base.input().clone();
        input.closure.policy.minimum_ticks = NumberId::NumbersClosureMinimumTicks.integer();
        input.closure.policy.maximum_ticks = NumberId::NumbersClosureMaximumTicks.integer();
        input.closure.cause = cause;
        input.closure.policy.target = if cause == package::ClosureCause::TargetAfterMinimum {
            u64::try_from(self_acts().len()).unwrap()
        } else {
            NumberId::NumbersAdmissionTarget.integer()
        };
        input.closure.determined_at = if cause == package::ClosureCause::TargetAfterMinimum {
            input.closure.policy.minimum_ticks
        } else {
            input.closure.policy.maximum_ticks
        };
        let attested = Causes(input.clone());
        let context = package::verify_candidate(input.clone(), &attested, &attested).unwrap();
        close(&context, None);
        let mut early = input.clone();
        early.closure.determined_at -= 1;
        let admits_early = Causes(early.clone());
        assert!(matches!(
            package::verify_candidate(early, &admits_early, &admits_early),
            Err(package::PackageError::Closure)
        ));
        let mut late = input.clone();
        late.closure.determined_at += 1;
        assert!(matches!(
            package::verify_candidate(late, &attested, &attested),
            Err(package::PackageError::Closure)
        ));
        let mut altered = input;
        altered.closure.attestation.push('!');
        assert!(matches!(
            package::verify_candidate(altered, &attested, &attested),
            Err(package::PackageError::Closure)
        ));
    }
}

/// Claim: Independent closure replay refuses context substitution before consuming gates and refuses a changed final solve record after recomputation. A correct solve from a different declared complete candidate cannot supply this candidate's stamps.
/// ´claim:admission:closure-replay-binds-one-common-context´
/// ´test:integration:closure-context´
#[test]
fn closure_context() {
    let context = candidate(&self_acts(), 1, &[("a", NumberId::NumbersClosureBurn.value())]);
    let other = candidate(&self_acts(), 1, &[("a", NumberId::NumbersClosureAlternateBurn.value())]);
    let result = close(&context, None);
    let alternate = close(&other, None);
    let plan = procedure(&context);
    let led = closure_initial(&context);
    let blocks = closure::partition(&context).unwrap();
    let input = ClosureInput {
        candidate: &context,
        partition: &blocks,
        schedule: &led,
        previous: None,
    };
    assert!(matches!(
        closure::replay(
            &input,
            &plan,
            &joined::Verifier,
            &Published(plan.solve.clone()),
            joined::numeric(),
            alternate.record()
        ),
        Err(ClosureError::Context)
    ));
    let next = candidate(&self_acts(), 2, &[("a", NumberId::NumbersClosureBurn.value())]);
    let np = procedure(&next);
    let correct = next_schedule(NumberId::NumbersClosureBurn.value());
    let foreign = next_schedule(NumberId::NumbersClosureAlternateBurn.value());
    assert_eq!(
        correct.record().publications[0].effective,
        foreign.record().publications[0].effective
    );
    run(&next, &np, &correct).unwrap();
    assert!(matches!(
        run(&next, &np, &foreign),
        Err(FinalRefusal::Refused(AdmissionRefusal::Evidence))
    ));
    let mut changed = result.record().clone();
    changed
        .final_gates
        .standing
        .clone_from(&alternate.record().final_gates.standing);
    assert!(matches!(
        closure::replay(
            &input,
            &plan,
            &joined::Verifier,
            &Published(plan.solve.clone()),
            joined::numeric(),
            &changed
        ),
        Err(ClosureError::Evidence)
    ));
}

fn next_schedule(burn: &str) -> schedules::CheckedSchedule {
    next_schedule_for(&self_acts(), &[("a", burn)])
}
fn next_schedule_for(acts: &[pn_records::CandidateAct], burns: &[(&str, &str)]) -> schedules::CheckedSchedule {
    let source = joined::package_at_numeraires(acts, 1, burns, NumberId::NumbersAdmissionWall.value(), &["1", "1"]);
    let state = compile_final_state(
        &source,
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        NumberId::NumbersControllerTestWork.integer(),
    )
    .unwrap();
    let ctx = candidate(acts, 1, burns);
    let mut declared = schedule(&ctx, NumberId::NumbersAdmissionWall.value())
        .record()
        .declaration
        .clone();
    declared.initialization.parameters.as_mut().unwrap().deadband = NumberId::NumbersClosureDeadband.value().into();
    let declared = admission::declare_schedule(declared, Limits::default()).unwrap();
    let p = procedure(&ctx).solve;
    let published = Published(p.clone());
    let bound = bind_procedure(&state, p, &published, Limits::default()).unwrap();
    let search = pn_epoch::controller::InverseSearch {
        bracket: pn_records::primitive::Range {
            lower: NumberId::NumbersControllerTestBracketLower.value().into(),
            upper: NumberId::NumbersControllerTestBracketUpper.value().into(),
        },
        stopping_width: NumberId::NumbersControllerTestStoppingWidth.value().into(),
        maximum_steps: NumberId::NumbersControllerTestSteps.integer(),
    };
    let frame = schedules::Boundary {
        completed: &bound,
        search: &search,
        announced_at: 1,
        effective_at: 2,
        policy_floor: None,
    };
    let record = schedules::evaluate(&declared, &[frame], None, Limits::default()).unwrap();
    let frame = schedules::Boundary {
        completed: &bound,
        search: &search,
        announced_at: 1,
        effective_at: 2,
        policy_floor: None,
    };
    schedules::replay(&declared, &[frame], None, Limits::default(), &record).unwrap()
}

#[derive(Debug)]
struct NoApproval;
impl pn_graph::registration::RegistrationVerifier for NoApproval {
    fn approval(&self, _: &pn_records::ValidatedAct) -> bool {
        false
    }
    fn removal(&self, _: &pn_records::ValidatedAct, _: pn_graph::registration::OpeningKind, _: pn_records::Position) -> bool {
        false
    }
}

fn closure_initial(context: &package::CandidateContext) -> schedules::CheckedSchedule {
    let mut d = schedule(context, NumberId::NumbersAdmissionWall.value())
        .record()
        .declaration
        .clone();
    d.initialization.parameters.as_mut().unwrap().deadband = NumberId::NumbersClosureDeadband.value().into();
    let d = admission::declare_schedule(d, Limits::default()).unwrap();
    let record = schedules::evaluate(&d, &[], None, Limits::default()).unwrap();
    schedules::replay(&d, &[], None, Limits::default(), &record).unwrap()
}
fn test_raw(act: &pn_records::ValidatedAct) -> pn_records::CandidateAct {
    pn_records::CandidateAct {
        commitments: act.commitments().cloned(),
        id: act.id().clone(),
        body: act.body().clone(),
        legs: act
            .legs()
            .iter()
            .map(|leg| pn_records::CandidateLeg {
                id: leg.id().clone(),
                source: leg.source().clone(),
                target: leg.target().clone(),
                removal: None,
            })
            .collect(),
        projections: act.projections().clone(),
        protocol_references: act.protocol_references().to_vec(),
        authentication_evidence: act.authentication_evidence().to_vec(),
        finalization_epoch: act.finalization_epoch(),
        authoritative_position: act.authoritative_position(),
        logical_time: act.logical_time(),
    }
}

fn marker_controls(
    first: &package::CandidateContext,
    next: &package::CandidateContext,
    prior: &ClosedBoundary,
    acts: &[pn_records::CandidateAct],
) {
    let blocks = closure::partition(next).unwrap();
    let reset = closure_initial(next);
    let plan = procedure(next);
    let input = ClosureInput {
        candidate: next,
        partition: &blocks,
        schedule: &reset,
        previous: Some(prior),
    };
    assert!(matches!(
        closure::close(
            &input,
            &plan,
            &joined::Verifier,
            &Published(plan.solve.clone()),
            joined::numeric()
        ),
        Err(ClosureError::Context)
    ));
    for (context, previous) in [(first, Some(prior)), (next, None)] {
        let plan = procedure(context);
        let led = closure_initial(context);
        let blocks = closure::partition(context).unwrap();
        assert!(matches!(
            closure::close(
                &ClosureInput {
                    candidate: context,
                    partition: &blocks,
                    schedule: &led,
                    previous
                },
                &plan,
                &joined::Verifier,
                &Published(plan.solve.clone()),
                joined::numeric()
            ),
            Err(ClosureError::MarkerOrder)
        ));
    }
    marker_context_controls(next, prior, acts);
}

fn marker_context_controls(next: &package::CandidateContext, prior: &ClosedBoundary, acts: &[pn_records::CandidateAct]) {
    let blocks = closure::partition(next).unwrap();
    let first: Vec<_> = acts.iter().filter(|a| a.finalization_epoch == 1).cloned().collect();
    let changed = candidate(
        acts,
        2,
        &[
            ("b", NumberId::NumbersClosureAlternateBurn.value()),
            ("a", NumberId::NumbersClosureAlternateBurn.value()),
        ],
    );
    let mut input = changed.input().clone();
    input.closure = next.input().closure.clone();
    let verifier = Causes(input.clone());
    let changed = package::verify_candidate(input, &verifier, &verifier).unwrap();
    let plan = procedure(&changed);
    let burns = [
        ("b", NumberId::NumbersClosureAlternateBurn.value()),
        ("a", NumberId::NumbersClosureAlternateBurn.value()),
    ];
    let led = next_schedule_for(&first, &burns);
    run(&changed, &plan, &led).unwrap();
    assert!(matches!(
        closure::close(
            &ClosureInput {
                candidate: &changed,
                partition: &blocks,
                schedule: &led,
                previous: Some(prior)
            },
            &plan,
            &joined::Verifier,
            &Published(plan.solve.clone()),
            joined::numeric()
        ),
        Err(ClosureError::Context)
    ));
    let led = next_schedule_for(
        &first,
        &[
            ("b", NumberId::NumbersClosureBurn.value()),
            ("a", NumberId::NumbersClosureBurn.value()),
        ],
    );
    for clock in [false, true] {
        let mut input = next.input().clone();
        if clock {
            input.closure.policy.clock.push('!');
        } else {
            input.closure.opened_at += 1;
            input.closure.determined_at += 1;
        }
        let verifier = Causes(input.clone());
        let shifted = package::verify_candidate(input, &verifier, &verifier).unwrap();
        let input = ClosureInput {
            candidate: &shifted,
            partition: &blocks,
            schedule: &led,
            previous: Some(prior),
        };
        assert!(matches!(
            closure::close(
                &input,
                &plan,
                &joined::Verifier,
                &Published(plan.solve.clone()),
                joined::numeric()
            ),
            Err(ClosureError::Context)
        ));
    }
}

/// Claim: The finite coupled probe retains individual safety as unresolved when its outward standing interval straddles the wall; no unresolved stamp is published.
/// ´claim:admission:individual-straddles-withhold-publication´
/// ´test:integration:admission-individual-straddle´
#[test]
fn admission_individual_straddle() {
    let context = candidate(
        &coupled(),
        1,
        &[
            ("b", NumberId::NumbersAdmissionStraddleSourceBurn.value()),
            ("a", NumberId::NumbersAdmissionIndividualTargetBurn.value()),
        ],
    );
    let mut plan = procedure(&context);
    plan.solve.grid = vec![NumberId::NumbersAdmissionPositiveStrength.value().into(), "0".into()];
    let state = compiled(&context);
    let bound = bind_procedure(&state, plan.solve.clone(), &Published(plan.solve.clone()), Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    let solved = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    pn_epoch::conserved::replay(&bound, &solved).unwrap();
    let round = solved.rounds.last().unwrap();
    assert_eq!(round.certified.rung, NumberId::NumbersAdmissionPositiveStrength.value());
    let wall = Fraction::parse(NumberId::NumbersAdmissionWall.value());
    let individual = &round.standing["a"];
    assert!(wall.minus(Fraction::parse(&individual.lower)).0 > 0);
    assert!(Fraction::parse(&individual.upper).minus(wall).0 > 0);
    assert!(matches!(
        run(&context, &plan, &schedule(&context, NumberId::NumbersAdmissionWall.value())),
        Err(FinalRefusal::Refused(AdmissionRefusal::Indecisive(
            admission::Comparison::IndividualSafety
        )))
    ));
}

/// Claim: The finite coupled own-solvency probe uses the same supporter in both histories; its support lifts a solvent author's stamp above the wall but cannot fund an insolvent author's debit.
/// ´claim:admission:real-support-cannot-fund-own-debits´
/// ´test:integration:admission-solvent-support´
#[test]
fn admission_solvent_support() {
    let context = candidate(
        &coupled(),
        1,
        &[
            ("b", NumberId::NumbersAdmissionStraddleSourceBurn.value()),
            ("a", NumberId::NumbersAdmissionPoorBurn.value()),
        ],
    );
    let mut plan = procedure(&context);
    plan.solve.grid = vec!["0".into()];
    let led = schedule(&context, NumberId::NumbersAdmissionWall.value());
    let admitted = run(&context, &plan, &led).unwrap();
    let wall = Fraction::parse(NumberId::NumbersAdmissionWall.value());
    let own = Fraction::parse(NumberId::NumbersAdmissionPoorBurn.value()).minus(wall);
    assert!(own.0 > 0);
    assert!(wall.minus(own).0 > 0);
    let support = Fraction::parse(NumberId::NumbersAdmissionStraddleSourceBurn.value())
        .minus(wall.times(Fraction(2, 1)))
        .over(Fraction(3, 1));
    let expected = own.plus(support).over(Fraction(1, 1).plus(Fraction(2, 3)));
    let result = admitted.evidence().rounds.last().unwrap();
    let stamp = result.stamps.iter().find(|(act, _)| act.author == "a").unwrap().1;
    assert_eq!(Fraction::parse(&stamp.lower), expected);
    assert_eq!(Fraction::parse(&stamp.upper), expected);
    assert!(expected.minus(wall).0 > 0);
    let insolvent = candidate(
        &coupled(),
        1,
        &[
            ("b", NumberId::NumbersAdmissionStraddleSourceBurn.value()),
            ("a", NumberId::NumbersAdmissionInsolventBurn.value()),
        ],
    );
    assert_eq!(context.input().causes.history.acts(), insolvent.input().causes.history.acts());
    assert!(matches!(
        run(
            &insolvent,
            &plan,
            &schedule(&insolvent, NumberId::NumbersAdmissionWall.value())
        ),
        Err(FinalRefusal::Refused(AdmissionRefusal::Failed(Gate::OwnSolvency)))
    ));
}
