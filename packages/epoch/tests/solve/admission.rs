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
