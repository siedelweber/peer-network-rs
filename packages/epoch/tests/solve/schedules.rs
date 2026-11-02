use super::*;
use pn_epoch::{
    admission::{
        ControllerParameters, Delivery, InitializationInput, Refinement, ScheduleDeclaration, ScheduleInput, declare_schedule,
    },
    controller::InverseSearch,
    schedules::{self, Boundary},
};

fn text(x: Fraction) -> String {
    format!("{}/{}", x.0, x.1)
}
fn number(id: NumberId) -> Fraction {
    Fraction::parse(id.value())
}
fn model(previous: Fraction) -> Fraction {
    let floor = Fraction::parse(&wall_floor_rational());
    let absolute = number(NumberId::NumbersEffectiveScheduleAbsoluteCap);
    let relative = previous.times(number(NumberId::NumbersEffectiveScheduleRelativeCap));
    let distance = previous.minus(floor);
    let cap = if absolute.0 * relative.1 < relative.0 * absolute.1 {
        absolute
    } else {
        relative
    };
    previous.minus(if cap.0 * distance.1 < distance.0 * cap.1 {
        cap
    } else {
        distance
    })
}
fn walls() -> Vec<String> {
    let mut x = number(NumberId::NumbersEffectiveScheduleInitialWall);
    (0..NumberId::NumbersEffectiveScheduleBoundaryCount.integer())
        .map(|_| {
            let result = text(x);
            x = model(x);
            result
        })
        .collect()
}
fn fixture(
    boundary: u64,
    walls: &[String],
    scale: Fraction,
    migration: bool,
    changed: bool,
) -> pn_epoch::compiler::CompiledState {
    let mut acts = Vec::new();
    for epoch in 1..=boundary {
        for (offset, actor) in ["b", "a"].into_iter().enumerate() {
            if changed && epoch == 2 && actor == "b" {
                continue;
            }
            let mut act = joined::act(
                if epoch == 1 { "Registration" } else { "Opinion" },
                actor,
                2 * epoch + u64::try_from(offset).unwrap(),
                epoch,
            );
            if epoch > 1 {
                act.legs[0].target = joined::named("prof", if changed { "b" } else { actor });
            }
            acts.push(act);
        }
    }
    acts.reverse();
    let amount = number(NumberId::NumbersEffectiveScheduleBurn).times(if migration { Fraction(1, 1) } else { scale });
    let amount = text(amount);
    let nu = text(scale);
    let numeraires = vec![nu.as_str(); usize::try_from(boundary).unwrap()];
    let wall_refs: Vec<_> = walls.iter().map(String::as_str).collect();
    let package = joined::package_at_prices(&acts, boundary, &[("b", &amount), ("a", &amount)], &wall_refs, &numeraires);
    compile_final_state(
        &package,
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        NumberId::NumbersControllerTestWork.integer(),
    )
    .unwrap()
}
fn policy(state: &pn_epoch::compiler::CompiledState, bits: u32) -> Procedure {
    let mut p = fence_procedure(state);
    p.precision = Precision::AbsoluteWidthBits(vec![bits]);
    p.maximum_work = NumberId::NumbersControllerTestWork.integer();
    p.maximum_replay_work = p.maximum_work;
    let e = p.enclosure.as_mut().unwrap();
    e.operation.work = p.maximum_work;
    e.operation.arithmetic_steps = NumberId::NumbersEffectiveScheduleArithmeticCeiling.integer();
    e.store = e.operation.clone();
    e.refinement.precision = bits;
    p
}
fn declaration(state: &pn_epoch::compiler::CompiledState, bits: u32) -> ScheduleDeclaration {
    let price = state.package().input().prices.first().unwrap();
    declare_schedule(
        ScheduleInput {
            controller: "canonical-interim-v1".into(),
            announced_at: 0,
            initialization: InitializationInput {
                floor: Some(pn_records::numerics::Floor::RationalThreeThirtySevenths),
                wall: Some(price.wall().exact().into()),
                policy_floor: Some(NumberId::NumbersEffectiveSchedulePolicy.value().into()),
                effective_boundary: Some(1),
                parameters: Some(ControllerParameters {
                    absolute_cap: NumberId::NumbersEffectiveScheduleAbsoluteCap.value().into(),
                    relative_cap: NumberId::NumbersEffectiveScheduleRelativeCap.value().into(),
                    deadband: "0".into(),
                    margin: policy(state, bits).margin,
                }),
            },
            numeraire: price.numeraire().clone(),
            delivery: Delivery::ExactRational,
            refinement: Refinement {
                precision_bits: vec![bits],
                maximum_work: NumberId::NumbersControllerTestWork.integer(),
                maximum_replay_work: NumberId::NumbersControllerTestWork.integer(),
            },
        },
        Limits::default(),
    )
    .unwrap()
}
fn search() -> InverseSearch {
    InverseSearch {
        bracket: pn_records::primitive::Range {
            lower: NumberId::NumbersEffectiveScheduleBracketLower.value().into(),
            upper: NumberId::NumbersControllerTestBracketUpper.value().into(),
        },
        stopping_width: NumberId::NumbersEffectiveScheduleStoppingWidth.value().into(),
        maximum_steps: NumberId::NumbersControllerTestSteps.integer(),
    }
}
fn sequence(states: &[pn_epoch::compiler::CompiledState], bits: u32) -> schedules::Record {
    let policies: Vec<_> = states.iter().map(|s| policy(s, bits)).collect();
    let publications: Vec<_> = policies.iter().cloned().map(Published).collect();
    let bounds: Vec<_> = states
        .iter()
        .zip(&policies)
        .zip(&publications)
        .map(|((s, p), v)| bind_procedure(s, p.clone(), v, Limits::default()).unwrap())
        .collect();
    let search = search();
    let frames: Vec<_> = bounds
        .iter()
        .enumerate()
        .map(|(i, b)| Boundary {
            completed: b,
            search: &search,
            announced_at: u64::try_from(i).unwrap() + 1,
            effective_at: u64::try_from(i).unwrap() + 2,
            policy_floor: (i == 1).then(|| NumberId::NumbersEffectiveScheduleChangedPolicy.value().into()),
        })
        .collect();
    let d = declaration(&states[0], bits);
    let r = schedules::evaluate(&d, &frames, None, Limits::default()).unwrap();
    assert_eq!(
        schedules::replay(&d, &frames, None, Limits::default(), &r).unwrap().record(),
        &r
    );
    r
}

/// Claim: The finite complete-history boundary sequence retains explicit initialization, one-boundary lead, policy persistence and validity, exact wall-price identity and unchanged debit vintages; independent replay refuses altered publications and skipped or invalid announcements, without admitting writes or authenticating deployment publication.
/// ´claim:admission:effective-schedules-retain-led-prices-and-vintages´
/// ´test:integration:effective-schedules´
#[test]
fn effective_schedules() {
    let bits = u32::try_from(NumberId::NumbersEffectiveScheduleScopePrecision.integer()).unwrap();
    let walls = walls();
    let states: Vec<_> = (1..=NumberId::NumbersEffectiveScheduleBoundaryCount.integer())
        .map(|k| fixture(k, &walls, Fraction(1, 1), false, false))
        .collect();
    let r = sequence(&states, bits);
    let mut expected = number(NumberId::NumbersEffectiveScheduleInitialWall);
    for (i, p) in r.publications.iter().enumerate() {
        expected = model(expected);
        assert_eq!(Fraction::parse(&p.effective.wall), expected);
        assert_eq!(Fraction::parse(&p.effective.charge), expected);
        assert_eq!(p.announced_at + 1, p.effective.boundary);
        assert_eq!(p.proposal.controller.inputs.width, "0");
        assert_eq!(p.proposal.fence.selected.as_deref(), Some("1"));
        assert_eq!(
            Fraction::parse(&p.effective.policy_floor),
            number(if i == 0 {
                NumberId::NumbersEffectiveSchedulePolicy
            } else {
                NumberId::NumbersEffectiveScheduleChangedPolicy
            })
        );
    }
    for pair in states.windows(2) {
        for (act, vintage) in &pair[0].view().ledger.debits {
            assert_eq!(&pair[1].view().ledger.debits[act], vintage);
        }
    }
    controls(&states, bits, &r);
    let mut low = declaration(&states[0], bits).input().clone();
    low.refinement.precision_bits = vec![bits - 1];
    assert!(matches!(
        declare_schedule(low, Limits::default()),
        Err(pn_epoch::admission::DeclarationError::Refinement)
    ));
}

fn controls(states: &[pn_epoch::compiler::CompiledState], bits: u32, record: &schedules::Record) {
    let p = policy(&states[0], bits);
    let v = Published(p.clone());
    let bound = bind_procedure(&states[0], p, &v, Limits::default()).unwrap();
    let d = declaration(&states[0], bits);
    let search = search();
    let mut frame = Boundary {
        completed: &bound,
        search: &search,
        announced_at: 1,
        effective_at: 2,
        policy_floor: None,
    };
    let mut first = record.clone();
    first.publications.truncate(1);
    for effective_at in [3, 1] {
        frame.effective_at = effective_at;
        assert!(matches!(
            schedules::replay(&d, std::slice::from_ref(&frame), None, Limits::default(), &first),
            Err(schedules::Error::Refused(
                pn_epoch::admission::AdmissionRefusal::ScheduleValidity
            ))
        ));
    }
    frame.effective_at = 2;
    frame.policy_floor = Some(wall_floor_rational());
    assert!(matches!(
        schedules::replay(&d, std::slice::from_ref(&frame), None, Limits::default(), &first),
        Err(schedules::Error::Refused(
            pn_epoch::admission::AdmissionRefusal::ScheduleValidity
        ))
    ));
    frame.policy_floor = None;
    for changed in (0..4).rev() {
        let mut bad = first.clone();
        match changed {
            0 => bad.publications[0].effective.charge = "0".into(),
            1 => bad.publications[0].proposal.controller.inputs.width = "1".into(),
            2 => bad.publications[0].announced_at = 0,
            _ => bad.publications[0].effective.policy_floor = "0".into(),
        }
        let refusal = schedules::replay(&d, std::slice::from_ref(&frame), None, Limits::default(), &bad).unwrap_err();
        if changed == 1 {
            assert!(matches!(
                refusal,
                schedules::Error::Controller(pn_epoch::controller::Error::Kernel(
                    pn_graph::numeric::controller::Error::Evidence
                ))
            ));
        } else {
            assert!(matches!(
                refusal,
                schedules::Error::Refused(pn_epoch::admission::AdmissionRefusal::Evidence)
            ));
        }
    }
    let mut changed_walls = walls();
    changed_walls[0] = text(Fraction::parse(&changed_walls[0]).plus(number(NumberId::NumbersEffectiveScheduleAbsoluteCap)));
    let changed = fixture(2, &changed_walls, Fraction(1, 1), false, false);
    let p = policy(&changed, bits);
    let verifier = Published(p.clone());
    let second = bind_procedure(&changed, p, &verifier, Limits::default()).unwrap();
    let frames = [
        frame,
        Boundary {
            completed: &second,
            search: &search,
            announced_at: 2,
            effective_at: 3,
            policy_floor: None,
        },
    ];
    let mut prefix = record.clone();
    prefix.publications.truncate(frames.len());
    assert!(matches!(
        schedules::replay(&d, &frames, None, Limits::default(), &prefix),
        Err(schedules::Error::Refused(
            pn_epoch::admission::AdmissionRefusal::ScheduleValidity
        ))
    ));
}

fn current(state: &pn_epoch::compiler::CompiledState, bits: u32, policy_scale: Fraction) -> schedules::Record {
    let p = policy(state, bits);
    let verifier = Published(p.clone());
    let bound = bind_procedure(state, p, &verifier, Limits::default()).unwrap();
    let mut d = declaration(state, bits).input().clone();
    let last = state.package().input().bindings.last().unwrap();
    d.announced_at = last.marker.index - 1;
    d.initialization.effective_boundary = Some(last.marker.index);
    d.initialization.wall = Some(last.price.wall().exact().into());
    d.initialization.policy_floor = Some(text(number(NumberId::NumbersEffectiveSchedulePolicy).times(policy_scale)));
    let d = declare_schedule(d, Limits::default()).unwrap();
    let search = search();
    let frames = [Boundary {
        completed: &bound,
        search: &search,
        announced_at: last.marker.index,
        effective_at: last.marker.index + 1,
        policy_floor: None,
    }];
    let r = schedules::evaluate(&d, &frames, None, Limits::default()).unwrap();
    assert_eq!(
        schedules::replay(&d, &frames, None, Limits::default(), &r).unwrap().record(),
        &r
    );
    r
}

/// Claim: The finite changed-width history certifies its own contributing width without repricing earlier debits; recoinage retains reduced controller inputs and scales its charge, while fixed-ledger migration halves the independently recomputed pair width and applies a new controller evaluation, without asserting controller homogeneity or invariant admission gates.
/// ´claim:admission:schedule-covariance-retains-transformed-inputs´
/// ´test:integration:schedule-covariance´
#[test]
fn schedule_covariance() {
    let bits = u32::try_from(NumberId::NumbersEffectiveSchedulePrecision.integer()).unwrap();
    let walls = walls();
    let scale = number(NumberId::NumbersEffectiveScheduleRecoinage);
    let unchanged = fixture(2, &walls, Fraction(1, 1), false, false);
    let changed = fixture(2, &walls, Fraction(1, 1), false, true);
    let old = fixture(1, &walls, Fraction(1, 1), false, false);
    let sequence_record = sequence(&[old.clone(), changed.clone()], bits);
    let original = current(&changed, bits, Fraction(1, 1));
    floor_control(&changed);
    assert_eq!(
        sequence_record.publications[1].proposal.controller,
        original.publications[0].proposal.controller
    );
    assert_eq!(
        sequence_record.publications[1].proposal.fence,
        original.publications[0].proposal.fence
    );
    let no_excursion = current(&unchanged, bits, Fraction(1, 1));
    assert_eq!(no_excursion.publications[0].proposal.controller.inputs.width, "0");
    let inputs = &original.publications[0].proposal.controller.inputs;
    for (act, vintage) in &old.view().ledger.debits {
        assert_eq!(&changed.view().ledger.debits[act], vintage);
    }
    let count = |actor| {
        Fraction::new(
            i128::try_from(
                changed
                    .package()
                    .input()
                    .history
                    .acts()
                    .iter()
                    .filter(|act| act.id().author == actor)
                    .count(),
            )
            .unwrap(),
            1,
        )
    };
    let count_a = count("a");
    let count_b = count("b");
    let burn = number(NumberId::NumbersEffectiveScheduleBurn);
    let debit_a = Fraction::parse(&walls[0]).plus(Fraction::parse(&walls[1]));
    let rate_a = burn.minus(debit_a).over(count_a);
    let rate_b = burn.minus(Fraction::parse(&walls[0])).over(count_b);
    let width = rate_b.minus(rate_a);
    assert!(width.0 > 0);
    assert_eq!(Fraction::parse(&inputs.width), width);
    let recoin = fixture(2, &walls, scale, false, true);
    let coined = current(&recoin, bits, Fraction(1, 1));
    assert_eq!(
        coined.publications[0].proposal.controller,
        original.publications[0].proposal.controller
    );
    assert_eq!(
        Fraction::parse(&coined.publications[0].effective.charge),
        Fraction::parse(&original.publications[0].effective.charge).times(scale)
    );
    let migrated_walls: Vec<_> = walls.iter().map(|w| text(Fraction::parse(w).over(scale))).collect();
    let migration = fixture(2, &migrated_walls, scale, true, true);
    for (act, vintage) in &changed.view().ledger.debits {
        assert_eq!(migration.view().ledger.debits[act].charged(), vintage.charged());
    }
    for compensated in [true, false] {
        let factor = if compensated {
            Fraction(1, 1).over(scale)
        } else {
            Fraction(1, 1)
        };
        let result = current(&migration, bits, factor);
        assert_eq!(
            Fraction::parse(&result.publications[0].proposal.controller.inputs.width),
            width.over(scale)
        );
        assert_eq!(
            Fraction::parse(&result.publications[0].effective.charge),
            Fraction::parse(&result.publications[0].effective.wall).times(scale)
        );
        assert_eq!(
            Fraction::parse(&result.initial.policy_floor).times(scale),
            number(NumberId::NumbersEffectiveSchedulePolicy).times(if compensated { Fraction(1, 1) } else { scale })
        );
    }
}

fn floor_control(state: &pn_epoch::compiler::CompiledState) {
    let bits = u32::try_from(NumberId::NumbersEffectiveScheduleFailedPrecision.integer()).unwrap();
    let p = policy(state, bits);
    let verifier = Published(p.clone());
    let bound = bind_procedure(state, p, &verifier, Limits::default()).unwrap();
    let d = declaration(state, bits);
    let search = search();
    let evidence = pn_epoch::controller::evaluate(&bound, &d, &search, None).unwrap();
    assert_eq!(evidence.controller.verdict, pn_records::controller::Verdict::Indecisive);
    let attempt = evidence.controller.attempts.last().unwrap();
    assert_eq!(attempt.stopped_at, Some(pn_records::controller::Stage::InverseGain));
    let inverse = attempt.inverse.as_ref().unwrap();
    assert!(inverse.indecisive);
    assert_eq!(inverse.steps.last().unwrap().sign, pn_records::wall::Sign::Indecisive);
    assert!(matches!(
        pn_epoch::controller::replay(&bound, &d, &search, None, &evidence),
        Err(pn_epoch::controller::Error::Refused(
            pn_epoch::admission::AdmissionRefusal::Indecisive(pn_epoch::admission::Comparison::InverseGain)
        ))
    ));
    let bounds = inverse.steps.last().unwrap().primitive.evidence.bounds.as_ref().unwrap();
    let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    let zero = nrz_cas::Rational::parse("0", &mut budget).unwrap();
    assert!(!bounds.lower().compare(&zero, &mut budget).unwrap().is_gt());
    assert!(!bounds.upper().compare(&zero, &mut budget).unwrap().is_lt());
}

/// Claim: The finite zero-width schedule accepts a policy exactly at its led wall and independently refuses the adjacent lower declaration; this is an exact rational boundary control, not a numerical accuracy floor.
/// ´claim:admission:scheduled-policy-compares-at-the-led-wall´
/// ´test:integration:policy-edges´
#[test]
fn policy_edges() {
    let bits = u32::try_from(NumberId::NumbersEffectiveScheduleScopePrecision.integer()).unwrap();
    let state = fixture(1, &walls(), Fraction(1, 1), false, false);
    let p = policy(&state, bits);
    let published = Published(p.clone());
    let bound = bind_procedure(&state, p, &published, Limits::default()).unwrap();
    let d = declaration(&state, bits);
    let search = search();
    let next = model(number(NumberId::NumbersEffectiveScheduleInitialWall));
    let mut frame = Boundary {
        completed: &bound,
        search: &search,
        announced_at: 1,
        effective_at: 2,
        policy_floor: Some(text(next)),
    };
    let record = schedules::evaluate(&d, std::slice::from_ref(&frame), None, Limits::default()).unwrap();
    assert_eq!(Fraction::parse(&record.publications[0].effective.wall), next);
    assert_eq!(Fraction::parse(&record.publications[0].effective.policy_floor), next);
    assert_eq!(
        schedules::replay(&d, std::slice::from_ref(&frame), None, Limits::default(), &record)
            .unwrap()
            .record(),
        &record
    );
    frame.policy_floor = Some(text(next.minus(number(NumberId::NumbersSchedulePolicyAdjacency))));
    assert!(matches!(
        schedules::replay(&d, std::slice::from_ref(&frame), None, Limits::default(), &record),
        Err(schedules::Error::Refused(
            pn_epoch::admission::AdmissionRefusal::ScheduleValidity
        ))
    ));
}

fn retained_refusal(state: &pn_epoch::compiler::CompiledState, bits: u32) {
    let last = state.package().input().bindings.last().unwrap();
    let current_wall = Fraction::parse(last.price.wall().exact());
    let mut input = declaration(state, bits).input().clone();
    input.announced_at = last.marker.index - 1;
    input.initialization.effective_boundary = Some(last.marker.index);
    input.initialization.wall = Some(text(current_wall));
    input.initialization.policy_floor = Some(text(current_wall));
    let d = declare_schedule(input, Limits::default()).unwrap();
    let p = policy(state, bits);
    let published = Published(p.clone());
    let bound = bind_procedure(state, p, &published, Limits::default()).unwrap();
    let search = search();
    let mut frame = Boundary {
        completed: &bound,
        search: &search,
        announced_at: last.marker.index,
        effective_at: last.marker.index + 1,
        policy_floor: Some(NumberId::NumbersEffectiveSchedulePolicy.value().into()),
    };
    let record = schedules::evaluate(&d, std::slice::from_ref(&frame), None, Limits::default()).unwrap();
    let next_wall = Fraction::parse(&record.publications[0].effective.wall);
    assert!(next_wall.minus(current_wall).0 > 0);
    frame.policy_floor = None;
    assert!(matches!(
        schedules::replay(&d, &[frame], None, Limits::default(), &record),
        Err(schedules::Error::Refused(
            pn_epoch::admission::AdmissionRefusal::ScheduleValidity
        ))
    ));
}

/// Claim: The finite changed-width and fixed-ledger migration histories independently refuse a retained policy overtaken by their rising led wall, even when that policy was valid at initialization. The failed inverse neighbour withholds the defining proposal; no homogeneous controller or monotonic-accuracy law is asserted.
/// ´claim:admission:retained-policy-must-cover-a-rising-wall´
/// ´test:integration:retained-policy´
#[test]
fn retained_policy() {
    let bits = u32::try_from(NumberId::NumbersEffectiveSchedulePrecision.integer()).unwrap();
    let walls = walls();
    let changed = fixture(2, &walls, Fraction(1, 1), false, true);
    retained_refusal(&changed, bits);
    floor_control(&changed);
    let scale = number(NumberId::NumbersEffectiveScheduleRecoinage);
    let migrated_walls: Vec<_> = walls.iter().map(|wall| text(Fraction::parse(wall).over(scale))).collect();
    let migrated = fixture(2, &migrated_walls, scale, true, true);
    retained_refusal(&migrated, bits);
}
