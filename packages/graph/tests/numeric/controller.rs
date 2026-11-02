use super::*;
use pn_graph::numeric::controller as kernel;
use pn_records::{
    controller::{Delivery, Inputs, Relation, Verdict},
    numerics::Floor,
};

fn value(id: NumberId) -> String {
    id.value().into()
}
fn bits(id: NumberId) -> u32 {
    u32::try_from(id.integer()).unwrap()
}
fn published(key: &str) -> String {
    let rows: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/datasets/org.peer-network.design.constants.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let definition = &rows["rows"].as_array().unwrap().iter().find(|r| r["id"] == key).unwrap()["definition"];
    definition["value"]
        .as_str()
        .or_else(|| definition["expr"].as_str())
        .unwrap()
        .into()
}
fn input() -> Inputs {
    Inputs {
        width: published("fixture.wall.width"),
        empty_live_domain: false,
        accepted_rung: "1".into(),
        cumulative_tilt: value(NumberId::NumbersControllerTestCharteredTilt),
        bleed_squared: published("const.activation.eta_sq"),
        previous: value(NumberId::NumbersControllerTestPrevious),
        floor: Floor::RationalThreeThirtySevenths,
        absolute_cap: published("const.epoch.step_abs"),
        relative_cap: published("const.epoch.step_rel"),
        deadband: published("const.epoch.deadband"),
        bracket: range(
            NumberId::NumbersControllerTestBracketLower.value(),
            NumberId::NumbersControllerTestBracketUpper.value(),
        ),
        stopping_width: value(NumberId::NumbersControllerTestStoppingWidth),
        maximum_steps: NumberId::NumbersControllerTestSteps.integer(),
        maximum_work: NumberId::NumbersControllerTestWork.integer(),
        maximum_replay_work: NumberId::NumbersControllerTestWork.integer(),
        delivery: Delivery::Grid {
            quantum: value(NumberId::NumbersControllerTestQuantum),
            maximum_error: value(NumberId::NumbersControllerTestError),
        },
    }
}
fn policy(precision: u32) -> Procedure {
    let mut p = verification_policy();
    p.precision = Precision::AbsoluteWidthBits(vec![precision]);
    let e = p.enclosure.as_mut().unwrap();
    e.refinement.precision = precision;
    e.operation.work = NumberId::NumbersControllerTestWork.integer();
    e.store.work = e.operation.work;
    p
}
fn checked(p: &Procedure, i: &Inputs) -> pn_records::controller::Record {
    let r = kernel::evaluate(p, i, None).unwrap();
    assert_eq!(kernel::replay(p, i, None, &r).unwrap(), r);
    r
}
fn rational(x: &str, b: &mut nrz_cas::limits::Budget) -> nrz_cas::Rational {
    nrz_cas::Rational::parse(x, b).unwrap()
}

/// Claim: The finite canonical-controller fixtures retain separate floor, deadband, direction and cap decisions, exact equality controls, signed updates and zero-width empty-domain behavior, with independent replay; they establish no schedule activation or admission guarantee.
/// ´claim:numerics:controller-branches-retain-ordered-comparisons´
/// ´test:integration:controller-branches´
#[test]
fn controller_branches() {
    let procedure = policy(bits(NumberId::NumbersControllerTestScopePrecision));
    let mut inputs = input();
    inputs.width = "0".into();
    inputs.delivery = Delivery::ExactRational;
    let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    // Complete scalar inputs arrive in deliberately reversed scenario order.
    for case in (0..4).rev() {
        let mut scenario = inputs.clone();
        match case {
            0 => {
                scenario.previous = wall_floor_rational();
                scenario.deadband = "0".into();
            }
            1 => {
                scenario.previous = value(NumberId::NumbersControllerTestDeadbandEqualityPrevious);
                scenario.deadband = value(NumberId::NumbersControllerTestDeadbandEquality);
            }
            2 => {
                scenario.previous = value(NumberId::NumbersControllerTestDeadbandEqualityPrevious);
                scenario.deadband = value(NumberId::NumbersControllerTestCapRelease);
                scenario.absolute_cap = value(NumberId::NumbersControllerTestCapEquality);
                scenario.relative_cap = value(NumberId::NumbersControllerTestDeadbandEquality);
            }
            _ => {
                scenario.previous = value(NumberId::NumbersControllerTestCapPrevious);
            }
        }
        let record = checked(&procedure, &scenario);
        assert_eq!(record.verdict, Verdict::Delivered);
        let attempt = record.attempts.last().unwrap();
        let branches = attempt.branches.as_ref().unwrap();
        assert!(branches.zero_width);
        assert_eq!(branches.floor, Relation::Equal);
        match case {
            0 => {
                assert_eq!(branches.deadband, Relation::Equal);
                assert_eq!(attempt.delivered.as_ref().unwrap(), &wall_floor_rational());
            }
            1 => {
                assert_eq!(branches.deadband, Relation::Equal);
                assert_eq!(attempt.delivered.as_ref().unwrap(), &scenario.previous);
            }
            2 => {
                assert_eq!(branches.deadband, Relation::Above);
                assert_eq!(branches.absolute_cap, Relation::Equal);
                assert_eq!(branches.relative_cap, Relation::Equal);
                assert_eq!(attempt.delivered.as_ref().unwrap(), &wall_floor_rational());
            }
            _ => {
                assert_eq!(branches.direction, Relation::Below);
                assert_eq!(branches.absolute_cap, Relation::Above);
                assert_eq!(branches.relative_cap, Relation::Above);
                let expected = rational(&scenario.previous, &mut budget)
                    .sub(&rational(&scenario.absolute_cap, &mut budget), &mut budget)
                    .unwrap();
                assert_eq!(rational(attempt.delivered.as_ref().unwrap(), &mut budget), expected);
            }
        }
        scenario.empty_live_domain = true;
        let empty = checked(&procedure, &scenario);
        assert_eq!(empty.attempts, record.attempts);
    }
}

/// Claim: The finite positive-width controller fixture encloses the tagged inverse target, certifies upward and downward caps and grid delivery, retains unresolved inverse and representation refusals, and independently rejects substituted inputs and evidence; finite controls establish no universal precision improvement.
/// ´claim:numerics:controller-delivery-retains-defining-and-replay-evidence´
/// ´test:integration:controller-delivery´
#[test]
fn controller_delivery() {
    let procedure = policy(bits(NumberId::NumbersControllerTestPrecision));
    let inputs = input();
    let record = checked(&procedure, &inputs);
    assert_eq!(record.verdict, Verdict::Delivered);
    let attempt = record.attempts.last().unwrap();
    let target = attempt.inverse.as_ref().unwrap().target.as_ref().unwrap();
    let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    assert!(
        rational(&target.lower, &mut budget)
            .compare(
                &rational(NumberId::NumbersPublishedWallLower.value(), &mut budget),
                &mut budget
            )
            .unwrap()
            .is_le()
    );
    assert!(
        rational(&target.upper, &mut budget)
            .compare(
                &rational(NumberId::NumbersPublishedWallUpper.value(), &mut budget),
                &mut budget
            )
            .unwrap()
            .is_ge()
    );
    let width = rational(&target.upper, &mut budget)
        .sub(&rational(&target.lower, &mut budget), &mut budget)
        .unwrap();
    assert!(
        width
            .compare(&rational(&inputs.stopping_width, &mut budget), &mut budget)
            .unwrap()
            .is_le()
    );
    assert_eq!(attempt.branches.as_ref().unwrap().deadband, Relation::Below);
    assert_eq!(attempt.delivered.as_ref().unwrap(), &inputs.previous);
    let mut moving = inputs.clone();
    moving.deadband = "0".into();
    let mut straddle = moving.clone();
    straddle.stopping_width = value(NumberId::NumbersControllerTestStraddlingWidth);
    let unresolved = checked(&procedure, &straddle);
    assert_eq!(unresolved.verdict, Verdict::Indecisive);
    assert_eq!(
        unresolved.attempts.last().unwrap().stopped_at,
        Some(pn_records::controller::Stage::Deadband)
    );
    let grid = checked(&procedure, &moving);
    assert_eq!(grid.verdict, Verdict::Delivered);
    assert_eq!(grid.attempts.last().unwrap().delivered.as_ref().unwrap(), &inputs.previous);
    let error = grid.attempts.last().unwrap().delivery_error.as_ref().unwrap();
    assert!(
        rational(&error.upper, &mut budget)
            .compare(
                &rational(NumberId::NumbersControllerTestError.value(), &mut budget),
                &mut budget
            )
            .unwrap()
            .is_le()
    );
    let mut exact = moving.clone();
    exact.delivery = Delivery::ExactRational;
    assert_eq!(checked(&procedure, &exact).verdict, Verdict::DeliveryRefused);
    signed_caps(&procedure, &inputs, &mut budget);
    let failed = policy(bits(NumberId::NumbersControllerTestFailedPrecision));
    let refused = checked(&failed, &inputs);
    assert_eq!(refused.verdict, Verdict::Indecisive);
    assert_eq!(
        refused
            .attempts
            .last()
            .unwrap()
            .inverse
            .as_ref()
            .unwrap()
            .steps
            .last()
            .unwrap()
            .sign,
        pn_records::wall::Sign::Indecisive
    );
    replay_controls(&procedure, &inputs, &record);
}

fn replay_controls(procedure: &Procedure, inputs: &Inputs, record: &pn_records::controller::Record) {
    let mut changed = inputs.clone();
    changed.width = value(NumberId::NumbersControllerTestUpWidth);
    assert!(matches!(
        kernel::replay(procedure, &changed, None, record),
        Err(kernel::Error::Evidence)
    ));
    let mut changed = record.clone();
    changed.attempts[0].delivered = Some(wall_floor_rational());
    assert!(matches!(
        kernel::replay(procedure, inputs, None, &changed),
        Err(kernel::Error::Evidence)
    ));
    let mut changed = record.clone();
    changed.attempts[0].inverse.as_mut().unwrap().steps[0].primitive.query.target = 0;
    assert!(matches!(
        kernel::replay(procedure, inputs, None, &changed),
        Err(kernel::Error::Inverse(pn_graph::numeric::wall::Error::Query))
    ));
    let mut changed = record.clone();
    changed.attempts[0].inverse.as_mut().unwrap().steps[0]
        .primitive
        .evidence
        .attachment = None;
    assert!(matches!(
        kernel::replay(procedure, inputs, None, &changed),
        Err(kernel::Error::Inverse(pn_graph::numeric::wall::Error::Attachment))
    ));
    let mut limits = inputs.clone();
    limits.maximum_replay_work = limits.maximum_replay_work.checked_add(1).unwrap();
    // Production does not consume this replay-only ceiling. Replay the same
    // production evidence under the larger ceiling without producing it twice.
    let mut larger_replay = record.clone();
    larger_replay.inputs = limits.clone();
    assert_eq!(
        kernel::replay(procedure, &limits, None, &larger_replay).unwrap().verdict,
        Verdict::Delivered
    );
    let mut refinement = procedure.clone();
    refinement.precision = Precision::AbsoluteWidthBits(vec![
        bits(NumberId::NumbersControllerTestFailedPrecision),
        bits(NumberId::NumbersControllerTestUpwardPrecision),
    ]);
    refinement.enclosure.as_mut().unwrap().refinement.precision = bits(NumberId::NumbersControllerTestFailedPrecision);
    let refined = checked(&refinement, inputs);
    assert_eq!(refined.verdict, Verdict::Delivered);
    assert_eq!(
        refined.attempts[0].stopped_at,
        Some(pn_records::controller::Stage::InverseGain)
    );
    assert_eq!(refined.attempts.len(), 2);
}

fn signed_caps(p: &Procedure, i: &Inputs, b: &mut nrz_cas::limits::Budget) {
    for upward in [false, true] {
        let mut x = i.clone();
        x.delivery = Delivery::ExactRational;
        if upward {
            x.width = value(NumberId::NumbersControllerTestUpWidth);
        } else {
            x.previous = value(NumberId::NumbersControllerTestDownPrevious);
        }
        let used = if upward {
            policy(bits(NumberId::NumbersControllerTestUpwardPrecision))
        } else {
            p.clone()
        };
        let result = checked(&used, &x);
        assert_eq!(result.verdict, Verdict::Delivered);
        let branches = result.attempts.last().unwrap().branches.as_ref().unwrap();
        assert_eq!(branches.direction, if upward { Relation::Above } else { Relation::Below });
        assert_eq!(branches.absolute_cap, Relation::Above);
        let previous = rational(&x.previous, b);
        let cap = rational(&x.absolute_cap, b);
        let expected = if upward {
            previous.add(&cap, b).unwrap()
        } else {
            previous.sub(&cap, b).unwrap()
        };
        assert_eq!(
            rational(result.attempts.last().unwrap().delivered.as_ref().unwrap(), b),
            expected
        );
        relative_cap(&used, &x, upward, b);
        if upward {
            let failed = checked(p, &x);
            assert_eq!(failed.verdict, Verdict::Indecisive);
            assert_eq!(
                failed.attempts.last().unwrap().stopped_at,
                Some(pn_records::controller::Stage::InverseGain)
            );
        }
    }
}

fn relative_cap(p: &Procedure, input: &Inputs, upward: bool, budget: &mut nrz_cas::limits::Budget) {
    let mut scenario = input.clone();
    scenario.absolute_cap = value(NumberId::NumbersControllerTestRelativeLimitedAbsoluteCap);
    let previous = rational(&scenario.previous, budget);
    let cap = rational(&scenario.relative_cap, budget).mul(&previous, budget).unwrap();
    assert!(
        cap.compare(&rational(&scenario.absolute_cap, budget), budget)
            .unwrap()
            .is_lt()
    );
    let record = checked(p, &scenario);
    assert_eq!(record.verdict, Verdict::Delivered);
    let attempt = record.attempts.last().unwrap();
    let branches = attempt.branches.as_ref().unwrap();
    assert_eq!(branches.relative_cap, Relation::Above);
    assert_eq!(branches.direction, if upward { Relation::Above } else { Relation::Below });
    let expected = if upward {
        previous.add(&cap, budget).unwrap()
    } else {
        previous.sub(&cap, budget).unwrap()
    };
    assert_eq!(rational(attempt.delivered.as_ref().unwrap(), budget), expected);
}

/// Claim: The zero-width ridge-floor controller retains its independent defining object, certifies an admissible grid wall above that object and refuses exact-rational delivery without equality evidence; the fixture does not charge a ridge enclosure endpoint.
/// ´claim:numerics:controller-ridge-delivery-retains-defining-floor´
/// ´test:integration:controller-ridge´
#[test]
fn controller_ridge() {
    let (p, defining, _, ridge) = super::ridge::certified(NumberId::NumbersRidgeCertificatePrecision);
    let mut i = input();
    i.floor = Floor::RidgeImage;
    i.width = "0".into();
    i.previous = value(NumberId::NumbersControllerTestRidgePrevious);
    i.relative_cap = value(NumberId::NumbersControllerTestRidgeRelativeCap);
    i.deadband = "0".into();
    i.delivery = Delivery::Grid {
        quantum: value(NumberId::NumbersControllerTestRidgeQuantum),
        maximum_error: value(NumberId::NumbersControllerTestRidgeQuantum),
    };
    let r = kernel::evaluate(&p, &i, Some(&ridge)).unwrap();
    assert_eq!(r.verdict, Verdict::Delivered);
    assert_eq!(kernel::replay(&p, &i, Some(&ridge), &r).unwrap(), r);
    let a = r.attempts.last().unwrap();
    let wall = a.delivered.as_ref().unwrap();
    assert_ne!(wall, &ridge.image().unwrap().lower);
    assert_ne!(wall, &ridge.image().unwrap().upper);
    let comparison =
        pn_graph::numeric::ridge::compare(&ridge, &pn_records::ridge::Wall::Rational(wall.clone()), Floor::RidgeImage).unwrap();
    assert_eq!(comparison.verdict, pn_records::numerics::FloorComparison::Above);
    let mut failed = p.clone();
    let precision = bits(NumberId::NumbersRidgeCertificateFailedPrecision);
    failed.precision = Precision::AbsoluteWidthBits(vec![precision]);
    failed.enclosure.as_mut().unwrap().refinement.precision = precision;
    let failed_record = pn_graph::numeric::ridge::evaluate(&failed, &defining).unwrap();
    let failed_ridge = pn_graph::numeric::ridge::replay(&failed, &defining, &failed_record).unwrap();
    assert!(failed_ridge.image().is_none());
    assert_eq!(
        kernel::evaluate(&p, &i, Some(&failed_ridge)).unwrap().verdict,
        Verdict::Indecisive
    );
    i.delivery = Delivery::ExactRational;
    assert_eq!(
        kernel::evaluate(&p, &i, Some(&ridge)).unwrap().verdict,
        Verdict::DeliveryRefused
    );
}
