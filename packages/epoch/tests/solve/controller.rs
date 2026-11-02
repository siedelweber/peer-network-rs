use super::*;
use pn_epoch::{
    admission::{ControllerParameters, Delivery, InitializationInput, Refinement, ScheduleInput, declare_schedule},
    controller::{InverseSearch, evaluate, replay},
};

/// Claim: The zero-width completed-epoch controller derives its width, chartered tilt, bleed, current wall and accepted rung from the frozen compile and independently replayed fence, binds the declared rational numeraire image, and rejects substituted declaration, controller and burn-image evidence without modifying debit vintages; schedule activation and final admission remain separate.
/// ´claim:admission:controller-publication-retains-frozen-epoch-inputs´
/// ´test:integration:controller-binding´
#[test]
fn controller_binding() {
    let state = singleton_hull_state();
    let before = state.view().clone();
    let price = state.package().input().prices.last().unwrap().clone();
    let mut p = fence_procedure(&state);
    let precision = u32::try_from(NumberId::NumbersControllerTestScopePrecision.integer()).unwrap();
    p.precision = Precision::AbsoluteWidthBits(vec![precision]);
    p.enclosure.as_mut().unwrap().refinement.precision = precision;
    let declaration = ScheduleInput {
        controller: "canonical-interim-v1".into(),
        announced_at: 0,
        initialization: InitializationInput {
            floor: Some(state.package().input().inputs.last().unwrap().constants().content().floor),
            wall: Some(price.wall().exact().into()),
            policy_floor: Some(price.wall().exact().into()),
            effective_boundary: Some(1),
            parameters: Some(ControllerParameters {
                absolute_cap: NumberId::NumbersScheduleFixtureAbsoluteCap.value().into(),
                relative_cap: NumberId::NumbersScheduleFixtureRelativeCap.value().into(),
                deadband: NumberId::NumbersScheduleFixtureDeadband.value().into(),
                margin: p.margin.clone(),
            }),
        },
        numeraire: price.numeraire().clone(),
        delivery: Delivery::ExactRational,
        refinement: Refinement {
            precision_bits: vec![precision],
            maximum_work: NumberId::NumbersControllerTestWork.integer(),
            maximum_replay_work: NumberId::NumbersControllerTestWork.integer(),
        },
    };
    let d = declare_schedule(declaration.clone(), Limits::default()).unwrap();
    let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
    let search = InverseSearch {
        bracket: pn_records::primitive::Range {
            lower: NumberId::NumbersControllerTestBracketLower.value().into(),
            upper: NumberId::NumbersControllerTestBracketUpper.value().into(),
        },
        stopping_width: NumberId::NumbersControllerTestStoppingWidth.value().into(),
        maximum_steps: NumberId::NumbersControllerTestSteps.integer(),
    };
    let e = evaluate(&bound, &d, &search, None).unwrap();
    let checked = replay(&bound, &d, &search, None, &e).unwrap();
    assert_eq!(checked.evidence(), &e);
    assert_eq!(e.controller.inputs.width, "0");
    assert!(!e.controller.inputs.empty_live_domain);
    assert_eq!(e.controller.inputs.previous, price.wall().exact());
    assert_eq!(Some(&e.controller.inputs.accepted_rung), e.fence.selected.as_ref());
    assert!(e.controller.attempts.iter().all(|a| a.inverse.is_none()));
    let wall = e.controller.attempts.last().unwrap().delivered.as_ref().unwrap();
    let expected = Fraction::parse(wall).times(Fraction::parse(price.numeraire().amount().exact()));
    assert_eq!(Fraction::parse(e.burn_image.as_ref().unwrap()), expected);
    for mutation in (0..3).rev() {
        let mut changed = e.clone();
        match mutation {
            0 => changed.burn_image = Some("0".into()),
            1 => changed.controller.inputs.width = "1".into(),
            _ => changed.declaration.controller = "unadmitted".into(),
        }
        assert!(replay(&bound, &d, &search, None, &changed).is_err());
    }
    assert_eq!(state.view(), &before);
    assert_eq!(state.package().input().prices.last().unwrap(), &price);
}
