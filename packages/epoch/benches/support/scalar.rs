#[path = "../../../documents/src/pins_graph.rs"]
pub mod pins;
use pins::NumberId as N;
use pn_records::{primitive::Range, solve::Procedure};

pub fn ridge(p: &Procedure, cap: u32) -> (Procedure, pn_records::ridge::Inputs, pn_records::ridge::Record) {
    let mut p = p.clone();
    let bits = u32::try_from(N::NumbersRidgeCertificatePrecision.integer()).unwrap();
    p.precision = pn_records::solve::Precision::AbsoluteWidthBits(vec![bits]);
    p.maximum_work = N::NumbersVerificationTrialWorkCeiling.integer();
    let e = p.enclosure.as_mut().unwrap();
    e.refinement.precision = bits;
    e.operation.work = p.maximum_work;
    e.operation.arithmetic_steps = 1_000_000_000;
    e.operation.literal_bytes = 4096;
    e.store = e.operation.clone();
    let input = pn_records::ridge::Inputs {
        definition: pn_records::ridge::Definition {
            schema: "clean-elasticity-ridge-v1".into(),
            inverse_temperature: "2*ln(2)".into(),
            bleed_squared: "0".into(),
            core_power: "1".into(),
        },
        bracket: Range {
            lower: N::NumbersRidgeBracketLower.value().into(),
            upper: N::NumbersRidgeBracketUpper.value().into(),
        },
        maximum_depth: cap,
        maximum_work: N::NumbersReferenceWorkCeiling.integer(),
        maximum_replay_work: N::NumbersReferenceWorkCeiling.integer(),
    };
    let r = pn_graph::numeric::ridge::evaluate(&p, &input).unwrap();
    (p, input, r)
}
pub fn rational(
    p: &Procedure,
    cap: u64,
) -> Result<(pn_records::controller::Inputs, pn_records::controller::Record), pn_graph::numeric::controller::Error> {
    let input = pn_records::controller::Inputs {
        width: "1".into(),
        empty_live_domain: false,
        accepted_rung: "1".into(),
        cumulative_tilt: N::NumbersControllerTestCharteredTilt.value().into(),
        bleed_squared: super::constants::pins::NumberId::NumbersReferenceSquaredBleed.value().into(),
        previous: "2".into(),
        floor: pn_records::numerics::Floor::RationalThreeThirtySevenths,
        absolute_cap: "1/4".into(),
        relative_cap: "1/4".into(),
        deadband: "0".into(),
        bracket: Range {
            lower: N::NumbersControllerTestBracketLower.value().into(),
            upper: N::NumbersControllerTestBracketUpper.value().into(),
        },
        stopping_width: "1/64".into(),
        maximum_steps: cap,
        maximum_work: N::NumbersControllerTestWork.integer(),
        maximum_replay_work: N::NumbersControllerTestWork.integer(),
        delivery: pn_records::controller::Delivery::Grid {
            quantum: N::NumbersControllerTestQuantum.value().into(),
            maximum_error: N::NumbersControllerTestError.value().into(),
        },
    };
    let r = pn_graph::numeric::controller::evaluate(p, &input, None)?;
    Ok((input, r))
}
pub fn check(p: &Procedure) {
    let (p, i, r) = ridge(p, 1);
    let checked = pn_graph::numeric::ridge::replay(&p, &i, &r).unwrap();
    assert_eq!(checked.image(), r.image.as_ref());
    let mut bad = r.clone();
    bad.input.definition.schema.push_str("-changed");
    assert!(pn_graph::numeric::ridge::replay(&p, &i, &bad).is_err());
    let (i, r) = rational(&p, 8).unwrap();
    assert!(matches!(
        rational(&p, 1),
        Err(pn_graph::numeric::controller::Error::Inverse(
            pn_graph::numeric::wall::Error::Iterations
        ))
    ));
    assert_eq!(pn_graph::numeric::controller::replay(&p, &i, None, &r).unwrap(), r);
    let mut bad = r.clone();
    bad.inputs.maximum_steps += 1;
    assert!(pn_graph::numeric::controller::replay(&p, &i, None, &bad).is_err());
}
