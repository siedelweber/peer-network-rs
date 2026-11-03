use super::*;
use pn_graph::numeric::ridge as kernel;
use pn_records::{
    numerics::{Floor, NumericError},
    primitive::Range,
    ridge::{ChargeEvidence, Definition, Inputs},
};

fn proof(bits: NumberId) -> ChargeEvidence {
    let context = candidate(&self_acts(), 1, &[("a", NumberId::NumbersAdmissionRepeatedBurn.value())]);
    let mut p = fence_procedure(&compiled(&context));
    let precision = u32::try_from(bits.integer()).unwrap();
    p.precision = Precision::AbsoluteWidthBits(vec![precision]);
    p.enclosure.as_mut().unwrap().refinement.precision = precision;
    let input = Inputs {
        definition: Definition {
            schema: "clean-elasticity-ridge-v1".into(),
            inverse_temperature: "2*ln(2)".into(),
            bleed_squared: "0".into(),
            core_power: "1".into(),
        },
        bracket: Range {
            lower: NumberId::NumbersRidgeBracketLower.value().into(),
            upper: NumberId::NumbersRidgeBracketUpper.value().into(),
        },
        maximum_depth: u32::try_from(NumberId::NumbersRidgeConcavityDepthCeiling.integer()).unwrap(),
        maximum_work: NumberId::NumbersReferenceWorkCeiling.integer(),
        maximum_replay_work: NumberId::NumbersReferenceWorkCeiling.integer(),
    };
    let record = kernel::evaluate(&p, &input).unwrap();
    ChargeEvidence {
        analytic_premises: "clean-ridge-analytic-v1".into(),
        procedure: p,
        input,
        record,
    }
}

fn charge(e: &ChargeEvidence, wall: &str) -> Result<pn_records::numerics::ChargedPrice, NumericError> {
    let mut n = joined::numeric();
    let (_, edition, _) = common::fixture();
    let wall = n.literal(wall).unwrap();
    let wall = n.computed(&wall).unwrap();
    n.charged_price_with_ridge(&wall, &edition.numeraire, e, &kernel::ChargeReplay)
}

/// Claim: The finite ridge charge controls retain the declared defining transcript under graph replay; changed bleed, image and query precision are refused, and an unresolved image or wall straddle constructs no charge. The retained rational wall, not a rounded floor image, supplies the charge.
/// ´claim:admission:ridge-charge-requires-defining-replay´
/// ´test:integration:ridge-charge-controls´
#[test]
fn ridge_charge_controls() {
    let evidence = proof(NumberId::NumbersRidgeCertificatePrecision);
    assert!(evidence.record.image.is_some());
    let price = charge(&evidence, NumberId::NumbersAdmissionWall.value()).unwrap();
    assert_eq!(price.wall().exact(), NumberId::NumbersAdmissionWall.value());
    assert_eq!(price.price().exact(), NumberId::NumbersAdmissionWall.value());
    let low = proof(NumberId::NumbersRidgeCertificateFailedPrecision);
    assert!(low.record.image.is_none());
    assert_eq!(
        charge(&low, NumberId::NumbersAdmissionWall.value()),
        Err(NumericError::Indecisive)
    );
    let image = evidence.record.image.as_ref().unwrap();
    let middle = Fraction::parse(&image.lower)
        .plus(Fraction::parse(&image.upper))
        .over(Fraction(2, 1));
    let middle = format!("{}/{}", middle.0, middle.1);
    assert_eq!(charge(&evidence, &middle), Err(NumericError::Indecisive));
    assert_eq!(charge(&evidence, "0"), Err(NumericError::BelowFloor));
    let mut changed = evidence.clone();
    changed.input.definition.bleed_squared = NumberId::NumbersReferenceSquaredBleed.value().into();
    assert_eq!(
        charge(&changed, NumberId::NumbersAdmissionWall.value()),
        Err(NumericError::RidgeDefinition)
    );
    changed = evidence.clone();
    changed.record.image.as_mut().unwrap().lower = "0".into();
    assert_eq!(
        charge(&changed, NumberId::NumbersAdmissionWall.value()),
        Err(NumericError::RidgeEvidence)
    );
    changed = evidence;
    changed.record.queries[0].precision += 1;
    assert_eq!(
        charge(&changed, NumberId::NumbersAdmissionWall.value()),
        Err(NumericError::RidgeEvidence)
    );
}

fn ridge_candidate(evidence: &ChargeEvidence) -> package::CandidateContext {
    let original = candidate(&self_acts(), 1, &[("a", NumberId::NumbersAdmissionRepeatedBurn.value())]);
    let mut context = original.input().clone();
    let (declaration, mut edition, _) = common::fixture();
    edition.floor = Floor::RidgeImage;
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let record = pn_records::validate_record(&[], &empty, &[declaration]).unwrap();
    let constants = pn_records::constants::bind_constants(&record, vec![edition]).unwrap();
    let parameters = context.causes.inputs[0].parameters().clone();
    let input = pn_epoch::bind_inputs(&constants, parameters, Limits::default()).unwrap();
    let price = charge(evidence, NumberId::NumbersAdmissionWall.value()).unwrap();
    context.causes.inputs[0] = input.clone();
    context.causes.prices[0] = price.clone();
    context.causes.bindings[0].inputs = input;
    context.causes.bindings[0].price = price;
    let verifier = Causes(context.clone());
    package::verify_candidate(context, &verifier, &verifier).unwrap()
}

/// Claim: The finite reversed complete self-supported history admits under each chartered floor through production ledger, support, schedule and final gates. Ridge charging replays the defining transcript independently and retains the same rational charge, exact stamps and independent final replay; no published-reference or deployment authority is inferred.
/// ´claim:admission:both-floors-retain-production-charge-gates´
/// ´test:integration:ridge-charge-admission´
#[test]
fn ridge_charge_admission() {
    let evidence = proof(NumberId::NumbersRidgeCertificatePrecision);
    let checked = kernel::replay(&evidence.procedure, &evidence.input, &evidence.record).unwrap();
    let rational = candidate(&self_acts(), 1, &[("a", NumberId::NumbersAdmissionRepeatedBurn.value())]);
    let ridge = ridge_candidate(&evidence);
    assert_eq!(rational.input().causes.history.acts(), ridge.input().causes.history.acts());
    let mut previous = None;
    for (context, ridge) in [(&ridge, Some(&checked)), (&rational, None)] {
        let plan = procedure(context);
        let base = schedule(&rational, NumberId::NumbersAdmissionWall.value());
        let mut declaration = base.record().declaration.clone();
        declaration.initialization.floor = Some(context.input().causes.inputs[0].constants().content().floor);
        let declaration = admission::declare_schedule(declaration, Limits::default()).unwrap();
        let record = schedules::evaluate(&declaration, &[], ridge, Limits::default()).unwrap();
        let led = schedules::replay(&declaration, &[], ridge, Limits::default(), &record).unwrap();
        let admitted = run(context, &plan, &led).unwrap();
        let final_round = admitted.evidence().rounds.last().unwrap();
        for stamp in final_round.stamps.values() {
            assert_eq!(stamp.lower, NumberId::NumbersAdmissionWall.value());
            assert_eq!(stamp.upper, NumberId::NumbersAdmissionWall.value());
        }
        let blocks = closure::partition(context).unwrap();
        let input = ClosureInput {
            candidate: context,
            partition: &blocks,
            schedule: &led,
            previous: None,
        };
        let closed = closure::close(
            &input,
            &plan,
            &joined::Verifier,
            &Published(plan.solve.clone()),
            joined::numeric(),
        )
        .unwrap();
        let replayed = closure::replay(
            &input,
            &plan,
            &joined::Verifier,
            &Published(plan.solve.clone()),
            joined::numeric(),
            closed.record(),
        )
        .unwrap();
        assert_eq!(replayed.record(), closed.record());
        assert_eq!(&closed.record().final_gates, admitted.evidence());
        if let Some(expected) = &previous {
            assert_eq!(final_round, expected);
        }
        previous = Some(final_round.clone());
    }
}

#[path = "ridge_charge/envelope.rs"]
mod envelope;

#[path = "ridge_charge/publication.rs"]
mod publication;
