use super::*;
use pn_graph::numeric::ridge as kernel;
use pn_records::{
    numerics::{Floor, FloorComparison},
    ridge::{Definition, Inputs, Wall},
};

fn definition() -> Definition {
    Definition {
        schema: "clean-elasticity-ridge-v1".into(),
        inverse_temperature: "2*ln(2)".into(),
        bleed_squared: "0".into(),
        core_power: "1".into(),
    }
}
fn input() -> Inputs {
    Inputs {
        definition: definition(),
        bracket: range(
            NumberId::NumbersRidgeBracketLower.value(),
            NumberId::NumbersRidgeBracketUpper.value(),
        ),
        maximum_depth: u32::try_from(NumberId::NumbersRidgeConcavityDepthCeiling.integer()).unwrap(),
        maximum_work: NumberId::NumbersReferenceWorkCeiling.integer(),
        maximum_replay_work: NumberId::NumbersReferenceWorkCeiling.integer(),
    }
}
fn policy(bits: u32) -> Procedure {
    let mut p = verification_policy();
    p.precision = Precision::AbsoluteWidthBits(vec![bits]);
    p.enclosure.as_mut().unwrap().refinement.precision = bits;
    p
}
fn constant(key: &str) -> String {
    let data: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/datasets/org.peer-network.design.constants.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let row = data["rows"].as_array().unwrap().iter().find(|r| r["id"] == key).unwrap();
    row["definition"]["value"].as_str().unwrap().into()
}
fn image(point: &str) -> String {
    let mut b = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    let p = nrz_cas::Rational::parse(point, &mut b).unwrap();
    let one = nrz_cas::Rational::parse("1", &mut b).unwrap();
    p.div(&one.sub(&p, &mut b).unwrap(), &mut b)
        .unwrap()
        .exact_string(&mut b)
        .unwrap()
}

fn bits(id: NumberId) -> u32 {
    u32::try_from(id.integer()).unwrap()
}
fn certified(precision: NumberId) -> (Procedure, Inputs, pn_records::ridge::Record, kernel::CheckedRidge) {
    let p = policy(bits(precision));
    let i = input();
    let r = kernel::evaluate(&p, &i).unwrap();
    assert!(r.image.is_some());
    let c = kernel::replay(&p, &i, &r).unwrap();
    (p, i, r, c)
}
fn rational(text: &str, b: &mut nrz_cas::limits::Budget) -> nrz_cas::Rational {
    nrz_cas::Rational::parse(text, b).unwrap()
}
fn independent_derivative(point: Q) -> I {
    let one = I::point(Q(1, 1));
    let two = I::point(Q(2, 1));
    let p = I::point(point);
    let (lo, hi) = tight_log(Q(2, 1));
    let beta = I::rounded(lo.mul(Q(2, 1)), hi.mul(Q(2, 1)));
    let sigma = beta.mul(p).sigmoid();
    let t = p.tanh();
    let square = t.mul(t);
    let kernel = beta.mul(one.sub(sigma)).add(one.sub(square).div(two.mul(t)));
    let slope = beta
        .mul(beta)
        .mul(sigma)
        .mul(one.sub(sigma))
        .add(one.div(square).sub(square).div(two));
    one.sub(two.mul(p)).mul(kernel).sub(p.mul(one.sub(p)).mul(slope))
}

/// Claim: The closed clean-ridge schema retains checked analytic premises, a complete concavity-majorant cover and strict endpoint signs, with a rational image containing the tagged published bounds and lying below the default door; the finite independent oracle and failed precision control witness instances, not uniqueness laws.
/// ´claim:numerics:ridge-definition-retains-analytic-premises´
/// ´test:integration:ridge-definition´
#[test]
fn ridge_definition() {
    let (p, i, r, checked) = certified(NumberId::NumbersRidgeCertificatePrecision);
    assert_eq!(r.work, NumberId::NumbersRidgeCertificateWork.integer());
    assert_eq!(
        checked.image(),
        Some(&range(
            NumberId::NumbersRidgeImageLower.value(),
            NumberId::NumbersRidgeImageUpper.value()
        ))
    );
    let mut next = "0";
    for cell in &r.cells {
        assert_eq!(cell.lower, next);
        next = &cell.upper;
    }
    assert_eq!(next, "1/2");
    let mut b = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    let image_bounds = checked.image().unwrap();
    let lo = rational(&image_bounds.lower, &mut b);
    let hi = rational(&image_bounds.upper, &mut b);
    for (id, lower) in [
        (NumberId::NumbersPublishedRidgeImageUpper, false),
        (NumberId::NumbersPublishedRidgeImageLower, true),
    ] {
        let value = rational(id.value(), &mut b);
        assert!(if lower {
            lo.compare(&value, &mut b).unwrap().is_lt()
        } else {
            hi.compare(&value, &mut b).unwrap().is_gt()
        });
    }
    let door = constant("const.comparator.policy_floor");
    assert!(hi.compare(&rational(&door, &mut b), &mut b).unwrap().is_lt());
    let rational_floor = rational(&wall_floor_rational(), &mut b);
    assert!(hi.compare(&rational_floor, &mut b).unwrap().is_lt());
    assert!(rational_floor.compare(&rational(&door, &mut b), &mut b).unwrap().is_lt());
    for (point, positive) in [
        (NumberId::NumbersRidgeIndependentBracketUpper, false),
        (NumberId::NumbersRidgeIndependentBracketLower, true),
    ] {
        let derivative = independent_derivative(Q::parse(point.value()));
        assert!(if positive { derivative.0.0 > 0 } else { derivative.1.0 < 0 });
        let independent_image = image(point.value());
        let independent_image = rational(&independent_image, &mut b);
        assert!(if positive {
            independent_image.compare(&lo, &mut b).unwrap().is_lt()
        } else {
            independent_image.compare(&hi, &mut b).unwrap().is_gt()
        });
    }
    let failed = policy(bits(NumberId::NumbersRidgeCertificateFailedPrecision));
    let prefix = kernel::evaluate(&failed, &i).unwrap();
    assert!(prefix.image.is_none());
    assert!(kernel::replay(&failed, &i, &prefix).unwrap().image().is_none());
    let bounds = prefix.queries.last().unwrap().evidence.bounds.as_ref().unwrap();
    let zero = rational("0", &mut b);
    assert!(!bounds.lower().compare(&zero, &mut b).unwrap().is_gt() && !bounds.upper().compare(&zero, &mut b).unwrap().is_lt());
    let mut capped = i.clone();
    capped.maximum_work = r.work;
    assert_eq!(kernel::evaluate(&p, &capped).unwrap().image, r.image);
    capped.maximum_work -= 1;
    assert!(kernel::evaluate(&p, &capped).is_err());
}

/// Claim: Both chartered floors retain exact equality or checked defining identity, adjacent rational comparisons separate at the measured precision, a checked straddle refines or remains indecisive, and no published decimal or ridge endpoint is adopted as the defining floor or a charge.
/// ´claim:numerics:ridge-comparisons-refine-or-remain-indecisive´
/// ´test:integration:ridge-comparisons´
#[test]
fn ridge_comparisons() {
    let (_, i, r, checked) = certified(NumberId::NumbersRidgeComparisonPrecision);
    assert_eq!(r.work, NumberId::NumbersRidgeComparisonCertificateWork.integer());
    let adjacent = [
        (
            Wall::Rational(image(&constant("bound.dynamics.ridge_p_hi"))),
            FloorComparison::Above,
            NumberId::NumbersRidgeUpperComparisonWork,
        ),
        (
            Wall::Rational(image(&constant("bound.dynamics.ridge_p_lo"))),
            FloorComparison::Below,
            NumberId::NumbersRidgeLowerComparisonWork,
        ),
    ];
    for (wall, expected, work) in &adjacent {
        let record = kernel::compare(&checked, wall, Floor::RidgeImage).unwrap();
        assert_eq!(record.verdict, *expected);
        assert_eq!(record.work, work.integer());
        assert_eq!(
            kernel::replay_comparison(&checked, wall, Floor::RidgeImage, &record)
                .unwrap()
                .verdict,
            *expected
        );
    }
    let identity = Wall::DefiningRidge(definition());
    for (floor, expected) in [
        (Floor::RationalThreeThirtySevenths, FloorComparison::Below),
        (Floor::RidgeImage, FloorComparison::Equal),
    ] {
        let record = kernel::compare(&checked, &identity, floor).unwrap();
        assert_eq!(record.verdict, expected);
        assert_eq!(
            kernel::replay_comparison(&checked, &identity, floor, &record)
                .unwrap()
                .verdict,
            expected
        );
    }
    let mut b = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    let floor = rational(&wall_floor_rational(), &mut b);
    let step = rational(NumberId::NumbersRidgeRationalNeighborStep.value(), &mut b);
    for (wall, expected) in [
        (floor.add(&step, &mut b).unwrap(), FloorComparison::Above),
        (floor.clone(), FloorComparison::Equal),
        (floor.sub(&step, &mut b).unwrap(), FloorComparison::Below),
    ] {
        let wall = Wall::Rational(wall.exact_string(&mut b).unwrap());
        let r = kernel::compare(&checked, &wall, Floor::RationalThreeThirtySevenths).unwrap();
        assert_eq!(r.verdict, expected);
        assert_eq!(
            kernel::replay_comparison(&checked, &wall, Floor::RationalThreeThirtySevenths, &r)
                .unwrap()
                .verdict,
            expected
        );
    }
    let wall = Wall::Rational(NumberId::NumbersPublishedRidgeRootDisplay.value().into());
    let r = kernel::compare(&checked, &wall, Floor::RidgeImage).unwrap();
    assert_eq!(r.verdict, FloorComparison::Indecisive);
    assert_eq!(
        kernel::replay_comparison(&checked, &wall, Floor::RidgeImage, &r)
            .unwrap()
            .verdict,
        FloorComparison::Indecisive
    );
    let bounds = r.queries.last().unwrap().evidence.bounds.as_ref().unwrap();
    let zero = rational("0", &mut b);
    assert!(!bounds.lower().compare(&zero, &mut b).unwrap().is_gt() && !bounds.upper().compare(&zero, &mut b).unwrap().is_lt());
    let failed = policy(bits(NumberId::NumbersRidgeComparisonFailedPrecision));
    let prefix = kernel::evaluate(&failed, &i).unwrap();
    let coarse = kernel::replay(&failed, &i, &prefix).unwrap();
    assert_eq!(
        kernel::compare(&coarse, &adjacent[1].0, Floor::RidgeImage).unwrap().verdict,
        FloorComparison::Indecisive
    );
    let mut refining = policy(bits(NumberId::NumbersRidgeComparisonPrecision));
    refining.precision = Precision::AbsoluteWidthBits(vec![1, bits(NumberId::NumbersRidgeComparisonPrecision)]);
    let r = kernel::evaluate(&refining, &i).unwrap();
    let refined = kernel::replay(&refining, &i, &r).unwrap();
    let result = kernel::compare(&refined, &adjacent[1].0, Floor::RidgeImage).unwrap();
    assert_eq!(result.verdict, FloorComparison::Below);
    assert!(result.queries.iter().any(|q| q.precision == 1));
    assert_eq!(
        kernel::replay_comparison(&refined, &adjacent[1].0, Floor::RidgeImage, &result)
            .unwrap()
            .verdict,
        FloorComparison::Below
    );
}

/// Claim: Independent ridge replay reconstructs the defining formula, complete cover and expected floor query, refusing changed defining inputs, queries, attachments, cells, image and asserted comparison; finite wrong-sign and exhausted-cover controls never establish a ridge.
/// ´claim:numerics:ridge-replay-refuses-defining-and-query-substitution´
/// ´test:integration:ridge-replay´
#[test]
fn ridge_replay() {
    let (p, i, r, checked) = certified(NumberId::NumbersRidgeCertificatePrecision);
    for mutation in (0..4).rev() {
        let mut changed = i.clone();
        match mutation {
            0 => changed.definition.schema.push_str("-foreign"),
            1 => changed.definition.inverse_temperature = "ln(2)".into(),
            2 => changed.definition.bleed_squared = "1".into(),
            _ => changed.definition.core_power = "1/4".into(),
        }
        assert_eq!(kernel::evaluate(&p, &changed).unwrap_err(), kernel::Error::Definition);
        assert!(matches!(kernel::replay(&p, &changed, &r), Err(kernel::Error::Definition)));
    }
    let mut changed = r.clone();
    changed.queries[0].query.nodes[0] = Node::Rational("1".into());
    assert!(matches!(kernel::replay(&p, &i, &changed), Err(kernel::Error::Query)));
    let mut changed = r.clone();
    changed.queries[0].evidence.attachment = None;
    assert!(matches!(kernel::replay(&p, &i, &changed), Err(kernel::Error::Attachment)));
    let mut changed = r.clone();
    changed.cells[0].lower = "1".into();
    assert!(matches!(kernel::replay(&p, &i, &changed), Err(kernel::Error::Record)));
    let mut changed = r.clone();
    changed.image.as_mut().unwrap().lower = "1".into();
    assert!(matches!(kernel::replay(&p, &i, &changed), Err(kernel::Error::Record)));
    let wall = Wall::DefiningRidge(definition());
    let record = kernel::compare(&checked, &wall, Floor::RidgeImage).unwrap();
    let mut changed = record.clone();
    changed.verdict = FloorComparison::Above;
    assert_eq!(
        kernel::replay_comparison(&checked, &wall, Floor::RidgeImage, &changed).unwrap_err(),
        kernel::Error::Record
    );
    assert_eq!(
        kernel::replay_comparison(&checked, &Wall::Rational("1".into()), Floor::RidgeImage, &record).unwrap_err(),
        kernel::Error::Query
    );
    let mut bad = i.clone();
    bad.bracket = range(
        NumberId::NumbersRidgeIndependentBracketLower.value(),
        NumberId::NumbersRidgeBracketLower.value(),
    );
    assert!(matches!(kernel::evaluate(&p, &bad), Err(kernel::Error::Bracket)));
    let mut short = i.clone();
    short.maximum_depth = 0;
    let prefix = kernel::evaluate(&p, &short).unwrap();
    assert!(prefix.image.is_none());
    assert!(kernel::replay(&p, &short, &prefix).unwrap().image().is_none());
}
