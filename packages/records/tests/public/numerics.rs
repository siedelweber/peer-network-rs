use pn_records::constants::{ConstantDefinition, ConstantsError, EditionInput, bind_constants};
use pn_records::numerics::{ActionCount, ComparisonLimits, ExactLimits, Floor, FloorComparison, NumericContext, NumericError};
use pn_records::{Declaration, DeclarationId, validate_history, validate_record};

fn context() -> NumericContext {
    NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap()
}

/// Claim: Recoinage multiplies burn and numeraire together and preserves the reduced coordinate, while repricing the same unit divides burn by the market factor at fixed purchasing power and changes the reduced coordinate when the numeraire stays fixed.
/// ´claim:numerics:recoinage-and-repricing-have-distinct-laws´
/// ´test:integration:unit-laws´
#[test]
fn unit_laws() {
    let mut c = context();
    let twelve = c.literal("12").unwrap();
    let two = c.literal("2").unwrap();
    let four = c.literal("4").unwrap();
    let amount = c.burn(&twelve, "old-unit").unwrap();
    let nu_amount = c.burn_per_action(&two, "old-unit").unwrap();
    let nu = c.numeraire("declared-nu", &nu_amount).unwrap();
    let full = c.standing(&twelve, "old-unit").unwrap();
    let original = c.reduce(&full, &nu).unwrap();
    assert_eq!(original.exact(), "6");
    let (coined, co_nu) = c.recoin(&amount, &nu, &four, "new-unit").unwrap();
    assert_eq!((coined.exact(), co_nu.amount().exact()), ("48", "8"));
    let (coined_full, standing_nu) = c.recoin_standing(&full, &nu, &four, "new-unit").unwrap();
    assert_eq!(standing_nu, co_nu);
    assert_eq!(c.reduce_burn(&coined, &co_nu).unwrap().exact(), "6");
    assert_eq!(c.reduce(&coined_full, &co_nu).unwrap().exact(), original.exact());
    assert_eq!(co_nu.identity(), nu.identity());
    let repriced = c.reprice(&amount, &four).unwrap();
    assert_eq!((repriced.exact(), repriced.unit()), ("3", "old-unit"));
    let repriced_full = c.reprice_standing(&full, &four).unwrap();
    assert_eq!(c.reduce_burn(&repriced, &nu).unwrap().exact(), "3/2");
    let reduced = c.reduce(&repriced_full, &nu).unwrap();
    assert_eq!(reduced.exact(), "3/2");
    assert_ne!(reduced.exact(), original.exact());
    assert_eq!(reduced.numeraire(), &nu);
}

/// Claim: A positive sub-unit external cost multiplies only burn quantities, including an action count times the per-action sum theta plus numeraire times a reduced coordinate; recording-event charges retain their own evidence and mismatched burn units refuse.
/// ´claim:numerics:external-cost-projects-burn-units-only´
/// ´test:integration:unit-costs´
#[test]
fn unit_costs() {
    let mut c = context();
    let quarter = c.literal("1/4").unwrap();
    let two = c.literal("2").unwrap();
    let twelve = c.literal("12").unwrap();
    let cost = c.unit_cost(&quarter, "USD", "burn", "market-window").unwrap();
    let theta = c.burn_per_action(&two, "burn").unwrap();
    let nu = c.numeraire("nu", &theta).unwrap();
    let three = c.literal("3").unwrap();
    let rho = c.computed(&three).unwrap();
    let additional = c.per_action(&rho, &nu).unwrap();
    assert_eq!(additional.exact(), "6");
    let door = c.door_amount(ActionCount(5), &theta, &rho, &nu).unwrap();
    assert_eq!(door.exact(), "40");
    assert_eq!(c.apply_cost(&cost, &door).unwrap().exact(), "10");
    assert_eq!(c.door_amount(ActionCount(0), &theta, &rho, &nu).unwrap().exact(), "0");
    assert_eq!(c.recording_cost(&twelve, "USD", "receipt-7").unwrap().exact(), "12");
    let other = c.burn(&two, "other").unwrap();
    assert_eq!(c.apply_cost(&cost, &other), Err(NumericError::Units));
}

/// Claim: Rational walls immediately below, equal to and above three thirty-sevenths compare exactly despite identical rounded displays; unresolved ridge comparisons and exhausted attempt budgets remain indecisive and cannot produce a charged price.
/// ´claim:numerics:boundary-comparisons-remain-sound-or-indecisive´
/// ´test:integration:floor-decisions´
#[test]
fn floor_decisions() {
    let mut c = context();
    for (text, expected) in [
        ("2999999999999999999/37000000000000000000", FloorComparison::Below),
        ("3/37", FloorComparison::Equal),
        ("3000000000000000001/37000000000000000000", FloorComparison::Above),
    ] {
        let literal = c.literal(text).unwrap();
        let wall = c.computed(&literal).unwrap();
        assert_eq!(c.compare_floor(&wall, Floor::RationalThreeThirtySevenths), Ok(expected));
        assert_eq!(c.display(&wall, 2).unwrap().text(), "0.08");
        assert_eq!(c.compare_floor(&wall, Floor::RidgeImage), Ok(FloorComparison::Indecisive));
        let one = c.literal("1").unwrap();
        let unit = c.burn_per_action(&one, "burn").unwrap();
        let nu = c.numeraire("nu", &unit).unwrap();
        assert_eq!(c.charged_price(&wall, &nu, Floor::RidgeImage), Err(NumericError::Indecisive));
        if expected == FloorComparison::Below {
            assert_eq!(
                c.charged_price(&wall, &nu, Floor::RationalThreeThirtySevenths),
                Err(NumericError::BelowFloor)
            );
        }
        let mut exhausted = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(0, 0)).unwrap();
        assert_eq!(
            exhausted.compare_floor(&wall, Floor::RationalThreeThirtySevenths),
            Ok(FloorComparison::Indecisive)
        );
    }
}

/// Claim: A charged price is derived from one exact wall-numeraire pair, and a consummated vintage retains that pair and total when a later price changes; no independently supplied price can disagree with its wall.
/// ´claim:ledger:later-prices-preserve-charged-vintages´
/// ´test:integration:charged-vintages´
#[test]
fn charged_vintages() {
    let mut c = context();
    let two = c.literal("2").unwrap();
    let three = c.literal("3").unwrap();
    let four = c.literal("4").unwrap();
    let amount = c.burn_per_action(&three, "burn").unwrap();
    let nu = c.numeraire("nu", &amount).unwrap();
    let wall = c.computed(&two).unwrap();
    let price = c.charged_price(&wall, &nu, Floor::RationalThreeThirtySevenths).unwrap();
    assert_eq!(price.price().exact(), "6");
    let vintage = c.consummate(&price, ActionCount(5), 10).unwrap();
    let later_wall = c.computed(&four).unwrap();
    let later = c.charged_price(&later_wall, &nu, Floor::RationalThreeThirtySevenths).unwrap();
    assert_eq!(later.price().exact(), "12");
    assert_eq!(c.consummate(&later, ActionCount(5), 11).unwrap().charged().exact(), "60");
    assert_eq!(vintage.charged().exact(), "30");
    assert_eq!(vintage.price(), &price);
    assert_eq!(vintage.boundary(), 10);
}

fn header(edition: u64, at: u64) -> Declaration {
    Declaration {
        id: DeclarationId {
            namespace: "numeric".into(),
            name: "constants".into(),
            edition,
        },
        announced_at: at - 1,
        effective_at: at,
    }
}
fn payload(c: &mut NumericContext, id: DeclarationId, controller: &str, floor: Floor) -> EditionInput {
    let two = c.literal("2").unwrap();
    let amount = c.burn_per_action(&two, "burn").unwrap();
    EditionInput {
        id,
        floor,
        numeraire: c.numeraire("nu", &amount).unwrap(),
        formula_edition: "formula-1".into(),
        controller_edition: controller.into(),
        constants: vec![ConstantDefinition::Literal {
            name: "margin".into(),
            value: two,
        }],
        permitted_overrides: vec!["margin".into()],
        domain_profiles: vec!["finite".into()],
        numerical_procedure: "exact-rational-or-indecisive".into(),
        authentication_realization: "declared-signature".into(),
        publication_profile: "internal".into(),
    }
}

/// Claim: Binding every payload once to validated announcement/effective identities returns the old controller, numeraire and exact floor definitions at an old boundary; a later structural floor choice cannot reinterpret the earlier edition.
/// ´claim:declarations:effective-editions-preserve-historical-constants´
/// ´test:integration:historical-constants´
#[test]
fn historical_constants() {
    let mut c = context();
    let old = header(1, 10);
    let new = header(2, 20);
    let history = validate_history(&[], &[]).unwrap();
    let records = validate_record(&[], &history, &[old.clone(), new.clone()]).unwrap();
    let a = payload(&mut c, old.id, "controller-old", Floor::RationalThreeThirtySevenths);
    let b = payload(&mut c, new.id, "controller-new", Floor::RidgeImage);
    let constants = bind_constants(&records, vec![b.clone(), a.clone()]).unwrap();
    assert_eq!(constants.resolve("numeric", "constants", 10).unwrap().content(), &a);
    assert_eq!(constants.resolve("numeric", "constants", 19).unwrap().content(), &a);
    assert_eq!(constants.resolve("numeric", "constants", 20).unwrap().content(), &b);
    assert!(constants.resolve("numeric", "constants", 9).is_err());
    assert_eq!(
        constants.resolve("numeric", "constants", 10).unwrap().floor_source(),
        &ConstantDefinition::Expression {
            name: "structural-floor".into(),
            expression: "3/37".into(),
            source_label: "case:epoch:safety-wall-floor-rational-floor".into()
        }
    );
    assert!(
        matches!(constants.resolve("numeric","constants",20).unwrap().floor_source(),ConstantDefinition::Expression{expression,source_label,..} if expression.contains("defining ridge real") && source_label=="case:epoch:safety-wall-floor-ridge-floor")
    );
    assert_eq!(
        bind_constants(&records, vec![a.clone()]).unwrap_err(),
        ConstantsError::EditionSet
    );
    assert_eq!(
        bind_constants(&records, vec![a.clone(), a.clone()]).unwrap_err(),
        ConstantsError::EditionSet
    );
    let mut invalid = b.clone();
    invalid.permitted_overrides.push("structural-floor".into());
    assert_eq!(
        bind_constants(&records, vec![a.clone(), invalid]).unwrap_err(),
        ConstantsError::Override
    );
    let mut invalid = b;
    invalid.controller_edition.clear();
    assert_eq!(
        bind_constants(&records, vec![a, invalid]).unwrap_err(),
        ConstantsError::Definition
    );
}

/// Claim: The typed rational floor source agrees with the committed constant definition, while the ridge declaration remains its named defining real rather than either displayed enclosure endpoint.
/// ´claim:declarations:floor-sources-match-declared-constants´
/// ´test:integration:constant-correspondence´
#[test]
fn constant_correspondence() {
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/datasets/org.peer-network.design.constants.json"
    ))
    .unwrap();
    let rows = data["rows"].as_array().unwrap();
    let rational = rows.iter().find(|r| r["id"] == "const.epoch.wall_floor_rational").unwrap();
    assert_eq!(rational["definition"]["expr"], "3/37");
    let ridge = rows.iter().find(|r| r["id"] == "const.epoch.wall_floor_ridge").unwrap();
    assert_eq!(ridge["definition"]["func"], "wall_floor_ridge");
    assert_ne!(Floor::RidgeImage, Floor::RationalThreeThirtySevenths);
}

/// Claim: With a declared compensation-family width law W/c, market repricing preserves the reduced-amount versus width verdict; a fixed-width family can lose it, so quantity covariance alone supplies no width or fence theorem.
/// ´claim:numerics:width-verdicts-require-the-family-law´
/// ´test:integration:family-width-premise´
#[test]
fn family_width_premise() {
    let mut numeric = context();
    let twelve = numeric.literal("12").unwrap();
    let two = numeric.literal("2").unwrap();
    let four = numeric.literal("4").unwrap();
    let amount = numeric.burn(&twelve, "burn").unwrap();
    let numeraire_amount = numeric.burn_per_action(&two, "burn").unwrap();
    let nu = numeric.numeraire("nu", &numeraire_amount).unwrap();
    let repriced = numeric.reprice(&amount, &four).unwrap();
    let old_full = numeric.standing(&twelve, "burn").unwrap();
    let full = numeric.reprice_standing(&old_full, &four).unwrap();
    assert_eq!(full.exact(), repriced.exact());
    let repriced_reduced = numeric.reduce(&full, &nu).unwrap();
    let old_reduced = numeric.reduce(&old_full, &nu).unwrap();
    let pair = |text: &str| {
        let (numerator, denominator) = text.split_once('/').unwrap_or((text, "1"));
        (numerator.parse::<u64>().unwrap(), denominator.parse::<u64>().unwrap())
    };
    let meets = |reduced: &str, width: &str| {
        let (numerator, denominator) = pair(reduced);
        let (width_numerator, width_denominator) = pair(width);
        numerator * width_denominator >= width_numerator * denominator
    };
    let declared_width_before = "4";
    let covariant_width_after = "1";
    let fixed_width_after = "4";
    assert!(meets(old_reduced.exact(), declared_width_before));
    assert!(meets(repriced_reduced.exact(), covariant_width_after));
    assert!(!meets(repriced_reduced.exact(), fixed_width_after));
}
