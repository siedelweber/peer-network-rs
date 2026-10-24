//! Inner public-surface predicates; the outer consumer owns its own oracle.
use pn_records::test_support::{Scenario, corrupt, generate};
use pn_records::{ActId, Layout, ValidationError, assemble_boundary_inputs, validate_history, validate_record};
use std::collections::{BTreeMap, BTreeSet};

fn permute<T>(items: &mut [T], seed: u64) {
    let mut random = pn_testkit::Seeded::new(seed);
    for index in (1..items.len()).rev() {
        let bound = u64::try_from(index + 1).unwrap();
        let other = usize::try_from(random.next_u64() % bound).unwrap();
        items.swap(index, other);
    }
}

fn oracle(case: &Scenario, root: &ActId) -> BTreeSet<ActId> {
    let mut pending = vec![root.clone()];
    let mut members = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if let Some(act) = case.proposals.iter().find(|act| act.id == id)
            && members.insert(id)
        {
            pending.extend(act.body.asserted_parents.iter().cloned());
        }
    }
    members
}

pub fn closures(words: &[u64]) {
    let case = generate(words);
    co_legs(&case);
    let expected: BTreeMap<_, _> = case
        .proposals
        .iter()
        .map(|act| (act.id.clone(), oracle(&case, &act.id)))
        .collect();
    let union: BTreeSet<_> = expected.values().flatten().cloned().collect();
    assert_eq!(union, case.proposals.iter().map(|act| act.id.clone()).collect());
    let mut expected_work = 0_u64;
    for act in &case.proposals {
        expected_work +=
            1 + u64::try_from(act.body.asserted_parents.len()).unwrap() + u64::try_from(expected[&act.id].len()).unwrap();
        for parent in &act.body.asserted_parents {
            expected_work += u64::try_from(expected.get(parent).map_or(0, BTreeSet::len)).unwrap();
        }
    }
    for order in 0..3 {
        let mut input = case.clone();
        if order == 1 {
            input.history.reverse();
            input.proposals.reverse();
        }
        if order == 2 {
            let seed = words.first().copied().unwrap_or(0);
            permute(&mut input.history, seed);
            permute(&mut input.proposals, seed);
        }
        let history = validate_history(&input.history, &input.names).unwrap();
        let records = validate_record(&input.proposals, &history, &[]).unwrap();
        let boundary = assemble_boundary_inputs(&records, input.boundary).unwrap();
        let actual: BTreeMap<_, BTreeSet<_>> = boundary
            .closures()
            .iter()
            .map(|closure| (closure.root().clone(), closure.members().iter().cloned().collect()))
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(boundary.work(), Some(expected_work));
        assert_eq!(
            boundary.acts().iter().map(|act| act.id().clone()).collect::<BTreeSet<_>>(),
            union
        );
        for act in boundary.acts() {
            assert_eq!(act.legs().len(), if act.body().layout == Layout::Paired { 2 } else { 1 });
            assert!(act.legs().iter().all(|leg| &leg.id().act == act.id()));
        }
    }
    let mut extended = case.clone();
    let mut added = extended.proposals.last().unwrap().clone();
    added.id.sequence += 1;
    added.authoritative_position += 1;
    if matches!(added.projections.content, pn_records::Removal::Tombstoned(_)) {
        added.projections.content = pn_records::Removal::Tombstoned(added.authoritative_position + 1);
    }
    if matches!(added.projections.dependency, pn_records::DependencyProjection::Tombstoned(_)) {
        added.projections.dependency = pn_records::DependencyProjection::Tombstoned(added.authoritative_position + 1);
    }
    for leg in &mut added.legs {
        leg.id.act = added.id.clone();
    }
    extended.proposals.push(added);
    let history = validate_history(&extended.history, &extended.names).unwrap();
    let records = validate_record(&extended.proposals, &history, &[]).unwrap();
    assert!(assemble_boundary_inputs(&records, extended.boundary).unwrap().work().unwrap() > expected_work);
}

fn co_legs(case: &Scenario) {
    let history = validate_history(&case.history, &case.names).unwrap();
    for (index, act) in case
        .proposals
        .iter()
        .enumerate()
        .filter(|(_, act)| act.body.layout == Layout::Paired)
    {
        for (leg_index, leg) in act.legs.iter().enumerate() {
            let mut candidates = case.proposals.clone();
            candidates[index].legs.remove(leg_index);
            assert_eq!(
                validate_record(&candidates, &history, &[]).unwrap_err(),
                ValidationError::MissingCoLeg {
                    act: act.id.clone(),
                    role: leg.id.role
                }
            );
            candidates.clone_from(&case.proposals);
            candidates[index].legs[leg_index].removal = Some(pn_records::Removal::Live);
            assert_eq!(
                validate_record(&candidates, &history, &[]).unwrap_err(),
                ValidationError::InvalidRepresentation {
                    act: act.id.clone(),
                    cause: pn_records::InvalidCause::CoLegRemoval
                }
            );
        }
    }
}

fn outcome(case: &Scenario) -> Result<(), ValidationError> {
    let history = validate_history(&case.history, &case.names)?;
    let records = validate_record(&case.proposals, &history, &[])?;
    assemble_boundary_inputs(&records, case.boundary).map(|_| ())
}

pub fn refusal(words: &[u64], mutation: &str) {
    let mut case = generate(words);
    assert_eq!(outcome(&case), Ok(()));
    let expected = corrupt(&mut case, mutation).unwrap();
    assert_eq!(outcome(&case), Err(expected.clone()), "{mutation}");
    case.history.reverse();
    case.proposals.reverse();
    assert_eq!(outcome(&case), Err(expected.clone()), "reversed {mutation}");
    let seed = words.first().copied().unwrap_or(0);
    permute(&mut case.history, seed);
    permute(&mut case.proposals, seed);
    assert_eq!(outcome(&case), Err(expected), "permuted {mutation}");
}

pub fn numeric(words: &[u64]) {
    use pn_records::numerics::{
        ActionCount, ComparisonLimits, ExactLimits, Floor, FloorComparison, NumericContext, NumericError,
    };
    let input = pn_records::test_support::numeric_input(words);
    let mut context = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
    let burn_literal = context.literal(&input.burn.to_string()).unwrap();
    let numeraire_literal = context.literal(&input.numeraire.to_string()).unwrap();
    let factor_literal = context.literal(&input.factor.to_string()).unwrap();
    let amount = context.burn(&burn_literal, "burn").unwrap();
    let nu_amount = context.burn(&numeraire_literal, "burn").unwrap();
    let nu = context.numeraire("nu", &nu_amount).unwrap();
    let full = context.standing(&burn_literal, "burn").unwrap();
    let reduced = context.reduce(&full, &nu).unwrap();
    let (new_amount, new_nu) = context.recoin(&amount, &nu, &factor_literal, "new-unit").unwrap();
    let new_literal = context.literal(new_amount.exact()).unwrap();
    let new_full = context.standing(&new_literal, "new-unit").unwrap();
    assert_eq!(context.reduce(&new_full, &new_nu).unwrap().exact(), reduced.exact());
    let repriced = context.reprice(&amount, &factor_literal).unwrap();
    let expected = context.literal(&format!("{}/{}", input.burn, input.factor)).unwrap();
    assert_eq!(repriced.exact(), expected.exact());
    let repriced_literal = context.literal(repriced.exact()).unwrap();
    let repriced_full = context.standing(&repriced_literal, "burn").unwrap();
    let after = context.reduce(&repriced_full, &nu).unwrap();
    let expected = context
        .literal(&format!("{}/{}", input.burn, input.numeraire * input.factor))
        .unwrap();
    assert_eq!(after.exact(), expected.exact());
    if input.burn > 0 && input.factor > 1 {
        assert_ne!(after.exact(), reduced.exact());
    }
    let two = context.literal("2").unwrap();
    let wall = context.computed(&two).unwrap();
    let price = context.charged_price(&wall, &nu, Floor::RationalThreeThirtySevenths).unwrap();
    let vintage = context.consummate(&price, ActionCount(input.actions), 7).unwrap();
    assert_eq!(vintage.charged().exact(), (2 * input.numeraire * input.actions).to_string());
    let zero = context.literal("0").unwrap();
    let quarter = context.literal("1/4").unwrap();
    let unit_cost = context.unit_cost(&quarter, "USD", "burn", "shared-terms").unwrap();
    let expected_cost = context.literal(&format!("{}/4", input.burn)).unwrap();
    assert_eq!(
        context.apply_cost(&unit_cost, &amount).unwrap().exact(),
        expected_cost.exact()
    );
    assert_eq!(context.unit_cost(&zero, "USD", "burn", "terms"), Err(NumericError::Sign));
    let cost = context.unit_cost(&two, "USD", "other", "terms").unwrap();
    assert_eq!(context.apply_cost(&cost, &amount), Err(NumericError::Units));
    assert_eq!(
        context.compare_floor(&wall, Floor::RidgeImage),
        Ok(FloorComparison::Indecisive)
    );
    let low = context.computed(&zero).unwrap();
    assert_eq!(
        context.charged_price(&low, &nu, Floor::RationalThreeThirtySevenths),
        Err(NumericError::BelowFloor)
    );
}
