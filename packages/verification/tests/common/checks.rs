//! Outer consumer oracle and cause table, independent of the records predicates.
use pn_records::test_support::{Scenario, corrupt, generate};
use pn_records::{ActId, DependencyCause, InvalidCause, Layout, ParentCause, PublicReference, Role, ValidationError};
use std::collections::{BTreeMap, BTreeSet};

fn closure_model(case: &Scenario) -> BTreeMap<ActId, BTreeSet<ActId>> {
    let mut relation: BTreeMap<_, _> = case
        .proposals
        .iter()
        .map(|act| (act.id.clone(), BTreeSet::from([act.id.clone()])))
        .collect();
    loop {
        let previous = relation.clone();
        for act in &case.proposals {
            for parent in &act.body.asserted_parents {
                if let Some(ancestors) = previous.get(parent) {
                    relation.get_mut(&act.id).unwrap().extend(ancestors.iter().cloned());
                }
            }
        }
        if previous == relation {
            return relation;
        }
    }
}

fn orders(case: &Scenario, seed: u64) -> Vec<Scenario> {
    let mut reversed = case.clone();
    reversed.history.reverse();
    reversed.proposals.reverse();
    let mut shuffled = case.clone();
    let mut rng = pn_testkit::Seeded::new(seed);
    for acts in [&mut shuffled.history, &mut shuffled.proposals] {
        for index in (1..acts.len()).rev() {
            let other = usize::try_from(rng.next_u64() % u64::try_from(index + 1).unwrap()).unwrap();
            acts.swap(index, other);
        }
    }
    vec![case.clone(), reversed, shuffled]
}

pub fn closures(words: &[u64]) {
    let case = generate(words);
    let expected = closure_model(&case);
    let identities: BTreeSet<_> = case.proposals.iter().map(|act| act.id.clone()).collect();
    assert_eq!(expected.values().flatten().cloned().collect::<BTreeSet<_>>(), identities);
    for input in orders(&case, words.first().copied().unwrap_or(0)) {
        let history = pn_records::validate_history(&input.history, &input.names).unwrap();
        let records = pn_records::validate_record(&input.proposals, &history, &[]).unwrap();
        let boundary = pn_records::assemble_boundary_inputs(&records, input.boundary).unwrap();
        let actual: BTreeMap<_, BTreeSet<_>> = boundary
            .closures()
            .iter()
            .map(|row| (row.root().clone(), row.members().iter().cloned().collect()))
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(
            boundary.acts().iter().map(|act| act.id().clone()).collect::<BTreeSet<_>>(),
            identities
        );
        for act in boundary.acts() {
            let roles: BTreeSet<_> = act.legs().iter().map(|leg| leg.id().role).collect();
            assert_eq!(
                roles,
                if act.body().layout == Layout::Paired {
                    BTreeSet::from([Role::A, Role::T])
                } else {
                    BTreeSet::from([Role::Binary])
                }
            );
            assert!(act.legs().iter().all(|leg| &leg.id().act == act.id()));
        }
    }
}

fn expected_cause(case: &Scenario, mutation: &str) -> ValidationError {
    let first = &case.proposals[0];
    let last = case.proposals.last().unwrap();
    let id = last.id.clone();
    let missing = ActId {
        sequence: 9999,
        ..id.clone()
    };
    match mutation {
        "duplicate" => ValidationError::DuplicateAct(first.id.clone()),
        "history-duplicate" => ValidationError::DuplicateAct(case.history[0].id.clone()),
        "missing-leg" => ValidationError::MissingCoLeg { act: id, role: Role::T },
        "leg-removal" => ValidationError::InvalidRepresentation {
            act: id,
            cause: InvalidCause::CoLegRemoval,
        },
        "unresolved-reference" => ValidationError::UnresolvedReference(PublicReference::Act(missing)),
        "edge-only-history" => ValidationError::InvalidReference(PublicReference::Edge(case.history[0].legs[0].id.clone())),
        "cut-placement" => ValidationError::Dependency {
            act: first.id.clone(),
            dependency: None,
            cause: DependencyCause::BoundaryPlacement,
        },
        "parent-missing" => ValidationError::Parent {
            act: id,
            parent: Some(missing),
            cause: ParentCause::Missing,
        },
        "parent-late" => ValidationError::Parent {
            act: id,
            parent: Some(first.id.clone()),
            cause: ParentCause::NotEarlier,
        },
        "parent-duplicate" | "parent-unsorted" => ValidationError::Parent {
            act: id,
            parent: None,
            cause: ParentCause::NonCanonical,
        },
        "parent-self" => ValidationError::Parent {
            act: id.clone(),
            parent: Some(id),
            cause: ParentCause::SelfParent,
        },
        "parent-bound" => ValidationError::Parent {
            act: id,
            parent: None,
            cause: ParentCause::TooMany,
        },
        "dependency-missing" => ValidationError::Dependency {
            act: id,
            dependency: Some(missing),
            cause: DependencyCause::Missing,
        },
        "dependency-late" => ValidationError::Dependency {
            act: id,
            dependency: Some(first.id.clone()),
            cause: DependencyCause::NotEarlier,
        },
        "dependency-duplicate" | "dependency-unsorted" => ValidationError::Dependency {
            act: id,
            dependency: None,
            cause: DependencyCause::NonCanonical,
        },
        "dependency-self" => ValidationError::Dependency {
            act: id.clone(),
            dependency: Some(id),
            cause: DependencyCause::SelfDependency,
        },
        "dependency-bound" => ValidationError::Dependency {
            act: id,
            dependency: None,
            cause: DependencyCause::TooMany,
        },
        _ => panic!("unregistered outer cause: {mutation}"),
    }
}

fn outcome(case: &Scenario) -> Result<(), ValidationError> {
    let history = pn_records::validate_history(&case.history, &case.names)?;
    let records = pn_records::validate_record(&case.proposals, &history, &[])?;
    pn_records::assemble_boundary_inputs(&records, case.boundary).map(|_| ())
}

pub fn refusal(words: &[u64], mutation: &str) {
    let mut case = generate(words);
    assert_eq!(outcome(&case), Ok(()));
    let expected = expected_cause(&case, mutation);
    // The generator supplies the mutation, never the outer tier's answer.
    assert!(corrupt(&mut case, mutation).is_some());
    for input in orders(&case, words.first().copied().unwrap_or(0)) {
        assert_eq!(outcome(&input), Err(expected.clone()), "{mutation}");
    }
}

pub fn numeric(words: &[u64]) {
    use pn_records::numerics::{
        ActionCount, ComparisonLimits, ExactLimits, Floor, FloorComparison, NumericContext, NumericError,
    };
    let input = pn_records::test_support::numeric_input(words);
    let rational = |text: &str| {
        let (numerator, denominator) = text.split_once('/').unwrap_or((text, "1"));
        (numerator.parse::<u128>().unwrap(), denominator.parse::<u128>().unwrap())
    };
    let burn = u128::from(input.burn);
    let numeraire = u128::from(input.numeraire);
    let factor = u128::from(input.factor);
    let mut context = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
    let source = context.literal(&input.burn.to_string()).unwrap();
    let amount = context.burn(&source, "burn").unwrap();
    let full = context.standing(&source, "burn").unwrap();
    let source_n = context.literal(&input.numeraire.to_string()).unwrap();
    let n_amount = context.burn(&source_n, "burn").unwrap();
    let nu = context.numeraire("nu", &n_amount).unwrap();
    let original = context.reduce(&full, &nu).unwrap();
    let (p, q) = rational(original.exact());
    assert_eq!(p * numeraire, burn * q);
    let factor_literal = context.literal(&input.factor.to_string()).unwrap();
    let (co_amount, co_nu) = context.recoin(&amount, &nu, &factor_literal, "new").unwrap();
    let (p, q) = rational(co_amount.exact());
    assert_eq!(p, burn * factor * q);
    let (p, q) = rational(co_nu.amount().exact());
    assert_eq!(p, numeraire * factor * q);
    let co_literal = context.literal(co_amount.exact()).unwrap();
    let co_full = context.standing(&co_literal, "new").unwrap();
    let co = context.reduce(&co_full, &co_nu).unwrap();
    let (p, q) = rational(co.exact());
    assert_eq!(p * numeraire, burn * q);
    let repriced = context.reprice(&amount, &factor_literal).unwrap();
    let (p, q) = rational(repriced.exact());
    assert_eq!(p * factor, burn * q);
    let rp = context.literal(repriced.exact()).unwrap();
    let rp_full = context.standing(&rp, "burn").unwrap();
    let rp_reduced = context.reduce(&rp_full, &nu).unwrap();
    let (p, q) = rational(rp_reduced.exact());
    assert_eq!(p * numeraire * factor, burn * q);
    if burn > 0 && factor > 1 {
        assert_ne!(rp_reduced.exact(), original.exact());
    }
    let two = context.literal("2").unwrap();
    let wall = context.computed(&two).unwrap();
    let price = context.charged_price(&wall, &nu, Floor::RationalThreeThirtySevenths).unwrap();
    let vintage = context.consummate(&price, ActionCount(input.actions), 7).unwrap();
    let (p, q) = rational(vintage.charged().exact());
    assert_eq!(p, 2 * numeraire * u128::from(input.actions) * q);
    let zero = context.literal("0").unwrap();
    let quarter = context.literal("1/4").unwrap();
    let unit_cost = context.unit_cost(&quarter, "USD", "burn", "shared-terms").unwrap();
    let projected_cost = context.apply_cost(&unit_cost, &amount).unwrap();
    let (p, q) = rational(projected_cost.exact());
    assert_eq!(4 * p, burn * q);
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
