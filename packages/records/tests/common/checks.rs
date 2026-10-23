//! Shared public-surface predicates; included by both test consumers.
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
        assert_eq!(boundary.acts().len(), union.len());
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
