mod common;

fn scenario(parents: &[&[usize]]) -> pn_records::test_support::Scenario {
    let mut case = pn_records::test_support::generate(&[1; 8]);
    case.proposals.truncate(parents.len());
    let ids: Vec<_> = case.proposals.iter().map(|act| act.id.clone()).collect();
    for (act, links) in case.proposals.iter_mut().zip(parents) {
        act.body.asserted_parents = links.iter().map(|index| ids[*index].clone()).collect();
        act.body.asserted_parents.sort();
    }
    case
}

/// Claim: Against fixed history, overlapping principal closures merge once, interleaved blocks remain separate, history parents and removable declared dependencies do not join blocks, and every published union equals the proposed whole-act set; this establishes records-level partition only, not authenticated formation or final-marker selection.
/// ´claim:membership:dependency-closures-partition-the-final-act-set´
/// ´test:integration:partition-cases´
#[test]
fn partition_cases() {
    for parents in [
        vec![],
        vec![&[][..]],
        vec![&[][..], &[0], &[0]],
        vec![&[][..], &[], &[0], &[1]],
        vec![&[][..], &[0], &[1]],
    ] {
        common::check(&scenario(&parents));
    }
    let mut case = scenario(&[&[], &[]]);
    let shared = case.history[0].id.clone();
    for act in &mut case.proposals {
        act.body.asserted_parents = vec![shared.clone()];
    }
    case.proposals[1].projections.dependency = pn_records::DependencyProjection::Full(vec![case.proposals[0].id.clone()]);
    common::check(&case);
    case.proposals[1].projections.dependency = pn_records::DependencyProjection::Tombstoned(20);
    common::check(&case);
}

/// Claim: Enumerating all 1024 backward-parent relations on five paired proposals agrees with a naive ancestor-and-set-merge oracle in original, reversed and shuffled presentations, including exact overlap witnesses and deterministic backend indices.
/// ´claim:membership:small-dags-preserve-partition-and-indices´
/// ´test:integration:exhaustive-dags´
#[test]
fn exhaustive_dags() {
    for mask in 0_u16..1024 {
        let mut case = scenario(&[&[], &[], &[], &[], &[]]);
        let ids: Vec<_> = case.proposals.iter().map(|act| act.id.clone()).collect();
        let mut bit = 0;
        for (index, act) in case.proposals.iter_mut().enumerate() {
            for id in ids.iter().take(index) {
                if mask & (1 << bit) != 0 {
                    act.body.asserted_parents.push(id.clone());
                }
                bit += 1;
            }
        }
        common::check(&case);
    }
}

/// Claim: Missing or late causal parents and a missing paired co-leg fail with exact records causes before a boundary input can reach graph partition, so invalid placement or partial acts cannot acquire partition evidence through this public path.
/// ´claim:membership:invalid-records-never-reach-partition´
/// ´test:integration:invalid-inputs´
#[test]
fn invalid_inputs() {
    use pn_records::{ParentCause, Role, ValidationError};
    let case = scenario(&[&[], &[0]]);
    let history = pn_records::validate_history(&case.history, &case.names).unwrap();
    let mut missing = case.proposals.clone();
    let mut absent = missing[0].id.clone();
    absent.sequence = 100;
    missing[1].body.asserted_parents = vec![absent.clone()];
    assert_eq!(
        pn_records::validate_record(&missing, &history, &[]).unwrap_err(),
        ValidationError::Parent {
            act: missing[1].id.clone(),
            parent: Some(absent),
            cause: ParentCause::Missing
        }
    );
    let mut late = case.proposals.clone();
    late[0].body.asserted_parents = vec![late[1].id.clone()];
    assert_eq!(
        pn_records::validate_record(&late, &history, &[]).unwrap_err(),
        ValidationError::Parent {
            act: late[0].id.clone(),
            parent: Some(late[1].id.clone()),
            cause: ParentCause::NotEarlier
        }
    );
    let mut partial = case.proposals;
    partial[0].legs.retain(|leg| leg.id.role != Role::T);
    assert_eq!(
        pn_records::validate_record(&partial, &history, &[]).unwrap_err(),
        ValidationError::MissingCoLeg {
            act: partial[0].id.clone(),
            role: Role::T
        }
    );
}
