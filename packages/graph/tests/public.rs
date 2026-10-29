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
    case.proposals[1].projections.dependency = pn_records::DependencyProjection::Tombstoned((2, 20));
    common::check(&case);
}

/// Claim: Enumerating all 1024 backward-parent relations on five paired proposals agrees with a naive ancestor-and-set-merge oracle in original, reversed and shuffled presentations, including the least shared identity on each intersection edge and deterministic backend indices.
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

/// Claim: Causal chains of 32, 128 and 256 proposals produce one block and exactly N(N-1)/2 intersection edges, each storing only the least shared act identity; records retain N(N+1)/2 closure members from which full intersections can be recovered, so graph edge-weight identity storage is quadratic rather than cubic.
/// ´claim:membership:chain-intersections-retain-quadratic-witness-storage´
/// ´test:integration:chain-storage´
#[test]
fn chain_storage() {
    for count in [32_u64, 128, 256] {
        let mut case = pn_records::test_support::generate(&[1]);
        let template = case.proposals[0].clone();
        case.proposals.clear();
        for index in 0..count {
            let mut act = template.clone();
            act.id.sequence = index + 1000;
            act.authoritative_position = index + 10;
            act.body.asserted_parents = case
                .proposals
                .last()
                .map(|previous| previous.id.clone())
                .into_iter()
                .collect();
            for leg in &mut act.legs {
                leg.id.act = act.id.clone();
            }
            case.proposals.push(act);
        }
        let history = pn_records::validate_history(&case.history, &case.names).unwrap();
        let records = pn_records::validate_record(&case.proposals, &history, &[]).unwrap();
        let input = pn_records::assemble_boundary_inputs(&records, case.boundary).unwrap();
        let (graph, blocks) = pn_graph::partition_dependencies(&input).unwrap();
        let count = usize::try_from(count).unwrap();
        assert_eq!(graph.node_count(), count);
        assert_eq!(graph.edge_count(), count * (count - 1) / 2);
        assert_eq!(
            blocks,
            vec![case.proposals.iter().map(|act| act.id.clone()).collect::<Vec<_>>()]
        );
        let witnesses: Vec<&pn_records::ActId> = graph.edge_weights().collect();
        assert_eq!(witnesses.len(), count * (count - 1) / 2);
        assert!(witnesses.iter().all(|id| **id == case.proposals[0].id));
        assert_eq!(
            input.closures().iter().map(|closure| closure.members().len()).sum::<usize>(),
            count * (count + 1) / 2
        );
    }
}
