use std::collections::{BTreeMap, BTreeSet};

use pn_records::{ActId, CandidateAct, test_support::Scenario};

fn oracle(acts: &[CandidateAct]) -> Vec<Vec<ActId>> {
    let mut ordered: Vec<_> = acts.iter().collect();
    ordered.sort_by_key(|act| (act.finalization_epoch, act.authoritative_position));
    // Independently enumerate each root's ancestors, then repeatedly merge
    // intersecting sets. No backend component algorithm supplies expectations.
    let mut closures = Vec::<BTreeSet<ActId>>::new();
    for act in &ordered {
        let mut seen = BTreeSet::new();
        let mut pending = vec![act.id.clone()];
        while let Some(id) = pending.pop() {
            if let Some(parent) = ordered.iter().find(|candidate| candidate.id == id)
                && seen.insert(id)
            {
                pending.extend(parent.body.asserted_parents.iter().cloned());
            }
        }
        let mut index = 0;
        while index < closures.len() {
            if seen.is_disjoint(&closures[index]) {
                index += 1;
            } else {
                seen.extend(closures.remove(index));
                index = 0;
            }
        }
        closures.push(seen);
    }
    let mut blocks: Vec<Vec<_>> = closures
        .iter()
        .map(|members| {
            ordered
                .iter()
                .filter(|act| members.contains(&act.id))
                .map(|act| act.id.clone())
                .collect()
        })
        .collect();
    blocks.sort_by_key(|block| ordered.iter().position(|act| block.first() == Some(&act.id)));
    blocks
}

pub fn check(case: &Scenario) {
    let expected = oracle(&case.proposals);
    let history = pn_records::validate_history(&case.history, &case.names).unwrap();
    let mut presentations = vec![case.proposals.clone()];
    let mut reversed = case.proposals.clone();
    reversed.reverse();
    presentations.push(reversed);
    let mut shuffled = case.proposals.clone();
    let mut random = pn_testkit::Seeded::new(17);
    shuffled.sort_by_key(|_| random.next_u64());
    presentations.push(shuffled);
    let mut baseline = None;
    for acts in presentations {
        let records = pn_records::validate_record(&acts, &history, &[]).unwrap();
        let input = pn_records::assemble_boundary_inputs(&records, case.boundary).unwrap();
        let (graph, blocks) = pn_graph::partition_dependencies(&input).unwrap();
        assert_eq!(blocks, expected);
        assert_eq!(graph.node_count(), acts.len());
        let roots: Vec<_> = graph.node_weights().cloned().collect();
        assert_eq!(roots, input.acts().iter().map(|act| act.id().clone()).collect::<Vec<_>>());
        let closures: BTreeMap<_, BTreeSet<_>> = input
            .closures()
            .iter()
            .map(|closure| (closure.root(), closure.members().iter().cloned().collect()))
            .collect();
        let mut edges = Vec::new();
        for (left, root) in roots.iter().enumerate() {
            for (right, other) in roots.iter().enumerate().skip(left + 1) {
                if let Some(shared) = closures[root].iter().filter(|id| closures[other].contains(*id)).min() {
                    edges.push((left, right, shared.clone()));
                }
            }
        }
        let actual: Vec<_> = graph
            .raw_edges()
            .iter()
            .map(|edge| (edge.source().index(), edge.target().index(), edge.weight.clone()))
            .collect();
        assert_eq!(actual, edges);
        let signature = (roots, actual, blocks);
        if let Some(previous) = &baseline {
            assert_eq!(&signature, previous);
        }
        baseline = Some(signature);
        for act in input.acts() {
            let expected_legs = match act.body().layout {
                pn_records::Layout::Binary => 1,
                pn_records::Layout::Paired => 2,
            };
            assert_eq!(act.legs().len(), expected_legs);
            assert!(act.legs().iter().all(|leg| &leg.id().act == act.id()));
        }
    }
}
