use std::collections::BTreeSet;

pub fn check(words: &[u64]) {
    let case = pn_records::test_support::generate(words);
    let mut ordered: Vec<_> = case.proposals.iter().collect();
    ordered.sort_by_key(|act| (act.finalization_epoch, act.authoritative_position));
    // Every direct parent outside history puts its two acts in the same block.
    // Enumerate fixed points of this undirected relation, without computing
    // principal closures or reading the implementation's intersection graph.
    let mut remaining: BTreeSet<_> = ordered.iter().map(|act| act.id.clone()).collect();
    let mut expected = Vec::new();
    for root in &ordered {
        if !remaining.contains(&root.id) {
            continue;
        }
        let mut component = BTreeSet::from([root.id.clone()]);
        loop {
            let before = component.len();
            for act in &ordered {
                for parent in &act.body.asserted_parents {
                    if !ordered.iter().any(|candidate| &candidate.id == parent) {
                        continue;
                    }
                    if component.contains(&act.id) || component.contains(parent) {
                        component.insert(act.id.clone());
                        component.insert(parent.clone());
                    }
                }
            }
            if component.len() == before {
                break;
            }
        }
        remaining.retain(|id| !component.contains(id));
        expected.push(
            ordered
                .iter()
                .filter(|act| component.contains(&act.id))
                .map(|act| act.id.clone())
                .collect::<Vec<_>>(),
        );
    }
    let history = pn_records::validate_history(&case.history, &case.names).unwrap();
    let mut proposals = case.proposals;
    for presentation in 0..3 {
        match presentation {
            1 => proposals.reverse(),
            2 => {
                let mut random = pn_testkit::Seeded::new(31);
                proposals.sort_by_key(|_| random.next_u64());
            }
            _ => {}
        }
        let records = pn_records::validate_record(&proposals, &history, &[]).unwrap();
        let input = pn_records::assemble_boundary_inputs(&records, case.boundary).unwrap();
        let (_, actual) = pn_graph::partition_dependencies(&input).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.iter().map(Vec::len).sum::<usize>(), proposals.len());
    }
}
