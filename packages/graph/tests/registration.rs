use std::cell::RefCell;

use pn_graph::registration::{
    GroundedNode, OpeningKind, RegistrationError, RegistrationGraph, RegistrationVerifier, project_complete_registration,
    reconstruct_registrations, validate_registration_graph,
};
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, RemovableProjections,
    Removal, Role, StructuralBody, ValidatedAct, validate_history,
};

fn named(namespace: &str, author: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: author.into(),
    }
}

fn candidate(author: &str, sequence: u64, position: u64) -> CandidateAct {
    let id = ActId {
        author: author.into(),
        sequence,
        family: "Registration".into(),
    };
    CandidateAct {
        id: id.clone(),
        body: StructuralBody {
            settlement: None,
            license: None,
            asserted_parents: vec![],
            layout: Layout::Binary,
            quantities: vec![],
        },
        legs: vec![CandidateLeg {
            id: EdgeId {
                act: id,
                role: Role::Binary,
            },
            source: named("addr", author),
            target: named("prof", author),
            removal: None,
        }],
        projections: RemovableProjections {
            content: Removal::Live,
            dependency: DependencyProjection::FullEmpty,
        },
        protocol_references: vec![],
        authentication_evidence: vec![1],
        finalization_epoch: 1,
        authoritative_position: position,
        logical_time: position,
    }
}

fn names() -> Vec<PublicReference> {
    ["a", "b"]
        .into_iter()
        .flat_map(|author| [named("addr", author), named("prof", author)])
        .collect()
}

#[derive(Debug)]
struct FixtureVerifier {
    approved: Vec<CandidateAct>,
    authorized: Vec<(ActId, OpeningKind, Position)>,
    removals: RefCell<Vec<(ActId, OpeningKind, Position)>>,
}

impl RegistrationVerifier for FixtureVerifier {
    fn approval(&self, act: &ValidatedAct) -> bool {
        self.approved.iter().any(|approved| {
            &approved.id == act.id()
                && &approved.body == act.body()
                && approved.authentication_evidence == act.authentication_evidence()
                && approved.protocol_references == act.protocol_references()
                && approved.legs.len() == act.legs().len()
                && approved.legs.iter().zip(act.legs()).all(|(left, right)| {
                    &left.id == right.id() && &left.source == right.source() && &left.target == right.target()
                })
        })
    }

    fn removal(&self, act: &ValidatedAct, opening: OpeningKind, at: Position) -> bool {
        let fact = (act.id().clone(), opening, at);
        self.removals.borrow_mut().push(fact.clone());
        self.authorized.contains(&fact)
    }
}

fn verifier(acts: &[CandidateAct]) -> FixtureVerifier {
    FixtureVerifier {
        approved: acts.to_vec(),
        authorized: vec![],
        removals: RefCell::new(vec![]),
    }
}

/// Claim: Registration-only projection requires the complete binary act, the author's addr-to-prof pair, fixed-parameter carriage and declared verifier approval; another family, wrong incidence, undefined protocol references, changed approved content or unauthorized removal cannot publish a projection, and records refuse a missing leg first. Protocol references refuse at incidence before approval; changed authentication evidence remains an approval refusal. Fixture authorization does not establish cryptographic soundness or title.
/// ´claim:formation:registration-projection-requires-complete-approved-input´
/// ´test:integration:complete-projection´
#[test]
fn complete_projection() {
    let original = candidate("a", 1, 1);
    let auth = verifier(std::slice::from_ref(&original));
    let history = validate_history(std::slice::from_ref(&original), &names()).unwrap();
    let (source, target, edge) = project_complete_registration(&history.acts()[0], &auth).unwrap();
    assert_eq!(
        (source, target),
        (GroundedNode::Actor("a".into()), GroundedNode::Profile("a".into()))
    );
    assert_eq!((edge.sequence, edge.position, edge.logical_time), (1, (1, 1), 1));
    let mut changed = original.clone();
    changed.authentication_evidence = vec![2];
    let view = validate_history(&[changed], &names()).unwrap();
    assert_eq!(
        project_complete_registration(&view.acts()[0], &auth),
        Err(RegistrationError::Unapproved)
    );
    let mut changed = original.clone();
    changed.protocol_references = vec![named("addr", "b")];
    let view = validate_history(&[changed], &names()).unwrap();
    assert_eq!(
        project_complete_registration(&view.acts()[0], &auth),
        Err(RegistrationError::Incidence)
    );
    let mut changed = original.clone();
    changed.body.quantities.push((
        "coordinate".into(),
        pn_records::Quantity {
            value: 1,
            unit: "fixed".into(),
            vintage: 1,
        },
    ));
    let view = validate_history(&[changed], &names()).unwrap();
    assert_eq!(
        project_complete_registration(&view.acts()[0], &auth),
        Err(RegistrationError::Incidence)
    );
    let mut changed = original.clone();
    changed.legs[0].target = named("prof", "b");
    let view = validate_history(&[changed], &names()).unwrap();
    assert_eq!(
        project_complete_registration(&view.acts()[0], &auth),
        Err(RegistrationError::Incidence)
    );
    let mut changed = original.clone();
    changed.id.family = "Publish".into();
    changed.legs[0].id.act = changed.id.clone();
    let view = validate_history(&[changed], &names()).unwrap();
    assert_eq!(
        project_complete_registration(&view.acts()[0], &auth),
        Err(RegistrationError::UnsupportedFamily)
    );
    let mut changed = original.clone();
    changed.legs.clear();
    assert!(validate_history(&[changed], &names()).is_err());
    let mut changed = original;
    changed.projections.content = Removal::Tombstoned((2, 1));
    let view = validate_history(&[changed], &names()).unwrap();
    assert_eq!(
        project_complete_registration(&view.acts()[0], &auth),
        Err(RegistrationError::UnauthorizedRemoval)
    );
}

type NodeSnapshot = Vec<(usize, GroundedNode)>;
type EdgeSnapshot = Vec<(usize, usize, usize, pn_graph::registration::RegistrationProjection)>;

fn snapshot(graph: &RegistrationGraph) -> (NodeSnapshot, EdgeSnapshot) {
    let nodes = graph
        .node_indices()
        .map(|index| (index.index(), graph[index].clone()))
        .collect();
    let edges = graph
        .edge_indices()
        .map(|index| {
            let (source, target) = graph.edge_endpoints(index).unwrap();
            (index.index(), source.index(), target.index(), graph[index].clone())
        })
        .collect();
    (nodes, edges)
}

/// Claim: Registration history reconstructs deterministic first-occurrence Actor/Profile indices and every parallel projection across reversed presentation; authorized opening removals are checked in published order without changing structural weights, while a later unapproved act refuses the entire reconstruction and non-compliant dependency carriage remains unchanged input rather than a time verdict.
/// ´claim:formation:registration-reconstruction-retains-parallel-projections´
/// ´test:integration:reconstruction´
#[test]
fn reconstruction() {
    let mut acts = vec![candidate("b", 1, 1), candidate("a", 1, 2), candidate("b", 2, 3)];
    let mut auth = verifier(&acts);
    let history = validate_history(&acts, &names()).unwrap();
    let graph = reconstruct_registrations(&history, &auth).unwrap();
    let baseline = snapshot(&graph);
    assert_eq!(
        baseline.0,
        vec![
            (0, GroundedNode::Actor("b".into())),
            (1, GroundedNode::Profile("b".into())),
            (2, GroundedNode::Actor("a".into())),
            (3, GroundedNode::Profile("a".into()))
        ]
    );
    assert_eq!(
        baseline
            .1
            .iter()
            .map(|(index, source, target, edge)| (*index, *source, *target, edge.sequence))
            .collect::<Vec<_>>(),
        vec![(0, 0, 1, 1), (1, 2, 3, 1), (2, 0, 1, 2)]
    );
    acts.reverse();
    let reversed = validate_history(&acts, &names()).unwrap();
    assert_eq!(snapshot(&reconstruct_registrations(&reversed, &auth).unwrap()), baseline);
    acts.reverse();
    acts[0].projections.content = Removal::Tombstoned((2, 2));
    acts[1].projections.dependency = DependencyProjection::Tombstoned((2, 1));
    auth.authorized = vec![
        (acts[1].id.clone(), OpeningKind::Dependency, (2, 1)),
        (acts[0].id.clone(), OpeningKind::Content, (2, 2)),
    ];
    let removed = validate_history(&acts, &names()).unwrap();
    assert_eq!(snapshot(&reconstruct_registrations(&removed, &auth).unwrap()), baseline);
    assert_eq!(*auth.removals.borrow(), auth.authorized);
    acts[0].projections.dependency = DependencyProjection::Full(vec![acts[2].id.clone()]);
    let noncompliant = validate_history(&acts, &names()).unwrap();
    assert_eq!(noncompliant.non_compliance().len(), 1);
    assert_eq!(snapshot(&reconstruct_registrations(&noncompliant, &auth).unwrap()), baseline);
    assert_eq!(noncompliant.acts()[0].logical_time(), 1);
    auth.approved.pop();
    assert_eq!(
        reconstruct_registrations(&history, &auth).unwrap_err(),
        RegistrationError::Unapproved
    );
}

/// Claim: A diagnostic serde round trip regains only scoped Registration validity after comparison with complete history; missing, extra or changed nodes and projections refuse, and backend removal preserves unrelated live indices while the resulting partial graph fails revalidation. Serialized bytes never supply binding equality.
/// ´claim:formation:registration-cache-requires-complete-revalidation´
/// ´test:integration:revalidation´
#[test]
fn revalidation() {
    let acts = [candidate("b", 1, 1), candidate("a", 1, 2), candidate("b", 2, 3)];
    let auth = verifier(&acts);
    let history = validate_history(&acts, &names()).unwrap();
    let graph = reconstruct_registrations(&history, &auth).unwrap();
    let encoded = serde_json::to_vec(&graph).unwrap();
    let decoded: RegistrationGraph = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(validate_registration_graph(&decoded, &history, &auth), Ok(()));
    assert_eq!(snapshot(&decoded), snapshot(&graph));
    let mut changed = graph.clone();
    changed[petgraph::graph::NodeIndex::new(0)] = GroundedNode::Profile("spoof".into());
    assert_eq!(
        validate_registration_graph(&changed, &history, &auth),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    let edge = changed.edge_indices().next().unwrap();
    changed[edge].logical_time = 99;
    assert_eq!(
        validate_registration_graph(&changed, &history, &auth),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    let unrelated_node = petgraph::graph::NodeIndex::new(2);
    let unrelated_edge = petgraph::graph::EdgeIndex::new(1);
    let node_weight = changed[unrelated_node].clone();
    let edge_weight = changed[unrelated_edge].clone();
    changed.remove_node(petgraph::graph::NodeIndex::new(0));
    assert_eq!(changed[unrelated_node], node_weight);
    assert_eq!(changed[unrelated_edge], edge_weight);
    assert_eq!(
        validate_registration_graph(&changed, &history, &auth),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    changed.add_node(GroundedNode::Profile("extra".into()));
    assert_eq!(
        validate_registration_graph(&changed, &history, &auth),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    changed.add_edge(
        petgraph::graph::NodeIndex::new(0),
        petgraph::graph::NodeIndex::new(1),
        edge_weight,
    );
    assert_eq!(
        validate_registration_graph(&changed, &history, &auth),
        Err(RegistrationError::GraphMismatch)
    );
}
