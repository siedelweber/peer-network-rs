use pn_graph::formation::{Node, Projection, project_complete_act, reconstruct, validate_formation};
use pn_graph::registration::{GroundedNode, OpeningKind, RegistrationError, RegistrationVerifier};
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, Quantity,
    RemovableProjections, Removal, Role, StructuralBody, ValidatedAct, validate_history,
};

fn named(namespace: &str, name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: name.into(),
    }
}

fn candidate(family: &str, sequence: u64) -> CandidateAct {
    let id = ActId {
        author: "a".into(),
        sequence,
        family: family.into(),
    };
    let quantities = if family == "Affinity" {
        [
            ("association.numerator", -1),
            ("association.denominator", 2),
            ("attraction.numerator", 2),
            ("attraction.denominator", 3),
        ]
        .into_iter()
        .map(|(name, value)| {
            (
                name.into(),
                Quantity {
                    value,
                    unit: "one".into(),
                    vintage: 0,
                },
            )
        })
        .collect()
    } else {
        vec![]
    };
    CandidateAct {
        id: id.clone(),
        body: StructuralBody {
            license: None,
            asserted_parents: vec![],
            layout: Layout::Binary,
            quantities,
        },
        legs: vec![CandidateLeg {
            id: EdgeId {
                act: id,
                role: Role::Binary,
            },
            source: named("addr", "a"),
            target: if family == "Registration" {
                named("prof", "a")
            } else {
                named("name", "topic")
            },
            removal: None,
        }],
        projections: RemovableProjections {
            content: Removal::Live,
            dependency: DependencyProjection::FullEmpty,
        },
        protocol_references: vec![],
        authentication_evidence: vec![1],
        finalization_epoch: 1,
        authoritative_position: sequence,
        logical_time: sequence,
    }
}

fn names() -> Vec<PublicReference> {
    vec![
        named("addr", "a"),
        named("prof", "a"),
        named("name", "topic"),
        named("addr", "b"),
    ]
}

fn publication(sequence: u64) -> CandidateAct {
    let mut input = candidate("Publish", sequence);
    input.legs[0].target = PublicReference::Minted(input.id.clone());
    input.body.quantities = [("attachment.numerator", -1), ("attachment.denominator", 2)]
        .into_iter()
        .map(|(name, value)| {
            (
                name.into(),
                Quantity {
                    value,
                    unit: "one".into(),
                    vintage: 0,
                },
            )
        })
        .collect();
    input.body.license = Some(pn_records::LicenseQualifiers {
        attribution: pn_records::LicenseDegree {
            numerator: 1,
            denominator: 2,
        },
        provenance: pn_records::LicenseDegree {
            numerator: 2,
            denominator: 3,
        },
    });
    input
}

fn malformed_publications(input: &CandidateAct) -> Vec<CandidateAct> {
    let mut cases = Vec::new();
    let mut paired = input.clone();
    paired.body.layout = Layout::Paired;
    paired.body.license = None;
    paired.legs[0].id.role = Role::A;
    let mut terminal = paired.legs[0].clone();
    terminal.id.role = Role::T;
    paired.legs.push(terminal);
    cases.push(paired);
    for target in [
        PublicReference::Act(input.id.clone()),
        named("name", "topic"),
        PublicReference::Minted(ActId {
            family: "Owner".into(),
            ..input.id.clone()
        }),
    ] {
        let mut c = input.clone();
        c.legs[0].target = target;
        c.body.license = None;
        cases.push(c);
    }
    for denominator in [0, -1] {
        let mut c = input.clone();
        c.body.quantities[1].1.value = denominator;
        cases.push(c);
    }
    let mut c = input.clone();
    c.body.quantities[0].1.value = i64::MIN;
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities[0].1.unit = "money".into();
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities[0].1.vintage = 1;
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities.pop();
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities.push((
        "extra".into(),
        Quantity {
            value: 1,
            unit: "one".into(),
            vintage: 0,
        },
    ));
    cases.push(c);
    let mut c = input.clone();
    c.legs[0].source = named("addr", "b");
    cases.push(c);
    let mut c = input.clone();
    c.protocol_references = vec![named("name", "topic")];
    cases.push(c);
    cases
}

/// Claim: Scoped Publish formation requires the author's Actor, a Content mint term, one exact signed attachment coordinate and a bounded genesis-only license pair. Genesis and ordinary targets remain distinct structural identities, dangling endpoints do not certify anchors, and wrong coordinates, constructors or protocol-reference kinds refuse before projection.
/// # Panics
/// Panics only if Publish dispatch returns another family, which correct dispatch cannot arrange.
/// ´claim:formation:publish-retains-typed-content-and-qualifiers´
/// ´test:integration:publish-projection´
#[test]
fn publish_projection() {
    let input = publication(1);
    let (source, target, edge) = project(&input).unwrap();
    assert_eq!(source, Node::Grounded(GroundedNode::Actor("a".into())));
    assert_eq!(
        target,
        Node::Content {
            author: "a".into(),
            sequence: 1
        }
    );
    let Projection::Publish(weight) = edge else {
        panic!("wrong family")
    };
    assert_eq!((weight.attachment.numerator, weight.attachment.denominator), (-1, 2));
    assert!(weight.license.is_some());
    let unsupplied = validate_history(std::slice::from_ref(&input), &[]).unwrap();
    assert_eq!(
        project_complete_act(
            &unsupplied.acts()[0],
            &Verifier {
                acts: vec![input.clone()],
                removals: false
            }
        )
        .unwrap(),
        vec![(source, target, Projection::Publish(weight))]
    );
    for denominator in 1..=8 {
        for numerator in -denominator - 1..=denominator + 1 {
            let mut changed = input.clone();
            changed.body.quantities[0].1.value = numerator;
            changed.body.quantities[1].1.value = denominator;
            assert_eq!(
                project(&changed).map(|_| ()),
                if (-denominator..=denominator).contains(&numerator) {
                    Ok(())
                } else {
                    Err(FormationFailure::Graph(RegistrationError::Incidence))
                }
            );
        }
    }
    let mut dangling = input.clone();
    let mut absent = input.id.clone();
    absent.sequence = 99;
    dangling.legs[0].target = PublicReference::Minted(absent);
    dangling.body.license = None;
    assert_eq!(
        project(&dangling).unwrap().1,
        Node::Content {
            author: "a".into(),
            sequence: 99
        }
    );
    for c in malformed_publications(&input) {
        assert_eq!(project(&c), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
}

/// Claim: Publish genesis and subsequent publication share one Content identity through mixed binary reconstruction, retain the genesis pair and parallel edges across authorized removals, and reject partial, altered, unapproved or unsupported whole histories; typed revalidation distinguishes structurally different rational carriers even when their values agree.
/// # Panics
/// Panics only if the fixture's Publish edge has another family, which correct reconstruction cannot arrange.
/// ´claim:formation:publish-shares-whole-history-revalidation´
/// ´test:integration:publish-reconstruction´
#[test]
fn publish_reconstruction() {
    let mut inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        publication(3),
        publication(4),
    ];
    inputs[3].legs[0].target = PublicReference::Minted(inputs[2].id.clone());
    inputs[3].body.license = None;
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &names()).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (4, 4));
    let endpoints: Vec<_> = graph
        .edge_indices()
        .map(|i| graph.edge_endpoints(i).map(|(a, b)| (a.index(), b.index())).unwrap())
        .collect();
    assert_eq!(endpoints, vec![(0, 1), (0, 2), (0, 3), (0, 3)]);
    assert_eq!(
        graph[petgraph::graph::NodeIndex::new(3)],
        Node::Content {
            author: "a".into(),
            sequence: 3
        }
    );
    inputs.reverse();
    assert_eq!(
        validate_formation(&graph, &validate_history(&inputs, &names()).unwrap(), &verifier),
        Ok(())
    );
    let decoded = serde_json::from_slice(&serde_json::to_vec(&graph).unwrap()).unwrap();
    assert_eq!(validate_formation(&decoded, &history, &verifier), Ok(()));
    let mut partial = graph.clone();
    partial.remove_edge(petgraph::graph::EdgeIndex::new(2));
    assert_eq!(
        partial[petgraph::graph::EdgeIndex::new(3)],
        graph[petgraph::graph::EdgeIndex::new(3)]
    );
    assert_eq!(
        validate_formation(&partial, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    let Projection::Publish(weight) = &mut changed[petgraph::graph::EdgeIndex::new(2)] else {
        panic!("wrong family")
    };
    weight.attachment.numerator *= 2;
    weight.attachment.denominator *= 2;
    assert_eq!(
        validate_formation(&changed, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    let Projection::Publish(weight) = &mut changed[petgraph::graph::EdgeIndex::new(2)] else {
        panic!("wrong family")
    };
    weight.license = None;
    weight.attachment = pn_graph::formation::Coordinate {
        numerator: -1,
        denominator: 2,
    };
    assert_eq!(
        validate_formation(&changed, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = inputs.clone();
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &names()).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs[0].id.family = "Withdraw".into();
    inputs[0].legs[0].id.act = inputs[0].id.clone();
    let unsupported = validate_history(&inputs, &names()).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}

#[derive(Debug)]
struct Verifier {
    acts: Vec<CandidateAct>,
    removals: bool,
}
impl RegistrationVerifier for Verifier {
    fn approval(&self, act: &ValidatedAct) -> bool {
        self.acts.iter().any(|input| {
            &input.id == act.id()
                && &input.body == act.body()
                && input.authentication_evidence == act.authentication_evidence()
                && input.protocol_references == act.protocol_references()
                && input.legs.len() == act.legs().len()
                && act.legs().iter().all(|right| {
                    input
                        .legs
                        .iter()
                        .any(|left| &left.id == right.id() && &left.source == right.source() && &left.target == right.target())
                })
        })
    }
    fn removal(&self, _: &ValidatedAct, _: OpeningKind, _: Position) -> bool {
        self.removals
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FormationFailure {
    Records(pn_records::ValidationError),
    Graph(RegistrationError),
}

fn project(input: &CandidateAct) -> Result<pn_graph::formation::CompleteProjection, FormationFailure> {
    let history = validate_history(std::slice::from_ref(input), &names()).map_err(FormationFailure::Records)?;
    project_complete_act(
        &history.acts()[0],
        &Verifier {
            acts: vec![input.clone()],
            removals: false,
        },
    )
    .map_err(FormationFailure::Graph)
    .map(|mut projections| {
        assert_eq!(projections.len(), 1);
        projections.remove(0)
    })
}

/// Claim: Affinity requires the author's Actor source, an exact public Type name and both signed rational coordinates within the unit interval; malformed units, vintage, missing or extra coordinates and wrong endpoint constructors refuse before projection. A finite independent numerator/denominator grid checks the bounded carrier without claiming real-valued geometry.
/// # Panics
/// Panics only if the fixture projects to another family, which correct dispatch cannot arrange.
/// ´claim:formation:affinity-requires-typed-complete-coordinates´
/// ´test:integration:affinity-coordinates´
#[test]
fn affinity_coordinates() {
    let input = candidate("Affinity", 1);
    let (source, target, edge) = project(&input).unwrap();
    assert_eq!(source, Node::Grounded(GroundedNode::Actor("a".into())));
    assert_eq!(target, Node::Type("topic".into()));
    let Projection::Affinity(weight) = edge else {
        panic!("wrong family")
    };
    assert_eq!((weight.association.numerator, weight.association.denominator), (-1, 2));
    assert_eq!((weight.attraction.numerator, weight.attraction.denominator), (2, 3));
    for (numerator_index, denominator_index) in [(0, 1), (2, 3)] {
        for denominator in 1..=8 {
            for numerator in -denominator - 1..=denominator + 1 {
                let mut changed = input.clone();
                changed.body.quantities[numerator_index].1.value = numerator;
                changed.body.quantities[denominator_index].1.value = denominator;
                assert_eq!(
                    project(&changed).map(|_| ()),
                    if (-denominator..=denominator).contains(&numerator) {
                        Ok(())
                    } else {
                        Err(FormationFailure::Graph(RegistrationError::Incidence))
                    }
                );
            }
        }
    }
    let mut cases = Vec::new();
    for value in [0, -1] {
        let mut c = input.clone();
        c.body.quantities[1].1.value = value;
        cases.push(c);
    }
    let mut c = input.clone();
    c.body.quantities[0].1.value = i64::MIN;
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities[0].1.unit = "money".into();
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities[0].1.vintage = 1;
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities.pop();
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities.push((
        "extra".into(),
        Quantity {
            value: 0,
            unit: "one".into(),
            vintage: 0,
        },
    ));
    cases.push(c);
    let mut c = input.clone();
    c.legs[0].target = named("prof", "a");
    cases.push(c);
    let mut c = input;
    c.legs[0].source = named("addr", "b");
    cases.push(c);
    for c in cases {
        assert_eq!(project(&c), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
}

/// Claim: Mixed Registration and Affinity histories share deterministic reconstruction and authorization checks, preserve parallel acts and retained times, and refuse the entire result when any family, approval or removal is unsupported; diagnostic graph mutation and decoding require complete typed revalidation.
/// ´claim:formation:mixed-binary-history-refuses-partial-formation´
/// ´test:integration:mixed-reconstruction´
#[test]
fn mixed_reconstruction() {
    let mut inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        candidate("Affinity", 3),
    ];
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &names()).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (3, 3));
    assert_eq!(
        graph.node_weights().collect::<Vec<_>>(),
        vec![
            &Node::Grounded(GroundedNode::Actor("a".into())),
            &Node::Grounded(GroundedNode::Profile("a".into())),
            &Node::Type("topic".into())
        ]
    );
    assert_eq!(
        graph
            .edge_indices()
            .map(|i| graph.edge_endpoints(i).map(|(a, b)| (a.index(), b.index())).unwrap())
            .collect::<Vec<_>>(),
        vec![(0, 1), (0, 2), (0, 2)]
    );
    let legacy = pn_graph::registration::project_complete_registration(&history.acts()[0], &verifier).unwrap();
    assert_eq!(graph[petgraph::graph::EdgeIndex::new(0)], Projection::Registration(legacy.2));
    inputs.reverse();
    let reversed = validate_history(&inputs, &names()).unwrap();
    assert_eq!(validate_formation(&graph, &reversed, &verifier), Ok(()));
    let decoded = serde_json::from_slice(&serde_json::to_vec(&graph).unwrap()).unwrap();
    assert_eq!(validate_formation(&decoded, &history, &verifier), Ok(()));
    let mut partial = graph.clone();
    partial.remove_edge(petgraph::graph::EdgeIndex::new(1));
    assert_eq!(
        partial[petgraph::graph::EdgeIndex::new(2)],
        graph[petgraph::graph::EdgeIndex::new(2)]
    );
    assert_eq!(
        validate_formation(&partial, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    changed[petgraph::graph::NodeIndex::new(2)] = Node::Type("changed".into());
    assert_eq!(
        validate_formation(&changed, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = inputs.clone();
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &names()).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs[0].id.family = "Withdraw".into();
    inputs[0].legs[0].id.act = inputs[0].id.clone();
    let unsupported = validate_history(&inputs, &names()).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}

fn ownership(sequence: u64) -> CandidateAct {
    let mut input = candidate("Owner", sequence);
    input.legs[0].target = PublicReference::Minted(input.id.clone());
    input.body.quantities = [("attachment.numerator", -1), ("attachment.denominator", 2)]
        .into_iter()
        .map(|(name, value)| {
            (
                name.into(),
                Quantity {
                    value,
                    unit: "one".into(),
                    vintage: 0,
                },
            )
        })
        .collect();

    input
}

fn malformed_ownerships(input: &CandidateAct) -> Vec<CandidateAct> {
    let mut cases = Vec::new();
    let mut paired = input.clone();
    paired.body.layout = Layout::Paired;
    paired.legs[0].id.role = Role::A;
    let mut terminal = paired.legs[0].clone();
    terminal.id.role = Role::T;
    paired.legs.push(terminal);
    cases.push(paired);
    for target in [
        PublicReference::Act(input.id.clone()),
        named("name", "topic"),
        PublicReference::Minted(ActId {
            family: "Publish".into(),
            ..input.id.clone()
        }),
    ] {
        let mut c = input.clone();
        c.legs[0].target = target;
        cases.push(c);
    }
    for denominator in [0, -1] {
        let mut c = input.clone();
        c.body.quantities[1].1.value = denominator;
        cases.push(c);
    }
    let mut c = input.clone();
    c.body.quantities[0].1.value = i64::MIN;
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities[0].1.unit = "money".into();
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities[0].1.vintage = 1;
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities.pop();
    cases.push(c);
    let mut c = input.clone();
    c.body.quantities.push((
        "extra".into(),
        Quantity {
            value: 1,
            unit: "one".into(),
            vintage: 0,
        },
    ));
    cases.push(c);
    let mut c = input.clone();
    c.legs[0].source = named("addr", "b");
    cases.push(c);
    let mut c = input.clone();
    c.protocol_references = vec![named("name", "topic")];
    cases.push(c);
    cases
}

/// Claim: Scoped Owner formation requires the author's Actor, a Item mint term, one exact signed attachment coordinate with no license or protocol-reference qualifiers. Genesis and ordinary targets remain distinct structural identities, dangling endpoints do not certify anchors, and wrong coordinates, constructors or protocol-reference kinds refuse before projection.
/// # Panics
/// Panics only if Owner dispatch returns another family, which correct dispatch cannot arrange.
/// ´claim:formation:owner-retains-typed-item-and-qualifiers´
/// ´test:integration:owner-projection´
#[test]
fn owner_projection() {
    let input = ownership(1);
    let (source, target, edge) = project(&input).unwrap();
    assert_eq!(source, Node::Grounded(GroundedNode::Actor("a".into())));
    assert_eq!(
        target,
        Node::Item {
            author: "a".into(),
            sequence: 1
        }
    );
    let Projection::Owner(weight) = edge else {
        panic!("wrong family")
    };
    assert_eq!((weight.attachment.numerator, weight.attachment.denominator), (-1, 2));

    for denominator in 1..=8 {
        for numerator in -denominator - 1..=denominator + 1 {
            let mut changed = input.clone();
            changed.body.quantities[0].1.value = numerator;
            changed.body.quantities[1].1.value = denominator;
            assert_eq!(
                project(&changed).map(|_| ()),
                if (-denominator..=denominator).contains(&numerator) {
                    Ok(())
                } else {
                    Err(FormationFailure::Graph(RegistrationError::Incidence))
                }
            );
        }
    }
    let mut dangling = input.clone();
    let mut absent = input.id.clone();
    absent.sequence = 99;
    dangling.legs[0].target = PublicReference::Minted(absent);
    dangling.body.license = None;
    assert_eq!(
        project(&dangling).unwrap().1,
        Node::Item {
            author: "a".into(),
            sequence: 99
        }
    );
    for c in malformed_ownerships(&input) {
        assert_eq!(project(&c), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
}

/// Claim: Owner genesis and subsequent ownership share one Item identity through mixed binary reconstruction, retain parallel edges without qualifiers across authorized removals, and reject partial, altered, unapproved or unsupported whole histories; typed revalidation distinguishes structurally different rational carriers even when their values agree.
/// # Panics
/// Panics only if the fixture's Owner edge has another family, which correct reconstruction cannot arrange.
/// ´claim:formation:owner-shares-whole-history-revalidation´
/// ´test:integration:owner-reconstruction´
#[test]
fn owner_reconstruction() {
    let mut inputs = vec![candidate("Registration", 1), publication(2), ownership(3), ownership(4)];
    inputs[3].legs[0].target = PublicReference::Minted(inputs[2].id.clone());
    inputs[3].body.license = None;
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &names()).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (4, 4));
    let endpoints: Vec<_> = graph
        .edge_indices()
        .map(|i| graph.edge_endpoints(i).map(|(a, b)| (a.index(), b.index())).unwrap())
        .collect();
    assert_eq!(endpoints, vec![(0, 1), (0, 2), (0, 3), (0, 3)]);
    assert_eq!(
        graph[petgraph::graph::NodeIndex::new(3)],
        Node::Item {
            author: "a".into(),
            sequence: 3
        }
    );
    inputs.reverse();
    assert_eq!(
        validate_formation(&graph, &validate_history(&inputs, &names()).unwrap(), &verifier),
        Ok(())
    );
    let decoded = serde_json::from_slice(&serde_json::to_vec(&graph).unwrap()).unwrap();
    assert_eq!(validate_formation(&decoded, &history, &verifier), Ok(()));
    let mut partial = graph.clone();
    partial.remove_edge(petgraph::graph::EdgeIndex::new(2));
    assert_eq!(
        partial[petgraph::graph::EdgeIndex::new(3)],
        graph[petgraph::graph::EdgeIndex::new(3)]
    );
    assert_eq!(
        validate_formation(&partial, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    let Projection::Owner(weight) = &mut changed[petgraph::graph::EdgeIndex::new(2)] else {
        panic!("wrong family")
    };
    weight.attachment.numerator *= 2;
    weight.attachment.denominator *= 2;
    assert_eq!(
        validate_formation(&changed, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    let Projection::Owner(weight) = &mut changed[petgraph::graph::EdgeIndex::new(2)] else {
        panic!("wrong family")
    };
    weight.position = (2, 3);
    weight.attachment = pn_graph::formation::Coordinate {
        numerator: -1,
        denominator: 2,
    };
    assert_eq!(
        validate_formation(&changed, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = inputs.clone();
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &names()).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs[0].id.family = "Withdraw".into();
    inputs[0].legs[0].id.act = inputs[0].id.clone();
    let unsupported = validate_history(&inputs, &names()).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}

fn participation(sequence: u64, origin: u64, destination: u64) -> CandidateAct {
    let mut act = candidate("Participant", sequence);
    let chat = |sequence| {
        PublicReference::Minted(ActId {
            sequence,
            ..act.id.clone()
        })
    };
    act.body.layout = Layout::Paired;
    act.body.quantities = [
        ("interactivity.numerator", -1),
        ("interactivity.denominator", 2),
        ("responsibility.numerator", 2),
        ("responsibility.denominator", 3),
        ("continuity.numerator", 1),
        ("continuity.denominator", 2),
    ]
    .into_iter()
    .map(|(name, value)| {
        (
            name.into(),
            Quantity {
                value,
                unit: "one".into(),
                vintage: 0,
            },
        )
    })
    .collect();
    act.legs[0].id.role = Role::A;
    act.legs[0].target = chat(origin);
    act.legs.push(CandidateLeg {
        id: EdgeId {
            act: act.id.clone(),
            role: Role::T,
        },
        source: chat(origin),
        target: chat(destination),
        removal: None,
    });
    act
}

fn bundle(input: &CandidateAct) -> Result<Vec<pn_graph::formation::CompleteProjection>, FormationFailure> {
    let history = validate_history(std::slice::from_ref(input), &names()).map_err(FormationFailure::Records)?;
    project_complete_act(
        &history.acts()[0],
        &Verifier {
            acts: vec![input.clone()],
            removals: false,
        },
    )
    .map_err(FormationFailure::Graph)
}

/// Claim: Participant forms one ordered A/T bundle for found, join, found-successor and move, requiring Actor-to-Chat-to-Chat incidence, signed interactivity and responsibility and nonnegative continuity. Both projections retain one act identity, attached time and full parameter tuple; malformed coordinates or endpoints refuse the whole bundle without membership or ordering verdicts.
/// # Panics
/// Panics only if Participant dispatch returns another family, which correct dispatch cannot arrange.
/// ´claim:formation:participant-requires-complete-typed-incidence´
/// ´test:integration:participant-projection´
#[test]
fn participant_projection() {
    use pn_graph::formation::ParticipantRole;
    for (origin, destination) in [(3, 3), (1, 1), (1, 3), (1, 2)] {
        let input = participation(3, origin, destination);
        let result = bundle(&input).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, Node::Grounded(GroundedNode::Actor("a".into())));
        assert_eq!(
            result[0].1,
            Node::Chat {
                author: "a".into(),
                sequence: origin
            }
        );
        assert_eq!(result[1].0, result[0].1);
        assert_eq!(
            result[1].1,
            Node::Chat {
                author: "a".into(),
                sequence: destination
            }
        );
        let (Projection::Participant(a), Projection::Participant(t)) = (&result[0].2, &result[1].2) else {
            panic!("wrong family")
        };
        assert_eq!(a.role, ParticipantRole::A);
        assert_eq!(t.role, ParticipantRole::T);
        assert_eq!((a.sequence, a.logical_time, a.position), (3, 3, (1, 3)));
        let mut expected = a.clone();
        expected.role = ParticipantRole::T;
        assert_eq!(&expected, t);
    }
    participant_coordinates();
    participant_refusals();
    participant_constructor_refusals();
}

/// Claim: Shared reconstruction retains both Participant projections among binary families with deterministic nodes and A/T edge indices, parallel acts and one retained time per pair. Revalidation rejects a missing sibling or changed tuple, approval and removal refusals remain whole-result, and diagnostic decoding grants no validation by itself.
/// # Panics
/// Panics only if the fixture's Participant edge has another family, which correct reconstruction cannot arrange.
/// ´claim:formation:participant-shares-whole-history-revalidation´
/// ´test:integration:participant-reconstruction´
#[test]
fn participant_reconstruction() {
    let mut inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        publication(3),
        ownership(4),
        participation(5, 5, 5),
        participation(6, 5, 5),
    ];
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &names()).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (6, 8));
    let endpoints: Vec<_> = graph
        .edge_indices()
        .map(|i| graph.edge_endpoints(i).map(|(a, b)| (a.index(), b.index())).unwrap())
        .collect();
    assert_eq!(
        endpoints,
        vec![(0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (5, 5), (0, 5), (5, 5)]
    );
    inputs.reverse();
    for input in &mut inputs {
        input.legs.reverse();
    }
    let reordered = validate_history(&inputs, &names()).unwrap();
    assert_eq!(validate_formation(&graph, &reordered, &verifier), Ok(()));
    participant_cache(&graph, &history, &verifier);
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = history
        .acts()
        .iter()
        .map(|act| inputs.iter().find(|input| &input.id == act.id()).unwrap().clone())
        .collect();
    // Restore role order for the fixture verifier, which compares complete legs.
    for input in &mut verifier.acts {
        input.legs.sort_by_key(|leg| leg.id.role);
    }
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &names()).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs[0].id.family = "Withdraw".into();
    let changed_id = inputs[0].id.clone();
    for leg in &mut inputs[0].legs {
        leg.id.act = changed_id.clone();
    }
    let unsupported = validate_history(&inputs, &names()).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}

fn participant_coordinates() {
    let input = participation(3, 1, 2);
    for pair in [0, 2, 4] {
        for denominator in 1..=8 {
            for numerator in -denominator - 1..=denominator + 1 {
                let mut changed = input.clone();
                changed.body.quantities[pair].1.value = numerator;
                changed.body.quantities[pair + 1].1.value = denominator;
                let lower = if pair == 4 { 0 } else { -denominator };
                assert_eq!(
                    bundle(&changed).map(|_| ()),
                    if (lower..=denominator).contains(&numerator) {
                        Ok(())
                    } else {
                        Err(FormationFailure::Graph(RegistrationError::Incidence))
                    }
                );
            }
        }
    }
}

fn participant_refusals() {
    let input = participation(3, 1, 2);
    for index in 0..6 {
        let mut changed = input.clone();
        changed.body.quantities.remove(index);
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        let mut changed = input.clone();
        changed.body.quantities[index].1.unit = "money".into();
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        let mut changed = input.clone();
        changed.body.quantities[index].1.vintage = 1;
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    for index in [1, 3, 5] {
        for value in [0, -1] {
            let mut changed = input.clone();
            changed.body.quantities[index].1.value = value;
            assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        }
    }
    for endpoint in 0..4 {
        let mut changed = input.clone();
        let replacement = named("name", "topic");
        match endpoint {
            0 => changed.legs[0].source = replacement,
            1 => changed.legs[0].target = replacement,
            2 => changed.legs[1].source = replacement,
            _ => changed.legs[1].target = replacement,
        }
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    let mut changed = input.clone();
    changed.legs[1].source = PublicReference::Minted(ActId {
        sequence: 99,
        ..input.id.clone()
    });
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.protocol_references = vec![named("name", "topic")];
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    for role in [0, 1] {
        let mut partial = input.clone();
        let removed = partial.legs.remove(role);
        assert_eq!(
            bundle(&partial),
            Err(FormationFailure::Records(pn_records::ValidationError::MissingCoLeg {
                act: partial.id.clone(),
                role: removed.id.role,
            }))
        );
    }
}

fn participant_cache(graph: &pn_graph::formation::FormationGraph, history: &pn_records::ValidatedHistory, verifier: &Verifier) {
    let decoded = serde_json::from_slice(&serde_json::to_vec(&graph).unwrap()).unwrap();
    assert_eq!(validate_formation(&decoded, history, verifier), Ok(()));
    for index in [4, 5] {
        let mut partial = graph.clone();
        partial.remove_edge(petgraph::graph::EdgeIndex::new(index));
        assert_eq!(
            partial[petgraph::graph::EdgeIndex::new(7)],
            graph[petgraph::graph::EdgeIndex::new(7)]
        );
        assert_eq!(
            validate_formation(&partial, history, verifier),
            Err(RegistrationError::GraphMismatch)
        );
    }
    let mut changed = graph.clone();
    let Projection::Participant(weight) = &mut changed[petgraph::graph::EdgeIndex::new(5)] else {
        panic!("wrong family")
    };
    weight.logical_time += 1;
    assert_eq!(
        validate_formation(&changed, history, verifier),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    let Projection::Participant(weight) = &mut changed[petgraph::graph::EdgeIndex::new(5)] else {
        panic!("wrong family")
    };
    weight.continuity.numerator = 0;
    assert_eq!(
        validate_formation(&changed, history, verifier),
        Err(RegistrationError::GraphMismatch)
    );
}

fn participant_constructor_refusals() {
    let input = participation(3, 1, 2);
    for family in ["Owner", "Publish"] {
        let mut changed = input.clone();
        let other = PublicReference::Minted(ActId {
            family: family.into(),
            ..input.id.clone()
        });
        changed.legs[0].target = other.clone();
        changed.legs[1].source = other.clone();
        changed.legs[1].target = other;
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    let mut changed = input.clone();
    changed.legs[0].source = named("addr", "b");
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.body.layout = Layout::Binary;
    changed.legs.truncate(1);
    changed.legs[0].id.role = Role::Binary;
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input;
    changed.body.quantities.push((
        "extra".into(),
        Quantity {
            value: 1,
            unit: "one".into(),
            vintage: 0,
        },
    ));
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
}

fn review(sequence: u64, middle: PublicReference, terminal: u64) -> CandidateAct {
    let mut input = participation(sequence, 1, 2);
    input.id.family = "Review".into();
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
    }
    input.legs[0].target = middle.clone();
    input.legs[1].source = middle;
    input.legs[1].target = PublicReference::Minted(ActId {
        sequence: terminal,
        ..input.id.clone()
    });
    input.body.quantities.truncate(4);
    for (field, name) in input.body.quantities.iter_mut().zip([
        "enthusiasm.numerator",
        "enthusiasm.denominator",
        "effort.numerator",
        "effort.denominator",
    ]) {
        field.0 = name.into();
    }

    input
}

/// Claim: Review forms an ordered Actor-to-passive-to-Comment bundle for every passive constructor, retaining both signed coordinates and one act time, with no qualifiers on each leg. Genesis, ordinary and dangling terminals are representable without an anchor verdict; wrong constructors, incomplete incidence and malformed coordinates refuse the whole bundle.
/// # Panics
/// Panics only if Review dispatch returns another family, which correct dispatch cannot arrange.
/// ´claim:formation:review-requires-complete-passive-comment-incidence´
/// ´test:integration:review-projection´
#[test]
fn review_projection() {
    use pn_graph::formation::ReviewRole;
    let mut middles = vec![
        (named("prof", "a"), Node::Grounded(GroundedNode::Profile("a".into()))),
        (named("name", "topic"), Node::Type("topic".into())),
    ];
    for (family, node) in [
        (
            "Publish",
            Node::Content {
                author: "a".into(),
                sequence: 1,
            },
        ),
        (
            "Owner",
            Node::Item {
                author: "a".into(),
                sequence: 1,
            },
        ),
        (
            "Participant",
            Node::Chat {
                author: "a".into(),
                sequence: 1,
            },
        ),
        (
            "Review",
            Node::Comment {
                author: "a".into(),
                sequence: 1,
            },
        ),
        (
            "Send",
            Node::Message {
                author: "a".into(),
                sequence: 1,
            },
        ),
        (
            "Bid",
            Node::Offer {
                author: "a".into(),
                sequence: 1,
            },
        ),
    ] {
        middles.push((
            PublicReference::Minted(ActId {
                author: "a".into(),
                sequence: 1,
                family: family.into(),
            }),
            node,
        ));
    }
    for (middle, node) in middles {
        for terminal in [1, 3, 99] {
            let input = review(3, middle.clone(), terminal);
            let result = bundle(&input).unwrap();
            assert_eq!(result.len(), 2);
            assert_eq!(result[0].0, Node::Grounded(GroundedNode::Actor("a".into())));
            assert_eq!(result[0].1, node);
            assert_eq!(result[1].0, node);
            assert_eq!(
                result[1].1,
                Node::Comment {
                    author: "a".into(),
                    sequence: terminal
                }
            );
            let (Projection::Review(a), Projection::Review(t)) = (&result[0].2, &result[1].2) else {
                panic!("wrong family")
            };
            assert_eq!(a.role, ReviewRole::A);
            assert_eq!((a.sequence, a.position, a.logical_time), (3, (1, 3), 3));
            assert_eq!((a.enthusiasm.numerator, a.enthusiasm.denominator), (-1, 2));
            assert_eq!((a.effort.numerator, a.effort.denominator), (2, 3));

            let mut expected = a.clone();
            expected.role = ReviewRole::T;
            assert_eq!(t, &expected);
        }
    }
    review_refusals();
}

fn review_refusals() {
    let input = review(3, named("name", "topic"), 3);
    for pair in [0, 2] {
        for denominator in 1..=8 {
            for numerator in -denominator - 1..=denominator + 1 {
                let mut changed = input.clone();
                changed.body.quantities[pair].1.value = numerator;
                changed.body.quantities[pair + 1].1.value = denominator;
                assert_eq!(
                    bundle(&changed).map(|_| ()),
                    if (-denominator..=denominator).contains(&numerator) {
                        Ok(())
                    } else {
                        Err(FormationFailure::Graph(RegistrationError::Incidence))
                    }
                );
            }
        }
        for denominator in [0, -1] {
            let mut changed = input.clone();
            changed.body.quantities[pair + 1].1.value = denominator;
            assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        }
    }
    for index in 0..4 {
        let mut changed = input.clone();
        changed.body.quantities.remove(index);
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        let mut changed = input.clone();
        changed.body.quantities[index].1.unit = "money".into();
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        let mut changed = input.clone();
        changed.body.quantities[index].1.vintage = 1;
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    for reference in [
        named("addr", "a"),
        PublicReference::Act(input.id.clone()),
        PublicReference::Minted(ActId {
            family: "Affinity".into(),
            ..input.id.clone()
        }),
    ] {
        let mut changed = input.clone();
        changed.legs[0].target = reference.clone();
        changed.legs[1].source = reference;
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    for index in 0..2 {
        let mut changed = input.clone();
        let removed = changed.legs.remove(index);
        assert_eq!(
            bundle(&changed),
            Err(FormationFailure::Records(pn_records::ValidationError::MissingCoLeg {
                act: changed.id.clone(),
                role: removed.id.role,
            }))
        );
    }
    let mut changed = input.clone();
    changed.legs[0].source = named("addr", "b");
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.legs[1].source = named("name", "other");
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.legs[1].target = named("name", "topic");
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input;
    changed.protocol_references = vec![named("name", "topic")];
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
}

/// Claim: Review shares whole-history reconstruction with the five earlier families, retaining deterministic A/T indices and parallel ordinary acts. Typed revalidation rejects missing siblings, changed coordinates and role metadata after decoding; approval, removal and unsupported-family refusals publish no partial graph.
/// # Panics
/// Panics only if the fixture's Review edge has another family, which correct reconstruction cannot arrange.
/// ´claim:formation:review-shares-whole-history-revalidation´
/// ´test:integration:review-reconstruction´
#[test]
fn review_reconstruction() {
    let mut inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        publication(3),
        ownership(4),
        participation(5, 5, 5),
        review(6, named("name", "topic"), 6),
        review(7, named("name", "topic"), 6),
    ];
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (7, 10));
    let endpoints: Vec<_> = graph
        .edge_indices()
        .map(|i| graph.edge_endpoints(i).map(|(a, b)| (a.index(), b.index())).unwrap())
        .collect();
    assert_eq!(
        endpoints,
        vec![(0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (5, 5), (0, 2), (2, 6), (0, 2), (2, 6)]
    );
    inputs.reverse();
    for input in &mut inputs {
        input.legs.reverse();
    }
    let reordered = validate_history(&inputs, &[]).unwrap();
    assert_eq!(validate_formation(&graph, &reordered, &verifier), Ok(()));
    let bytes = serde_json::to_vec(&graph).unwrap();
    let decoded = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(validate_formation(&decoded, &history, &verifier), Ok(()));
    for removed in [6, 7] {
        let mut partial = graph.clone();
        partial.remove_edge(petgraph::graph::EdgeIndex::new(removed));
        assert_eq!(
            partial[petgraph::graph::EdgeIndex::new(9)],
            graph[petgraph::graph::EdgeIndex::new(9)]
        );
        assert_eq!(
            validate_formation(&partial, &history, &verifier),
            Err(RegistrationError::GraphMismatch)
        );
    }
    let mut changed = graph.clone();
    let Projection::Review(weight) = &mut changed[petgraph::graph::EdgeIndex::new(6)] else {
        panic!("wrong family")
    };
    weight.effort.numerator *= 2;
    weight.effort.denominator *= 2;
    assert_eq!(
        validate_formation(&changed, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    let Projection::Review(weight) = &mut changed[petgraph::graph::EdgeIndex::new(7)] else {
        panic!("wrong family")
    };
    weight.role = pn_graph::formation::ReviewRole::A;
    assert_eq!(
        validate_formation(&changed, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = inputs.clone();
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs[0].id.family = "Withdraw".into();
    let id = inputs[0].id.clone();
    for leg in &mut inputs[0].legs {
        leg.id.act = id.clone();
    }
    let unsupported = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}

/// Claim: Publish projects the exact genesis license pair at all corners and sampled interiors, preserves it across payload removal and rejects changed structural pairs during revalidation. Publish, Owner, Participant and Review reject the former license-reference encoding even when its name is supplied; non-genesis families carry no license pair.
/// # Panics
/// Panics only if Publish dispatch returns another family, which correct dispatch cannot arrange.
/// ´claim:formation:publish-license-pair-survives-removal-and-revalidation´
/// ´test:integration:publish-license-pair´
#[test]
fn publish_license_pair() {
    for (a, o) in [(0, 0), (0, 6), (6, 0), (6, 6), (1, 2), (3, 5)] {
        let mut input = publication(1);
        let pair = pn_records::LicenseQualifiers {
            attribution: pn_records::LicenseDegree {
                numerator: a,
                denominator: 6,
            },
            provenance: pn_records::LicenseDegree {
                numerator: o,
                denominator: 6,
            },
        };
        input.body.license = Some(pair);
        let verifier = Verifier {
            acts: vec![input.clone()],
            removals: true,
        };
        let history = validate_history(std::slice::from_ref(&input), &[]).unwrap();
        let graph = reconstruct(&history, &verifier).unwrap();
        let Projection::Publish(weight) = &graph[petgraph::graph::EdgeIndex::new(0)] else {
            panic!("wrong family")
        };
        let expected = pn_graph::formation::LicenseQualifiers {
            attribution: pn_graph::formation::Coordinate {
                numerator: a,
                denominator: 6,
            },
            provenance: pn_graph::formation::Coordinate {
                numerator: o,
                denominator: 6,
            },
        };
        assert_eq!(weight.license, Some(expected));
        input.projections.content = Removal::Tombstoned((2, 1));
        let removed = validate_history(&[input], &[]).unwrap();
        assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
        for attribution in [true, false] {
            let mut changed = graph.clone();
            let Projection::Publish(weight) = &mut changed[petgraph::graph::EdgeIndex::new(0)] else {
                panic!("wrong family")
            };
            let pair = weight.license.as_mut().unwrap();
            let degree = if attribution {
                &mut pair.attribution
            } else {
                &mut pair.provenance
            };
            degree.numerator *= 2;
            degree.denominator *= 2;
            assert_eq!(
                validate_formation(&changed, &removed, &verifier),
                Err(RegistrationError::GraphMismatch)
            );
        }
    }
    let legacy = named("license", "fixture-terms");
    let mut supplied = names();
    supplied.push(legacy.clone());
    for mut input in [
        publication(1),
        ownership(1),
        participation(1, 1, 1),
        review(1, named("name", "topic"), 1),
    ] {
        input.protocol_references = vec![legacy.clone()];
        assert_eq!(
            validate_history(std::slice::from_ref(&input), &supplied).unwrap_err(),
            pn_records::ValidationError::InvalidRepresentation {
                act: input.id.clone(),
                cause: pn_records::InvalidCause::LicenseQualifiers
            }
        );
        input.protocol_references = vec![named("name", "topic")];
        let history = validate_history(std::slice::from_ref(&input), &supplied).unwrap();
        let verifier = Verifier {
            acts: vec![input],
            removals: true,
        };
        assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Incidence);
    }
}

fn sending(sequence: u64, origin: u64, terminal: u64) -> CandidateAct {
    let mut input = participation(sequence, origin, origin);
    input.id.family = "Send".into();
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
    }
    input.legs[1].target = PublicReference::Minted(ActId {
        sequence: terminal,
        ..input.id.clone()
    });
    input.body.quantities.truncate(2);
    input.body.quantities[0].0 = "importance.numerator".into();
    input.body.quantities[1].0 = "importance.denominator".into();
    input
}

/// Claim: Send requires complete Actor-to-Chat-to-Message incidence and one signed bounded importance coordinate, retained with one act identity and attached time on both A/T projections. Genesis and ordinary terminals are representable without an anchor verdict; malformed coordinates, constructors, co-leg incidence and protocol references refuse the complete bundle.
/// # Panics
/// Panics only if Send dispatch returns another family, which correct dispatch cannot arrange.
/// ´claim:formation:send-requires-complete-chat-message-incidence´
/// ´test:integration:send-projection´
#[test]
fn send_projection() {
    use pn_graph::formation::SendRole;
    for terminal in [1, 3, 99] {
        let input = sending(3, 1, terminal);
        let result = bundle(&input).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, Node::Grounded(GroundedNode::Actor("a".into())));
        assert_eq!(
            result[0].1,
            Node::Chat {
                author: "a".into(),
                sequence: 1
            }
        );
        assert_eq!(result[1].0, result[0].1);
        assert_eq!(
            result[1].1,
            Node::Message {
                author: "a".into(),
                sequence: terminal
            }
        );
        let (Projection::Send(a), Projection::Send(t)) = (&result[0].2, &result[1].2) else {
            panic!("wrong family")
        };
        assert_eq!(a.role, SendRole::A);
        assert_eq!((a.sequence, a.position, a.logical_time), (3, (1, 3), 3));
        assert_eq!((a.importance.numerator, a.importance.denominator), (-1, 2));
        let mut expected = a.clone();
        expected.role = SendRole::T;
        assert_eq!(t, &expected);
    }
    let input = sending(3, 1, 3);
    for denominator in 1..=8 {
        for numerator in -denominator - 1..=denominator + 1 {
            let mut changed = input.clone();
            changed.body.quantities[0].1.value = numerator;
            changed.body.quantities[1].1.value = denominator;
            assert_eq!(
                bundle(&changed).map(|_| ()),
                if (-denominator..=denominator).contains(&numerator) {
                    Ok(())
                } else {
                    Err(FormationFailure::Graph(RegistrationError::Incidence))
                }
            );
        }
    }
    send_refusals(&input);
}

fn send_refusals(input: &CandidateAct) {
    for index in 0..2 {
        let mut changed = input.clone();
        let removed = changed.legs.remove(index);
        assert_eq!(
            bundle(&changed),
            Err(FormationFailure::Records(pn_records::ValidationError::MissingCoLeg {
                act: changed.id.clone(),
                role: removed.id.role,
            }))
        );
        let mut changed = input.clone();
        changed.body.quantities.remove(index);
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        let mut changed = input.clone();
        changed.body.quantities[index].1.unit = "money".into();
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        let mut changed = input.clone();
        changed.body.quantities[index].1.vintage = 1;
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    for denominator in [0, -1] {
        let mut changed = input.clone();
        changed.body.quantities[1].1.value = denominator;
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    for family in ["Publish", "Owner", "Review", "Bid"] {
        let wrong = PublicReference::Minted(ActId {
            family: family.into(),
            ..input.id.clone()
        });
        let mut changed = input.clone();
        changed.legs[0].target = wrong.clone();
        changed.legs[1].source = wrong.clone();
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        let mut changed = input.clone();
        changed.legs[1].target = wrong;
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    let mut changed = input.clone();
    changed.legs[0].source = named("addr", "b");
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.legs[1].source = named("name", "topic");
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.legs[1].target = PublicReference::Act(input.id.clone());
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.protocol_references = vec![named("name", "topic")];
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.body.license = publication(1).body.license;
    assert_eq!(
        bundle(&changed),
        Err(FormationFailure::Records(
            pn_records::ValidationError::InvalidRepresentation {
                act: changed.id.clone(),
                cause: pn_records::InvalidCause::LicenseQualifiers,
            }
        ))
    );
}

/// Claim: Send shares whole-history reconstruction with the six earlier families, retaining deterministic A/T indices and parallel ordinary acts. Typed revalidation rejects missing siblings, changed coordinates and role metadata after decoding; approval, removal and unsupported-family refusals publish no partial graph.
/// # Panics
/// Panics only if the fixture's Send edge has another family, which correct reconstruction cannot arrange.
/// ´claim:formation:send-shares-whole-history-revalidation´
/// ´test:integration:send-reconstruction´
#[test]
fn send_reconstruction() {
    let mut inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        publication(3),
        ownership(4),
        participation(5, 5, 5),
        review(6, named("name", "topic"), 6),
        sending(7, 5, 7),
        sending(8, 5, 7),
    ];
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (8, 12));
    let endpoints: Vec<_> = graph
        .edge_indices()
        .map(|i| graph.edge_endpoints(i).map(|(a, b)| (a.index(), b.index())).unwrap())
        .collect();
    assert_eq!(
        endpoints,
        vec![
            (0, 1),
            (0, 2),
            (0, 3),
            (0, 4),
            (0, 5),
            (5, 5),
            (0, 2),
            (2, 6),
            (0, 5),
            (5, 7),
            (0, 5),
            (5, 7)
        ]
    );
    inputs.reverse();
    for input in &mut inputs {
        input.legs.reverse();
    }
    let reordered = validate_history(&inputs, &[]).unwrap();
    assert_eq!(validate_formation(&graph, &reordered, &verifier), Ok(()));
    let bytes = serde_json::to_vec(&graph).unwrap();
    let decoded = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(validate_formation(&decoded, &history, &verifier), Ok(()));
    for removed in [8, 9] {
        let mut partial = graph.clone();
        partial.remove_edge(petgraph::graph::EdgeIndex::new(removed));
        assert_eq!(
            partial[petgraph::graph::EdgeIndex::new(11)],
            graph[petgraph::graph::EdgeIndex::new(11)]
        );
        assert_eq!(
            validate_formation(&partial, &history, &verifier),
            Err(RegistrationError::GraphMismatch)
        );
    }
    let mut changed = graph.clone();
    let Projection::Send(weight) = &mut changed[petgraph::graph::EdgeIndex::new(8)] else {
        panic!("wrong family")
    };
    weight.importance.numerator *= 2;
    weight.importance.denominator *= 2;
    assert_eq!(
        validate_formation(&changed, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    let Projection::Send(weight) = &mut changed[petgraph::graph::EdgeIndex::new(9)] else {
        panic!("wrong family")
    };
    weight.role = pn_graph::formation::SendRole::A;
    assert_eq!(
        validate_formation(&changed, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = inputs.clone();
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs[0].id.family = "Withdraw".into();
    let id = inputs[0].id.clone();
    for leg in &mut inputs[0].legs {
        leg.id.act = id.clone();
    }
    let unsupported = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}

fn bidding(sequence: u64, item: u64, terminal: u64) -> CandidateAct {
    let middle = PublicReference::Minted(ActId {
        author: "a".into(),
        sequence: item,
        family: "Owner".into(),
    });
    let mut input = review(sequence, middle, terminal);
    input.id.family = "Bid".into();
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
    }
    input.legs[1].target = PublicReference::Minted(ActId {
        sequence: terminal,
        ..input.id.clone()
    });
    for (field, name) in input.body.quantities.iter_mut().zip([
        "generosity.numerator",
        "generosity.denominator",
        "urgency.numerator",
        "urgency.denominator",
    ]) {
        field.0 = name.into();
    }
    input
}

/// Claim: Bid requires complete Actor-to-Item-to-Offer incidence and its own fresh minted Offer terminal. Both projections retain signed generosity, nonnegative urgency and shared act metadata; either zero coordinate remains formable. Ordinary Offer targets, malformed bounds, incomplete incidence and qualifiers refuse the complete bundle without a settlement or title verdict.
/// # Panics
/// Panics only if Bid dispatch returns another family, which correct dispatch cannot arrange.
/// ´claim:formation:bid-requires-complete-fresh-offer-incidence´
/// ´test:integration:bid-projection´
#[test]
fn bid_projection() {
    use pn_graph::formation::BidRole;
    let input = bidding(3, 1, 3);
    let result = bundle(&input).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, Node::Grounded(GroundedNode::Actor("a".into())));
    assert_eq!(
        result[0].1,
        Node::Item {
            author: "a".into(),
            sequence: 1
        }
    );
    assert_eq!(result[1].0, result[0].1);
    assert_eq!(
        result[1].1,
        Node::Offer {
            author: "a".into(),
            sequence: 3
        }
    );
    let (Projection::Bid(a), Projection::Bid(t)) = (&result[0].2, &result[1].2) else {
        panic!("wrong family")
    };
    assert_eq!(a.role, BidRole::A);
    assert_eq!((a.sequence, a.position, a.logical_time), (3, (1, 3), 3));
    assert_eq!((a.generosity.numerator, a.generosity.denominator), (-1, 2));
    assert_eq!((a.urgency.numerator, a.urgency.denominator), (2, 3));
    let mut expected = a.clone();
    expected.role = BidRole::T;
    assert_eq!(t, &expected);
    for terminal in [1, 99] {
        assert_eq!(
            bundle(&bidding(3, 1, terminal)),
            Err(FormationFailure::Graph(RegistrationError::Incidence))
        );
    }
    for pair in [0, 2] {
        for denominator in 1..=8 {
            for numerator in -denominator - 1..=denominator + 1 {
                let mut changed = input.clone();
                changed.body.quantities[pair].1.value = numerator;
                changed.body.quantities[pair + 1].1.value = denominator;
                let lower = if pair == 0 { -denominator } else { 0 };
                assert_eq!(
                    bundle(&changed).map(|_| ()),
                    if (lower..=denominator).contains(&numerator) {
                        Ok(())
                    } else {
                        Err(FormationFailure::Graph(RegistrationError::Incidence))
                    }
                );
            }
        }
    }
    let reused = vec![bidding(1, 1, 1), bidding(3, 1, 1)];
    let history = validate_history(&reused, &[]).unwrap();
    let verifier = Verifier {
        acts: reused,
        removals: true,
    };
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Incidence);
    bid_refusals(&input);
}

fn bid_refusals(input: &CandidateAct) {
    for index in 0..4 {
        let mut changed = input.clone();
        changed.body.quantities.remove(index);
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        let mut changed = input.clone();
        changed.body.quantities[index].1.unit = "money".into();
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        let mut changed = input.clone();
        changed.body.quantities[index].1.vintage = 1;
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    for pair in [1, 3] {
        for denominator in [0, -1] {
            let mut changed = input.clone();
            changed.body.quantities[pair].1.value = denominator;
            assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        }
    }
    for index in 0..2 {
        let mut changed = input.clone();
        let removed = changed.legs.remove(index);
        assert_eq!(
            bundle(&changed),
            Err(FormationFailure::Records(pn_records::ValidationError::MissingCoLeg {
                act: changed.id.clone(),
                role: removed.id.role,
            }))
        );
    }
    for family in ["Publish", "Participant", "Review", "Send", "Bid"] {
        let wrong = PublicReference::Minted(ActId {
            family: family.into(),
            ..input.id.clone()
        });
        let mut changed = input.clone();
        changed.legs[0].target = wrong.clone();
        changed.legs[1].source = wrong;
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    let mut changed = input.clone();
    changed.legs[0].source = named("addr", "b");
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.legs[1].source = named("name", "topic");
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.legs[1].target = PublicReference::Minted(ActId {
        author: "b".into(),
        ..input.id.clone()
    });
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.protocol_references = vec![named("name", "topic")];
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.body.license = publication(1).body.license;
    assert_eq!(
        bundle(&changed),
        Err(FormationFailure::Records(
            pn_records::ValidationError::InvalidRepresentation {
                act: changed.id.clone(),
                cause: pn_records::InvalidCause::LicenseQualifiers,
            }
        ))
    );
}

/// Claim: Bid shares whole-history reconstruction with the seven earlier families, retaining deterministic A/T indices and parallel bids with distinct fresh Offers. Typed revalidation rejects missing siblings, changed coordinates and role metadata after decoding; approval, removal and unsupported-family refusals publish no partial graph.
/// # Panics
/// Panics only if the fixture's Bid edge has another family, which correct reconstruction cannot arrange.
/// ´claim:formation:bid-shares-whole-history-revalidation´
/// ´test:integration:bid-reconstruction´
#[test]
fn bid_reconstruction() {
    let mut inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        publication(3),
        ownership(4),
        participation(5, 5, 5),
        review(6, named("name", "topic"), 6),
        sending(7, 5, 7),
        bidding(8, 4, 8),
        bidding(9, 4, 9),
    ];
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (10, 14));
    let endpoints: Vec<_> = graph
        .edge_indices()
        .map(|i| graph.edge_endpoints(i).map(|(a, b)| (a.index(), b.index())).unwrap())
        .collect();
    assert_eq!(
        endpoints,
        vec![
            (0, 1),
            (0, 2),
            (0, 3),
            (0, 4),
            (0, 5),
            (5, 5),
            (0, 2),
            (2, 6),
            (0, 5),
            (5, 7),
            (0, 4),
            (4, 8),
            (0, 4),
            (4, 9)
        ]
    );
    inputs.reverse();
    for input in &mut inputs {
        input.legs.reverse();
    }
    let reordered = validate_history(&inputs, &[]).unwrap();
    assert_eq!(validate_formation(&graph, &reordered, &verifier), Ok(()));
    let bytes = serde_json::to_vec(&graph).unwrap();
    let decoded = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(validate_formation(&decoded, &history, &verifier), Ok(()));
    for removed in [10, 11] {
        let mut partial = graph.clone();
        partial.remove_edge(petgraph::graph::EdgeIndex::new(removed));
        assert_eq!(
            partial[petgraph::graph::EdgeIndex::new(13)],
            graph[petgraph::graph::EdgeIndex::new(13)]
        );
        assert_eq!(
            validate_formation(&partial, &history, &verifier),
            Err(RegistrationError::GraphMismatch)
        );
    }
    bid_cache(&graph, &history, &verifier);
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = inputs.clone();
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs[0].id.family = "Withdraw".into();
    let id = inputs[0].id.clone();
    for leg in &mut inputs[0].legs {
        leg.id.act = id.clone();
    }
    let unsupported = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}

fn bid_cache(graph: &pn_graph::formation::FormationGraph, history: &pn_records::ValidatedHistory, verifier: &Verifier) {
    let mut changed = graph.clone();
    let Projection::Bid(weight) = &mut changed[petgraph::graph::EdgeIndex::new(10)] else {
        panic!("wrong family")
    };
    weight.generosity.numerator *= 2;
    weight.generosity.denominator *= 2;
    assert_eq!(
        validate_formation(&changed, history, verifier),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    let Projection::Bid(weight) = &mut changed[petgraph::graph::EdgeIndex::new(11)] else {
        panic!("wrong family")
    };
    weight.role = pn_graph::formation::BidRole::A;
    assert_eq!(
        validate_formation(&changed, history, verifier),
        Err(RegistrationError::GraphMismatch)
    );
}

fn opinion(sequence: u64, target: PublicReference) -> CandidateAct {
    let mut input = candidate("Affinity", sequence);
    input.id.family = "Opinion".into();
    input.legs[0].id.act = input.id.clone();
    input.legs[0].target = target;
    for (field, name) in input.body.quantities.iter_mut().zip([
        "polarity.numerator",
        "polarity.denominator",
        "reaction.numerator",
        "reaction.denominator",
    ]) {
        field.0 = name.into();
    }
    input
}

/// Claim: Opinion forms one author Actor to any of the eight passive constructors, retaining signed polarity and reaction with exact structural metadata. Both coordinate bounds and malformed carriers are checked independently; active targets, wrong incidence and protocol references refuse without an anchoring or standing verdict.
/// # Panics
/// Panics only if the fixture projects to another family, which correct dispatch cannot arrange.
/// ´claim:formation:opinion-requires-complete-passive-coordinates´
/// ´test:integration:opinion-projection´
#[test]
fn opinion_projection() {
    let mut targets = vec![named("prof", "b"), named("name", "topic")];
    for family in ["Publish", "Owner", "Participant", "Review", "Send", "Bid"] {
        targets.push(PublicReference::Minted(ActId {
            author: "b".into(),
            sequence: 99,
            family: family.into(),
        }));
    }
    for target in targets {
        let input = opinion(3, target.clone());
        let (source, node, edge) = project(&input).unwrap();
        assert_eq!(source, Node::Grounded(GroundedNode::Actor("a".into())));
        let reviewed = bundle(&review(4, target, 4)).unwrap();
        assert_eq!(node, reviewed[0].1);
        let Projection::Opinion(weight) = edge else {
            panic!("wrong family")
        };
        assert_eq!((weight.polarity.numerator, weight.polarity.denominator), (-1, 2));
        assert_eq!((weight.reaction.numerator, weight.reaction.denominator), (2, 3));
        assert_eq!(
            (weight.author.as_str(), weight.sequence, weight.position, weight.logical_time),
            ("a", 3, (1, 3), 3)
        );
    }
    let input = opinion(3, named("prof", "a"));
    for (n, d) in [(0, 1), (2, 3)] {
        for denominator in 1..=8 {
            for numerator in -denominator - 1..=denominator + 1 {
                let mut changed = input.clone();
                changed.body.quantities[n].1.value = numerator;
                changed.body.quantities[d].1.value = denominator;
                assert_eq!(
                    project(&changed).map(|_| ()),
                    if (-denominator..=denominator).contains(&numerator) {
                        Ok(())
                    } else {
                        Err(FormationFailure::Graph(RegistrationError::Incidence))
                    }
                );
            }
        }
    }
    for changed in opinion_refusals(&input) {
        assert_eq!(project(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    let mut changed = input.clone();
    changed.body.license = publication(1).body.license;
    assert_eq!(
        project(&changed),
        Err(FormationFailure::Records(
            pn_records::ValidationError::InvalidRepresentation {
                act: changed.id.clone(),
                cause: pn_records::InvalidCause::LicenseQualifiers,
            }
        ))
    );
}

fn opinion_refusals(input: &CandidateAct) -> Vec<CandidateAct> {
    let mut cases = Vec::new();
    for index in 0..4 {
        let mut changed = input.clone();
        changed.body.quantities[index].1.unit = "money".into();
        cases.push(changed);
        let mut changed = input.clone();
        changed.body.quantities[index].1.vintage = 1;
        cases.push(changed);
        let mut changed = input.clone();
        changed.body.quantities.remove(index);
        cases.push(changed);
    }
    for index in [1, 3] {
        for value in [0, -1] {
            let mut changed = input.clone();
            changed.body.quantities[index].1.value = value;
            cases.push(changed);
        }
    }
    for index in [0, 2] {
        let mut changed = input.clone();
        changed.body.quantities[index].1.value = i64::MIN;
        cases.push(changed);
    }
    let mut changed = input.clone();
    changed.legs[0].source = named("addr", "other");
    cases.push(changed);
    let mut changed = input.clone();
    changed.legs[0].target = named("addr", "a");
    cases.push(changed);
    let mut changed = input.clone();
    changed.protocol_references.push(named("name", "topic"));
    cases.push(changed);
    let mut changed = input.clone();
    changed.body.layout = Layout::Paired;
    changed.legs[0].id.role = Role::A;
    let mut terminal = changed.legs[0].clone();
    terminal.id.role = Role::T;
    changed.legs.push(terminal);
    cases.push(changed);
    cases
}

/// Claim: Opinion joins the eight earlier families through shared deterministic reconstruction, retaining parallel binary edges and unrelated indices. Typed revalidation after decoding rejects altered coordinates or missing acts; approval and removal failures refuse the whole history without publishing a partial graph.
/// # Panics
/// Panics only if the fixture's Opinion edge has another family, which correct reconstruction cannot arrange.
/// ´claim:formation:opinion-shares-whole-history-revalidation´
/// ´test:integration:opinion-reconstruction´
#[test]
fn opinion_reconstruction() {
    let mut inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        publication(3),
        ownership(4),
        participation(5, 5, 5),
        review(6, named("name", "topic"), 6),
        sending(7, 5, 7),
        bidding(8, 4, 8),
        opinion(9, named("prof", "a")),
        opinion(10, named("prof", "a")),
    ];
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (9, 14));
    for index in [12, 13] {
        assert_eq!(
            graph
                .edge_endpoints(petgraph::graph::EdgeIndex::new(index))
                .map(|(a, b)| (a.index(), b.index())),
            Some((0, 1))
        );
    }
    inputs.reverse();
    let reversed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(validate_formation(&graph, &reversed, &verifier), Ok(()));
    let decoded = serde_json::from_slice(&serde_json::to_vec(&graph).unwrap()).unwrap();
    assert_eq!(validate_formation(&decoded, &history, &verifier), Ok(()));
    let mut partial = graph.clone();
    partial.remove_edge(petgraph::graph::EdgeIndex::new(12));
    assert_eq!(
        partial[petgraph::graph::EdgeIndex::new(13)],
        graph[petgraph::graph::EdgeIndex::new(13)]
    );
    assert_eq!(
        validate_formation(&partial, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    for polarity in [true, false] {
        let mut changed = graph.clone();
        let Projection::Opinion(weight) = &mut changed[petgraph::graph::EdgeIndex::new(12)] else {
            panic!("wrong family")
        };
        let coordinate = if polarity {
            &mut weight.polarity
        } else {
            &mut weight.reaction
        };
        coordinate.numerator *= 2;
        coordinate.denominator *= 2;
        assert_eq!(
            validate_formation(&changed, &history, &verifier),
            Err(RegistrationError::GraphMismatch)
        );
    }
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = inputs.clone();
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs.push(candidate("Withdraw", 11));
    let unsupported = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}

fn join_request(sequence: u64, target: PublicReference) -> CandidateAct {
    let mut input = candidate("Affinity", sequence);
    input.id.family = "Join Request".into();
    input.legs[0].id.act = input.id.clone();
    input.legs[0].target = target;
    for (field, name) in input.body.quantities.iter_mut().zip([
        "urgency.numerator",
        "urgency.denominator",
        "formality.numerator",
        "formality.denominator",
    ]) {
        field.0 = name.into();
    }
    input
}

/// Claim: Join Request requires author Actor to Chat incidence and both signed urgency and formality coordinates. Dangling Chat terms and zero or negative proposal coordinates remain formable without membership effects; other endpoint sorts, malformed carriers and qualifiers refuse the whole projection.
/// # Panics
/// Panics only if the fixture projects to another family, which correct dispatch cannot arrange.
/// ´claim:formation:join-request-requires-complete-chat-coordinates´
/// ´test:integration:join-request-projection´
#[test]
fn join_request_projection() {
    let target = PublicReference::Minted(ActId {
        author: "b".into(),
        sequence: 99,
        family: "Participant".into(),
    });
    let input = join_request(3, target);
    let (source, target, edge) = project(&input).unwrap();
    assert_eq!(source, Node::Grounded(GroundedNode::Actor("a".into())));
    assert_eq!(
        target,
        Node::Chat {
            author: "b".into(),
            sequence: 99
        }
    );
    let Projection::JoinRequest(weight) = edge else {
        panic!("wrong family")
    };
    assert_eq!((weight.urgency.numerator, weight.urgency.denominator), (-1, 2));
    assert_eq!((weight.formality.numerator, weight.formality.denominator), (2, 3));
    assert_eq!(
        (weight.author.as_str(), weight.sequence, weight.position, weight.logical_time),
        ("a", 3, (1, 3), 3)
    );
    for (n, d) in [(0, 1), (2, 3)] {
        for denominator in 1..=8 {
            for numerator in -denominator - 1..=denominator + 1 {
                let mut changed = input.clone();
                changed.body.quantities[n].1.value = numerator;
                changed.body.quantities[d].1.value = denominator;
                assert_eq!(
                    project(&changed).map(|_| ()),
                    if (-denominator..=denominator).contains(&numerator) {
                        Ok(())
                    } else {
                        Err(FormationFailure::Graph(RegistrationError::Incidence))
                    }
                );
            }
        }
    }
    for changed in opinion_refusals(&input) {
        assert_eq!(project(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    let mut changed = input.clone();
    changed.body.license = publication(1).body.license;
    assert_eq!(
        project(&changed),
        Err(FormationFailure::Records(
            pn_records::ValidationError::InvalidRepresentation {
                act: changed.id.clone(),
                cause: pn_records::InvalidCause::LicenseQualifiers,
            }
        ))
    );
    for target in [named("prof", "b"), named("name", "topic")] {
        let mut changed = input.clone();
        changed.legs[0].target = target;
        assert_eq!(project(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    for family in ["Publish", "Owner", "Review", "Send", "Bid", "Join Request"] {
        let mut changed = input.clone();
        changed.legs[0].target = PublicReference::Minted(ActId {
            author: "b".into(),
            sequence: 99,
            family: family.into(),
        });
        assert_eq!(project(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
}

/// Claim: Join Request joins the nine earlier families through shared deterministic reconstruction, retaining parallel binary edges and unrelated indices. Typed revalidation after decoding rejects altered coordinates or missing acts; approval and removal failures refuse the whole history without publishing a partial graph.
/// # Panics
/// Panics only if the fixture's Join Request edge has another family, which correct reconstruction cannot arrange.
/// ´claim:formation:join-request-shares-whole-history-revalidation´
/// ´test:integration:join-request-reconstruction´
#[test]
fn join_request_reconstruction() {
    let mut inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        publication(3),
        ownership(4),
        participation(5, 5, 5),
        review(6, named("name", "topic"), 6),
        sending(7, 5, 7),
        bidding(8, 4, 8),
        opinion(9, named("prof", "a")),
        join_request(10, PublicReference::Minted(inputs_chat())),
        join_request(11, PublicReference::Minted(inputs_chat())),
    ];
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (9, 15));
    for index in [13, 14] {
        assert_eq!(
            graph
                .edge_endpoints(petgraph::graph::EdgeIndex::new(index))
                .map(|(a, b)| (a.index(), b.index())),
            Some((0, 5))
        );
    }
    inputs.reverse();
    let reversed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(validate_formation(&graph, &reversed, &verifier), Ok(()));
    let decoded = serde_json::from_slice(&serde_json::to_vec(&graph).unwrap()).unwrap();
    assert_eq!(validate_formation(&decoded, &history, &verifier), Ok(()));
    let mut partial = graph.clone();
    partial.remove_edge(petgraph::graph::EdgeIndex::new(13));
    assert_eq!(
        partial[petgraph::graph::EdgeIndex::new(14)],
        graph[petgraph::graph::EdgeIndex::new(14)]
    );
    assert_eq!(
        validate_formation(&partial, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    for urgency in [true, false] {
        let mut changed = graph.clone();
        let Projection::JoinRequest(weight) = &mut changed[petgraph::graph::EdgeIndex::new(13)] else {
            panic!("wrong family")
        };
        let coordinate = if urgency { &mut weight.urgency } else { &mut weight.formality };
        coordinate.numerator *= 2;
        coordinate.denominator *= 2;
        assert_eq!(
            validate_formation(&changed, &history, &verifier),
            Err(RegistrationError::GraphMismatch)
        );
    }
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = inputs.clone();
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs.push(candidate("Withdraw", 12));
    let unsupported = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}

fn inputs_chat() -> ActId {
    ActId {
        author: "a".into(),
        sequence: 5,
        family: "Participant".into(),
    }
}

fn tagging(sequence: u64, middle: PublicReference) -> CandidateAct {
    let mut input = review(sequence, middle, sequence);
    input.id.family = "Tag".into();
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
    }
    input.legs[1].target = named("name", "topic");
    for (field, name) in input.body.quantities.iter_mut().zip([
        "relevance.numerator",
        "relevance.denominator",
        "confidence.numerator",
        "confidence.denominator",
    ]) {
        field.0 = name.into();
    }
    input
}

/// Claim: Tag requires complete author Actor to Taggable to Type incidence, excluding Offer while admitting the other seven passive constructors. Both projections retain signed relevance, nonnegative confidence and shared metadata; malformed bounds, wrong sorts, unmatched co-legs and qualifiers refuse the entire bundle without minting a node or assigning standing.
/// # Panics
/// Panics only if the fixture projects to another family, which correct dispatch cannot arrange.
/// ´claim:formation:tag-requires-complete-taggable-type-incidence´
/// ´test:integration:tag-projection´
#[test]
fn tag_projection() {
    let mut middles = vec![named("prof", "b"), named("name", "topic")];
    for family in ["Publish", "Owner", "Participant", "Review", "Send"] {
        middles.push(PublicReference::Minted(ActId {
            author: "b".into(),
            sequence: 99,
            family: family.into(),
        }));
    }
    for middle in middles {
        let input = tagging(3, middle.clone());
        let result = bundle(&input).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, Node::Grounded(GroundedNode::Actor("a".into())));
        assert_eq!(result[0].1, project(&opinion(4, middle)).unwrap().1);
        assert_eq!(result[0].1, result[1].0);
        assert_eq!(result[1].1, Node::Type("topic".into()));
        let (Projection::Tag(a), Projection::Tag(t)) = (&result[0].2, &result[1].2) else {
            panic!("wrong family")
        };
        assert_eq!(a.role, pn_graph::formation::TagRole::A);
        assert_eq!((a.relevance.numerator, a.relevance.denominator), (-1, 2));
        assert_eq!((a.confidence.numerator, a.confidence.denominator), (2, 3));
        assert_eq!(
            (a.author.as_str(), a.sequence, a.position, a.logical_time),
            ("a", 3, (1, 3), 3)
        );
        let mut expected = a.clone();
        expected.role = pn_graph::formation::TagRole::T;
        assert_eq!(t, &expected);
    }
    let input = tagging(3, named("prof", "a"));
    for (n, d) in [(0, 1), (2, 3)] {
        for denominator in 1..=8 {
            for numerator in -denominator - 1..=denominator + 1 {
                let mut changed = input.clone();
                changed.body.quantities[n].1.value = numerator;
                changed.body.quantities[d].1.value = denominator;
                let lower = if n == 0 { -denominator } else { 0 };
                assert_eq!(
                    bundle(&changed).map(|_| ()),
                    if (lower..=denominator).contains(&numerator) {
                        Ok(())
                    } else {
                        Err(FormationFailure::Graph(RegistrationError::Incidence))
                    }
                );
            }
        }
    }
    tag_refusals(&input);
}

fn tag_refusals(input: &CandidateAct) {
    for index in 0..4 {
        let mut changed = input.clone();
        changed.body.quantities.remove(index);
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        for (unit, vintage) in [("money", 0), ("one", 1)] {
            let mut changed = input.clone();
            changed.body.quantities[index].1.unit = unit.into();
            changed.body.quantities[index].1.vintage = vintage;
            assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        }
    }
    for index in [1, 3] {
        for value in [0, -1] {
            let mut changed = input.clone();
            changed.body.quantities[index].1.value = value;
            assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
        }
    }
    for removed in [0, 1] {
        let mut changed = input.clone();
        let removed = changed.legs.remove(removed);
        assert_eq!(
            bundle(&changed),
            Err(FormationFailure::Records(pn_records::ValidationError::MissingCoLeg {
                act: changed.id.clone(),
                role: removed.id.role,
            }))
        );
    }
    for target in [named("addr", "a"), named("prof", "a"), PublicReference::Minted(inputs_chat())] {
        let mut changed = input.clone();
        changed.legs[1].target = target;
        assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    for middle in [
        named("addr", "a"),
        PublicReference::Minted(ActId {
            author: "b".into(),
            sequence: 99,
            family: "Bid".into(),
        }),
    ] {
        assert_eq!(
            bundle(&tagging(3, middle)),
            Err(FormationFailure::Graph(RegistrationError::Incidence))
        );
    }
    let mut changed = input.clone();
    changed.legs[0].source = named("addr", "b");
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.legs[1].source = named("prof", "other");
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.protocol_references.push(named("name", "topic"));
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.body.license = publication(1).body.license;
    assert_eq!(
        bundle(&changed),
        Err(FormationFailure::Records(
            pn_records::ValidationError::InvalidRepresentation {
                act: changed.id.clone(),
                cause: pn_records::InvalidCause::LicenseQualifiers,
            }
        ))
    );
}

/// Claim: Tag joins the ten earlier families through shared deterministic reconstruction with complete A/T pairs and parallel classification acts. Revalidation rejects missing siblings, changed coordinates or roles after decoding while preserving unrelated indices; approval and removal failures refuse the whole result.
/// # Panics
/// Panics only if the fixture's Tag edge has another family, which correct reconstruction cannot arrange.
/// ´claim:formation:tag-shares-whole-history-revalidation´
/// ´test:integration:tag-reconstruction´
#[test]
fn tag_reconstruction() {
    let content = PublicReference::Minted(publication(3).id);
    let mut inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        publication(3),
        ownership(4),
        participation(5, 5, 5),
        review(6, named("name", "topic"), 6),
        sending(7, 5, 7),
        bidding(8, 4, 8),
        opinion(9, named("prof", "a")),
        join_request(10, PublicReference::Minted(inputs_chat())),
        tagging(11, content.clone()),
        tagging(12, content),
    ];
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (9, 18));
    for (index, endpoints) in [(14, (0, 3)), (15, (3, 2)), (16, (0, 3)), (17, (3, 2))] {
        assert_eq!(
            graph
                .edge_endpoints(petgraph::graph::EdgeIndex::new(index))
                .map(|(a, b)| (a.index(), b.index())),
            Some(endpoints)
        );
    }
    inputs.reverse();
    for input in &mut inputs {
        input.legs.reverse();
    }
    let reversed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(validate_formation(&graph, &reversed, &verifier), Ok(()));
    let decoded = serde_json::from_slice(&serde_json::to_vec(&graph).unwrap()).unwrap();
    assert_eq!(validate_formation(&decoded, &history, &verifier), Ok(()));
    tag_cache(&graph, &history, &verifier);
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = inputs.clone();
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs.push(candidate("Withdraw", 13));
    let unsupported = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}

fn tag_cache(graph: &pn_graph::formation::FormationGraph, history: &pn_records::ValidatedHistory, verifier: &Verifier) {
    for index in [14, 15] {
        let mut partial = graph.clone();
        partial.remove_edge(petgraph::graph::EdgeIndex::new(index));
        assert_eq!(
            partial[petgraph::graph::EdgeIndex::new(17)],
            graph[petgraph::graph::EdgeIndex::new(17)]
        );
        assert_eq!(
            validate_formation(&partial, history, verifier),
            Err(RegistrationError::GraphMismatch)
        );
    }
    for relevance in [true, false] {
        let mut changed = graph.clone();
        let Projection::Tag(weight) = &mut changed[petgraph::graph::EdgeIndex::new(14)] else {
            panic!("wrong family")
        };
        let coordinate = if relevance {
            &mut weight.relevance
        } else {
            &mut weight.confidence
        };
        coordinate.numerator *= 2;
        coordinate.denominator *= 2;
        assert_eq!(
            validate_formation(&changed, history, verifier),
            Err(RegistrationError::GraphMismatch)
        );
    }
    let mut changed = graph.clone();
    let Projection::Tag(weight) = &mut changed[petgraph::graph::EdgeIndex::new(15)] else {
        panic!("wrong family")
    };
    weight.role = pn_graph::formation::TagRole::A;
    assert_eq!(
        validate_formation(&changed, history, verifier),
        Err(RegistrationError::GraphMismatch)
    );
}

fn leaving(sequence: u64, target: PublicReference) -> CandidateAct {
    let mut input = candidate("Leave", sequence);
    input.legs[0].target = target;
    input.body.quantities.clear();
    input
}

/// Claim: Across the twelve formed families, missing act and edge protocol references refuse at records resolution, while resolved act, edge and supplied-name protocol references refuse at formation because these family blocks define none. Each refusal is typed and whole-history formation publishes no partial graph; endpoint lookup and anchoring are not inferred from this protocol-reference check.
/// ´claim:formation:formed-families-separate-protocol-resolution-from-incidence´
/// ´test:integration:formed-reference-conformance´
#[test]
fn formed_reference_conformance() {
    let inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        publication(3),
        ownership(4),
        participation(5, 5, 5),
        review(6, named("name", "topic"), 6),
        sending(7, 5, 7),
        bidding(8, 4, 8),
        opinion(9, named("prof", "a")),
        join_request(10, PublicReference::Minted(inputs_chat())),
        tagging(11, named("prof", "a")),
        leaving(12, PublicReference::Minted(inputs_chat())),
    ];
    for input in &inputs {
        let absent = ActId {
            sequence: 99,
            ..input.id.clone()
        };
        for reference in [
            PublicReference::Act(absent.clone()),
            PublicReference::Edge(EdgeId {
                act: absent,
                role: input.legs[0].id.role,
            }),
        ] {
            let mut changed = input.clone();
            changed.protocol_references = vec![reference.clone()];
            assert_eq!(
                bundle(&changed),
                Err(FormationFailure::Records(pn_records::ValidationError::UnresolvedReference(
                    reference
                )))
            );
        }
        for reference in [
            PublicReference::Act(input.id.clone()),
            PublicReference::Edge(input.legs[0].id.clone()),
            named("name", "topic"),
        ] {
            let mut changed = input.clone();
            changed.protocol_references = vec![reference];
            assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
            let mut batch = inputs.clone();
            *batch.iter_mut().find(|act| act.id == input.id).unwrap() = changed;
            let history = validate_history(&batch, &names()).unwrap();
            let verifier = Verifier {
                acts: batch,
                removals: true,
            };
            assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Incidence);
        }
    }
}

/// Claim: The six formed genesis families produce the same typed minted node that records resolves from their self-minting act. Opinion projects that term identically with or without its genesis present, without asserting an anchor; permitted payload removal preserves the genesis lookup and the complete graph.
/// ´claim:formation:minted-nodes-agree-with-records-genesis-resolution´
/// ´test:integration:minted-node-conformance´
#[test]
fn minted_node_conformance() {
    for mut genesis in [
        publication(1),
        ownership(1),
        participation(1, 1, 1),
        review(1, named("name", "topic"), 1),
        sending(1, 99, 1),
        bidding(1, 99, 1),
    ] {
        let reference = PublicReference::Minted(genesis.id.clone());
        let expected = bundle(&genesis).unwrap().last().unwrap().1.clone();
        let consumer = opinion(2, reference.clone());
        assert_eq!(project(&consumer).unwrap().1, expected);
        let unanchored = validate_history(std::slice::from_ref(&consumer), &[]).unwrap();
        let records = pn_records::validate_record(&[], &unanchored, &[]).unwrap();
        assert_eq!(
            pn_records::resolve_public_reference(&records, &reference),
            Err(pn_records::ValidationError::UnresolvedReference(reference.clone()))
        );
        let inputs = vec![genesis.clone(), consumer.clone()];
        let history = validate_history(&inputs, &[]).unwrap();
        let records = pn_records::validate_record(&[], &history, &[]).unwrap();
        assert_eq!(
            pn_records::resolve_public_reference(&records, &reference),
            Ok(pn_records::ReferenceOrigin::History)
        );
        let verifier = Verifier {
            acts: inputs,
            removals: true,
        };
        let graph = reconstruct(&history, &verifier).unwrap();
        assert_eq!(graph.node_weights().filter(|node| *node == &expected).count(), 1);
        genesis.projections.content = Removal::Tombstoned((2, 1));
        let removed = validate_history(&[genesis, consumer], &[]).unwrap();
        let records = pn_records::validate_record(&[], &removed, &[]).unwrap();
        assert_eq!(
            pn_records::resolve_public_reference(&records, &reference),
            Ok(pn_records::ReferenceOrigin::History)
        );
        assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    }
}

/// Claim: Leave forms an approved author Actor to Chat control edge with no authored parameters, protocol references or license pair. A dangling Chat and an author without participation are admitted; wrong constructors, altered incidence and extra coordinates refuse at formation, while a license pair refuses at records validation. Formation decides no membership or standing effect.
/// # Panics
/// Panics only if Leave dispatch returns another family, which correct dispatch cannot arrange.
/// ´claim:formation:leave-requires-complete-chat-control-incidence´
/// ´test:integration:leave-projection´
#[test]
fn leave_projection() {
    let input = leaving(3, PublicReference::Minted(inputs_chat()));
    let (source, target, edge) = project(&input).unwrap();
    assert_eq!(source, Node::Grounded(GroundedNode::Actor("a".into())));
    assert_eq!(
        target,
        Node::Chat {
            author: "a".into(),
            sequence: 5
        }
    );
    let Projection::Leave(weight) = edge else {
        panic!("wrong family")
    };
    assert_eq!(
        (weight.author.as_str(), weight.sequence, weight.position, weight.logical_time),
        ("a", 3, (1, 3), 3)
    );
    for target in [
        named("addr", "a"),
        named("prof", "a"),
        named("name", "topic"),
        PublicReference::Act(input.id.clone()),
    ] {
        let mut changed = input.clone();
        changed.legs[0].target = target;
        assert_eq!(project(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    for family in ["Publish", "Owner", "Review", "Send", "Bid", "Leave"] {
        let mut changed = input.clone();
        changed.legs[0].target = PublicReference::Minted(ActId {
            family: family.into(),
            ..inputs_chat()
        });
        assert_eq!(project(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    }
    let mut changed = input.clone();
    changed.legs[0].source = named("addr", "b");
    assert_eq!(project(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.protocol_references = vec![named("name", "topic")];
    assert_eq!(project(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.body.quantities = join_request(3, named("name", "topic")).body.quantities;
    assert_eq!(project(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input.clone();
    changed.body.layout = Layout::Paired;
    changed.legs[0].id.role = Role::A;
    let mut terminal = changed.legs[0].clone();
    terminal.id.role = Role::T;
    changed.legs.push(terminal);
    assert_eq!(bundle(&changed), Err(FormationFailure::Graph(RegistrationError::Incidence)));
    let mut changed = input;
    changed.body.license = publication(1).body.license;
    assert_eq!(
        project(&changed),
        Err(FormationFailure::Records(
            pn_records::ValidationError::InvalidRepresentation {
                act: changed.id.clone(),
                cause: pn_records::InvalidCause::LicenseQualifiers,
            }
        ))
    );
}

/// Claim: Leave joins the eleven earlier families through shared deterministic reconstruction, retaining parallel binary edges and unrelated indices. Typed revalidation after decoding rejects altered identity metadata or missing acts; approval and removal failures refuse the whole history without publishing a partial graph.
/// # Panics
/// Panics only if the fixture's Leave edge has another family, which correct reconstruction cannot arrange.
/// ´claim:formation:leave-shares-whole-history-revalidation´
/// ´test:integration:leave-reconstruction´
#[test]
fn leave_reconstruction() {
    let mut inputs = vec![
        candidate("Registration", 1),
        candidate("Affinity", 2),
        publication(3),
        ownership(4),
        participation(5, 5, 5),
        review(6, named("name", "topic"), 6),
        sending(7, 5, 7),
        bidding(8, 4, 8),
        opinion(9, named("prof", "a")),
        join_request(10, PublicReference::Minted(inputs_chat())),
        tagging(11, named("prof", "a")),
        leaving(12, PublicReference::Minted(inputs_chat())),
        leaving(13, PublicReference::Minted(inputs_chat())),
    ];
    let mut verifier = Verifier {
        acts: inputs.clone(),
        removals: false,
    };
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &verifier).unwrap();
    assert_eq!((graph.node_count(), graph.edge_count()), (9, 18));
    for index in [16, 17] {
        assert_eq!(
            graph
                .edge_endpoints(petgraph::graph::EdgeIndex::new(index))
                .map(|(a, b)| (a.index(), b.index())),
            Some((0, 5))
        );
    }
    inputs.reverse();
    let reversed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(validate_formation(&graph, &reversed, &verifier), Ok(()));
    let decoded = serde_json::from_slice(&serde_json::to_vec(&graph).unwrap()).unwrap();
    assert_eq!(validate_formation(&decoded, &history, &verifier), Ok(()));
    let mut partial = graph.clone();
    partial.remove_edge(petgraph::graph::EdgeIndex::new(16));
    assert_eq!(
        partial[petgraph::graph::EdgeIndex::new(17)],
        graph[petgraph::graph::EdgeIndex::new(17)]
    );
    assert_eq!(
        validate_formation(&partial, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    let mut changed = graph.clone();
    let Projection::Leave(weight) = &mut changed[petgraph::graph::EdgeIndex::new(16)] else {
        panic!("wrong family")
    };
    weight.author = "b".into();
    assert_eq!(
        validate_formation(&changed, &history, &verifier),
        Err(RegistrationError::GraphMismatch)
    );
    verifier.acts.pop();
    assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Unapproved);
    verifier.acts = inputs.clone();
    inputs[0].projections.content = Removal::Tombstoned((2, 1));
    let removed = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&removed, &verifier).unwrap_err(),
        RegistrationError::UnauthorizedRemoval
    );
    verifier.removals = true;
    assert_eq!(validate_formation(&graph, &removed, &verifier), Ok(()));
    inputs.push(candidate("Withdraw", 14));
    let unsupported = validate_history(&inputs, &[]).unwrap();
    assert_eq!(
        reconstruct(&unsupported, &verifier).unwrap_err(),
        RegistrationError::UnsupportedFamily
    );
}
