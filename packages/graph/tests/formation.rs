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
            assert_eq!(project(&changed).is_ok(), (-denominator..=denominator).contains(&numerator));
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
        assert_eq!(project(&c), Err(RegistrationError::Incidence));
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
    inputs[0].id.family = "Opinion".into();
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

fn project(input: &CandidateAct) -> Result<pn_graph::formation::CompleteProjection, RegistrationError> {
    let history = validate_history(std::slice::from_ref(input), &names()).map_err(|_| RegistrationError::Incidence)?;
    project_complete_act(
        &history.acts()[0],
        &Verifier {
            acts: vec![input.clone()],
            removals: false,
        },
    )
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
                assert_eq!(project(&changed).is_ok(), (-denominator..=denominator).contains(&numerator));
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
        assert_eq!(project(&c), Err(RegistrationError::Incidence));
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
    inputs[0].id.family = "Opinion".into();
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
            assert_eq!(project(&changed).is_ok(), (-denominator..=denominator).contains(&numerator));
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
        assert_eq!(project(&c), Err(RegistrationError::Incidence));
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
    inputs[0].id.family = "Opinion".into();
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

fn bundle(input: &CandidateAct) -> Result<Vec<pn_graph::formation::CompleteProjection>, RegistrationError> {
    let history = validate_history(std::slice::from_ref(input), &names()).map_err(|_| RegistrationError::Incidence)?;
    project_complete_act(
        &history.acts()[0],
        &Verifier {
            acts: vec![input.clone()],
            removals: false,
        },
    )
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
    inputs[0].id.family = "Send".into();
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
                assert_eq!(bundle(&changed).is_ok(), (lower..=denominator).contains(&numerator));
            }
        }
    }
}

fn participant_refusals() {
    let input = participation(3, 1, 2);
    for index in 0..6 {
        let mut changed = input.clone();
        changed.body.quantities.remove(index);
        assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
        let mut changed = input.clone();
        changed.body.quantities[index].1.unit = "money".into();
        assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
        let mut changed = input.clone();
        changed.body.quantities[index].1.vintage = 1;
        assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    }
    for index in [1, 3, 5] {
        for value in [0, -1] {
            let mut changed = input.clone();
            changed.body.quantities[index].1.value = value;
            assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
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
        assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    }
    let mut changed = input.clone();
    changed.legs[1].source = PublicReference::Minted(ActId {
        sequence: 99,
        ..input.id.clone()
    });
    assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    let mut changed = input.clone();
    changed.protocol_references = vec![named("name", "topic")];
    assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    for role in [0, 1] {
        let mut partial = input.clone();
        partial.legs.remove(role);
        assert!(validate_history(&[partial], &names()).is_err());
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
        assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    }
    let mut changed = input.clone();
    changed.legs[0].source = named("addr", "b");
    assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    let mut changed = input.clone();
    changed.body.layout = Layout::Binary;
    changed.legs.truncate(1);
    changed.legs[0].id.role = Role::Binary;
    assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    let mut changed = input;
    changed.body.quantities.push((
        "extra".into(),
        Quantity {
            value: 1,
            unit: "one".into(),
            vintage: 0,
        },
    ));
    assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
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
                assert_eq!(bundle(&changed).is_ok(), (-denominator..=denominator).contains(&numerator));
            }
        }
        for denominator in [0, -1] {
            let mut changed = input.clone();
            changed.body.quantities[pair + 1].1.value = denominator;
            assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
        }
    }
    for index in 0..4 {
        let mut changed = input.clone();
        changed.body.quantities.remove(index);
        assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
        let mut changed = input.clone();
        changed.body.quantities[index].1.unit = "money".into();
        assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
        let mut changed = input.clone();
        changed.body.quantities[index].1.vintage = 1;
        assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
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
        assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    }
    for index in 0..2 {
        let mut changed = input.clone();
        changed.legs.remove(index);
        assert!(validate_history(&[changed], &[]).is_err());
    }
    let mut changed = input.clone();
    changed.legs[0].source = named("addr", "b");
    assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    let mut changed = input.clone();
    changed.legs[1].source = named("name", "other");
    assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    let mut changed = input.clone();
    changed.legs[1].target = named("name", "topic");
    assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
    let mut changed = input;
    changed.protocol_references = vec![named("name", "topic")];
    assert_eq!(bundle(&changed), Err(RegistrationError::Incidence));
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
    inputs[0].id.family = "Send".into();
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
        assert!(validate_history(std::slice::from_ref(&input), &supplied).is_err());
        input.protocol_references = vec![named("name", "topic")];
        let history = validate_history(std::slice::from_ref(&input), &supplied).unwrap();
        let verifier = Verifier {
            acts: vec![input],
            removals: true,
        };
        assert_eq!(reconstruct(&history, &verifier).unwrap_err(), RegistrationError::Incidence);
    }
}
