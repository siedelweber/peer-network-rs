//! Scoped binary formation observation witness (´[ROOT-inv:observe:noninterference]´).

use pn_graph::formation::{project_complete_act, reconstruct, validate_formation};
use pn_graph::registration::{OpeningKind, RegistrationVerifier};
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, RemovableProjections,
    Removal, Role, StructuralBody, ValidatedAct,
};

#[derive(Debug)]
struct FixtureApproval(bool);

impl RegistrationVerifier for FixtureApproval {
    fn approval(&self, _: &ValidatedAct) -> bool {
        self.0
    }
    fn removal(&self, _: &ValidatedAct, _: OpeningKind, _: Position) -> bool {
        self.0
    }
}

fn main() {
    let enabled = std::env::args().nth(1).as_deref() != Some("disabled");
    let guard = cli_common::observation::bootstrap(enabled, false, tracing::Level::INFO).expect("configured observation");
    let names: Vec<_> = ["addr", "name", "license"]
        .into_iter()
        .map(|namespace| PublicReference::Named {
            namespace: namespace.into(),
            name: "fixture".into(),
        })
        .collect();
    let act = affinity(&names);
    let mut publication = act.clone();
    publication.id.family = "Publish".into();
    publication.id.sequence = 2;
    publication.legs[0].id.act = publication.id.clone();
    publication.legs[0].target = PublicReference::Minted(publication.id.clone());
    publication.body.quantities.truncate(2);
    publication.body.quantities[0].0 = "attachment.numerator".into();
    publication.body.quantities[1].0 = "attachment.denominator".into();
    publication.protocol_references = vec![names[2].clone()];
    publication.authoritative_position = 2;
    publication.logical_time = 2;
    let mut ownership = publication.clone();
    ownership.id.family = "Owner".into();
    ownership.id.sequence = 3;
    ownership.legs[0].id.act = ownership.id.clone();
    ownership.legs[0].target = PublicReference::Minted(ownership.id.clone());
    ownership.authoritative_position = 3;
    ownership.logical_time = 3;
    let participant = participation(ownership.clone());
    let history = pn_records::validate_history(&[act, publication, ownership, participant], &names).unwrap();
    let auth = FixtureApproval(true);
    let projection = project_complete_act(&history.acts()[0], &auth);
    let publication = project_complete_act(&history.acts()[1], &auth);
    let ownership = project_complete_act(&history.acts()[2], &auth);
    let participant = project_complete_act(&history.acts()[3], &auth);
    let graph = reconstruct(&history, &auth).unwrap();
    let valid = validate_formation(&graph, &history, &auth);
    let denied = reconstruct(&history, &FixtureApproval(false));
    let mut partial = graph.clone();
    let edge = partial.edge_indices().next().unwrap();
    partial.remove_edge(edge);
    let invalid = validate_formation(&partial, &history, &auth);
    cli_common::emit(&serde_json::json!({
        "projection": format!("{projection:?}"), "graph": format!("{graph:?}"),
        "publication": format!("{publication:?}"),
        "ownership": format!("{ownership:?}"),
        "participant": format!("{participant:?}"),
        "valid": format!("{valid:?}"), "denied": format!("{denied:?}"), "invalid": format!("{invalid:?}")
    }))
    .unwrap();
    drop(guard);
    if std::env::var_os("PN_TEST_OBSERVATION_RENDEZVOUS").is_some() {
        let mut release = [0];
        let _ignored = std::io::Read::read_exact(&mut std::io::stdin(), &mut release);
    }
}

fn participation(mut participant: CandidateAct) -> CandidateAct {
    participant.id.family = "Participant".into();
    participant.id.sequence = 4;
    participant.body.layout = Layout::Paired;
    participant.legs[0].id.act = participant.id.clone();
    participant.legs[0].id.role = Role::A;
    participant.legs[0].target = PublicReference::Minted(participant.id.clone());
    let mut terminal = participant.legs[0].clone();
    terminal.id.role = Role::T;
    terminal.source = terminal.target.clone();
    participant.legs.push(terminal);
    participant.body.quantities = [
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
            pn_records::Quantity {
                value,
                unit: "one".into(),
                vintage: 0,
            },
        )
    })
    .collect();
    participant.authoritative_position = 4;
    participant.logical_time = 4;
    participant
}

fn affinity(names: &[PublicReference]) -> CandidateAct {
    let id = ActId {
        author: "fixture".into(),
        sequence: 1,
        family: "Affinity".into(),
    };
    CandidateAct {
        id: id.clone(),
        body: StructuralBody {
            asserted_parents: vec![],
            layout: Layout::Binary,
            quantities: [
                ("association.numerator", -1),
                ("association.denominator", 2),
                ("attraction.numerator", 2),
                ("attraction.denominator", 3),
            ]
            .into_iter()
            .map(|(name, value)| {
                (
                    name.into(),
                    pn_records::Quantity {
                        value,
                        unit: "one".into(),
                        vintage: 0,
                    },
                )
            })
            .collect(),
        },
        legs: vec![CandidateLeg {
            id: EdgeId {
                act: id,
                role: Role::Binary,
            },
            source: names[0].clone(),
            target: names[1].clone(),
            removal: None,
        }],
        projections: RemovableProjections {
            content: Removal::Live,
            dependency: DependencyProjection::FullEmpty,
        },
        protocol_references: vec![],
        authentication_evidence: vec![1],
        finalization_epoch: 1,
        authoritative_position: 1,
        logical_time: 1,
    }
}
