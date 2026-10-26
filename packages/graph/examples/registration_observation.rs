//! Scoped Registration observation witness (´[ROOT-inv:observe:noninterference]´).

use pn_graph::registration::{
    OpeningKind, RegistrationVerifier, project_complete_registration, reconstruct_registrations, validate_registration_graph,
};
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
    let id = ActId {
        author: "fixture".into(),
        sequence: 1,
        family: "Registration".into(),
    };
    let names: Vec<_> = ["addr", "prof"]
        .into_iter()
        .map(|namespace| PublicReference::Named {
            namespace: namespace.into(),
            name: "fixture".into(),
        })
        .collect();
    let act = CandidateAct {
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
    };
    let history = pn_records::validate_history(&[act], &names).unwrap();
    let auth = FixtureApproval(true);
    let projection = project_complete_registration(&history.acts()[0], &auth);
    let graph = reconstruct_registrations(&history, &auth).unwrap();
    let valid = validate_registration_graph(&graph, &history, &auth);
    let denied = reconstruct_registrations(&history, &FixtureApproval(false));
    let mut partial = graph.clone();
    let edge = partial.edge_indices().next().unwrap();
    partial.remove_edge(edge);
    let invalid = validate_registration_graph(&partial, &history, &auth);
    cli_common::emit(&serde_json::json!({
        "projection": format!("{projection:?}"), "graph": format!("{graph:?}"),
        "valid": format!("{valid:?}"), "denied": format!("{denied:?}"), "invalid": format!("{invalid:?}")
    }))
    .unwrap();
    drop(guard);
    if std::env::var_os("PN_TEST_OBSERVATION_RENDEZVOUS").is_some() {
        let mut release = [0];
        let _ignored = std::io::Read::read_exact(&mut std::io::stdin(), &mut release);
    }
}
