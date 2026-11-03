use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, PublicReference, Quantity, Removal, Role,
    StructuralBody, ValidatedHistory, validate_history,
};

pub fn named(name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: "fixture".into(),
        name: name.into(),
    }
}

pub fn resolved() -> ValidatedHistory {
    validate_history(&[], &[named("left"), named("right")]).unwrap()
}

pub fn act(sequence: u64, layout: Layout) -> CandidateAct {
    let id = ActId {
        author: "author".into(),
        sequence,
        family: "fixture".into(),
    };
    let roles: &[Role] = match layout {
        Layout::Binary => &[Role::Binary],
        Layout::Paired => &[Role::A, Role::T],
    };
    CandidateAct {
        commitments: None,
        body: StructuralBody {
            settlement: None,
            license: None,
            asserted_parents: Vec::new(),
            layout,
            quantities: vec![(
                "count".into(),
                Quantity {
                    value: 7,
                    unit: "count".into(),
                    vintage: 2,
                },
            )],
        },
        legs: roles
            .iter()
            .map(|role| CandidateLeg {
                id: EdgeId {
                    act: id.clone(),
                    role: *role,
                },
                source: named("left"),
                target: named("right"),
                removal: None,
            })
            .collect(),
        projections: pn_records::RemovableProjections {
            content: Removal::Live,
            dependency: DependencyProjection::FullEmpty,
        },
        protocol_references: vec![named("left")],
        authentication_evidence: pn_records::authentication::AuthenticationFields {
            proposal_precommitment: b"fixture-P".to_vec(),
            actor_proposal_signature: vec![1, 2, 3],
            content_edition: "fixture-content".into(),
            dependency_edition: "fixture-dependency".into(),
            verified_header: b"fixture-V".to_vec(),
            host_seal: b"fixture-seal".to_vec(),
            approval_binding: b"fixture-approval".to_vec(),
            authentication_edition: "fixture-authentication".into(),
            public_verification_material: b"fixture-public-key".to_vec(),
        },
        finalization_epoch: 5,
        authoritative_position: sequence,
        logical_time: 1,
        id,
    }
}
