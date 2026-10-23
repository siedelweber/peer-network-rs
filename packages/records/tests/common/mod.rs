use pn_records::{ActId, CandidateAct, EdgeId, Layout, Projection, PublicReference, Quantity, Removal, Role, StructuralBody};
use std::collections::BTreeSet;

pub fn named(name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: "fixture".into(),
        name: name.into(),
    }
}

pub fn resolved() -> BTreeSet<PublicReference> {
    [named("left"), named("right")].into()
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
        body: StructuralBody {
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
            .map(|role| Projection {
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
            dependency: Removal::Live,
        },
        protocol_references: vec![named("left")],
        authentication_evidence: vec![1, 2, 3],
        finalization_epoch: 5,
        authoritative_position: 8,
        id,
    }
}
