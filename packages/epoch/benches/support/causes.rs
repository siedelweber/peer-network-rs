use pn_graph::registration::{OpeningKind, RegistrationVerifier};
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, Quantity,
    RemovableProjections, Removal, Role, SettlementReferences, StructuralBody, ValidatedAct,
};
use std::collections::{BTreeMap, BTreeSet};

// Synthetic approval is equality to the complete, validated generated cause set.
// It is not a signature or settlement-authenticity measurement.
#[derive(Debug)]
pub struct Approval(pub Vec<ValidatedAct>);
impl RegistrationVerifier for Approval {
    fn approval(&self, act: &ValidatedAct) -> bool {
        self.0.contains(act)
    }
    fn removal(&self, _: &ValidatedAct, _: OpeningKind, _: Position) -> bool {
        false
    }
}
pub fn named(namespace: &str, name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: name.into(),
    }
}
pub fn id(family: &str, author: &str, sequence: u64) -> ActId {
    ActId {
        family: family.into(),
        author: author.into(),
        sequence,
    }
}
fn minted(family: &str, author: &str, sequence: u64) -> PublicReference {
    PublicReference::Minted(id(family, author, sequence))
}
pub fn coordinates(act: &mut CandidateAct, names: &[&str], numerator: i64) {
    act.body.quantities = names
        .iter()
        .flat_map(|name| [(format!("{name}.numerator"), numerator), (format!("{name}.denominator"), 1)])
        .map(|(name, value)| {
            (
                name,
                Quantity {
                    value,
                    unit: "one".into(),
                    vintage: 0,
                },
            )
        })
        .collect();
}
fn paired(act: &mut CandidateAct, middle: PublicReference, target: PublicReference) {
    act.body.layout = Layout::Paired;
    act.legs[0].id.role = Role::A;
    act.legs[0].target = middle.clone();
    act.legs.push(CandidateLeg {
        id: EdgeId {
            act: act.id.clone(),
            role: Role::T,
        },
        source: middle,
        target,
        removal: None,
    });
}

// Raw input construction only. The expected recipients below are literal tables,
// not a second invocation of the production fold, title fold or recipient logic.
pub fn act(family: &str, author: &str, sequence: u64, epoch: u64) -> CandidateAct {
    let mut act = CandidateAct {
        commitments: None,
        id: id(family, author, sequence),
        body: StructuralBody {
            layout: Layout::Binary,
            quantities: vec![],
            license: None,
            settlement: None,
            asserted_parents: vec![],
        },
        legs: vec![CandidateLeg {
            id: EdgeId {
                act: id(family, author, sequence),
                role: Role::Binary,
            },
            source: named("addr", author),
            target: named("prof", "buyer"),
            removal: None,
        }],
        projections: RemovableProjections {
            content: Removal::Live,
            dependency: DependencyProjection::FullEmpty,
        },
        protocol_references: vec![],
        authentication_evidence: authentication(),
        finalization_epoch: epoch,
        authoritative_position: sequence,
        logical_time: sequence,
    };
    match family {
        "Registration" => act.legs[0].target = named("prof", author),
        "Publish" | "Owner" => {
            act.legs[0].target = PublicReference::Minted(act.id.clone());
            coordinates(&mut act, &["attachment"], 1);
            if family == "Publish" {
                let degree = pn_records::LicenseDegree {
                    numerator: 0,
                    denominator: 1,
                };
                act.body.license = Some(pn_records::LicenseQualifiers {
                    attribution: degree,
                    provenance: degree,
                });
            }
        }
        "Opinion" => coordinates(&mut act, &["polarity", "reaction"], 1),
        "Affinity" => {
            act.legs[0].target = named("name", "topic");
            coordinates(&mut act, &["association", "attraction"], 1);
        }
        "Participant" => {
            let chat = PublicReference::Minted(act.id.clone());
            paired(&mut act, chat.clone(), chat);
            coordinates(&mut act, &["interactivity", "responsibility", "continuity"], 1);
        }
        "Reference" | "Review" => {
            let terminal = if family == "Reference" {
                named("prof", "buyer")
            } else {
                PublicReference::Minted(act.id.clone())
            };
            paired(&mut act, named("name", "artifact"), terminal);
            coordinates(&mut act, &["effort", "enthusiasm"], 1);
        }
        "Tag" => {
            paired(&mut act, named("prof", "buyer"), named("name", "topic"));
            coordinates(&mut act, &["relevance", "confidence"], 1);
        }
        "Send" => {
            let terminal = PublicReference::Minted(act.id.clone());
            paired(&mut act, minted("Participant", "seller", 90), terminal);
            coordinates(&mut act, &["importance"], 1);
        }
        "Bid" => {
            let offer = PublicReference::Minted(act.id.clone());
            paired(&mut act, minted("Owner", "seller", 4), offer);
            coordinates(&mut act, &["generosity", "urgency"], 1);
        }
        "Join Request" | "Leave" => {
            act.legs[0].target = minted("Participant", "seller", 90);
            if family == "Join Request" {
                coordinates(&mut act, &["urgency", "formality"], 1);
            }
        }
        "Invitation" | "De-invite" => {
            paired(&mut act, minted("Participant", "seller", 90), named("prof", "buyer"));
            if family == "Invitation" {
                coordinates(&mut act, &["urgency", "formality", "relevance"], 1);
            }
        }
        "Withdraw" | "Rescind" => act.legs[0].target = minted("Bid", "buyer", 5),
        "Accept" | "Ratify" => {
            act.legs[0].target = named("addr", "buyer");
            coordinates(&mut act, &["comfort", "equity"], 1);
        }
        _ => unreachable!("fixture family census"),
    }
    act
}
pub fn stamp(inputs: &mut [CandidateAct]) {
    inputs.sort_by_key(|act| (act.finalization_epoch, act.authoritative_position));
    let mut positions = BTreeMap::new();
    for input in inputs.iter_mut() {
        let next = positions.entry(input.finalization_epoch).or_insert(0);
        *next += 1;
        input.authoritative_position = *next;
    }
    let mut endpoints = BTreeMap::new();
    let mut times = BTreeMap::new();
    for input in inputs {
        let mut predecessors = input.body.asserted_parents.clone();
        match &input.body.settlement {
            Some(SettlementReferences::Accept { settles }) => predecessors.push(settles.clone()),
            Some(SettlementReferences::Ratify { settles, accepts }) => predecessors.extend([settles.clone(), accepts.clone()]),
            None => {}
        }
        let touched: BTreeSet<_> = input
            .legs
            .iter()
            .flat_map(|leg| [leg.source.clone(), leg.target.clone()])
            .collect();
        let maximum = touched
            .iter()
            .filter_map(|node| endpoints.get(node))
            .chain(predecessors.iter().filter_map(|id| times.get(id)))
            .copied()
            .max()
            .unwrap_or(0);
        input.logical_time = maximum + 1;
        times.insert(input.id.clone(), input.logical_time);
        for node in touched {
            endpoints.insert(node, input.logical_time);
        }
    }
}

fn authentication() -> pn_records::authentication::AuthenticationFields {
    pn_records::authentication::AuthenticationFields {
        proposal_precommitment: b"fixture-P".to_vec(),
        actor_proposal_signature: vec![1],
        content_edition: "fixture-content".into(),
        dependency_edition: "fixture-dependency".into(),
        verified_header: b"fixture-V".to_vec(),
        host_seal: b"fixture-seal".to_vec(),
        approval_binding: b"fixture-approval".to_vec(),
        authentication_edition: "fixture-authentication".into(),
        public_verification_material: b"fixture-public-key".to_vec(),
    }
}
