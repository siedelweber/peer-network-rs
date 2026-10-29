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
    let names: Vec<_> = ["addr", "name"]
        .into_iter()
        .map(|namespace| PublicReference::Named {
            namespace: namespace.into(),
            name: "fixture".into(),
        })
        .collect();
    let history = pn_records::validate_history(&formation_inputs(&names), &names).unwrap();
    let auth = FixtureApproval(true);
    let projection = project_complete_act(&history.acts()[0], &history, &auth);
    let publication = project_complete_act(&history.acts()[1], &history, &auth);
    let ownership = project_complete_act(&history.acts()[2], &history, &auth);
    let participant = project_complete_act(&history.acts()[3], &history, &auth);
    let review = project_complete_act(&history.acts()[4], &history, &auth);
    let send = project_complete_act(&history.acts()[5], &history, &auth);
    let bid = project_complete_act(&history.acts()[6], &history, &auth);
    let opinion = project_complete_act(&history.acts()[7], &history, &auth);
    let join_request = project_complete_act(&history.acts()[8], &history, &auth);
    let tag = project_complete_act(&history.acts()[9], &history, &auth);
    let leave = project_complete_act(&history.acts()[10], &history, &auth);
    let reference = project_complete_act(&history.acts()[11], &history, &auth);
    let invitation = project_complete_act(&history.acts()[12], &history, &auth);
    let deinvite = project_complete_act(&history.acts()[13], &history, &auth);
    let withdraw = project_complete_act(&history.acts()[14], &history, &auth);
    let rescind = project_complete_act(&history.acts()[15], &history, &auth);
    let accept = project_complete_act(&history.acts()[16], &history, &auth);
    let ratify = project_complete_act(&history.acts()[17], &history, &auth);
    let graph = reconstruct(&history, &auth).unwrap();
    let valid = validate_formation(&graph, &history, &auth);
    let title = pn_graph::title::title_inputs(&graph, &history, &auth);
    let mut context = pn_graph::recognition::RecognitionContext {
        epoch: 1,
        prior_epoch: 0,
        owners: std::collections::BTreeMap::new(),
        consumed: std::collections::BTreeSet::new(),
    };
    let recognition = pn_graph::recognition::recognize_settlements(&graph, &history, &auth, &context);
    context.prior_epoch = 1;
    let wrong_boundary = pn_graph::recognition::recognize_settlements(&graph, &history, &auth, &context);
    let replay = pn_graph::title::replay_title(&graph, &history, &auth, 1);
    let selected_title =
        pn_graph::title::evaluate_candidate_title(&graph, &history, &auth, 1, pn_graph::title::FinalSetDecision::Selected);
    let rejected_title =
        pn_graph::title::evaluate_candidate_title(&graph, &history, &auth, 1, pn_graph::title::FinalSetDecision::Rejected);
    let denied = reconstruct(&history, &FixtureApproval(false));
    let mut partial = graph.clone();
    let edge = partial.edge_indices().next().unwrap();
    partial.remove_edge(edge);
    let invalid = validate_formation(&partial, &history, &auth);
    let partial_title = pn_graph::title::title_inputs(&partial, &history, &auth);
    let partial_replay = pn_graph::title::replay_title(&partial, &history, &auth, 1);
    cli_common::emit(&serde_json::json!({
        "recognition": format!("{recognition:?}"), "wrong_boundary": format!("{wrong_boundary:?}"),
        "selected_title": format!("{selected_title:?}"), "rejected_title": format!("{rejected_title:?}"),
        "replay": format!("{replay:?}"), "partial_replay": format!("{partial_replay:?}"),
        "title": format!("{title:?}"), "partial_title": format!("{partial_title:?}"),
        "projection": format!("{projection:?}"), "graph": format!("{graph:?}"),
        "publication": format!("{publication:?}"),
        "ownership": format!("{ownership:?}"),
        "participant": format!("{participant:?}"),
        "review": format!("{review:?}"),
        "send": format!("{send:?}"),
        "bid": format!("{bid:?}"),
        "opinion": format!("{opinion:?}"),
        "join_request": format!("{join_request:?}"),
        "tag": format!("{tag:?}"),
        "leave": format!("{leave:?}"),
        "reference": format!("{reference:?}"),
        "invitation": format!("{invitation:?}"),
        "deinvite": format!("{deinvite:?}"),
        "withdraw": format!("{withdraw:?}"),
        "rescind": format!("{rescind:?}"),
        "accept": format!("{accept:?}"),
        "ratify": format!("{ratify:?}"),
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
            settlement: None,
            license: None,
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

fn review(mut input: CandidateAct) -> CandidateAct {
    input.id.family = "Review".into();
    input.id.sequence = 5;
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
    }
    input.legs[1].target = PublicReference::Minted(input.id.clone());
    input.body.quantities.truncate(4);
    for (field, name) in input.body.quantities.iter_mut().zip([
        "enthusiasm.numerator",
        "enthusiasm.denominator",
        "effort.numerator",
        "effort.denominator",
    ]) {
        field.0 = name.into();
    }
    input.authoritative_position = 5;
    input.logical_time = 5;
    input
}

fn sending(mut input: CandidateAct) -> CandidateAct {
    input.id.family = "Send".into();
    input.id.sequence = 6;
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
    }
    input.legs[1].target = PublicReference::Minted(input.id.clone());
    input.body.quantities.truncate(2);
    input.body.quantities[0].0 = "importance.numerator".into();
    input.body.quantities[1].0 = "importance.denominator".into();
    input.authoritative_position = 6;
    input.logical_time = 6;
    input
}

fn bidding(mut input: CandidateAct) -> CandidateAct {
    let item = input.legs[0].target.clone();
    input.id.family = "Bid".into();
    input.id.sequence = 7;
    input.body.layout = Layout::Paired;
    input.legs[0].id.act = input.id.clone();
    input.legs[0].id.role = Role::A;
    input.legs.push(CandidateLeg {
        id: EdgeId {
            act: input.id.clone(),
            role: Role::T,
        },
        source: item,
        target: PublicReference::Minted(input.id.clone()),
        removal: None,
    });
    input.body.quantities = [
        ("generosity.numerator", -1),
        ("generosity.denominator", 2),
        ("urgency.numerator", 2),
        ("urgency.denominator", 3),
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
    input.authoritative_position = 7;
    input.logical_time = 7;
    input
}

fn opinion(mut input: CandidateAct) -> CandidateAct {
    input.id.family = "Opinion".into();
    input.id.sequence = 8;
    input.legs[0].id.act = input.id.clone();
    input.legs[0].target = PublicReference::Named {
        namespace: "prof".into(),
        name: "other".into(),
    };
    for (field, name) in input.body.quantities.iter_mut().zip([
        "polarity.numerator",
        "polarity.denominator",
        "reaction.numerator",
        "reaction.denominator",
    ]) {
        field.0 = name.into();
    }
    input.authoritative_position = 8;
    input.logical_time = 8;
    input
}

fn join_request(mut input: CandidateAct, target: PublicReference) -> CandidateAct {
    input.id.family = "Join Request".into();
    input.id.sequence = 9;
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
    input.authoritative_position = 9;
    input.logical_time = 9;
    input
}

fn tagging(mut input: CandidateAct) -> CandidateAct {
    input.id.family = "Tag".into();
    input.id.sequence = 10;
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
    }
    input.legs[1].target = PublicReference::Named {
        namespace: "name".into(),
        name: "topic".into(),
    };
    for (field, name) in input.body.quantities.iter_mut().zip([
        "relevance.numerator",
        "relevance.denominator",
        "confidence.numerator",
        "confidence.denominator",
    ]) {
        field.0 = name.into();
    }
    input.authoritative_position = 10;
    input.logical_time = 10;
    input
}

fn leaving(mut input: CandidateAct) -> CandidateAct {
    input.id.family = "Leave".into();
    input.id.sequence = 11;
    input.legs[0].id.act = input.id.clone();
    input.authoritative_position = 11;
    input.logical_time = 11;
    input.body.quantities.clear();
    input
}

fn publication(mut publication: CandidateAct) -> CandidateAct {
    publication.id.family = "Publish".into();
    publication.id.sequence = 2;
    publication.legs[0].id.act = publication.id.clone();
    publication.legs[0].target = PublicReference::Minted(publication.id.clone());
    publication.body.quantities.truncate(2);
    publication.body.quantities[0].0 = "attachment.numerator".into();
    publication.body.quantities[1].0 = "attachment.denominator".into();
    publication.body.license = Some(pn_records::LicenseQualifiers {
        attribution: pn_records::LicenseDegree {
            numerator: 1,
            denominator: 2,
        },
        provenance: pn_records::LicenseDegree {
            numerator: 2,
            denominator: 3,
        },
    });
    publication.authoritative_position = 2;
    publication.logical_time = 2;
    publication
}

fn referencing(mut input: CandidateAct) -> CandidateAct {
    input.id.family = "Reference".into();
    input.id.sequence = 12;
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
    }
    input.legs[1].target = input.legs[0].target.clone();
    input.authoritative_position = 12;
    input.logical_time = 12;
    input
}

fn formation_inputs(names: &[PublicReference]) -> Vec<CandidateAct> {
    let act = affinity(names);
    let publication = publication(act.clone());
    let mut ownership = publication.clone();
    ownership.id.family = "Owner".into();
    ownership.body.license = None;
    ownership.id.sequence = 3;
    ownership.legs[0].id.act = ownership.id.clone();
    ownership.legs[0].target = PublicReference::Minted(ownership.id.clone());
    ownership.authoritative_position = 3;
    ownership.logical_time = 3;
    let participant = participation(ownership.clone());
    let review = review(participant.clone());
    let tag = tagging(review.clone());
    let reference = referencing(review.clone());
    let invitation = invitation(participant.clone());
    let deinvite = deinvite(invitation.clone());
    let send = sending(participant.clone());
    let bid = bidding(ownership.clone());
    let withdraw = withdrawing(ownership.clone(), bid.legs[1].target.clone());
    let rescind = rescinding(withdraw.clone());
    let opinion = opinion(act.clone());
    let join_request = join_request(act.clone(), participant.legs[0].target.clone());
    let leave = leaving(join_request.clone());
    let accept = settlement(act.clone(), 17, &bid, None);
    let ratify = settlement(act.clone(), 18, &bid, Some(&accept));
    vec![
        act,
        publication,
        ownership,
        participant,
        review,
        send,
        bid,
        opinion,
        join_request,
        tag,
        leave,
        reference,
        invitation,
        deinvite,
        withdraw,
        rescind,
        accept,
        ratify,
    ]
}

fn invitation(mut input: CandidateAct) -> CandidateAct {
    input.id.family = "Invitation".into();
    input.id.sequence = 13;
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
    }
    input.legs[1].target = PublicReference::Named {
        namespace: "prof".into(),
        name: "invitee".into(),
    };
    for (field, name) in input.body.quantities.iter_mut().zip([
        "urgency.numerator",
        "urgency.denominator",
        "formality.numerator",
        "formality.denominator",
        "relevance.numerator",
        "relevance.denominator",
    ]) {
        field.0 = name.into();
    }
    input.authoritative_position = 13;
    input.logical_time = 13;
    input
}

fn deinvite(mut input: CandidateAct) -> CandidateAct {
    input.id.family = "De-invite".into();
    input.id.sequence = 14;
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
    }
    input.body.quantities.clear();
    input.authoritative_position = 14;
    input.logical_time = 14;
    input
}

fn withdrawing(mut input: CandidateAct, offer: PublicReference) -> CandidateAct {
    input.id.family = "Withdraw".into();
    input.id.sequence = 15;
    input.legs[0].id.act = input.id.clone();
    input.legs[0].target = offer;
    input.body.quantities.clear();
    input.authoritative_position = 15;
    input.logical_time = 15;
    input
}

fn rescinding(mut input: CandidateAct) -> CandidateAct {
    input.id.family = "Rescind".into();
    input.id.sequence = 16;
    input.legs[0].id.act = input.id.clone();
    input.authoritative_position = 16;
    input.logical_time = 16;
    input
}

fn settlement(mut input: CandidateAct, sequence: u64, bid: &CandidateAct, accept: Option<&CandidateAct>) -> CandidateAct {
    input.id.family = if accept.is_some() { "Ratify" } else { "Accept" }.into();
    input.id.sequence = sequence;
    input.legs[0].id.act = input.id.clone();
    input.legs[0].target = input.legs[0].source.clone();
    input.body.settlement = Some(match accept {
        Some(accept) => pn_records::SettlementReferences::Ratify {
            settles: bid.id.clone(),
            accepts: accept.id.clone(),
        },
        None => pn_records::SettlementReferences::Accept { settles: bid.id.clone() },
    });
    for (field, name) in input.body.quantities.iter_mut().zip([
        "comfort.numerator",
        "comfort.denominator",
        "equity.numerator",
        "equity.denominator",
    ]) {
        field.0 = name.into();
    }
    input.authoritative_position = sequence;
    input.logical_time = sequence;
    input
}
