use std::collections::BTreeMap;

use nrz_cas::limits::Limits;
use pn_epoch::recipients::resolve_recipients;
use pn_graph::registration::{OpeningKind, RegistrationVerifier};
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, Quantity,
    RemovableProjections, Removal, Role, SettlementReferences, StructuralBody, ValidatedAct, validate_history,
};

#[derive(Debug)]
struct Verifier;
impl RegistrationVerifier for Verifier {
    fn approval(&self, _: &ValidatedAct) -> bool {
        true
    }
    fn removal(&self, _: &ValidatedAct, _: OpeningKind, _: Position) -> bool {
        true
    }
}

#[derive(Debug)]
struct Deny;
impl RegistrationVerifier for Deny {
    fn approval(&self, _: &ValidatedAct) -> bool {
        false
    }
    fn removal(&self, _: &ValidatedAct, _: OpeningKind, _: Position) -> bool {
        false
    }
}

fn named(namespace: &str, name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: name.into(),
    }
}
fn id(family: &str, author: &str, sequence: u64) -> ActId {
    ActId {
        family: family.into(),
        author: author.into(),
        sequence,
    }
}
fn minted(family: &str, author: &str, sequence: u64) -> PublicReference {
    PublicReference::Minted(id(family, author, sequence))
}
fn coordinates(act: &mut CandidateAct, names: &[&str], numerator: i64) {
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
fn act(family: &str, author: &str, sequence: u64, epoch: u64) -> CandidateAct {
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
        authentication_evidence: vec![1],
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
fn positions(inputs: &[CandidateAct]) -> Vec<CandidateAct> {
    // Compact raw fixture gaps without sorting the presentation or changing its order of record.
    let mut keys: Vec<_> = inputs
        .iter()
        .map(|act| (act.finalization_epoch, act.authoritative_position, act.id.clone()))
        .collect();
    keys.sort();
    let mut counters = BTreeMap::new();
    let assigned: BTreeMap<_, _> = keys
        .into_iter()
        .map(|(epoch, _, id)| {
            let next = counters.entry(epoch).or_insert(0);
            *next += 1;
            (id, *next)
        })
        .collect();
    inputs
        .iter()
        .cloned()
        .map(|mut act| {
            act.authoritative_position = assigned[&act.id];
            act
        })
        .collect()
}
fn history(inputs: &[CandidateAct]) -> pn_records::ValidatedHistory {
    let placed = positions(inputs);
    let history = validate_history(&placed, &[]).unwrap();
    assert_eq!(
        history.acts().iter().map(ValidatedAct::id).collect::<Vec<_>>(),
        inputs.iter().map(|act| &act.id).collect::<Vec<_>>()
    );
    history
}
fn recipients(inputs: &[CandidateAct], boundary: u64) -> BTreeMap<ActId, String> {
    let history = history(inputs);
    let result = resolve_recipients(&history, boundary, &Verifier, Limits::default());
    assert!(result.is_ok(), "{result:?} for {inputs:?}");
    let result = result.unwrap();
    result
        .into_iter()
        .flat_map(|row| row.cell.members.into_iter().map(move |id| (id, row.recipient.clone())))
        .collect()
}
fn anchors() -> Vec<CandidateAct> {
    vec![
        act("Registration", "seller", 1, 1),
        act("Registration", "buyer", 2, 1),
        act("Registration", "third", 3, 1),
    ]
}

/// Claim: Across all nineteen families, independent literal recipient tables send only positive Profile Opinion, Reference and Invitation cells to anchored persons without a successful settlement event; artifact and control families remain home. Every mandatory sign is tested independently, dangling and future anchors resolve home, unauthorized formation refuses, and positive Invitation resolves to its anchored invitee.
/// ´claim:compiler:recipient-classes-require-positive-anchored-persons´
/// ´test:integration:recipient-classes´
#[test]
fn recipient_classes() {
    let cases = [
        ("Registration", "seller"),
        ("Publish", "seller"),
        ("Owner", "seller"),
        ("Opinion", "buyer"),
        ("Reference", "buyer"),
        ("Invitation", "buyer"),
        ("Affinity", "seller"),
        ("Participant", "seller"),
        ("Review", "seller"),
        ("Tag", "seller"),
        ("Send", "seller"),
        ("Bid", "seller"),
        ("Join Request", "seller"),
        ("De-invite", "seller"),
        ("Leave", "seller"),
        ("Withdraw", "seller"),
        ("Rescind", "seller"),
        ("Accept", "seller"),
        ("Ratify", "seller"),
    ];
    for (family, expected) in cases {
        let mut inputs = anchors();
        let mut input = act(family, "seller", 10, 1);
        // Existing earlier wrong-family targets form, but bind no settlement.
        if family == "Accept" {
            input.body.settlement = Some(SettlementReferences::Accept {
                settles: inputs[0].id.clone(),
            });
        }
        if family == "Ratify" {
            input.body.settlement = Some(SettlementReferences::Ratify {
                settles: inputs[0].id.clone(),
                accepts: inputs[1].id.clone(),
            });
        }
        let identity = input.id.clone();
        inputs.push(input);
        assert_eq!(recipients(&inputs, 1)[&identity], expected, "{family}");
    }
    for family in ["Opinion", "Reference", "Invitation"] {
        for coordinate in [0, 2] {
            for value in [-1, 0, 1] {
                let mut inputs = anchors();
                let mut input = act(family, "seller", 10, 1);
                input.body.quantities[coordinate].1.value = value;
                inputs.push(input);
                assert_eq!(
                    recipients(&inputs, 1)[&id(family, "seller", 10)],
                    if value > 0 { "buyer" } else { "seller" }
                );
            }
        }
        for anchor_epoch in [0, 2] {
            let mut inputs = anchors();
            if anchor_epoch == 0 {
                inputs.remove(1);
            } else {
                inputs[1].finalization_epoch = anchor_epoch;
            }
            inputs.push(act(family, "seller", 10, 1));
            assert_eq!(recipients(&inputs, 1)[&id(family, "seller", 10)], "seller");
        }
        if family != "Invitation" {
            let mut inputs = anchors();
            let mut input = act(family, "seller", 10, 1);
            input.legs.last_mut().unwrap().target = named("name", "artifact");
            inputs.push(input);
            assert_eq!(recipients(&inputs, 1)[&id(family, "seller", 10)], "seller");
        }
    }
    assert!(matches!(
        resolve_recipients(&history(&anchors()), 1, &Deny, Limits::default()),
        Err(pn_epoch::recipients::RecipientError::Cells(
            pn_epoch::cells::CellError::Formation(_)
        ))
    ));
}

fn settlement() -> Vec<CandidateAct> {
    let mut inputs = anchors();
    inputs.push(act("Owner", "seller", 4, 1));
    inputs.extend(handshake("buyer", "seller", 5, 2));
    inputs
}
fn handshake(buyer: &str, seller: &str, sequence: u64, epoch: u64) -> Vec<CandidateAct> {
    let bid = act("Bid", buyer, sequence, epoch);
    let mut accept = act("Accept", seller, sequence + 1, epoch);
    accept.legs[0].target = named("addr", buyer);
    accept.body.settlement = Some(SettlementReferences::Accept { settles: bid.id.clone() });
    let mut ratify = act("Ratify", buyer, sequence + 2, epoch);
    ratify.legs[0].target = named("addr", seller);
    ratify.body.settlement = Some(SettlementReferences::Ratify {
        settles: bid.id.clone(),
        accepts: accept.id.clone(),
    });
    vec![bid, accept, ratify]
}

/// Claim: Independent event tables distinguish unique transfer, conflict, buyer or seller cancellation, each wrong party, consumed-record reuse and resale. Successful Accept and Ratify cells retain counterparty recipients after consumption and resale, while losing or reused attempts resolve home; hostile settlement coordinates remain home without reversing title. Each of eleven event cases reaches validation in both distinct forward and reversed presentations with equal recipients.
/// ´claim:compiler:recipients-read-persistent-title-events´
/// ´test:integration:recipient-settlements´
#[test]
fn recipient_settlements() {
    for case in 0..11 {
        let mut inputs = settlement();
        let (mut accept, mut ratify) = ("buyer", "seller");
        match case {
            1 => {
                let mut other = inputs[6].clone();
                other.id.sequence = 8;
                other.legs[0].id.act = other.id.clone();
                inputs.push(other);
                accept = "seller";
                ratify = "buyer";
            }
            2 | 3 => {
                inputs.push(act(
                    if case == 2 { "Withdraw" } else { "Rescind" },
                    if case == 2 { "buyer" } else { "seller" },
                    8,
                    2,
                ));
                accept = "seller";
                ratify = "buyer";
            }
            4 => {
                inputs[6].id.author = "third".into();
                inputs[6].legs[0].id.act = inputs[6].id.clone();
                inputs[6].legs[0].source = named("addr", "third");
                accept = "seller";
                ratify = "third";
            }
            5 => {
                inputs[5].legs[0].target = named("addr", "third");
                accept = "seller";
                ratify = "buyer";
            }
            6 => {
                inputs[6].legs[0].target = named("addr", "third");
                accept = "seller";
                ratify = "buyer";
            }
            7 => {
                let mut reused = inputs[6].clone();
                reused.id.sequence = 8;
                reused.finalization_epoch = 3;
                reused.legs[0].id.act = reused.id.clone();
                inputs.push(reused);
            }
            8 => inputs.extend(handshake("third", "buyer", 10, 3)),
            9 | 10 => inputs.push(act(
                if case == 9 { "Withdraw" } else { "Rescind" },
                if case == 9 { "buyer" } else { "seller" },
                8,
                3,
            )),
            _ => {}
        }
        let results = recipients(&inputs, 4);
        assert_eq!(results[&inputs[5].id], accept, "case {case}");
        assert_eq!(results[&inputs[6].id], ratify, "case {case}");
        if case == 1 || case == 7 {
            assert_eq!(results[&id("Ratify", "buyer", 8)], "buyer");
        }
        if case == 8 {
            assert_eq!(results[&id("Accept", "buyer", 11)], "third");
            assert_eq!(results[&id("Ratify", "third", 12)], "buyer");
        }
        let forward: Vec<_> = history(&inputs).acts().iter().map(|act| act.id().clone()).collect();
        inputs.reverse();
        let reversed: Vec<_> = history(&inputs).acts().iter().map(|act| act.id().clone()).collect();
        assert_ne!(forward, reversed);
        assert_eq!(recipients(&inputs, 4), results);
    }
    for index in [5, 6] {
        for coordinate in [0, 2] {
            let mut inputs = settlement();
            inputs[index].body.quantities[coordinate].1.value = -1;
            assert_eq!(recipients(&inputs, 3)[&inputs[index].id], inputs[index].id.author);
            let history = history(&inputs);
            let graph = pn_graph::formation::reconstruct_replay(&history, &Verifier).unwrap();
            let title = pn_graph::title::replay_title(&graph, &history, &Verifier, 3).unwrap();
            assert_eq!(title.certificate[&minted("Owner", "seller", 4)].as_deref(), Some("buyer"));
            assert!(title.consumed.contains(&inputs[index].id));
        }
    }
}

/// Claim: Completed-set recipient compilation retains earlier cell members across empty epochs and nets later opposite stance before resolving a target. Distinct forward and reversed five-act presentations reach validation unchanged and preserve recipients; payload or dependency removal and published stamp faults also preserve recipients, with every member present.
/// ´claim:compiler:recipient-cells-read-the-cumulative-boundary-set´
/// ´test:integration:recipient-cumulative´
#[test]
fn recipient_cumulative() {
    let mut inputs = anchors();
    inputs.push(act("Opinion", "seller", 10, 1));
    let original = recipients(&inputs, 1);
    assert_eq!(recipients(&inputs, 2), original);
    let mut opposite = act("Opinion", "seller", 11, 3);
    coordinates(&mut opposite, &["polarity", "reaction"], -1);
    inputs.push(opposite);
    let expected = recipients(&inputs, 3);
    assert_eq!(expected[&id("Opinion", "seller", 10)], "seller");
    assert_eq!(expected[&id("Opinion", "seller", 11)], "seller");
    assert_eq!(expected.len(), inputs.len());
    let mut reversed = inputs.clone();
    reversed.reverse();
    assert_ne!(history(&inputs).acts(), history(&reversed).acts());
    assert_eq!(recipients(&reversed, 3), expected);
    inputs[3].projections.content = Removal::Tombstoned((3, 1));
    inputs[3].projections.dependency = DependencyProjection::Tombstoned((3, 1));
    inputs[4].logical_time = 500;
    inputs.reverse();
    assert_eq!(recipients(&inputs, 3), expected);
}

/// Claim: The released Invitation netting fixture and independent rational tables cancel one author's bundle to zero and home, restore a later positive vouch, preserve independent authors, and keep De-invite singleton at self with coefficient one. Both compliant co-epoch placements produce identical cells, coefficients and recipients; the released positive nonsquare coefficient remains explicit irrational evidence.
/// ´claim:compiler:invitation-netting-is-author-local-and-order-free´
/// ´test:integration:invitation-netting´
#[test]
fn invitation_netting() {
    use pn_epoch::coefficients::{CoefficientError, coefficient};
    for (u, f, denominator, positive, pair) in [(8, 7, 10, None, ("4/5", "7/10")), (1, 1, 2, Some("1/2"), ("1/2", "1/2"))] {
        let make = |author, sequence, epoch, sign: i64| {
            let mut input = act("Invitation", author, sequence, epoch);
            input.body.quantities[0].1.value = sign * u;
            input.body.quantities[1].1.value = denominator;
            input.body.quantities[2].1.value = sign * f;
            input.body.quantities[3].1.value = denominator;
            input.body.quantities[4].1.value = 4;
            input.body.quantities[5].1.value = 5;
            input
        };
        let mut inputs = anchors();
        inputs.extend([
            make("seller", 10, 2, 1),
            make("third", 11, 2, 1),
            make("seller", 12, 3, -1),
            make("seller", 13, 4, 1),
            act("De-invite", "seller", 14, 5),
        ]);
        for boundary in 2..=5 {
            let result = resolve_recipients(&history(&inputs), boundary, &Verifier, Limits::default()).unwrap();
            for row in result.iter().filter(|row| row.cell.identity.family == "Invitation") {
                let cancelled = row.cell.identity.author == "seller" && boundary == 3;
                let (urgency, formality) = if cancelled { ("0", "0") } else { pair };
                assert_eq!(row.cell.coordinates["urgency"], urgency);
                assert_eq!(row.cell.coordinates["formality"], formality);
                assert_eq!(row.recipient, if cancelled { "seller" } else { "buyer" });
                let expected = if cancelled {
                    Ok("0".into())
                } else if let Some(value) = positive {
                    Ok(value.into())
                } else {
                    Err(CoefficientError::Irrational {
                        radicand: "14/25".into(),
                    })
                };
                assert_eq!(coefficient(&row.cell, Limits::default()), expected);
                let members = if row.cell.identity.author == "third" {
                    1
                } else {
                    usize::try_from(boundary.min(4) - 1).unwrap()
                };
                assert_eq!(row.cell.members.len(), members);
            }
            if boundary == 5 {
                let row = result.iter().find(|row| row.cell.identity.family == "De-invite").unwrap();
                assert_eq!(row.recipient, "seller");
                assert_eq!(row.cell.members.len(), 1);
                assert_eq!(coefficient(&row.cell, Limits::default()).unwrap(), "1");
            }
        }
        inputs.truncate(6);
        inputs[5].finalization_epoch = 2;
        let mut placed = positions(&inputs);
        let first = resolve_recipients(&validate_history(&placed, &[]).unwrap(), 2, &Verifier, Limits::default()).unwrap();
        let old = placed[3].authoritative_position;
        placed[3].authoritative_position = placed[5].authoritative_position;
        placed[5].authoritative_position = old;
        let second = resolve_recipients(&validate_history(&placed, &[]).unwrap(), 2, &Verifier, Limits::default()).unwrap();
        assert_eq!(first, second);
        let cancelled = first
            .iter()
            .find(|row| row.cell.identity.family == "Invitation" && row.cell.identity.author == "seller")
            .unwrap();
        assert_eq!(cancelled.recipient, "seller");
        assert_eq!(cancelled.cell.coordinates["urgency"], "0");
        assert_eq!(cancelled.cell.coordinates["formality"], "0");
        assert_eq!(coefficient(&cancelled.cell, Limits::default()).unwrap(), "0");
    }
}
