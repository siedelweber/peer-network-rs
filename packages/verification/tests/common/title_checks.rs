use std::collections::{BTreeMap, BTreeSet};

use pn_graph::formation::reconstruct;
use pn_graph::registration::{OpeningKind, RegistrationVerifier};
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, Quantity,
    RemovableProjections, Removal, Role, SettlementReferences, StructuralBody, ValidatedAct, validate_history,
};

#[derive(Debug)]
struct Approval;
impl RegistrationVerifier for Approval {
    fn approval(&self, _: &ValidatedAct) -> bool {
        true
    }
    fn removal(&self, _: &ValidatedAct, _: OpeningKind, _: Position) -> bool {
        true
    }
}

fn node(namespace: &str, name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: name.into(),
    }
}

fn act(family: &str, author: &str, sequence: u64, epoch: u64, target: PublicReference) -> CandidateAct {
    let id = ActId {
        family: family.into(),
        author: author.into(),
        sequence,
    };
    CandidateAct {
        legs: vec![CandidateLeg {
            id: EdgeId {
                act: id.clone(),
                role: Role::Binary,
            },
            source: node("addr", author),
            target,
            removal: None,
        }],
        id,
        body: StructuralBody {
            layout: Layout::Binary,
            quantities: vec![],
            license: None,
            settlement: None,
            asserted_parents: vec![],
        },
        projections: RemovableProjections {
            content: Removal::Live,
            dependency: DependencyProjection::FullEmpty,
        },
        protocol_references: vec![],
        authentication_evidence: vec![1],
        finalization_epoch: epoch,
        authoritative_position: sequence,
        logical_time: 0,
    }
}

fn quantities(input: &mut CandidateAct, names: [&str; 2], numerator: i64) {
    input.body.quantities = names
        .into_iter()
        .flat_map(|name| {
            [
                (
                    format!("{name}.numerator"),
                    Quantity {
                        value: numerator,
                        unit: "one".into(),
                        vintage: 0,
                    },
                ),
                (
                    format!("{name}.denominator"),
                    Quantity {
                        value: 1,
                        unit: "one".into(),
                        vintage: 0,
                    },
                ),
            ]
        })
        .collect();
}

fn item() -> PublicReference {
    PublicReference::Minted(ActId {
        author: "seller".into(),
        sequence: 99,
        family: "Owner".into(),
    })
}

fn bid(sequence: u64) -> CandidateAct {
    let mut input = act("Bid", "buyer", sequence, 1, item());
    quantities(&mut input, ["generosity", "urgency"], 1);
    input.body.layout = Layout::Paired;
    input.legs[0].id.role = Role::A;
    input.legs.push(CandidateLeg {
        id: EdgeId {
            act: input.id.clone(),
            role: Role::T,
        },
        source: item(),
        target: PublicReference::Minted(input.id.clone()),
        removal: None,
    });
    input
}

// Fixture preparation only: a raw-carrier recurrence, not used by the predicate oracle.
fn stamp(inputs: &mut [CandidateAct]) {
    inputs.sort_by_key(|act| (act.finalization_epoch, act.authoritative_position));
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

fn handshake(sequence: u64, epoch: u64, buyer: &str, seller: &str) -> Vec<CandidateAct> {
    let mut bid = bid(sequence);
    bid.id.author = buyer.into();
    bid.finalization_epoch = epoch;
    bid.legs[0].source = node("addr", buyer);
    for leg in &mut bid.legs {
        leg.id.act = bid.id.clone();
    }
    bid.legs[1].target = PublicReference::Minted(bid.id.clone());
    let mut accept = act("Accept", seller, sequence + 1, epoch, node("addr", buyer));
    quantities(&mut accept, ["comfort", "equity"], -1);
    accept.body.settlement = Some(SettlementReferences::Accept { settles: bid.id.clone() });
    let mut ratify = act("Ratify", buyer, sequence + 2, epoch, node("addr", seller));
    quantities(&mut ratify, ["comfort", "equity"], -1);
    ratify.body.settlement = Some(SettlementReferences::Ratify {
        settles: bid.id.clone(),
        accepts: accept.id.clone(),
    });
    vec![bid, accept, ratify]
}

fn inputs(words: &[u64]) -> Vec<CandidateAct> {
    let mut genesis = act("Owner", "seller", 99, 1, item());
    genesis.body.quantities = vec![
        (
            "attachment.numerator".into(),
            Quantity {
                value: 0,
                unit: "one".into(),
                vintage: 0,
            },
        ),
        (
            "attachment.denominator".into(),
            Quantity {
                value: 1,
                unit: "one".into(),
                vintage: 0,
            },
        ),
    ];
    genesis.authoritative_position = 1;
    let mut inputs = vec![genesis];
    for (boundary, word) in words.iter().take(2).enumerate() {
        let epoch = u64::try_from(boundary).unwrap() + 1;
        let seller = if boundary == 0 || word & 16 != 0 { "seller" } else { "buyer1" };
        for (slot, buyer) in ["buyer1", "buyer2"].into_iter().enumerate() {
            let kind = (word >> (slot * 2)) & 3;
            if kind == 0 {
                continue;
            }
            let sequence = epoch * 10 + u64::try_from(slot).unwrap() * 4;
            let mut chain = handshake(sequence, epoch, buyer, seller);
            if kind == 3 {
                chain[1].legs[0].target = node("addr", "outsider");
            }
            if kind == 2 {
                inputs.push(act(
                    "Withdraw",
                    buyer,
                    sequence + 3,
                    epoch,
                    PublicReference::Minted(chain[0].id.clone()),
                ));
            }
            inputs.extend(chain);
        }
    }
    stamp(&mut inputs);
    inputs
}

// Independent boundary truth table over the case alphabet. This consumes only
// words, not records, graph projections, recognition evidence or fold helpers.
fn expected(words: &[u64]) -> Vec<(String, Vec<[u64; 3]>, bool)> {
    let mut owner = "seller".to_owned();
    words
        .iter()
        .take(2)
        .enumerate()
        .map(|(boundary, word)| {
            let authorized = if boundary == 0 || word & 16 != 0 {
                owner == "seller"
            } else {
                owner == "buyer1"
            };
            let valid = [word & 3 == 1 && authorized, (word / 4) & 3 == 1 && authorized];
            let winner = match valid {
                [true, false] => Some("buyer1"),
                [false, true] => Some("buyer2"),
                _ => None,
            };
            if let Some(buyer) = winner {
                buyer.clone_into(&mut owner);
            }
            let epoch = u64::try_from(boundary).unwrap() + 1;
            let triples = valid
                .into_iter()
                .enumerate()
                .filter(|(_, yes)| *yes)
                .map(|(slot, _)| {
                    let n = epoch * 10 + u64::try_from(slot).unwrap() * 4;
                    [n, n + 1, n + 2]
                })
                .collect();
            (owner.clone(), triples, winner.is_some())
        })
        .collect()
}

/// Exercise the shared public title contract against the independent word table.
///
/// # Panics
/// Panics only if a fixture is malformed or an observable result differs from its table.
pub(crate) fn check(words: &[u64]) -> pn_graph::title::TitleReplay {
    let raw = inputs(words);
    let table = expected(words);
    let mut result = None;
    for reversed in [false, true] {
        let mut presented = raw.clone();
        if reversed {
            presented.reverse();
        }
        let history = validate_history(&presented, &[]).unwrap();
        let graph = reconstruct(&history, &Approval).unwrap();
        let replay = pn_graph::title::replay_title(&graph, &history, &Approval, u64::try_from(table.len()).unwrap()).unwrap();
        let mut consumed = BTreeSet::new();
        let mut events = vec![];
        let mut prior_owner = "seller";
        for (index, (owner, triples, transfer)) in table.iter().enumerate() {
            let boundary = &replay.boundaries[index];
            assert_eq!(boundary.premises.owners, BTreeMap::from([(item(), prior_owner.to_owned())]));
            assert_eq!(boundary.premises.consumed, consumed);
            for triple in triples {
                for sequence in triple {
                    consumed.insert(raw.iter().find(|act| act.id.sequence == *sequence).unwrap().id.clone());
                }
                events.push((u64::try_from(index).unwrap() + 1, *triple, *transfer));
            }
            assert_eq!(boundary.certificate, BTreeMap::from([(item(), Some(owner.clone()))]));
            assert_eq!(boundary.consumed, consumed);
            prior_owner = owner;
        }
        assert_eq!(replay.consumed, consumed);
        assert_eq!(
            replay.certificate,
            if table.is_empty() {
                BTreeMap::new()
            } else {
                BTreeMap::from([(item(), Some(prior_owner.to_owned()))])
            }
        );
        let actual: Vec<_> = replay
            .events
            .iter()
            .map(|event| {
                (
                    event.epoch,
                    event.acts.each_ref().map(|id| id.sequence),
                    event.outcome == pn_graph::title::TitleOutcome::Transferred,
                )
            })
            .collect();
        assert_eq!(actual, events);
        if let Some(previous) = &result {
            assert_eq!(previous, &replay);
        }
        result = Some(replay);
    }
    result.unwrap()
}
