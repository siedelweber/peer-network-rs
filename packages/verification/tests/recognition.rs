use std::collections::{BTreeMap, BTreeSet};

use pn_graph::formation::reconstruct;
use pn_graph::recognition::{RecognitionClause, RecognitionContext, RecognitionError, recognize_settlements};
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

/// Claim: The seven fully carried acts of network-v0.31.0's ``ver:boundary:act-time-recomputation`` match all 31 declared result fields against an independent literal boundary table, retaining two parent-placement faults, one dependency violation and one stamp mismatch without changing any published placement or stamp. Reversing presentation preserves the evidence.
/// ´claim:verification:carried-time-replay-matches-paper-fixture´
/// ´test:integration:paper-time-fixture´
#[test]
fn paper_time_fixture() {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/datasets/org.peer-network.design.constants.json")).unwrap();
    let rows = data["rows"].as_array().unwrap();
    let fixture = &rows.iter().find(|row| row["id"] == "act_time_fixture").unwrap()["definition"];
    let identity = |key: &str| ActId {
        author: key.into(),
        sequence: 1,
        family: "Fixture".into(),
    };
    let mut positions = BTreeMap::new();
    let inputs: Vec<_> = fixture["acts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let key = row["key"].as_str().unwrap();
            let epoch = row["epoch"].as_u64().unwrap();
            let mut input = act("Fixture", key, 1, epoch, node("name", row["incidence"][1].as_str().unwrap()));
            input.legs[0].source = node("name", row["incidence"][0].as_str().unwrap());
            let position = positions.entry(epoch).or_insert(0);
            *position += 1;
            input.authoritative_position = *position;
            input.logical_time = row["published"].as_u64().unwrap();
            input.body.asserted_parents = row["parents"]
                .as_array()
                .unwrap()
                .iter()
                .map(|key| identity(key.as_str().unwrap()))
                .collect();
            input.body.asserted_parents.sort();
            let mut dependencies: Vec<_> = row["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .map(|key| identity(key.as_str().unwrap()))
                .collect();
            dependencies.sort();
            if !dependencies.is_empty() {
                input.projections.dependency = DependencyProjection::Full(dependencies);
            }
            input
        })
        .collect();
    let history = validate_history(&inputs, &[]).unwrap();
    // An independent table, not a second call to production recurrence or its helpers.
    let expected = [
        ("alpha", 1, 1, 1, 1),
        ("beta", 1, 2, 2, 2),
        ("gamma", 1, 3, 1, 1),
        ("delta", 2, 1, 3, 3),
        ("epsilon", 2, 2, 2, 3),
        ("zeta", 2, 3, 1, 1),
        ("eta", 2, 4, 4, 4),
    ];
    let mut compared = BTreeSet::new();
    for (key, epoch, position, published, recomputed) in expected {
        let actual = history.acts().iter().find(|act| act.id() == &identity(key)).unwrap();
        let evidence = history.time_evidence().iter().find(|row| row.act == identity(key)).unwrap();
        assert_eq!(evidence.recomputed, pn_records::RecomputedTime::Available(recomputed));
        for (field, expected, actual) in [
            ("epoch", epoch, u128::from(actual.position().0)),
            ("position", position, u128::from(actual.position().1)),
            ("published", published, u128::from(actual.logical_time())),
            ("recomputed", recomputed, recomputed),
        ] {
            let id = format!("result.act_time.{key}_{field}");
            assert!(rows.iter().any(|row| row["id"] == id));
            assert_eq!(actual, expected, "{id}");
            compared.insert(id);
        }
    }
    for (field, expected, actual) in [
        ("parent_fault_count", 2, history.parent_faults().len()),
        ("dependency_fault_count", 1, history.non_compliance().len()),
        (
            "mismatch_count",
            1,
            history
                .time_evidence()
                .iter()
                .filter(|row| matches!(row.verdict, pn_records::TimeVerdict::Mismatch { .. }))
                .count(),
        ),
    ] {
        let id = format!("result.act_time.{field}");
        assert!(rows.iter().any(|row| row["id"] == id));
        assert_eq!(actual, expected, "{id}");
        compared.insert(id);
    }
    assert_eq!(compared.len(), 31);
    let reversed: Vec<_> = inputs.into_iter().rev().collect();
    let replay = validate_history(&reversed, &[]).unwrap();
    assert_eq!(replay.time_evidence(), history.time_evidence());
    assert_eq!(replay.parent_faults(), history.parent_faults());
    assert_eq!(replay.non_compliance(), history.non_compliance());
}

fn act(family: &str, author: &str, sequence: u64, epoch: u64, target: PublicReference) -> CandidateAct {
    let id = ActId {
        family: family.into(),
        author: author.into(),
        sequence,
    };
    CandidateAct {
        commitments: None,
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

fn fixture(stance: i64, withdraw: u64, rescind: u64) -> Vec<CandidateAct> {
    let bid = bid(1);
    let mut accept = act("Accept", "seller", 2, 1, node("addr", "buyer"));
    quantities(&mut accept, ["comfort", "equity"], stance);
    accept.body.settlement = Some(SettlementReferences::Accept { settles: bid.id.clone() });
    let mut ratify = act("Ratify", "buyer", 3, 2, node("addr", "seller"));
    quantities(&mut ratify, ["comfort", "equity"], stance);
    ratify.body.settlement = Some(SettlementReferences::Ratify {
        settles: bid.id.clone(),
        accepts: accept.id.clone(),
    });
    let offer = PublicReference::Minted(bid.id.clone());
    let mut inputs = vec![bid, accept, ratify];
    for (family, author, sequence, epoch) in [("Withdraw", "buyer", 4, withdraw), ("Rescind", "seller", 5, rescind)] {
        if epoch != 0 {
            inputs.push(act(family, author, sequence, epoch, offer.clone()));
        }
    }
    for input in &mut inputs {
        input.authoritative_position += 1;
    }
    inputs.push(genesis());
    stamp(&mut inputs);
    inputs.rotate_left(1);
    inputs
}

// Fixture preparation only: a raw-carrier recurrence, not used by the predicate oracle.
fn stamp(inputs: &mut [CandidateAct]) {
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

fn context() -> RecognitionContext {
    RecognitionContext {
        epoch: 2,
        prior_epoch: 1,
        owners: BTreeMap::from([(item(), "seller".into())]),
        consumed: BTreeSet::new(),
    }
}

// Independently enumerate raw triples, without title inputs, validated-act accessors,
// recognition helpers, graph weights or the implementation's candidate iteration.
fn oracle(inputs: &[CandidateAct], context: &RecognitionContext) -> BTreeMap<[ActId; 3], ([bool; 6], bool)> {
    let mut output = BTreeMap::new();
    for bid in inputs {
        for accept in inputs {
            for ratify in inputs {
                let Some(SettlementReferences::Ratify { settles, accepts }) = &ratify.body.settlement else {
                    continue;
                };
                if settles != &bid.id || accepts != &accept.id || ratify.finalization_epoch != context.epoch {
                    continue;
                }
                let item = if bid.id.family == "Bid" {
                    Some(&bid.legs[0].target)
                } else {
                    None
                };
                let reference_binding = bid.id.family == "Bid"
                    && accept.id.family == "Accept"
                    && accept.body.settlement == Some(SettlementReferences::Accept { settles: bid.id.clone() });
                let seller = item.and_then(|item| context.owners.get(item));
                let parties = seller == Some(&accept.id.author)
                    && ratify.id.author == bid.id.author
                    && accept.legs[0].target == node("addr", &bid.id.author)
                    && seller.is_some_and(|seller| ratify.legs[0].target == node("addr", seller));
                let mut cancelled = [false; 2];
                for control in inputs {
                    if control.finalization_epoch <= context.epoch
                        && control.legs[0].target == PublicReference::Minted(bid.id.clone())
                    {
                        cancelled[0] |= control.id.family == "Withdraw" && control.id.author == bid.id.author;
                        cancelled[1] |= control.id.family == "Rescind" && seller == Some(&control.id.author);
                    }
                }
                let chain = [bid, accept, ratify];
                let clauses = [
                    chain.iter().all(|act| act.finalization_epoch <= context.epoch),
                    reference_binding,
                    parties,
                    !cancelled[0],
                    !cancelled[1],
                    chain.windows(2).all(|pair| {
                        (pair[0].finalization_epoch, pair[0].authoritative_position)
                            < (pair[1].finalization_epoch, pair[1].authoritative_position)
                    }),
                ];
                let ids = [bid.id.clone(), accept.id.clone(), ratify.id.clone()];
                let recognized = clauses.iter().all(|passed| *passed) && ids.iter().all(|id| !context.consumed.contains(id));
                output.insert(ids, (clauses, recognized));
            }
        }
    }
    output
}

fn compare(inputs: &[CandidateAct], context: &RecognitionContext) {
    let history = validate_history(inputs, &[]).unwrap();
    assert!(
        history
            .time_evidence()
            .iter()
            .all(|e| e.verdict == pn_records::TimeVerdict::Matches)
    );
    let graph = reconstruct(&history, &Approval).unwrap();
    let evidence = recognize_settlements(&graph, &history, &Approval, context).unwrap();
    for row in &evidence {
        let raw = row.acts.each_ref().map(|id| inputs.iter().find(|act| &act.id == id).unwrap());
        assert_eq!(
            row.references,
            [raw[1].body.settlement.clone(), raw[2].body.settlement.clone()]
        );
        assert_eq!(
            row.chain
                .map(|metadata| metadata.map(|metadata| (metadata.position, metadata.logical_time))),
            raw.map(|act| Some(((act.finalization_epoch, act.authoritative_position), act.logical_time)))
        );
        assert_eq!(
            row.consumed,
            row.acts.iter().filter(|id| context.consumed.contains(*id)).cloned().collect()
        );
        for (family, author, witnessed) in [
            ("Withdraw", Some(&raw[0].id.author), &row.withdrawals),
            ("Rescind", context.owners.get(&raw[0].legs[0].target), &row.rescissions),
        ] {
            let mut expected: Vec<_> = inputs
                .iter()
                .filter(|act| {
                    act.id.family == family
                        && Some(&act.id.author) == author
                        && act.finalization_epoch <= context.epoch
                        && act.legs[0].target == PublicReference::Minted(raw[0].id.clone())
                })
                .map(|act| act.id.clone())
                .collect();
            expected.sort();
            assert_eq!(witnessed, &expected);
        }
    }
    let actual: BTreeMap<_, _> = evidence
        .iter()
        .map(|row| {
            let clauses = [
                RecognitionClause::Completeness,
                RecognitionClause::ReferenceBinding,
                RecognitionClause::Authorization,
                RecognitionClause::BuyerConsent,
                RecognitionClause::SellerConsent,
                RecognitionClause::WellFormedness,
            ]
            .map(|clause| row.clauses[&clause]);
            (row.acts.clone(), (clauses, row.recognized))
        })
        .collect();
    assert_eq!(actual, oracle(inputs, context));
}

/// Claim: On compliant histories, six-clause recognition matches an independently enumerated raw-carrier triple oracle across signed stances, earlier/co-epochal/later cancellation, prior-owner premises, each consumed identity and reversed presentations. Distinct parallel Ratify identities remain separate; no title transfer is inferred.
/// ´claim:verification:compliant-recognition-matches-independent-enumerator´
/// ´test:integration:recognition-enumerator´
#[test]
fn recognition_enumerator() {
    for stance in [-1, 0, 1] {
        for withdraw in 0..=3 {
            for rescind in 0..=3 {
                let mut inputs = fixture(stance, withdraw, rescind);
                for premise in 0..5 {
                    let mut context = context();
                    if premise == 1 {
                        context.owners.clear();
                    }
                    if premise >= 2 {
                        context.consumed.insert(
                            inputs
                                .iter()
                                .find(|a| a.id.family == ["Bid", "Accept", "Ratify"][premise - 2])
                                .unwrap()
                                .id
                                .clone(),
                        );
                    }
                    compare(&inputs, &context);
                    inputs.reverse();
                    compare(&inputs, &context);
                }
            }
        }
    }
    let mut inputs = fixture(0, 0, 0);
    let mut parallel = inputs[2].clone();
    parallel.id.sequence = 6;
    parallel.authoritative_position = 6;
    parallel.legs[0].id.act = parallel.id.clone();
    inputs.push(parallel);
    stamp(&mut inputs);
    compare(&inputs, &context());
    assert_eq!(oracle(&inputs, &context()).len(), 2);
    // Unrelated cancels must not defeat the candidate by family alone.
    for wrong_author in [false, true] {
        let mut inputs = fixture(1, 2, 2);
        for input in &mut inputs {
            if matches!(input.id.family.as_str(), "Withdraw" | "Rescind") {
                if wrong_author {
                    input.id.author = "outsider".into();
                    input.legs[0].source = node("addr", "outsider");
                    input.legs[0].id.act = input.id.clone();
                } else {
                    input.legs[0].target = PublicReference::Minted(ActId {
                        family: "Bid".into(),
                        author: "outsider".into(),
                        sequence: 10,
                    });
                }
            }
        }
        stamp(&mut inputs);
        compare(&inputs, &context());
        assert!(oracle(&inputs, &context()).values().all(|(_, recognized)| *recognized));
    }
}

/// Claim: Existing earlier wrong-family settles and accepts targets and a different-Bid Ratify form without rewriting their Actor projections, then receive explicit reference-binding clause (ii) failure on compliant histories. Missing and later targets remain records refusals, not negative recognition evidence.
/// ´claim:verification:wrong-settlement-targets-fail-reference-binding´
/// ´test:integration:recognition-binding´
#[test]
fn recognition_binding() {
    for kind in 0..4 {
        let mut inputs = fixture(1, 0, 0);
        for input in &mut inputs {
            if input.id.family != "Owner" {
                input.authoritative_position += 1;
            }
        }
        let mut other = if kind == 2 {
            bid(0)
        } else {
            act("Registration", "other", 0, 1, node("prof", "other"))
        };
        other.authoritative_position = 2;
        if kind == 0 || kind == 3 {
            inputs[1].body.settlement = Some(SettlementReferences::Accept {
                settles: other.id.clone(),
            });
        }
        if let Some(SettlementReferences::Ratify { settles, accepts }) = &mut inputs[2].body.settlement {
            if kind == 1 {
                *accepts = other.id.clone();
            }
            if kind == 2 || kind == 3 {
                *settles = other.id.clone();
            }
        }
        inputs.push(other);
        stamp(&mut inputs);
        compare(&inputs, &context());
        let history = validate_history(&inputs, &[]).unwrap();
        let graph = reconstruct(&history, &Approval).unwrap();
        let evidence = recognize_settlements(&graph, &history, &Approval, &context()).unwrap();
        assert_eq!(evidence.len(), 1);
        assert!(!evidence[0].targets_bind);
        assert!(!evidence[0].clauses[&RecognitionClause::ReferenceBinding]);
        assert!(!evidence[0].recognized);
    }
}

/// Claim: On compliant histories, record-derived buyer and certified or fresh-thread seller determine authorization clause (iii), separately from reference binding (ii). A third-party Ratify, a misdirected Accept and a misdirected Ratify retain written incidence and exact binding but fail only (iii), preserve the owner and consume no records, with no host fault. The independent enumerator checks every clause and the wrong-party fixture.
/// ´claim:verification:partner-mismatches-fail-record-derived-authorization´
/// ´test:integration:recognition-partners´
#[test]
fn recognition_partners() {
    for kind in 0..3 {
        let mut inputs = fixture(1, 0, 0);
        match kind {
            0 => {
                inputs[2].id.author = "outsider".into();
                inputs[2].legs[0].id.act = inputs[2].id.clone();
                inputs[2].legs[0].source = node("addr", "outsider");
            }
            1 => inputs[1].legs[0].target = node("addr", "outsider"),
            _ => inputs[2].legs[0].target = node("addr", "outsider"),
        }
        stamp(&mut inputs);
        compare(&inputs, &context());
        let history = validate_history(&inputs, &[]).unwrap();
        let graph = reconstruct(&history, &Approval).unwrap();
        let evidence = recognize_settlements(&graph, &history, &Approval, &context()).unwrap();
        assert_eq!(evidence.len(), 1);
        let evidence = &evidence[0];
        assert!(evidence.targets_bind);
        assert_eq!(evidence.partners.ratify_author_is_buyer, kind != 0);
        assert_eq!(evidence.partners.accept_target_is_buyer, kind != 1);
        assert_eq!(evidence.partners.ratify_target_is_seller, kind != 2);
        assert!(!evidence.clauses[&RecognitionClause::Authorization]);
        assert!(
            evidence
                .clauses
                .iter()
                .all(|(clause, passed)| *clause == RecognitionClause::Authorization || *passed)
        );
        assert!(!evidence.recognized);
        // network-v0.31.0, ver:settlement:wrong-party: seller, buyer and
        // outsider play Bob, Carol and Dave; the third case also misdirects Ratify.
        let title = pn_graph::title::replay_title(&graph, &history, &Approval, 2).unwrap();
        assert_eq!(title.certificate[&item()], Some("seller".into()));
        assert_eq!(title.events, []);
        assert!(title.consumed.is_empty());
        assert_eq!(history.parent_faults(), []);
        assert!(
            history
                .time_evidence()
                .iter()
                .all(|row| row.verdict == pn_records::TimeVerdict::Matches)
        );
    }
}

/// Claim: Recognition refuses incomplete graph or boundary premises before returning clauses. Changed published stamps and tombstoned dependencies retain mismatch or unavailable-time evidence without changing clause verdicts or recognition; payload removal preserves all evidence.
/// ´claim:verification:recognition-preserves-unavailable-time-evidence´
/// ´test:integration:recognition-holds´
#[test]
fn recognition_holds() {
    let original = fixture(1, 0, 0);
    let history = validate_history(&original, &[]).unwrap();
    let graph = reconstruct(&history, &Approval).unwrap();
    let expected = recognize_settlements(&graph, &history, &Approval, &context()).unwrap();
    assert!(expected[0].recognized);
    let mut boundary = context();
    boundary.prior_epoch = 0;
    assert_eq!(
        recognize_settlements(&graph, &history, &Approval, &boundary),
        Err(RecognitionError::Boundary)
    );
    let mut partial = graph.clone();
    partial.remove_edge(partial.edge_indices().next().unwrap());
    assert!(matches!(
        recognize_settlements(&partial, &history, &Approval, &context()),
        Err(RecognitionError::Formation(_))
    ));
    for kind in 0..3 {
        let mut inputs = original.clone();
        match kind {
            0 => inputs[2].logical_time = 1,
            1 => inputs[0].projections.dependency = DependencyProjection::Tombstoned((3, 1)),
            _ => inputs[0].projections.content = Removal::Tombstoned((3, 1)),
        }
        let history = validate_history(&inputs, &[]).unwrap();
        let graph = reconstruct(&history, &Approval).unwrap();
        let actual = recognize_settlements(&graph, &history, &Approval, &context());
        if kind == 2 {
            assert_eq!(actual.unwrap(), expected);
        } else if kind == 0 {
            let evidence = actual.unwrap();
            assert_eq!(evidence[0].clauses, expected[0].clauses);
            assert!(evidence[0].recognized);
            assert!(matches!(
                evidence[0].times[2].as_ref().unwrap().verdict,
                pn_records::TimeVerdict::Mismatch { .. }
            ));
        } else {
            let evidence = actual.unwrap();
            assert_eq!(evidence[0].clauses, expected[0].clauses);
            assert!(evidence[0].recognized);
            assert!(matches!(
                evidence[0].times[0].as_ref().unwrap().recomputed,
                pn_records::RecomputedTime::Unavailable(_)
            ));
        }
    }
}

/// Claim: Finalized settlement replay retains absent and misplaced targets with parent-placement evidence and unchanged actor projections. All six clauses are asserted: missing Bid or Accept gives false/false/false/true/true/false, an otherwise valid later target in the boundary gives true/true/true/true/true/false, and a future Accept additionally fails (i). Absent chains have false (vi), never an unevaluated clause; candidate formation still refuses each, title retains the incumbent without consuming these attempts, and mutated replay graphs refuse before recognition evidence escapes.
/// ´claim:verification:settlement-replay-retains-target-placement-faults´
/// ´test:integration:settlement-replay-faults´
#[test]
fn settlement_replay_faults() {
    for kind in 0..5 {
        let mut inputs = fixture(1, 0, 0);
        match kind {
            0 => {
                inputs.remove(0);
            }
            1 => {
                inputs.remove(1);
            }
            2 => {
                inputs[1].finalization_epoch = 2;
                inputs[1].authoritative_position = inputs[2].authoritative_position + 1;
            }
            3 => {
                let key = inputs[0].authoritative_position;
                inputs[0].authoritative_position = inputs[1].authoritative_position;
                inputs[1].authoritative_position = key;
            }
            _ => {
                inputs[1].finalization_epoch = 3;
            }
        }
        stamp(&mut inputs);
        let history = validate_history(&inputs, &[]).unwrap();
        assert_ne!(history.parent_faults(), []);
        let empty = validate_history(&[], &[]).unwrap();
        assert!(pn_records::validate_record(&inputs, &empty, &[]).is_err());
        assert!(reconstruct(&history, &Approval).is_err());
        let graph = pn_graph::formation::reconstruct_replay(&history, &Approval).unwrap();
        assert_eq!(graph.edge_count(), inputs.iter().map(|act| act.legs.len()).sum::<usize>());
        for (actual, input) in history.acts().iter().zip(&inputs) {
            assert_eq!(actual.id(), &input.id);
            assert_eq!(actual.position(), (input.finalization_epoch, input.authoritative_position));
            assert_eq!(actual.logical_time(), input.logical_time);
            assert_eq!(actual.body(), &input.body);
        }
        let evidence = recognize_settlements(&graph, &history, &Approval, &context()).unwrap();
        assert_eq!(evidence.len(), 1);
        let expected = match kind {
            0 | 1 => [false, false, false, true, true, false],
            2 | 3 => [true, true, true, true, true, false],
            _ => [false, true, true, true, true, false],
        };
        assert_eq!(
            evidence[0].clauses,
            BTreeMap::from([
                (RecognitionClause::Completeness, expected[0]),
                (RecognitionClause::ReferenceBinding, expected[1]),
                (RecognitionClause::Authorization, expected[2]),
                (RecognitionClause::BuyerConsent, expected[3]),
                (RecognitionClause::SellerConsent, expected[4]),
                (RecognitionClause::WellFormedness, expected[5]),
            ])
        );
        assert!(!evidence[0].recognized);
        let title = pn_graph::title::replay_title(&graph, &history, &Approval, 2).unwrap();
        assert_eq!(title.certificate[&item()], Some("seller".into()));
        assert_eq!(title.events, []);
        assert!(title.consumed.is_empty());
        assert_eq!(title.boundaries[1].candidates, evidence);
        let mut changed = graph;
        changed.remove_edge(changed.edge_indices().next().unwrap());
        assert!(matches!(
            recognize_settlements(&changed, &history, &Approval, &context()),
            Err(RecognitionError::Formation(_))
        ));
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

fn genesis() -> CandidateAct {
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
    genesis
}

fn title_history() -> Vec<CandidateAct> {
    let genesis = genesis();
    let mut inputs = vec![genesis];
    inputs.extend(handshake(10, 2, "first", "seller"));
    // Shared Bid and Accept; two distinct co-epochal Ratify records conflict.
    let mut twin = inputs.last().unwrap().clone();
    twin.id.sequence = 13;
    twin.authoritative_position = 13;
    twin.legs[0].id.act = twin.id.clone();
    inputs.push(twin);
    inputs.extend(handshake(20, 3, "first", "seller"));
    inputs.extend(handshake(30, 4, "intruder", "seller"));
    inputs.extend(handshake(40, 5, "second", "first"));
    // Reusing consumed Bid and Accept cannot revive recognition after conflict.
    let mut reuse = inputs[3].clone();
    reuse.id.sequence = 50;
    reuse.authoritative_position = 50;
    reuse.finalization_epoch = 3;
    reuse.legs[0].id.act = reuse.id.clone();
    inputs.push(reuse);
    stamp(&mut inputs);
    inputs
}

/// Claim: On compliant histories, full title replay matches an independently specified boundary table for genesis, empty boundaries, shared-record conflicts, fresh retry, prior-owner refusal, resale and consumed-record reuse. Each derived premise reproduces the separately invoked recognition evidence; consumption excludes individual records, not only repeated triples.
/// ´claim:verification:compliant-title-matches-independent-boundary-table´
/// ´test:integration:title-boundaries´
#[test]
fn title_boundaries() {
    use pn_graph::title::replay_title;
    let inputs = title_history();
    // Literal specification table: epoch, owner, newly consumed authored sequences.
    // Neither the fold nor the recognition oracle derives these expectations.
    let table = [
        (0, "", vec![]),
        (1, "seller", vec![]),
        (2, "seller", vec![10, 11, 12, 13]),
        (3, "first", vec![20, 21, 22]),
        (4, "first", vec![]),
        (5, "second", vec![40, 41, 42]),
        (6, "second", vec![]),
    ];
    for reversed in [false, true] {
        let mut presented = inputs.clone();
        if reversed {
            presented.reverse();
        }
        let history = validate_history(&presented, &[]).unwrap();
        let graph = reconstruct(&history, &Approval).unwrap();
        let mut consumed = BTreeSet::new();
        for (epoch, owner, added) in &table {
            for sequence in added {
                consumed.insert(inputs.iter().find(|act| act.id.sequence == *sequence).unwrap().id.clone());
            }
            let replay = replay_title(&graph, &history, &Approval, *epoch).unwrap();
            assert_eq!(
                replay.certificate,
                if *epoch == 0 {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([(item(), Some((*owner).into()))])
                }
            );
            assert_eq!(replay.consumed, consumed);
            for boundary in &replay.boundaries {
                assert_eq!(
                    boundary.candidates,
                    recognize_settlements(&graph, &history, &Approval, &boundary.premises).unwrap()
                );
                let previous = replay_title(&graph, &history, &Approval, boundary.premises.prior_epoch).unwrap();
                assert_eq!(boundary.premises.consumed, previous.consumed);
                let mut owners: BTreeMap<_, _> = previous
                    .certificate
                    .into_iter()
                    .filter_map(|(item, owner)| owner.map(|owner| (item, owner)))
                    .collect();
                if boundary.premises.epoch == 1 {
                    owners.insert(item(), "seller".into());
                }
                assert_eq!(boundary.premises.owners, owners);
            }
        }
        let replay = replay_title(&graph, &history, &Approval, 6).unwrap();
        assert_eq!(replay.boundaries[1].candidates.iter().filter(|c| c.recognized).count(), 2);
        assert!(!replay.boundaries[3].candidates[0].clauses[&RecognitionClause::Authorization]);
        let reuse = replay.boundaries[2]
            .candidates
            .iter()
            .find(|candidate| candidate.acts[2].sequence == 50)
            .unwrap();
        assert_eq!(reuse.consumed.len(), 2);
        assert!(reuse.clauses.values().all(|passed| *passed));
        assert!(!reuse.recognized);
    }
}

/// Claim: Title replay revalidates its complete graph, admits dangling Item endpoints with void title and failed owner authorization before genesis, keeps boundary zero empty, introduces fresh genesis only at its positive boundary, authorizes a same-epoch fresh thread by its genesis owner, and gives ordinary Owner updates no title force. Stamp faults do not change the certificate.
/// ´claim:verification:title-voids-dangling-items-and-keeps-faults-as-evidence´
/// ´test:integration:title-premises´
#[test]
fn title_premises() {
    use pn_graph::title::replay_title;
    let mut inputs = title_history();
    let genesis = inputs.remove(0);
    stamp(&mut inputs);
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &Approval).unwrap();
    let dangling = replay_title(&graph, &history, &Approval, 2).unwrap();
    assert_eq!(dangling.certificate[&item()], None);
    assert!(
        dangling.boundaries[1]
            .candidates
            .iter()
            .all(|candidate| !candidate.clauses[&RecognitionClause::Authorization])
    );
    let mut late = genesis.clone();
    late.finalization_epoch = 3;
    inputs.push(late);
    stamp(&mut inputs);
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &Approval).unwrap();
    let dangling = replay_title(&graph, &history, &Approval, 2).unwrap();
    assert_eq!(dangling.certificate[&item()], None);
    assert!(
        dangling.boundaries[1]
            .candidates
            .iter()
            .all(|candidate| !candidate.clauses[&RecognitionClause::Authorization])
    );
    inputs.retain(|act| act.id.family != "Owner");
    inputs.push(genesis.clone());
    let mut fresh = vec![genesis.clone()];
    fresh.extend(handshake(10, 1, "first", "seller"));
    stamp(&mut fresh);
    let fresh_history = validate_history(&fresh, &[]).unwrap();
    let fresh_graph = reconstruct(&fresh_history, &Approval).unwrap();
    assert!(
        replay_title(&fresh_graph, &fresh_history, &Approval, 0)
            .unwrap()
            .certificate
            .is_empty()
    );
    let entered = replay_title(&fresh_graph, &fresh_history, &Approval, 1).unwrap();
    assert_eq!(entered.boundaries[0].premises.prior_epoch, 0);
    assert_eq!(entered.boundaries[0].premises.owners[&item()], "seller");
    assert!(entered.boundaries[0].candidates[0].clauses[&RecognitionClause::Authorization]);
    assert_eq!(entered.certificate[&item()], Some("first".into()));
    let mut ordinary = genesis;
    ordinary.id.author = "outsider".into();
    ordinary.id.sequence = 100;
    ordinary.finalization_epoch = 4;
    ordinary.authoritative_position = 100;
    ordinary.legs[0].id.act = ordinary.id.clone();
    ordinary.legs[0].source = node("addr", "outsider");
    inputs.push(ordinary);
    stamp(&mut inputs);
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &Approval).unwrap();
    assert!(replay_title(&graph, &history, &Approval, 0).unwrap().certificate.is_empty());
    let replay = replay_title(&graph, &history, &Approval, 6).unwrap();
    assert_eq!(replay.boundaries[0].premises.owners[&item()], "seller");
    assert_eq!(replay.certificate[&item()], Some("second".into()));
    let mut partial = graph.clone();
    partial.remove_edge(partial.edge_indices().next().unwrap());
    assert!(matches!(
        replay_title(&partial, &history, &Approval, 6),
        Err(RecognitionError::Formation(_))
    ));
    inputs.last_mut().unwrap().logical_time = 0;
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &Approval).unwrap();
    let changed = replay_title(&graph, &history, &Approval, 6).unwrap();
    assert_eq!(changed.certificate, replay.certificate);
    assert_eq!(changed.events, replay.events);
}

/// Claim: On compliant histories, recognized conflicts and title-transferring events remain distinct, and successful transfer evidence survives later resale. Selected candidate sets use the identical title fold; rejected sets return no certificate or events and still undergo complete formation validation. Final-set admission remains an explicit caller premise.
/// ´claim:verification:title-events-persist-without-publishing-rejected-sets´
/// ´test:integration:title-events´
#[test]
fn title_events() {
    use pn_graph::title::{FinalSetDecision, TitleOutcome, evaluate_candidate_title, replay_title};
    let inputs = title_history();
    let history = validate_history(&inputs, &[]).unwrap();
    let graph = reconstruct(&history, &Approval).unwrap();
    let replay = replay_title(&graph, &history, &Approval, 6).unwrap();
    let actual: Vec<_> = replay
        .events
        .iter()
        .map(|event| {
            (
                event.epoch,
                event.acts.each_ref().map(|id| id.sequence),
                event.buyer.as_str(),
                event.seller.as_str(),
                event.outcome,
            )
        })
        .collect();
    assert_eq!(
        actual,
        vec![
            (2, [10, 11, 12], "first", "seller", TitleOutcome::Conflict),
            (2, [10, 11, 13], "first", "seller", TitleOutcome::Conflict),
            (3, [20, 21, 22], "first", "seller", TitleOutcome::Transferred),
            (5, [40, 41, 42], "second", "first", TitleOutcome::Transferred),
        ]
    );
    assert!(replay.events.iter().all(|event| event.item == item()));
    let before_resale = replay_title(&graph, &history, &Approval, 3).unwrap();
    assert_eq!(&replay.events[..3], before_resale.events);
    assert_eq!(
        evaluate_candidate_title(&graph, &history, &Approval, 6, FinalSetDecision::Selected).unwrap(),
        Some(replay)
    );
    assert_eq!(
        evaluate_candidate_title(&graph, &history, &Approval, 6, FinalSetDecision::Rejected).unwrap(),
        None
    );
    let mut partial = graph;
    partial.remove_edge(partial.edge_indices().next().unwrap());
    for decision in [FinalSetDecision::Selected, FinalSetDecision::Rejected] {
        assert!(matches!(
            evaluate_candidate_title(&partial, &history, &Approval, 6, decision),
            Err(RecognitionError::Formation(_))
        ));
    }
}

/// Claim: Finalized title uses the epoch-major settlement chain even when positions restart, preserves both Bid projections, and agrees between complete-history replay and each epoch prefix. Dangling Item title stays void and authorization fails before genesis; genesis in the Ratify epoch supplies the fresh owner and earlier genesis supplies the certified owner. No time-evidence premise or future genesis supplies title.
/// ´claim:verification:title-replay-preserves-epoch-and-dangling-semantics´
/// ´test:integration:title-replay-edges´
#[test]
fn title_replay_edges() {
    for genesis_epoch in [None, Some(1), Some(2), Some(3), Some(4)] {
        let mut inputs = handshake(10, 1, "buyer", "seller");
        inputs[0].authoritative_position = 2;
        inputs[1].finalization_epoch = 2;
        inputs[1].authoritative_position = 1;
        inputs[2].finalization_epoch = 3;
        inputs[2].authoritative_position = 1;
        if let Some(epoch) = genesis_epoch {
            let mut owner = genesis();
            owner.finalization_epoch = epoch;
            owner.authoritative_position = if epoch == 2 || epoch == 3 { 2 } else { 1 };
            inputs.push(owner);
        }
        stamp(&mut inputs);
        let history = validate_history(&inputs, &[]).unwrap();
        let graph = pn_graph::formation::reconstruct_replay(&history, &Approval).unwrap();
        assert_eq!(graph.edge_count(), inputs.len() + 1);
        let replay = pn_graph::title::replay_title(&graph, &history, &Approval, 4).unwrap();
        let candidate = &replay.boundaries[2].candidates[0];
        assert!(candidate.clauses[&RecognitionClause::WellFormedness]);
        let anchored = genesis_epoch.is_some_and(|epoch| epoch <= 3);
        assert_eq!(candidate.clauses[&RecognitionClause::Authorization], anchored);
        assert_eq!(candidate.recognized, anchored);
        assert_eq!(replay.boundaries[2].certificate[&item()], anchored.then(|| "buyer".into()));
        for epoch in 0..=4 {
            let prefix: Vec<_> = inputs.iter().filter(|act| act.finalization_epoch <= epoch).cloned().collect();
            let prefix_history = validate_history(&prefix, &[]).unwrap();
            let prefix_graph = pn_graph::formation::reconstruct_replay(&prefix_history, &Approval).unwrap();
            let incremental = pn_graph::title::replay_title(&prefix_graph, &prefix_history, &Approval, epoch).unwrap();
            let full = pn_graph::title::replay_title(&graph, &history, &Approval, epoch).unwrap();
            assert_eq!(incremental, full);
        }
    }
}
