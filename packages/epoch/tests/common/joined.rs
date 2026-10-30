use std::collections::BTreeMap;

use pn_graph::registration::{OpeningKind, RegistrationVerifier};
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, Quantity,
    RemovableProjections, Removal, Role, SettlementReferences, StructuralBody, ValidatedAct, validate_history,
};

#[derive(Debug)]
pub(crate) struct Verifier;
impl RegistrationVerifier for Verifier {
    fn approval(&self, _: &ValidatedAct) -> bool {
        true
    }
    fn removal(&self, _: &ValidatedAct, _: OpeningKind, _: Position) -> bool {
        true
    }
}

pub(crate) fn named(namespace: &str, name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: name.into(),
    }
}
pub(crate) fn id(family: &str, author: &str, sequence: u64) -> ActId {
    ActId {
        family: family.into(),
        author: author.into(),
        sequence,
    }
}
fn minted(family: &str, author: &str, sequence: u64) -> PublicReference {
    PublicReference::Minted(id(family, author, sequence))
}
pub(crate) fn coordinates(act: &mut CandidateAct, names: &[&str], numerator: i64) {
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
pub(crate) fn act(family: &str, author: &str, sequence: u64, epoch: u64) -> CandidateAct {
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
pub(crate) fn positions(inputs: &[CandidateAct]) -> Vec<CandidateAct> {
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
pub(crate) fn history(inputs: &[CandidateAct]) -> pn_records::ValidatedHistory {
    let placed = positions(inputs);
    let history = validate_history(&placed, &[]).unwrap();
    assert_eq!(
        history.acts().iter().map(ValidatedAct::id).collect::<Vec<_>>(),
        inputs.iter().map(|act| &act.id).collect::<Vec<_>>()
    );
    history
}
pub(crate) fn anchors() -> Vec<CandidateAct> {
    vec![
        act("Registration", "seller", 1, 1),
        act("Registration", "buyer", 2, 1),
        act("Registration", "third", 3, 1),
    ]
}

pub(crate) fn settlement() -> Vec<CandidateAct> {
    let mut inputs = anchors();
    inputs.push(act("Owner", "seller", 4, 1));
    inputs.extend(handshake("buyer", "seller", 5, 2));
    inputs
}
pub(crate) fn handshake(buyer: &str, seller: &str, sequence: u64, epoch: u64) -> Vec<CandidateAct> {
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

pub(crate) fn numeric() -> pn_records::numerics::NumericContext {
    pn_records::numerics::NumericContext::new(
        nrz_cas::limits::Limits::default(),
        pn_records::numerics::ComparisonLimits::new(1000, 1000),
    )
    .unwrap()
}

#[derive(Debug)]
struct Publication(Vec<pn_epoch::package::EpochBinding>);
impl pn_epoch::package::PackageVerifier for Publication {
    fn published_package(&self, input: &pn_epoch::package::PackageInput) -> bool {
        input.bindings == self.0
    }
}

pub(crate) fn package(acts: &[CandidateAct], boundary: u64, burns: &[(&str, &str)]) -> pn_epoch::package::VerifiedPackage {
    use pn_records::{
        burn::{AcceptedSet, Address},
        test_support::burn,
    };
    let mut numeric = numeric();
    let mut raw = burn::generate(&[9]);
    let template = raw.history.records[0].clone();
    raw.history.records.clear();
    for (index, (author, value)) in burns.iter().enumerate() {
        let address = Address((*author).into());
        let literal = numeric.literal(value).unwrap();
        let amount = numeric.burn(&literal, "burn").unwrap();
        raw.burn.read_addresses.insert(address.clone());
        raw.burn.amounts.insert(address.clone(), amount.clone());
        let mut record = template.clone();
        record.identity = format!("r{index}");
        record.destruction = format!("d{index}");
        record.address = address;
        record.amount = amount;
        record.evidence = format!(
            "{}:{}:{}:{}",
            record.destruction,
            record.address.0,
            record.amount.exact(),
            record.amount.unit()
        )
        .into_bytes();
        raw.history.records.push(record);
    }
    let all: std::collections::BTreeSet<_> = raw.history.records.iter().map(|record| record.identity.clone()).collect();
    for marker in raw.history.markers.iter_mut().skip(1) {
        marker.lineage.clone_from(&all);
        marker.accepted = AcceptedSet::CompleteList(all.clone());
    }
    let markers = burn::recognize(raw).unwrap();
    let history = history(acts);
    let mut inputs = Vec::new();
    let mut prices = Vec::new();
    let mut bindings = Vec::new();
    for epoch in 1..=boundary {
        let (declaration, edition, mut parameters) = crate::common::fixture();
        parameters.boundary = epoch;
        // The literal compiler oracle uses unit domain weights and one hop.
        for name in parameters.domain_weights.values_mut() {
            *name = "one".into();
        }
        parameters.depth_mass = vec!["one".into()];
        let empty = validate_history(&[], &[]).unwrap();
        let record = pn_records::validate_record(&[], &empty, &[declaration]).unwrap();
        let constants = pn_records::constants::bind_constants(&record, vec![edition]).unwrap();
        let input = pn_epoch::bind_inputs(&constants, parameters, nrz_cas::limits::Limits::default()).unwrap();
        let literal = numeric.literal("2").unwrap();
        let wall = numeric.computed(&literal).unwrap();
        let price = numeric
            .charged_price(&wall, &input.parameters().numeraire, input.constants().content().floor)
            .unwrap();
        let mut sequence: Vec<_> = history
            .acts()
            .iter()
            .filter(|act| act.position().0 == epoch)
            .cloned()
            .collect();
        sequence.sort_by_key(ValidatedAct::position);
        let index = usize::try_from(epoch).unwrap();
        bindings.push(pn_epoch::package::EpochBinding {
            marker: markers.markers()[index].identity().clone(),
            predecessor: markers.markers()[index - 1].identity().clone(),
            inputs: input.clone(),
            price: price.clone(),
            sequence,
        });
        inputs.push(input);
        prices.push(price);
    }
    let publication = Publication(bindings.clone());
    pn_epoch::package::verify_package(
        pn_epoch::package::PackageInput {
            markers,
            history,
            inputs,
            prices,
            bindings,
        },
        &publication,
    )
    .unwrap()
}

pub(crate) fn reordered_package(
    acts: &[CandidateAct],
    boundary: u64,
    burns: &[(&str, &str)],
) -> pn_epoch::package::VerifiedPackage {
    let original = package(acts, boundary, burns);
    let mut input = original.input().clone();
    let mut reordered = positions(acts);
    let last = reordered.len() - 1;
    let earlier = reordered[last - 1].authoritative_position;
    reordered[last - 1].authoritative_position = reordered[last].authoritative_position;
    reordered[last].authoritative_position = earlier;
    input.history = validate_history(&reordered, &[]).unwrap();
    for binding in &mut input.bindings {
        binding.sequence = input
            .history
            .acts()
            .iter()
            .filter(|act| act.position().0 == binding.marker.index)
            .cloned()
            .collect();
        binding.sequence.sort_by_key(ValidatedAct::position);
    }
    let publication = Publication(input.bindings.clone());
    pn_epoch::package::verify_package(input, &publication).unwrap()
}
