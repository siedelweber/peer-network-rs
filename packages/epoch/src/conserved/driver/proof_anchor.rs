#![cfg(test)]

use std::collections::BTreeMap;

use pn_graph::registration::{OpeningKind, RegistrationVerifier};
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, Quantity,
    RemovableProjections, Removal, Role, StructuralBody, ValidatedAct, validate_history,
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
fn numeric() -> pn_records::numerics::NumericContext {
    pn_records::numerics::NumericContext::new(
        nrz_cas::limits::Limits::default(),
        pn_records::numerics::ComparisonLimits::new(1000, 1000),
    )
    .unwrap()
}

#[derive(Debug)]
struct Publication(Vec<crate::package::EpochBinding>);
impl crate::package::PackageVerifier for Publication {
    fn published_package(&self, input: &crate::package::PackageInput) -> bool {
        input.bindings == self.0
    }
}

fn complete_markers(raw: &mut pn_records::test_support::burn::BurnCase, boundary: u64) {
    let all: std::collections::BTreeSet<_> = raw.history.records.iter().map(|record| record.identity.clone()).collect();
    for marker in raw.history.markers.iter_mut().skip(1) {
        marker.lineage.clone_from(&all);
        marker.accepted = pn_records::burn::AcceptedSet::CompleteList(all.clone());
    }
    while raw.history.markers.last().unwrap().index < boundary {
        let mut next = raw.history.markers.last().unwrap().clone();
        next.predecessor = Some(next.history_position);
        next.index += 1;
        next.history_position += 1;
        next.name = format!("m{}", next.index);
        raw.history.markers.push(next);
    }
}

fn package_at_prices(
    acts: &[CandidateAct],
    boundary: u64,
    burns: &[(&str, &str)],
    wall_texts: &[&str],
    numeraires: &[&str],
) -> crate::package::VerifiedPackage {
    use pn_records::{burn::Address, test_support::burn};
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
    complete_markers(&mut raw, boundary);
    let markers = burn::recognize(raw).unwrap();
    let history = history(acts);
    let mut inputs = Vec::new();
    let mut prices = Vec::new();
    let mut bindings = Vec::new();
    for epoch in 1..=boundary {
        let (mut declaration, mut edition, mut parameters) = fixture();
        if let Some(value) = numeraires.get(usize::try_from(epoch - 1).unwrap()) {
            declaration.id.edition = epoch;
            declaration.announced_at = epoch - 1;
            declaration.effective_at = epoch;
            edition.id = declaration.id.clone();
            parameters.edition = declaration.id.clone();
            for profile in &mut parameters.profiles {
                profile.edition = declaration.id.clone();
            }
            let literal = numeric.literal(value).unwrap();
            let amount = numeric.burn_per_action(&literal, "burn").unwrap();
            let numeraire = numeric.numeraire("nu", &amount).unwrap();
            edition.numeraire = numeraire.clone();
            parameters.numeraire = numeraire;
        }
        parameters.boundary = epoch;
        // The literal compiler oracle uses unit domain weights and one hop.
        for name in parameters.domain_weights.values_mut() {
            *name = "one".into();
        }
        parameters.depth_mass = vec!["one".into()];
        let empty = validate_history(&[], &[]).unwrap();
        let record = pn_records::validate_record(&[], &empty, &[declaration]).unwrap();
        let constants = pn_records::constants::bind_constants(&record, vec![edition]).unwrap();
        let input = crate::bind_inputs(&constants, parameters, nrz_cas::limits::Limits::default()).unwrap();
        let literal = numeric.literal(wall_texts[usize::try_from(epoch - 1).unwrap()]).unwrap();
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
        bindings.push(crate::package::EpochBinding {
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
    crate::package::verify_package(
        crate::package::PackageInput {
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

use crate::{FamilyProfile, ParameterInput};
use pn_records::constants::{ConstantDefinition, EditionInput};
use pn_records::numerics::{ComparisonLimits, ExactLimits, Floor, NumericContext};
use pn_records::{Declaration, DeclarationContent, DeclarationId};
fn fixture() -> (Declaration, EditionInput, ParameterInput) {
    let mut c = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
    let one = c.literal("1").unwrap();
    let unit = c.burn_per_action(&one, "burn").unwrap();
    let numeraire = c.numeraire("nu", &unit).unwrap();
    let id = DeclarationId {
        namespace: "numeric".into(),
        name: "constants".into(),
        edition: 1,
    };
    let declaration = Declaration {
        id: id.clone(),
        announced_at: 0,
        effective_at: 1,
        content: DeclarationContent::Opaque,
    };
    let definitions = [
        ("one", "1"),
        ("zero", "0"),
        ("negative", "-1/3"),
        ("third", "1/3"),
        ("rest", "2/3"),
        ("hops", "4"),
        ("bleed", "1/400"),
    ]
    .into_iter()
    .map(|(name, value)| ConstantDefinition::Literal {
        name: name.into(),
        value: c.literal(value).unwrap(),
    })
    .collect();
    let edition = EditionInput {
        id: id.clone(),
        floor: Floor::RationalThreeThirtySevenths,
        numeraire: numeraire.clone(),
        formula_edition: "formula".into(),
        controller_edition: "controller".into(),
        constants: definitions,
        permitted_overrides: vec![],
        domain_profiles: vec!["declared".into()],
        numerical_procedure: "exact-rational".into(),
        authentication_realization: "declared".into(),
        publication_profile: "internal".into(),
    };
    let mut profiles: Vec<_> = [
        ("Registration", "Identity"),
        ("Publish", "Economic"),
        ("Owner", "Economic"),
        ("Bid", "Economic"),
        ("Opinion", "Tribal"),
        ("Affinity", "Epistemic"),
        ("Tag", "Epistemic"),
        ("Participant", "Relational"),
        ("Invitation", "Relational"),
        ("Review", "Tribal"),
        ("Reference", "Epistemic"),
        ("Join Request", "Relational"),
        ("Accept", "Relational"),
        ("Ratify", "Relational"),
        ("Send", "Minimal"),
        ("De-invite", "Minimal"),
        ("Leave", "Minimal"),
        ("Withdraw", "Minimal"),
        ("Rescind", "Minimal"),
    ]
    .into_iter()
    .map(|(family, domain)| FamilyProfile {
        family: family.into(),
        name: "declared".into(),
        edition: id.clone(),
        weights: BTreeMap::from([(domain.into(), "one".into())]),
    })
    .collect();
    profiles[7].weights = BTreeMap::from([("Relational".into(), "third".into()), ("Epistemic".into(), "rest".into())]);
    let input = ParameterInput {
        boundary: 1,
        edition: id,
        numeraire,
        profiles,
        domain_weights: ["Identity", "Economic", "Tribal", "Epistemic", "Relational", "Minimal"]
            .into_iter()
            .map(|domain| (domain.into(), if domain == "Economic" { "rest" } else { "one" }.into()))
            .collect(),
        hop_limit: "hops".into(),
        self_base: "one".into(),
        depth_mass: vec!["third".into(), "rest".into()],
    };
    (declaration, edition, input)
}

use nrz_cas::limits::Limits;
use pn_records::solve::{Equality, Precision, Primitive, Procedure};
use std::collections::BTreeSet;

fn frozen_state(buyer: &str, opinion: bool) -> crate::compiler::CompiledState {
    let mut acts = vec![act("Registration", "seller", 1, 1), act("Registration", "buyer", 2, 1)];
    if opinion {
        acts.push(act("Opinion", "seller", 3, 1));
    }
    crate::compiler::compile_final_state(
        &package_at_prices(&acts, 1, &[("seller", "50"), ("buyer", buyer)], &["1"], &[]),
        &Verifier,
        &mut numeric(),
        Limits::default(),
        10000,
    )
    .unwrap()
}

#[derive(Debug)]
struct Published(Procedure);
impl crate::solve::ProcedureVerifier for Published {
    fn published_procedure(&self, p: &Procedure) -> bool {
        p == &self.0
    }
}
fn procedure(state: &crate::compiler::CompiledState) -> Procedure {
    let inputs = state.package().input().inputs.last().unwrap();
    let limits = Limits {
        work: 10_000_000,
        ..Limits::default()
    };
    Procedure {
        edition: inputs.parameters().edition.clone(),
        boundary: 1,
        name: inputs.constants().content().numerical_procedure.clone(),
        backend: "nrz-cas".into(),
        primitives: BTreeSet::from([
            Primitive::Rational,
            Primitive::Root,
            Primitive::Exponential,
            Primitive::Logarithm,
            Primitive::Power,
            Primitive::Sigmoid,
            Primitive::Tanh,
            Primitive::SmoothDerivative,
            Primitive::ClampGeneralized,
        ]),
        precision: Precision::AbsoluteWidthBits(vec![4]),
        equality: Equality::ExactRationalOnly,
        grid: vec!["0".into()],
        margin: "5/4".into(),
        maximum_work: limits.work,
        maximum_solve_work: limits.work,
        maximum_replay_work: limits.work,
        maximum_iterations: 2,
        endpoint_grid: "1/64".into(),
        fence: Some(pn_records::solve::FenceProfile {
            bleed_squared: "bleed".into(),
            shape: vec!["one".into(), "rest".into(), "third".into(), "zero".into()],
            inverse_wall: false,
        }),
        enclosure: Some(pn_records::primitive::EnclosurePolicy {
            store: limits.clone(),
            operation: limits,
            refinement: nrz_cas::enclosure::RefinementPolicy {
                version: 1,
                precision: 4,
                grid_ceiling: 64,
                rounds: 1,
                reduction_ceiling: 4,
                term_ceiling: 64,
                checking_work: 0,
            },
        }),
    }
}

/// Claim: The existing fence join accepts the producer's certificate-free zero anchor and refuses a nonzero accepted upper endpoint, an inadmissible empty transcript, a changed hull and a changed accepted rung, without conserved solve or replay.
/// ´claim:numerics:exact-anchor-requires-its-empty-proof-conditions´
/// ´test:unit:proof-anchor´
#[test]
fn proof_anchor() {
    let state = frozen_state("100", true);
    let p = procedure(&state);
    let bound = crate::solve::bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
    let made = crate::fence::search(&bound, None).unwrap();
    assert_eq!(made.evidence.primitives, []);
    assert!(made.evidence.attempts.iter().all(|a| a.primitives.is_empty()));
    assert!(super::fence(&bound, &made.evidence, "0").unwrap().is_zero());
    assert_eq!(made.evidence.attempts.len(), 1, "single-attempt anchor control");
    let mut upper = made.evidence.clone();
    upper.attempts[0].margined_fence.upper = "1/2".into();
    assert!(
        matches!(super::fence(&bound, &upper, "0"), Err(super::Error::Scope)),
        "nonzero anchor upper endpoint"
    );
    let mut hull = made.evidence.clone();
    hull.hull.clear();
    assert!(
        matches!(super::fence(&bound, &hull, "0"), Err(super::Error::Scope)),
        "changed frozen hull"
    );
    assert!(
        matches!(super::fence(&bound, &made.evidence, "1"), Err(super::Error::Scope)),
        "changed accepted rung"
    );
    let mut p = procedure(&state);
    p.grid = vec!["1".into(), "0".into()];
    let bound = crate::solve::bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
    let mut empty = made.evidence;
    assert!(
        empty.hull.values().any(|r| r.lower != r.upper),
        "fixture has nonzero contributing width"
    );
    empty.attempts[0].rung = "1".into();
    assert!(
        matches!(super::fence(&bound, &empty, "1"), Err(super::Error::Scope)),
        "empty proof at nonzero width and rung"
    );
    let point_state = frozen_state("50", false);
    let mut p = procedure(&point_state);
    p.grid = vec!["1".into(), "0".into()];
    let bound = crate::solve::bind_procedure(&point_state, p.clone(), &Published(p), Limits::default()).unwrap();
    let point = crate::fence::search(&bound, None).unwrap();
    assert!(!point.evidence.hull.is_empty());
    assert!(
        point.evidence.hull.values().all(|r| r.lower == r.upper),
        "equal burns produce a point hull"
    );
    assert_eq!(point.evidence.attempts.len(), 1);
    assert_eq!(point.evidence.attempts[0].rung, "1");
    assert_eq!(point.evidence.primitives, []);
    assert!(
        matches!(super::fence(&bound, &point.evidence, "1"), Ok(value) if value.is_zero()),
        "nonzero-rung point anchor"
    );
    let mut nonpass = point.evidence;
    let mut failed = nonpass.attempts[0].clone();
    failed.completion = pn_records::solve::Completion::Fail;
    failed.margined_fence.lower = "2".into();
    failed.margined_fence.upper = "2".into();
    nonpass.attempts[0].rung = "0".into();
    nonpass.attempts.insert(0, failed);
    pn_records::solve::validate_evidence(bound.inputs().1, &nonpass, Limits::default()).unwrap();
    assert!(
        matches!(super::fence(&bound, &nonpass, "0"), Err(super::Error::Scope)),
        "non-Pass empty attempt"
    );
}
