use std::collections::BTreeMap;

use pn_epoch::{CompilerInputs, bind_inputs};
use pn_records::constants::{ConstantDefinition, bind_constants};
use pn_records::numerics::{ComparisonLimits, ExactLimits, NumericContext};
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, Quantity,
    RemovableProjections, Removal, Role, StructuralBody, ValidatedAct, ValidatedHistory, validate_history, validate_record,
};

#[derive(Debug)]
pub(crate) struct Verifier;
impl pn_graph::registration::RegistrationVerifier for Verifier {
    fn approval(&self, act: &ValidatedAct) -> bool {
        act.authentication_evidence() == [1]
    }
    fn removal(&self, _: &ValidatedAct, _: pn_graph::registration::OpeningKind, _: Position) -> bool {
        true
    }
}

pub(crate) fn inputs() -> CompilerInputs {
    let (declaration, mut edition, mut input) = crate::common::fixture();
    let mut numeric = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(1000, 1000)).unwrap();
    for (name, value) in [("two", "2"), ("three", "3"), ("four", "4")] {
        edition.constants.push(ConstantDefinition::Literal {
            name: name.into(),
            value: numeric.literal(value).unwrap(),
        });
    }
    input.domain_weights.insert("Epistemic".into(), "two".into());
    input.domain_weights.insert("Tribal".into(), "three".into());
    input.domain_weights.insert("Economic".into(), "four".into());
    let reference = input
        .profiles
        .iter_mut()
        .find(|profile| profile.family == "Reference")
        .unwrap();
    reference.weights = BTreeMap::from([("Epistemic".into(), "third".into()), ("Tribal".into(), "rest".into())]);
    let empty = validate_history(&[], &[]).unwrap();
    let records = validate_record(&[], &empty, &[declaration]).unwrap();
    let constants = bind_constants(&records, vec![edition]).unwrap();
    bind_inputs(&constants, input, ExactLimits::default()).unwrap()
}

pub(crate) fn named(namespace: &str, name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: name.into(),
    }
}

pub(crate) fn act(
    position: u64,
    author: &str,
    family: &str,
    target: PublicReference,
    coordinates: &[(&str, i64, i64)],
) -> CandidateAct {
    let id = ActId {
        author: author.into(),
        sequence: position,
        family: family.into(),
    };
    CandidateAct {
        commitments: None,
        id: id.clone(),
        body: StructuralBody {
            settlement: None,
            license: None,
            asserted_parents: vec![],
            layout: Layout::Binary,
            quantities: coordinates
                .iter()
                .flat_map(|(name, n, d)| [(format!("{name}.numerator"), *n), (format!("{name}.denominator"), *d)])
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
                .collect(),
        },
        legs: vec![CandidateLeg {
            id: EdgeId {
                act: id,
                role: Role::Binary,
            },
            source: named("addr", author),
            target,
            removal: None,
        }],
        projections: RemovableProjections {
            content: Removal::Live,
            dependency: DependencyProjection::FullEmpty,
        },
        protocol_references: vec![],
        authentication_evidence: vec![1],
        finalization_epoch: 1,
        authoritative_position: position,
        logical_time: position,
    }
}

pub(crate) fn acts() -> Vec<CandidateAct> {
    let mut acts: Vec<_> = ["address-2", "address-3", "address-4"]
        .into_iter()
        .enumerate()
        .map(|(index, author)| {
            act(
                u64::try_from(index).unwrap() + 1,
                author,
                "Registration",
                named("prof", author),
                &[],
            )
        })
        .collect();
    let mut reference = act(
        4,
        "address-2",
        "Reference",
        named("name", "citing-artifact"),
        &[("effort", 1, 2), ("enthusiasm", 1, 2)],
    );
    reference.body.layout = Layout::Paired;
    reference.legs[0].id.role = Role::A;
    reference.legs.push(CandidateLeg {
        id: EdgeId {
            act: reference.id.clone(),
            role: Role::T,
        },
        source: reference.legs[0].target.clone(),
        target: named("prof", "address-3"),
        removal: None,
    });
    acts.push(reference);
    for position in [5, 6] {
        acts.push(act(
            position,
            "address-2",
            "Opinion",
            named("prof", "address-3"),
            &[("polarity", 1, 4), ("reaction", 1, 4)],
        ));
    }
    acts.push(act(
        7,
        "address-2",
        "Publish",
        PublicReference::Minted(ActId {
            author: "content-author".into(),
            sequence: 99,
            family: "Publish".into(),
        }),
        &[("attachment", 1, 2)],
    ));
    acts.push(act(
        8,
        "address-2",
        "Opinion",
        named("name", "artifact"),
        &[("polarity", 1, 2), ("reaction", 1, 2)],
    ));
    acts
}

pub(crate) fn history(acts: &[CandidateAct]) -> ValidatedHistory {
    validate_history(acts, &[]).unwrap()
}
