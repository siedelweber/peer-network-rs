//! Canonical public storage values; field order belongs to the admitted v1 recipe.
use pn_interchange::{Array, Value};
use pn_records::burn::{self, AcceptedSet, BurnInput, BurnRecord, Marker, PolicyInput};
use pn_records::constants::{ConstantDefinition, ConstantsEdition};
use pn_records::numerics::{BurnAmount, Floor};

pub(crate) fn text(value: &str) -> Value {
    Value::Text(value.to_owned().into())
}
pub(crate) fn array(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(values))
}
fn strings<'a>(values: impl IntoIterator<Item = &'a String>) -> Value {
    array(values.into_iter().map(|s| text(s)))
}
fn optional<T>(value: Option<&T>, encode: impl FnOnce(&T) -> Value) -> Value {
    value.map_or(Value::Null, encode)
}
fn amount(value: &BurnAmount) -> Value {
    array([text(value.exact()), text(value.unit())])
}
fn amounts(values: &std::collections::BTreeMap<burn::Address, BurnAmount>) -> Value {
    array(values.iter().map(|(address, value)| array([text(&address.0), amount(value)])))
}
pub(crate) fn publication(value: &BurnInput) -> Value {
    let BurnInput {
        address_space,
        edition,
        sample_convention,
        boundary,
        read_addresses,
        amounts: samples,
        bootstrap,
        unit_cost,
        evidence,
    } = value;
    let burn::BurnEvidence {
        edition: evidence_edition,
        sample_convention: evidence_convention,
        settlement_depth,
        finality_assumptions,
        provenance,
        recording_costs,
        operator,
    } = evidence;
    array([
        text(address_space),
        text(edition),
        text(sample_convention),
        Value::Unsigned(*boundary),
        array(read_addresses.iter().map(|v| text(&v.0))),
        amounts(samples),
        optional(bootstrap.as_ref(), |v| {
            array([amount(&v.bound), Value::Bool(v.empty_interval), text(&v.explanation)])
        }),
        optional(unit_cost.as_ref(), |v| {
            let (exact, denomination, unit, terms) = v.disclosure();
            array([text(exact), text(denomination), text(unit), text(terms)])
        }),
        array([
            text(evidence_edition),
            text(evidence_convention),
            settlement_depth.map_or(Value::Null, Value::Unsigned),
            optional(finality_assumptions.as_ref(), |v| text(v)),
            optional(provenance.as_ref(), |v| text(v)),
            optional(recording_costs.as_ref(), |v| {
                array(v.iter().map(|v| {
                    let (exact, denomination, terms) = v.disclosure();
                    array([text(exact), text(denomination), text(terms)])
                }))
            }),
            optional(operator.as_ref(), |v| match v {
                burn::OperatorEvidence::Bound { amount: bound, proof } => array([text("bound"), amount(bound), text(proof)]),
                burn::OperatorEvidence::Absent { explanation } => array([text("absent"), text(explanation)]),
            }),
        ]),
    ])
}
pub(crate) fn policy(value: &PolicyInput) -> Value {
    let PolicyInput {
        identity,
        edition,
        sequence,
        published_at,
        genesis_at,
        initial_marker,
        open_placement,
        placement_procedure,
        cadence,
        encoding,
        candidate_rule,
        verification_profile,
        stability_buffer,
    } = value;
    array([
        text(identity),
        text(edition),
        text(sequence),
        Value::Unsigned(*published_at),
        Value::Unsigned(*genesis_at),
        text(initial_marker),
        Value::Bool(*open_placement),
        text(placement_procedure),
        text(cadence),
        text(match encoding {
            burn::Encoding::CompleteList => "complete-list",
            burn::Encoding::PublicCommitment => "public-commitment",
            burn::Encoding::WholePrefixAcceptAll => "whole-prefix",
        }),
        text(match candidate_rule {
            burn::CandidateRule::FirstValidInHistoryOrder => "first-valid",
            burn::CandidateRule::UniquePerIndex => "unique-per-index",
        }),
        text(verification_profile),
        Value::Unsigned(*stability_buffer),
    ])
}
fn record(value: &BurnRecord) -> Value {
    let BurnRecord {
        identity,
        destruction,
        address,
        amount: value,
        evidence,
    } = value;
    array([
        text(identity),
        text(destruction),
        text(&address.0),
        amount(value),
        Value::Bytes(evidence.clone().into()),
    ])
}
fn marker(value: &Marker) -> Value {
    let Marker {
        name,
        history,
        policy_identity,
        policy_edition,
        sequence,
        index,
        history_position,
        predecessor,
        lineage,
        accepted,
        initial_snapshot,
    } = value;
    array([
        text(name),
        text(history),
        text(policy_identity),
        text(policy_edition),
        text(sequence),
        Value::Unsigned(*index),
        Value::Unsigned(*history_position),
        predecessor.map_or(Value::Null, Value::Unsigned),
        strings(lineage),
        match accepted {
            AcceptedSet::CompleteList(members) => array([text("complete-list"), strings(members)]),
            AcceptedSet::WholePrefix => array([text("whole-prefix")]),
            AcceptedSet::Commitment { commitment, openings } => array([
                text("commitment"),
                Value::Bytes(commitment.clone().into()),
                array(
                    openings
                        .iter()
                        .map(|opening| array([strings(&opening.members), Value::Bytes(opening.proof.clone().into())])),
                ),
            ]),
        },
        optional(initial_snapshot.as_ref(), amounts),
    ])
}
pub(crate) fn disclosure(value: &burn::ValidatedMarkerHistory) -> Value {
    let (history, policy_input, burn) = value.disclosure();
    // Presentation order is not history order. Validation guarantees unique
    // record identities and disclosed positions; retain every candidate.
    let mut records: Vec<_> = history.records.iter().collect();
    records.sort_by(|a, b| a.identity.cmp(&b.identity));
    let mut markers: Vec<_> = history.markers.iter().collect();
    markers.sort_by_key(|v| v.history_position);
    array([
        text(&history.identity),
        array(records.into_iter().map(record)),
        array(markers.into_iter().map(marker)),
        policy(policy_input),
        publication(burn),
    ])
}
pub(crate) fn recognition(value: &burn::RecognizedMarkers) -> Value {
    let basis = value.basis();
    array([
        array([
            text(&basis.history),
            text(&basis.policy_identity),
            text(&basis.policy_edition),
            text(&basis.verifier_profile),
            text(&basis.burn_publication_edition),
            text(&basis.sample_convention),
        ]),
        array(value.markers().iter().map(|v| {
            array([
                marker(v.identity()),
                strings(v.accepted()),
                array(v.destructions().values().map(record)),
            ])
        })),
        optional(value.first_refusal(), |v| {
            array([
                optional(v.candidate.as_ref(), marker),
                cause(&v.cause),
                array(v.competitors.iter().map(marker)),
            ])
        }),
        text("unsettled"),
    ])
}
pub(crate) fn cause(value: &burn::BurnError) -> Value {
    use burn::BurnError as E;
    // Recognition cannot produce declaration binding errors. Keep the enum
    // exhaustive so a new refusal requires an explicit representation review.
    text(match value {
        E::PolicySelection(_) => "policy-selection",
        E::PolicyBinding => "policy-binding",
        E::DeploymentBinding => "deployment-binding",
        E::PolicyDigest => "policy-digest",
        E::UnsupportedPolicyRecipe => "unsupported-policy-recipe",
        E::Publication(_) => "publication",
        E::EvidenceBinding => "evidence-binding",
        E::SampleCoverage => "sample-coverage",
        E::Units => "units",
        E::Bootstrap => "bootstrap",
        E::Policy => "policy",
        E::Buffer => "buffer",
        E::Verifier => "verifier",
        E::RecordIdentity => "record-identity",
        E::HistoryPolicy => "history-policy",
        E::HistoryPosition => "history-position",
        E::Initial => "initial",
        E::Succession => "succession",
        E::MissingLineage => "missing-lineage",
        E::RegressedLineage => "regressed-lineage",
        E::Encoding => "encoding",
        E::MissingOpening => "missing-opening",
        E::AmbiguousOpening => "ambiguous-opening",
        E::InvalidOpening => "invalid-opening",
        E::RegressedAcceptance => "regressed-acceptance",
        E::OutOfLineage => "out-of-lineage",
        E::InvalidMember => "invalid-member",
        E::InconsistentAlias => "inconsistent-alias",
    })
}
fn definition(value: &ConstantDefinition) -> Value {
    match value {
        ConstantDefinition::Literal { name, value } => {
            array([text("literal"), text(name), text(value.source()), text(value.exact())])
        }
        ConstantDefinition::Expression {
            name,
            expression,
            source_label,
        } => array([text("expression"), text(name), text(expression), text(source_label)]),
    }
}
pub(crate) fn constants(value: &ConstantsEdition) -> Value {
    let pn_records::constants::EditionInput {
        id,
        floor,
        numeraire,
        formula_edition,
        controller_edition,
        constants,
        permitted_overrides,
        domain_profiles,
        numerical_procedure,
        authentication_realization,
        publication_profile,
    } = value.content();
    array([
        array([text(&id.namespace), text(&id.name), Value::Unsigned(id.edition)]),
        text(match floor {
            Floor::RationalThreeThirtySevenths => "rational-3/37",
            Floor::RidgeImage => "ridge-image",
        }),
        array([
            text(numeraire.identity()),
            text(numeraire.amount().exact()),
            text(numeraire.amount().unit()),
        ]),
        text(formula_edition),
        text(controller_edition),
        array(constants.iter().map(definition)),
        strings(permitted_overrides),
        strings(domain_profiles),
        text(numerical_procedure),
        text(authentication_realization),
        text(publication_profile),
        definition(value.floor_source()),
    ])
}
