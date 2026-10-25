//! Scoped binary formation; unsupported families refuse as whole acts.
//! (´def:formation:affinity´)

use petgraph::stable_graph::StableDiGraph;
use pn_records::{Layout, Position, PublicReference, Role, ValidatedAct, ValidatedHistory};
use serde::{Deserialize, Serialize};

use crate::registration::{self, GroundedNode, RegistrationError, RegistrationProjection, RegistrationVerifier};

/// Disjoint grounded and public-name constructors in this implemented scope.
/// Type names are exact strings; no normalization or minting is performed.
/// (´def:formation:affinity´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Node {
    /// Existing Actor/Profile constructors, shared with Registration.
    Grounded(GroundedNode),
    /// The public string commons constructor name(s), interpreted as Type.
    Type(String),
}

/// An exact bounded carrier for a signed unit-interval coordinate.
/// Construction and deserialization do not establish validity; formation checks
/// a positive denominator and absolute numerator no greater than denominator.
/// (´def:formation:affinity´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coordinate {
    /// Authored integer numerator, retained without rounding.
    pub numerator: i64,
    /// Authored positive integer denominator, retained without normalization.
    pub denominator: i64,
}

/// Complete Affinity binary weight; coordinates remain distinct directional roles.
/// (´def:formation:affinity´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffinityProjection {
    /// Author atom shared with the initiating Actor endpoint.
    pub author: String,
    /// Author-local sequence, never host order.
    pub sequence: u64,
    /// Retained epoch-qualified published placement.
    pub position: Position,
    /// Retained host attachment; this operation gives no recurrence verdict.
    pub logical_time: u64,
    /// Association occupies the directional role `p_d`.
    pub association: Coordinate,
    /// Attraction occupies the intensity role `p_i`.
    pub attraction: Coordinate,
}

/// Distinct supported families, preserving each complete authored projection.
/// (´def:formation:affinity´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Projection {
    /// Existing Registration projection, with its fixed coordinate roles.
    Registration(RegistrationProjection),
    /// Affinity projection, with both required authored coordinates.
    Affinity(AffinityProjection),
}

/// Direct diagnostic backend, requiring revalidation after mutation or decoding.
/// (´def:formation:affinity´)
pub type FormationGraph = StableDiGraph<Node, Projection>;

/// A complete binary projection; no partial family witness is returned.
/// (´def:formation:affinity´)
pub type CompleteProjection = (Node, Node, Projection);

/// Project Registration or Affinity with complete approval and removal checks.
/// The existing verifier is the explicit public authentication boundary for both.
/// (´[ROOT-alg:design:formation]´)
///
/// # Errors
/// Refuses unsupported families, wrong incidence or coordinate carriage, failed
/// approval and unauthorized removal. This does not decide geometry or title.
#[tracing::instrument(
    name = "alg:design:formation",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:formation",
        source_item = "formation::project_complete_act"
    ),
    ret
)]
pub fn project_complete_act(
    act: &ValidatedAct,
    verifier: &impl RegistrationVerifier,
) -> Result<CompleteProjection, RegistrationError> {
    let result = project(act, verifier).and_then(|projection| {
        registration::authorize_removals(&[act], verifier)?;
        Ok(projection)
    });
    if result.is_err() {
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}

/// Reconstruct the complete supplied history of supported families together.
/// Shared Registration machinery fixes indices and verifies chronological removals;
/// no unsupported or invalid later act can publish a partial graph.
/// (´[ROOT-alg:design:formation]´)
///
/// # Errors
/// Refuses unsupported formation, duplicate published positions or backend capacity.
#[tracing::instrument(
    name = "alg:design:formation",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:formation",
        source_item = "formation::reconstruct"
    ),
    ret
)]
pub fn reconstruct(
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
) -> Result<FormationGraph, RegistrationError> {
    let result = registration::reconstruct_with(history, verifier, |act| project(act, verifier));
    if result.is_err() {
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}

/// Reconstruct and compare every typed live index, weight and endpoint.
/// Serde bytes never establish binding replay equality or canonical publication.
/// (´[ROOT-alg:design:formation]´)
///
/// # Errors
/// Returns reconstruction refusals or `GraphMismatch` for partial or altered state.
#[tracing::instrument(
    name = "alg:design:formation",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:formation",
        source_item = "formation::validate_formation"
    ),
    ret
)]
pub fn validate_formation(
    graph: &FormationGraph,
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
) -> Result<(), RegistrationError> {
    let result = registration::reconstruct_with(history, verifier, |act| project(act, verifier))
        .and_then(|expected| registration::compare_graph(graph, &expected));
    if result.is_err() {
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}

fn project(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<CompleteProjection, RegistrationError> {
    if act.id().family == "Registration" {
        return registration::project(act, verifier)
            .map(|(source, target, edge)| (Node::Grounded(source), Node::Grounded(target), Projection::Registration(edge)));
    }
    if act.id().family != "Affinity" {
        return Err(RegistrationError::UnsupportedFamily);
    }
    let [leg] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let PublicReference::Named { namespace, name } = leg.target() else {
        return Err(RegistrationError::Incidence);
    };
    if act.body().layout != Layout::Binary
        || leg.id().role != Role::Binary
        || leg.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || namespace != "name"
        || act.body().quantities.len() != 4
    {
        return Err(RegistrationError::Incidence);
    }
    let association = coordinate(act, "association.numerator", "association.denominator")?;
    let attraction = coordinate(act, "attraction.numerator", "attraction.denominator")?;
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    Ok((
        Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
        Node::Type(name.clone()),
        Projection::Affinity(AffinityProjection {
            author: act.id().author.clone(),
            sequence: act.id().sequence,
            position: act.position(),
            logical_time: act.logical_time(),
            association,
            attraction,
        }),
    ))
}

fn coordinate(act: &ValidatedAct, numerator: &str, denominator: &str) -> Result<Coordinate, RegistrationError> {
    let field = |key| {
        act.body()
            .quantities
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
            .filter(|value| value.unit == "one" && value.vintage == 0)
            .map(|value| value.value)
            .ok_or(RegistrationError::Incidence)
    };
    let result = Coordinate {
        numerator: field(numerator)?,
        denominator: field(denominator)?,
    };
    if result.denominator <= 0 || result.numerator.unsigned_abs() > result.denominator.unsigned_abs() {
        return Err(RegistrationError::Incidence);
    }
    Ok(result)
}
