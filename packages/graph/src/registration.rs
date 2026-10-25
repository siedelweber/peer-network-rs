//! Registration-only formation; other families and title remain held.
//! (´def:formation:registration´)

use std::collections::BTreeMap;

use petgraph::stable_graph::StableDiGraph;
use pn_records::{DependencyProjection, Layout, Position, PublicReference, Removal, Role, ValidatedAct, ValidatedHistory};
use serde::{Deserialize, Serialize};

/// Grounded identifiers; Registration anchors this existing pair and mints nothing.
/// (´def:formation:registration´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GroundedNode {
    /// The primitive address atom interpreted as its Actor.
    Actor(String),
    /// The same address atom interpreted as its Profile.
    Profile(String),
}

/// A cache of one Registration binary projection and inherited finalization fields.
/// Family and role are fixed by this type; neither time nor position is identity.
/// (´def:formation:registration´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationProjection {
    /// Public author atom, also the grounded pair's atom.
    pub author: String,
    /// Author-local sequence in the Registration act identity.
    pub sequence: u64,
    /// Inherited published epoch and position, never an independent edge stamp.
    pub position: Position,
    /// Inherited attachment, never recomputed or independently authoritative.
    pub logical_time: u64,
}

/// Direct backend value with every parallel Registration retained.
/// Serde is diagnostic only; mutation or deserialization requires revalidation.
/// (´def:formation:registration´)
pub type RegistrationGraph = StableDiGraph<GroundedNode, RegistrationProjection>;

/// Exactly one binary projection with its two typed endpoints.
/// (´def:formation:registration´)
pub type CompleteRegistration = (GroundedNode, GroundedNode, RegistrationProjection);

/// Which act-owned removable opening a public authorization covers.
/// Structural graph edges are never removed by either operation.
/// (´def:formation:registration´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OpeningKind {
    /// Content and its co-removed private value.
    Content,
    /// The declared dependency list and opening.
    Dependency,
}

/// Declared public authentication boundary, not a cryptographic implementation.
/// Implementations must deterministically verify the exact author approval and
/// retained commitments, authentic address interpretation and author-controlled
/// removals. Their Debug contains only public state. Fixtures do not establish
/// cryptographic soundness. No epoch, position or logical time is author-signed.
/// (´def:formation:registration´)
pub trait RegistrationVerifier: std::fmt::Debug {
    /// Check genuine approval of the complete immutable act and commitments.
    fn approval(&self, act: &ValidatedAct) -> bool;
    /// Check the author's public authorization of this opening's removal fact.
    fn removal(&self, act: &ValidatedAct, opening: OpeningKind, at: Position) -> bool;
}

/// Scoped refusal; no partial projection graph is returned on any error.
/// (´def:formation:registration´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegistrationError {
    /// This entry point admits Registration only.
    #[error("unsupported act family")]
    UnsupportedFamily,
    /// Layout, endpoints or fixed parameter carriage differs from Registration.
    #[error("invalid Registration incidence or body")]
    Incidence,
    /// The declared verifier did not establish complete author approval.
    #[error("Registration approval not established")]
    Unapproved,
    /// A removal fact lacks the declared verifier's authorization.
    #[error("opening removal not authorized")]
    UnauthorizedRemoval,
    /// Repeated published positions cannot determine reconstruction order.
    #[error("ambiguous published order")]
    AmbiguousOrder,
    /// The backend cannot represent another index.
    #[error("Registration graph capacity exhausted")]
    Capacity,
    /// Live identifiers, projections, endpoints or indices differ from reconstruction.
    #[error("Registration graph differs from complete reconstruction")]
    GraphMismatch,
}

/// Project one complete Registration under the declared verifier.
/// The scoped carrier spelling is family Registration with Named addr/prof
/// endpoints naming its author; fixed parameters have no quantity fields.
/// (´[ROOT-alg:design:formation]´)
///
/// # Errors
/// Refuses another family, invalid incidence, unapproved acts or unauthorized removals.
#[tracing::instrument(
    name = "alg:design:formation",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:formation",
        source_item = "registration::project_complete_registration"
    ),
    ret
)]
pub fn project_complete_registration(
    act: &ValidatedAct,
    verifier: &impl RegistrationVerifier,
) -> Result<CompleteRegistration, RegistrationError> {
    let result = project(act, verifier).and_then(|projection| {
        authorize_removals(&[act], verifier)?;
        Ok(projection)
    });
    if result.is_err() {
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}

/// Reconstruct complete Registration history in published epoch-major order.
/// Nodes enter at first occurrence, Actor before Profile; every act adds one
/// distinct binary edge. Removals are verified in published order and never
/// delete structural projections. Recurrence, epoch admission and title are not
/// inferred; attached times and non-compliant history remain unchanged inputs.
/// (´[ROOT-alg:design:formation]´)
///
/// # Errors
/// Refuses unsupported or incomplete formation, ambiguous order or backend capacity.
#[tracing::instrument(
    name = "alg:design:formation",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:formation",
        source_item = "registration::reconstruct_registrations"
    ),
    ret
)]
pub fn reconstruct_registrations(
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
) -> Result<RegistrationGraph, RegistrationError> {
    let result = reconstruct(history, verifier);
    if result.is_err() {
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}

/// Revalidate live structural values and indices against complete public history.
/// This compares typed content, never serialized graph bytes. A successful check
/// supplies only this Registration scope; further mutation invalidates it.
/// (´[ROOT-alg:design:formation]´)
///
/// # Errors
/// Returns reconstruction refusals or `GraphMismatch` for a partial, extra or altered graph.
#[tracing::instrument(
    name = "alg:design:formation",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:formation",
        source_item = "registration::validate_registration_graph"
    ),
    ret
)]
pub fn validate_registration_graph(
    graph: &RegistrationGraph,
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
) -> Result<(), RegistrationError> {
    let result = reconstruct(history, verifier).and_then(|expected| {
        let matches = graph.node_count() == expected.node_count()
            && graph.edge_count() == expected.edge_count()
            && expected
                .node_indices()
                .all(|index| graph.node_weight(index) == expected.node_weight(index))
            && expected.edge_indices().all(|index| {
                graph.edge_weight(index) == expected.edge_weight(index)
                    && graph.edge_endpoints(index) == expected.edge_endpoints(index)
            });
        if matches {
            Ok(())
        } else {
            Err(RegistrationError::GraphMismatch)
        }
    });
    if result.is_err() {
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}

fn project(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<CompleteRegistration, RegistrationError> {
    if act.id().family != "Registration" {
        return Err(RegistrationError::UnsupportedFamily);
    }
    let [leg] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let named = |namespace: &str| PublicReference::Named {
        namespace: namespace.into(),
        name: act.id().author.clone(),
    };
    if act.body().layout != Layout::Binary
        || !act.body().quantities.is_empty()
        || leg.id().role != Role::Binary
        || leg.source() != &named("addr")
        || leg.target() != &named("prof")
    {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    Ok((
        GroundedNode::Actor(act.id().author.clone()),
        GroundedNode::Profile(act.id().author.clone()),
        RegistrationProjection {
            author: act.id().author.clone(),
            sequence: act.id().sequence,
            position: act.position(),
            logical_time: act.logical_time(),
        },
    ))
}

fn authorize_removals(acts: &[&ValidatedAct], verifier: &impl RegistrationVerifier) -> Result<(), RegistrationError> {
    let mut removals = Vec::new();
    for act in acts {
        if let Removal::Tombstoned(at) = act.projections().content {
            removals.push((at, act.id(), OpeningKind::Content, *act));
        }
        if let DependencyProjection::Tombstoned(at) = act.projections().dependency {
            removals.push((at, act.id(), OpeningKind::Dependency, *act));
        }
    }
    removals.sort_by_key(|(at, id, kind, _)| (*at, *id, *kind));
    for (at, _, kind, act) in removals {
        if !verifier.removal(act, kind, at) {
            return Err(RegistrationError::UnauthorizedRemoval);
        }
    }
    Ok(())
}

fn reconstruct(history: &ValidatedHistory, verifier: &impl RegistrationVerifier) -> Result<RegistrationGraph, RegistrationError> {
    let mut acts: Vec<_> = history.acts().iter().collect();
    acts.sort_by_key(|act| (act.position(), act.id()));
    if acts.windows(2).any(|pair| pair[0].position() == pair[1].position()) {
        return Err(RegistrationError::AmbiguousOrder);
    }
    let mut graph = RegistrationGraph::new();
    let mut nodes = BTreeMap::new();
    for act in &acts {
        let (source, target, projection) = project(act, verifier)?;
        let mut indices = Vec::new();
        for node in [source, target] {
            let index = if let Some(index) = nodes.get(&node) {
                *index
            } else {
                let index = graph.try_add_node(node.clone()).map_err(|_| RegistrationError::Capacity)?;
                nodes.insert(node, index);
                index
            };
            indices.push(index);
        }
        graph
            .try_add_edge(indices[0], indices[1], projection)
            .map_err(|_| RegistrationError::Capacity)?;
    }
    authorize_removals(&acts, verifier)?;
    Ok(graph)
}
