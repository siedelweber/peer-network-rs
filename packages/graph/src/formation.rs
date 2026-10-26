//! Scoped complete-act formation; unsupported families refuse as whole acts.
//! (´def:formation:affinity´)

use petgraph::stable_graph::StableDiGraph;
use pn_records::{Layout, Position, PublicReference, Role, ValidatedAct, ValidatedHistory};
use serde::{Deserialize, Serialize};

use crate::registration::{self, GroundedNode, RegistrationError, RegistrationProjection, RegistrationVerifier};

/// Disjoint grounded, public-name and minted node constructors in this scope.
/// Type names are exact strings; no normalization or new identity is invented.
/// (´def:formation:affinity´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Node {
    /// Existing Actor/Profile constructors, shared with Registration.
    Grounded(GroundedNode),
    /// The public string commons constructor name(s), interpreted as Type.
    Type(String),
    /// Content minted by a Publish act; the family is fixed by this variant.
    Content {
        /// Genesis act author, never a host attachment.
        author: String,
        /// Genesis act's author-local sequence.
        sequence: u64,
    },
    /// Item minted by a Owner act; the family is fixed by this variant.
    Item {
        /// Genesis act author, never a host attachment.
        author: String,
        /// Genesis act's author-local sequence.
        sequence: u64,
    },
    /// Chat minted by a Participant act; the family is fixed by this variant.
    Chat {
        /// Genesis act author, never a host attachment.
        author: String,
        /// Genesis act's author-local sequence.
        sequence: u64,
    },
    /// Comment minted by a Review act; the family is fixed by this variant.
    Comment {
        /// Genesis act author, never a host attachment.
        author: String,
        /// Genesis act's author-local sequence.
        sequence: u64,
    },
    /// Message minted by a Send act; the family is fixed by this variant.
    Message {
        /// Genesis act author, never a host attachment.
        author: String,
        /// Genesis act's author-local sequence.
        sequence: u64,
    },
    /// Offer minted by a Bid act; the family is fixed by this variant.
    Offer {
        /// Genesis act author, never a host attachment.
        author: String,
        /// Genesis act's author-local sequence.
        sequence: u64,
    },
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

/// Complete Opinion binary weight; coordinates remain distinct directional roles.
/// (´def:formation:opinion´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpinionProjection {
    /// Author atom shared with the initiating Actor endpoint.
    pub author: String,
    /// Author-local sequence, never host order.
    pub sequence: u64,
    /// Retained epoch-qualified published placement.
    pub position: Position,
    /// Retained host attachment; this operation gives no recurrence verdict.
    pub logical_time: u64,
    /// Polarity occupies the directional role `p_d`.
    pub polarity: Coordinate,
    /// Reaction occupies the intensity role `p_i`.
    pub reaction: Coordinate,
}

/// Complete Join Request binary weight; coordinates remain distinct directional roles.
/// (´def:formation:join-request´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequestProjection {
    /// Author atom shared with the initiating Actor endpoint.
    pub author: String,
    /// Author-local sequence, never host order.
    pub sequence: u64,
    /// Retained epoch-qualified published placement.
    pub position: Position,
    /// Retained host attachment; this operation gives no recurrence verdict.
    pub logical_time: u64,
    /// Urgency occupies the directional role `p_d`.
    pub urgency: Coordinate,
    /// Formality occupies the intensity role `p_i`.
    pub formality: Coordinate,
}

/// Complete Leave control weight; both parameter roles are fixed at one.
/// (´def:formation:leave´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaveProjection {
    /// Author atom shared with the initiating Actor endpoint.
    pub author: String,
    /// Author-local sequence, never host order.
    pub sequence: u64,
    /// Retained epoch-qualified published placement.
    pub position: Position,
    /// Retained host attachment; this operation gives no recurrence verdict.
    pub logical_time: u64,
}

/// Exact Content genesis pair, retained structurally for typed revalidation.
/// No license interpretation participates in formation or geometry.
/// (´def:formation:publish´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenseQualifiers {
    /// Attribution degree a in the nonnegative unit interval.
    pub attribution: Coordinate,
    /// Provenance degree o in the nonnegative unit interval.
    pub provenance: Coordinate,
}

/// Complete scoped Publish weight, retaining immutable license qualifiers.
/// (´def:formation:publish´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishProjection {
    /// Author atom shared with the initiating Actor endpoint.
    pub author: String,
    /// Author-local act sequence.
    pub sequence: u64,
    /// Retained published placement.
    pub position: Position,
    /// Retained host attachment, without a recurrence verdict.
    pub logical_time: u64,
    /// Authored directional coordinate; intensity is fixed at one.
    pub attachment: Coordinate,
    /// Pair fixed only on a self-minting Content genesis act.
    pub license: Option<LicenseQualifiers>,
}

/// Complete scoped Owner weight, with no license or protocol-reference field.
/// (´def:formation:owner´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerProjection {
    /// Author atom shared with the initiating Actor endpoint.
    pub author: String,
    /// Author-local act sequence.
    pub sequence: u64,
    /// Retained ownered placement.
    pub position: Position,
    /// Retained host attachment, without a recurrence verdict.
    pub logical_time: u64,
    /// Authored directional coordinate; intensity is fixed at one.
    pub attachment: Coordinate,
}

/// Constructor role of a Participant edge, derived from one complete act.
/// (´def:formation:participant´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParticipantRole {
    /// Initiating Actor to origin Chat.
    A,
    /// Origin Chat to destination Chat.
    T,
}

/// Complete Participant tuple shared by its two role-addressed projections.
/// (´def:formation:participant´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantProjection {
    /// Initiating author shared by both legs.
    pub author: String,
    /// Author-local act sequence shared by both legs.
    pub sequence: u64,
    /// A or T constructor role, never a separately authored identity.
    pub role: ParticipantRole,
    /// Retained published placement of the whole act.
    pub position: Position,
    /// One retained time shared by both projections.
    pub logical_time: u64,
    /// Signed A-leg directional coordinate.
    pub interactivity: Coordinate,
    /// Signed A-leg intensity coordinate.
    pub responsibility: Coordinate,
    /// Nonnegative T-leg directional coordinate; intensity is fixed at one.
    pub continuity: Coordinate,
}

/// Constructor role of a Review edge, derived from one complete act.
/// (´def:formation:review´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewRole {
    /// Initiating Actor to reviewed passive node.
    A,
    /// Reviewed passive node to Comment.
    T,
}

/// Complete Review tuple shared by both role-addressed projections.
/// (´def:formation:review´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewProjection {
    /// Initiating author shared by both legs.
    pub author: String,
    /// Author-local act sequence shared by both legs.
    pub sequence: u64,
    /// A or T constructor role, never a separately authored identity.
    pub role: ReviewRole,
    /// Retained published placement of the whole act.
    pub position: Position,
    /// One retained time shared by both projections.
    pub logical_time: u64,
    /// Signed enthusiasm, directional on A and intensity on T.
    pub enthusiasm: Coordinate,
    /// Signed effort, intensity on A and directional on T.
    pub effort: Coordinate,
}

/// Constructor role of a Tag edge, derived from one complete act.
/// (´def:formation:tag´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TagRole {
    /// Initiating Actor to taged passive node.
    A,
    /// Tagged passive node to Type.
    T,
}

/// Complete Tag tuple shared by both role-addressed projections.
/// (´def:formation:tag´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagProjection {
    /// Initiating author shared by both legs.
    pub author: String,
    /// Author-local act sequence shared by both legs.
    pub sequence: u64,
    /// A or T constructor role, never a separately authored identity.
    pub role: TagRole,
    /// Retained published placement of the whole act.
    pub position: Position,
    /// One retained time shared by both projections.
    pub logical_time: u64,
    /// Signed relevance, directional on A and intensity on T.
    pub relevance: Coordinate,
    /// Nonnegative confidence, intensity on A and directional on T.
    pub confidence: Coordinate,
}

/// Constructor role of a Send edge, derived from one complete act.
/// (´def:formation:send´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendRole {
    /// Initiating Actor to Chat.
    A,
    /// Chat to Message.
    T,
}

/// Complete Send tuple shared by both role-addressed projections.
/// (´def:formation:send´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendProjection {
    /// Initiating author shared by both legs.
    pub author: String,
    /// Author-local act sequence shared by both legs.
    pub sequence: u64,
    /// A or T constructor role, never a separately authored identity.
    pub role: SendRole,
    /// Retained published placement of the whole act.
    pub position: Position,
    /// One retained time shared by both projections.
    pub logical_time: u64,
    /// Signed importance, directional on A and intensity on T.
    pub importance: Coordinate,
}

/// Constructor role of a Bid edge, derived from one complete act.
/// (´def:formation:bid´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BidRole {
    /// Initiating Actor to Item.
    A,
    /// Item to Offer.
    T,
}

/// Complete Bid tuple shared by both role-addressed projections.
/// (´def:formation:bid´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BidProjection {
    /// Initiating author shared by both legs.
    pub author: String,
    /// Author-local act sequence shared by both legs.
    pub sequence: u64,
    /// A or T constructor role, never a separately authored identity.
    pub role: BidRole,
    /// Retained published placement of the whole act.
    pub position: Position,
    /// One retained time shared by both projections.
    pub logical_time: u64,
    /// Signed generosity, directional on A and intensity on T.
    pub generosity: Coordinate,
    /// Nonnegative urgency, intensity on A and directional on T.
    pub urgency: Coordinate,
}

/// Distinct supported families, preserving each complete authored projection.
/// (´def:formation:affinity´)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Projection {
    /// Existing Registration projection, with its fixed coordinate roles.
    Registration(RegistrationProjection),
    /// Affinity projection, with both required authored coordinates.
    Affinity(AffinityProjection),
    /// Publish projection, with its required authored coordinate and qualifiers.
    Publish(PublishProjection),
    /// Owner projection; structural formation confers no title.
    Owner(OwnerProjection),
    /// Both Participant legs retain the same full tuple and act metadata.
    Participant(ParticipantProjection),
    /// Review retains the full tuple on both author-fixed legs.
    Review(ReviewProjection),
    /// Send retains importance and shared metadata on both legs.
    Send(SendProjection),
    /// Bid creates one fresh Offer with both role-addressed projections.
    Bid(BidProjection),
    /// Opinion retains signed polarity and reaction toward any passive node.
    Opinion(OpinionProjection),
    /// Join Request is a Chat proposal, without a membership effect.
    JoinRequest(JoinRequestProjection),
    /// Leave is unconditional Chat dissociation, with fixed control parameters.
    Leave(LeaveProjection),
    /// Tag classifies a Taggable passive node with a public Type.
    Tag(TagProjection),
}

/// Direct diagnostic backend, requiring revalidation after mutation or decoding.
/// (´def:formation:affinity´)
pub type FormationGraph = StableDiGraph<Node, Projection>;

/// One typed edge projection; complete acts return the entire ordered vector.
/// (´def:formation:affinity´)
pub type CompleteProjection = (Node, Node, Projection);

/// Project a supported family with complete approval and removal checks.
/// The existing verifier is the explicit public authentication boundary for all.
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
) -> Result<Vec<CompleteProjection>, RegistrationError> {
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

fn project(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<Vec<CompleteProjection>, RegistrationError> {
    if act.id().family == "Tag" {
        tag(act, verifier)
    } else if act.id().family == "Participant" {
        participant(act, verifier)
    } else if act.id().family == "Review" {
        review(act, verifier)
    } else if act.id().family == "Send" {
        send(act, verifier)
    } else if act.id().family == "Bid" {
        bid(act, verifier)
    } else {
        binary(act, verifier).map(|projection| vec![projection])
    }
}

fn binary(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<CompleteProjection, RegistrationError> {
    if act.id().family == "Registration" {
        return registration::project(act, verifier)
            .map(|(source, target, edge)| (Node::Grounded(source), Node::Grounded(target), Projection::Registration(edge)));
    }
    if act.id().family == "Publish" {
        return publish(act, verifier);
    }
    if act.id().family == "Leave" {
        return leave(act, verifier);
    }
    if act.id().family == "Join Request" {
        return join_request(act, verifier);
    }
    if act.id().family == "Opinion" {
        return opinion(act, verifier);
    }
    if act.id().family == "Owner" {
        return owner(act, verifier);
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

fn publish(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<CompleteProjection, RegistrationError> {
    let [leg] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let PublicReference::Minted(genesis) = leg.target() else {
        return Err(RegistrationError::Incidence);
    };
    if act.body().layout != Layout::Binary
        || leg.id().role != Role::Binary
        || leg.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || genesis.family != "Publish"
        || act.body().quantities.len() != 2
    {
        return Err(RegistrationError::Incidence);
    }
    let attachment = coordinate(act, "attachment.numerator", "attachment.denominator")?;
    if !act.protocol_references().is_empty() {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    Ok((
        Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
        Node::Content {
            author: genesis.author.clone(),
            sequence: genesis.sequence,
        },
        Projection::Publish(PublishProjection {
            author: act.id().author.clone(),
            sequence: act.id().sequence,
            position: act.position(),
            logical_time: act.logical_time(),
            attachment,
            license: act.body().license.map(|pair| LicenseQualifiers {
                attribution: Coordinate {
                    numerator: pair.attribution.numerator,
                    denominator: pair.attribution.denominator,
                },
                provenance: Coordinate {
                    numerator: pair.provenance.numerator,
                    denominator: pair.provenance.denominator,
                },
            }),
        }),
    ))
}

fn owner(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<CompleteProjection, RegistrationError> {
    let [leg] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let PublicReference::Minted(genesis) = leg.target() else {
        return Err(RegistrationError::Incidence);
    };
    if act.body().layout != Layout::Binary
        || leg.id().role != Role::Binary
        || leg.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || genesis.family != "Owner"
        || act.body().quantities.len() != 2
    {
        return Err(RegistrationError::Incidence);
    }
    let attachment = coordinate(act, "attachment.numerator", "attachment.denominator")?;
    if !act.protocol_references().is_empty() {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    Ok((
        Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
        Node::Item {
            author: genesis.author.clone(),
            sequence: genesis.sequence,
        },
        Projection::Owner(OwnerProjection {
            author: act.id().author.clone(),
            sequence: act.id().sequence,
            position: act.position(),
            logical_time: act.logical_time(),
            attachment,
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

fn participant(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<Vec<CompleteProjection>, RegistrationError> {
    let [first, second] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let (a, t) = match (first.id().role, second.id().role) {
        (Role::A, Role::T) => (first, second),
        (Role::T, Role::A) => (second, first),
        _ => return Err(RegistrationError::Incidence),
    };
    if act.body().layout != Layout::Paired
        || a.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || a.target() != t.source()
        || act.body().quantities.len() != 6
    {
        return Err(RegistrationError::Incidence);
    }
    let origin = chat(a.target())?;
    let destination = chat(t.target())?;
    let interactivity = coordinate(act, "interactivity.numerator", "interactivity.denominator")?;
    let responsibility = coordinate(act, "responsibility.numerator", "responsibility.denominator")?;
    let continuity = coordinate(act, "continuity.numerator", "continuity.denominator")?;
    if continuity.numerator < 0 {
        return Err(RegistrationError::Incidence);
    }
    if !act.protocol_references().is_empty() {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    let a_weight = ParticipantProjection {
        author: act.id().author.clone(),
        sequence: act.id().sequence,
        role: ParticipantRole::A,
        position: act.position(),
        logical_time: act.logical_time(),
        interactivity,
        responsibility,
        continuity,
    };
    let t_weight = ParticipantProjection {
        role: ParticipantRole::T,
        ..a_weight.clone()
    };
    Ok(vec![
        (
            Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
            origin.clone(),
            Projection::Participant(a_weight),
        ),
        (origin, destination, Projection::Participant(t_weight)),
    ])
}

fn chat(reference: &PublicReference) -> Result<Node, RegistrationError> {
    match reference {
        PublicReference::Minted(genesis) if genesis.family == "Participant" => Ok(Node::Chat {
            author: genesis.author.clone(),
            sequence: genesis.sequence,
        }),
        _ => Err(RegistrationError::Incidence),
    }
}

fn review(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<Vec<CompleteProjection>, RegistrationError> {
    let [first, second] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let (a, t) = match (first.id().role, second.id().role) {
        (Role::A, Role::T) => (first, second),
        (Role::T, Role::A) => (second, first),
        _ => return Err(RegistrationError::Incidence),
    };
    if act.body().layout != Layout::Paired
        || a.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || a.target() != t.source()
        || act.body().quantities.len() != 4
    {
        return Err(RegistrationError::Incidence);
    }
    let middle = passive(a.target())?;
    let target = passive(t.target())?;
    if !matches!(target, Node::Comment { .. }) {
        return Err(RegistrationError::Incidence);
    }
    let enthusiasm = coordinate(act, "enthusiasm.numerator", "enthusiasm.denominator")?;
    let effort = coordinate(act, "effort.numerator", "effort.denominator")?;
    if !act.protocol_references().is_empty() {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    let a_weight = ReviewProjection {
        author: act.id().author.clone(),
        sequence: act.id().sequence,
        role: ReviewRole::A,
        position: act.position(),
        logical_time: act.logical_time(),
        enthusiasm,
        effort,
    };
    let t_weight = ReviewProjection {
        role: ReviewRole::T,
        ..a_weight.clone()
    };
    Ok(vec![
        (
            Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
            middle.clone(),
            Projection::Review(a_weight),
        ),
        (middle, target, Projection::Review(t_weight)),
    ])
}

fn passive(reference: &PublicReference) -> Result<Node, RegistrationError> {
    match reference {
        PublicReference::Named { namespace, name } if namespace == "prof" => {
            Ok(Node::Grounded(GroundedNode::Profile(name.clone())))
        }
        PublicReference::Named { namespace, name } if namespace == "name" => Ok(Node::Type(name.clone())),
        PublicReference::Minted(genesis) => {
            let author = genesis.author.clone();
            let sequence = genesis.sequence;
            match genesis.family.as_str() {
                "Publish" => Ok(Node::Content { author, sequence }),
                "Owner" => Ok(Node::Item { author, sequence }),
                "Participant" => Ok(Node::Chat { author, sequence }),
                "Review" => Ok(Node::Comment { author, sequence }),
                "Send" => Ok(Node::Message { author, sequence }),
                "Bid" => Ok(Node::Offer { author, sequence }),
                _ => Err(RegistrationError::Incidence),
            }
        }
        _ => Err(RegistrationError::Incidence),
    }
}

fn send(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<Vec<CompleteProjection>, RegistrationError> {
    let [first, second] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let (a, t) = match (first.id().role, second.id().role) {
        (Role::A, Role::T) => (first, second),
        (Role::T, Role::A) => (second, first),
        _ => return Err(RegistrationError::Incidence),
    };
    if act.body().layout != Layout::Paired
        || a.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || a.target() != t.source()
        || act.body().quantities.len() != 2
    {
        return Err(RegistrationError::Incidence);
    }
    let middle = chat(a.target())?;
    let target = passive(t.target())?;
    if !matches!(target, Node::Message { .. }) {
        return Err(RegistrationError::Incidence);
    }
    let importance = coordinate(act, "importance.numerator", "importance.denominator")?;
    if !act.protocol_references().is_empty() {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    let a_weight = SendProjection {
        author: act.id().author.clone(),
        sequence: act.id().sequence,
        role: SendRole::A,
        position: act.position(),
        logical_time: act.logical_time(),
        importance,
    };
    let t_weight = SendProjection {
        role: SendRole::T,
        ..a_weight.clone()
    };
    Ok(vec![
        (
            Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
            middle.clone(),
            Projection::Send(a_weight),
        ),
        (middle, target, Projection::Send(t_weight)),
    ])
}

fn bid(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<Vec<CompleteProjection>, RegistrationError> {
    let [first, second] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let (a, t) = match (first.id().role, second.id().role) {
        (Role::A, Role::T) => (first, second),
        (Role::T, Role::A) => (second, first),
        _ => return Err(RegistrationError::Incidence),
    };
    if act.body().layout != Layout::Paired
        || a.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || a.target() != t.source()
        || act.body().quantities.len() != 4
    {
        return Err(RegistrationError::Incidence);
    }
    let middle = passive(a.target())?;
    let target = passive(t.target())?;
    if !matches!(middle, Node::Item { .. })
        || !matches!(target, Node::Offer { .. })
        || t.target() != &PublicReference::Minted(act.id().clone())
    {
        return Err(RegistrationError::Incidence);
    }
    let generosity = coordinate(act, "generosity.numerator", "generosity.denominator")?;
    let urgency = coordinate(act, "urgency.numerator", "urgency.denominator")?;
    if urgency.numerator < 0 || !act.protocol_references().is_empty() {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    let a_weight = BidProjection {
        author: act.id().author.clone(),
        sequence: act.id().sequence,
        role: BidRole::A,
        position: act.position(),
        logical_time: act.logical_time(),
        generosity,
        urgency,
    };
    let t_weight = BidProjection {
        role: BidRole::T,
        ..a_weight.clone()
    };
    Ok(vec![
        (
            Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
            middle.clone(),
            Projection::Bid(a_weight),
        ),
        (middle, target, Projection::Bid(t_weight)),
    ])
}

fn opinion(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<CompleteProjection, RegistrationError> {
    let [leg] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let target = passive(leg.target())?;
    if act.body().layout != Layout::Binary
        || leg.id().role != Role::Binary
        || leg.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || act.body().quantities.len() != 4
    {
        return Err(RegistrationError::Incidence);
    }
    let polarity = coordinate(act, "polarity.numerator", "polarity.denominator")?;
    let reaction = coordinate(act, "reaction.numerator", "reaction.denominator")?;
    if !act.protocol_references().is_empty() {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    Ok((
        Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
        target,
        Projection::Opinion(OpinionProjection {
            author: act.id().author.clone(),
            sequence: act.id().sequence,
            position: act.position(),
            logical_time: act.logical_time(),
            polarity,
            reaction,
        }),
    ))
}

fn join_request(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<CompleteProjection, RegistrationError> {
    let [leg] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let target = chat(leg.target())?;
    if act.body().layout != Layout::Binary
        || leg.id().role != Role::Binary
        || leg.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || act.body().quantities.len() != 4
    {
        return Err(RegistrationError::Incidence);
    }
    let urgency = coordinate(act, "urgency.numerator", "urgency.denominator")?;
    let formality = coordinate(act, "formality.numerator", "formality.denominator")?;
    if !act.protocol_references().is_empty() {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    Ok((
        Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
        target,
        Projection::JoinRequest(JoinRequestProjection {
            author: act.id().author.clone(),
            sequence: act.id().sequence,
            position: act.position(),
            logical_time: act.logical_time(),
            urgency,
            formality,
        }),
    ))
}

fn tag(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<Vec<CompleteProjection>, RegistrationError> {
    let [first, second] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let (a, t) = match (first.id().role, second.id().role) {
        (Role::A, Role::T) => (first, second),
        (Role::T, Role::A) => (second, first),
        _ => return Err(RegistrationError::Incidence),
    };
    if act.body().layout != Layout::Paired
        || a.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || a.target() != t.source()
        || act.body().quantities.len() != 4
    {
        return Err(RegistrationError::Incidence);
    }
    let middle = passive(a.target())?;
    let target = passive(t.target())?;
    if matches!(middle, Node::Offer { .. }) || !matches!(target, Node::Type(_)) {
        return Err(RegistrationError::Incidence);
    }
    let relevance = coordinate(act, "relevance.numerator", "relevance.denominator")?;
    let confidence = coordinate(act, "confidence.numerator", "confidence.denominator")?;
    if confidence.numerator < 0 || !act.protocol_references().is_empty() {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    let a_weight = TagProjection {
        author: act.id().author.clone(),
        sequence: act.id().sequence,
        role: TagRole::A,
        position: act.position(),
        logical_time: act.logical_time(),
        relevance,
        confidence,
    };
    let t_weight = TagProjection {
        role: TagRole::T,
        ..a_weight.clone()
    };
    Ok(vec![
        (
            Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
            middle.clone(),
            Projection::Tag(a_weight),
        ),
        (middle, target, Projection::Tag(t_weight)),
    ])
}

fn leave(act: &ValidatedAct, verifier: &impl RegistrationVerifier) -> Result<CompleteProjection, RegistrationError> {
    let [leg] = act.legs() else {
        return Err(RegistrationError::Incidence);
    };
    let target = chat(leg.target())?;
    if act.body().layout != Layout::Binary
        || leg.id().role != Role::Binary
        || leg.source()
            != &(PublicReference::Named {
                namespace: "addr".into(),
                name: act.id().author.clone(),
            })
        || !act.body().quantities.is_empty()
    {
        return Err(RegistrationError::Incidence);
    }
    if !act.protocol_references().is_empty() {
        return Err(RegistrationError::Incidence);
    }
    if !verifier.approval(act) {
        return Err(RegistrationError::Unapproved);
    }
    Ok((
        Node::Grounded(GroundedNode::Actor(act.id().author.clone())),
        target,
        Projection::Leave(LeaveProjection {
            author: act.id().author.clone(),
            sequence: act.id().sequence,
            position: act.position(),
            logical_time: act.logical_time(),
        }),
    ))
}
