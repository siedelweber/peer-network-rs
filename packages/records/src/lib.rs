//! Internal carriers; no codec, host admission or graph algorithm.
//! (´[ROOT-amend:design:bite-one-internal-envelopes]´)

/// Exact numeric carriers and explicit unit operations.
/// (´def:numerics:exact-carriers´)
pub mod numerics;

/// Exact declaration payloads attached to validated effective editions.
/// (´def:declarations:constants-edition´)
pub mod constants;

/// Public burn disclosures and pure marker recognition, without snapshot derivation.
/// (´def:burn:carriers´)
pub mod burn;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Development-only fixture generator shared with the outer verification tier.
/// (´def:acts:test-support´)
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

/// Authored identity before finalization or host ordering.
/// (´def:acts:identity´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActId {
    /// Exact public author identifier, nonempty.
    pub author: String,
    /// Author-local sequence, not a host position.
    pub sequence: u64,
    /// Exact family name, nonempty; family semantics belong to the graph bite.
    pub family: String,
}

/// The declared role in one complete act projection.
/// (´def:acts:projection´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// The sole projection of a binary act.
    Binary,
    /// First co-leg of a paired act.
    A,
    /// Second co-leg of a paired act.
    T,
}

/// Edge identity is exactly its parent act and declared role.
/// (´def:acts:identity´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeId {
    /// Parent structural identity.
    pub act: ActId,
    /// Declared projection role.
    pub role: Role,
}

/// Immutable protocol target; no removal or storage-position field exists here.
/// (´def:acts:references´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublicReference {
    /// An act's structural identity.
    Act(ActId),
    /// An edge's structural identity.
    Edge(EdgeId),
    /// An exact external structural name; resolution is supplied by the caller.
    Named {
        /// Exact namespace, nonempty.
        namespace: String,
        /// Exact name, nonempty.
        name: String,
    },
    /// A node minted by the identified genesis act, distinct from that act.
    Minted(ActId),
}

/// The outer constructor class of a recognized structural node identifier.
/// Act and edge references, and other external namespaces, are not node terms.
/// (´def:acts:references´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierClass {
    /// Actor or Profile over one external address atom.
    Grounded,
    /// Type over an exact public string.
    Named,
    /// A node over its genesis act identifier.
    Minted,
}

impl PublicReference {
    /// Read the node constructor class without claiming resolution or formation.
    /// The existing internal addr/prof/name namespaces retain their graph spelling.
    /// (´def:acts:references´)
    #[must_use]
    /// Justified: Pure constructor classification inherits its enclosing records or formation operation; it does not validate, resolve, authenticate or count an act.
    pub fn identifier_class(&self) -> Option<IdentifierClass> {
        match self {
            Self::Named { namespace, .. } if namespace == "addr" || namespace == "prof" => Some(IdentifierClass::Grounded),
            Self::Named { namespace, .. } if namespace == "name" => Some(IdentifierClass::Named),
            Self::Minted(_) => Some(IdentifierClass::Minted),
            _ => None,
        }
    }
}

/// Projection completeness declared by the structural body.
/// (´def:acts:projection´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// Exactly the Binary role.
    Binary,
    /// Exactly both A and T roles, owned by one act.
    Paired,
}

/// Published position as (finalization epoch, position within that epoch).
/// The epoch-major convention remains provisional pending the paper correction.
/// (´def:acts:history´)
pub type Position = (u64, u64);

/// Local comparison of retained time with the complete available recurrence inputs.
/// This never replaces the attached time or certifies family formation.
/// (´def:acts:history´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimeVerdict {
    /// Attached time equals the recurrence over retained predecessor times.
    Matches,
    /// The exact recurrence result differs; u128 also represents `u64::MAX` + 1.
    Mismatch {
        /// Retained host-attached value.
        attached: u64,
        /// Exact locally expected value, never written back.
        expected: u128,
    },
    /// The dependency opening is absent; no recurrence verdict follows.
    UnavailableOpening,
    /// Dependency placement is non-compliant; its time rule remains unspecified.
    NonCompliant,
    /// Repeated published positions do not supply a unique replay order.
    AmbiguousPlacement,
}

/// One recurrence observation associated with its immutable act identity.
/// (´def:acts:history´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeEvidence {
    /// Act whose attached time was read.
    pub act: ActId,
    /// Scoped equality, mismatch or explicit absence of a verdict.
    pub verdict: TimeVerdict,
}

/// A dependency projection's versioned removal fact, distinct from identity.
/// (´def:acts:projection´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// Present in this accepted snapshot.
    Live,
    /// Removed at the given authoritative position; the identity remains.
    Tombstoned(Position),
}

/// One owned edge projection; never an independent accounting record.
/// (´def:acts:projection´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateLeg {
    /// Structural identity, checked against the owning act and layout.
    pub id: EdgeId,
    /// Exact source reference.
    pub source: PublicReference,
    /// Exact target reference.
    pub target: PublicReference,
    /// Untrusted input only: any supplied leg removal fact is refused.
    /// Validated legs have no such field; dependency status derives from the act.
    pub removal: Option<Removal>,
}

/// An exact integer with its declared unit and consummated vintage.
/// (´def:acts:body´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quantity {
    /// Exact integer; no floating conversion or valuation occurs here.
    pub value: i64,
    /// Nonempty unit name, retained without conversion.
    pub unit: String,
    /// Declared epoch, never replaced with finalization time.
    pub vintage: u64,
}

/// Structural content retained unchanged by local validation.
/// (´def:acts:body´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuralBody {
    /// Non-removable asserted parents, sorted by derived `ActId` order.
    pub asserted_parents: Vec<ActId>,
    /// Required role set; endpoint and family semantics are later contracts.
    pub layout: Layout,
    /// Named exact quantities; duplicate field names are ambiguous and refused.
    pub quantities: Vec<(String, Quantity)>,
}

/// An unchecked act candidate; downstream operations require `ValidatedRecords`.
/// (´def:acts:carrier´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateAct {
    /// Authored structural identity.
    pub id: ActId,
    /// Unchanged structural body with units and vintages.
    pub body: StructuralBody,
    /// Immutable structural legs, always owned together by this candidate.
    pub legs: Vec<CandidateLeg>,
    /// One-way removal facts for the act, never for an individual co-leg.
    pub projections: RemovableProjections,
    /// Immutable protocol references, independently required even after removal.
    pub protocol_references: Vec<PublicReference>,
    /// Public authentication evidence; retained, not cryptographically certified.
    pub authentication_evidence: Vec<u8>,
    /// Accepted finalization epoch, not identity or a quantity's vintage.
    pub finalization_epoch: u64,
    /// Host-authoritative order; never used for identity equality.
    pub authoritative_position: u64,
    /// Host-attached logical time, retained unchanged and never authored identity.
    pub logical_time: u64,
}

/// Act-level content and dependency projections, independent of structural legs.
/// (´def:acts:projection´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovableProjections {
    /// Content removal does not erase structural identity or public references.
    pub content: Removal,
    /// Every dependency edge derives this single act-owned removal fact.
    pub dependency: DependencyProjection,
}

/// Canonical dependency content; empty is available content, not absence.
/// (´def:acts:dependencies´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DependencyProjection {
    /// Complete empty dependency set.
    FullEmpty,
    /// Complete nonempty sorted, duplicate-free identifiers; admission also requires self-free earlier targets.
    Full(Vec<ActId>),
    /// Content unavailable after this position; never interpreted as empty.
    Tombstoned(Position),
}

/// Provisional representation bound, pending bite 2's published parameter.
/// Identifier byte bounds are also held there; this is not a paper-derived limit.
/// (´def:acts:dependencies´)
pub const MAX_DEPENDENCIES: usize = 1024;

/// Provisional asserted-parent count bound, pending bite 2 parameters and byte bounds.
/// (´def:acts:dependencies´)
pub const MAX_ASSERTED_PARENTS: usize = 1024;

/// Status derived from the owning act, not an independently supplied removal fact.
/// (´def:acts:dependencies´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyStatus {
    /// Complete empty content.
    FullEmpty,
    /// Complete nonempty content.
    Full,
    /// The act's dependency content is unavailable at this position.
    Tombstoned(Position),
}

/// Validated structural leg; no candidate removal field exists here.
/// (´def:acts:projection´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedLeg {
    /// Parent-and-role identity.
    id: EdgeId,
    /// Immutable source reference.
    source: PublicReference,
    /// Immutable target reference.
    target: PublicReference,
}

/// Immutable view owned by a validated snapshot, distinct from unchecked candidates.
/// (´def:acts:carrier´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedAct {
    /// Structural identity, containing the sole author and family representation.
    id: ActId,
    /// Retained quantities, units, vintage and layout.
    body: StructuralBody,
    /// All required legs together, with act-derived dependency status.
    legs: Vec<ValidatedLeg>,
    /// Act-owned removable projections.
    projections: RemovableProjections,
    /// Immutable required public references.
    protocol_references: Vec<PublicReference>,
    /// Public evidence retained without cryptographic certification.
    authentication_evidence: Vec<u8>,
    /// Finalization epoch, not identity.
    finalization_epoch: u64,
    /// Authoritative position, not identity.
    authoritative_position: u64,
    /// One retained time shared by all projections of this act.
    logical_time: u64,
}

/// Previously accepted whole acts and external names, checked locally before use.
/// The constructor checks representation, not host admission or authentication.
/// (´def:acts:history´)
#[derive(Clone, Debug)]
pub struct ValidatedHistory {
    acts: Arc<Vec<ValidatedAct>>,
    references: Arc<BTreeSet<PublicReference>>,
    non_compliance: Arc<Vec<DependencyViolation>>,
    time_evidence: Arc<Vec<TimeEvidence>>,
}

/// A committed-dependency violation retained without rewriting finalized history.
/// This is local evidence, not cryptographic verification of an opening.
/// (´def:acts:history´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyViolation {
    /// Finalized act whose declared dependency fails compliance.
    pub act: ActId,
    /// Exact dependency identity retained in the opening.
    pub dependency: ActId,
    /// Missing, non-earlier or self dependency; representation errors still refuse.
    pub cause: DependencyCause,
}

impl ValidatedHistory {
    /// Read recurrence evidence without replacing retained finalization metadata.
    /// (´def:acts:history´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn time_evidence(&self) -> &[TimeEvidence] {
        &self.time_evidence
    }

    /// Read accepted acts unchanged, in the supplied presentation order.
    /// (´def:acts:history´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn acts(&self) -> &[ValidatedAct] {
        &self.acts
    }

    /// Read all available opening violations, ordered by act position and identity.
    /// Tombstoned openings provide no compliance verdict.
    /// (´def:acts:history´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn non_compliance(&self) -> &[DependencyViolation] {
        &self.non_compliance
    }
}

/// Finite declaration representation causes.
/// (´def:acts:declarations´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationCause {
    /// A key requires a namespace.
    #[error("empty declaration namespace")]
    EmptyNamespace,
    /// A key requires a name.
    #[error("empty declaration name")]
    EmptyName,
    /// Retrospective announcements would change historical answers.
    #[error("effective boundary before announcement")]
    LateAnnouncement,
}

/// Dependency and boundary refusals preserve missing information as missing.
/// (´def:acts:dependencies´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DependencyCause {
    /// Full-empty has its own explicit representation.
    #[error("empty full list; use full-empty")]
    EmptyFull,
    /// Input exceeds the declared local bound.
    #[error("dependency list exceeds bound")]
    TooMany,
    /// The list must increase strictly by structural act identity.
    #[error("dependency list is not canonical")]
    NonCanonical,
    /// An act cannot depend on itself.
    #[error("self dependency")]
    SelfDependency,
    /// A dependency is absent from both fixed accepted history and the proposed batch.
    #[error("missing dependency")]
    Missing,
    /// Each dependency must strictly precede its dependent act.
    #[error("dependency does not precede act")]
    NotEarlier,
    /// Fixed history must precede the boundary, and proposals must not precede it.
    #[error("act on wrong side of boundary")]
    BoundaryPlacement,
}

/// Finite local representation causes, suitable for exhaustive matching.
/// (´def:acts:validation´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InvalidCause {
    /// The identity's author is empty.
    #[error("empty author")]
    EmptyAuthor,
    /// The identity's family is empty.
    #[error("empty family")]
    EmptyFamily,
    /// Authentication evidence is absent; nonempty evidence is not authenticated here.
    #[error("empty authentication evidence")]
    EmptyAuthentication,
    /// A quantity field has no name.
    #[error("empty quantity name")]
    EmptyQuantityName,
    /// Two quantity fields claim one name.
    #[error("duplicate quantity name")]
    DuplicateQuantityName,
    /// A quantity has no unit.
    #[error("empty quantity unit")]
    EmptyUnit,
    /// A leg names another act, including an inconsistent author or family.
    #[error("wrong projection parent")]
    ProjectionParent,
    /// A role is outside the structural layout.
    #[error("projection role outside layout")]
    ProjectionRole,
    /// A reference contains an empty structural component.
    #[error("empty reference component")]
    ReferenceComponent,
    /// An untrusted leg attempts to own a removal fact.
    #[error("removal fact on structural leg")]
    CoLegRemoval,
    /// An act's content or dependency tombstone does not follow acceptance.
    #[error("tombstone at or before acceptance")]
    TombstonePosition,
}

/// Canonical asserted-parent or causal placement refusal.
/// (´def:acts:dependencies´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParentCause {
    /// The provisional count bound is exceeded.
    #[error("too many asserted parents")]
    TooMany,
    /// Parent identifiers are not strictly increasing.
    #[error("asserted parents are not canonical")]
    NonCanonical,
    /// An act asserts itself as parent.
    #[error("self asserted parent")]
    SelfParent,
    /// The parent is absent from history and proposals.
    #[error("unresolved asserted parent")]
    Missing,
    /// The parent is not strictly before the child.
    #[error("asserted parent is not earlier")]
    NotEarlier,
}

/// Typed local refusal; exhaustive while this workspace package is unpublished.
/// Consumers must handle new variants at compile time. No standing verdict is implied.
/// (´def:acts:validation´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// Asserted-parent metadata is noncanonical, unresolved or misplaced.
    #[error("invalid asserted parents of {act:?}, target {parent:?}: {cause}")]
    Parent {
        act: ActId,
        parent: Option<ActId>,
        cause: ParentCause,
    },
    /// Duplicate batch or previously accepted identity, even with different host positions.
    #[error("ambiguous act identity: {0:?}")]
    DuplicateAct(ActId),
    /// Two legs claim the same parent and role.
    #[error("ambiguous edge identity: {0:?}")]
    DuplicateEdge(EdgeId),
    /// A required reference is absent from accepted history and the validated batch.
    #[error("unresolved required reference: {0:?}")]
    UnresolvedReference(PublicReference),
    /// The layout's complete role set is absent.
    #[error("missing {role:?} co-leg of {act:?}")]
    MissingCoLeg { act: ActId, role: Role },
    /// A local structural field is invalid for the named typed reason.
    #[error("invalid local representation of {act:?}: {cause}")]
    InvalidRepresentation { act: ActId, cause: InvalidCause },
    /// Previously accepted history or a query contains an invalid reference.
    #[error("invalid structural reference: {0:?}")]
    InvalidReference(PublicReference),
    /// Declaration identities and boundaries must be locally well formed.
    #[error("invalid declaration {id:?}: {cause}")]
    InvalidDeclaration { id: DeclarationId, cause: DeclarationCause },
    /// A selection key is malformed independently of edition availability.
    #[error("invalid declaration query: {0}")]
    InvalidSelectionKey(DeclarationCause),
    /// A dependency or boundary representation cannot supply a complete closure.
    #[error("invalid dependencies of {act:?}, target {dependency:?}: {cause}")]
    Dependency {
        act: ActId,
        dependency: Option<ActId>,
        cause: DependencyCause,
    },
    /// Repeated identities cannot silently replace old editions.
    #[error("duplicate declaration identity: {0:?}")]
    DuplicateDeclaration(DeclarationId),
    /// Two editions would take effect at the same boundary for the same key.
    #[error("ambiguous effective declaration: {0:?}")]
    AmbiguousDeclaration(DeclarationId),
    /// No announced and effective edition exists at the requested boundary.
    #[error("no effective declaration for {namespace}/{name} at {boundary}")]
    MissingDeclaration { namespace: String, name: String, boundary: u64 },
}

/// Typed edition identity without a declaration payload or byte encoding.
/// (´def:acts:declarations´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeclarationId {
    /// Nonempty structural namespace.
    pub namespace: String,
    /// Nonempty declaration key within that namespace.
    pub name: String,
    /// Structural edition identity, not a sort priority.
    pub edition: u64,
}

/// Family-specific structural content; opaque families bind their payload separately.
/// (´def:acts:declarations´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeclarationContent {
    /// A family whose content is bound separately.
    Opaque,
    /// Immutable deployment genesis, not selected by a marker policy payload.
    Deployment { genesis_at: u64 },
    /// SHA-256 of the complete marker policy under the internal policy digest framing.
    MarkerPolicy { recipe: String, digest: [u8; 32] },
}

/// Announcement and effective boundaries for an opaque declaration identity.
/// (´def:acts:declarations´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    /// Immutable edition identity; content is keyed by declaration family.
    pub id: DeclarationId,
    /// Boundary at which this edition was publicly announced.
    pub announced_at: u64,
    /// First boundary where the edition is in force, not before announcement.
    pub effective_at: u64,
    /// Structural deployment or policy content, otherwise an opaque family.
    pub content: DeclarationContent,
}

/// Which immutable validated source resolves a public identity.
/// (´def:acts:references´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceOrigin {
    /// Caller-supplied previously accepted history.
    History,
    /// A complete act or leg in this validated batch.
    Batch,
}

/// Read-only complete acts; borrowing prevents mutation after validation.
/// (´def:acts:validation´)
#[derive(Debug)]
pub struct ValidatedRecords {
    acts: Vec<ValidatedAct>,
    history: ValidatedHistory,
    declarations: Vec<Declaration>,
}

impl ValidatedRecords {
    /// Read the fixed accepted history, including its retained non-compliance.
    /// (´def:acts:history´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn history(&self) -> &ValidatedHistory {
        &self.history
    }

    /// Return whole acts, never a flattened list of accounting co-legs.
    /// (´def:acts:validation´)
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "complete-act-access",
            source_item = "ValidatedRecords::acts"
        ),
        ret
    )]
    pub fn acts(&self) -> &[ValidatedAct] {
        &self.acts
    }
}

fn valid_id(id: &ActId) -> bool {
    !id.author.is_empty() && !id.family.is_empty()
}
fn valid_reference(reference: &PublicReference) -> bool {
    match reference {
        PublicReference::Act(id) | PublicReference::Minted(id) => valid_id(id),
        PublicReference::Edge(id) => valid_id(&id.act),
        PublicReference::Named { namespace, name } => !namespace.is_empty() && !name.is_empty(),
    }
}

fn mints(id: &ActId, layout: Layout, role: Role, target: &PublicReference) -> bool {
    let terminal = match id.family.as_str() {
        "Publish" | "Owner" => Some((Layout::Binary, Role::Binary)),
        "Participant" | "Review" | "Send" | "Bid" => Some((Layout::Paired, Role::T)),
        _ => None,
    };
    terminal == Some((layout, role)) && target == &PublicReference::Minted(id.clone())
}

fn insert_minted_reference(act: &CandidateAct, references: &mut BTreeSet<PublicReference>) {
    if act
        .legs
        .iter()
        .any(|leg| mints(&act.id, act.body.layout, leg.id.role, &leg.target))
    {
        references.insert(PublicReference::Minted(act.id.clone()));
    }
}

/// Validate candidates, previously accepted history and opaque declaration editions.
/// Author and family have one representation in `ActId`. All downstream operations
/// require this immutable view; no authentication or membership verdict is implied.
/// (´def:acts:validation´)
///
/// # Errors
/// Returns a typed ambiguity, missing reference or co-leg, invalid local cause,
/// or malformed/ambiguous declaration. Tombstones must follow act acceptance.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "validate-record",
        source_item = "validate_record"
    ),
    ret
)]
pub fn validate_record(
    acts: &[CandidateAct],
    history: &ValidatedHistory,
    declarations: &[Declaration],
) -> Result<ValidatedRecords, ValidationError> {
    let bytes = validation_started(acts);
    let result = validate(acts, history, declarations);
    validation_finished(bytes, acts.len(), result.is_ok());
    result
}

fn validation_started(acts: &[CandidateAct]) -> f64 {
    let bytes = carrier_bytes(acts);
    metrics::gauge!("records__root__sig__design__records__active_validation").increment(1.0);
    metrics::gauge!("records__root__sig__design__records__live_carrier_bytes").increment(bytes);
    metrics::histogram!("records__root__sig__design__records__input_bytes").record(bytes);
    bytes
}

fn validation_finished(bytes: f64, count: usize, success: bool) {
    metrics::gauge!("records__root__sig__design__records__live_carrier_bytes").decrement(bytes);
    metrics::gauge!("records__root__sig__design__records__active_validation").decrement(1.0);
    if success {
        metrics::counter!("records__root__sig__design__records__validated_records")
            .increment(u64::try_from(count).unwrap_or(u64::MAX));
    } else {
        refused();
    }
}

fn refused() {
    tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    metrics::counter!("records__root__sig__design__records__refusals").increment(1);
}

// Estimated inline candidate storage only; heap allocations and history are not
// measured. This explicitly bounded estimate never participates in validation.
fn carrier_bytes(acts: &[CandidateAct]) -> f64 {
    let bytes = std::mem::size_of_val(acts);
    let bounded = u32::try_from(bytes).unwrap_or(u32::MAX);
    f64::from(bounded)
}

fn validate(
    acts: &[CandidateAct],
    history: &ValidatedHistory,
    declarations: &[Declaration],
) -> Result<ValidatedRecords, ValidationError> {
    let references = local_references(acts, history)?;
    let available: BTreeMap<_, _> = history
        .acts
        .iter()
        .map(|act| (&act.id, (act.position(), act.logical_time)))
        .chain(acts.iter().map(|act| (&act.id, order(act))))
        .collect();
    for act in acts {
        validate_act(act, &references, &history.references)?;
        validate_dependencies(act, &available)?;
        validate_parents(act, &available)?;
    }
    validate_declarations(declarations)?;
    Ok(ValidatedRecords {
        acts: acts.iter().map(validated_act).collect(),
        history: history.clone(),
        declarations: declarations.to_vec(),
    })
}

fn local_references(acts: &[CandidateAct], history: &ValidatedHistory) -> Result<BTreeSet<PublicReference>, ValidationError> {
    let mut identities = BTreeSet::new();
    let mut references = BTreeSet::new();
    for act in acts {
        if history.references.contains(&PublicReference::Act(act.id.clone())) || !identities.insert(&act.id) {
            return Err(ValidationError::DuplicateAct(act.id.clone()));
        }
        references.insert(PublicReference::Act(act.id.clone()));
        insert_minted_reference(act, &mut references);
        for leg in &act.legs {
            references.insert(PublicReference::Edge(leg.id.clone()));
        }
    }
    Ok(references)
}

fn validate_act(
    act: &CandidateAct,
    references: &BTreeSet<PublicReference>,
    history_references: &BTreeSet<PublicReference>,
) -> Result<(), ValidationError> {
    let invalid = |cause| ValidationError::InvalidRepresentation {
        act: act.id.clone(),
        cause,
    };
    if act.id.author.is_empty() {
        return Err(invalid(InvalidCause::EmptyAuthor));
    }
    if act.id.family.is_empty() {
        return Err(invalid(InvalidCause::EmptyFamily));
    }
    if act.authentication_evidence.is_empty() {
        return Err(invalid(InvalidCause::EmptyAuthentication));
    }
    let mut fields = BTreeSet::new();
    for (name, quantity) in &act.body.quantities {
        if name.is_empty() {
            return Err(invalid(InvalidCause::EmptyQuantityName));
        }
        if quantity.unit.is_empty() {
            return Err(invalid(InvalidCause::EmptyUnit));
        }
        if !fields.insert(name) {
            return Err(invalid(InvalidCause::DuplicateQuantityName));
        }
    }
    let required: &[Role] = match act.body.layout {
        Layout::Binary => &[Role::Binary],
        Layout::Paired => &[Role::A, Role::T],
    };
    let mut roles = BTreeSet::new();
    for leg in &act.legs {
        if leg.id.act != act.id {
            return Err(invalid(InvalidCause::ProjectionParent));
        }
        if !required.contains(&leg.id.role) {
            return Err(invalid(InvalidCause::ProjectionRole));
        }
        if !roles.insert(leg.id.role) {
            return Err(ValidationError::DuplicateEdge(leg.id.clone()));
        }
        if leg.removal.is_some() {
            return Err(invalid(InvalidCause::CoLegRemoval));
        }
        for reference in [&leg.source, &leg.target] {
            if !valid_reference(reference) {
                return Err(invalid(InvalidCause::ReferenceComponent));
            }
            // Node terms are representable without an anchor or a supplied name.
            // Act, edge and external protocol identities still require lookup.
            if reference.identifier_class().is_none()
                && !references.contains(reference)
                && !history_references.contains(reference)
            {
                return Err(ValidationError::UnresolvedReference(reference.clone()));
            }
        }
    }
    let dependency_removal = match act.projections.dependency {
        DependencyProjection::Tombstoned(position) => Removal::Tombstoned(position),
        _ => Removal::Live,
    };
    for state in [act.projections.content, dependency_removal] {
        if matches!(state, Removal::Tombstoned(position) if position <= order(act).0) {
            return Err(invalid(InvalidCause::TombstonePosition));
        }
    }
    for role in required {
        if !roles.contains(role) {
            return Err(ValidationError::MissingCoLeg {
                act: act.id.clone(),
                role: *role,
            });
        }
    }
    for reference in &act.protocol_references {
        if !valid_reference(reference) {
            return Err(invalid(InvalidCause::ReferenceComponent));
        }
        let qualifier = matches!(reference, PublicReference::Named { namespace, .. } if namespace == "license");
        if !qualifier && !references.contains(reference) && !history_references.contains(reference) {
            return Err(ValidationError::UnresolvedReference(reference.clone()));
        }
    }
    Ok(())
}

fn validate_declarations(declarations: &[Declaration]) -> Result<(), ValidationError> {
    let mut editions = BTreeSet::new();
    let mut boundaries = BTreeSet::new();
    for declaration in declarations {
        let id = &declaration.id;
        let cause = invalid_key(&id.namespace, &id.name)
            .or_else(|| (declaration.effective_at < declaration.announced_at).then_some(DeclarationCause::LateAnnouncement));
        if let Some(cause) = cause {
            return Err(ValidationError::InvalidDeclaration { id: id.clone(), cause });
        }
        if !editions.insert(id) {
            return Err(ValidationError::DuplicateDeclaration(id.clone()));
        }
        if !boundaries.insert((&id.namespace, &id.name, declaration.effective_at)) {
            return Err(ValidationError::AmbiguousDeclaration(id.clone()));
        }
    }
    Ok(())
}

/// Resolve a structural reference from the validated batch or accepted history.
/// Removal never erases a protocol identity. No repository or database is read.
/// (´def:acts:references´)
///
/// # Errors
/// Returns `InvalidReference` for malformed queries, or `UnresolvedReference` if absent.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "resolve-public-reference",
        source_item = "resolve_public_reference"
    ),
    ret
)]
pub fn resolve_public_reference(
    records: &ValidatedRecords,
    reference: &PublicReference,
) -> Result<ReferenceOrigin, ValidationError> {
    let result = if !valid_reference(reference) {
        Err(ValidationError::InvalidReference(reference.clone()))
    } else if records.history.references.contains(reference) {
        Ok(ReferenceOrigin::History)
    } else if records.acts.iter().any(|act| match reference {
        PublicReference::Act(id) => id == &act.id,
        PublicReference::Edge(id) => act.legs.iter().any(|leg| &leg.id == id),
        PublicReference::Named { .. } => false,
        PublicReference::Minted(id) => {
            id == &act.id
                && act
                    .legs
                    .iter()
                    .any(|leg| mints(&act.id, act.body.layout, leg.id.role, &leg.target))
        }
    }) {
        Ok(ReferenceOrigin::Batch)
    } else {
        Err(ValidationError::UnresolvedReference(reference.clone()))
    };
    if result.is_ok() {
        metrics::counter!("records__root__sig__design__records__resolved_references").increment(1);
    } else {
        refused();
    }
    result
}

/// Select the latest effective opaque edition of a key at a historical boundary.
/// Edition numbers and collection order are not priority. Contents belong to bite 2.
/// (´def:acts:declarations´)
///
/// # Errors
/// Returns `InvalidSelectionKey` for malformed keys, or `MissingDeclaration` if no announced and effective edition exists.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "select-effective-declaration",
        source_item = "select_effective_declaration"
    ),
    ret
)]
pub fn select_effective_declaration<'a>(
    records: &'a ValidatedRecords,
    namespace: &str,
    name: &str,
    boundary: u64,
) -> Result<&'a Declaration, ValidationError> {
    if let Some(cause) = invalid_key(namespace, name) {
        refused();
        return Err(ValidationError::InvalidSelectionKey(cause));
    }
    let selected = records
        .declarations
        .iter()
        .filter(|d| d.id.namespace == namespace && d.id.name == name && d.announced_at <= boundary && d.effective_at <= boundary)
        .max_by_key(|d| d.effective_at);
    selected.ok_or_else(|| {
        refused();
        ValidationError::MissingDeclaration {
            namespace: namespace.into(),
            name: name.into(),
            boundary,
        }
    })
}

fn invalid_key(namespace: &str, name: &str) -> Option<DeclarationCause> {
    if namespace.is_empty() {
        Some(DeclarationCause::EmptyNamespace)
    } else if name.is_empty() {
        Some(DeclarationCause::EmptyName)
    } else {
        None
    }
}

fn validated_act(act: &CandidateAct) -> ValidatedAct {
    ValidatedAct {
        id: act.id.clone(),
        body: act.body.clone(),
        projections: act.projections.clone(),
        legs: act
            .legs
            .iter()
            .map(|leg| ValidatedLeg {
                id: leg.id.clone(),
                source: leg.source.clone(),
                target: leg.target.clone(),
            })
            .collect(),
        protocol_references: act.protocol_references.clone(),
        authentication_evidence: act.authentication_evidence.clone(),
        finalization_epoch: act.finalization_epoch,
        authoritative_position: act.authoritative_position,
        logical_time: act.logical_time,
    }
}

fn dependency_error(act: &ActId, dependency: Option<&ActId>, cause: DependencyCause) -> ValidationError {
    ValidationError::Dependency {
        act: act.clone(),
        dependency: dependency.cloned(),
        cause,
    }
}

fn order(act: &CandidateAct) -> (Position, u64) {
    ((act.finalization_epoch, act.authoritative_position), act.logical_time)
}

fn precedes(left: (Position, u64), right: (Position, u64)) -> bool {
    left.0 < right.0 && (left.0.0, left.1, left.0.1) < (right.0.0, right.1, right.0.1)
}

fn check_times(
    ordered: &[&CandidateAct],
    available: &BTreeMap<&ActId, (Position, u64)>,
    violations: &[DependencyViolation],
) -> Vec<TimeEvidence> {
    if ordered.windows(2).any(|pair| order(pair[0]).0 == order(pair[1]).0) {
        return ordered
            .iter()
            .map(|act| TimeEvidence {
                act: act.id.clone(),
                verdict: TimeVerdict::AmbiguousPlacement,
            })
            .collect();
    }
    let mut frontiers = BTreeMap::new();
    let mut evidence = Vec::new();
    for act in ordered {
        let endpoints: BTreeSet<_> = act.legs.iter().flat_map(|leg| [&leg.source, &leg.target]).collect();
        let verdict = if violations.iter().any(|violation| violation.act == act.id) {
            TimeVerdict::NonCompliant
        } else if matches!(act.projections.dependency, DependencyProjection::Tombstoned(_)) {
            TimeVerdict::UnavailableOpening
        } else {
            let dependencies = match &act.projections.dependency {
                DependencyProjection::Full(ids) => ids.as_slice(),
                DependencyProjection::FullEmpty | DependencyProjection::Tombstoned(_) => &[],
            };
            let endpoint_max = endpoints
                .iter()
                .filter_map(|endpoint| frontiers.get(endpoint))
                .copied()
                .max()
                .unwrap_or(0);
            let predecessor_max = act
                .body
                .asserted_parents
                .iter()
                .chain(dependencies)
                .filter_map(|id| available.get(id))
                .map(|(_, time)| *time)
                .max()
                .unwrap_or(0);
            let expected = u128::from(endpoint_max.max(predecessor_max)) + 1;
            if expected == u128::from(act.logical_time) {
                TimeVerdict::Matches
            } else {
                TimeVerdict::Mismatch {
                    attached: act.logical_time,
                    expected,
                }
            }
        };
        for endpoint in endpoints {
            frontiers.insert(endpoint, act.logical_time);
        }
        evidence.push(TimeEvidence {
            act: act.id.clone(),
            verdict,
        });
    }
    evidence
}

fn validate_dependencies(act: &CandidateAct, available: &BTreeMap<&ActId, (Position, u64)>) -> Result<(), ValidationError> {
    if let Some(violation) = dependency_violations(act, available)?.first() {
        return Err(dependency_error(&act.id, Some(&violation.dependency), violation.cause));
    }
    Ok(())
}

fn dependency_violations(
    act: &CandidateAct,
    available: &BTreeMap<&ActId, (Position, u64)>,
) -> Result<Vec<DependencyViolation>, ValidationError> {
    let DependencyProjection::Full(dependencies) = &act.projections.dependency else {
        return Ok(Vec::new());
    };
    if dependencies.is_empty() {
        return Err(dependency_error(&act.id, None, DependencyCause::EmptyFull));
    }
    if dependencies.len() > MAX_DEPENDENCIES {
        return Err(dependency_error(&act.id, None, DependencyCause::TooMany));
    }
    if dependencies.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(dependency_error(&act.id, None, DependencyCause::NonCanonical));
    }
    let mut violations = Vec::new();
    for dependency in dependencies {
        let cause = if dependency == &act.id {
            Some(DependencyCause::SelfDependency)
        } else {
            match available.get(dependency) {
                None => Some(DependencyCause::Missing),
                Some(position) if !precedes(*position, order(act)) => Some(DependencyCause::NotEarlier),
                Some(_) => None,
            }
        };
        if let Some(cause) = cause {
            violations.push(DependencyViolation {
                act: act.id.clone(),
                dependency: dependency.clone(),
                cause,
            });
        }
    }
    Ok(violations)
}

fn validate_parents(act: &CandidateAct, available: &BTreeMap<&ActId, (Position, u64)>) -> Result<(), ValidationError> {
    validate_parents_with(act, available, precedes)
}

fn validate_parents_with(
    act: &CandidateAct,
    available: &BTreeMap<&ActId, (Position, u64)>,
    earlier: impl Fn((Position, u64), (Position, u64)) -> bool,
) -> Result<(), ValidationError> {
    let error = |parent: Option<&ActId>, cause| ValidationError::Parent {
        act: act.id.clone(),
        parent: parent.cloned(),
        cause,
    };
    let parents = &act.body.asserted_parents;
    if parents.len() > MAX_ASSERTED_PARENTS {
        return Err(error(None, ParentCause::TooMany));
    }
    if parents.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(error(None, ParentCause::NonCanonical));
    }
    for parent in parents {
        if parent == &act.id {
            return Err(error(Some(parent), ParentCause::SelfParent));
        }
        let target = available
            .get(parent)
            .ok_or_else(|| error(Some(parent), ParentCause::Missing))?;
        if !earlier(*target, order(act)) {
            return Err(error(Some(parent), ParentCause::NotEarlier));
        }
    }
    Ok(())
}

/// Check caller-supplied accepted whole history and separately supplied external names.
/// Act and edge references are derived together; free-standing act/edge names refuse.
/// Representation errors refuse; committed-dependency violations remain evidence.
/// This does not certify cryptographic or host admission.
/// (´def:acts:history´)
///
/// # Errors
/// Returns typed local, dependency-content, parent, duplicate or invalid external-name refusals.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "validate-history",
        source_item = "validate_history"
    ),
    ret
)]
pub fn validate_history(acts: &[CandidateAct], names: &[PublicReference]) -> Result<ValidatedHistory, ValidationError> {
    let bytes = validation_started(acts);
    let result = history_snapshot(acts, names);
    validation_finished(bytes, acts.len(), result.is_ok());
    result
}

fn history_snapshot(acts: &[CandidateAct], names: &[PublicReference]) -> Result<ValidatedHistory, ValidationError> {
    let mut references = BTreeSet::new();
    for name in names {
        if !matches!(name, PublicReference::Named { .. }) || !valid_reference(name) {
            return Err(ValidationError::InvalidReference(name.clone()));
        }
        references.insert(name.clone());
    }
    for act in acts {
        if !references.insert(PublicReference::Act(act.id.clone())) {
            return Err(ValidationError::DuplicateAct(act.id.clone()));
        }
        insert_minted_reference(act, &mut references);
        for leg in &act.legs {
            references.insert(PublicReference::Edge(leg.id.clone()));
        }
    }
    for act in acts {
        validate_act(act, &references, &BTreeSet::new())?;
    }
    let available: BTreeMap<_, _> = acts.iter().map(|act| (&act.id, order(act))).collect();
    let mut ordered: Vec<_> = acts.iter().collect();
    ordered.sort_by_key(|act| (order(act).0, &act.id));
    let mut non_compliance = Vec::new();
    for act in &ordered {
        non_compliance.extend(dependency_violations(act, &available)?);
        validate_parents_with(act, &available, |parent, child| parent.0 < child.0)?;
    }
    Ok(ValidatedHistory {
        acts: Arc::new(acts.iter().map(validated_act).collect()),
        references: Arc::new(references),
        time_evidence: Arc::new(check_times(&ordered, &available, &non_compliance)),
        non_compliance: Arc::new(non_compliance),
    })
}

/// Derive a validated edge's dependency status from its owning whole act.
/// The validated leg has no independent status or candidate removal field.
/// (´def:acts:dependencies´)
///
/// # Errors
/// Refuses malformed or unresolved structural edge identities.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "dependency-status",
        source_item = "dependency_status"
    ),
    ret
)]
pub fn dependency_status(records: &ValidatedRecords, edge: &EdgeId) -> Result<DependencyStatus, ValidationError> {
    let reference = PublicReference::Edge(edge.clone());
    let result = if !valid_id(&edge.act) {
        Err(ValidationError::InvalidReference(reference))
    } else if let Some(act) = records
        .acts
        .iter()
        .chain(records.history.acts.iter())
        .find(|act| act.legs.iter().any(|leg| &leg.id == edge))
    {
        Ok(match &act.projections.dependency {
            DependencyProjection::FullEmpty => DependencyStatus::FullEmpty,
            DependencyProjection::Full(_) => DependencyStatus::Full,
            DependencyProjection::Tombstoned(position) => DependencyStatus::Tombstoned(*position),
        })
    } else {
        Err(ValidationError::UnresolvedReference(reference))
    };
    if result.is_err() {
        refused();
    }
    result
}

/// One proposed root and its complete principal closure, without partition membership.
/// (´def:acts:boundary-inputs´)
#[derive(Debug)]
pub struct PrincipalClosure {
    /// Proposed structural root.
    root: ActId,
    /// Whole-act identities in authoritative order, with no duplicate within a closure.
    members: Vec<ActId>,
}

/// Read-only whole-act inputs for the later graph partition.
/// (´def:acts:boundary-inputs´)
#[derive(Debug)]
pub struct BoundaryInputs<'a> {
    /// Node visits, parent inspections, inherited-member insert attempts and emitted members.
    /// None means counter overflow, never a work-limit refusal.
    work: Option<u64>,
    /// Fixed pre-epoch cut: history lies before it and proposals at or after it.
    boundary: Position,
    /// Union of all closures, each whole act carried once in authoritative order.
    acts: Vec<&'a ValidatedAct>,
    /// Overlap is retained; no connected components or disjoint blocks are computed.
    closures: Vec<PrincipalClosure>,
}

/// Assemble principal closures against fixed pre-epoch history, preserving overlaps.
/// Structural sorting never substitutes for authoritative placement; co-legs travel
/// only inside their act. This supplies inputs, not the partition or its membership claim.
/// (´def:acts:boundary-inputs´)
///
/// # Errors
/// Refuses invalid boundary placement. Parent resolution and order are checked at validation.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "assemble-boundary-inputs",
        source_item = "assemble_boundary_inputs"
    ),
    ret
)]
pub fn assemble_boundary_inputs(records: &ValidatedRecords, boundary: Position) -> Result<BoundaryInputs<'_>, ValidationError> {
    let result = assemble(records, boundary);
    match &result {
        Ok(inputs) => metrics::histogram!("records__root__sig__design__records__records_per_boundary")
            .record(carrier_count(inputs.acts.len())),
        Err(_) => refused(),
    }
    result
}

fn carrier_count(count: usize) -> f64 {
    f64::from(u32::try_from(count).unwrap_or(u32::MAX))
}

fn assemble(records: &ValidatedRecords, boundary: Position) -> Result<BoundaryInputs<'_>, ValidationError> {
    for act in records.history.acts.iter() {
        if act.position() >= boundary {
            return Err(dependency_error(&act.id, None, DependencyCause::BoundaryPlacement));
        }
    }
    for act in &records.acts {
        if act.position() < boundary {
            return Err(dependency_error(&act.id, None, DependencyCause::BoundaryPlacement));
        }
    }
    let mut roots: Vec<_> = records.acts.iter().collect();
    roots.sort_by_key(|act| (act.position(), &act.id));
    // Strict parent placement provides a topological order. This shared memo
    // visits each proposal once; history parents have no memo entry and add nothing.
    let mut visited: BTreeMap<&ActId, BTreeSet<&ActId>> = BTreeMap::new();
    let mut work = Some(0_u64);
    let mut count = || {
        work = work.and_then(|total| total.checked_add(1));
        metrics::counter!("records__root__sig__design__records__assembly_steps").increment(1);
    };
    for root in &roots {
        count();
        let mut members = BTreeSet::from([&root.id]);
        for parent in &root.body.asserted_parents {
            count();
            if let Some(ancestors) = visited.get(parent) {
                for ancestor in ancestors {
                    count();
                    members.insert(*ancestor);
                }
            }
        }
        visited.insert(&root.id, members);
    }
    let mut closures = Vec::new();
    let positions: BTreeMap<_, _> = roots.iter().map(|act| (&act.id, act.position())).collect();
    for root in &roots {
        let members = &visited[&root.id];
        let mut ordered: Vec<_> = members
            .iter()
            .map(|id| {
                count();
                (*id).clone()
            })
            .collect();
        ordered.sort_by_key(|id| (positions[id], id.clone()));
        closures.push(PrincipalClosure {
            root: root.id.clone(),
            members: ordered,
        });
    }
    Ok(BoundaryInputs {
        boundary,
        acts: roots,
        closures,
        work,
    })
}

impl ValidatedLeg {
    /// Read the validated id without permitting replacement.
    /// (´def:acts:projection´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn id(&self) -> &EdgeId {
        &self.id
    }
    /// Read the validated source without permitting replacement.
    /// (´def:acts:projection´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn source(&self) -> &PublicReference {
        &self.source
    }
    /// Read the validated target without permitting replacement.
    /// (´def:acts:projection´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn target(&self) -> &PublicReference {
        &self.target
    }
}

impl ValidatedAct {
    /// Read the published epoch and position pair.
    /// (´def:acts:carrier´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn position(&self) -> Position {
        (self.finalization_epoch, self.authoritative_position)
    }
    /// Read the sole attached logical time inherited by every owned projection.
    /// (´def:acts:carrier´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn logical_time(&self) -> u64 {
        self.logical_time
    }

    /// Read the validated id without permitting replacement.
    /// (´def:acts:carrier´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn id(&self) -> &ActId {
        &self.id
    }
    /// Read the validated body without permitting replacement.
    /// (´def:acts:carrier´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn body(&self) -> &StructuralBody {
        &self.body
    }
    /// Read the validated legs without permitting replacement.
    /// (´def:acts:carrier´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn legs(&self) -> &[ValidatedLeg] {
        &self.legs
    }
    /// Read the validated projections without permitting replacement.
    /// (´def:acts:carrier´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn projections(&self) -> &RemovableProjections {
        &self.projections
    }
    /// Read the validated protocol references without permitting replacement.
    /// (´def:acts:carrier´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn protocol_references(&self) -> &[PublicReference] {
        &self.protocol_references
    }
    /// Read the validated authentication evidence without permitting replacement.
    /// (´def:acts:carrier´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn authentication_evidence(&self) -> &[u8] {
        &self.authentication_evidence
    }
    /// Read the validated finalization epoch without permitting replacement.
    /// (´def:acts:carrier´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn finalization_epoch(&self) -> u64 {
        self.finalization_epoch
    }
    /// Read the validated authoritative position without permitting replacement.
    /// (´def:acts:carrier´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn authoritative_position(&self) -> u64 {
        self.authoritative_position
    }
}

impl PrincipalClosure {
    /// Read the validated root without permitting replacement.
    /// (´def:acts:boundary-inputs´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn root(&self) -> &ActId {
        &self.root
    }
    /// Read the validated members without permitting replacement.
    /// (´def:acts:boundary-inputs´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn members(&self) -> &[ActId] {
        &self.members
    }
}

impl<'a> BoundaryInputs<'a> {
    /// Read the validated boundary without permitting replacement.
    /// (´def:acts:boundary-inputs´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn boundary(&self) -> Position {
        self.boundary
    }
    /// Read the validated acts without permitting replacement.
    /// (´def:acts:boundary-inputs´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn acts(&self) -> &[&'a ValidatedAct] {
        &self.acts
    }
    /// Read the validated closures without permitting replacement.
    /// (´def:acts:boundary-inputs´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn closures(&self) -> &[PrincipalClosure] {
        &self.closures
    }
    /// Read the validated work without permitting replacement.
    /// (´def:acts:boundary-inputs´)
    #[must_use]
    /// Justified: Pure immutable field access inherits the labelled records operation that obtained this validated view; it is not a new act-level operation.
    pub fn work(&self) -> Option<u64> {
        self.work
    }
}

#[cfg(test)]
mod tests {
    use super::{ActId, EdgeId, Role};

    /// Claim: With an injected internal declaration whose announcement is after genesis but effect is before it, the binder's announcement guard refuses independently; public declaration validation already excludes this inconsistent ordering.
    /// ´claim:burn:binding-defends-genesis-announcement´
    /// ´test:unit:deployment-announcement-guard´
    #[test]
    fn deployment_announcement_guard() {
        use super::burn::{BurnError, validate_burn};
        use super::constants::{bind_marker_policy, marker_policy_digest};
        use super::{Declaration, DeclarationContent, DeclarationId, validate_history, validate_record};
        let case = super::test_support::burn::generate(&[3]);
        let policy = case.policy;
        let burn = validate_burn(case.burn).unwrap();
        let history = validate_history(&[], &[]).unwrap();
        let declarations = [
            Declaration {
                id: DeclarationId {
                    namespace: "deployment".into(),
                    name: "genesis".into(),
                    edition: 1,
                },
                announced_at: 0,
                effective_at: 0,
                content: DeclarationContent::Deployment {
                    genesis_at: policy.genesis_at,
                },
            },
            Declaration {
                id: DeclarationId {
                    namespace: "marker".into(),
                    name: "policy".into(),
                    edition: 1,
                },
                announced_at: 0,
                effective_at: 0,
                content: DeclarationContent::MarkerPolicy {
                    recipe: "pn-records/marker-policy/v1".into(),
                    digest: marker_policy_digest(&policy),
                },
            },
        ];
        let mut records = validate_record(&[], &history, &declarations).unwrap();
        assert!(bind_marker_policy(&records, policy.clone(), &burn).is_ok());
        // Defensive internal-state injection: this ordering cannot pass validate_record.
        records.declarations[0].announced_at = policy.genesis_at + 1;
        assert_eq!(bind_marker_policy(&records, policy, &burn), Err(BurnError::DeploymentBinding));
    }

    /// Claim: A generated paired history and proposal snapshot contains one act entry per identity and two owned legs per paired act, so the internal validated carrier never promotes co-legs to accounting units.
    /// (´claim:acts:complete-acts-are-counted-once´)
    /// ´test:unit:whole-act-carrier´
    #[test]
    fn whole_act_carrier() {
        let case = super::test_support::generate(&[u64::MAX; 8]);
        let history = super::validate_history(&case.history, &case.names).unwrap();
        let records = super::validate_record(&case.proposals, &history, &[]).unwrap();
        assert_eq!(records.acts.len(), case.proposals.len());
        assert!(records.acts.iter().all(|act| act.legs.len() == 2));
        let boundary = super::assemble_boundary_inputs(&records, case.boundary).unwrap();
        assert_eq!(boundary.acts.len(), case.proposals.len());
    }

    /// Claim: Validating a batch retains the same immutable history allocations, so repeated consumers do not copy the accepted history's act bodies or reference roster.
    /// ´claim:acts:history-storage-is-shared´
    /// ´test:unit:history-storage-is-shared´
    #[test]
    fn history_storage_is_shared() {
        let history = super::validate_history(
            &[],
            &[super::PublicReference::Named {
                namespace: "fixture".into(),
                name: "accepted".into(),
            }],
        )
        .unwrap();
        assert!(super::local_references(&[], &history).unwrap().is_empty());
        let case = super::test_support::generate(&[u64::MAX]);
        let local = super::local_references(&case.proposals, &history).unwrap();
        assert_eq!(
            local.len(),
            case.proposals.iter().map(|act| 1 + act.legs.len()).sum::<usize>()
        );
        assert!(local.is_disjoint(&history.references));
        let records = super::validate_record(&[], &history, &[]).unwrap();
        assert!(super::Arc::ptr_eq(&history.acts, &records.history.acts));
        assert!(super::Arc::ptr_eq(&history.references, &records.history.references));
        assert_eq!(history.references.len(), 1);
    }

    /// Claim: Structural equality distinguishes each author, local sequence and family component and each edge role, while reconstructing the same components preserves identity without host metadata.
    /// ´claim:acts:identity-is-structural´
    /// ´test:unit:identity-components´
    #[test]
    fn identity_components() {
        let id = ActId {
            author: "author".into(),
            sequence: 7,
            family: "family".into(),
        };
        assert_eq!(
            id,
            ActId {
                author: "author".into(),
                sequence: 7,
                family: "family".into()
            }
        );
        let mut other = id.clone();
        other.author = "other".into();
        assert_ne!(id, other);
        other = id.clone();
        other.sequence = 8;
        assert_ne!(id, other);
        other = id.clone();
        other.family = "other".into();
        assert_ne!(id, other);
        assert_ne!(
            EdgeId {
                act: id.clone(),
                role: Role::A
            },
            EdgeId { act: id, role: Role::T }
        );
    }
}
