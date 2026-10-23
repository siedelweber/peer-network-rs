//! Internal carriers; no codec, host admission or graph algorithm.
//! (´[ROOT-amend:design:bite-one-internal-envelopes]´)

use std::collections::BTreeSet;

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

/// A dependency projection's versioned removal fact, distinct from identity.
/// (´def:acts:projection´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// Present in this accepted snapshot.
    Live,
    /// Removed at the given authoritative position; the identity remains.
    Tombstoned(u64),
}

/// One owned edge projection; never an independent accounting record.
/// (´def:acts:projection´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection {
    /// Structural identity, checked against the owning act and layout.
    pub id: EdgeId,
    /// Exact source reference.
    pub source: PublicReference,
    /// Exact target reference.
    pub target: PublicReference,
    /// Untrusted input only: any supplied leg removal fact is refused.
    /// Validated legs always carry None; dependency status derives from the act.
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
    pub legs: Vec<Projection>,
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
}

/// Act-level content and dependency projections, independent of structural legs.
/// (´def:acts:projection´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemovableProjections {
    /// Content removal does not erase structural identity or public references.
    pub content: Removal,
    /// Every dependency edge derives this single act-owned removal fact.
    pub dependency: Removal,
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

/// Typed local refusal; exhaustive while this workspace package is unpublished.
/// Consumers must handle new variants at compile time. No standing verdict is implied.
/// (´def:acts:validation´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
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
    #[error("invalid declaration: {0:?}")]
    InvalidDeclaration(DeclarationId),
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

/// Announcement and effective boundaries for an opaque declaration identity.
/// (´def:acts:declarations´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    /// Immutable edition identity; contents belong to bite 2.
    pub id: DeclarationId,
    /// Boundary at which this edition was publicly announced.
    pub announced_at: u64,
    /// First boundary where the edition is in force, not before announcement.
    pub effective_at: u64,
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
pub struct ValidatedRecords<'a> {
    acts: &'a [CandidateAct],
    history: BTreeSet<PublicReference>,
    declarations: Vec<Declaration>,
}

impl ValidatedRecords<'_> {
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
            source_item = "ValidatedRecords < '_ >::acts"
        ),
        ret
    )]
    pub fn acts(&self) -> &[CandidateAct] {
        self.acts
    }
}

fn valid_id(id: &ActId) -> bool {
    !id.author.is_empty() && !id.family.is_empty()
}
fn valid_reference(reference: &PublicReference) -> bool {
    match reference {
        PublicReference::Act(id) => valid_id(id),
        PublicReference::Edge(id) => valid_id(&id.act),
        PublicReference::Named { namespace, name } => !namespace.is_empty() && !name.is_empty(),
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
pub fn validate_record<'a>(
    acts: &'a [CandidateAct],
    history: &BTreeSet<PublicReference>,
    declarations: &[Declaration],
) -> Result<ValidatedRecords<'a>, ValidationError> {
    let bytes = carrier_bytes(acts);
    metrics::gauge!("records__root__sig__design__records__active_validation").increment(1.0);
    metrics::gauge!("records__root__sig__design__records__live_carrier_bytes").increment(bytes);
    metrics::histogram!("records__root__sig__design__records__input_bytes").record(bytes);
    let result = validate(acts, history, declarations);
    metrics::gauge!("records__root__sig__design__records__live_carrier_bytes").decrement(bytes);
    metrics::gauge!("records__root__sig__design__records__active_validation").decrement(1.0);
    if result.is_ok() {
        metrics::counter!("records__root__sig__design__records__validated_records")
            .increment(u64::try_from(acts.len()).unwrap_or(u64::MAX));
    } else {
        refused();
    }
    result
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

fn validate<'a>(
    acts: &'a [CandidateAct],
    history: &BTreeSet<PublicReference>,
    declarations: &[Declaration],
) -> Result<ValidatedRecords<'a>, ValidationError> {
    for reference in history {
        if !valid_reference(reference) {
            return Err(ValidationError::InvalidReference(reference.clone()));
        }
    }
    let mut identities = BTreeSet::new();
    let mut references = history.clone();
    for act in acts {
        if history.contains(&PublicReference::Act(act.id.clone())) || !identities.insert(&act.id) {
            return Err(ValidationError::DuplicateAct(act.id.clone()));
        }
        references.insert(PublicReference::Act(act.id.clone()));
        for leg in &act.legs {
            references.insert(PublicReference::Edge(leg.id.clone()));
        }
    }
    for act in acts {
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
                if !references.contains(reference) {
                    return Err(ValidationError::UnresolvedReference(reference.clone()));
                }
            }
        }
        for state in [act.projections.content, act.projections.dependency] {
            if matches!(state, Removal::Tombstoned(position) if position <= act.authoritative_position) {
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
            if !references.contains(reference) {
                return Err(ValidationError::UnresolvedReference(reference.clone()));
            }
        }
    }
    validate_declarations(declarations)?;
    Ok(ValidatedRecords {
        acts,
        history: history.clone(),
        declarations: declarations.to_vec(),
    })
}

fn validate_declarations(declarations: &[Declaration]) -> Result<(), ValidationError> {
    let mut editions = BTreeSet::new();
    let mut boundaries = BTreeSet::new();
    for declaration in declarations {
        let id = &declaration.id;
        if id.namespace.is_empty() || id.name.is_empty() || declaration.effective_at < declaration.announced_at {
            return Err(ValidationError::InvalidDeclaration(id.clone()));
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
    records: &ValidatedRecords<'_>,
    reference: &PublicReference,
) -> Result<ReferenceOrigin, ValidationError> {
    let result = if !valid_reference(reference) {
        Err(ValidationError::InvalidReference(reference.clone()))
    } else if records.history.contains(reference) {
        Ok(ReferenceOrigin::History)
    } else if records.acts.iter().any(|act| match reference {
        PublicReference::Act(id) => id == &act.id,
        PublicReference::Edge(id) => act.legs.iter().any(|leg| &leg.id == id),
        PublicReference::Named { .. } => false,
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
/// Returns `MissingDeclaration` if no announced and effective edition exists.
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
    records: &'a ValidatedRecords<'_>,
    namespace: &str,
    name: &str,
    boundary: u64,
) -> Result<&'a Declaration, ValidationError> {
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

#[cfg(test)]
mod tests {
    use super::{ActId, EdgeId, Role};

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
