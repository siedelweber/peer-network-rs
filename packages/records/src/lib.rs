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
    /// Removal state; mandatory projections must remain live.
    pub removal: Removal,
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

/// An accepted-act candidate whose local representation must be validated.
/// (´def:acts:carrier´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedAct {
    /// Authored structural identity.
    pub id: ActId,
    /// Public author; must equal the identity's author.
    pub author: String,
    /// Declared family; must equal the identity's family.
    pub family: String,
    /// Unchanged structural body with units and vintages.
    pub body: StructuralBody,
    /// Non-removable complete-act projections.
    pub mandatory: Vec<Projection>,
    /// Tombstonable dependency projections, still owned by this act.
    pub removable: Vec<Projection>,
    /// Immutable protocol references, independently required even after removal.
    pub protocol_references: Vec<PublicReference>,
    /// Public authentication evidence; retained, not cryptographically certified.
    pub authentication_evidence: Vec<u8>,
    /// Accepted finalization epoch, not identity or a quantity's vintage.
    pub finalization_epoch: u64,
    /// Host-authoritative order; never used for identity equality.
    pub authoritative_position: u64,
}

/// Typed local refusal; no refusal asserts a standing or formation verdict.
/// (´def:acts:validation´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// Even identical duplicate rows are ambiguous input, not silently deduplicated.
    DuplicateAct(ActId),
    /// Two projections claim the same parent/role identity.
    DuplicateEdge(EdgeId),
    /// A required reference is absent from the supplied resolution set and batch.
    UnresolvedReference(PublicReference),
    /// The layout's complete role set is absent.
    MissingCoLeg { act: ActId, role: Role },
    /// A local field, parent, role, removal or unit declaration is inconsistent.
    InvalidRepresentation { act: ActId, field: &'static str },
}

/// Read-only complete acts; borrowing prevents mutation after validation.
/// (´def:acts:validation´)
#[derive(Debug)]
pub struct ValidatedRecords<'a> {
    acts: &'a [AcceptedAct],
}

impl ValidatedRecords<'_> {
    /// Return whole acts, never a flattened list of accounting co-legs.
    /// (´def:acts:validation´)
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "ValidatedRecords < '_ >::acts"
        ),
        ret
    )]
    pub fn acts(&self) -> &[AcceptedAct] {
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

/// Validate local complete projections and required references for a batch.
/// (´def:acts:validation´)
///
/// # Errors
/// Returns typed ambiguity, unresolved reference, missing co-leg or local-form
/// errors. Supplied references are already resolved by the caller; this does
/// not authenticate evidence, certify family formation, or compute membership.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "validate_record"
    ),
    ret
)]
pub fn validate_record<'a>(
    acts: &'a [AcceptedAct],
    resolved: &BTreeSet<PublicReference>,
) -> Result<ValidatedRecords<'a>, ValidationError> {
    let mut identities = BTreeSet::new();
    let mut references = resolved.clone();
    for act in acts {
        if !identities.insert(&act.id) {
            return Err(ValidationError::DuplicateAct(act.id.clone()));
        }
        references.insert(PublicReference::Act(act.id.clone()));
        for projection in act.mandatory.iter().chain(&act.removable) {
            references.insert(PublicReference::Edge(projection.id.clone()));
        }
    }
    for act in acts {
        let invalid = |field| ValidationError::InvalidRepresentation {
            act: act.id.clone(),
            field,
        };
        if !valid_id(&act.id) || act.author != act.id.author || act.family != act.id.family {
            return Err(invalid("identity"));
        }
        if act.authentication_evidence.is_empty() {
            return Err(invalid("authentication_evidence"));
        }
        let mut fields = BTreeSet::new();
        for (name, quantity) in &act.body.quantities {
            if name.is_empty() || quantity.unit.is_empty() || !fields.insert(name) {
                return Err(invalid("quantities"));
            }
        }
        let required: &[Role] = match act.body.layout {
            Layout::Binary => &[Role::Binary],
            Layout::Paired => &[Role::A, Role::T],
        };
        let mut roles = BTreeSet::new();
        for projection in act.mandatory.iter().chain(&act.removable) {
            if projection.id.act != act.id || !required.contains(&projection.id.role) {
                return Err(invalid("projection_identity"));
            }
            if !roles.insert(projection.id.role) {
                return Err(ValidationError::DuplicateEdge(projection.id.clone()));
            }
            for reference in [&projection.source, &projection.target] {
                if !valid_reference(reference) {
                    return Err(invalid("projection_reference"));
                }
                if !references.contains(reference) {
                    return Err(ValidationError::UnresolvedReference(reference.clone()));
                }
            }
        }
        if act.mandatory.iter().any(|p| p.removal != Removal::Live) {
            return Err(invalid("mandatory_removal"));
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
                return Err(invalid("protocol_reference"));
            }
            if !references.contains(reference) {
                return Err(ValidationError::UnresolvedReference(reference.clone()));
            }
        }
    }
    Ok(ValidatedRecords { acts })
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
