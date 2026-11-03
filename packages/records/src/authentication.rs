//! Retained authentication disclosures, with presence checks only.
//! (´def:acts:authentication-disclosure´)

/// Untrusted public handshake fields. Bytes are retained exactly; their encoding,
/// bindings and signatures belong to the declared authentication verifier.
/// (´def:acts:authentication-disclosure´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationFields {
    /// Actor's proposal pre-commitment P, separate from its signature.
    pub proposal_precommitment: Vec<u8>,
    /// Actor signature over P.
    pub actor_proposal_signature: Vec<u8>,
    /// Content commitment edition, separate from its recipe identifier.
    pub content_edition: String,
    /// Dependency commitment edition, separate from its recipe identifier.
    pub dependency_edition: String,
    /// Exact disclosed representation of V; no decoding or hash is performed here.
    pub verified_header: Vec<u8>,
    /// Host seal over V, not an inclusion promise.
    pub host_seal: Vec<u8>,
    /// Actor approval witness binding the exact V and host seal.
    pub approval_binding: Vec<u8>,
    /// Declared authentication edition, not an admission of its cryptography.
    pub authentication_edition: String,
    /// Public verification material; never private keys or proposal secrets.
    pub public_verification_material: Vec<u8>,
}

/// The absent field of a malformed disclosure, not a cryptographic verdict.
/// (´def:acts:authentication-disclosure´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MissingField {
    /// P is absent.
    #[error("proposal pre-commitment is absent")]
    ProposalPrecommitment,
    /// The Actor proposal signature is absent.
    #[error("Actor proposal signature is absent")]
    ActorProposalSignature,
    /// The content edition is absent.
    #[error("content edition is absent")]
    ContentEdition,
    /// The dependency edition is absent.
    #[error("dependency edition is absent")]
    DependencyEdition,
    /// V is absent.
    #[error("verified header is absent")]
    VerifiedHeader,
    /// The host seal is absent.
    #[error("host seal is absent")]
    HostSeal,
    /// The approval witness is absent.
    #[error("approval binding is absent")]
    ApprovalBinding,
    /// The authentication edition is absent.
    #[error("authentication edition is absent")]
    AuthenticationEdition,
    /// The public verification material is absent.
    #[error("public verification material is absent")]
    PublicVerificationMaterial,
}

/// Presence-checked disclosure. This is not authenticated evidence or an act
/// eligibility verdict; all disclosed bindings remain untrusted.
/// (´def:acts:authentication-disclosure´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationDisclosure(AuthenticationFields);

impl AuthenticationDisclosure {
    /// Retain a complete disclosure without interpreting its edition or bytes.
    /// # Errors
    /// Returns the first absent field in the declared handshake order.
    /// (´def:acts:authentication-disclosure´)
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "authentication-disclosure",
            source_item = "authentication::AuthenticationDisclosure::new"
        ),
        ret
    )]
    pub fn new(fields: AuthenticationFields) -> Result<Self, MissingField> {
        let result = check(&fields).map(|()| Self(fields));
        if result.is_err() {
            crate::refused();
        }
        result
    }

    /// Exact retained fields, still untrusted by a cryptographic consumer.
    /// (´def:acts:authentication-disclosure´)
    /// Justified: Immutable field access inherits the operation that constructed the disclosure; it performs no verification.
    #[must_use]
    pub const fn fields(&self) -> &AuthenticationFields {
        &self.0
    }
}

pub(crate) fn check(fields: &AuthenticationFields) -> Result<(), MissingField> {
    for (absent, field) in [
        (fields.proposal_precommitment.is_empty(), MissingField::ProposalPrecommitment),
        (
            fields.actor_proposal_signature.is_empty(),
            MissingField::ActorProposalSignature,
        ),
        (fields.content_edition.is_empty(), MissingField::ContentEdition),
        (fields.dependency_edition.is_empty(), MissingField::DependencyEdition),
        (fields.verified_header.is_empty(), MissingField::VerifiedHeader),
        (fields.host_seal.is_empty(), MissingField::HostSeal),
        (fields.approval_binding.is_empty(), MissingField::ApprovalBinding),
        (fields.authentication_edition.is_empty(), MissingField::AuthenticationEdition),
        (
            fields.public_verification_material.is_empty(),
            MissingField::PublicVerificationMaterial,
        ),
    ] {
        if absent {
            return Err(field);
        }
    }
    Ok(())
}
