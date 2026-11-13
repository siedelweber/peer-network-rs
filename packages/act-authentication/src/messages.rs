//! Computed proposal and framed seal/approval roles, with unopened digests kept distinct.
use crate::encoding::{EncodingError, VerifiedHeader, array, bytes, text};
use pn_interchange::Value;
use pn_records::commitments::ProposalCommitment;
use sha2::{Digest, Sha256};

pub(crate) fn framed(recipe: &str, tag: &str, fields: Vec<Value>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(recipe.as_bytes());
    hash.update([0]);
    hash.update(array([text(tag), array(fields)]).to_canonical_bytes());
    hash.finalize().into()
}

/// Recipe-specific public message; no other role converts into this type.
/// (´def:authentication:messages´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalMessage(pub(crate) [u8; 32]);
impl ProposalMessage {
    /// Justified: Immutable byte access inherits the admitted message-producing operation.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:messages",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:messages",
            operation = "proposalmessage-bytes",
            source_item = "messages::ProposalMessage::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Recipe-specific public message; no other role converts into this type.
/// (´def:authentication:messages´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealMessage(pub(crate) [u8; 32]);
impl SealMessage {
    /// Justified: Immutable byte access inherits the admitted message-producing operation.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:messages",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:messages",
            operation = "sealmessage-bytes",
            source_item = "messages::SealMessage::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Recipe-specific public message; no other role converts into this type.
/// (´def:authentication:messages´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalMessage(pub(crate) [u8; 32]);
impl ApprovalMessage {
    /// Justified: Immutable byte access inherits the admitted message-producing operation.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:messages",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:messages",
            operation = "approvalmessage-bytes",
            source_item = "messages::ApprovalMessage::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Use only P computed by the profile from its admitted body and openings.
/// (´def:authentication:messages´)
#[tracing::instrument(
    name = "def:authentication:messages",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:messages",
        operation = "proposal-message",
        source_item = "messages::proposal_message"
    ),
    ret
)]
pub fn proposal_message(proposal: &pn_act_profile::ComputedProposalCommitment) -> ProposalMessage {
    ProposalMessage(proposal.as_recorded().bytes)
}

/// Unopened public digest, with no established relation to a proposal body.
/// A verifier may verify a signature over these bytes, but must separately check
/// the proposal recipe against openings before claiming a proposal relation.
/// (´def:authentication:messages´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnestablishedProposalDigest([u8; 32]);
impl UnestablishedProposalDigest {
    /// Borrow unestablished public bytes without asserting how they were produced.
    /// (´def:authentication:messages´)
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:messages",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:messages",
            operation = "unestablished-proposal-bytes",
            source_item = "messages::UnestablishedProposalDigest::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Admit the recipe label of unopened bytes, without establishing a proposal.
/// # Errors
/// Refuses another recipe; the digest itself remains unestablished.
/// (´def:authentication:messages´)
#[tracing::instrument(
    name = "def:authentication:messages",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:messages",
        operation = "unopened-proposal-digest",
        source_item = "messages::unopened_proposal_digest"
    ),
    ret
)]
pub fn unopened_proposal_digest(proposal: &ProposalCommitment) -> Result<UnestablishedProposalDigest, EncodingError> {
    if proposal.recipe != pn_act_profile::PROPOSAL_RECIPE {
        return Err(EncodingError::Recipe);
    }
    Ok(UnestablishedProposalDigest(proposal.bytes))
}
/// Bind the selected run, host and exact header bytes to the host-seal role.
/// # Errors
/// Refuses a host identity outside the material encoding form.
/// (´def:authentication:messages´)
#[tracing::instrument(
    name = "def:authentication:messages",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:messages",
        operation = "seal-message",
        source_item = "messages::seal_message"
    ),
    ret
)]
pub fn seal_message(run: &[u8; 32], host_identity: &str, header: &VerifiedHeader) -> Result<SealMessage, EncodingError> {
    if !crate::encoding::host(host_identity) {
        return Err(EncodingError::Shape);
    }
    Ok(SealMessage(framed(
        "pn-act-authentication/host-seal/v1",
        "PN-verified-act-v1",
        vec![bytes(run), text(host_identity), bytes(header.bytes())],
    )))
}
/// Bind Actor approval to the exact host realization and its retained seal.
/// # Errors
/// Refuses a host identity outside the material encoding form.
/// (´def:authentication:messages´)
#[tracing::instrument(
    name = "def:authentication:messages",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:messages",
        operation = "approval-message",
        source_item = "messages::approval_message"
    ),
    ret
)]
pub fn approval_message(
    run: &[u8; 32],
    host_identity: &str,
    header: &VerifiedHeader,
    seal: &[u8; 64],
) -> Result<ApprovalMessage, EncodingError> {
    if !crate::encoding::host(host_identity) {
        return Err(EncodingError::Shape);
    }
    Ok(ApprovalMessage(framed(
        "pn-act-authentication/actor-approval/v1",
        "PN-act-approval-v1",
        vec![bytes(run), text(host_identity), bytes(header.bytes()), bytes(seal)],
    )))
}
