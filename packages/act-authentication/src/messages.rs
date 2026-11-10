//! Four role-typed public messages and the selected publication marker value.
use crate::encoding::{AUTHENTICATION_EDITION, EncodingError, VerifiedHeader, array, bytes, canonical, text};
use pn_interchange::{Map, Value};
use pn_records::burn::{AcceptedSet, Marker};
use pn_records::commitments::ProposalCommitment;
use sha2::{Digest, Sha256};

/// Exact public marker value checked against its decoded carrier. This establishes
/// representation only, not recognition, settlement or chain inclusion.
/// (´def:authentication:messages´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkerValue(Value);

fn strings(values: &std::collections::BTreeSet<String>) -> Value {
    array(values.iter().map(|s| text(s)))
}
fn marker_projection(marker: &Marker) -> Result<Value, EncodingError> {
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
    } = marker;
    let accepted = match accepted {
        AcceptedSet::CompleteList(v) => array([Value::Unsigned(0), strings(v)]),
        AcceptedSet::WholePrefix => array([Value::Unsigned(2)]),
        AcceptedSet::Commitment { commitment, openings } => array([
            Value::Unsigned(1),
            bytes(commitment),
            array(openings.iter().map(|o| array([strings(&o.members), bytes(&o.proof)]))),
        ]),
    };
    let initial = match initial_snapshot {
        None => Value::Null,
        Some(values) => Value::Map(
            Map::new(values.iter().map(|(address, amount)| {
                let (n, d) = amount.exact().split_once('/').unwrap_or((amount.exact(), "1"));
                (text(&address.0), array([array([text(n), text(d)]), text(amount.unit())]))
            }))
            .map_err(|_| EncodingError::Shape)?,
        ),
    };
    Ok(array([
        text(name),
        text(history),
        text(policy_identity),
        text(policy_edition),
        text(sequence),
        text(&index.to_string()),
        text(&history_position.to_string()),
        predecessor.map_or(Value::Null, |n| text(&n.to_string())),
        strings(lineage),
        accepted,
        initial,
    ]))
}

/// Check supplied canonical publication bytes against the complete typed marker.
/// This does not select or validate the marker's authority.
/// # Errors
/// Refuses noncanonical, oversized or mismatching publication values.
/// (´def:authentication:messages´)
#[tracing::instrument(
    name = "def:authentication:messages",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:messages",
        operation = "marker-value",
        source_item = "messages::marker_value"
    ),
    ret
)]
pub fn marker_value(input: &[u8], marker: &Marker) -> Result<MarkerValue, EncodingError> {
    let value = canonical(input)?;
    if value != marker_projection(marker)? {
        return Err(EncodingError::Shape);
    }
    Ok(MarkerValue(value))
}

fn framed(recipe: &str, tag: &str, fields: Vec<Value>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(recipe.as_bytes());
    hash.update([0]);
    hash.update(array([text(tag), array(fields)]).to_canonical_bytes());
    hash.finalize().into()
}

/// Recipe-specific public message; no other role converts into this type.
/// (´def:authentication:messages´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalMessage([u8; 32]);
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
pub struct SealMessage([u8; 32]);
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
pub struct ApprovalMessage([u8; 32]);
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

/// Recipe-specific public message; no other role converts into this type.
/// (´def:authentication:messages´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetirementMessage([u8; 32]);
impl RetirementMessage {
    /// Justified: Immutable byte access inherits the admitted message-producing operation.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:messages",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:messages",
            operation = "retirementmessage-bytes",
            source_item = "messages::RetirementMessage::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Use the supplied proposal recipe's P unchanged; no opening is available here.
/// # Errors
/// Refuses another proposal recipe. This does not authenticate P's producer.
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
pub fn proposal_message(proposal: &ProposalCommitment) -> Result<ProposalMessage, EncodingError> {
    if proposal.recipe != pn_act_profile::PROPOSAL_RECIPE {
        return Err(EncodingError::Recipe);
    }
    Ok(ProposalMessage(proposal.bytes))
}
/// Bind the selected run, host and exact header bytes to the host-seal role.
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
pub fn seal_message(run: &[u8; 32], host_identity: &str, header: &VerifiedHeader) -> SealMessage {
    SealMessage(framed(
        "pn-act-authentication/host-seal/v1",
        "PN-verified-act-v1",
        vec![bytes(run), text(host_identity), bytes(header.bytes())],
    ))
}
/// Bind Actor approval to the exact host realization and its retained seal.
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
pub fn approval_message(run: &[u8; 32], host_identity: &str, header: &VerifiedHeader, seal: &[u8; 64]) -> ApprovalMessage {
    ApprovalMessage(framed(
        "pn-act-authentication/actor-approval/v1",
        "PN-act-approval-v1",
        vec![bytes(run), text(host_identity), bytes(header.bytes()), bytes(seal)],
    ))
}
/// Bind a prospective retirement to its public author, marker and accepting epoch.
/// The marker is embedded as a value; the transaction uses display-order bytes.
/// (´def:authentication:messages´)
#[tracing::instrument(
    name = "def:authentication:messages",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:messages",
        operation = "retirement-message",
        source_item = "messages::retirement_message"
    ),
    ret
)]
pub fn retirement_message(
    run: &[u8; 32],
    author: &str,
    marker: &MarkerValue,
    accepting_epoch: u64,
    transaction_id: &[u8; 32],
) -> RetirementMessage {
    RetirementMessage(framed(
        "pn-act-authentication/key-retirement/v1",
        "PN-key-retirement-v1",
        vec![
            text(AUTHENTICATION_EDITION),
            bytes(run),
            text(author),
            marker.0.clone(),
            Value::Unsigned(accepting_epoch),
            bytes(transaction_id),
        ],
    ))
}
