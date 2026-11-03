//! Trusted live settlement is distinct from independent offline proof validation.
//! (´rule:burn:live-marker-settlement´)
use crate::burn::{self, BurnInput, HistoryInput, PolicyInput, RecognizedMarkers, ValidatedPolicy};

/// A declared live service's assessment, not a conclusion from a depth counter.
/// (´rule:burn:live-marker-settlement´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Final,
    Pending,
    Lost,
}

/// The adapter must bind the entire history, policy, placement authority, cadence,
/// settlement depth and finality assumptions to retained evidence. This is a trusted
/// live-service contract; no offline cryptographic verification is implied.
/// (´rule:burn:live-marker-settlement´)
pub trait LiveVerifier: burn::PublicVerifier {
    fn settlement(&self, history: &HistoryInput, policy: &PolicyInput, burn: &BurnInput, evidence: &[u8]) -> Status;
}

/// Complete recognized prefix rechecked under one explicitly selected live verifier.
/// (´rule:burn:live-marker-settlement´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveMarkers {
    markers: RecognizedMarkers,
}

/// Missing proof never authorizes a smaller accepted set.
/// (´rule:burn:live-marker-settlement´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("marker recognition: {0}")]
    Recognition(#[from] burn::BurnError),
    #[error("missing live settlement evidence")]
    MissingEvidence,
    #[error("live settlement or placement is not established")]
    Pending,
    #[error("the bound final lineage is lost")]
    Lost,
}

/// Recheck complete acceptance and destruction evidence, then ask the live verifier
/// about the whole fixed disclosure. A copied name carries no authority.
/// (´rule:burn:live-marker-settlement´)
/// # Errors
/// Refuses every recognition fault, missing evidence, pending settlement or lost lineage.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "verify-live-markers",
        source_item = "live_markers::verify"
    ),
    ret
)]
pub fn verify(
    input: HistoryInput,
    policy: &ValidatedPolicy,
    evidence: &[u8],
    verifier: &impl LiveVerifier,
) -> Result<LiveMarkers, Error> {
    if evidence.is_empty() {
        return Err(Error::MissingEvidence);
    }
    let history = burn::validate_marker_history(input, policy, verifier)?;
    let markers = burn::recognize_markers(&history);
    if let Some(refusal) = markers.first_refusal() {
        return Err(refusal.cause.clone().into());
    }
    let (input, policy, burn) = history.disclosure();
    match verifier.settlement(input, policy, burn, evidence) {
        Status::Final => Ok(LiveMarkers { markers }),
        Status::Pending => Err(Error::Pending),
        Status::Lost => Err(Error::Lost),
    }
}

impl LiveMarkers {
    /// Borrow the complete checked recognition, never a rewritten accepted subset.
    /// (´rule:burn:live-marker-settlement´)
    /// Justified: Immutable access inherits the live verification operation.
    #[must_use]
    pub fn markers(&self) -> &RecognizedMarkers {
        &self.markers
    }
}
