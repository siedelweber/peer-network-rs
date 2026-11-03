//! Live settlement joins immutable admitted packages; no offline authentication.
//! (´rule:admission:live-publication´)
use crate::publication::{self, AdmittedPackage, Carrier};
use pn_records::{burn, constants, live_markers};

/// Explicit published response to a lost final lineage, never an automatic repair.
/// (´rule:admission:live-publication´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    Reanchor {
        continuity: Vec<u8>,
        publication: Vec<u8>,
    },
    Follow {
        divergence: usize,
        superseded: Vec<crate::closure::ClosureRecord>,
        continuity: Vec<u8>,
        publication: Vec<u8>,
    },
}

/// Trusted deployment verification of a newly published policy and its continuity.
/// This contract does not supply offline cryptographic evidence.
/// (´rule:admission:live-publication´)
pub trait ResponseVerifier: std::fmt::Debug {
    fn published_response(&self, old: &Carrier, replacement: &Carrier, response: &Response) -> bool;
}

/// Last closed package survives a breach unchanged. Only the halt bit is mutable.
/// (´rule:admission:live-publication´)
#[derive(Debug)]
pub struct LiveState {
    closed: AdmittedPackage,
    halted: bool,
    response: Option<Response>,
}

/// Pending settlement, permanent halt and semantic replay faults remain distinct.
/// (´rule:admission:live-publication´)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("live marker assessment: {0}")]
    Live(#[from] live_markers::Error),
    #[error("original marker inputs: {0}")]
    Burn(#[from] burn::BurnError),
    #[error("publication declarations: {0}")]
    Records(#[from] pn_records::ValidationError),
    #[error("semantic restoration: {0}")]
    Publication(#[source] Box<publication::Error>),
    #[error("closed lineage is frozen")]
    Halted,
    #[error("not one unchanged consecutive closed prefix")]
    Prefix,
    #[error("new published response and policy are not established")]
    Response,
}

fn assess(carrier: &Carrier, verifier: &impl live_markers::LiveVerifier) -> Result<(), Error> {
    let empty = pn_records::validate_history(&[], &[])?;
    let declarations = pn_records::validate_record(&[], &empty, &carrier.causes.declarations)?;
    if carrier.frames.is_empty() {
        return Err(Error::Prefix);
    }
    for frame in &carrier.frames {
        let burn = burn::validate_burn(frame.burn.clone())?;
        let policy = constants::bind_marker_policy(&declarations, frame.marker_policy.clone(), &burn)?;
        live_markers::verify(
            frame.marker_history.clone(),
            &policy,
            &frame.realization.settlement_and_finality,
            verifier,
        )?;
    }
    Ok(())
}

/// Re-verify every original disclosure live, then independently restore all admission evidence.
/// (´rule:admission:live-publication´)
/// # Errors
/// Refuses missing, pending, lost or malformed disclosures and every semantic replay fault.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        operation = "live-consume",
        source_item = "live_publication::consume"
    ),
    ret
)]
pub fn consume(
    carrier: Carrier,
    verifier: &impl publication::Verifier,
    live: &impl live_markers::LiveVerifier,
) -> Result<LiveState, Error> {
    assess(&carrier, live)?;
    Ok(LiveState {
        closed: publication::consume(carrier, verifier).map_err(|e| Error::Publication(Box::new(e)))?,
        halted: false,
        response: None,
    })
}

impl LiveState {
    /// Borrow the immutable last closed package, even after a finality breach.
    /// (´rule:admission:live-publication´)
    /// Justified: Immutable access inherits live publication verification.
    #[must_use]
    pub fn closed(&self) -> &AdmittedPackage {
        &self.closed
    }

    /// A lost final lineage is sticky; pending assessment does not manufacture a breach.
    /// (´rule:admission:live-publication´)
    /// Justified: Immutable status access inherits live publication verification.
    #[must_use]
    pub fn halted(&self) -> bool {
        self.halted
    }

    /// Retained response is explicit, not a rewriting of the previous package.
    /// (´rule:admission:live-publication´)
    /// Justified: Immutable response access inherits live publication verification.
    #[must_use]
    pub fn response(&self) -> Option<&Response> {
        self.response.as_ref()
    }

    /// Check the old bound lineage before any further close.
    /// (´rule:admission:live-publication´)
    /// # Errors
    /// Refuses a sticky halt or any failed live assessment, freezing on lost lineage.
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            operation = "live-refresh",
            source_item = "live_publication::LiveState::refresh"
        ),
        ret
    )]
    pub fn refresh(&mut self, live: &impl live_markers::LiveVerifier) -> Result<(), Error> {
        if self.halted {
            return Err(Error::Halted);
        }
        match assess(self.closed.carrier(), live) {
            Err(Error::Live(live_markers::Error::Lost)) => {
                self.halted = true;
                Err(Error::Halted)
            }
            other => other,
        }
    }

    /// Close exactly one successor after verifying the unchanged original prefix.
    /// (´rule:admission:live-publication´)
    /// # Errors
    /// Refuses repeats, skips, changed prior fields, halted lineage and replay faults.
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            operation = "live-successor",
            source_item = "live_publication::LiveState::successor"
        ),
        ret
    )]
    pub fn successor(
        &mut self,
        carrier: Carrier,
        verifier: &impl publication::Verifier,
        live: &impl live_markers::LiveVerifier,
    ) -> Result<LiveState, Error> {
        self.refresh(live)?;
        let old = self.closed.carrier();
        if carrier.frames.len() != old.frames.len() + 1
            || !carrier.frames.starts_with(&old.frames)
            || carrier.numeric != old.numeric
        {
            return Err(Error::Prefix);
        }
        consume(carrier, verifier, live)
    }

    /// Start a separately published response without mutating the frozen closed state.
    /// The alternative follow route names its divergence and every superseded certificate.
    /// (´rule:admission:live-publication´)
    /// # Errors
    /// Refuses an unhalted source, the same policy, missing continuity or publication,
    /// an inaccurate supersession list, and any replacement live or admission replay fault.
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            operation = "live-respond",
            source_item = "live_publication::LiveState::respond"
        ),
        ret
    )]
    pub fn respond(
        &self,
        replacement: Carrier,
        response: Response,
        verifier: &impl publication::Verifier,
        live: &impl live_markers::LiveVerifier,
        deployment: &impl ResponseVerifier,
    ) -> Result<LiveState, Error> {
        let old = self.closed.carrier();
        let old_policy = &old.frames.last().ok_or(Error::Response)?.marker_policy;
        let new_policy = &replacement.frames.first().ok_or(Error::Response)?.marker_policy;
        if !self.halted
            || new_policy.edition == old_policy.edition
            || new_policy.published_at <= old_policy.published_at
            || new_policy.sequence == old_policy.sequence
        {
            return Err(Error::Response);
        }
        let (continuity, publication) = match &response {
            Response::Reanchor { continuity, publication } => {
                if new_policy.initial_marker == old_policy.initial_marker {
                    return Err(Error::Response);
                }
                (continuity, publication)
            }
            Response::Follow {
                divergence,
                superseded,
                continuity,
                publication,
            } => {
                if *divergence >= old.frames.len()
                    || *superseded
                        != old.frames[*divergence..]
                            .iter()
                            .map(|f| f.closure.clone())
                            .collect::<Vec<_>>()
                {
                    return Err(Error::Response);
                }
                (continuity, publication)
            }
        };
        if continuity.is_empty() || publication.is_empty() || !deployment.published_response(old, &replacement, &response) {
            return Err(Error::Response);
        }
        let mut next = consume(replacement, verifier, live)?;
        next.response = Some(response);
        Ok(next)
    }
}
