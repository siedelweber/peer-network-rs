//! Bind a declared numerical procedure and preflight its explicit scalar capabilities.
//! (´def:compiler:solve-binding´)

use crate::compiler::CompiledState;
use nrz_cas::limits::Limits;
use pn_records::solve::{Procedure, RecordError, validate_procedure};

/// Public declaration verification remains an explicit deployment premise.
/// (´def:compiler:solve-binding´)
pub trait ProcedureVerifier: std::fmt::Debug {
    fn published_procedure(&self, procedure: &Procedure) -> bool;
}

/// A procedure bound to this immutable compiled state; composition remains separate.
/// (´def:compiler:solve-binding´)
#[derive(Debug)]
pub struct BoundProcedure<'a> {
    state: &'a CompiledState,
    procedure: Procedure,
}

/// Binding refusals differ from numerical comparison outcomes.
/// (´def:compiler:solve-binding´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProcedureError {
    #[error("procedure boundary, edition or name differs from frozen package")]
    Binding,
    #[error("procedure publication verification refused")]
    Publication,
    #[error("procedure records: {0}")]
    Record(#[from] RecordError),
    #[error("nonlinear backend is not admitted")]
    Unsupported,
    #[error("numerical preflight: {0}")]
    Numeric(#[from] pn_graph::numeric::Error),
}

/// Bind the complete payload through its verifier, not just a matching procedure name.
/// (´[ROOT-sig:design:epoch]´)
/// # Errors
/// Refuses a different package binding, malformed procedure or failed publication check.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "solve::bind_procedure"
    ),
    ret
)]
pub fn bind_procedure<'a>(
    state: &'a CompiledState,
    procedure: Procedure,
    verifier: &impl ProcedureVerifier,
    limits: Limits,
) -> Result<BoundProcedure<'a>, ProcedureError> {
    let inputs = state.package().input().inputs.last().ok_or(ProcedureError::Binding)?;
    if procedure.boundary != inputs.parameters().boundary
        || procedure.edition != inputs.parameters().edition
        || procedure.name != inputs.constants().content().numerical_procedure
    {
        return Err(ProcedureError::Binding);
    }
    validate_procedure(&procedure, limits)?;
    if !verifier.published_procedure(&procedure) {
        return Err(ProcedureError::Publication);
    }
    Ok(BoundProcedure { state, procedure })
}

impl BoundProcedure<'_> {
    /// Inspect the complete retained inputs without permitting mutation.
    /// (´def:compiler:solve-binding´)
    /// Justified: Immutable access inherits the procedure binding boundary.
    #[must_use]
    pub fn inputs(&self) -> (&CompiledState, &Procedure) {
        (self.state, &self.procedure)
    }

    /// Admit only the declared scalar inventory with explicit absolute-width policy.
    /// (´[ROOT-open:design:numeric-backend]´)
    /// # Errors
    /// Refuses unsupported precision, missing policy and held compositions.
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "solve::BoundProcedure < '_ >::preflight"
        ),
        ret
    )]
    pub fn preflight(&self) -> Result<(), ProcedureError> {
        if self.procedure.enclosure.is_none() {
            return Err(ProcedureError::Unsupported);
        }
        pn_graph::numeric::preflight(&self.procedure)?;
        Ok(())
    }
}
