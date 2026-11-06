//! Bind a declared numerical procedure and preflight its explicit scalar capabilities.
//! (´def:compiler:solve-binding´)

use crate::compiler::CompiledState;
use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
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
    enclosed_wall: Option<pn_records::primitive::Range>,
}

/// Binding refusals differ from numerical comparison outcomes.
/// (´def:compiler:solve-binding´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProcedureError {
    #[error("procedure boundary, edition or name differs from frozen package")]
    Binding,
    #[error("frozen wall is outside the declared reduction range")]
    WallRange,
    #[error("exact binding arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
    #[error("base entry is absent from the frozen compiler output")]
    BaseEntry,
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
    validate_procedure(&procedure, limits.clone())?;
    wall_range(state, &procedure, limits)?;
    if !verifier.published_procedure(&procedure) {
        return Err(ProcedureError::Publication);
    }
    Ok(BoundProcedure {
        state,
        procedure,
        enclosed_wall: None,
    })
}

impl BoundProcedure<'_> {
    pub(crate) fn enclosed_wall(&self) -> Option<&pn_records::primitive::Range> {
        self.enclosed_wall.as_ref()
    }

    pub(crate) fn with_enclosed_wall(&self, wall: pn_records::primitive::Range) -> Result<Self, ProcedureError> {
        let limits = self
            .procedure
            .enclosure
            .as_ref()
            .ok_or(ProcedureError::Unsupported)?
            .operation
            .clone();
        let mut b = Budget::new(limits.clone())?;
        if Rational::parse(&wall.lower, &mut b)?
            .compare(&Rational::parse(&wall.upper, &mut b)?, &mut b)?
            .is_gt()
        {
            return Err(ProcedureError::WallRange);
        }
        check_wall_range(&wall.lower, &self.procedure, limits)?;
        Ok(Self {
            state: self.state,
            procedure: self.procedure.clone(),
            enclosed_wall: Some(wall),
        })
    }
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

fn wall_range(state: &CompiledState, procedure: &Procedure, limits: Limits) -> Result<(), ProcedureError> {
    if procedure.fence.as_ref().is_none_or(|profile| profile.inverse_wall) {
        return Ok(());
    }
    let wall = state
        .package()
        .input()
        .prices
        .last()
        .ok_or(ProcedureError::Binding)?
        .wall()
        .exact();
    check_wall_range(wall, procedure, limits)
}

fn check_wall_range(wall: &str, procedure: &Procedure, limits: Limits) -> Result<(), ProcedureError> {
    let Some(policy) = &procedure.enclosure else { return Ok(()) };
    let k = policy.refinement.reduction_ceiling;
    let scale = 1_u64.checked_shl(k).filter(|v| *v > 2).ok_or(ProcedureError::WallRange)?;
    let mut b = Budget::new(limits)?;
    let lower = Rational::parse("1", &mut b)?.div(&Rational::parse(&(scale - 2).to_string(), &mut b)?, &mut b)?;
    if Rational::parse(wall, &mut b)?.compare(&lower, &mut b)?.is_lt() {
        return Err(ProcedureError::WallRange);
    }
    Ok(())
}

/// Bind the explicitly compact compiler edition.
/// (´def:compiler:solve-binding´)
pub mod compact;
