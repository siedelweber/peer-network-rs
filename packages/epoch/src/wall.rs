//! Bind a separately published reference definition without changing frozen charged prices.
//! (´[ROOT-alg:design:reference-wall]´)

use crate::solve::BoundProcedure;
use pn_records::wall::{Inputs, Record};

/// Publication binds the complete reference declaration beside its frozen procedure.
/// (´[ROOT-alg:design:reference-wall]´)
pub trait ReferenceVerifier: std::fmt::Debug {
    fn published_reference(&self, procedure: &pn_records::solve::Procedure, input: &Inputs) -> bool;
}

/// A reference definition remains separate from the package's rational debit vintage.
/// (´[ROOT-alg:design:reference-wall]´)
#[derive(Debug)]
pub struct BoundReference<'a> {
    procedure: &'a pn_records::solve::Procedure,
    input: Inputs,
}

/// Publication and scalar refusals retain distinct categories.
/// (´[ROOT-alg:design:reference-wall]´)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reference wall differs from the frozen composition or has unresolved branches")]
    Scope,
    #[error("reference composition: {0}")]
    Fence(#[from] crate::fence::Error),
    #[error("reference binding arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
    #[error("reference definition publication refused")]
    Publication,
    #[error("bound procedure: {0}")]
    Procedure(#[from] crate::solve::ProcedureError),
    #[error("reference wall: {0}")]
    Wall(#[from] pn_graph::numeric::wall::Error),
}

/// Bind the whole reference declaration through its publication verifier.
/// (´[ROOT-alg:design:reference-wall]´)
/// # Errors
/// Refuses an unsupported frozen procedure or a failed reference publication check.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "wall::bind"
    ),
    ret
)]
pub fn bind<'a>(
    bound: &'a BoundProcedure<'_>,
    input: Inputs,
    verifier: &impl ReferenceVerifier,
) -> Result<BoundReference<'a>, Error> {
    bound.preflight()?;
    let (_, procedure) = bound.inputs();
    pn_graph::numeric::wall::check_declaration(procedure, &input)?;
    if !verifier.published_reference(procedure, &input) {
        return Err(Error::Publication);
    }
    Ok(BoundReference { procedure, input })
}

impl BoundReference<'_> {
    /// Bind the replayed delivered enclosure to the frozen width and cumulative tilt.
    /// (´[ROOT-rule:design:reference-wall-consumption]´)
    /// # Errors
    /// Refuses changed scopes, incomplete branches, altered evidence and unsupported lower endpoints.
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "wall::BoundReference < '_ >::consume"
        ),
        ret
    )]
    pub fn consume<'a>(&self, bound: &BoundProcedure<'a>, record: &Record) -> Result<BoundProcedure<'a>, Error> {
        use nrz_cas::{Rational, limits::Budget};
        use pn_records::wall::Verdict;
        if bound.inputs().1 != self.procedure || self.procedure.fence.as_ref().is_none_or(|p| !p.inverse_wall) {
            return Err(Error::Scope);
        }
        let (prepared, _) = crate::fence::prepare(bound)?;
        let mut b = Budget::new(self.procedure.enclosure.as_ref().ok_or(Error::Scope)?.operation.clone())?;
        if Rational::parse(&prepared.width, &mut b)? != Rational::parse(&self.input.width, &mut b)?
            || Rational::parse(&prepared.cumulative_tilt, &mut b)? != Rational::parse(&self.input.cumulative_tilt, &mut b)?
        {
            return Err(Error::Scope);
        }
        let checked = self.replay(record)?;
        let branches = checked.branches.as_ref().ok_or(Error::Scope)?;
        if checked.indecisive || branches.above_floor != Verdict::Pass || branches.policy_valid != Verdict::Pass {
            return Err(Error::Scope);
        }
        Ok(bound.with_enclosed_wall(branches.delivered.clone())?)
    }

    /// Evaluate only the retained reference definition; the frozen package is immutable.
    /// (´[ROOT-alg:design:reference-wall]´)
    /// # Errors
    /// Refuses invalid reference domains, wrong brackets and operational stops.
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "wall::BoundReference < '_ >::evaluate"
        ),
        ret
    )]
    pub fn evaluate(&self) -> Result<Record, Error> {
        Ok(pn_graph::numeric::wall::evaluate(self.procedure, &self.input)?)
    }

    /// Rebuild all reference queries before checking the supplied record.
    /// (´[ROOT-alg:design:reference-wall]´)
    /// # Errors
    /// Refuses changed queries, attachments and derived results at their named kernel checks.
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "wall::BoundReference < '_ >::replay"
        ),
        ret
    )]
    pub fn replay(&self, record: &Record) -> Result<Record, Error> {
        Ok(pn_graph::numeric::wall::replay(self.procedure, &self.input, record)?)
    }
}
