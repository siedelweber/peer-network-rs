//! Projected rational proposals and the frozen conserved map's residual certificate.
//! (´[ROOT-alg:design:residual]´)

mod arithmetic;
mod driver;
mod map;
pub mod prepared;
mod prepared_map;
mod residual;
mod verification;

pub use verification::verification_declaration;

use crate::solve::BoundProcedure;
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    conserved::MapRecord,
    solve::{Bounds, Precision, Procedure},
};
use std::collections::BTreeMap;

/// A refusal never constitutes a standing or convergence verdict.
/// (´[ROOT-alg:design:residual]´)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("conserved solve declaration or frozen scope refused")]
    Scope,
    #[error("applied transport: {0}")]
    Applied(#[from] pn_graph::transport::applied::Error),
    #[error("mandatory replay Work differs from the independently measured count")]
    ReplayWork,
    #[error("map evidence or endpoint composition refused")]
    Map,
    #[error("residual bound refused")]
    Residual,
    #[error("residual radius refused")]
    Radius,
    #[error("procedure: {0}")]
    Procedure(#[from] crate::solve::ProcedureError),
    #[error("primitive: {0}")]
    Primitive(#[from] pn_graph::numeric::Error),
    #[error("transport: {0}")]
    Transport(#[from] pn_records::transport::KernelError),
    #[error("exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
    #[error("frozen constants: {0}")]
    Input(#[from] crate::InputError),
    #[error("accepted fence: {0}")]
    Fence(#[from] crate::fence::Error),
    #[error("records: {0}")]
    Records(#[from] pn_records::solve::RecordError),
}

fn policy(procedure: &Procedure, precision: u32, remaining: u64) -> Result<Procedure, Error> {
    let mut next = procedure.clone();
    next.maximum_work = remaining;
    next.precision = Precision::AbsoluteWidthBits(vec![precision]);
    let declared = next.enclosure.as_mut().ok_or(Error::Scope)?;
    declared.refinement.precision = precision;
    declared.operation.work = declared.operation.work.min(remaining);
    Ok(next)
}

fn hull(bound: &BoundProcedure<'_>) -> BTreeMap<String, Bounds> {
    bound
        .inputs()
        .0
        .view()
        .support
        .ranges
        .iter()
        .map(|(actor, range)| {
            (
                actor.clone(),
                Bounds {
                    lower: range.minimum.clone(),
                    upper: range.maximum.clone(),
                },
            )
        })
        .collect()
}

fn image(
    output: &[nrz_cas::enclosure::Interval],
    actors: &[String],
    budget: &mut Budget,
) -> Result<BTreeMap<String, Bounds>, Error> {
    actors
        .iter()
        .zip(output)
        .map(|(actor, range)| {
            Ok((
                actor.clone(),
                Bounds {
                    lower: range.lower().exact_string(budget)?,
                    upper: range.upper().exact_string(budget)?,
                },
            ))
        })
        .collect()
}

fn point_in_hull(point: &BTreeMap<String, String>, bounds: &BTreeMap<String, Bounds>, budget: &mut Budget) -> Result<(), Error> {
    if point.keys().ne(bounds.keys()) {
        return Err(Error::Scope);
    }
    for (actor, value) in point {
        let value = Rational::parse(value, budget)?;
        let range = &bounds[actor];
        if value.compare(&Rational::parse(&range.lower, budget)?, budget)?.is_lt()
            || value.compare(&Rational::parse(&range.upper, budget)?, budget)?.is_gt()
        {
            return Err(Error::Scope);
        }
    }
    Ok(())
}

/// Evaluate the frozen map at one rational point with a new evaluation-local session.
/// A point-map record alone neither selects a rung nor certifies standing.
/// (´[ROOT-alg:design:solve]´)
/// # Errors
/// Refuses scope, unsupported premises, exhausted limits and incomplete scalar evidence.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "conserved::evaluate_map"
    ),
    ret
)]
pub fn evaluate_map(
    bound: &BoundProcedure<'_>,
    rung: &str,
    point: &BTreeMap<String, String>,
    precision: u32,
) -> Result<MapRecord, Error> {
    bound.preflight()?;
    map::run(bound, rung, point, precision, bound.inputs().1.maximum_solve_work, None)
}

/// Rebuild every scalar question and transport factor from the original frozen package.
/// (´[ROOT-alg:design:residual]´)
/// # Errors
/// Refuses changed points, premises, factor joins or endpoint compositions.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "conserved::replay_map"
    ),
    ret
)]
pub fn replay_map(bound: &BoundProcedure<'_>, record: &MapRecord) -> Result<MapRecord, Error> {
    bound.preflight()?;
    map::run(
        bound,
        &record.rung,
        &record.point,
        record.precision,
        bound.inputs().1.maximum_replay_work,
        Some(record),
    )
}

/// Execute every declared precision with deterministic proposals and one residual map.
/// (´[ROOT-alg:design:solve]´)
/// # Errors
/// Refuses an unproved fence, malformed schedule, exhausted attempt or unavailable map.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "conserved::solve"
    ),
    ret
)]
pub fn solve(bound: &BoundProcedure<'_>, accepted: &crate::fence::Search) -> Result<pn_records::conserved::SolveRecord, Error> {
    let mut result = driver::run(
        bound,
        &accepted.evidence,
        accepted.selected.as_deref().ok_or(Error::Scope)?,
        None,
    )?;
    let checked = driver::run(
        bound,
        &result.fence,
        &result.rounds.first().ok_or(Error::Scope)?.certified.rung,
        Some(&result),
    )?;
    result.replay_work = checked.work;
    Ok(result)
}

/// Replay the frozen map scopes and independently reconstruct each residual and radius.
/// (´[ROOT-alg:design:residual]´)
/// # Errors
/// Refuses changed candidates, scalar evidence, residuals, radii or published intersections.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "conserved::replay"
    ),
    ret
)]
pub fn replay(
    bound: &BoundProcedure<'_>,
    supplied: &pn_records::conserved::SolveRecord,
) -> Result<pn_records::conserved::SolveRecord, Error> {
    let rung = &supplied.rounds.first().ok_or(Error::Scope)?.certified.rung;
    let checked = driver::run(bound, &supplied.fence, rung, Some(supplied))?;
    if checked.work != supplied.replay_work {
        return Err(Error::ReplayWork);
    }
    Ok(checked)
}

/// Explicit applied-dyadic procedure revision.
/// (´[ROOT-rule:design:evaluation-schedule]´)
pub mod compact;
