//! A public sequence, fresh per-map state and cumulative attempt accounting.
//! (´[ROOT-rule:design:refinement]´)
use super::{Error, map, residual};
use crate::solve::BoundProcedure;
use nrz_cas::{Location, Rational, limits::Budget};
use pn_records::{
    conserved::{ResidualRound, SolveRecord},
    solve::{AttemptStop, Completion, Evidence, Precision},
};

pub(super) fn fence(bound: &BoundProcedure<'_>, evidence: &Evidence, rung: &str) -> Result<Rational, Error> {
    let p = bound.inputs().1;
    let limits = p.enclosure.as_ref().ok_or(Error::Scope)?.operation.clone();
    pn_records::solve::validate_evidence(p, evidence, limits.clone())?;
    if evidence.hull != super::hull(bound)
        || evidence
            .attempts
            .last()
            .is_none_or(|a| a.rung != rung || a.completion != Completion::Pass)
    {
        return Err(Error::Scope);
    }
    let Precision::AbsoluteWidthBits(sequence) = &p.precision else {
        return Err(Error::Scope);
    };
    if evidence.attempts.iter().any(|a| a.stop == AttemptStop::WorkLimit)
        && crate::fence::search(bound, None)?.evidence != *evidence
    {
        return Err(Error::Scope);
    }
    let mut b = Budget::new(limits)?;
    for attempt in &evidence.attempts {
        if attempt.stop == AttemptStop::PrecisionSequenceExhausted && attempt.primitives.len() != sequence.len() {
            return Err(Error::Scope);
        }
        if attempt.primitives.is_empty()
            && (attempt.completion != Completion::Pass
                || (attempt.rung != "0" && evidence.hull.values().any(|r| r.lower != r.upper)))
        {
            return Err(Error::Scope);
        }
        for (position, index) in attempt.primitives.iter().enumerate() {
            let record = evidence.primitives.get(*index).ok_or(Error::Scope)?;
            if sequence.get(position) != Some(&record.precision) {
                return Err(Error::Scope);
            }
            if record.evidence.attachment.is_some() {
                let checked = crate::fence::replay(bound, &attempt.rung, record)?;
                if checked.bounds != record.evidence.bounds
                    || checked.outcome != record.evidence.outcome
                    || checked.resource_fault != record.evidence.resource_fault
                {
                    return Err(Error::Scope);
                }
            } else if attempt.stop != AttemptStop::WorkLimit {
                return Err(Error::Scope);
            }
        }
        if let Some(value) = attempt
            .primitives
            .iter()
            .rev()
            .find_map(|i| evidence.primitives[*i].evidence.bounds.as_ref())
            && (Rational::parse(&attempt.margined_fence.lower, &mut b)? != *value.lower()
                || Rational::parse(&attempt.margined_fence.upper, &mut b)? != *value.upper())
        {
            return Err(Error::Scope);
        }
    }
    let accepted = evidence.attempts.last().ok_or(Error::Scope)?;
    let upper = Rational::parse(&accepted.margined_fence.upper, &mut b)?;
    // Empty mathematical transcripts are admitted only for the exact zero fence.
    if accepted.primitives.is_empty() && !upper.is_zero() {
        return Err(Error::Scope);
    }
    Ok(upper.div(&Rational::parse(&p.margin, &mut b)?, &mut b)?)
}

fn round(
    bound: &BoundProcedure<'_>,
    rung: &str,
    precision: u32,
    contraction: &Rational,
    supplied: Option<&ResidualRound>,
    b: &mut Budget,
) -> Result<ResidualRound, Error> {
    let p = bound.inputs().1;
    if precision < 2 {
        return Err(Error::Scope);
    }
    let allowance = if supplied.is_some() {
        p.maximum_replay_work
    } else {
        p.maximum_solve_work
    };
    let start = b.usage().work;
    let hull = super::hull(bound);
    let grid = residual::grid(
        &p.endpoint_grid,
        p.enclosure.as_ref().ok_or(Error::Scope)?.refinement.grid_ceiling,
        b,
    )?;
    let mut point = residual::proposal(&hull, &hull, &grid, b)?;
    let mut proposals = Vec::new();
    let proposal_precision = (precision / 2).max(1);
    let iterations = if Rational::parse(rung, b)?.is_zero() || hull.is_empty() {
        0
    } else {
        p.maximum_iterations
    };
    for index in 0..iterations {
        let given = supplied
            .map(|s| {
                s.proposals
                    .get(usize::try_from(index).map_err(|_| Error::Scope)?)
                    .ok_or(Error::Scope)
            })
            .transpose()?;
        if given.is_some_and(|r| r.point != point || r.rung != rung || r.precision != proposal_precision) {
            return Err(Error::Scope);
        }
        let record = map::run(
            bound,
            rung,
            &point,
            proposal_precision,
            allowance.checked_sub(b.usage().work).ok_or(Error::Scope)?,
            given,
        )?;
        b.work(record.work, Location::new("candidate map"))?;
        let next = residual::proposal(&record.image, &hull, &grid, b)?;
        proposals.push(record);
        if next == point {
            break;
        }
        point = next;
    }
    if supplied.is_some_and(|s| s.proposals.len() != proposals.len()) {
        return Err(Error::Scope);
    }
    point = residual::projected(&point, &hull, b)?;
    let candidate_work = b.usage().work - start;
    let given = supplied.map(|s| &s.certified);
    if given.is_some_and(|r| r.point != point || r.rung != rung || r.precision != precision) {
        return Err(Error::Scope);
    }
    let certified = map::run(
        bound,
        rung,
        &point,
        precision,
        allowance.checked_sub(b.usage().work).ok_or(Error::Scope)?,
        given,
    )?;
    b.work(certified.work, Location::new("certified residual map"))?;
    let mut result = residual::assemble(certified, &hull, contraction, b)?;
    result.proposals = proposals;
    result.candidate_work = candidate_work;
    result.work = b.usage().work - start;
    if let Some(s) = supplied {
        if s.residual != result.residual {
            return Err(Error::Residual);
        }
        if s.radius != result.radius {
            return Err(Error::Radius);
        }
        if s.contraction != result.contraction || s.standing != result.standing {
            return Err(Error::Residual);
        }
    }
    Ok(result)
}

pub(super) fn run(
    bound: &BoundProcedure<'_>,
    accepted: &Evidence,
    rung: &str,
    supplied: Option<&SolveRecord>,
) -> Result<SolveRecord, Error> {
    bound.preflight()?;
    let contraction = fence(bound, accepted, rung)?;
    let p = bound.inputs().1;
    let Precision::AbsoluteWidthBits(sequence) = &p.precision else {
        return Err(Error::Scope);
    };
    let mut limits = p.enclosure.as_ref().ok_or(Error::Scope)?.operation.clone();
    limits.work = if supplied.is_some() {
        p.maximum_replay_work
    } else {
        p.maximum_solve_work
    };
    let mut budget = Budget::new(limits)?;
    let mut rounds = Vec::new();
    for (index, precision) in sequence.iter().enumerate() {
        let given = supplied.map(|s| s.rounds.get(index).ok_or(Error::Scope)).transpose()?;
        rounds.push(round(bound, rung, *precision, &contraction, given, &mut budget)?);
    }
    if supplied.is_some_and(|s| s.rounds.len() != rounds.len()) {
        return Err(Error::Scope);
    }
    Ok(SolveRecord {
        fence: accepted.clone(),
        rounds,
        work: budget.usage().work,
        replay_work: budget.usage().work,
    })
}
