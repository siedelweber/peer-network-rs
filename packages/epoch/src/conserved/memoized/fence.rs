//! A public sequence, fresh per-map state and cumulative attempt accounting.
//! (´[ROOT-rule:design:refinement]´)
use super::super::Error;
use crate::solve::compact::BoundProcedure;
use nrz_cas::{Rational, limits::Budget};
use pn_records::solve::{AttemptStop, Completion, Evidence, Precision};

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
        && crate::fence::compact::search(bound, None)?.evidence != *evidence
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
                let checked = crate::fence::compact::replay(bound, &attempt.rung, record)?;
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
