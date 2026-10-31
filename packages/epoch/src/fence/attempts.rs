//! Each rung owns one ordered precision transcript and cumulative numerical Work allowance.
//! (´def:compiler:fence-search´)

use super::Error;
use nrz_cas::{
    Rational,
    limits::{Budget, BudgetKind},
};
use pn_graph::numeric::{self, activation::fence};
use pn_records::{
    primitive::{Outcome, PrimitiveRecord},
    solve::{Attempt, AttemptStop, Bounds, Completion, Evidence, Procedure},
};

fn exact(rung: &str) -> Attempt {
    Attempt {
        rung: rung.into(),
        margined_fence: Bounds {
            lower: "0".into(),
            upper: "0".into(),
        },
        work: 0,
        completion: Completion::Pass,
        stop: AttemptStop::ComparisonSeparated,
        primitives: Vec::new(),
    }
}

fn stopped(record: &PrimitiveRecord, remaining: u64) -> bool {
    record.evidence.resource_fault.is_some_and(|fault| {
        matches!(fault.kind,
        nrz_cas::FaultKind::Exhausted { budget: BudgetKind::Work, limit, needed, .. } if limit == remaining && needed > limit)
    })
}

fn range(record: &PrimitiveRecord, budget: &mut Budget) -> Result<Option<Bounds>, Error> {
    record
        .evidence
        .bounds
        .as_ref()
        .map(|r| {
            Ok(Bounds {
                lower: r.lower().exact_string(budget)?,
                upper: r.upper().exact_string(budget)?,
            })
        })
        .transpose()
}

pub(super) fn run(
    procedure: &Procedure,
    sequence: &[u32],
    prepared: &fence::Inputs,
    rung: &str,
    interrupt_at: Option<u64>,
    evidence: &mut Evidence,
) -> Result<Option<Outcome>, Error> {
    let policy = procedure.enclosure.as_ref().ok_or(Error::Profile)?;
    let mut preparation = Budget::new(policy.operation.clone())?;
    let strength = Rational::parse(rung, &mut preparation)?;
    if strength.is_zero() || Rational::parse(&prepared.width, &mut preparation)?.is_zero() {
        evidence.attempts.push(exact(rung));
        return Ok(None);
    }
    if procedure.fence.as_ref().is_some_and(|profile| profile.inverse_wall) {
        return Err(Error::ReferenceWall);
    }
    let mut input = prepared.clone();
    input.cumulative_tilt = strength
        .mul(
            &Rational::parse(&prepared.cumulative_tilt, &mut preparation)?,
            &mut preparation,
        )?
        .exact_string(&mut preparation)?;
    let query = fence::query(procedure, &input)?;
    let mut attempt = Attempt {
        rung: rung.into(),
        margined_fence: Bounds {
            lower: "0".into(),
            upper: "0".into(),
        },
        work: 0,
        completion: Completion::Indecisive,
        stop: AttemptStop::PrecisionSequenceExhausted,
        primitives: Vec::new(),
    };
    let mut has_bound = false;
    for precision in sequence {
        let remaining = procedure.maximum_work.checked_sub(attempt.work).ok_or(Error::Profile)?;
        let mut request = procedure.clone();
        let declared = request.enclosure.as_mut().ok_or(Error::Profile)?;
        declared.operation.work = declared.operation.work.min(remaining);
        declared.refinement.precision = *precision;
        let checked = numeric::evaluate(&request, &query, interrupt_at.map(|v| v.saturating_sub(attempt.work)))?;
        attempt.work = attempt.work.checked_add(checked.work).ok_or(Error::Profile)?;
        let record = PrimitiveRecord {
            query: query.clone(),
            precision: *precision,
            evidence: checked,
        };
        if let Some(bounds) = range(&record, &mut preparation)? {
            attempt.margined_fence = bounds;
            has_bound = true;
        }
        let limited = stopped(&record, remaining);
        let outcome = record.evidence.outcome;
        attempt.primitives.push(evidence.primitives.len());
        evidence.primitives.push(record);
        match outcome {
            Outcome::Pass | Outcome::Fail => {
                attempt.completion = if outcome == Outcome::Pass {
                    Completion::Pass
                } else {
                    Completion::Fail
                };
                attempt.stop = AttemptStop::ComparisonSeparated;
                evidence.attempts.push(attempt);
                return Ok(None);
            }
            Outcome::Indecisive(_) | Outcome::Exhausted if limited && has_bound => {
                attempt.stop = AttemptStop::WorkLimit;
                evidence.attempts.push(attempt);
                return Ok(None);
            }
            Outcome::Indecisive(
                nrz_cas::enclosure::UndecidedReason::Straddle | nrz_cas::enclosure::UndecidedReason::WidthLimit,
            ) => {}
            other => return Ok(Some(other)),
        }
    }
    if has_bound {
        evidence.attempts.push(attempt);
        Ok(None)
    } else {
        Ok(Some(Outcome::Exhausted))
    }
}
