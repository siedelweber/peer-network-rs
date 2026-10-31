//! Supplied numerical procedure and evidence records, without an evaluator.
//! (´def:numerics:solve-records´)

use crate::DeclarationId;
use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use std::collections::{BTreeMap, BTreeSet};

/// Required operations are declarations, never evidence of backend support.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Primitive {
    Rational,
    Root,
    Exponential,
    Logarithm,
    Power,
    Sigmoid,
    Tanh,
    SmoothDerivative,
    ClampGeneralized,
    Matrix,
    Krawczyk,
    InverseGain,
}

/// Precision requests do not select or install a backend.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Precision {
    ExactRational,
    BinaryBits(Vec<u32>),
    AbsoluteWidthBits(Vec<u32>),
}

/// This initial record admits exact rational equality only.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Equality {
    ExactRationalOnly,
}

/// Public procedure payload; publication binding is an owning consumer's duty.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Procedure {
    pub edition: DeclarationId,
    pub boundary: u64,
    pub name: String,
    pub backend: String,
    pub primitives: BTreeSet<Primitive>,
    pub precision: Precision,
    pub equality: Equality,
    pub grid: Vec<String>,
    pub margin: String,
    pub maximum_work: u64,
    pub maximum_iterations: u64,
    pub endpoint_grid: String,
    pub enclosure: Option<crate::primitive::EnclosurePolicy>,
}

/// Rational endpoints supplied as evidence; each use validates their ordering.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub lower: String,
    pub upper: String,
}

/// Completion distinguishes a stopped command from a mathematical verdict.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Completion {
    Pass,
    Fail,
    Indecisive,
    Interrupted,
}

/// Declared reason an attempt stops; this assertion is not numerical evidence.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptStop {
    ComparisonSeparated,
    PrecisionSequenceExhausted,
    WorkLimit,
    Interrupted,
}

/// A completed comparison or an interrupted attempt; the fence is already margined.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub rung: String,
    pub margined_fence: Bounds,
    pub work: u64,
    pub completion: Completion,
    pub stop: AttemptStop,
    pub primitives: Vec<usize>,
}

/// Supplied residual premises and claimed radius, not a checked map evaluation.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Residual {
    pub candidate: BTreeMap<String, String>,
    pub residual_upper: String,
    pub contraction_upper: String,
    pub radius: String,
}

/// Untrusted transcript; structural validation does not certify its numerical premises.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub hull: BTreeMap<String, Bounds>,
    pub attempts: Vec<Attempt>,
    pub residual: Option<Residual>,
    pub primitives: Vec<crate::primitive::PrimitiveRecord>,
}

/// Distinct representation refusals; no arithmetic failure becomes a fence FAIL.
/// (´def:numerics:solve-records´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("invalid procedure declaration")]
    Procedure,
    #[error("invalid descending rung grid or missing zero anchor")]
    Grid,
    #[error("invalid nonnegative bounds")]
    Bounds,
    #[error("attempt transcript differs from declared procedure")]
    Attempt,
    #[error("residual premises or radius are inconsistent")]
    Residual,
    #[error("exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

fn nonnegative(text: &str, budget: &mut Budget) -> Result<Rational, RecordError> {
    let value = Rational::parse(text, budget)?;
    if value.is_negative() {
        return Err(RecordError::Bounds);
    }
    Ok(value)
}

fn bounds(input: &Bounds, budget: &mut Budget) -> Result<(Rational, Rational), RecordError> {
    let lower = nonnegative(&input.lower, budget)?;
    let upper = nonnegative(&input.upper, budget)?;
    if lower.compare(&upper, budget)?.is_gt() {
        return Err(RecordError::Bounds);
    }
    Ok((lower, upper))
}

fn work_stop(procedure: &Procedure, attempt: &Attempt, records: &[crate::primitive::PrimitiveRecord]) -> bool {
    let mut work = 0_u64;
    let mut prior = 0_u64;
    let mut checked = false;
    let mut last = None;
    for (position, index) in attempt.primitives.iter().enumerate() {
        if attempt.primitives[..position].contains(index) {
            return false;
        }
        let Some(record) = records.get(*index) else { return false };
        prior = work;
        let Some(total) = work.checked_add(record.evidence.work) else {
            return false;
        };
        work = total;
        checked |= record.evidence.bounds.is_some() && record.evidence.attachment.is_some();
        last = Some(&record.evidence);
    }
    let Some(last) = last else { return false };
    let Some(remaining) = procedure.maximum_work.checked_sub(prior) else {
        return false;
    };
    checked
        && work == attempt.work
        && work <= procedure.maximum_work
        && matches!(
            last.outcome,
            crate::primitive::Outcome::Exhausted
                | crate::primitive::Outcome::Indecisive(nrz_cas::enclosure::UndecidedReason::WorkExhausted)
        )
        && last.resource_fault.is_some_and(|fault| {
            matches!(fault.kind,
            nrz_cas::FaultKind::Exhausted { budget: nrz_cas::limits::BudgetKind::Work, limit, needed, .. }
            if limit == remaining && needed > limit)
        })
}

fn declared_stop(procedure: &Procedure, attempt: &Attempt, records: &[crate::primitive::PrimitiveRecord]) -> bool {
    match (&attempt.completion, &attempt.stop) {
        (Completion::Pass | Completion::Fail, AttemptStop::ComparisonSeparated)
        | (Completion::Indecisive, AttemptStop::PrecisionSequenceExhausted)
        | (Completion::Interrupted, AttemptStop::Interrupted) => true,
        (Completion::Indecisive, AttemptStop::WorkLimit) => work_stop(procedure, attempt, records),
        _ => false,
    }
}

/// Validate only the declared procedure's finite structural contract.
/// (´[ROOT-sig:design:numeric-kernel]´)
/// # Errors
/// Refuses malformed declarations, grids or exact arithmetic resource exhaustion.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "solve-procedure",
        source_item = "solve::validate_procedure"
    ),
    ret
)]
pub fn validate_procedure(input: &Procedure, limits: Limits) -> Result<(), RecordError> {
    let mut budget = Budget::new(limits)?;
    let one = Rational::parse("1", &mut budget)?;
    if input.boundary == 0
        || input.name.is_empty()
        || input.backend.is_empty()
        || input.primitives.is_empty()
        || input.maximum_work == 0
        || input.maximum_iterations == 0
        || !nonnegative(&input.margin, &mut budget)?.compare(&one, &mut budget)?.is_gt()
        || nonnegative(&input.endpoint_grid, &mut budget)?.is_zero()
    {
        return Err(RecordError::Procedure);
    }
    if let Precision::BinaryBits(bits) | Precision::AbsoluteWidthBits(bits) = &input.precision
        && (bits.is_empty() || bits[0] == 0 || bits.windows(2).any(|pair| pair[0] >= pair[1]))
    {
        return Err(RecordError::Procedure);
    }
    let mut previous: Option<Rational> = None;
    for rung in &input.grid {
        let value = nonnegative(rung, &mut budget)?;
        if previous
            .as_ref()
            .map(|old| old.compare(&value, &mut budget))
            .transpose()?
            .is_some_and(|order| !order.is_gt())
        {
            return Err(RecordError::Grid);
        }
        previous = Some(value);
    }
    if !previous.is_some_and(|last| last.is_zero()) {
        return Err(RecordError::Grid);
    }
    Ok(())
}

/// Check supplied transcript consistency, without checking a map or admitting standing.
/// (´[ROOT-alg:design:rungs]´)
/// # Errors
/// Refuses inconsistent hulls, verdicts, stopping records and residual arithmetic.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "solve-evidence",
        source_item = "solve::validate_evidence"
    ),
    ret
)]
pub fn validate_evidence(procedure: &Procedure, input: &Evidence, limits: Limits) -> Result<(), RecordError> {
    validate_procedure(procedure, limits.clone())?;
    let mut budget = Budget::new(limits)?;
    let one = Rational::parse("1", &mut budget)?;
    for range in input.hull.values() {
        bounds(range, &mut budget)?;
    }
    if input.attempts.is_empty() || input.attempts.len() > procedure.grid.len() {
        return Err(RecordError::Attempt);
    }
    let mut stopped = false;
    let mut passed = false;
    for (attempt, rung) in input.attempts.iter().zip(&procedure.grid) {
        if stopped
            || !declared_stop(procedure, attempt, &input.primitives)
            || attempt.work > procedure.maximum_work
            || Rational::parse(&attempt.rung, &mut budget)?
                .compare(&Rational::parse(rung, &mut budget)?, &mut budget)?
                .is_ne()
        {
            return Err(RecordError::Attempt);
        }
        let (lower, upper) = bounds(&attempt.margined_fence, &mut budget)?;
        match attempt.completion {
            Completion::Pass if !upper.compare(&one, &mut budget)?.is_gt() => {
                stopped = true;
                passed = true;
            }
            Completion::Fail if lower.compare(&one, &mut budget)?.is_gt() => {}
            Completion::Indecisive if !lower.compare(&one, &mut budget)?.is_gt() && upper.compare(&one, &mut budget)?.is_gt() => {
            }
            Completion::Interrupted => {
                stopped = true;
            }
            _ => return Err(RecordError::Attempt),
        }
    }
    if !stopped {
        return Err(RecordError::Attempt);
    }
    if let Some(residual) = &input.residual {
        if !passed || residual.candidate.keys().ne(input.hull.keys()) {
            return Err(RecordError::Residual);
        }
        for (actor, point) in &residual.candidate {
            let point = nonnegative(point, &mut budget)?;
            let (lower, upper) = bounds(&input.hull[actor], &mut budget)?;
            if point.compare(&lower, &mut budget)?.is_lt() || point.compare(&upper, &mut budget)?.is_gt() {
                return Err(RecordError::Residual);
            }
        }
        let c = nonnegative(&residual.contraction_upper, &mut budget)?;
        if !c.compare(&one, &mut budget)?.is_lt() {
            return Err(RecordError::Residual);
        }
        let r = nonnegative(&residual.residual_upper, &mut budget)?;
        let required = r.div(&one.sub(&c, &mut budget)?, &mut budget)?;
        if nonnegative(&residual.radius, &mut budget)?
            .compare(&required, &mut budget)?
            .is_lt()
        {
            return Err(RecordError::Residual);
        }
    }
    Ok(())
}
