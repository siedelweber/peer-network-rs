//! Pure final-set admission over checked candidate causes and effective schedules.
//! (´[ROOT-alg:design:admission]´)

use super::{AdmissionRefusal, Comparison, Gate};
use crate::{compiler, conserved, fence, package, schedules, solve};
use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use pn_graph::registration::RegistrationVerifier;
use pn_records::{ActId, numerics::NumericContext, solve::Bounds};
use std::collections::BTreeMap;

/// Declared solve and exact assembly limits; no demand or rejected-submission input.
/// (´[ROOT-alg:design:admission]´)
///
/// ```compile_fail,E0609
/// use pn_epoch::admission::FinalProcedure;
/// fn rejected_demand(p: &mut FinalProcedure) {
///     p.rejected_submissions = 1;
/// }
/// ```
#[derive(Clone, Debug)]
pub struct FinalProcedure {
    pub solve: pn_records::solve::Procedure,
    pub arithmetic: Limits,
    pub maximum_products: u64,
}

/// Own balance immediately before and after one complete act's single debit.
/// (´[ROOT-alg:design:admission]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Solvency {
    pub act: ActId,
    pub before: String,
    pub debit: String,
    pub after: String,
}

/// Boundary-frozen action stamps, act-weighted mean and output-only headroom.
/// (´[ROOT-alg:design:admission]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StampRound {
    pub precision: u32,
    pub stamps: BTreeMap<ActId, Bounds>,
    pub epoch: Bounds,
    pub headroom: Bounds,
}

/// Public final-gate record; only attachment to the privately constructed
/// admitted boundary carries admission authority. A standalone record is untrusted.
/// Empty epochs retain no stamp, mean or diagnostic invented from a zero denominator.
/// (´[ROOT-inv:design:atomic-admission]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalEvidence {
    pub effective: schedules::Effective,
    pub solvency: Vec<Solvency>,
    pub standing: Option<pn_records::conserved::SolveRecord>,
    pub rounds: Vec<StampRound>,
}

/// Invalid causes and operational kernel errors never assert a failed mathematical gate.
/// (´[ROOT-amend:design:admission-refusals]´)
#[derive(Debug, thiserror::Error)]
pub enum FinalRefusal {
    #[error("final admission: {0}")]
    Refused(#[from] AdmissionRefusal),
    #[error("candidate compilation: {0}")]
    Compile(#[source] Box<compiler::CompileError>),
    #[error("procedure binding: {0}")]
    Procedure(#[from] solve::ProcedureError),
    #[error("fence: {0}")]
    Fence(#[from] fence::Error),
    #[error("standing: {0}")]
    Solve(#[source] Box<conserved::Error>),
    #[error("bounded exact gate arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

fn effective(
    candidate: &package::CandidateContext,
    schedule: &schedules::CheckedSchedule,
) -> Result<schedules::Effective, FinalRefusal> {
    let source = &candidate.input().causes;
    let binding = source.bindings.last().ok_or(AdmissionRefusal::Evidence)?;
    let record = schedule.record();
    let selected = std::iter::once(&record.initial)
        .chain(record.publications.iter().map(|p| &p.effective))
        .find(|e| e.boundary == binding.marker.index)
        .ok_or(AdmissionRefusal::ScheduleValidity)?;
    if binding.price.wall().exact() != selected.wall
        || binding.price.price().exact() != selected.charge
        || binding.price.numeraire() != &selected.numeraire
        || Some(binding.inputs.constants().content().floor) != record.declaration.initialization.floor
    {
        return Err(AdmissionRefusal::ScheduleValidity.into());
    }
    Ok(selected.clone())
}

fn solvency(state: &compiler::CompiledState, b: &mut Budget) -> Result<Vec<Solvency>, FinalRefusal> {
    let binding = state.package().input().bindings.last().ok_or(AdmissionRefusal::Evidence)?;
    let ledger = &state.view().ledger;
    let charge = Rational::parse(binding.price.price().exact(), b)?;
    let mut balances = BTreeMap::new();
    for (address, amount) in &ledger.balances {
        balances.insert(address.0.clone(), Rational::parse(amount.exact(), b)?);
    }
    // The compiled ledger is already post-debit. Undo exactly the current sequence's
    // debits to reconstruct the live pre-write check, never charge the result again.
    for act in &binding.sequence {
        let balance = balances.get_mut(&act.id().author).ok_or(AdmissionRefusal::Evidence)?;
        *balance = balance.add(&charge, b)?;
    }
    let mut result = Vec::new();
    for act in &binding.sequence {
        let balance = balances.get_mut(&act.id().author).ok_or(AdmissionRefusal::Evidence)?;
        if balance.compare(&charge, b)?.is_lt() {
            return Err(AdmissionRefusal::Failed(Gate::OwnSolvency).into());
        }
        let before = balance.exact_string(b)?;
        *balance = balance.sub(&charge, b)?;
        result.push(Solvency {
            act: act.id().clone(),
            before,
            debit: charge.exact_string(b)?,
            after: balance.exact_string(b)?,
        });
    }
    Ok(result)
}

fn bounds(lower: &Rational, upper: &Rational, b: &mut Budget) -> Result<Bounds, FinalRefusal> {
    Ok(Bounds {
        lower: lower.exact_string(b)?,
        upper: upper.exact_string(b)?,
    })
}

fn comparison(range: &Bounds, threshold: &str, b: &mut Budget) -> Result<Option<bool>, FinalRefusal> {
    let threshold = Rational::parse(threshold, b)?;
    let lower = Rational::parse(&range.lower, b)?;
    let upper = Rational::parse(&range.upper, b)?;
    if lower.compare(&threshold, b)?.is_ge() {
        Ok(Some(true))
    } else if upper.compare(&threshold, b)?.is_lt() {
        Ok(Some(false))
    } else {
        Ok(None)
    }
}

fn stamps(
    state: &compiler::CompiledState,
    round: &pn_records::conserved::ResidualRound,
    effective: &schedules::Effective,
    b: &mut Budget,
) -> Result<StampRound, FinalRefusal> {
    let binding = state.package().input().bindings.last().ok_or(AdmissionRefusal::Evidence)?;
    let mut stamps = BTreeMap::new();
    let mut lower = Rational::parse("0", b)?;
    let mut upper = lower.clone();
    for act in &binding.sequence {
        let range = round.standing.get(&act.id().author).ok_or(AdmissionRefusal::Evidence)?;
        lower = lower.add(&Rational::parse(&range.lower, b)?, b)?;
        upper = upper.add(&Rational::parse(&range.upper, b)?, b)?;
        stamps.insert(act.id().clone(), range.clone());
    }
    let count = Rational::parse(&binding.sequence.len().to_string(), b)?;
    let policy = Rational::parse(&effective.policy_floor, b)?.mul(&count, b)?;
    Ok(StampRound {
        precision: round.certified.precision,
        stamps,
        epoch: bounds(&lower.div(&count, b)?, &upper.div(&count, b)?, b)?,
        headroom: bounds(&lower.sub(&policy, b)?, &upper.sub(&policy, b)?, b)?,
    })
}

fn verdict(round: &StampRound, effective: &schedules::Effective, b: &mut Budget) -> Result<Option<Comparison>, FinalRefusal> {
    let mut unresolved = None;
    for range in round.stamps.values() {
        match comparison(range, &effective.wall, b)? {
            Some(false) => return Err(AdmissionRefusal::Failed(Gate::IndividualSafety).into()),
            None => unresolved = Some(Comparison::IndividualSafety),
            Some(true) => {}
        }
    }
    match comparison(&round.epoch, &effective.policy_floor, b)? {
        Some(false) => return Err(AdmissionRefusal::Failed(Gate::EpochPolicy).into()),
        None if unresolved.is_none() => unresolved = Some(Comparison::EpochPolicy),
        _ => {}
    }
    Ok(unresolved)
}

/// Evaluate final-set gates without mutating candidate causes, history or schedules.
/// Candidate verification supplies the complete proposed causes; it never asserts
/// publication. The numerical context is consumed, so no mutable caller state escapes
/// a refusal. Closure and common-marker deployment verification remain separate premises.
/// (´[ROOT-alg:design:admission]´)
/// # Errors
/// Refuses schedule binding, capacity, own insolvency, certified stamp failures,
/// unresolved comparisons after declared refinement, and bounded kernel failures.
#[tracing::instrument(
    name = "alg:design:admission",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "alg:design:admission",
        source_item = "admission::finalize::admit"
    ),
    ret
)]
pub fn admit(
    candidate: &package::CandidateContext,
    schedule: &schedules::CheckedSchedule,
    procedure: &FinalProcedure,
    registration: &impl RegistrationVerifier,
    published: &impl solve::ProcedureVerifier,
    mut numeric: NumericContext,
) -> Result<package::AdmittedBoundary, FinalRefusal> {
    let effective = effective(candidate, schedule)?;
    let binding = candidate.input().causes.bindings.last().ok_or(AdmissionRefusal::Evidence)?;
    if u64::try_from(binding.sequence.len()).map_err(|_| AdmissionRefusal::Failed(Gate::Capacity))?
        > candidate.input().closure.policy.target
    {
        return Err(AdmissionRefusal::Failed(Gate::Capacity).into());
    }
    let state = match compiler::compile_candidate(
        candidate,
        registration,
        &mut numeric,
        procedure.arithmetic.clone(),
        procedure.maximum_products,
    ) {
        Err(compiler::CompileError::Ledger(crate::ledger::LedgerError::InsufficientBalance { boundary, .. }))
            if boundary == binding.marker.index =>
        {
            return Err(AdmissionRefusal::Failed(Gate::OwnSolvency).into());
        }
        other => other.map_err(|error| FinalRefusal::Compile(Box::new(error)))?,
    };
    let mut b = Budget::new(procedure.arithmetic.clone())?;
    let solvency = solvency(&state, &mut b)?;
    let mut evidence = FinalEvidence {
        effective,
        solvency,
        standing: None,
        rounds: Vec::new(),
    };
    if binding.sequence.is_empty() {
        return Ok(package::AdmittedBoundary::checked(candidate.clone(), evidence));
    }
    let bound = solve::bind_procedure(&state, procedure.solve.clone(), published, procedure.arithmetic.clone())?;
    let fence = fence::search(&bound, None)?;
    let solved = conserved::solve(&bound, &fence).map_err(|error| FinalRefusal::Solve(Box::new(error)))?;
    // Production solve already independently replays its complete record before return.
    let mut unresolved = Comparison::IndividualSafety;
    for round in &solved.rounds {
        let stamps = stamps(&state, round, &evidence.effective, &mut b)?;
        let result = verdict(&stamps, &evidence.effective, &mut b)?;
        evidence.rounds.push(stamps);
        if let Some(comparison) = result {
            unresolved = comparison;
        } else {
            evidence.standing = Some(solved);
            return Ok(package::AdmittedBoundary::checked(candidate.clone(), evidence));
        }
    }
    Err(AdmissionRefusal::Indecisive(unresolved).into())
}
