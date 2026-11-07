//! Explicit bounded-activation revision four; legacy replay is a separate entry point.
//! (´[ROOT-rule:design:evaluation-schedule]´)
use super::super::Error;
use super::records::{ResidualRound, SolveRecord};
use super::{map, residual};
use crate::solve::compact::BoundProcedure;
use nrz_cas::{Location, Rational, limits::Budget};
use pn_records::solve::{Evidence, Precision};

/// Actual Work classified by purpose, never padded to an allowance.
/// Setup, map execution, final checks and driver work are disjoint charged categories.
/// (´[ROOT-rule:design:evaluation-schedule]´)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accounting {
    pub setup: u64,
    pub driver_work: u64,
    pub map_passes: Vec<u64>,
    pub final_checks: Vec<u64>,
}

/// Explicit procedure revision, pinned by the API and checked on replay.
/// No legacy record is silently upgraded or accepted as this procedure's record.
/// (´[ROOT-rule:design:evaluation-schedule]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub revision: String,
    pub plan: super::Plan,
    pub solve: SolveRecord,
    pub production: Accounting,
    pub mandatory_replay: Accounting,
}

/// Execute memoized-dyadic-v4 and independently prepare and replay its original scope.
/// (´[ROOT-rule:design:evaluation-schedule]´)
/// # Errors
/// Refuses invalid original premises, exhausted limits and evidence disagreement.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "conserved::memoized::driver::solve"
    ),
    ret
)]
pub fn solve(plan: super::Plan, bound: &BoundProcedure<'_>, accepted: &crate::fence::Search) -> Result<Record, Error> {
    solve_revision(super::Revision::Legacy, plan, bound, accepted)
}

/// Execute the strict bounded-power contract, with exact fallback, as revision five.
/// (´[ROOT-rule:design:evaluation-schedule]´)
/// # Errors
/// Refuses invalid original premises, exhausted limits and evidence disagreement.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "conserved::memoized::driver::domain_solve"
    ),
    ret
)]
pub fn domain_solve(plan: super::Plan, bound: &BoundProcedure<'_>, accepted: &crate::fence::Search) -> Result<Record, Error> {
    solve_revision(super::Revision::Domain, plan, bound, accepted)
}
fn solve_revision(
    revision: super::Revision,
    plan: super::Plan,
    bound: &BoundProcedure<'_>,
    accepted: &crate::fence::Search,
) -> Result<Record, Error> {
    let rung = accepted.selected.as_deref().ok_or(Error::Scope)?;
    let (mut result, production) = run(revision, plan, bound, &accepted.evidence, rung, None)?;
    let (checked, mandatory_replay) = run(revision, plan, bound, &result.fence, rung, Some(&result))?;
    result.replay_work = checked.work;
    Ok(Record {
        revision: revision.name().into(),
        plan,
        solve: result,
        production,
        mandatory_replay,
    })
}

/// Rebuild a revision-four receiver without producer handles or cached authority.
/// (´[ROOT-rule:design:evaluation-schedule]´)
/// # Errors
/// Refuses unknown revisions, changed original requests and mismatched replay accounting.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "conserved::memoized::driver::replay"
    ),
    ret
)]
pub fn replay(plan: super::Plan, bound: &BoundProcedure<'_>, supplied: &Record) -> Result<Record, Error> {
    replay_revision(super::Revision::Legacy, plan, bound, supplied)
}

/// Independently replay revision five; revision four remains a separate entry.
/// (´[ROOT-rule:design:evaluation-schedule]´)
/// # Errors
/// Refuses revision substitution, changed inputs or evidence and accounting disagreement.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "conserved::memoized::driver::domain_replay"
    ),
    ret
)]
pub fn domain_replay(plan: super::Plan, bound: &BoundProcedure<'_>, supplied: &Record) -> Result<Record, Error> {
    replay_revision(super::Revision::Domain, plan, bound, supplied)
}
fn replay_revision(
    revision: super::Revision,
    plan: super::Plan,
    bound: &BoundProcedure<'_>,
    supplied: &Record,
) -> Result<Record, Error> {
    if supplied.revision != revision.name() || supplied.plan != plan {
        return Err(Error::Scope);
    }
    let rung = &supplied.solve.rounds.first().ok_or(Error::Scope)?.certified.rung;
    let (checked, accounting) = run(revision, plan, bound, &supplied.solve.fence, rung, Some(&supplied.solve))?;
    if checked.work != supplied.solve.replay_work || accounting != supplied.mandatory_replay {
        return Err(Error::ReplayWork);
    }
    // Producer accounting remains a declared measurement, not mathematical authority.
    Ok(Record {
        revision: supplied.revision.clone(),
        plan,
        solve: checked,
        production: supplied.production.clone(),
        mandatory_replay: accounting,
    })
}
fn compare_round(supplied: &ResidualRound, result: &ResidualRound) -> Result<(), Error> {
    if supplied.residual != result.residual {
        return Err(Error::Residual);
    }
    if supplied.radius != result.radius {
        return Err(Error::Radius);
    }
    if supplied.contraction != result.contraction || supplied.standing != result.standing {
        return Err(Error::Residual);
    }
    Ok(())
}

fn round(
    context: (super::Revision, super::Plan, &BoundProcedure<'_>),
    rung: &str,
    precision: u32,
    contraction: &Rational,
    supplied: Option<&ResidualRound>,
    b: &mut Budget,
    accounting: &mut Accounting,
) -> Result<ResidualRound, Error> {
    let (revision, plan, bound) = context;
    let p = bound.inputs().1;
    if precision < 2 {
        return Err(Error::Scope);
    }
    let allowance = work_allowance(p, supplied.is_some());
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
    let mut prepared = if iterations == 0 {
        None
    } else {
        Some(map::Context::new(
            revision,
            plan,
            bound,
            rung,
            proposal_precision,
            allowance.checked_sub(b.usage().work).ok_or(Error::Scope)?,
        )?)
    };
    let mut charged_setup = 0;
    for index in 0..iterations {
        let prepared = prepared.as_mut().ok_or(Error::Scope)?;
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
        let record = prepared.run(&point, allowance.checked_sub(b.usage().work).ok_or(Error::Scope)?, given)?;
        b.work(record.work, Location::new("candidate map"))?;
        let next = residual::proposal(&record.image, &hull, &grid, b)?;
        let newly_prepared = prepared.setup_work - charged_setup;
        accounting
            .map_passes
            .push(record.work.checked_sub(newly_prepared).ok_or(Error::Scope)?);
        charged_setup = prepared.setup_work;
        proposals.push(record);
        if next == point {
            break;
        }
        point = next;
    }
    if supplied.is_some_and(|s| s.proposals.len() != proposals.len()) {
        return Err(Error::Scope);
    }
    if let Some(prepared) = prepared {
        accounting.setup += prepared.setup_work;
    }
    point = residual::projected(&point, &hull, b)?;
    let candidate_work = b.usage().work - start;
    let given = supplied.map(|s| &s.certified);
    if given.is_some_and(|r| r.point != point || r.rung != rung || r.precision != precision) {
        return Err(Error::Scope);
    }
    let mut final_context = map::Context::new(
        revision,
        plan,
        bound,
        rung,
        precision,
        allowance.checked_sub(b.usage().work).ok_or(Error::Scope)?,
    )?;
    let certified = final_context.run(&point, allowance.checked_sub(b.usage().work).ok_or(Error::Scope)?, given)?;
    accounting.setup += final_context.setup_work;
    let final_start = b.usage().work;
    b.work(certified.work, Location::new("certified residual map"))?;
    let mut result = residual::assemble(certified, &hull, contraction, b)?;
    result.proposals = proposals;
    result.candidate_work = candidate_work;
    result.work = b.usage().work - start;
    accounting.final_checks.push(
        (b.usage().work - final_start)
            .checked_sub(final_context.setup_work)
            .ok_or(Error::Scope)?,
    );
    if let Some(s) = supplied {
        compare_round(s, &result)?;
    }
    Ok(result)
}

fn run(
    revision: super::Revision,
    plan: super::Plan,
    bound: &BoundProcedure<'_>,
    accepted: &Evidence,
    rung: &str,
    supplied: Option<&SolveRecord>,
) -> Result<(SolveRecord, Accounting), Error> {
    bound.preflight()?;
    if plan.working_precision
        > bound
            .inputs()
            .1
            .enclosure
            .as_ref()
            .ok_or(Error::Scope)?
            .refinement
            .grid_ceiling
    {
        return Err(Error::Scope);
    }
    let contraction = super::fence::fence(bound, accepted, rung)?;
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
    let mut accounting = Accounting::default();
    for (index, precision) in sequence.iter().enumerate() {
        let given = supplied.map(|s| s.rounds.get(index).ok_or(Error::Scope)).transpose()?;
        rounds.push(round(
            (revision, plan, bound),
            rung,
            *precision,
            &contraction,
            given,
            &mut budget,
            &mut accounting,
        )?);
    }
    if supplied.is_some_and(|s| s.rounds.len() != rounds.len()) {
        return Err(Error::Scope);
    }
    accounting.driver_work = budget
        .usage()
        .work
        .checked_sub(accounting.setup + accounting.map_passes.iter().sum::<u64>() + accounting.final_checks.iter().sum::<u64>())
        .ok_or(Error::Scope)?;
    Ok((
        SolveRecord {
            fence: accepted.clone(),
            rounds,
            work: budget.usage().work,
            replay_work: budget.usage().work,
        },
        accounting,
    ))
}

fn work_allowance(p: &pn_records::solve::Procedure, replay: bool) -> u64 {
    if replay { p.maximum_replay_work } else { p.maximum_solve_work }
}
