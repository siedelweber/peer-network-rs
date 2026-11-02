//! Effective wall and policy sequences, separate from final admission.
//! (´[ROOT-alg:design:effective-schedules]´)

use crate::{
    admission::{AdmissionRefusal, Comparison, ScheduleDeclaration},
    controller::{self, Evidence, InverseSearch},
    solve::BoundProcedure,
};
use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use pn_graph::numeric::ridge::{self, CheckedRidge};
use pn_records::{
    burn::Marker,
    numerics::{Floor, FloorComparison, Numeraire},
};

/// Public announcement beside a completed epoch; no demand or admission statistics.
/// (´[ROOT-alg:design:effective-schedules]´)
/// Admission statistics are not a schedule or controller input:
/// ```compile_fail
/// use pn_epoch::schedules::Boundary;
/// fn inject(boundary: &mut Boundary<'_, '_>) {
///     boundary.admission_statistics = Some(());
/// }
/// ```
#[derive(Debug)]
pub struct Boundary<'a, 'b> {
    pub completed: &'a BoundProcedure<'b>,
    pub search: &'a InverseSearch,
    pub announced_at: u64,
    pub effective_at: u64,
    /// Absence retains the preceding effective policy floor.
    pub policy_floor: Option<String>,
}

/// Exact effective coordinate pair and policy; never an enclosure endpoint charge.
/// (´[ROOT-alg:design:effective-schedules]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effective {
    pub boundary: u64,
    pub wall: String,
    pub charge: String,
    pub numeraire: Numeraire,
    pub policy_floor: String,
}

/// Candidate publication retains its completed marker and independently replayable proposal.
/// (´[ROOT-alg:design:effective-schedules]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publication {
    pub marker: Marker,
    pub announced_at: u64,
    pub effective: Effective,
    pub proposal: Evidence,
}

/// Untrusted sequence evidence. Only replay constructs a checked schedule.
/// (´[ROOT-alg:design:effective-schedules]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub declaration: crate::admission::ScheduleInput,
    pub initial: Effective,
    pub publications: Vec<Publication>,
}

/// Immutable replayed sequence; it does not admit a write or authenticate deployment publication.
/// (´[ROOT-alg:design:effective-schedules]´)
#[derive(Debug)]
pub struct CheckedSchedule {
    record: Record,
}

/// Schedule defects, unresolved comparisons and arithmetic stops remain distinct.
/// (´[ROOT-alg:design:effective-schedules]´)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("schedule refusal: {0}")]
    Refused(#[from] AdmissionRefusal),
    #[error("controller: {0}")]
    Controller(#[from] controller::Error),
    #[error("ridge: {0}")]
    Ridge(#[from] ridge::Error),
    #[error("bounded exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

fn effective(boundary: u64, wall: &str, policy: &str, nu: &Numeraire, b: &mut Budget) -> Result<Effective, Error> {
    let wall = Rational::parse(wall, b)?;
    let policy = Rational::parse(policy, b)?;
    if wall.is_negative() || wall.is_zero() || policy.compare(&wall, b)?.is_lt() {
        return Err(AdmissionRefusal::ScheduleValidity.into());
    }
    let charge = wall.mul(&Rational::parse(nu.amount().exact(), b)?, b)?;
    Ok(Effective {
        boundary,
        wall: wall.exact_string(b)?,
        charge: charge.exact_string(b)?,
        numeraire: nu.clone(),
        policy_floor: policy.exact_string(b)?,
    })
}

fn initial(d: &ScheduleDeclaration, ridge: Option<&CheckedRidge>, b: &mut Budget) -> Result<Effective, Error> {
    let input = d.input();
    let init = &input.initialization;
    let wall = init.wall.as_ref().ok_or(AdmissionRefusal::Evidence)?;
    let floor = init.floor.ok_or(AdmissionRefusal::Evidence)?;
    if floor == Floor::RidgeImage {
        let checked = ridge.ok_or(AdmissionRefusal::Indecisive(Comparison::Floor))?;
        let evidence = ridge::compare(checked, &pn_records::ridge::Wall::Rational(wall.clone()), floor)?;
        match evidence.verdict {
            FloorComparison::Above | FloorComparison::Equal => {}
            FloorComparison::Below => return Err(AdmissionRefusal::ScheduleValidity.into()),
            FloorComparison::Indecisive => return Err(AdmissionRefusal::Indecisive(Comparison::Floor).into()),
        }
    }
    effective(
        init.effective_boundary.ok_or(AdmissionRefusal::Evidence)?,
        wall,
        init.policy_floor.as_ref().ok_or(AdmissionRefusal::Evidence)?,
        &input.numeraire,
        b,
    )
}

fn bind_boundary(current: &Effective, frame: &Boundary<'_, '_>, prior: &[crate::package::EpochBinding]) -> Result<(), Error> {
    let (state, _) = frame.completed.inputs();
    let package = state.package().input();
    let last = package.bindings.last().ok_or(AdmissionRefusal::Evidence)?;
    let price = &last.price;
    if last.marker.index != current.boundary
        || frame.announced_at != current.boundary
        || frame.announced_at.checked_add(1) != Some(frame.effective_at)
        || price.wall().exact() != current.wall
        || price.price().exact() != current.charge
        || price.numeraire() != &current.numeraire
        || package.bindings.get(..prior.len()) != Some(prior)
    {
        return Err(AdmissionRefusal::ScheduleValidity.into());
    }
    Ok(())
}

fn run(
    d: &ScheduleDeclaration,
    frames: &[Boundary<'_, '_>],
    ridge: Option<&CheckedRidge>,
    limits: Limits,
    supplied: Option<&Record>,
) -> Result<Record, Error> {
    let mut b = Budget::new(limits)?;
    let first = initial(d, ridge, &mut b)?;
    if supplied.is_some_and(|s| s.declaration != *d.input() || s.initial != first || s.publications.len() != frames.len()) {
        return Err(AdmissionRefusal::Evidence.into());
    }
    let mut record = Record {
        declaration: d.input().clone(),
        initial: first.clone(),
        publications: Vec::new(),
    };
    let mut current = first;
    let mut prior = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        bind_boundary(&current, frame, &prior)?;
        let proposal = if let Some(s) = supplied {
            s.publications[index].proposal.clone()
        } else {
            controller::evaluate(frame.completed, d, frame.search, ridge)?
        };
        let checked = controller::replay(frame.completed, d, frame.search, ridge, &proposal)?;
        let evidence = checked.evidence();
        let wall = evidence
            .controller
            .attempts
            .last()
            .and_then(|a| a.delivered.as_deref())
            .ok_or(AdmissionRefusal::Evidence)?;
        let next = effective(
            frame.effective_at,
            wall,
            frame.policy_floor.as_deref().unwrap_or(&current.policy_floor),
            &current.numeraire,
            &mut b,
        )?;
        if evidence.burn_image.as_deref() != Some(next.charge.as_str()) {
            return Err(AdmissionRefusal::Evidence.into());
        }
        let (state, _) = frame.completed.inputs();
        prior.clone_from(&state.package().input().bindings);
        let publication = Publication {
            marker: prior.last().ok_or(AdmissionRefusal::Evidence)?.marker.clone(),
            announced_at: frame.announced_at,
            effective: next.clone(),
            proposal,
        };
        if supplied.is_some_and(|s| s.publications[index] != publication) {
            return Err(AdmissionRefusal::Evidence.into());
        }
        record.publications.push(publication);
        current = next;
    }
    Ok(record)
}

/// Derive a sequential candidate from completed epochs and explicit led announcements.
/// (´[ROOT-alg:design:effective-schedules]´)
/// # Errors
/// Refuses skipped boundaries, changed vintages, invalid policy pairings and controller failures.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "schedules::evaluate"
    ),
    ret
)]
pub fn evaluate(
    d: &ScheduleDeclaration,
    frames: &[Boundary<'_, '_>],
    ridge: Option<&CheckedRidge>,
    limits: Limits,
) -> Result<Record, Error> {
    run(d, frames, ridge, limits, None)
}

/// Independently rebuild each completed-epoch certificate, led wall, charge and effective policy.
/// (´[ROOT-alg:design:effective-schedules]´)
/// # Errors
/// Refuses any changed input, publication or historical prefix and unresolved numerical evidence.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "schedules::replay"
    ),
    ret
)]
pub fn replay(
    d: &ScheduleDeclaration,
    frames: &[Boundary<'_, '_>],
    ridge: Option<&CheckedRidge>,
    limits: Limits,
    record: &Record,
) -> Result<CheckedSchedule, Error> {
    Ok(CheckedSchedule {
        record: run(d, frames, ridge, limits, Some(record))?,
    })
}

impl CheckedSchedule {
    /// Borrow checked evidence; this access creates no publication or admission authority.
    /// (´[ROOT-alg:design:effective-schedules]´)
    /// Justified: Immutable access inherits schedule replay and performs no decision.
    #[must_use]
    pub fn record(&self) -> &Record {
        &self.record
    }
}
