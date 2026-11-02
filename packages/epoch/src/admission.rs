//! Final-admission declarations and atomic candidate gate evaluation.
//! (´[ROOT-amend:design:admission-declarations]´)

use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use pn_records::numerics::{Floor, Numeraire};
use std::cmp::Ordering;

mod finalize;
pub use finalize::{FinalEvidence, FinalProcedure, FinalRefusal, Solvency, StampRound, admit};

/// The closed set of controller editions admitted by this interface.
/// (´[ROOT-amend:design:admission-declarations]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerEdition {
    CanonicalInterim,
}

/// Required initialization fields, retained in missing-input refusals.
/// (´[ROOT-amend:design:admission-declarations]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitializationField {
    Floor,
    Wall,
    Parameters,
    PolicyFloor,
    EffectiveBoundary,
}

/// Exact rational parameters of the canonical controller, not host overrides.
/// (´[ROOT-amend:design:admission-declarations]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerParameters {
    pub absolute_cap: String,
    pub relative_cap: String,
    pub deadband: String,
    pub margin: String,
}

/// Untrusted initialization has explicit absence, never an inferred floor or wall.
/// (´[ROOT-amend:design:admission-declarations]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitializationInput {
    pub floor: Option<Floor>,
    pub wall: Option<String>,
    pub parameters: Option<ControllerParameters>,
    pub policy_floor: Option<String>,
    pub effective_boundary: Option<u64>,
}

/// Rational delivery choices; all grid quantities are in reduced-wall units.
/// (´[ROOT-rule:design:wall-delivery-declaration]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Requires proof that the ideal update is this exact rational.
    ExactRational,
    /// Nearest admissible grid point; ties approach the previous wall, then go lower.
    /// The absolute error from the ideal update must be certified within the bound.
    Grid { quantum: String, maximum_error: String },
}

/// Finite public comparison sequence and independent production/replay ceilings.
/// (´[ROOT-amend:design:admission-declarations]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refinement {
    pub precision_bits: Vec<u32>,
    pub maximum_work: u64,
    pub maximum_replay_work: u64,
}

/// Supplied schedule declaration; validation is not schedule publication or admission.
/// (´[ROOT-amend:design:admission-declarations]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleInput {
    pub controller: String,
    pub announced_at: u64,
    pub initialization: InitializationInput,
    pub numeraire: Numeraire,
    pub delivery: Delivery,
    pub refinement: Refinement,
}

/// Immutable structurally valid declaration. Ridge evidence and execution remain separate.
/// (´[ROOT-amend:design:admission-declarations]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleDeclaration {
    input: ScheduleInput,
    controller: ControllerEdition,
}

/// Declaration defects are distinct from an evaluated gate or incomplete comparison.
/// (´[ROOT-amend:design:admission-refusals]´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationError {
    #[error("unsupported controller edition")]
    Controller,
    #[error("missing initialization field: {0:?}")]
    Missing(InitializationField),
    #[error("declaration lacks one-boundary lead")]
    Late,
    #[error("invalid controller parameters")]
    Parameters,
    #[error("invalid initial wall or policy floor")]
    InitialWall,
    #[error("invalid rational delivery declaration")]
    Delivery,
    #[error("invalid finite refinement declaration")]
    Refinement,
    #[error("bounded exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

/// Binding comparisons whose unresolved result withholds admission or publication.
/// (´[ROOT-amend:design:admission-refusals]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    Floor,
    InverseGain,
    Deadband,
    StepCap,
    DeliveryError,
    IndividualSafety,
    EpochPolicy,
}

/// Mathematically failed final gates, never aliases for resource exhaustion.
/// (´[ROOT-amend:design:admission-refusals]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    OwnSolvency,
    IndividualSafety,
    EpochPolicy,
}

/// Operational stops publish no mathematical verdict.
/// (´[ROOT-amend:design:admission-refusals]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Work,
    ReplayWork,
    Storage,
    Interrupted,
}

/// Reserved semantic outcomes for the later admission and schedule producers.
/// No constructor in this cut produces an admitted boundary or a passing schedule.
/// (´[ROOT-amend:design:admission-refusals]´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionRefusal {
    #[error("declaration: {0}")]
    Declaration(#[from] DeclarationError),
    #[error("candidate causes: {0}")]
    Causes(#[from] crate::package::PackageError),
    #[error("closure evidence does not establish the declared condition")]
    Closure,
    #[error("certified final gate failed: {0:?}")]
    Failed(Gate),
    #[error("delivery cannot certify an admissible representation in the declared mode")]
    Delivery,
    #[error("replay inputs or retained evidence differ")]
    Evidence,
    #[error("later schedule violates its led wall or effective declaration")]
    ScheduleValidity,
    #[error("comparison remains indecisive: {0:?}")]
    Indecisive(Comparison),
    #[error("operation stopped without a verdict: {0:?}")]
    Operational(Stop),
}

/// Validate a declaration before any numerical schedule execution.
/// (´[ROOT-alg:design:schedules]´)
/// # Errors
/// Refuses unsupported editions, absent inputs, invalid ranges, late declarations,
/// malformed grid/refinement declarations or bounded arithmetic exhaustion.
#[tracing::instrument(
    name = "alg:design:schedules",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "alg:design:schedules",
        source_item = "admission::declare_schedule"
    ),
    ret
)]
pub fn declare_schedule(input: ScheduleInput, limits: Limits) -> Result<ScheduleDeclaration, DeclarationError> {
    if input.controller != "canonical-interim-v1" {
        return Err(DeclarationError::Controller);
    }
    let init = &input.initialization;
    let floor = init.floor.ok_or(DeclarationError::Missing(InitializationField::Floor))?;
    let wall = init
        .wall
        .as_ref()
        .ok_or(DeclarationError::Missing(InitializationField::Wall))?;
    let parameters = init
        .parameters
        .as_ref()
        .ok_or(DeclarationError::Missing(InitializationField::Parameters))?;
    let policy = init
        .policy_floor
        .as_ref()
        .ok_or(DeclarationError::Missing(InitializationField::PolicyFloor))?;
    let boundary = init
        .effective_boundary
        .ok_or(DeclarationError::Missing(InitializationField::EffectiveBoundary))?;
    if input.announced_at.checked_add(1) != Some(boundary) {
        return Err(DeclarationError::Late);
    }
    let mut budget = Budget::new(limits)?;
    let one = Rational::parse("1", &mut budget)?;
    let wall = positive(wall, &mut budget, DeclarationError::InitialWall)?;
    let policy = positive(policy, &mut budget, DeclarationError::InitialWall)?;
    if policy.compare(&wall, &mut budget)? == Ordering::Less {
        return Err(DeclarationError::InitialWall);
    }
    if floor == Floor::RationalThreeThirtySevenths
        && wall.compare(&Rational::parse("3/37", &mut budget)?, &mut budget)? == Ordering::Less
    {
        return Err(DeclarationError::InitialWall);
    }
    positive(&parameters.absolute_cap, &mut budget, DeclarationError::Parameters)?;
    let relative = positive(&parameters.relative_cap, &mut budget, DeclarationError::Parameters)?;
    let deadband = Rational::parse(&parameters.deadband, &mut budget)?;
    let margin = positive(&parameters.margin, &mut budget, DeclarationError::Parameters)?;
    if relative.compare(&one, &mut budget)? != Ordering::Less
        || deadband.is_negative()
        || deadband.compare(&one, &mut budget)? != Ordering::Less
        || margin.compare(&one, &mut budget)? != Ordering::Greater
    {
        return Err(DeclarationError::Parameters);
    }
    if let Delivery::Grid { quantum, maximum_error } = &input.delivery {
        let quantum = positive(quantum, &mut budget, DeclarationError::Delivery)?;
        let maximum_error = positive(maximum_error, &mut budget, DeclarationError::Delivery)?;
        if maximum_error.compare(&quantum, &mut budget)?.is_lt() {
            return Err(DeclarationError::Delivery);
        }
        if !wall.div(&quantum, &mut budget)?.is_integer() {
            return Err(DeclarationError::Delivery);
        }
    }
    let refinement = &input.refinement;
    if refinement.precision_bits.is_empty()
        || refinement.precision_bits.contains(&0)
        || refinement.precision_bits.windows(2).any(|pair| pair[0] >= pair[1])
        || refinement.maximum_work == 0
        || refinement.maximum_replay_work == 0
    {
        return Err(DeclarationError::Refinement);
    }
    Ok(ScheduleDeclaration {
        input,
        controller: ControllerEdition::CanonicalInterim,
    })
}

/// Validate one exact positive declaration field within the caller's budget.
/// (´[ROOT-alg:design:schedules]´)
fn positive(source: &str, budget: &mut Budget, error: DeclarationError) -> Result<Rational, DeclarationError> {
    let value = Rational::parse(source, budget)?;
    if value.is_zero() || value.is_negative() {
        return Err(error);
    }
    Ok(value)
}

impl ScheduleDeclaration {
    /// Borrow the complete checked declaration, without authorizing its execution.
    /// (´[ROOT-amend:design:admission-declarations]´)
    /// Justified: Immutable field access retains validation and performs no decision.
    #[must_use]
    pub fn input(&self) -> &ScheduleInput {
        &self.input
    }

    /// Read the admitted closed edition discriminator.
    /// (´[ROOT-amend:design:admission-declarations]´)
    /// Justified: Immutable field access retains validation and performs no decision.
    #[must_use]
    pub fn controller(&self) -> ControllerEdition {
        self.controller
    }
}
