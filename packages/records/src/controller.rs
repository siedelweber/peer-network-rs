//! Canonical controller inputs and retained decisions, separate from schedule admission.
//! (´[ROOT-alg:design:production-wall-controller]´)

use crate::{numerics::Floor, primitive::Range, ridge::ComparisonRecord, wall::Record as InverseRecord};

/// Public representation rule, in reduced-wall units.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    ExactRational,
    Grid { quantum: String, maximum_error: String },
}

/// Declared finite inverse search and controller constants; no admission statistics.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub width: String,
    pub empty_live_domain: bool,
    pub accepted_rung: String,
    pub cumulative_tilt: String,
    pub bleed_squared: String,
    pub previous: String,
    pub floor: Floor,
    pub absolute_cap: String,
    pub relative_cap: String,
    pub deadband: String,
    pub bracket: Range,
    pub stopping_width: String,
    pub maximum_steps: u64,
    pub maximum_work: u64,
    pub maximum_replay_work: u64,
    pub delivery: Delivery,
}

/// An interval comparison is never converted to a guessed branch.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    Below,
    Equal,
    Above,
    Indecisive,
}

/// Separate mathematical choices retain equality at every binding edge.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branches {
    pub zero_width: bool,
    pub floor: Relation,
    pub deadband: Relation,
    pub absolute_cap: Relation,
    pub relative_cap: Relation,
    pub direction: Relation,
    pub proposal: Range,
    pub ideal: Range,
}

/// The first unresolved mathematical comparison, distinct from delivery refusal.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Floor,
    InverseGain,
    Deadband,
    StepCap,
    Delivery,
}

/// A complete comparison attempt, including its independent scalar evidence.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub precision: u32,
    pub stopped_at: Option<Stage>,
    pub inverse: Option<InverseRecord>,
    pub floor_checks: Vec<ComparisonRecord>,
    pub branches: Option<Branches>,
    pub delivered: Option<String>,
    pub delivery_error: Option<Range>,
}

/// Certified representation failure differs from unresolved comparison and operational error.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Delivered,
    Indecisive,
    DeliveryRefused,
}

/// The mathematical proposal and its evidence are never replaced by a rounded charge.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub procedure: crate::solve::Procedure,
    pub inputs: Inputs,
    pub attempts: Vec<Attempt>,
    pub verdict: Verdict,
}
