//! Exact defining inputs and replay carriers for the separate reference evaluator.
//! (´[ROOT-alg:design:reference-wall]´)

use crate::primitive::{PrimitiveRecord, Range};

/// Identity with this target is stronger than equality of two interval displays.
/// (´[ROOT-rule:design:reference-wall-branches]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Previous {
    Target,
    Rational(String),
}

/// The ridge declaration is supported only when its certified upper bound is nonbinding.
/// (´[ROOT-rule:design:reference-wall-branches]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Floor {
    Rational,
    Ridge,
}

/// Public inputs in reduced units; no charged price or rounded target is admitted here.
/// (´[ROOT-alg:design:reference-wall]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub width: String,
    pub cumulative_tilt: String,
    pub bracket: Range,
    pub stopping_width: String,
    pub maximum_steps: u64,
    pub maximum_work: u64,
    pub maximum_replay_work: u64,
    pub floor: Floor,
    pub previous: Previous,
    pub door: String,
    pub absolute_cap: String,
    pub relative_cap: String,
    pub deadband: String,
}

/// Strict signs only; an unresolved enclosure cannot select a half bracket.
/// (´[ROOT-alg:design:reference-wall]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sign {
    Positive,
    Negative,
    Indecisive,
}

/// Every attempted precision remains in execution order, including indecisive attempts.
/// (´[ROOT-alg:design:reference-wall]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub primitive: PrimitiveRecord,
    pub sign: Sign,
    pub work: u64,
}

/// Outward branch certification distinguishes an unresolved comparison from a false one.
/// (´[ROOT-rule:design:reference-wall-branches]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Indecisive,
}

/// The effective participation floor follows the certified policy comparison.
/// (´[ROOT-rule:design:reference-wall-branches]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Participation {
    Door,
    Wall,
    Indecisive,
}

/// Ordered controller decisions and both enclosures; these are not ledger publication values.
/// (´[ROOT-rule:design:reference-wall-branches]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branches {
    pub floor_binding: bool,
    pub deadband_hold: bool,
    pub step_capped: bool,
    pub above_floor: Verdict,
    pub policy_valid: Verdict,
    pub participation: Participation,
    pub proposal: Range,
    pub delivered: Range,
}

/// A completed enclosure or a retained indecisive prefix, independently checked on replay.
/// (´[ROOT-alg:design:reference-wall]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub target: Option<Range>,
    pub steps: Vec<Step>,
    pub bisections: u64,
    pub bisection_work: Vec<u64>,
    pub branches: Option<Branches>,
    pub indecisive: bool,
    pub work: u64,
}
