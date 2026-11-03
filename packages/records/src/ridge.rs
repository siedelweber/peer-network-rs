//! Defining inputs and untrusted evidence for the clean elasticity ridge.
//! (´[ROOT-alg:design:binding-ridge]´)

use crate::{
    numerics::{Floor, FloorComparison},
    primitive::{PrimitiveRecord, Range},
};

/// Closed formula identity, checked before any numerical evaluation.
/// (´[ROOT-alg:design:binding-ridge]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Definition {
    pub schema: String,
    pub inverse_temperature: String,
    pub bleed_squared: String,
    pub core_power: String,
}

/// Declared bracket, complete-cover subdivision ceiling and independent Work limits.
/// (´[ROOT-alg:design:binding-ridge]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub definition: Definition,
    pub bracket: Range,
    pub maximum_depth: u32,
    pub maximum_work: u64,
    pub maximum_replay_work: u64,
}

/// Retained attempted queries and full concavity cover; absence of an image is indecisive.
/// (´[ROOT-alg:design:binding-ridge]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub input: Inputs,
    pub queries: Vec<PrimitiveRecord>,
    pub cells: Vec<Range>,
    pub image: Option<Range>,
    pub work: u64,
}

/// Either an exact rational wall or identity with the checked defining ridge.
/// The defining alternative is not a rational charge representation.
/// (´[ROOT-alg:design:binding-ridge]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wall {
    Rational(String),
    DefiningRidge(Definition),
}

/// Untrusted floor comparison, retaining every attempted precision and attachment.
/// (´[ROOT-alg:design:binding-ridge]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComparisonRecord {
    pub wall: Wall,
    pub floor: Floor,
    pub queries: Vec<PrimitiveRecord>,
    pub verdict: FloorComparison,
    pub work: u64,
}

/// Untrusted defining evidence for a rational charge, never a graph authority carrier.
/// (´[ROOT-rule:design:ridge-charge-contract]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChargeEvidence {
    pub analytic_premises: String,
    pub procedure: crate::solve::Procedure,
    pub input: Inputs,
    pub record: Record,
}

/// Declared verifier obligation: reconstruct and independently check every ridge query,
/// attachment and cover decision under the supplied procedure and analytic premises.
/// A successful return attests that the entire record is valid, including an unresolved prefix;
/// it does not authorize a charge or turn an absent image into a floor.
/// Only the graph kernel replay implementation is admitted by the current design.
/// Implementing this trait does not mechanically establish that obligation.
/// (´[ROOT-rule:design:ridge-charge-contract]´)
pub trait ChargeVerifier: std::fmt::Debug {
    /// Replay untrusted defining evidence in a fresh bounded context.
    /// (´[ROOT-rule:design:ridge-charge-contract]´)
    /// # Errors
    /// Refuses malformed, substituted or unchecked evidence and operational exhaustion.
    fn replay(&self, evidence: &ChargeEvidence) -> Result<(), crate::numerics::NumericError>;
}
