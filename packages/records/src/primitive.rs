//! Internal numerical requests and typed upstream evidence, without publication bytes.
//! (´def:numerics:primitive-records´)

use nrz_cas::{
    enclosure::{EnclosureCertificate, RefinementPolicy},
    limits::Limits,
};

/// A public procedure supplies every effective limit; the adapter selects no defaults.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclosurePolicy {
    pub store: Limits,
    pub operation: Limits,
    pub refinement: RefinementPolicy,
}

/// Original ordered expression nodes; references must point strictly backwards.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Node {
    Rational(String),
    Coordinate(usize),
    Negate(usize),
    Add(usize, usize),
    Subtract(usize, usize),
    Multiply(usize, usize),
    Divide(usize, usize),
    SquareRoot(usize),
    Logarithm(usize),
    Exponential(usize),
    Sigmoid(usize),
    Tanh(usize),
    PositivePower(usize, String),
    Derivative(usize, usize),
    Clamp(usize, usize),
    GeneralizedDerivative(usize, usize),
}

/// An exact question about the original target, not a rounded display.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Goal {
    Width,
    AtMost(String),
    LessThan(String),
    Equal(String),
}

/// A signed rational box bound; standing hull nonnegativity is a separate contract.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Range {
    pub lower: String,
    pub upper: String,
}

/// Empty-assumption real context, ordered coordinates and original expression.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Query {
    pub coordinates: Vec<Range>,
    pub nodes: Vec<Node>,
    pub target: usize,
    pub goal: Goal,
}

/// Names and semantic versions travel with evidence; names grant no checker authority.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    pub name: String,
    pub version: u32,
}

/// Supplied, untrusted evidence in nrz's own typed format; no new digest or wire format.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub schemas: Vec<Schema>,
    pub certificate: EnclosureCertificate,
}

/// Checked stopping reasons are kept apart from mathematical verdicts.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    Bound,
    Indecisive(nrz_cas::enclosure::UndecidedReason),
    Exhausted,
    Interrupted,
    Unsupported,
    DomainBoundary,
}

/// Owned projection of an evaluator fault, with no operation vocabulary or authority.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultAssertion {
    pub kind: nrz_cas::FaultKind,
    pub operation: String,
    pub logical_id: Option<u64>,
}

impl From<nrz_cas::Fault> for FaultAssertion {
    /// Preserve every fault field at its producer, including diagnostic identity.
    /// (´def:numerics:primitive-records´)
    /// Justified: Pure field projection inherits the enclosing numerical operation.
    fn from(fault: nrz_cas::Fault) -> Self {
        Self {
            kind: fault.kind,
            operation: fault.location.operation.into(),
            logical_id: fault.location.logical_id,
        }
    }
}

/// Actual consumed Work and checked bounds; never padded to a declared limit.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrimitiveEvidence {
    pub outcome: Outcome,
    pub bounds: Option<nrz_cas::enclosure::Interval>,
    pub attachment: Option<Attachment>,
    pub work: u64,
    pub usage: nrz_cas::limits::BudgetUsage,
    pub evaluation_work: u64,
    pub precision_met: bool,
    pub completed_rounds: u32,
    pub resource_fault: Option<FaultAssertion>,
}

/// One original primitive request, its declared policy and its untrusted evidence.
/// (´def:numerics:primitive-records´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrimitiveRecord {
    pub query: Query,
    pub precision: u32,
    pub evidence: PrimitiveEvidence,
}
