//! Shared exact finite-transport contract; no evaluator or ledger mutation.
//! (´def:numerics:exact-transport-contract´)
use std::{cmp::Ordering, fmt::Debug};

/// Exact arithmetic supplied by the owning composition, with cumulative resource refusal.
/// Implementations must satisfy exact field operations and ordering; the trait itself
/// does not verify that premise or admit an alternative numerical backend.
/// (´def:numerics:exact-transport-contract´)
pub trait ExactArithmetic: Debug {
    type Number: Clone + Debug;
    fn zero(&self) -> Self::Number;
    fn one(&self) -> Self::Number;
    /// Add exact operands.
    ///
    /// # Errors
    /// Returns a domain or cumulative resource refusal without rounding.
    fn add(&mut self, a: &Self::Number, b: &Self::Number) -> Result<Self::Number, KernelError>;
    /// Subtract exact operands.
    ///
    /// # Errors
    /// Returns a domain or cumulative resource refusal without rounding.
    fn sub(&mut self, a: &Self::Number, b: &Self::Number) -> Result<Self::Number, KernelError>;
    /// Multiply exact operands.
    ///
    /// # Errors
    /// Returns a domain or cumulative resource refusal without rounding.
    fn mul(&mut self, a: &Self::Number, b: &Self::Number) -> Result<Self::Number, KernelError>;
    /// Divide exact operands.
    ///
    /// # Errors
    /// Returns a domain or cumulative resource refusal without rounding.
    fn div(&mut self, a: &Self::Number, b: &Self::Number) -> Result<Self::Number, KernelError>;
    /// Compare exact operands.
    ///
    /// # Errors
    /// Returns a domain or cumulative resource refusal without rounding.
    fn compare(&mut self, a: &Self::Number, b: &Self::Number) -> Result<Ordering, KernelError>;
}

/// Sparse rows on an explicit, closed integer index.
/// (´def:numerics:exact-transport-contract´)
pub type Matrix<N> = Vec<std::collections::BTreeMap<usize, N>>;

/// Public exact operator inputs; the epoch adapter owns their provenance.
/// (´def:numerics:exact-transport-contract´)
#[derive(Clone, Debug)]
pub struct TransportInput<N> {
    pub hops: Vec<Matrix<N>>,
    pub depth_mass: Vec<N>,
    pub emission: Vec<N>,
    pub counts: Vec<N>,
    pub rates: Vec<N>,
}

/// Exact paired transport and direct mediant, with contributing rate hulls.
/// (´def:numerics:exact-transport-contract´)
#[derive(Clone, Debug)]
pub struct TransportOutput<N> {
    pub normalized: Vec<Matrix<N>>,
    pub raw: Matrix<N>,
    pub emitted: Matrix<N>,
    pub numerator: Vec<N>,
    pub denominator: Vec<N>,
    pub standing: Vec<N>,
    pub hull: Vec<(N, N)>,
}

/// Refusals carry no mathematical FAIL verdict.
/// (´def:numerics:exact-transport-contract´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KernelError {
    #[error("inconsistent exact operator input")]
    Input,
    #[error("exact operator cell limit exceeded")]
    Limit,
    #[error("exact arithmetic: {0}")]
    Arithmetic(String),
}
