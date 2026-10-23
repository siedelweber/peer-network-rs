//! Development-only support; no production domain imports or global state.
//! (´impl:testkit:support´)

#![doc = include_str!("../README.md")]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// One declared input; predicates belong to the shared adapter.
/// (´def:testkit:case´)
pub struct Case<T> {
    /// Stable identifier within the contract edition.
    pub id: String,
    /// Input shared unchanged by all implementations.
    pub input: T,
}

/// A complete execution identity and its original predicate result.
/// (´def:testkit:result´)
#[derive(Debug)]
pub struct CaseResult<E> {
    /// Declared suite name.
    pub suite: String,
    /// Declared contract edition.
    pub edition: String,
    /// Unchanged case identifier.
    pub case: String,
    /// Named implementation, never inferred from its answer.
    pub implementation: String,
    /// Predicate outcome; timing cannot modify it.
    pub outcome: Result<(), E>,
    /// Observed elapsed duration, with no timeout or retry policy.
    pub elapsed: Duration,
}

/// Refusal before any adapter executes.
/// (´def:testkit:declaration-error´)
#[derive(Debug, PartialEq, Eq)]
pub enum DeclarationError {
    /// Names, implementations and cases must be nonempty and unique.
    InvalidRoster,
}

/// Run every declared case once against every named implementation.
/// (´def:testkit:run´)
///
/// # Errors
/// Returns `InvalidRoster` before execution for empty or duplicate identities.
/// Adapter errors are retained as results and do not stop later cases.
pub fn run<T, E>(
    suite: &str,
    edition: &str,
    cases: &[Case<T>],
    implementations: &[&str],
    mut adapter: impl FnMut(&str, &T) -> Result<(), E>,
) -> Result<Vec<CaseResult<E>>, DeclarationError> {
    let names: BTreeSet<_> = implementations.iter().copied().collect();
    let ids: BTreeSet<_> = cases.iter().map(|case| case.id.as_str()).collect();
    if suite.is_empty()
        || edition.is_empty()
        || cases.is_empty()
        || implementations.is_empty()
        || names.len() != implementations.len()
        || ids.len() != cases.len()
        || names.contains("")
        || ids.contains("")
    {
        return Err(DeclarationError::InvalidRoster);
    }
    let mut results = Vec::new();
    for implementation in implementations {
        for case in cases {
            let started = Instant::now();
            let outcome = adapter(implementation, &case.input);
            results.push(CaseResult {
                suite: suite.to_owned(),
                edition: edition.to_owned(),
                case: case.id.clone(),
                implementation: (*implementation).to_owned(),
                outcome,
                elapsed: started.elapsed(),
            });
        }
    }
    Ok(results)
}

/// `SplitMix64` edition one: reproducible test inputs, never cryptographic keys.
/// (´def:testkit:seeded´)
pub struct Seeded(u64);

impl Seeded {
    /// Start from the recorded unsigned seed.
    /// (´def:testkit:seeded-new´)
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Advance exactly one deterministic step with explicitly wrapping arithmetic.
    /// (´def:testkit:seeded-next´)
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(11_400_714_819_323_198_485);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(13_787_848_793_156_543_929);
        value = (value ^ (value >> 27)).wrapping_mul(10_723_151_780_598_845_931);
        value ^ (value >> 31)
    }
}

/// Caller-controlled fault steps; no sleep, clock or global scheduler.
/// (´def:testkit:fault-plan´)
pub struct FaultPlan(BTreeSet<u64>);

impl FaultPlan {
    /// Declare the exact logical steps that fail.
    /// (´def:testkit:fault-plan-new´)
    #[must_use]
    pub fn new(steps: impl IntoIterator<Item = u64>) -> Self {
        Self(steps.into_iter().collect())
    }

    /// Query a logical step without consuming or mutating the plan.
    /// (´def:testkit:fault-at´)
    #[must_use]
    pub fn fails_at(&self, step: u64) -> bool {
        self.0.contains(&step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Claim: Duplicate case identities refuse before an adapter can have effects.
    /// ´claim:testkit:duplicate-roster-prevents-effects´
    /// ´test:unit:duplicate-roster´
    #[test]
    fn duplicate_roster() {
        let cases = [
            Case {
                id: "same".into(),
                input: (),
            },
            Case {
                id: "same".into(),
                input: (),
            },
        ];
        let mut called = false;
        let result = run("suite", "1", &cases, &["pure"], |_, ()| {
            called = true;
            Ok::<(), ()>(())
        });
        assert!(matches!(result, Err(DeclarationError::InvalidRoster)));
        assert!(!called);
    }

    /// Claim: The seed-zero first word fixes the generator edition, preventing silent replay drift.
    /// ´claim:testkit:generator-edition-vector´
    /// ´test:unit:generator-vector´
    #[test]
    fn generator_vector() {
        assert_eq!(Seeded::new(0).next_u64(), 16_294_208_416_658_607_535);
    }
}
