//! Development-only support; no production domain imports or global state.
//! (´impl:testkit:support´)

#![doc = include_str!("../README.md")]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Reviewed strategy and value-tree shrinking implementation for consumers.
/// (´def:testkit:property-config´)
pub use proptest;

/// Bounded replayable properties with proptest's value-tree shrinking.
/// The gate supplies source-derived `PROPTEST_RNG_SEED`, cases and algorithm;
/// local callers inherit the same environment interface. There is no clock timeout.
/// (´def:testkit:property-config´)
#[must_use]
pub fn property_config(corpus: &'static str) -> proptest::test_runner::Config {
    proptest::test_runner::Config {
        cases: 256,
        fork: false,
        timeout: 0,
        max_shrink_time: 0,
        max_shrink_iters: u32::MAX,
        failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::Direct(corpus))),
        ..proptest::test_runner::Config::default()
    }
}

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

    /// Claim: Repeating a fixed seed returns the same deliberately failing integer shrunk to seven, proving replay and minimization without a timed oracle.
    /// ´claim:testkit:recorded-seed-replays-a-shrunk-failure´
    /// ´test:unit:replay-and-shrink´
    #[test]
    fn replay_and_shrink() {
        use proptest::test_runner::{RngSeed, TestError, TestRunner};
        let config = proptest::test_runner::Config {
            rng_seed: RngSeed::Fixed(17),
            failure_persistence: None,
            ..property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/controlled.txt"))
        };
        let run = || {
            let visited = std::cell::RefCell::new(Vec::new());
            let result = TestRunner::new(config.clone()).run(&(7_u64..1000), |value| {
                visited.borrow_mut().push(value);
                proptest::prop_assert!(value < 7);
                Ok(())
            });
            assert!(matches!(result, Err(TestError::Fail(_, 7))));
            visited.into_inner()
        };
        let visited = run();
        assert!(visited[0] > 7);
        assert!(visited.len() > 1);
        assert_eq!(visited, run());
    }

    /// Claim: Two cases sharing one identifier return `InvalidRoster` without invoking the adapter, preventing ambiguous result identities and preflight side effects.
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

    /// Claim: Seed zero produces the pinned first `SplitMix64` word, detecting a change to that generator-edition vector used for replay.
    /// ´claim:testkit:generator-edition-vector´
    /// ´test:unit:generator-vector´
    #[test]
    fn generator_vector() {
        assert_eq!(Seeded::new(0).next_u64(), 16_294_208_416_658_607_535);
    }
}
