//! Development-only support; no production domain imports or global state.
//! (´impl:testkit:support´)

#![doc = include_str!("../README.md")]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Reviewed strategy and value-tree shrinking implementation for consumers.
/// (´def:testkit:property-config´)
pub use proptest;

/// Replayable properties using proptest's environment-reading default.
///
/// The gate supplies the seed, cases, algorithm, fork, timeout and shrink limits;
/// local callers use that same environment interface. Only the corpus is replaced.
/// (´def:testkit:property-config´)
#[must_use]
pub fn property_config(corpus: &'static str) -> proptest::test_runner::Config {
    proptest::test_runner::Config {
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

/// Named word inputs for the records generator, shared by both graph consumers.
/// Expectations remain independently owned by the consuming test suites.
/// (´def:testkit:case´)
pub const GRAPH_PARTITION_CASES: [(&str, &[u64]); 6] = [
    ("minimal", &[]),
    ("independent", &[1; 8]),
    ("dense", &[u64::MAX; 8]),
    ("mixed", &[9, 18, 37, 74, 149, 298]),
    ("dependencies", &[(65_535 << 16) | 1; 8]),
    ("removals", &[(3 << 62) | 1, (3 << 62) | 31, 1, 127]),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Claim: A fresh process reads an alternate declared case count, seed, algorithm and shrink limits, and executes exactly that many successful cases, so recorded configuration cannot silently diverge from the runner.
    /// ´claim:testkit:property-configuration-follows-environment´
    /// ´test:unit:property-configuration´
    #[test]
    fn property_configuration() {
        if std::env::var_os("PN_TEST_PROPERTY_CONFIGURATION").is_none() {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", "tests::property_configuration", "--nocapture"]);
            for (key, _) in std::env::vars_os() {
                if key.to_string_lossy().starts_with("PROPTEST_") {
                    command.env_remove(key);
                }
            }
            command.env("PN_TEST_PROPERTY_CONFIGURATION", "child");
            for (key, value) in [
                ("PROPTEST_CASES", "321"),
                ("PROPTEST_RNG_SEED", "17"),
                ("PROPTEST_RNG_ALGORITHM", "xs"),
                ("PROPTEST_FORK", "false"),
                ("PROPTEST_TIMEOUT", "0"),
                ("PROPTEST_MAX_SHRINK_TIME", "0"),
                ("PROPTEST_MAX_SHRINK_ITERS", "17"),
            ] {
                command.env(key, value);
            }
            assert!(command.status().unwrap().success());
            return;
        }
        let mut config = property_config("unused-property-corpus.txt");
        assert_eq!(config.cases, 321);
        assert_eq!(config.rng_seed, proptest::test_runner::RngSeed::Fixed(17));
        assert_eq!(config.rng_algorithm, proptest::test_runner::RngAlgorithm::XorShift);
        assert!(!config.fork);
        assert_eq!(config.timeout, 0);
        assert_eq!(config.max_shrink_time, 0);
        assert_eq!(config.max_shrink_iters, 17);
        config.failure_persistence = None;
        let count = std::cell::Cell::new(0);
        proptest::test_runner::TestRunner::new(config)
            .run(&(0_u8..10), |_| {
                count.set(count.get() + 1);
                Ok(())
            })
            .unwrap();
        assert_eq!(count.get(), 321);
    }

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
