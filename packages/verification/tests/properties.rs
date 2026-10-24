#[path = "common/checks.rs"]
mod checks;
use pn_testkit::proptest::{self, prelude::*};

fn configuration() -> proptest::test_runner::Config {
    let mut config = pn_testkit::property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/properties.txt"));
    match std::env::var("PN_PROPERTY_SEED_PN_VERIFICATION") {
        Ok(seed) => config.rng_seed = proptest::test_runner::RngSeed::Fixed(seed.parse().unwrap()),
        Err(std::env::VarError::NotPresent) => assert!(
            std::env::var_os("PN_HARNESS_SOURCE").is_none(),
            "missing consumer seed in gated run"
        ),
        Err(error) => panic!("invalid consumer seed: {error}"),
    }
    config
}

proptest! {
    #![proptest_config(configuration())]
    /// Claim: With a consumer-qualified seed over the shared finite-DAG generator, the outer fixed-point oracle agrees with every closure and the exact proposal identity set in original, reversed and shuffled presentations, with whole co-legs attached to their parent acts.
    /// ´claim:verification:generated-closures-match-independent-search´
    /// ´test:integration:closure-model´
    #[test]
    fn closure_model(words in proptest::collection::vec(any::<u64>(), 0..9)) {
        checks::closures(&words);
    }

    /// Claim: With a consumer-qualified seed, every declared mutation of a valid generated batch matches the outer-owned cause table in original, reversed and shuffled presentations; over-bound mutations specifically test count-check precedence over duplicate and missing identities.
    /// ´claim:verification:single-corruptions-retain-typed-causes´
    /// ´test:integration:typed-corruptions´
    #[test]
    fn typed_corruptions(words in proptest::collection::vec(any::<u64>(), 0..9)) {
        for mutation in pn_records::test_support::CORRUPTIONS {
            checks::refusal(&words, mutation);
        }
    }
}
