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

proptest! {
    #![proptest_config(configuration())]
    /// Claim: Over bounded shared integer inputs, the outer cross-product oracle establishes co-expressed recoinage, inverse market repricing with a fixed numeraire, coupled charged values, action-count door outlays with independently varying per-action coordinates, and exact sign, unit and floor refusals; no fence evaluation is asserted.
    /// ´claim:verification:generated-numeric-coordinates-retain-their-laws´
    /// ´test:integration:numeric-coordinates´
    #[test]
    fn numeric_coordinates(words in proptest::collection::vec(any::<u64>(),0..9)) { checks::numeric(&words); }
}

#[path = "common/burn_checks.rs"]
mod burn_checks;

proptest! {
    #![proptest_config(configuration())]
    /// Claim: Under its consumer-qualified seed, the outer tier derives per-marker accepted sets and destruction keys from bounded generated inputs and the refusal cause from each altered premise; both unique-index presentations agree under fixture verification, without claiming an independent implementation.
    /// ´claim:verification:generated-marker-corruptions-retain-typed-causes´
    /// ´test:integration:marker-recognition´
    #[test]
    fn marker_recognition(words in proptest::collection::vec(any::<u64>(),0..9)) {burn_checks::case(&words,"valid"); for name in pn_records::test_support::burn::CORRUPTIONS {burn_checks::case(&words,name);}}
}
