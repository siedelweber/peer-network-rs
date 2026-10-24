#[path = "common/checks.rs"]
mod checks;
use pn_testkit::proptest::{self, prelude::*};

proptest! {
    #![proptest_config(pn_testkit::property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/properties.txt")))]
    /// Claim: For generated finite causal DAGs, naive transitive search agrees with every closure and its exact proposal identity set; original, reversed and shuffled presentations preserve the work count, and adding a proposal increases work.
    /// ´claim:acts:generated-closures-match-independent-search´
    /// ´test:integration:closure-model´
    #[test]
    fn closure_model(words in proptest::collection::vec(any::<u64>(), 0..9)) {
        checks::closures(&words);
    }

    /// Claim: Every declared mutation of a valid generated batch returns its exact typed refusal in original, reversed and shuffled presentations; over-bound mutations test count-check precedence over duplicate and missing identities.
    /// ´claim:acts:single-corruptions-retain-typed-causes´
    /// ´test:integration:typed-corruptions´
    #[test]
    fn typed_corruptions(words in proptest::collection::vec(any::<u64>(), 0..9)) {
        for mutation in pn_records::test_support::CORRUPTIONS {
            checks::refusal(&words, mutation);
        }
    }
}

proptest! {
    #![proptest_config(pn_testkit::property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/properties.txt")))]
    /// Claim: Over bounded shared integer inputs, the inner exact-value checks establish co-expressed recoinage, inverse market repricing with a fixed numeraire, coupled charged values, action-count door outlays with independently varying per-action coordinates, and exact sign, unit and floor refusals; no fence evaluation is asserted.
    /// ´claim:numerics:generated-numeric-coordinates-retain-their-laws´
    /// ´test:integration:numeric-coordinates´
    #[test]
    fn numeric_coordinates(words in proptest::collection::vec(any::<u64>(),0..9)) { checks::numeric(&words); }
}

#[path = "common/burn_checks.rs"]
mod burn_checks;

proptest! {
    #![proptest_config(pn_testkit::property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/properties.txt")))]
    /// Claim: Generated bounded amounts and opaque addresses preserve complete marker recognition and alias deduplication; each corruption starts from a valid case and refuses with the consumer's exact cause in original and reversed presentation order under fixture proof verification.
    /// ´claim:burn:generated-marker-corruptions-retain-typed-causes´
    /// ´test:integration:marker-recognition´
    #[test]
    fn marker_recognition(words in proptest::collection::vec(any::<u64>(),0..9)) {burn_checks::case(&words,"valid"); for name in pn_records::test_support::burn::CORRUPTIONS {burn_checks::case(&words,name);}}
}
