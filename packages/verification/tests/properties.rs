#[path = "../../records/tests/common/checks.rs"]
mod checks;
use pn_testkit::proptest::{self, prelude::*};

proptest! {
    #![proptest_config(pn_testkit::property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/properties.txt")))]
    /// Claim: For generated finite causal DAGs, naive transitive search agrees with every closure, their union counts whole proposals once, both input orders preserve the exact work count, and adding a proposal increases work.
    /// ´claim:verification:generated-closures-match-independent-search´
    /// ´test:integration:closure-model´
    #[test]
    fn closure_model(words in proptest::collection::vec(any::<u64>(), 0..9)) {
        checks::closures(&words);
    }

    /// Claim: Every declared single corruption of a valid generated batch returns its exact typed refusal in both input orders, keeping rejection distinct from accidental invalid fixtures.
    /// ´claim:verification:single-corruptions-retain-typed-causes´
    /// ´test:integration:typed-corruptions´
    #[test]
    fn typed_corruptions(words in proptest::collection::vec(any::<u64>(), 0..9)) {
        for mutation in pn_records::test_support::CORRUPTIONS {
            checks::refusal(&words, mutation);
        }
    }
}
