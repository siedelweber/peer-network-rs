mod common;
use pn_testkit::proptest::{self, prelude::*};

proptest! {
    #![proptest_config(pn_testkit::property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/partition.txt")))]
    /// Claim: Recorded shrinkable DAG inputs agree with an independently enumerated closure-union partition and exact intersection witnesses in three presentations, preserving all whole-act identities without treating dependency tombstones as causal removals.
    /// ´claim:membership:generated-partitions-match-set-oracle´
    /// ´test:integration:generated-partitions´
    #[test]
    fn generated_partitions(words in proptest::collection::vec(any::<u64>(), 0..9)) {
        common::check(&pn_records::test_support::generate(&words));
    }
}
