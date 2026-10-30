#[path = "common/allocation.rs"]
mod allocation;
mod common;
#[path = "common/support.rs"]
mod support_fixture;

use allocation::{Verifier, history, inputs};
use pn_epoch::{
    base::compile_base,
    support::{SupportError, compile_support},
};
use pn_records::numerics::ExactLimits;
use std::collections::{BTreeMap, BTreeSet};

fn targets(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).into()).collect()
}

/// Claim: Source emission uses the final own balance and current writing price once, with exact zero, fractional and saturated emission; independent depth tables retain a solvent source's reach through a depleted relay, derive contributing rate extrema, and leave ledger values unchanged under accepted-set permutations.
/// ´claim:compiler:emission-and-support-follow-final-pairs-and-depths´
/// ´test:integration:support-tables´
#[test]
fn support_tables() {
    let inputs = inputs();
    let acts = support_fixture::support_acts();
    let history = history(&acts);
    let (mut numeric, price, ledger) = support_fixture::ledger(&inputs, &history);
    let saved = ledger.clone();
    let base = compile_base(&inputs, &history, &Verifier, ExactLimits::default()).unwrap();
    let result = compile_support(&inputs, &price, &ledger, &base, &mut numeric, ExactLimits::default(), 1000).unwrap();
    for (actor, rate, emission, retained) in [
        ("address-2", "1", "1/2", "1/2"),
        ("address-3", "0", "0", "1"),
        ("address-4", "4", "1", "0"),
    ] {
        let row = &result.sources[actor];
        assert_eq!(
            (&*row.reduced_rate, &*row.emission, &*row.retained),
            (rate, emission, retained)
        );
    }
    let one = BTreeMap::from([
        ("address-2".into(), targets(&["address-2", "address-3"])),
        ("address-3".into(), targets(&["address-3", "address-4"])),
        ("address-4".into(), targets(&["address-4"])),
    ]);
    let mut two = one.clone();
    two.insert("address-2".into(), targets(&["address-2", "address-3", "address-4"]));
    assert_eq!(result.by_depth, BTreeMap::from([(1, one), (2, two)]));
    assert_eq!(
        result.emitted,
        BTreeMap::from([
            ("address-2".into(), targets(&["address-2", "address-3", "address-4"])),
            ("address-3".into(), targets(&["address-3"])),
            ("address-4".into(), targets(&["address-4"])),
        ])
    );
    assert_eq!(
        result.contributors,
        BTreeMap::from([
            ("address-2".into(), targets(&["address-2"])),
            ("address-3".into(), targets(&["address-2", "address-3"])),
            ("address-4".into(), targets(&["address-2", "address-4"])),
        ])
    );
    for (actor, minimum, maximum, width) in [
        ("address-2", "1", "1", "0"),
        ("address-3", "0", "1", "1"),
        ("address-4", "1", "4", "3"),
    ] {
        let range = &result.ranges[actor];
        assert_eq!((&*range.minimum, &*range.maximum, &*range.width), (minimum, maximum, width));
    }
    assert_eq!(ledger, saved);
    for offset in 0..acts.len() {
        let mut acts = acts.clone();
        acts.rotate_left(offset);
        acts.reverse();
        let history = allocation::history(&acts);
        let base = compile_base(&inputs, &history, &Verifier, ExactLimits::default()).unwrap();
        let (_, _, ledger) = support_fixture::ledger(&inputs, &history);
        assert_eq!(
            compile_support(&inputs, &price, &ledger, &base, &mut numeric, ExactLimits::default(), 1000).unwrap(),
            result
        );
    }
    let depth_two = allocation::inputs_for_depth(&["zero", "one", "zero"]);
    let sparse = compile_support(&depth_two, &price, &ledger, &base, &mut numeric, ExactLimits::default(), 1000).unwrap();
    assert_eq!(sparse.by_depth.keys().copied().collect::<Vec<_>>(), [2]);
    assert_eq!(sparse.emitted, result.emitted);
}

/// Claim: Support refuses mismatched boundary or writing price, missing positive anchored counts, malformed base diagonals and exhausted product budgets; a positive irrational base term establishes reachability without establishing its magnitude.
/// ´claim:compiler:support-keeps-structural-refusals-and-numeric-holds-distinct´
/// ´test:integration:support-refusals´
#[test]
fn support_refusals() {
    let inputs = inputs();
    let mut acts = support_fixture::support_acts();
    let history = history(&acts);
    let (mut numeric, price, ledger) = support_fixture::ledger(&inputs, &history);
    let base = compile_base(&inputs, &history, &Verifier, ExactLimits::default()).unwrap();
    assert_eq!(
        compile_support(&inputs, &price, &ledger, &base, &mut numeric, ExactLimits::default(), 0),
        Err(SupportError::Products)
    );
    let mut wrong = base.clone();
    wrong.boundary += 1;
    assert_eq!(
        compile_support(&inputs, &price, &ledger, &wrong, &mut numeric, ExactLimits::default(), 1000),
        Err(SupportError::Boundary)
    );
    wrong = base.clone();
    wrong.rows.get_mut("address-2").unwrap().remove("address-2");
    assert_eq!(
        compile_support(&inputs, &price, &ledger, &wrong, &mut numeric, ExactLimits::default(), 1000),
        Err(SupportError::Base)
    );
    let mut missing = ledger.clone();
    missing
        .counts
        .get_mut(&pn_records::burn::Address("address-2".into()))
        .unwrap()
        .0 = 0;
    assert_eq!(
        compile_support(&inputs, &price, &missing, &base, &mut numeric, ExactLimits::default(), 1000),
        Err(SupportError::Ledger)
    );
    let literal = numeric.literal("4").unwrap();
    let wall = numeric.computed(&literal).unwrap();
    let later = numeric
        .charged_price(&wall, &inputs.parameters().numeraire, inputs.constants().content().floor)
        .unwrap();
    assert_eq!(
        compile_support(&inputs, &later, &ledger, &base, &mut numeric, ExactLimits::default(), 1000),
        Err(SupportError::Boundary)
    );
    acts[3].body.quantities[2].1.value = 1;
    acts[3].body.quantities[3].1.value = 1;
    let held = compile_base(&inputs, &allocation::history(&acts), &Verifier, ExactLimits::default()).unwrap();
    assert!(matches!(
        held.rows["address-2"]["address-3"].score,
        pn_epoch::base::BaseScore::Held { .. }
    ));
    let a = compile_support(&inputs, &price, &ledger, &base, &mut numeric, ExactLimits::default(), 1000).unwrap();
    let b = compile_support(&inputs, &price, &ledger, &held, &mut numeric, ExactLimits::default(), 1000).unwrap();
    assert_eq!(a, b);
}
