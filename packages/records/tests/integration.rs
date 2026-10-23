mod common;
use common::{act, resolved};
use pn_records::{Layout, validate_record};

/// Claim: In a batch containing one binary and one paired act, validation exposes exactly two complete acts with three owned projections and preserves quantities, units, vintages and host metadata unchanged; this establishes counting only for this structural fixture, not membership closure or ledger accounting.
/// ´claim:acts:complete-acts-are-counted-once´
/// ´test:integration:complete-acts-count-once´
#[test]
fn complete_acts_count_once() {
    let records = [act(1, Layout::Binary), act(2, Layout::Paired)];
    let validated = validate_record(&records, &resolved()).unwrap();
    assert_eq!(validated.acts().len(), 2);
    assert_eq!(
        validated
            .acts()
            .iter()
            .map(|a| a.mandatory.len() + a.removable.len())
            .sum::<usize>(),
        3
    );
    assert_eq!(validated.acts(), records);
    assert_eq!(validated.acts()[1].body.quantities[0].1.vintage, 2);
    assert_eq!(validated.acts()[1].finalization_epoch, 5);
}
