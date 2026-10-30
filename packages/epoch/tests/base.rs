#[path = "common/allocation.rs"]
mod allocation;
mod common;

use allocation::{Verifier, acts, history, inputs};
use pn_epoch::base::{BaseError, BaseScore, compile_base};
use pn_records::numerics::ExactLimits;
use std::collections::BTreeMap;

/// Claim: A sparse base on anchored Actors adds the positive self base and each complete cell's coefficient once with unequal profile and domain weights; independent literal rows retain home artifact activity without outward artifact allocation or early normalization, invariant under accepted-set permutations.
/// ´claim:compiler:base-is-an-unnormalized-weighted-cell-sum´
/// ´test:integration:base-tables´
#[test]
fn base_tables() {
    let inputs = inputs();
    let acts = acts();
    let base = compile_base(&inputs, &history(&acts), &Verifier, ExactLimits::default()).unwrap();
    let actual: BTreeMap<_, _> = base
        .rows
        .iter()
        .map(|(source, row)| {
            (
                source.as_str(),
                row.iter()
                    .map(|(target, entry)| (target.as_str(), entry.score.clone()))
                    .collect::<BTreeMap<_, _>>(),
            )
        })
        .collect();
    // Literal arithmetic: A self = 1 + Registration 1 + Publish (1/2)*4 + artifact Opinion (1/2)*3.
    // A outward = Reference (1/2)*(2/3 + 2) + one folded Opinion cell (1/2)*3.
    let expected = BTreeMap::from([
        (
            "address-2",
            BTreeMap::from([
                ("address-2", BaseScore::Exact("11/2".into())),
                ("address-3", BaseScore::Exact("17/6".into())),
            ]),
        ),
        ("address-3", BTreeMap::from([("address-3", BaseScore::Exact("2".into()))])),
        ("address-4", BTreeMap::from([("address-4", BaseScore::Exact("2".into()))])),
    ]);
    assert_eq!(actual, expected);
    assert_eq!(base.rows["address-2"]["address-3"].cells.len(), 2);
    for offset in 0..acts.len() {
        let mut permuted = acts.clone();
        permuted.rotate_left(offset);
        assert_eq!(
            compile_base(&inputs, &history(&permuted), &Verifier, ExactLimits::default()).unwrap(),
            base
        );
        permuted.reverse();
        assert_eq!(
            compile_base(&inputs, &history(&permuted), &Verifier, ExactLimits::default()).unwrap(),
            base
        );
    }
    let self_only = compile_base(&inputs, &history(&acts[..3]), &Verifier, ExactLimits::default()).unwrap();
    assert!(
        self_only
            .rows
            .iter()
            .all(|(actor, row)| row.len() == 1 && row[actor].score == BaseScore::Exact("2".into()))
    );
    assert!(
        compile_base(&inputs, &history(&[]), &Verifier, ExactLimits::default())
            .unwrap()
            .rows
            .is_empty()
    );
}

/// # Panics
/// Panics only if the controlled irrational fixture unexpectedly returns an exact score.
///
/// Claim: An irrational cell coefficient holds only its dependent base entry with its radicand and domain factor; exact entries remain exact, and a cell outside the anchored source index refuses rather than creating a non-Actor row.
/// ´claim:compiler:irrational-base-entries-retain-their-evidence-gap´
/// ´test:integration:base-holds´
#[test]
fn base_holds() {
    let inputs = inputs();
    let mut acts = acts();
    acts[3].body.quantities[2].1.value = 1;
    acts[3].body.quantities[3].1.value = 1;
    let base = compile_base(&inputs, &history(&acts), &Verifier, ExactLimits::default()).unwrap();
    let BaseScore::Held { exact_part, terms } = &base.rows["address-2"]["address-3"].score else {
        panic!("irrational base evidence must remain held")
    };
    assert_eq!(exact_part, "3/2");
    assert_eq!(terms.len(), 1);
    assert_eq!(terms[0].radicand, "1/2");
    assert_eq!(terms[0].domain_factor, "8/3");
    assert_eq!(base.rows["address-2"]["address-2"].score, BaseScore::Exact("11/2".into()));
    let mut unanchored = acts.remove(4);
    unanchored.authoritative_position = 1;
    assert_eq!(
        compile_base(&inputs, &history(&[unanchored]), &Verifier, ExactLimits::default()),
        Err(BaseError::ActorIndex)
    );
}
