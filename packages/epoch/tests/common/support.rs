use crate::allocation::{Verifier, act, acts, named};
use pn_epoch::CompilerInputs;
use pn_records::numerics::{ComparisonLimits, ExactLimits, NumericContext};
use pn_records::{CandidateAct, ValidatedHistory};

pub(crate) fn support_acts() -> Vec<CandidateAct> {
    let mut result = acts();
    result.push(act(
        9,
        "address-3",
        "Opinion",
        named("prof", "address-4"),
        &[("polarity", 1, 1), ("reaction", 1, 1)],
    ));
    result
}

pub(crate) fn ledger(
    inputs: &CompilerInputs,
    history: &ValidatedHistory,
) -> (
    NumericContext,
    pn_records::numerics::ChargedPrice,
    pn_epoch::ledger::FinalLedger,
) {
    use pn_records::{
        burn::{AcceptedSet, Address},
        test_support::burn,
    };
    let mut numeric = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(1000, 1000)).unwrap();
    let literal = numeric.literal("2").unwrap();
    let wall = numeric.computed(&literal).unwrap();
    let price = numeric
        .charged_price(&wall, &inputs.parameters().numeraire, inputs.constants().content().floor)
        .unwrap();
    let mut raw = burn::generate(&[9]);
    let template = raw.history.records[0].clone();
    raw.history.records.clear();
    for (index, (author, value)) in [("address-2", "18"), ("address-3", "4"), ("address-4", "6")]
        .into_iter()
        .enumerate()
    {
        let address = Address(author.into());
        let literal = numeric.literal(value).unwrap();
        let amount = numeric.burn(&literal, "burn").unwrap();
        raw.burn.read_addresses.insert(address.clone());
        raw.burn.amounts.insert(address.clone(), amount.clone());
        let mut record = template.clone();
        record.identity = format!("r{index}");
        record.destruction = format!("d{index}");
        record.address = address;
        record.amount = amount;
        record.evidence = format!(
            "{}:{}:{}:{}",
            record.destruction,
            record.address.0,
            record.amount.exact(),
            record.amount.unit()
        )
        .into_bytes();
        raw.history.records.push(record);
    }
    let all: std::collections::BTreeSet<_> = raw.history.records.iter().map(|record| record.identity.clone()).collect();
    for marker in raw.history.markers.iter_mut().skip(1) {
        marker.lineage.clone_from(&all);
        marker.accepted = AcceptedSet::CompleteList(all.clone());
    }
    let markers = burn::recognize(raw).unwrap();
    let ledger = pn_epoch::ledger::compile_ledger(
        std::slice::from_ref(inputs),
        std::slice::from_ref(&price),
        &markers,
        history,
        &Verifier,
        &mut numeric,
        ExactLimits::default(),
    )
    .unwrap();
    (numeric, price, ledger)
}
