use pn_records::{CandidateAct, ValidatedAct, validate_history};
pub fn numeric() -> pn_records::numerics::NumericContext {
    pn_records::numerics::NumericContext::new(
        nrz_cas::limits::Limits::default(),
        pn_records::numerics::ComparisonLimits::new(1000, 1000),
    )
    .unwrap()
}

fn complete_markers(raw: &mut pn_records::test_support::burn::BurnCase, boundary: u64) {
    let all: std::collections::BTreeSet<_> = raw.history.records.iter().map(|record| record.identity.clone()).collect();
    for marker in raw.history.markers.iter_mut().skip(1) {
        marker.lineage.clone_from(&all);
        marker.accepted = pn_records::burn::AcceptedSet::CompleteList(all.clone());
    }
    while raw.history.markers.last().unwrap().index < boundary {
        let mut next = raw.history.markers.last().unwrap().clone();
        next.predecessor = Some(next.history_position);
        next.index += 1;
        next.history_position += 1;
        next.name = format!("m{}", next.index);
        raw.history.markers.push(next);
    }
}

pub fn package_at_prices(
    acts: &[CandidateAct],
    boundary: u64,
    burns: &[(&str, &str)],
    wall_texts: &[&str],
    numeraires: &[&str],
) -> pn_epoch::package::PackageInput {
    use pn_records::{burn::Address, test_support::burn};
    let mut numeric = numeric();
    let mut raw = burn::generate(&[9]);
    let template = raw.history.records[0].clone();
    raw.history.records.clear();
    for (index, (author, value)) in burns.iter().enumerate() {
        let address = Address((*author).into());
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
    complete_markers(&mut raw, boundary);
    let markers = burn::recognize(raw).unwrap();
    let mut placed = acts.to_vec();
    super::causes::stamp(&mut placed);
    let history = validate_history(&placed, &[]).unwrap();
    let mut inputs = Vec::new();
    let mut prices = Vec::new();
    let mut bindings = Vec::new();
    for epoch in 1..=boundary {
        let (mut declaration, mut edition, mut parameters) = super::constants::fixture();
        if let Some(value) = numeraires.get(usize::try_from(epoch - 1).unwrap()) {
            declaration.id.edition = epoch;
            declaration.announced_at = epoch - 1;
            declaration.effective_at = epoch;
            edition.id = declaration.id.clone();
            parameters.edition = declaration.id.clone();
            for profile in &mut parameters.profiles {
                profile.edition = declaration.id.clone();
            }
            let literal = numeric.literal(value).unwrap();
            let amount = numeric.burn_per_action(&literal, "burn").unwrap();
            let numeraire = numeric.numeraire("nu", &amount).unwrap();
            edition.numeraire = numeraire.clone();
            parameters.numeraire = numeraire;
        }
        parameters.boundary = epoch;
        // The literal compiler oracle uses unit domain weights and one hop.
        for name in parameters.domain_weights.values_mut() {
            *name = "one".into();
        }
        parameters.depth_mass = vec!["one".into()];
        let empty = validate_history(&[], &[]).unwrap();
        let record = pn_records::validate_record(&[], &empty, &[declaration]).unwrap();
        let constants = pn_records::constants::bind_constants(&record, vec![edition]).unwrap();
        let input = pn_epoch::bind_inputs(&constants, parameters, nrz_cas::limits::Limits::default()).unwrap();
        let literal = numeric.literal(wall_texts[usize::try_from(epoch - 1).unwrap()]).unwrap();
        let wall = numeric.computed(&literal).unwrap();
        let price = numeric
            .charged_price(&wall, &input.parameters().numeraire, input.constants().content().floor)
            .unwrap();
        let mut sequence: Vec<_> = history
            .acts()
            .iter()
            .filter(|act| act.position().0 == epoch)
            .cloned()
            .collect();
        sequence.sort_by_key(ValidatedAct::position);
        let index = usize::try_from(epoch).unwrap();
        bindings.push(pn_epoch::package::EpochBinding {
            marker: markers.markers()[index].identity().clone(),
            predecessor: markers.markers()[index - 1].identity().clone(),
            inputs: input.clone(),
            price: price.clone(),
            sequence,
        });
        inputs.push(input);
        prices.push(price);
    }
    pn_epoch::package::PackageInput {
        markers,
        history,
        inputs,
        prices,
        bindings,
    }
}
