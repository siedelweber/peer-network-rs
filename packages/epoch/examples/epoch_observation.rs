//! Public parameter validation with executable-owned observation.
//! (´def:compiler:boundary-inputs´)
#[path = "../tests/common/allocation.rs"]
mod allocation;
#[path = "../tests/common/mod.rs"]
mod common;

#[derive(Debug)]
struct Verifier;
impl pn_graph::registration::RegistrationVerifier for Verifier {
    fn approval(&self, _: &pn_records::ValidatedAct) -> bool {
        false
    }
    fn removal(&self, _: &pn_records::ValidatedAct, _: pn_graph::registration::OpeningKind, _: pn_records::Position) -> bool {
        false
    }
}

fn main() -> std::process::ExitCode {
    let enabled = std::env::args().nth(1).as_deref() != Some("disabled");
    let guard = cli_common::observation::bootstrap(enabled, false, tracing::Level::INFO).expect("controlled observation fixture");
    let (declaration, edition, input) = common::fixture();
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let records = pn_records::validate_record(&[], &empty, &[declaration]).unwrap();
    let history = pn_records::constants::bind_constants(&records, vec![edition]).unwrap();
    let good = pn_epoch::bind_inputs(&history, input.clone(), pn_records::numerics::ExactLimits::default()).unwrap();
    let mut bad = input;
    bad.profiles.pop();
    let refused = pn_epoch::bind_inputs(&history, bad, pn_records::numerics::ExactLimits::default()).unwrap_err();
    let markers = pn_records::test_support::burn::recognize(pn_records::test_support::burn::generate(&[9])).unwrap();
    let mut numeric = pn_records::numerics::NumericContext::new(
        pn_records::numerics::ExactLimits::default(),
        pn_records::numerics::ComparisonLimits::new(1000, 1000),
    )
    .unwrap();
    let literal = numeric.literal("1").unwrap();
    let wall = numeric.computed(&literal).unwrap();
    let price = numeric
        .charged_price(&wall, &good.parameters().numeraire, good.constants().content().floor)
        .unwrap();
    let ledger = pn_epoch::ledger::compile_ledger(
        std::slice::from_ref(&good),
        &[price],
        &markers,
        &empty,
        &Verifier,
        &mut numeric,
        pn_records::numerics::ExactLimits::default(),
    )
    .unwrap();
    let ledger_refusal = pn_epoch::ledger::compile_ledger(
        &[],
        &[],
        &markers,
        &empty,
        &Verifier,
        &mut numeric,
        pn_records::numerics::ExactLimits::default(),
    )
    .unwrap_err();
    let cells = pn_epoch::cells::fold_cells(&empty, 1, &Verifier, pn_records::numerics::ExactLimits::default()).unwrap();
    let cell_refusal =
        pn_epoch::cells::fold_cells(&empty, 0, &Verifier, pn_records::numerics::ExactLimits::default()).unwrap_err();
    let mut cell = pn_epoch::cells::StandingCell {
        identity: pn_epoch::cells::CellIdentity {
            author: "author".into(),
            family: "Opinion".into(),
            incidence: vec![],
            singleton: None,
        },
        members: std::collections::BTreeSet::new(),
        coordinates: [("polarity".into(), "1/4".into()), ("reaction".into(), "1".into())]
            .into_iter()
            .collect(),
    };
    let coefficient = pn_epoch::coefficients::coefficient(&cell, pn_records::numerics::ExactLimits::default()).unwrap();
    cell.coordinates.insert("polarity".into(), "1/2".into());
    let coefficient_hold = pn_epoch::coefficients::coefficient(&cell, pn_records::numerics::ExactLimits::default()).unwrap_err();
    let recipients =
        pn_epoch::recipients::resolve_recipients(&empty, 1, &Verifier, pn_records::numerics::ExactLimits::default()).unwrap();
    let recipient_refusal =
        pn_epoch::recipients::resolve_recipients(&empty, 0, &Verifier, pn_records::numerics::ExactLimits::default()).unwrap_err();
    let base_inputs = allocation::inputs();
    let mut base_acts = allocation::acts();
    let base = pn_epoch::base::compile_base(
        &base_inputs,
        &allocation::history(&base_acts),
        &allocation::Verifier,
        pn_records::numerics::ExactLimits::default(),
    )
    .unwrap();
    base_acts[3].body.quantities[2].1.value = 1;
    base_acts[3].body.quantities[3].1.value = 1;
    let base_hold = pn_epoch::base::compile_base(
        &base_inputs,
        &allocation::history(&base_acts),
        &allocation::Verifier,
        pn_records::numerics::ExactLimits::default(),
    )
    .unwrap();
    let result = cli_common::emit(&format!(
        "{good:?};{refused:?};{ledger:?};{ledger_refusal:?};{cells:?};{cell_refusal:?};{coefficient:?};{coefficient_hold:?};{recipients:?};{recipient_refusal:?};{base:?};{base_hold:?}"
    ));
    drop(guard);
    if result.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
