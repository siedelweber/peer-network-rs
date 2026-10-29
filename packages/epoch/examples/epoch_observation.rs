//! Public parameter validation with executable-owned observation.
//! (´def:compiler:boundary-inputs´)
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
    let result = cli_common::emit(&format!("{good:?};{refused:?};{ledger:?};{ledger_refusal:?}"));
    drop(guard);
    if result.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
