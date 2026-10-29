//! Public parameter validation with executable-owned observation.
//! (´def:compiler:boundary-inputs´)
#[path = "../tests/common/mod.rs"]
mod common;

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
    let result = cli_common::emit(&format!("{good:?};{refused:?}"));
    drop(guard);
    if result.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
