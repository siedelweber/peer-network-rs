//! Bounded generated-refusal process witness through the public surface.
//! (´def:acts:test-support´)
use cli_common::observation::bootstrap;
use pn_records::test_support::{CORRUPTIONS, Scenario, corrupt, generate};
use pn_records::{ValidationError, assemble_boundary_inputs, validate_history, validate_record};

fn check(case: &Scenario) -> Result<(), ValidationError> {
    let history = validate_history(&case.history, &case.names)?;
    let records = validate_record(&case.proposals, &history, &[])?;
    assemble_boundary_inputs(&records, case.boundary).map(|_| ())
}

fn main() -> std::process::ExitCode {
    let guard = bootstrap(true, false, tracing::Level::INFO).expect("controlled observation fixture");
    let seed = std::env::var("PN_RECORDS_SEED")
        .expect("recorded seed")
        .parse::<u64>()
        .expect("unsigned seed");
    let mut random = pn_testkit::Seeded::new(seed);
    let words: Vec<_> = (0..4).map(|_| random.next_u64()).collect();
    for mutation in CORRUPTIONS {
        let mut case = generate(&words);
        let expected = corrupt(&mut case, mutation).expect("declared corruption");
        assert_eq!(check(&case), Err(expected), "{mutation}");
    }
    let result = cli_common::emit(&serde_json::json!({"seed":seed,"refusals":CORRUPTIONS.len()}));
    drop(guard);
    if result.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
