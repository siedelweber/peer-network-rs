//! Runtime witness for (´[ROOT-inv:observe:noninterference]´).
use cli_common::observation::{BootstrapError, bootstrap};
use pn_records::test_support::burn as fixtures;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "default".into());
    let valid = fixtures::generate(&[3]);
    let mut invalid = valid.clone();
    fixtures::corrupt(&mut invalid, "invalid-member");
    let mut missing = valid.clone();
    fixtures::corrupt(&mut missing, "lost-lineage");
    let guard = match bootstrap(mode != "disabled", false, tracing::Level::INFO) {
        Ok(guard) => Some(guard),
        Err(BootstrapError::Unavailable(_)) => None,
        Err(error @ BootstrapError::Configuration(_)) => {
            let mut record = cli_common::ControlPlaneRecord::usage_error("burn-observation", "observation_configuration");
            record.message = error.to_string();
            let _ignored = cli_common::emit_control_plane_record(&record);
            return cli_common::CommandExit::Usage.exit_code();
        }
    };
    let recognized = fixtures::recognize(valid).unwrap();
    let refused = [fixtures::recognize(invalid).is_err(), fixtures::recognize(missing).is_err()];
    let exit=if cli_common::emit(&serde_json::json!({"markers":recognized.markers().len(),"destructions":recognized.markers().last().unwrap().destructions().len(),"refused":refused})).is_ok(){ExitCode::SUCCESS}else{ExitCode::FAILURE};
    drop(guard);
    if std::env::var_os("PN_TEST_OBSERVATION_RENDEZVOUS").is_some() {
        let mut release = [0];
        let _ignored = std::io::Read::read_exact(&mut std::io::stdin(), &mut release);
    }
    exit
}
