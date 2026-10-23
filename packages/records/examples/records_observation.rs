//! Process witness for (´[ROOT-inv:observe:noninterference]´).

#[path = "../tests/common/mod.rs"]
mod common;

use cli_common::observation::{BootstrapError, bootstrap};
use pn_records::{Layout, validate_record};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "default".into());
    let guard = match bootstrap(mode != "disabled", false, tracing::Level::INFO) {
        Ok(guard) => Some(guard),
        Err(BootstrapError::Unavailable(_)) => None,
        Err(error @ BootstrapError::Configuration(_)) => {
            let mut record = cli_common::ControlPlaneRecord::usage_error("records-observation", "observation_configuration");
            record.message = error.to_string();
            let _ignored = cli_common::emit_control_plane_record(&record);
            return cli_common::CommandExit::Usage.exit_code();
        }
    };
    let records = [common::act(1, Layout::Binary), common::act(2, Layout::Paired)];
    let accepted = validate_record(&records, &common::resolved()).expect("complete fixture");
    let count = accepted.acts().len();
    let mut missing = common::act(3, Layout::Paired);
    missing.mandatory.pop();
    let refused = validate_record(&[missing], &common::resolved()).is_err();
    let exit = if cli_common::emit(&serde_json::json!({"accepted_acts":count,"missing_co_leg_refused":refused})).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    };
    drop(guard);
    if std::env::var_os("PN_TEST_OBSERVATION_RENDEZVOUS").is_some() {
        let mut release = [0];
        let _ignored = std::io::Read::read_exact(&mut std::io::stdin(), &mut release);
    }
    exit
}
