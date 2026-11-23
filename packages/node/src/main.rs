#![doc = include_str!("../README.md")]

use std::{ffi::OsString, process::ExitCode, time::Instant};

use clap::{Parser, Subcommand};
use cli_common::{OriginPreparation, observation::EntryOrigin};

const BUILD_STATEMENT: cli_common::BuildStatement = cli_common::BuildStatement::new(
    env!("CARGO_PKG_NAME"),
    option_env!("PN_BUILD_SOURCE_REVISION"),
    option_env!("PN_BUILD_RELEASE_TAG"),
);

mod process_adapter;

/// The initial command grammar has no edition operand or override.
/// (´[ROOT-amend:api:health-lifecycle]´)
#[derive(Parser)]
#[command(
    name = "pn",
    version,
    about = "Node control; start requires a supervisor notification socket"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the selected control edition under its supervisor.
    Start,
    /// Report the selected public edition as JSON; pipe or redirect stdout.
    Edition,
}

/// Capture entry before parsing and keep the shared runner's terminal and observation order.
/// (´[ROOT-amend:observe:entry-origin]´) (´[ROOT-amend:api:health-lifecycle]´)
/// Justified: Entry capture must precede all instrumentation; this binary delegates the observed command root, terminal output and exit to the origin runner.
fn main() -> ExitCode {
    let origin = EntryOrigin::capture();
    cli_common::select_observation_policy_or_exit("pn");
    let version_query_switch = cli_common::select_version_query_switch_or_exit("pn");
    cli_common::run_stdout_json_command_from_origin_with_load(
        origin,
        "pn",
        false,
        tracing::Level::INFO,
        || {
            let preparation_at = Instant::now();
            let arguments: Vec<OsString> = std::env::args_os().collect();
            let observed = serde_json::json!({
                "arguments": arguments.iter().map(|argument| argument.as_encoded_bytes().to_vec()).collect::<Vec<_>>()
            });
            match cli_common::parse_args_from::<Arguments, _, _>(arguments.clone()) {
                Ok(Arguments { command }) => process_adapter::prepare(&command, &arguments, preparation_at),
                Err(mut exit) => {
                    if exit.record.kind == cli_common::ControlPlaneRecordKind::Version {
                        exit.record = cli_common::ControlPlaneRecord::version("pn", &BUILD_STATEMENT.version());
                    }
                    OriginPreparation::Terminal {
                        exit,
                        arguments: observed,
                    }
                }
            }
        },
        || {
            if let Some(version_query_switch) = version_query_switch {
                tracing::warn!(
                    event = "debug_build_load",
                    version = %BUILD_STATEMENT.version(),
                    build_kind = cli_common::observation::BuildKind::compiled().name(),
                    epoch_version_query = version_query_switch.name(),
                    version_query_switch = "PN_DEBUG_VERSION_DISABLE",
                    "debug build"
                );
            }
        },
        process_adapter::run,
    )
}
