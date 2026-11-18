#![doc = include_str!("../README.md")]

use std::{convert::Infallible, ffi::OsString, process::ExitCode, time::Instant};

use clap::{Parser, Subcommand};
use cli_common::{CliExit, CommandExit, ControlPlaneRecord, OriginPreparation, observation::EntryOrigin};

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
    cli_common::run_stdout_json_command_from_origin(
        origin,
        "pn",
        false,
        tracing::Level::INFO,
        || {
            let _preparation_at = Instant::now();
            let arguments: Vec<OsString> = std::env::args_os().collect();
            let observed = serde_json::json!({
                "arguments": arguments.iter().map(|argument| argument.as_encoded_bytes().to_vec()).collect::<Vec<_>>()
            });
            let exit = match cli_common::parse_args_from::<Arguments, _, _>(arguments) {
                Ok(Arguments {
                    command: Command::Start | Command::Edition,
                }) => CliExit::new(ControlPlaneRecord::diagnostic("pn", "Configuration"), CommandExit::Failure),
                Err(exit) => exit,
            };
            OriginPreparation::<Infallible>::Terminal {
                exit,
                arguments: observed,
            }
        },
        |never: Infallible| -> Result<(), Infallible> { match never {} },
    )
}
