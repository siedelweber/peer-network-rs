//! `execwrap` binary: spawn a child process and route its stdout/stderr to log
//! files, with optional notifications.
//!
//! Diagnostics follow the command-line output contract through `cli-common`
//! (´[ROOT-rec:output:decision]´).

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use cli_common::{CommandExit, emit_control_plane_record, install_json_panic_hook, parse_args_from};
use execwrap::{ExecError, Notification, RoutingConfig, preflight_routing, run};

const COMMAND_NAME: &str = "execwrap";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ObservationMode {
    Enabled,
    Disabled,
}

#[derive(Debug, Parser)]
#[command(
    name = "execwrap",
    version,
    about = "Spawn a command and route its stdout/stderr to log files",
    trailing_var_arg = false
)]
struct Args {
    /// Redirect both STDOUT and STDERR to this file (raw, merged).
    #[arg(long = "redirect", value_name = "FILE")]
    redirect: Option<PathBuf>,

    /// Redirect STDOUT to this file.
    #[arg(long = "redirect-output", value_name = "FILE")]
    redirect_output: Option<PathBuf>,

    /// Redirect STDERR to this file.
    #[arg(long = "redirect-error", value_name = "FILE")]
    redirect_error: Option<PathBuf>,

    /// Redirect both streams to this file with per-stream prefixes.
    #[arg(long = "redirect-prefixed", value_name = "FILE")]
    redirect_prefixed: Option<PathBuf>,

    /// Emit notifications when log files are written.
    #[arg(long = "notify-on-write")]
    notify_on_write: bool,

    /// Change to this directory before executing the command.
    #[arg(long = "change-directory", short = 'C', value_name = "DIR")]
    change_directory: Option<PathBuf>,

    /// Add Writer write/line events at trace; does not select observation level. Use `PN_OBSERVE_LEVEL`.
    #[arg(long, short = 'd')]
    debug: bool,

    /// Observation delivery mode, independent of command results.
    #[arg(long, value_enum, default_value_t = ObservationMode::Enabled)]
    observation: ObservationMode,

    /// Command and its arguments (after `--`).
    #[arg(last = true, required = true, num_args = 1.., value_name = "COMMAND")]
    command: Vec<OsString>,
}

/// Justified: This executable bootstrap or termination adapter surrounds installation and handoff to the labelled command boundary; pre-installation control records remain direct and process termination fabricates no completion.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
fn main() -> ExitCode {
    // The panic hook precedes argument parsing (´[ROOT-rec:output:decision]´): a panic
    // anywhere in the process emits one JSON diagnostic, never Rust's
    // text hook.
    install_json_panic_hook(COMMAND_NAME);

    // clap owns help/version/usage handling; the `last = true`
    // positional makes the `--` separator a clap-enforced requirement,
    // so `--help`/`--version` exit 0 with JSON records and every argv
    // failure is usage class 2.
    let args: Args = match parse_args_from::<Args, _, _>(env::args_os()) {
        Ok(parsed) => parsed,
        Err(exit) => {
            let _ignored = emit_control_plane_record(&exit.record);
            return exit.exit_code();
        }
    };

    let _observation_guard = match cli_common::observation::bootstrap(
        args.observation == ObservationMode::Enabled,
        args.debug,
        tracing::Level::INFO,
    ) {
        Ok(guard) => Some(guard),
        Err(error @ cli_common::observation::BootstrapError::Configuration(_)) => {
            let mut record = cli_common::ControlPlaneRecord::usage_error(COMMAND_NAME, "observation_configuration");
            record.message = error.to_string();
            let _ignored = emit_control_plane_record(&record);
            return CommandExit::Usage.exit_code();
        }
        Err(cli_common::observation::BootstrapError::Unavailable(_)) => None,
    };

    execute(args)
}

fn execute(args: Args) -> ExitCode {
    let scope = cli_common::observation::scope("EXECWRAP", "rule:observe:spans", "execute", &args);
    let result = (|| {
        let cfg = RoutingConfig {
            redirect: args.redirect,
            redirect_output: args.redirect_output,
            redirect_error: args.redirect_error,
            redirect_prefixed: args.redirect_prefixed,
            notify_on_write: args.notify_on_write,
            debug: args.debug,
        };

        // Conflicting routing for one path is an invalid argument
        // combination: usage class 2, before any side effect. The
        // full public error text is retained in the usage diagnostic.
        if let Err(error @ ExecError::AmbiguousRedirection { .. }) = preflight_routing(&cfg) {
            let mut record = cli_common::ControlPlaneRecord::usage_error(COMMAND_NAME, "ambiguous_redirection");
            record.message = error.to_string();
            let _ignored = emit_control_plane_record(&record);
            return CommandExit::Usage.exit_code();
        }

        if let Some(directory) = &args.change_directory
            && let Err(error) = env::set_current_dir(directory)
        {
            tracing::error!(
                error = %error,
                directory = %directory.display(),
                "failed to change working directory",
            );
            return CommandExit::Failure.exit_code();
        }

        let outcome = match run(&args.command, &cfg, emit_notification) {
            Ok(outcome) => outcome,
            Err(ExecError::Spawn { source }) => {
                // The operation start already recorded the full public command.
                tracing::error!(error = %source, "failed to spawn child process");
                return CommandExit::Failure.exit_code();
            }
            Err(error) => {
                tracing::error!(error = %error, "execwrap setup failed");
                return CommandExit::Failure.exit_code();
            }
        };

        // Losing captured output is a wrapper failure even when the child
        // succeeded: a build must not silently continue on truncated logs.
        if outcome.data_loss && outcome.exit_code == 0 {
            tracing::error!("captured output may be incomplete; treating the run as failed");
            return CommandExit::Failure.exit_code();
        }

        wrapper_exit_from_child_status(outcome.exit_code)
    })();
    scope.finish_with(
        if result == ExitCode::SUCCESS {
            cli_common::observation::Outcome::Success
        } else if result == ExitCode::from(2) {
            cli_common::observation::Outcome::Refusal
        } else {
            cli_common::observation::Outcome::Error
        },
        &result,
    );
    result
}

/// Map a relayed child status onto the wrapper's exit code, keeping the
/// reserved workspace classes intact: 0 stays success, a child 1 or 2 becomes
/// wrapper runtime failure 1 (so code 2 stays reserved for wrapper usage), and
/// child statuses 3..=255 (including `128 + signal`) are relayed unchanged.
fn wrapper_exit_from_child_status(status: i32) -> ExitCode {
    let status = status.clamp(0, i32::from(u8::MAX));

    match status {
        0 => CommandExit::Success.exit_code(),
        1 | 2 => CommandExit::Failure.exit_code(),
        other => ExitCode::from(u8::try_from(other).unwrap_or(1)),
    }
}

fn emit_notification(notification: &Notification) {
    match notification {
        Notification::WritingToLog { path, stream } => {
            tracing::info!(
                path = %path.display(),
                stream = stream.label(),
                "Writing to log ({}): {}",
                stream.label(),
                path.display(),
            );
        }
        Notification::WroteToLog { path } => {
            tracing::info!(
                path = %path.display(),
                "Wrote to log file: {}",
                path.display(),
            );
        }
    }
}
