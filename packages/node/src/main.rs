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

/// A deferred fixture choice; shared grammar terminals are decided first.
enum FixtureRequest {
    #[cfg(not(feature = "fixture"))]
    Disabled,
    #[cfg(feature = "fixture")]
    Missing,
    #[cfg(feature = "fixture")]
    Candidate(String),
    #[cfg(feature = "fixture")]
    Refused,
}

enum FixtureAdmission {
    Unselected,
    #[cfg(feature = "fixture")]
    Selected(String),
    #[cfg(feature = "fixture")]
    Refused(Box<cli_common::CliExit>),
}

impl FixtureRequest {
    fn accepted(&self, command: &Command) -> FixtureAdmission {
        #[cfg(feature = "fixture")]
        {
            match (command, self) {
                (Command::Edition, Self::Missing) => FixtureAdmission::Unselected,
                (Command::Start, Self::Candidate(name)) if pn_fixtures::recognizes_name(name) => {
                    FixtureAdmission::Selected(name.clone())
                }
                _ => FixtureAdmission::Refused(Box::new(cli_common::CliExit::new(
                    cli_common::ControlPlaneRecord::usage_error("pn", "fixture_selection"),
                    cli_common::CommandExit::Usage,
                ))),
            }
        }
        #[cfg(not(feature = "fixture"))]
        {
            let _ = (self, command);
            FixtureAdmission::Unselected
        }
    }
}

#[cfg(feature = "fixture")]
fn fixture_arguments(arguments: Vec<OsString>) -> (Vec<OsString>, FixtureRequest) {
    let mut shared = Vec::with_capacity(arguments.len());
    let mut name = None;
    let mut refused = false;
    let mut start_seen = false;
    let mut positional_only = false;
    for argument in arguments {
        let bytes = argument.as_encoded_bytes();
        if bytes == b"--" {
            positional_only = true;
        }
        if !positional_only && bytes == b"--fixture" {
            refused = true;
            continue;
        }
        if !positional_only && bytes.starts_with(b"--fixture=") {
            if !start_seen || name.is_some() || refused {
                refused = true;
            } else if let Some(candidate) = argument.to_str().and_then(|text| text.strip_prefix("--fixture=")) {
                if candidate.is_empty() {
                    refused = true;
                } else {
                    name = Some(candidate.to_owned());
                }
            } else {
                refused = true;
            }
            continue;
        }
        if bytes == b"start" {
            start_seen = true;
        }
        shared.push(argument);
    }
    let request = if refused {
        FixtureRequest::Refused
    } else if let Some(name) = name {
        FixtureRequest::Candidate(name)
    } else {
        FixtureRequest::Missing
    };
    (shared, request)
}

#[cfg(not(feature = "fixture"))]
fn fixture_arguments(arguments: Vec<OsString>) -> (Vec<OsString>, FixtureRequest) {
    (arguments, FixtureRequest::Disabled)
}

fn parse_and_prepare(
    arguments: &[OsString],
    preparation_at: Instant,
    prepare: impl FnOnce(&Command, &[OsString], &[OsString], Instant, &FixtureRequest) -> OriginPreparation<process_adapter::Prepared>,
) -> OriginPreparation<process_adapter::Prepared> {
    let observed = serde_json::json!({
        "arguments": arguments.iter().map(|argument| argument.as_encoded_bytes().to_vec()).collect::<Vec<_>>()
    });
    let (shared, fixture) = fixture_arguments(arguments.to_vec());
    match cli_common::parse_args_from::<Arguments, _, _>(shared.iter().cloned()) {
        Ok(Arguments { command }) => prepare(&command, arguments, &shared, preparation_at, &fixture),
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
            parse_and_prepare(&arguments, preparation_at, process_adapter::prepare)
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

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, ffi::OsString, time::Instant};

    #[cfg(not(feature = "fixture"))]
    use cli_common::ControlPlaneRecordKind;
    use cli_common::{CommandExit, ControlPlaneFields, OriginPreparation};

    #[cfg(feature = "fixture")]
    use super::{Command, FixtureAdmission, FixtureRequest};
    use super::{parse_and_prepare, process_adapter};

    const EDITION: &str =
        "schema=org.peer-network.test.api-control-schema@1.0.0;register=org.peer-network.test.api-control-register@1.0.0";

    fn entry(
        arguments: &[&str],
        edition: Option<&str>,
        calls: &RefCell<Vec<&'static str>>,
    ) -> OriginPreparation<process_adapter::Prepared> {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        parse_and_prepare(&arguments, Instant::now(), |command, arguments, shared, clock, fixture| {
            process_adapter::tested_prepare(command, (arguments, shared), clock, fixture, edition, true, calls)
        })
    }

    fn terminal(result: OriginPreparation<process_adapter::Prepared>) -> cli_common::CliExit {
        match result {
            OriginPreparation::Terminal { exit, .. } => exit,
            OriginPreparation::Continue { .. } => panic!("expected terminal entry"),
        }
    }

    fn usage_kind(exit: &cli_common::CliExit) -> Option<&str> {
        match &exit.record.fields {
            Some(ControlPlaneFields::UsageError { clap_error_kind, .. }) => Some(clap_error_kind),
            _ => None,
        }
    }

    /// Claim: Closed attached fixture selection accepts the library's name only in the fixture build and refuses missing, malformed, repeated and wrong-operation selections while the plain build keeps the unknown-option route.
    /// ´claim:lifecycle:fixture-arguments-select-only-named-input´
    /// ´test:unit:fixture-arguments-select-only-named-input´
    #[test]
    fn fixture_arguments_select_only_named_input() {
        let calls = RefCell::new(Vec::new());
        #[cfg(feature = "fixture")]
        {
            assert!(matches!(
                FixtureRequest::Candidate("root".to_owned()).accepted(&Command::Start),
                FixtureAdmission::Selected(name) if name == "root"
            ));
            let accepted = terminal(entry(&["pn", "start", "--fixture=root"], Some(EDITION), &calls));
            assert_eq!(accepted.exit, CommandExit::Failure);
            assert_eq!(accepted.record.message, "Configuration");
            for arguments in [
                vec!["pn", "start"],
                vec!["pn", "start", "--fixture"],
                vec!["pn", "start", "--fixture="],
                vec!["pn", "start", "--fixture=other"],
                vec!["pn", "start", "--fixture=root", "--fixture=root"],
                vec!["pn", "edition", "--fixture=root"],
            ] {
                calls.borrow_mut().clear();
                let refused = terminal(entry(&arguments, Some(EDITION), &calls));
                assert_eq!(refused.exit, CommandExit::Usage);
                assert_eq!(usage_kind(&refused), Some("fixture_selection"));
            }
        }
        #[cfg(not(feature = "fixture"))]
        {
            let refused = terminal(entry(&["pn", "start", "--fixture=root"], Some(EDITION), &calls));
            assert_eq!(refused.exit, CommandExit::Usage);
            assert_eq!(usage_kind(&refused), Some("unknown_argument"));
            assert!(calls.borrow().is_empty());
        }
    }

    /// Claim: Shared grammar and returned help or version terminals keep their entry priority over a deferred fixture refusal, which prevents later public-input acquisition.
    /// ´claim:lifecycle:fixture-entry-terminal-precedence´
    /// ´test:unit:fixture-entry-terminal-precedence´
    #[test]
    fn fixture_entry_terminal_precedence() {
        let calls = RefCell::new(Vec::new());
        #[cfg(feature = "fixture")]
        {
            let helped = terminal(entry(&["pn", "start", "--fixture=other", "--help"], None, &calls));
            assert_eq!(helped.exit, CommandExit::Success);
            let versioned = terminal(entry(&["pn", "--version", "start", "--fixture=other"], None, &calls));
            assert_eq!(versioned.exit, CommandExit::Success);
            assert!(calls.borrow().is_empty());
            let shared = terminal(entry(&["pn", "start", "--fixture=other", "--unknown"], None, &calls));
            assert_eq!(shared.exit, CommandExit::Usage);
            assert_ne!(usage_kind(&shared), Some("fixture_selection"));
            let deferred = terminal(entry(&["pn", "start", "--fixture=other"], None, &calls));
            assert_eq!(deferred.exit, CommandExit::Usage);
            assert_eq!(usage_kind(&deferred), Some("fixture_selection"));
            assert!(calls.borrow().is_empty());
        }
        #[cfg(not(feature = "fixture"))]
        {
            let refused = terminal(entry(&["pn", "start", "--fixture=other"], None, &calls));
            assert_eq!(refused.exit, CommandExit::Usage);
            assert_eq!(usage_kind(&refused), Some("unknown_argument"));
            assert!(calls.borrow().is_empty());
            let earlier_unknown = terminal(entry(&["pn", "start", "--fixture=other", "--help"], None, &calls));
            assert_eq!(earlier_unknown.record.kind, ControlPlaneRecordKind::UsageError);
            let helped = terminal(entry(&["pn", "start", "--help", "--fixture=other"], None, &calls));
            assert_eq!(helped.record.kind, ControlPlaneRecordKind::Help);
        }
    }

    /// Claim: An accepted fixture name ends synchronous preparation as Configuration failure without continuing into command work, while a missing edition still wins.
    /// ´claim:lifecycle:fixture-unbound-start-never-runs´
    /// ´test:unit:fixture-unbound-start-never-runs´
    #[cfg(feature = "fixture")]
    #[test]
    fn fixture_unbound_start_never_runs() {
        let calls = RefCell::new(Vec::new());
        let accepted = terminal(entry(&["pn", "start", "--fixture=root"], Some(EDITION), &calls));
        assert_eq!(accepted.exit, CommandExit::Failure);
        assert_eq!(accepted.record.message, "Configuration");
        assert_eq!(*calls.borrow(), vec!["signal_registration", "public_inputs", "notification"]);
        calls.borrow_mut().clear();
        let earlier = terminal(entry(&["pn", "start", "--fixture=root"], None, &calls));
        assert_eq!(earlier.exit, CommandExit::Usage);
        assert_eq!(*calls.borrow(), vec!["signal_registration", "public_inputs"]);
    }
}
