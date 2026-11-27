//! # `cli-common` — integration tests
//!
//! These tests exercise the crate's **public** surface
//! (`emit`, `BaseArgs`) the same way a downstream helper
//! binary does: through `pub` items only, with no
//! `pub(crate)` peeking. The unit tests under
//! `src/tests/mod.rs` cover the same functions plus a few
//! private branches; this file pins the externally-visible
//! contract that helper binaries rely on.
//!
//! | Test                                  | What it covers                                    |
//! |---------------------------------------|---------------------------------------------------|
//! | `emit_real_stdout_through_public_api` | `emit` is callable through the crate's public API |
//! | `base_args_flattens_into_clap_parser` | `BaseArgs` composes via `#[command(flatten)]`     |
//! | `base_args_long_flag_toggles_debug`   | The `--debug` long flag flips the field           |
//! | `base_args_rejects_unknown_short_flag` | clap rejects an unrelated flag at parse time     |
//! | `parse_args_from_wraps_help_as_json_control_record` | shared parser returns JSON help metadata |

use clap::Parser;
use cli_common::{
    BaseArgs, CheckOutputArgs, CommandExit, ControlPlaneFields, ControlPlaneRecord, ControlPlaneRecordKind,
    OriginCallbackOutcome, OriginPreparation, emit, parse_args_from,
};
use serde::Serialize;

/// Minimal helper CLI: this fixture exercises the public composition of
/// `BaseArgs` via `#[command(flatten)]`.
#[derive(Parser)]
#[command(name = "fixture-helper")]
struct FixtureCli {
    #[command(flatten)]
    base: BaseArgs,
}

#[derive(Parser)]
#[command(name = "fixture-helper", version = "1.2.3", about = "Fixture helper")]
struct FixtureHelpCli {
    #[command(flatten)]
    base: BaseArgs,
}

#[derive(Parser)]
struct FixtureFileRoles {
    #[command(flatten)]
    files: CheckOutputArgs,
    #[arg(long, conflicts_with = "report")]
    output: Option<String>,
}

/// Claim: The renamed reciprocal file pair parses without old aliases, and a dirty check publishes its report without creating a clean stamp.
/// ´claim:cli:checker-file-role-spellings´
/// ´test:integration:checker-file-role-spellings´
#[test]
fn checker_file_role_spellings() {
    for args in [
        vec!["fixture", "--report", "x", "--stamp", "y"],
        vec!["fixture", "--report-file", "x"],
        vec!["fixture", "--stamp-file", "y"],
        vec!["fixture", "--report-file", "x", "--stamp-file", "y", "--output=report"],
    ] {
        assert!(FixtureFileRoles::try_parse_from(args).is_err());
    }
    let directory = tempfile::tempdir().expect("temporary directory");
    let report = directory.path().join("report.json");
    let stamp = directory.path().join("stamp");
    let parsed = FixtureFileRoles::try_parse_from([
        "fixture",
        "--report-file",
        report.to_str().expect("report path"),
        "--stamp-file",
        stamp.to_str().expect("stamp path"),
    ])
    .expect("renamed pair");
    let exit = cli_common::run_document_mode("fixture", false, tracing::Level::INFO, true, false, &parsed.files, || {
        Ok::<_, std::io::Error>((serde_json::json!({"findings": ["stale"]}), 1))
    });
    assert_eq!(exit, std::process::ExitCode::from(3));
    assert!(report.exists());
    assert!(!stamp.exists());
}

/// Claim: With harness-captured stdout, an external caller can emit the fixture payload successfully, checking public sink access without asserting captured byte contents.
/// ´claim:cli:emit-real-stdout-through-public-api´
/// ´test:integration:emit-real-stdout-through-public-api´
#[test]
fn emit_real_stdout_through_public_api() {
    // Under `cargo test`, stdout is captured by the harness,
    // so this is a happy-path smoke test — the documented
    // contract is "writes one JSON object + trailing newline".
    #[derive(Serialize)]
    struct Payload<'a> {
        schema: u32,
        name: &'a str,
    }

    emit(&Payload { schema: 1, name: "ok" }).expect("emit must succeed under captured stdout");
}

/// Claim: An external fixture parser can flatten `BaseArgs` and parse no options with debug false, checking the shared default through the public API.
/// ´claim:cli:base-args-flattens-into-clap-parser´
/// ´test:integration:base-args-flattens-into-clap-parser´
#[test]
fn base_args_flattens_into_clap_parser() {
    let cli = FixtureCli::try_parse_from(["fixture-helper"]).expect("no args is valid");
    assert!(!cli.base.debug, "default must be debug=false");
}

/// Claim: An external fixture parser accepts --debug and exposes debug true, checking the public shared-argument opt-in.
/// ´claim:cli:base-args-long-flag-toggles-debug´
/// ´test:integration:base-args-long-flag-toggles-debug´
#[test]
fn base_args_long_flag_toggles_debug() {
    let cli = FixtureCli::try_parse_from(["fixture-helper", "--debug"]).expect("--debug is valid");
    assert!(cli.base.debug);
}

/// Claim: An unknown long flag in the external fixture parser yields exit code 2, preventing unrecognized options from silently succeeding.
/// ´claim:cli:base-args-rejects-unknown-short-flag´
/// ´test:integration:base-args-rejects-unknown-short-flag´
#[test]
fn base_args_rejects_unknown_short_flag() {
    // Pins clap's contract that unknown flags surface as a
    // parse error rather than being silently dropped — every
    // helper binary depends on this for the `unknown-flag →
    // exit 2` mapping documented in the command-line output contract (´[ROOT-rec:output:decision]´).
    let Err(err) = FixtureCli::try_parse_from(["fixture-helper", "--no-such-flag"]) else {
        panic!("unknown flag must be rejected by clap");
    };
    assert_eq!(err.exit_code(), 2, "clap argv-parse failure exit code is 2");
}

/// Claim: The external fixture accepts debug and returns a successful `Help` record containing its description for --help, preserving public control-plane help access.
/// ´claim:cli:parse-args-from-wraps-help-as-json-control-record´
/// ´test:integration:parse-args-from-wraps-help-as-json-control-record´
#[test]
fn parse_args_from_wraps_help_as_json_control_record() {
    let parsed = FixtureHelpCli::try_parse_from(["fixture-helper", "--debug"]).expect("debug parses");
    assert!(parsed.base.debug);
    let Err(exit) = parse_args_from::<FixtureHelpCli, _, _>(["fixture-helper", "--help"]) else {
        panic!("help should return a control-plane exit record");
    };

    assert_eq!(exit.exit, CommandExit::Success);
    assert_eq!(exit.record.kind, ControlPlaneRecordKind::Help);

    let Some(ControlPlaneFields::Help { text }) = exit.record.fields else {
        panic!("help record should expose clap help text");
    };
    assert!(text.contains("Fixture helper"));
}

/// Claim: A public origin callback's explicit terminal refusal emits no stdout result and retains status two with enabled or validly disabled observation.
/// ´claim:cli:callback-terminal-refusal-output´
/// ´test:integration:callback-terminal-refusal-output´
#[test]
fn callback_terminal_refusal_output() {
    if std::env::var_os("PN_CALLBACK_REFUSAL_CHILD").is_some() {
        cli_common::observation::select_process_policy().expect("valid child observation policy");
        let exit = cli_common::run_stdout_json_command_from_origin_with_load_outcome(
            cli_common::observation::EntryOrigin::capture(),
            "callback-fixture",
            false,
            tracing::Level::INFO,
            || OriginPreparation::Continue {
                context: (),
                arguments: serde_json::json!({"command":"callback-fixture"}),
            },
            || {},
            |()| -> OriginCallbackOutcome<serde_json::Value, std::io::Error> {
                OriginCallbackOutcome::TerminalRefusal(ControlPlaneRecord::usage_error("callback-fixture", "target_not_empty"))
            },
        );
        assert_eq!(exit, CommandExit::Usage.exit_code());
        return;
    }
    for disable in [false, true] {
        let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"));
        child
            .arg("--exact")
            .arg("callback_terminal_refusal_output")
            .arg("--nocapture")
            .env("PN_CALLBACK_REFUSAL_CHILD", "1")
            .env_remove("PN_OBSERVE_LEVEL");
        if disable {
            child.env("PN_OBSERVE_DISABLE", "1");
        } else {
            child.env_remove("PN_OBSERVE_DISABLE");
        }
        let result = child.output().expect("child test");
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        assert!(
            String::from_utf8_lossy(&result.stdout)
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .all(|value| !value.is_object())
        );
        if disable {
            assert!(
                !String::from_utf8_lossy(&result.stderr).contains("target_not_empty"),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        } else {
            assert!(String::from_utf8_lossy(&result.stderr).contains("target_not_empty"));
        }
    }
}
