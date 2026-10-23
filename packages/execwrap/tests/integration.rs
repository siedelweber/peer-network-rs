//! End-to-end subprocess tests for the `execwrap` binary: real child
//! processes, real pipes, real log files. These pin the behaviors the
//! paper build depends on — byte-exact raw capture, per-stream
//! routing, exit-code propagation (including signals), ambiguous
//! routing refusal, and the data-loss failure policy.

use std::path::Path;
use std::process::{Command, Output};

fn execwrap() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_execwrap"));
    command.env("PN_OBSERVE_LEVEL", "trace");
    command
}

fn run(args: &[&str]) -> Output {
    execwrap().args(args).output().expect("execwrap runs")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("log file readable")
}

/// Claim: Unknown and non-UTF-8 observation levels refuse with one usage diagnostic and exit 2 before a child can create its marker, even when observation is disabled; a valid-level control proves the child would create it.
/// ´claim:cli:invalid-observation-level-refuses-before-child-start´
/// ´test:integration:invalid-observation-level-starts-no-child´
#[test]
fn invalid_observation_level_starts_no_child() {
    use std::os::unix::ffi::OsStringExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("child-started");
    let child = ["--", "sh", "-c", "printf started > \"$1\"", "fixture"];
    let control = execwrap()
        .env("PN_OBSERVE_LEVEL", "default")
        .args(child)
        .arg(&marker)
        .output()
        .expect("control runs");
    assert!(control.status.success());
    assert_eq!(read(&marker), b"started");
    std::fs::remove_file(&marker).expect("remove control marker");
    for level in [std::ffi::OsString::from("unknown"), std::ffi::OsString::from_vec(vec![255])] {
        for mode in ["enabled", "disabled"] {
            let output = execwrap()
                .env("PN_OBSERVE_LEVEL", &level)
                .args(["--observation", mode])
                .args(child)
                .arg(&marker)
                .output()
                .expect("wrapper runs");
            assert_eq!(output.status.code(), Some(2));
            assert_eq!(output.stdout, [] as [u8; 0]);
            let record: serde_json::Value = serde_json::from_slice(&output.stderr).expect("exactly one JSON diagnostic");
            assert_eq!(record["kind"], "usage_error");
            assert_eq!(record["fields"]["exit_code"], 2);
            assert_eq!(record["fields"]["clap_error_kind"], "observation_configuration");
            assert!(record["message"].as_str().expect("message").contains("PN_OBSERVE_LEVEL"));
            assert!(!marker.exists(), "refused configuration must not start the child");
        }
    }
}

/// `--redirect` (raw, merged) preserves arbitrary bytes: invalid
/// UTF-8, NUL, ANSI escapes, and a large binary chunk.
///
/// Claim: A merged raw redirect preserves the fixture's invalid UTF-8, NUL, escape bytes and 64 `KiB` binary chunk exactly after a successful child run.
/// ´claim:cli:raw-redirect-is-byte-exact´
/// ´test:integration:raw-redirect-is-byte-exact´
#[test]
fn raw_redirect_is_byte_exact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("raw.log");

    // 64 KiB of 0xA5 plus invalid UTF-8, NUL, and an ANSI escape.
    let script = r"
        printf '\377\376\000\033[31m'
        head -c 65536 /dev/zero | tr '\000' '\245'
        printf '\n'
    ";

    let output = run(&["--redirect", log.to_str().expect("utf8 path"), "--", "sh", "-c", script]);
    assert!(output.status.success());

    let written = read(&log);
    let mut expected: Vec<u8> = vec![0xff, 0xfe, 0x00, 0x1b, b'[', b'3', b'1', b'm'];
    expected.extend(std::iter::repeat_n(0xa5_u8, 65536));
    expected.push(b'\n');
    assert_eq!(written, expected, "raw redirection altered the byte stream");
}

/// Simultaneous stdout/stderr routing to separate files keeps each
/// stream's bytes exact and unmixed.
///
/// Claim: A child writing both streams leaves the exact distinct stdout and stderr lines in their respective files, preventing cross-stream mixing.
/// ´claim:cli:split-streams-route-to-their-own-files´
/// ´test:integration:split-streams-route-to-their-own-files´
#[test]
fn split_streams_route_to_their_own_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_log = dir.path().join("out.log");
    let err_log = dir.path().join("err.log");

    let output = run(&[
        "--redirect-output",
        out_log.to_str().expect("utf8 path"),
        "--redirect-error",
        err_log.to_str().expect("utf8 path"),
        "--",
        "sh",
        "-c",
        "printf 'to-stdout\\n'; printf 'to-stderr\\n' >&2",
    ]);
    assert!(output.status.success());

    assert_eq!(read(&out_log), b"to-stdout\n");
    assert_eq!(read(&err_log), b"to-stderr\n");
}

/// A child status in the relay range (3..=255) is propagated unchanged.
///
/// Claim: A spawned child exiting 7 makes the wrapper exit 7, checking a concrete member of the relay range.
/// ´claim:cli:child-exit-code-is-propagated´
/// ´test:integration:child-exit-code-is-propagated´
#[test]
fn child_exit_code_is_propagated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("raw.log");

    let output = run(&["--redirect", log.to_str().expect("utf8 path"), "--", "sh", "-c", "exit 7"]);
    assert_eq!(output.status.code(), Some(7));
}

/// Reserved workspace exit classes survive child-status relay: 0 stays
/// success, a child 1 or 2 becomes wrapper runtime failure 1 (so code 2 stays
/// reserved for wrapper usage), and 3..=255 relay unchanged.
///
/// Claim: Child statuses 0, 1, 2, 3 and 42 map to 0, 1, 1, 3 and 42, keeping usage code 2 reserved for wrapper argument failures.
/// ´claim:cli:reserved-wrapper-exit-classes-are-preserved´
/// ´test:integration:reserved-wrapper-exit-classes-are-preserved´
#[test]
fn reserved_wrapper_exit_classes_are_preserved() {
    let dir = tempfile::tempdir().expect("tempdir");

    for (child, wrapper) in [(0, 0), (1, 1), (2, 1), (3, 3), (42, 42)] {
        let log = dir.path().join(format!("relay-{child}.log"));
        let exit_command = format!("exit {child}");
        let output = run(&[
            "--redirect",
            log.to_str().expect("utf8 path"),
            "--",
            "sh",
            "-c",
            exit_command.as_str(),
        ]);
        assert_eq!(
            output.status.code(),
            Some(wrapper),
            "child {child} should map to wrapper {wrapper}",
        );
    }
}

/// A child that cannot be spawned is a wrapper runtime failure (1), not a
/// relayed child status.
///
/// Claim: A nonexistent executable makes the wrapper exit 1, distinguishing failure to spawn from a relayed child status.
/// ´claim:cli:unspawnable-child-is-wrapper-failure´
/// ´test:integration:unspawnable-child-is-wrapper-failure´
#[test]
fn unspawnable_child_is_wrapper_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("raw.log");

    let output = run(&[
        "--redirect",
        log.to_str().expect("utf8 path"),
        "--",
        "definitely-not-a-real-program-b3f1",
    ]);
    assert_eq!(output.status.code(), Some(1));
}

/// Claim: A nonexistent public program yields exit 1 and empty stdout while its complete name survives in JSON stderr, preserving failed-attempt context.
/// ´claim:cli:spawn-failure-records-public-program´
/// ´test:integration:spawn-failure-records-public-program´
#[test]
fn spawn_failure_records_public_program() {
    let secret = "SHOULD_NOT_APPEAR_spawn-program-secret";
    let program = format!("/nonexistent/{secret}");

    let output = run(&["--", program.as_str()]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(secret), "public program missing from diagnostics: {stderr}");

    for line in stderr.lines().filter(|line| !line.trim().is_empty()) {
        let value: serde_json::Value = serde_json::from_str(line).expect("diagnostic is JSON");
        assert!(value.is_object());
    }
}

/// Claim: A public URL-shaped program yields exit 1 and empty stdout with the entire URL retained in stderr, preventing heuristic content deletion.
/// ´claim:cli:spawn-failure-records-public-url´
/// ´test:integration:spawn-failure-records-public-url´
#[test]
fn spawn_failure_records_public_url() {
    let program = "https://user:hunter2-secret@example.invalid/SHOULD_NOT_APPEAR";

    let output = run(&["--", program]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(program),
        "public program URL missing from diagnostics: {stderr}",
    );
}

/// Signal termination is reported as 128 + signal.
///
/// Claim: A child terminating itself with SIGTERM makes the wrapper exit 143, preserving the declared signal-status encoding for that signal.
/// ´claim:cli:signal-termination-maps-to-128-plus-signal´
/// ´test:integration:signal-termination-maps-to-128-plus-signal´
#[test]
fn signal_termination_maps_to_128_plus_signal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("raw.log");

    let output = run(&[
        "--redirect",
        log.to_str().expect("utf8 path"),
        "--",
        "sh",
        "-c",
        "kill -TERM $$",
    ]);
    // SIGTERM = 15.
    assert_eq!(output.status.code(), Some(128 + 15));
}

/// The same path configured for two different routing kinds is an
/// invalid argument combination: usage class 2, no side effects.
///
/// Claim: Two route kinds naming one absent file yield exit 2, empty stdout and no log file, preventing usage failure from creating outputs.
/// ´claim:cli:ambiguous-same-path-routing-is-a-usage-failure´
/// ´test:integration:ambiguous-same-path-routing-is-a-usage-failure´
#[test]
fn ambiguous_same_path_routing_is_a_usage_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("both.log");
    let path = log.to_str().expect("utf8 path");

    let output = run(&["--redirect", path, "--redirect-output", path, "--", "true"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert!(!log.exists(), "usage failure must not open log files");
}

/// Claim: A successful child with a credential-named public argument leaves stdout empty and records the argument in stderr, distinguishing public input from secret-typed material.
/// ´claim:cli:public-child-arguments-are-observed´
/// ´test:integration:public-child-arguments-are-observed´
#[test]
fn public_child_arguments_are_observed() {
    let secret = "SHOULD_NOT_APPEAR_hunter2";
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("raw.log");

    let output = execwrap()
        .args([
            "--debug",
            "--redirect",
            log.to_str().expect("utf8 path"),
            "--",
            "sh",
            "-c",
            "true",
            "sh",
            "--api-token",
            secret,
        ])
        .output()
        .expect("execwrap runs");
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains(secret), "secret leaked to stdout");
    assert!(stderr.contains(secret), "public argument missing from diagnostics");
}

/// Claim: A successful child with a public URL argument records every URL component on stderr without changing empty result stdout.
/// ´claim:cli:public-child-urls-are-observed´
/// ´test:integration:public-child-urls-are-observed´
#[test]
fn public_child_urls_are_observed() {
    let url = "https://user:hunter2-secret@example.invalid/private?api_key=SHOULD_NOT_APPEAR";
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("raw.log");

    let output = execwrap()
        .args([
            "--debug",
            "--redirect",
            log.to_str().expect("utf8 path"),
            "--",
            "sh",
            "-c",
            "true",
            "sh",
            "--endpoint",
            url,
        ])
        .output()
        .expect("execwrap runs");
    assert!(output.status.success());

    assert_eq!(output.stdout, [] as [u8; 0]);
    assert!(String::from_utf8_lossy(&output.stderr).contains(url));
}

/// Redirecting only stderr must still relay stdout to the parent.
///
/// Claim: With only stderr redirected, the wrapper forwards exact stdout bytes and writes exact stderr bytes to its file, preserving the unsubscribed stream.
/// ´claim:cli:redirect-error-only-still-forwards-stdout´
/// ´test:integration:redirect-error-only-still-forwards-stdout´
#[test]
fn redirect_error_only_still_forwards_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("err.log");

    let output = run(&[
        "--redirect-error",
        log.to_str().expect("utf8 path"),
        "--",
        "sh",
        "-c",
        "printf 'stdout-visible'; printf 'to-file' >&2",
    ]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"stdout-visible");
    assert_eq!(read(&log), b"to-file");
}

/// The minimal valid invocation: a separator and a child, no options.
///
/// Claim: A separator followed by true and no options exits 0 with empty stdout, checking the minimal valid command boundary.
/// ´claim:cli:bare-separator-invocation-succeeds´
/// ´test:integration:bare-separator-invocation-succeeds´
#[test]
fn bare_separator_invocation_succeeds() {
    let output = run(&["--", "true"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
}

/// An unsubscribed child stream is relayed to the parent's stream even
/// when the parent stream is a pipe, never silently discarded.
///
/// Claim: Quiet mode relays both unredirected streams; redirecting only stdout empties wrapper stdout while stderr remains visible, preventing silent pipe-output loss.
/// ´claim:cli:unredirected-streams-pass-through-pipes´
/// ´test:integration:unredirected-streams-pass-through-pipes´
#[test]
fn unredirected_streams_pass_through_pipes() {
    // No redirection at all: both streams relay.
    let output = run(&["--", "sh", "-c", "printf 'out-bytes'; printf 'err-bytes' >&2"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"out-bytes");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("err-bytes"), "stderr bytes were discarded");

    // Only stdout redirected: stderr still relays.
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("out.log");
    let output = run(&[
        "--redirect-output",
        log.to_str().expect("utf8 path"),
        "--",
        "sh",
        "-c",
        "printf 'to-file'; printf 'still-visible' >&2",
    ]);
    assert!(output.status.success());
    assert!(output.stdout.is_empty(), "redirected stdout must not relay");
    assert_eq!(read(&log), b"to-file");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("still-visible"), "stderr was discarded");
}

/// Help and version are control-plane paths: JSON on stderr, empty
/// stdout, exit 0. Usage failures exit 2 (´[ROOT-rec:output:decision]´).
///
/// Claim: `Help` and version exit 0 with empty stdout and a first JSON record naming execwrap; unknown flags, missing separator and missing command exit 2.
/// ´claim:cli:help-version-and-usage-follow-the-output-contract´
/// ´test:integration:help-version-and-usage-follow-the-output-contract´
#[test]
fn help_version_and_usage_follow_the_output_contract() {
    for flag in ["--help", "--version"] {
        let output = run(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag} must exit 0");
        assert!(output.stdout.is_empty(), "{flag} must not write stdout");

        let stderr = String::from_utf8(output.stderr).expect("stderr is text");
        let record: serde_json::Value =
            serde_json::from_str(stderr.lines().next().expect("one record")).expect("stderr record is JSON");
        assert_eq!(record["command"], "execwrap");
    }

    // Unknown flag: usage class.
    let output = run(&["--no-such-flag", "--", "true"]);
    assert_eq!(output.status.code(), Some(2));

    // Missing `--` separator before the command: usage class.
    let output = run(&["true"]);
    assert_eq!(output.status.code(), Some(2));

    // No command at all: usage class.
    let output = run(&[]);
    assert_eq!(output.status.code(), Some(2));
}

/// Prefixed mode is a text presentation: streams are tagged and
/// control bytes are sanitized.
///
/// Claim: A successful two-stream child leaves stdout and stderr lines with their distinct configured tags, preserving their identities in the merged text log.
/// ´claim:cli:prefixed-redirect-tags-streams´
/// ´test:integration:prefixed-redirect-tags-streams´
#[test]
fn prefixed_redirect_tags_streams() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("prefixed.log");

    let output = run(&[
        "--redirect-prefixed",
        log.to_str().expect("utf8 path"),
        "--",
        "sh",
        "-c",
        "printf 'out-line\\n'; printf 'err-line\\n' >&2",
    ]);
    assert!(output.status.success());

    let text = String::from_utf8(read(&log)).expect("prefixed log is text");
    assert!(text.contains(">>> out-line"));
    assert!(text.contains("*** err-line"));
}

/// Losing captured bytes fails the run even when the child exited 0:
/// writes to /dev/full fail with ENOSPC, so the wrapper must not
/// report success.
///
/// Claim: When /dev/full is available, losing redirected bytes makes the wrapper exit 1 despite child exit 0, preventing data loss from being reported as success.
/// ´claim:cli:data-loss-fails-a-successful-child´
/// ´test:integration:data-loss-fails-a-successful-child´
#[test]
fn data_loss_fails_a_successful_child() {
    if !Path::new("/dev/full").exists() {
        // Non-Linux fallback: nothing to exercise.
        return;
    }

    let output = run(&[
        "--redirect",
        "/dev/full",
        "--",
        "sh",
        "-c",
        "printf 'doomed bytes\\n'; exit 0",
    ]);
    assert_eq!(output.status.code(), Some(1), "wrapper must fail when log bytes were lost");
}

/// Diagnostics are JSON on stderr (´[ROOT-rec:output:decision]´): a spawn failure produces
/// parseable JSON records and no stdout.
///
/// Claim: A nonexistent executable yields exit 1, empty stdout and at least one stderr JSON object with every nonempty line parseable, preserving diagnostic framing on failure.
/// ´claim:cli:spawn-failure-emits-json-diagnostics´
/// ´test:integration:spawn-failure-emits-json-diagnostics´
#[test]
fn spawn_failure_emits_json_diagnostics() {
    let output = run(&["--", "/nonexistent-binary-for-execwrap-test"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout must stay empty");

    let stderr = String::from_utf8(output.stderr).expect("stderr is text");
    let mut saw_json = false;
    for line in stderr.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line).expect("every stderr line is one JSON object");
        saw_json = true;
        assert!(value.is_object());
    }
    assert!(saw_json, "expected at least one JSON diagnostic");
}

/// Claim: The same binary child result, including NUL and invalid UTF-8, has identical stdout and exit with observation enabled and disabled; enabled metering retains those bytes and the returned status.
/// ´claim:cli:observation-preserves-child-results´
/// ´test:integration:observation-preserves-child-results´
#[test]
fn observation_preserves_child_results() {
    let script = r"printf '\377\000public'; exit 7";
    let enabled = run(&["--", "sh", "-c", script]);
    let disabled = run(&["--observation", "disabled", "--", "sh", "-c", script]);
    assert_eq!(enabled.stdout, disabled.stdout);
    assert_eq!(enabled.status.code(), disabled.status.code());
    assert_eq!(enabled.status.code(), Some(7));
    assert_eq!(enabled.stdout, b"\xff\0public");
    let unavailable: serde_json::Value = serde_json::from_slice(&disabled.stderr).unwrap();
    assert_eq!(unavailable["availability"], "disabled");
    assert_eq!(unavailable["measurements"], "unavailable");
    let records: Vec<serde_json::Value> = String::from_utf8(enabled.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let bytes: Vec<u8> = records
        .iter()
        .filter(|r| r["event_kind"] == "progress")
        .flat_map(|r| {
            let value = &r["detail"]["bytes"];
            let text = value["data"].as_str().unwrap();
            if value["encoding"] == "utf-8" {
                return text.as_bytes().to_vec();
            }
            assert_eq!(value["encoding"], "base64");
            let mut decoded = Vec::new();
            let mut bits = 0_u32;
            let mut count = 0;
            for byte in text.bytes().take_while(|byte| *byte != b'=') {
                let digit = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    .iter()
                    .position(|b| *b == byte)
                    .unwrap();
                bits = (bits << 6) | u32::try_from(digit).unwrap();
                count += 6;
                if count >= 8 {
                    count -= 8;
                    decoded.push(u8::try_from((bits >> count) & 255).unwrap());
                }
            }
            assert_eq!(
                decoded.len(),
                usize::try_from(value["length_bytes"].as_u64().unwrap()).unwrap()
            );
            decoded
        })
        .collect();
    assert_eq!(bytes, enabled.stdout);
    assert!(
        records
            .iter()
            .any(|r| r["event_kind"] == "completion" && r["detail"]["result"]["exit_code"] == 7)
    );
    assert!(records.iter().any(|r| r["kind"] == "metric_summary"));
}
