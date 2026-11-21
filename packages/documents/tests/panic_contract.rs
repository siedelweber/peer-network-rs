use std::process::Command;
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

/// Claim: The shared production startup preserves the public panic payload in one JSON diagnostic, with empty stdout and status one.
/// ´claim:cli:panic-proxy´
/// ´test:integration:panic-proxy´
#[test]
fn panic_proxy() -> documents::Result<()> {
    let output =
        Command::new(pn_testkit::runtime_path(pn_testkit::RuntimePath::Executable("documents-panic-probe")).unwrap()).output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"");
    let record: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(record["kind"], "panic");
    assert_eq!(record["command"], "documents");
    assert_eq!(record["fields"]["payload"], "contract probe");
    Ok(())
}

/// Claim: The admitted Rust backtrace setting selects the optional panic member without changing the one-row exit.
/// ´claim:cli:panic-backtrace-selection´
/// ´test:integration:panic-backtrace-selection´
#[test]
fn panic_backtrace_selection() -> documents::Result<()> {
    let executable = pn_testkit::runtime_path(pn_testkit::RuntimePath::Executable("documents-panic-probe")).unwrap();
    for setting in [
        None,
        Some(OsString::from("0")),
        Some(OsString::from("1")),
        Some(OsString::from("full")),
        Some(OsString::new()),
        Some(OsString::from_vec(vec![u8::MAX])),
    ] {
        let mut command = Command::new(&executable);
        command
            .env_remove("PN_OBSERVE_DISABLE")
            .env_remove("PN_OBSERVE_LEVEL")
            .env_remove("RUST_BACKTRACE");
        if let Some(value) = &setting {
            command.env("RUST_BACKTRACE", value);
        }
        let result = command.output()?;
        assert_eq!(result.status.code(), Some(1));
        assert_eq!(result.stdout, b"");
        let row: serde_json::Value = serde_json::from_slice(&result.stderr)?;
        assert_eq!(row["kind"], "panic");
        assert_eq!(
            row["fields"]["backtrace"].is_string(),
            setting.as_deref().is_some_and(|value| value != "0")
        );
        if let Some(backtrace) = row["fields"]["backtrace"].as_str() {
            let first_line = backtrace.lines().next().unwrap_or_default();
            if setting.as_deref() == Some(std::ffi::OsStr::new("full")) {
                assert!(first_line.trim_start().starts_with("0:"));
                assert!(first_line.contains("0x") && first_line.contains(" - "));
            } else {
                assert!(!first_line.contains("0x"));
            }
        }
    }
    Ok(())
}
