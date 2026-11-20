use std::process::Command;

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
    for setting in [None, Some("0"), Some("1"), Some("full")] {
        let mut command = Command::new(&executable);
        command
            .env_remove("PN_OBSERVE_DISABLE")
            .env_remove("PN_OBSERVE_LEVEL")
            .env_remove("RUST_BACKTRACE");
        if let Some(value) = setting {
            command.env("RUST_BACKTRACE", value);
        }
        let result = command.output()?;
        assert_eq!(result.status.code(), Some(1));
        assert_eq!(result.stdout, b"");
        let row: serde_json::Value = serde_json::from_slice(&result.stderr)?;
        assert_eq!(row["kind"], "panic");
        assert_eq!(row["fields"]["backtrace"].is_string(), matches!(setting, Some("1" | "full")));
    }
    Ok(())
}
