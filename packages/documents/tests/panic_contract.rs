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
