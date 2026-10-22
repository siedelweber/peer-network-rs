use std::process::Command;

/// Claim: the probe using shared production startup emits one payload-free JSON panic record, no stdout and status one.
/// ´claim:cli:panic-proxy´
/// ´test:integration:panic-proxy´
#[test]
fn panic_proxy() -> documents::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_documents-panic-probe")).output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"");
    let record: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(record["kind"], "panic");
    assert_eq!(record["command"], "documents");
    assert!(record["fields"].get("payload").is_none());
    Ok(())
}
