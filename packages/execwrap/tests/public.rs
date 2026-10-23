use execwrap::{ExecError, RoutingConfig, preflight_routing, run};

/// Claim: Empty argv is refused before notification or output-file creation through the public runner.
/// ´claim:cli:empty-command-has-no-effects´
/// ´test:integration:empty-command-preflight´
#[test]
fn empty_command_preflight() {
    let root = tempfile::tempdir().expect("private test root");
    let destination = root.path().join("not-created.log");
    let config = RoutingConfig {
        redirect_output: Some(destination.clone()),
        notify_on_write: true,
        ..RoutingConfig::default()
    };
    preflight_routing(&config).expect("a distinct destination");
    let mut notified = false;
    assert!(matches!(run(&[], &config, |_| notified = true), Err(ExecError::EmptyCommand)));
    assert!(!notified);
    assert!(!destination.exists());
}
