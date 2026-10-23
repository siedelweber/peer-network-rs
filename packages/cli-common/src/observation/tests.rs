use super::*;
use crate::secrets::{PrivateBytes, PrivateString, SecretBox, SecretRole, SecretString};
use std::sync::Mutex;

struct ManualClock(AtomicU64);
impl Clock for ManualClock {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::Relaxed))
    }
    fn utc(&self) -> Option<UtcInstant> {
        UtcInstant::parse("2026-10-23T00:00:00Z").ok()
    }
}
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn fixture() -> (Observation, Arc<ManualClock>, Capture) {
    let clock = Arc::new(ManualClock(AtomicU64::new(0)));
    let capture = Capture::default();
    (
        Observation::with_writer(capture.clone(), clock.clone()).unwrap(),
        clock,
        capture,
    )
}
fn records(observation: &Observation, capture: &Capture) -> Vec<Value> {
    observation.flush();
    capture
        .0
        .lock()
        .unwrap()
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

/// Claim: Injected entry and terminal instants include a wait and a nested child's interval in the parent, while each operation retains its own bytes and explicit resource accuracy.
/// ´claim:cli:metering-preserves-inclusive-time-and-owned-work´
/// ´test:unit:inclusive-metering´
#[test]
fn inclusive_metering() {
    let (observation, clock, capture) = fixture();
    let mut parent = observation.operation(OperationKind::Command, json!({"input":"public"}));
    parent.work_bytes(7);
    parent.resources(12, 12, Accuracy::Exact);
    clock.0.store(100, Ordering::Relaxed);
    let mut child = parent.child(OperationKind::Child, json!({"argv":["child"]}));
    child.work_bytes(3);
    child.resources(5, 8, Accuracy::Estimated);
    child.resources(2, 10, Accuracy::Exact);
    clock.0.store(350, Ordering::Relaxed);
    child.finish(Outcome::Refusal, json!({"reason":"fixture"}));
    parent.resources(2, 20, Accuracy::Exact);
    clock.0.store(500, Ordering::Relaxed);
    parent.finish(Outcome::Success, json!("done"));
    let rows = records(&observation, &capture);
    let completed: Vec<_> = rows.iter().filter(|r| r["event_kind"] == "completion").collect();
    assert_eq!(completed[0]["detail"]["duration_seconds"], 0.25);
    assert_eq!(completed[1]["detail"]["duration_seconds"], 0.5);
    assert_eq!(completed[0]["parent_id"], completed[1]["operation_id"]);
    assert_eq!(completed[0]["detail"]["work"]["value"], 3);
    assert_eq!(completed[1]["detail"]["work"]["value"], 7);
    assert_eq!(completed[1]["detail"]["resources"]["high_water"]["value"], 12);
    assert_eq!(completed[1]["detail"]["resources"]["current"]["value"], 2);
    assert_eq!(completed[1]["detail"]["resources"]["cumulative"]["value"], 20);
    assert_eq!(completed[0]["detail"]["resources"]["current"]["accuracy"], "exact");
    assert_eq!(completed[0]["detail"]["resources"]["high_water"]["accuracy"], "estimated");
    assert!(completed[0]["detail"]["resources"]["cpu_seconds"]["value"].is_null());
    let mut overflow = observation.operation(OperationKind::Command, Value::Null);
    overflow.work_bytes(u64::MAX);
    overflow.work_bytes(1);
    overflow.finish(Outcome::Success, Value::Null);
    let rows = records(&observation, &capture);
    let detail = &rows.last().unwrap()["detail"];
    assert!(detail["work"]["value"].is_null());
    assert_eq!(detail["work"]["accuracy"], "unavailable; counter overflow");
    assert_eq!(detail["outcome"], "success");
}

/// Claim: Explicit error and cancellation, ordinary drop and unwinding produce four distinct terminal classes, with unavailable resources remaining null and every active gauge returning to zero.
/// ´claim:cli:terminal-accounting-distinguishes-incomplete-work´
/// ´test:unit:terminal-accounting´
#[test]
fn terminal_accounting() {
    let (observation, _, capture) = fixture();
    for outcome in [Outcome::Error, Outcome::Cancelled] {
        observation
            .operation(OperationKind::Command, Value::Null)
            .finish(outcome, Value::Null);
    }
    drop(observation.operation(OperationKind::Command, Value::Null));
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _operation = observation.operation(OperationKind::Command, Value::Null);
        panic!("public panic");
    }));
    assert!(caught.is_err());
    let rows = records(&observation, &capture);
    let completed: Vec<_> = rows.iter().filter(|r| r["event_kind"] == "completion").collect();
    assert_eq!(
        completed
            .iter()
            .map(|r| r["detail"]["outcome"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["error", "cancelled", "incomplete", "unwinding"]
    );
    assert!(
        completed
            .iter()
            .all(|r| r["detail"]["resources"]["current"]["value"].is_null())
    );
    let snapshot = observation.recorder.snapshot();
    assert!(
        snapshot["instruments"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["name"].as_str().unwrap().ends_with("active_operations"))
            .all(|r| r["gauge"] == 0.0)
    );
}

/// Claim: A backward injected clock yields unavailable duration rather than a negative or invented elapsed value, without changing the explicit success outcome.
/// ´claim:cli:invalid-clock-cannot-change-outcome´
/// ´test:unit:backward-clock´
#[test]
fn backward_clock() {
    let (observation, clock, capture) = fixture();
    clock.0.store(100, Ordering::Relaxed);
    let operation = observation.operation(OperationKind::Command, Value::Null);
    clock.0.store(0, Ordering::Relaxed);
    operation.finish(Outcome::Success, Value::Null);
    let rows = records(&observation, &capture);
    let detail = &rows.last().unwrap()["detail"];
    assert!(detail["duration_seconds"].is_null());
    assert_eq!(detail["outcome"], "success");
}

/// Claim: UTC input must name Z and a valid calendar date; naive, offset, malformed fraction and impossible dates refuse by their own input class.
/// ´claim:cli:utc-input-never-infers-a-zone´
/// ´test:unit:explicit-utc´
#[test]
fn explicit_utc() {
    for valid in ["2024-02-29T23:59:59Z", "2026-10-23T00:00:00.123Z"] {
        assert!(UtcInstant::parse(valid).is_ok());
    }
    assert_eq!(UtcInstant::parse("2026-10-23T00:00:00").unwrap_err(), "naive instant refused");
    assert_eq!(
        UtcInstant::parse("2026-10-23T00:00:00+00:00").unwrap_err(),
        "offset instant refused"
    );
    for invalid in [
        "2025-02-29T00:00:00Z",
        "2026-10-23T24:00:00Z",
        "2026-10-23T00:00:00.Z",
        "2026-10-23T00:00:00.aZ",
    ] {
        assert_eq!(UtcInstant::parse(invalid).unwrap_err(), "malformed UTC instant");
    }
}

/// Claim: Secret string and byte carriers display only their finite role and marker through Debug, including a nested error chain; the sentinel never becomes ordinary error text.
/// ´claim:cli:secret-carriers-protect-nested-errors´
/// ´test:unit:secret-representations´
#[test]
fn secret_representations() {
    #[derive(Debug, thiserror::Error)]
    #[error("connection failed: {private:?}")]
    struct Inner {
        private: PrivateString,
    }
    #[derive(Debug, thiserror::Error)]
    #[error("request failed: {0}")]
    struct Outer(#[source] Inner);
    let secret = PrivateString::new(SecretRole::Authentication, SecretString::from("private-sentinel"));
    let bytes = PrivateBytes::new(SecretRole::SigningKey, SecretBox::new(Box::new(*b"private-sentinel")));
    assert_eq!(
        format!("{secret:?}"),
        "PrivateString { role: Authentication, value: [REDACTED] }"
    );
    assert_eq!(format!("{bytes:?}"), "PrivateBytes { role: SigningKey, value: [REDACTED] }");
    let error = Outer(Inner { private: secret });
    let observed = format!("{error}: {error:?}");
    assert!(!observed.contains("private-sentinel"));
    assert!(observed.contains("Authentication"));
    assert!(observed.contains("[REDACTED]"));
    assert!(format!("{:?}", bytes.secret()).contains("REDACTED"));
    let (observation, _, capture) = fixture();
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone()));
    tracing::subscriber::with_default(subscriber, || tracing::error!(error = ?error, "nested private field"));
    let emitted = serde_json::to_string(&records(&observation, &capture)).unwrap();
    assert!(!emitted.contains("private-sentinel"));
    assert!(emitted.contains("Authentication"));
    assert!(emitted.contains("[REDACTED]"));
}

/// Claim: Unknown metric names, arbitrary attributes and wrong instrument kinds cannot allocate series; a declared counter is shared by handles and the snapshot and loss is explicit.
/// ´claim:cli:metric-series-are-declared-and-bounded´
/// ´test:unit:metric-registry´
#[test]
fn metric_registry() {
    let recorder = JsonRecorder::new();
    metrics::with_local_recorder(&recorder, || {
        metrics::counter!(format!("{}__work_bytes", STEMS[0])).increment(7);
        metrics::counter!("unknown").increment(9);
        metrics::counter!(format!("{}__work_bytes",STEMS[0]),"request"=>"unbounded").increment(11);
        metrics::gauge!(format!("{}__work_bytes", STEMS[0])).set(12.0);
    });
    let snapshot = recorder.snapshot();
    let rows = snapshot["instruments"].as_array().unwrap();
    assert_eq!(rows.len(), 36);
    assert_eq!(snapshot["lost_updates"], 3);
    assert_eq!(
        rows.iter()
            .find(|r| r["name"] == format!("{}__work_bytes", STEMS[0]))
            .unwrap()["counter"],
        7
    );
}

/// Claim: Trace filtering removes delivered events but cannot remove operation completions or their work; admitted trace events retain full public fields and nested span data.
/// ´claim:cli:accounting-survives-trace-filtering´
/// ´test:unit:filtered-accounting´
#[test]
fn filtered_accounting() {
    let (observation, _, capture) = fixture();
    let subscriber = tracing_subscriber::registry()
        .with(AccountingLayer(observation.clone()).with_filter(tracing_subscriber::filter::LevelFilter::OFF));
    tracing::subscriber::with_default(subscriber, || {
        let mut operation = observation.operation(OperationKind::Command, json!({"argument":"public-token-value"}));
        tracing::info!(payload = "public-token-value", "filtered");
        operation.work_bytes(5);
        operation.finish(Outcome::Success, Value::Null);
    });
    let rows = records(&observation, &capture);
    assert!(!rows.iter().any(|r| r["kind"] == "trace"));
    assert_eq!(rows.last().unwrap()["detail"]["work"]["value"], 5);
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone()));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("rule:observe:metering", public = "whole value");
        let _entered = span.enter();
        tracing::info!(payload = "public-token-value", "delivered");
    });
    let rows = records(&observation, &capture);
    let trace = rows.iter().find(|r| r["kind"] == "trace").unwrap();
    assert_eq!(trace["fields"]["payload"], "public-token-value");
    assert_eq!(trace["spans"][0]["fields"]["public"], "whole value");
}

/// Claim: Oversized records, full queues and disconnected sinks increment loss while terminal metrics still account success and zero active work; `try_send` never waits for queue capacity.
/// ´claim:cli:observation-loss-is-nonbinding´
/// ´test:unit:bounded-loss´
#[test]
fn bounded_loss() {
    let (observation, _, _) = fixture();
    observation.emit(json!({"payload":"x".repeat(RECORD_LIMIT)}));
    assert_eq!(observation.lost.load(Ordering::Relaxed), 1);
    let (sender, receiver) = mpsc::sync_channel(1);
    let mut bounded = observation.clone();
    bounded.sender = sender;
    bounded.emit(json!({"one":1}));
    bounded.emit(json!({"two":2}));
    assert_eq!(bounded.lost.load(Ordering::Relaxed), 2);
    drop(receiver);
    bounded.emit(json!({"three":3}));
    assert_eq!(bounded.lost.load(Ordering::Relaxed), 3);
    bounded
        .operation(OperationKind::Command, Value::Null)
        .finish(Outcome::Success, json!(0));
    assert_eq!(bounded.lost.load(Ordering::Relaxed), 5);
    let snapshot = bounded.recorder.snapshot();
    let instruments = snapshot["instruments"].as_array().unwrap();
    assert_eq!(
        instruments
            .iter()
            .find(|r| r["name"] == format!("{}__completed_operations", STEMS[0]) && r["outcome"] == "success")
            .unwrap()["counter"],
        1
    );
    assert_eq!(
        instruments
            .iter()
            .find(|r| r["name"] == format!("{}__active_operations", STEMS[0]))
            .unwrap()["gauge"],
        0.0
    );
}
