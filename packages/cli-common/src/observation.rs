//! Application-owned observation under (´[ROOT-rule:observe:metering]´),
//! (´[ROOT-dec:observe:sinks]´) and (´[ROOT-inv:observe:noninterference]´).
//! Delivered fields follow (´[ROOT-rule:observe:privacy]´); dependency-origin
//! envelopes identify (´[ROOT-rule:observe:spans]´) without claiming their work.
//! Explicit operation contexts account independently of filtered tracing spans.

use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Map, Value, json};
use tracing::{
    Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::{Layer, layer::Context, prelude::*, registry::LookupSpan};

use crate::observation_metrics::{JsonRecorder, STEMS, estimate};

mod content;

const RECORD_LIMIT: usize = 1024 * 1024;
const CAPTURE_LIMIT: usize = 64 * 1024 * 1024;
const QUEUE_RECORDS: usize = 64;
static GLOBAL: OnceLock<Observation> = OnceLock::new();

/// Preserve public bytes as tagged UTF-8 or base64 for observation.
/// Justified: Representation runs inside the labelled observation delivery operation and must not recursively observe itself.
#[must_use]
pub fn public_bytes(value: &[u8]) -> Value {
    content::bytes(value)
}

thread_local! { static OBSERVING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
struct Observing;
impl Observing {
    fn enter(lost: &AtomicU64) -> Option<Self> {
        if OBSERVING.replace(true) {
            lost.fetch_add(1, Ordering::Relaxed);
            None
        } else {
            Some(Self)
        }
    }
}
impl Drop for Observing {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn drop(&mut self) {
        OBSERVING.set(false);
    }
}

/// Checked synchronous boundary for capabilities without a Debug contract.
/// Public data is supplied in full; opaque capabilities name their unavailable
/// representation rather than adding a new bound to a binding API.
#[must_use]
pub fn scope(owner: &'static str, label: &'static str, item: &'static str, arguments: &dyn fmt::Debug) -> Scope {
    Scope(tracing::info_span!("rule:observe:spans", execution_owner=owner, claim_owner="ROOT", claim_label=label, source_item=item, arguments=?arguments).entered())
}

/// Synchronous span lifetime; never retain this guard across suspension.
#[derive(Debug)]
pub struct Scope(tracing::span::EnteredSpan);
impl Scope {
    /// Record the full public result before the synchronous boundary closes.
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub fn finish(self, result: &dyn fmt::Debug) {
        tracing::info!("return"=?result);
        drop(self.0);
    }

    /// Record a bounded terminal class with the full available public result.
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub fn finish_with(self, outcome: Outcome, result: &dyn fmt::Debug) {
        tracing::info!(outcome=outcome.name(),"return"=?result);
        drop(self.0);
    }
}

/// A validated explicit-UTC instant; no local-zone inference is performed.
#[derive(Clone, Debug, Serialize)]
pub struct UtcInstant(String);

impl UtcInstant {
    /// Parse a calendar-valid UTC instant with a required Z designator.
    ///
    /// # Errors
    /// Names offset, naive or malformed input; never assigns a zone.
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if !value.ends_with('Z') {
            return Err(if value.get(19..).is_some_and(|s| s.contains('+') || s.contains('-')) {
                "offset instant refused"
            } else {
                "naive instant refused"
            });
        }
        let b = value.as_bytes();
        if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
            return Err("malformed UTC instant");
        }
        let number = |start, end| {
            value
                .get(start..end)
                .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or("malformed UTC instant")
        };
        let year = number(0, 4)?;
        let month = number(5, 7)?;
        let day = number(8, 10)?;
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if leap {
                    29
                } else {
                    28
                }
            }
            _ => 0,
        };
        if day == 0 || day > days || number(11, 13)? > 23 || number(14, 16)? > 59 || number(17, 19)? > 59 {
            return Err("malformed UTC instant");
        }
        if b.len() != 20 && (b[19] != b'.' || b.len() < 22 || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit)) {
            return Err("malformed UTC instant");
        }
        Ok(Self(value.into()))
    }
}

trait Clock: Send + Sync {
    fn elapsed(&self) -> Duration;
    fn utc(&self) -> Option<UtcInstant>;
}

struct SystemClock(Instant);
impl Clock for SystemClock {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn utc(&self) -> Option<UtcInstant> {
        let mut text = String::new();
        tracing_subscriber::fmt::time::SystemTime
            .format_time(&mut tracing_subscriber::fmt::format::Writer::new(&mut text))
            .ok()?;
        UtcInstant::parse(&text).ok()
    }
}

enum Message {
    Record(Vec<u8>),
    Wake,
}

struct Limited(Vec<u8>);
impl fmt::Write for Limited {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.write_all(value.as_bytes()).map_err(|_| fmt::Error)
    }
}
impl Write for Limited {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > CAPTURE_LIMIT {
            return Err(io::Error::other("observation record capacity"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Cloneable operation context; no initialization occurs in library operations.
#[derive(Clone)]
pub struct Observation {
    sender: SyncSender<Message>,
    summary_sender: SyncSender<Vec<u8>>,
    flush_sender: SyncSender<SyncSender<()>>,
    diagnostic_sender: SyncSender<Vec<u8>>,
    queued_bytes: Arc<AtomicU64>,
    lost: Arc<AtomicU64>,
    delivered: Arc<AtomicU64>,
    full_trace: bool,
    clock: Arc<dyn Clock>,
    recorder: JsonRecorder,
    next_id: Arc<AtomicU64>,
    bridge: Option<Arc<crate::observation_export::Bridge>>,
}

impl Observation {
    fn with_writer(writer: impl Write + Send + 'static, clock: Arc<dyn Clock>) -> io::Result<Self> {
        Self::with_writer_bridge(writer, clock, None)
    }

    fn with_writer_bridge(
        writer: impl Write + Send + 'static,
        clock: Arc<dyn Clock>,
        bridge: Option<Arc<crate::observation_export::Bridge>>,
    ) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_RECORDS);
        let (summary_sender, summary_receiver) = mpsc::sync_channel::<Vec<u8>>(2);
        let (flush_sender, flush_receiver) = mpsc::sync_channel::<SyncSender<()>>(1);
        let (diagnostic_sender, diagnostic_receiver) = mpsc::sync_channel::<Vec<u8>>(8);
        let lost = Arc::new(AtomicU64::new(0));
        let worker_lost = lost.clone();
        let delivered = Arc::new(AtomicU64::new(0));
        let worker_delivered = delivered.clone();
        let queued_bytes = Arc::new(AtomicU64::new(0));
        let worker_queued = queued_bytes.clone();
        let artifact_root = content::root();
        let worker_bridge = bridge.clone();
        std::thread::Builder::new().name("observation-json".into()).spawn(move || {
            let mut writer = writer;
            let mut deliver = |bytes: &[u8]| {
                let result = (|| -> io::Result<()> {
                    let mut record: Value = serde_json::from_slice(bytes)?;
                    content::compact(&mut record, &artifact_root)?;
                    let mut compact = serde_json::to_vec(&record)?;
                    compact.push(b'\n');
                    if compact.len() > RECORD_LIMIT {
                        return Err(io::Error::other("observation delivery capacity"));
                    }
                    if let Some(bridge) = &worker_bridge {
                        bridge.record(&compact);
                    }
                    writer.write_all(&compact)?;
                    writer.flush()
                })();
                if result.is_err() {
                    worker_lost.fetch_add(1, Ordering::Relaxed);
                } else {
                    worker_delivered.fetch_add(1, Ordering::Relaxed);
                }
            };
            while let Ok(first) = receiver.recv() {
                for message in std::iter::once(first).chain(receiver.try_iter().take(QUEUE_RECORDS)) {
                    for diagnostic in diagnostic_receiver.try_iter().take(8) {
                        deliver(&diagnostic);
                    }
                    for summary in summary_receiver.try_iter().take(2) {
                        deliver(&summary);
                    }
                    match message {
                        Message::Record(bytes) => {
                            let charged = bytes.len() as u64;
                            deliver(&bytes);
                            worker_queued.fetch_sub(charged, Ordering::Relaxed);
                        }
                        Message::Wake => {}
                    }
                }
                for done in flush_receiver.try_iter().take(1) {
                    for diagnostic in diagnostic_receiver.try_iter().take(8) {
                        deliver(&diagnostic);
                    }
                    for summary in summary_receiver.try_iter().take(2) {
                        deliver(&summary);
                    }
                    let _ignored = done.try_send(());
                }
            }
        })?;
        Ok(Self {
            sender,
            summary_sender,
            flush_sender,
            diagnostic_sender,
            queued_bytes,
            lost,
            delivered,
            full_trace: false,
            clock,
            recorder: bridge
                .as_ref()
                .map_or_else(JsonRecorder::new, |b| JsonRecorder::with_meter(Some(&b.meter()))),
            next_id: Arc::new(AtomicU64::new(1)),
            bridge,
        })
    }

    /// Borrow the context installed by the executable, if enabled.
    #[must_use]
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub fn current() -> Option<Self> {
        GLOBAL.get().cloned()
    }

    fn emit(&self, mut record: Value) {
        record["process_id"] = json!(std::process::id());
        record["timestamp"] = json!(self.clock.utc());
        record["timestamp_accuracy"] = json!(if record["timestamp"].is_null() {
            "unavailable"
        } else {
            "wall_clock"
        });
        record["lost_records"] = json!(self.lost.load(Ordering::Relaxed));
        let mut bytes = Limited(Vec::new());
        if serde_json::to_writer(&mut bytes, &record).is_err() || bytes.write_all(b"\n").is_err() {
            self.lost.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let reserved = if record["kind"] == "metric_summary" || record["kind"] == "export_summary" {
            Some(&self.summary_sender)
        } else if record["level"] == "ERROR" || record["level"] == "WARN" {
            Some(&self.diagnostic_sender)
        } else {
            None
        };
        if let Some(sender) = reserved {
            if bytes.0.len() > RECORD_LIMIT || sender.try_send(bytes.0).is_err() {
                self.lost.fetch_add(1, Ordering::Relaxed);
            } else {
                let _wake = self.sender.try_send(Message::Wake);
            }
            return;
        }
        let charged = bytes.0.len() as u64;
        if self
            .queued_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(charged).filter(|total| *total <= CAPTURE_LIMIT as u64)
            })
            .is_err()
        {
            self.lost.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.sender.try_send(Message::Record(bytes.0)).is_err() {
            self.queued_bytes.fetch_sub(charged, Ordering::Relaxed);
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn flush(&self) {
        let (done, wait) = mpsc::sync_channel(1);
        if self.flush_sender.try_send(done).is_err() {
            self.lost.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let _wake = self.sender.try_send(Message::Wake);
        if wait.recv_timeout(Duration::from_millis(100)).is_err() {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Start a declared operation; arguments must already preserve secret typing.
    #[must_use]
    pub fn operation(&self, kind: OperationKind, arguments: Value) -> Operation {
        self.operation_with_parent(kind, arguments, None)
    }

    fn operation_with_parent(&self, kind: OperationKind, arguments: Value, parent: Option<u64>) -> Operation {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let operation = Operation {
            observation: self.clone(),
            kind,
            id,
            parent,
            started: self.clock.elapsed(),
            work: 0,
            work_observed: false,
            work_overflow: false,
            current: Resource::unavailable(),
            high_water: Resource::unavailable(),
            cumulative: Resource::unavailable(),
            finished: false,
        };
        metrics::with_local_recorder(&self.recorder, || {
            metrics::counter!(format!("{}__started_operations", kind.stem())).increment(1);
            metrics::counter!(format!("{}__work_operations", kind.stem())).increment(1);
            metrics::gauge!(format!("{}__active_operations", kind.stem())).increment(1.0);
        });
        let mut detail = Map::new();
        detail.insert("arguments".into(), arguments);
        operation.record("start", Value::Object(detail));
        operation
    }

    /// Emit a bounded snapshot from the same recorder that owns API instruments.
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub fn summarize(&self) {
        if let Some(bridge) = &self.bridge {
            bridge.flush();
            let failures = bridge.failures.try_lock().ok().map(|values| values.clone());
            self.emit(json!({"kind":"export_summary","claim_owner":"ROOT","claim_label":"proposal:observe:export","execution_owner":"CLICOMMON","lost_exports":bridge.lost.load(Ordering::Relaxed),"failures":failures}));
        }
        self.emit(
            json!({"kind":"metric_summary","claim_owner":"ROOT","claim_label":"conv:observe:metrics",
            "execution_owner":"CLICOMMON","metrics":self.recorder.snapshot()}),
        );
    }
}

/// The finite core operation registry; later instrumentation extends this set.
#[derive(Clone, Copy, Debug)]
pub enum OperationKind {
    /// Shared command work.
    Command,
    /// Public child-process execution and byte relay.
    Child,
    /// Executable-owned subscriber/recorder installation.
    Bootstrap,
    /// Document projection, rendering and checks.
    Document,
    /// Interchange coding, theory evaluation and acceptance.
    Interchange,
    /// Shared CLI public operation.
    PublicCli,
    /// Execution wrapper public operation.
    PublicExec,
}
impl OperationKind {
    const fn stem(self) -> &'static str {
        match self {
            Self::Command => STEMS[0],
            Self::Child => STEMS[1],
            Self::Bootstrap => STEMS[2],
            Self::Document => STEMS[3],
            Self::Interchange => STEMS[4],
            Self::PublicCli => STEMS[5],
            Self::PublicExec => STEMS[6],
        }
    }
    const fn label(self) -> &'static str {
        match self {
            Self::Command => "rule:observe:metering",
            Self::Child => "rule:observe:privacy",
            Self::Bootstrap => "dec:observe:sinks",
            Self::Document | Self::Interchange | Self::PublicCli | Self::PublicExec => "rule:observe:spans",
        }
    }
    const fn owner(self) -> &'static str {
        match self {
            Self::Child | Self::PublicExec => "EXECWRAP",
            Self::Document => "DOCUMENTS",
            Self::Interchange => "INTERCHANGE",
            _ => "CLICOMMON",
        }
    }
}

/// Completion classes are finite metric attributes, never error text.
#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    /// Normal completion.
    Success,
    /// Declared refusal.
    Refusal,
    /// Operational error.
    Error,
    /// Explicit cancellation.
    Cancelled,
}
impl Outcome {
    const fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Refusal => "refusal",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Accuracy applies to each resource independently.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Accuracy {
    /// Independently counted within the operation.
    Exact,
    /// Estimated by the caller, with that limitation retained.
    Estimated,
    /// No measurement exists.
    Unavailable,
}

#[derive(Clone, Copy, Serialize)]
struct Resource {
    value: Option<u64>,
    accuracy: Accuracy,
    unit: &'static str,
}
impl Resource {
    const fn unavailable() -> Self {
        Self {
            value: None,
            accuracy: Accuracy::Unavailable,
            unit: "bytes",
        }
    }
}

/// Inclusive elapsed accounting that never supplies values to binding computation.
pub struct Operation {
    observation: Observation,
    kind: OperationKind,
    id: u64,
    parent: Option<u64>,
    started: Duration,
    work: u64,
    work_observed: bool,
    work_overflow: bool,
    current: Resource,
    high_water: Resource,
    cumulative: Resource,
    finished: bool,
}
impl Operation {
    fn record(&self, event: &str, mut detail: Value) {
        if !self.observation.full_trace {
            if !matches!(self.kind, OperationKind::Command) || event != "completion" {
                return;
            }
            if let Some(detail) = detail.as_object_mut() {
                detail.remove("result");
            }
        }
        let mut envelope = json!({"kind":"metering","name":self.kind.label(),"claim_owner":"ROOT","claim_label":self.kind.label(),
            "execution_owner":self.kind.owner(),"operation":format!("{:?}",self.kind),"operation_id":self.id,"parent_id":self.parent,"event_kind":event});
        envelope["detail"] = detail;
        self.observation.emit(envelope);
    }

    /// Start a child with its own work totals; parent elapsed time remains inclusive.
    #[must_use]
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub fn child(&self, kind: OperationKind, arguments: Value) -> Self {
        self.observation.operation_with_parent(kind, arguments, Some(self.id))
    }

    /// Add performed bytes, including retries and refused attempts, exactly once.
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub fn work_bytes(&mut self, bytes: u64) {
        self.work_observed = true;
        if let Some(total) = self.work.checked_add(bytes) {
            self.work = total;
        } else {
            self.work = u64::MAX;
            self.work_overflow = true;
        }
        metrics::with_local_recorder(&self.observation.recorder, || {
            metrics::counter!(format!("{}__work_bytes", self.kind.stem())).increment(bytes);
        });
    }

    /// Record current, high-water and cumulative resource bytes with explicit accuracy.
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub fn resources(&mut self, current: u64, current_accuracy: Accuracy, cumulative: u64, cumulative_accuracy: Accuracy) {
        let accuracy = current_accuracy;
        let previous = self.current.value.unwrap_or(0);
        let measured = if matches!(accuracy, Accuracy::Unavailable) {
            0
        } else {
            current
        };
        if self.current.value.is_some() || !matches!(accuracy, Accuracy::Unavailable) {
            metrics::with_local_recorder(&self.observation.recorder, || {
                let gauge = metrics::gauge!(format!("{}__resource_current_bytes", self.kind.stem()));
                gauge.increment(estimate(measured) - estimate(previous));
            });
        }
        if matches!(accuracy, Accuracy::Unavailable) {
            self.current = Resource::unavailable();
        } else {
            self.current = Resource {
                value: Some(current),
                accuracy,
                unit: "bytes",
            };
            self.high_water = Resource {
                value: Some(current.max(self.high_water.value.unwrap_or(0))),
                accuracy: if matches!(self.high_water.accuracy, Accuracy::Estimated) {
                    Accuracy::Estimated
                } else {
                    accuracy
                },
                unit: "bytes",
            };
        }
        self.cumulative = Resource {
            value: (!matches!(cumulative_accuracy, Accuracy::Unavailable)).then_some(cumulative),
            accuracy: cumulative_accuracy,
            unit: "bytes",
        };
    }

    /// Record full public progress content without affecting the relayed bytes.
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub fn progress(&self, content: Value) {
        self.record("progress", content);
    }

    /// Complete once with a bounded outcome and full public result or error.
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub fn finish(mut self, outcome: Outcome, result: Value) {
        self.complete(outcome.name(), result);
    }

    fn complete(&mut self, outcome: &'static str, result: Value) {
        let elapsed = self
            .observation
            .clock
            .elapsed()
            .checked_sub(self.started)
            .map(|d| d.as_secs_f64());
        let mut detail = json!({"duration_seconds":elapsed,"duration_accuracy":if elapsed.is_some(){"monotonic"}else{"unavailable"},
            "outcome":outcome,"work":{"value":if self.work_overflow {None}else{Some(if self.work_observed {self.work}else{1})},"accuracy":if self.work_overflow {"unavailable; counter overflow"}else{"exact"},"unit":if self.work_observed {"bytes"}else{"operations"},"aggregation":if self.work_observed {"own byte increments only"}else{"one invoked operation; child invocations separate"}},
            "resources":{"current":self.current,"high_water":self.high_water,"cumulative":self.cumulative,"cpu_seconds":{"value":null,"accuracy":"unavailable","unit":"seconds"},"allocation_bytes":{"value":null,"accuracy":"unavailable","unit":"bytes"}},
            "duration_aggregation":"inclusive; do not sum parent and child"});
        detail["result"] = result;
        self.record("completion", detail);
        metrics::with_local_recorder(&self.observation.recorder, || {
            metrics::counter!(format!("{}__completed_operations",self.kind.stem()),"outcome"=>outcome).increment(1);
            metrics::gauge!(format!("{}__active_operations", self.kind.stem())).decrement(1.0);
            metrics::histogram!(format!("{}__workload_operations", self.kind.stem())).record(1.0);
            if let Some(current) = self.current.value {
                metrics::gauge!(format!("{}__resource_current_bytes", self.kind.stem())).decrement(estimate(current));
            }
            if let Some(seconds) = elapsed {
                metrics::histogram!(format!("{}__elapsed_seconds", self.kind.stem())).record(seconds);
            }
            if self.work_observed && !self.work_overflow {
                metrics::histogram!(format!("{}__workload_bytes", self.kind.stem())).record(estimate(self.work));
            }
        });
        self.finished = true;
    }
}
impl Drop for Operation {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn drop(&mut self) {
        if !self.finished {
            self.complete(if std::thread::panicking() { "unwinding" } else { "incomplete" }, Value::Null);
        }
    }
}

#[derive(Default)]
struct Fields(Map<String, Value>, usize, bool);
impl Fields {
    fn insert(&mut self, field: &Field, value: Value, bytes: usize) {
        self.1 = self.1.saturating_add(field.name().len()).saturating_add(bytes);
        if self.1 > CAPTURE_LIMIT {
            self.2 = true;
        } else {
            self.0.insert(field.name().into(), value);
        }
    }
}
impl Visit for Fields {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let mut text = Limited(Vec::new());
        if fmt::write(&mut text, format_args!("{value:?}")).is_err() {
            self.2 = true;
            return;
        }
        let length = text.0.len();
        if let Ok(text) = String::from_utf8(text.0) {
            self.insert(field, content::structured(&text), length);
        } else {
            self.2 = true;
        }
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn record_str(&mut self, field: &Field, value: &str) {
        if value.len().saturating_add(self.1) > CAPTURE_LIMIT {
            self.2 = true;
        } else {
            self.insert(field, json!(value), value.len());
        }
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, json!(value), 20);
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, json!(value), 21);
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, json!(value), 5);
    }
}
// Identity and outcome only: default emission never formats public payloads.
#[derive(Default)]
struct SummaryFields(Fields);
impl Visit for SummaryFields {
    /// Justified: The delivery visitor selects accounting identity without recursively observing itself.
    fn record_debug(&mut self, _field: &Field, _value: &dyn fmt::Debug) {}
    /// Justified: The delivery visitor selects accounting identity without recursively observing itself.
    fn record_str(&mut self, field: &Field, value: &str) {
        if matches!(field.name(), "execution_owner" | "source_item" | "outcome") {
            self.0.record_str(field, value);
        }
    }
}
struct SpanAccount {
    fields: Fields,
    started: Duration,
    operation: Option<Operation>,
    result: Option<Value>,
    outcome: Option<&'static str>,
}
struct AccountingLayer(Observation, Option<tracing_subscriber::EnvFilter>);
impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for AccountingLayer {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, context: Context<'_, S>) {
        let Some(_observing) = Observing::enter(&self.0.lost) else {
            return;
        };
        if let Some(span) = context.span(id) {
            let mut fields = Fields::default();
            if self.0.full_trace {
                attributes.record(&mut fields);
            } else {
                let mut summary = SummaryFields::default();
                attributes.record(&mut summary);
                fields = summary.0;
            }
            if fields.2 {
                self.0.lost.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let command = matches!(
                fields.0.get("source_item").and_then(Value::as_str),
                Some(
                    "run_stdout_json_command"
                        | "run_no_stdout_command"
                        | "run_no_stdout_command_async"
                        | "run_check_command"
                        | "execute"
                )
            );
            let kind = if command {
                Some(OperationKind::Command)
            } else if !self.0.full_trace {
                return;
            } else {
                match fields.0.get("execution_owner").and_then(Value::as_str) {
                    Some("DOCUMENTS") => Some(OperationKind::Document),
                    Some("INTERCHANGE") => Some(OperationKind::Interchange),
                    Some("CLICOMMON") => Some(OperationKind::PublicCli),
                    Some("EXECWRAP") => Some(OperationKind::PublicExec),
                    _ => None,
                }
            };
            let parent = span.parent().and_then(|parent| {
                parent
                    .extensions()
                    .get::<SpanAccount>()
                    .and_then(|account| account.operation.as_ref().map(|operation| operation.id))
            });
            let operation = kind.map(|kind| self.0.operation_with_parent(kind, json!(fields.0), parent));
            span.extensions_mut().insert(SpanAccount {
                fields,
                started: self.0.clock.elapsed(),
                operation,
                result: None,
                outcome: None,
            });
        }
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn on_record(&self, id: &Id, values: &Record<'_>, context: Context<'_, S>) {
        let Some(_observing) = Observing::enter(&self.0.lost) else {
            return;
        };
        if let Some(span) = context.span(id)
            && let Some(account) = span.extensions_mut().get_mut::<SpanAccount>()
            && self.0.full_trace
        {
            values.record(&mut account.fields);
        }
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn on_event(&self, event: &tracing::Event<'_>, context: Context<'_, S>) {
        let Some(_observing) = Observing::enter(&self.0.lost) else {
            return;
        };
        let mut fields = Fields::default();
        let diagnostic = *event.metadata().level() <= tracing::Level::WARN;
        if self.0.full_trace || diagnostic {
            event.record(&mut fields);
        } else {
            let mut summary = SummaryFields::default();
            event.record(&mut summary);
            fields = summary.0;
        }
        if let Some(span) = context.event_span(event)
            && let Some(account) = span.extensions_mut().get_mut::<SpanAccount>()
        {
            if let Some(value) = fields.0.get("return") {
                account.result = Some(value.clone());
            }
            account.outcome = match fields.0.get("outcome").and_then(Value::as_str) {
                Some("success") => Some("success"),
                Some("refusal") => Some("refusal"),
                Some("error") => Some("error"),
                Some("cancelled") => Some("cancelled"),
                _ => account.outcome,
            };
            if let Some(bytes) = fields.0.get("work_bytes").and_then(Value::as_u64)
                && let Some(operation) = &mut account.operation
            {
                operation.work_bytes(bytes);
            }
        }
        if !self.0.full_trace && !diagnostic {
            return;
        }
        if fields.2 {
            self.0.lost.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.1.as_ref().is_some_and(|filter| {
            !<tracing_subscriber::EnvFilter as Layer<S>>::enabled(filter, event.metadata(), context.clone())
        }) {
            return;
        }
        let mut spans = Vec::new();
        if let Some(scope) = context.event_scope(event) {
            for span in scope.from_root() {
                if let Some(account) = span.extensions().get::<SpanAccount>() {
                    if account.fields.2 || spans.len() == 64 {
                        self.0.lost.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    spans.push(json!({"name":span.name(),"fields":account.fields.0}));
                }
            }
        }
        self.0.emit(json!({"kind":"trace","claim_owner":"ROOT","claim_label":"rule:observe:spans","execution_owner":"CLICOMMON",
            "origin":event.metadata().target(),"name":"rule:observe:spans","origin_name":event.metadata().name(),"level":event.metadata().level().as_str(),"fields":fields.0,"spans":spans}));
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn on_close(&self, id: Id, context: Context<'_, S>) {
        let Some(_observing) = Observing::enter(&self.0.lost) else {
            return;
        };
        if let Some(span) = context.span(&id)
            && let Some(account) = span.extensions_mut().remove::<SpanAccount>()
        {
            if let Some(mut operation) = account.operation {
                let outcome = if std::thread::panicking() {
                    "unwinding"
                } else if let Some(outcome) = account.outcome {
                    outcome
                } else if account.result.as_ref().is_some_and(|value| value["constructor"] == "Err") {
                    "error"
                } else if account.result.is_some() {
                    "success"
                } else if account.fields.0.get("asynchronous").and_then(Value::as_bool) == Some(true) {
                    "cancelled"
                } else {
                    "incomplete"
                };
                operation.complete(outcome, account.result.unwrap_or(Value::Null));
            }
            if !self.0.full_trace {
                return;
            }
            if account.fields.2 {
                self.0.lost.fetch_add(1, Ordering::Relaxed);
                return;
            }
            self.0.emit(json!({"kind":"span_envelope","claim_owner":"ROOT","claim_label":"rule:observe:spans","execution_owner":"CLICOMMON",
                "name":"rule:observe:spans","origin_name":span.name(),"fields":account.fields.0,"duration_seconds":self.0.clock.elapsed().checked_sub(account.started).map(|d|d.as_secs_f64()),"outcome":"unobservable; explicit operation completion is authoritative"}));
        }
    }
}

/// Executable-owned lifetime for a bounded final metric snapshot and drain.
pub struct BootstrapGuard(Option<Observation>);
impl Drop for BootstrapGuard {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn drop(&mut self) {
        if let Some(observation) = &self.0 {
            observation.summarize();
            observation.flush();
            observation.emit(json!({"kind":"observation_status","availability":"enabled",
                "level":if observation.full_trace {"trace"} else {"default"},
                "delivered_records":observation.delivered.load(Ordering::Relaxed),
                "count_scope":"records preceding this status; status excluded",
                "claim_owner":"ROOT","claim_label":"dec:observe:sinks","execution_owner":"CLICOMMON"}));
            observation.flush();
        }
    }
}

/// Compose one subscriber/accounting layer and one metrics recorder at executable startup.
/// Disabled observation installs nothing. Library operations never call this function.
///
/// # Errors
/// Refuses an unknown or non-UTF-8 `PN_OBSERVE_LEVEL`, an existing global installation or an unavailable writer thread by name.
/// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
pub fn bootstrap(enabled: bool, debug: bool, default_level: tracing::Level) -> Result<BootstrapGuard, &'static str> {
    bootstrap_inner(enabled, debug, default_level, None, Instant::now())
}

/// Compose the same subscriber and recorder with the bounded SDK export bridge.
/// The executable calls this before spawning threads; environment mutation after
/// startup is outside the admitted configuration. The transport must have passed
/// its secret-boundary review; credentials never enter SDK headers or endpoints.
///
/// # Errors
/// Returns full public initialization errors, or names forbidden environment input.
/// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
pub fn bootstrap_with_export(
    enabled: bool,
    debug: bool,
    default_level: tracing::Level,
    config: crate::observation_export::ExportConfig,
) -> Result<BootstrapGuard, Box<dyn std::error::Error + Send + Sync>> {
    let started = Instant::now();
    let bridge = if enabled {
        Some(Arc::new(crate::observation_export::Bridge::new(config)?))
    } else {
        None
    };
    bootstrap_inner(enabled, debug, default_level, bridge, started).map_err(Into::into)
}

fn emission_level(value: Option<&str>) -> Result<bool, &'static str> {
    match value {
        None | Some("default") => Ok(false),
        Some("trace") => Ok(true),
        Some(_) => Err("PN_OBSERVE_LEVEL must be default or trace"),
    }
}

fn bootstrap_inner(
    enabled: bool,
    _debug: bool,
    _default_level: tracing::Level,
    bridge: Option<Arc<crate::observation_export::Bridge>>,
    started: Instant,
) -> Result<BootstrapGuard, &'static str> {
    let level = match std::env::var("PN_OBSERVE_LEVEL") {
        Ok(value) => emission_level(Some(&value))?,
        Err(std::env::VarError::NotPresent) => emission_level(None)?,
        Err(std::env::VarError::NotUnicode(_)) => return Err("PN_OBSERVE_LEVEL must be UTF-8: default or trace"),
    };
    if !enabled {
        let status = Observation::with_writer(StderrSink, Arc::new(SystemClock(Instant::now())))
            .map_err(|_| "observation status writer unavailable")?;
        status.emit(json!({"kind":"observation_status","name":"dec:observe:sinks","claim_owner":"ROOT",
            "claim_label":"dec:observe:sinks","execution_owner":"CLICOMMON","availability":"disabled","measurements":"unavailable"}));
        status.flush();
        return Ok(BootstrapGuard(None));
    }
    if GLOBAL.get().is_some() {
        return Err("observation already initialized");
    }
    let mut observation = Observation::with_writer_bridge(StderrSink, Arc::new(SystemClock(started)), bridge)
        .map_err(|_| "observation writer unavailable")?;
    observation.full_trace = level;
    // Legacy verbosity arguments do not silently enable payload persistence.
    tracing_subscriber::registry()
        .with(AccountingLayer(observation.clone(), None))
        .try_init()
        .map_err(|_| "subscriber already initialized")?;
    metrics::set_global_recorder(observation.recorder.clone()).map_err(|_| "metrics recorder already initialized")?;
    GLOBAL
        .set(observation.clone())
        .map_err(|_| "observation already initialized")?;
    let mut operation=observation.operation(OperationKind::Bootstrap,json!({"level":if observation.full_trace {"trace"} else {"default"},"queue_records":QUEUE_RECORDS,"record_capacity_bytes":RECORD_LIMIT}));
    operation.started = Duration::ZERO;
    operation.finish(
        Outcome::Success,
        json!({"subscriber":"accounting_layer","metrics_recorder":"json"}),
    );
    Ok(BootstrapGuard(Some(observation)))
}

struct StderrSink;
impl Write for StderrSink {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        crate::LockedStderrWriter::locked_stderr().write_all(bytes)?;
        Ok(bytes.len())
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
