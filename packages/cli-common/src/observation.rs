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

const RECORD_LIMIT: usize = 1024 * 1024;
const QUEUE_RECORDS: usize = 64;
static GLOBAL: OnceLock<Observation> = OnceLock::new();

/// A validated explicit-UTC instant; no local-zone inference is performed.
#[derive(Clone, Debug, Serialize)]
pub struct UtcInstant(String);

impl UtcInstant {
    /// Parse a calendar-valid UTC instant with a required Z designator.
    ///
    /// # Errors
    /// Names offset, naive or malformed input; never assigns a zone.
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
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
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
    Flush(SyncSender<()>),
}

struct Limited(Vec<u8>);
impl fmt::Write for Limited {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.write_all(value.as_bytes()).map_err(|_| fmt::Error)
    }
}
impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > RECORD_LIMIT {
            return Err(io::Error::other("observation record capacity"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Cloneable operation context; no initialization occurs in library operations.
#[derive(Clone)]
pub struct Observation {
    sender: SyncSender<Message>,
    lost: Arc<AtomicU64>,
    clock: Arc<dyn Clock>,
    recorder: JsonRecorder,
    next_id: Arc<AtomicU64>,
}

impl Observation {
    fn with_writer(writer: impl Write + Send + 'static, clock: Arc<dyn Clock>) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_RECORDS);
        let lost = Arc::new(AtomicU64::new(0));
        let worker_lost = lost.clone();
        std::thread::Builder::new().name("observation-json".into()).spawn(move || {
            let mut writer = writer;
            while let Ok(message) = receiver.recv() {
                match message {
                    Message::Record(bytes) => {
                        if writer.write_all(&bytes).and_then(|()| writer.flush()).is_err() {
                            worker_lost.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Message::Flush(done) => {
                        let _ignored = done.try_send(());
                    }
                }
            }
        })?;
        Ok(Self {
            sender,
            lost,
            clock,
            recorder: JsonRecorder::new(),
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Borrow the context installed by the executable, if enabled.
    #[must_use]
    pub fn current() -> Option<Self> {
        GLOBAL.get().cloned()
    }

    fn emit(&self, mut record: Value) {
        record["timestamp"] = json!(self.clock.utc());
        record["timestamp_accuracy"] = json!(if record["timestamp"].is_null() {
            "unavailable"
        } else {
            "wall_clock"
        });
        record["lost_records"] = json!(self.lost.load(Ordering::Relaxed));
        let mut bytes = Limited(Vec::new());
        if serde_json::to_writer(&mut bytes, &record).is_err()
            || bytes.write_all(b"\n").is_err()
            || self.sender.try_send(Message::Record(bytes.0)).is_err()
        {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn flush(&self) {
        let (done, wait) = mpsc::sync_channel(1);
        if self.sender.try_send(Message::Flush(done)).is_err() || wait.recv_timeout(Duration::from_millis(100)).is_err() {
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
            work_overflow: false,
            current: Resource::unavailable(),
            high_water: Resource::unavailable(),
            cumulative: Resource::unavailable(),
            finished: false,
        };
        metrics::with_local_recorder(&self.recorder, || {
            metrics::counter!(format!("{}__started_operations", kind.stem())).increment(1);
            metrics::gauge!(format!("{}__active_operations", kind.stem())).increment(1.0);
        });
        let mut detail = Map::new();
        detail.insert("arguments".into(), arguments);
        operation.record("start", Value::Object(detail));
        operation
    }

    /// Emit a bounded snapshot from the same recorder that owns API instruments.
    pub fn summarize(&self) {
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
}
impl OperationKind {
    const fn stem(self) -> &'static str {
        match self {
            Self::Command => STEMS[0],
            Self::Child => STEMS[1],
            Self::Bootstrap => STEMS[2],
        }
    }
    const fn label(self) -> &'static str {
        match self {
            Self::Command => "rule:observe:metering",
            Self::Child => "rule:observe:privacy",
            Self::Bootstrap => "dec:observe:sinks",
        }
    }
    const fn owner(self) -> &'static str {
        match self {
            Self::Child => "EXECWRAP",
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
    work_overflow: bool,
    current: Resource,
    high_water: Resource,
    cumulative: Resource,
    finished: bool,
}
impl Operation {
    fn record(&self, event: &str, detail: Value) {
        let mut envelope = json!({"kind":"metering","name":self.kind.label(),"claim_owner":"ROOT","claim_label":self.kind.label(),
            "execution_owner":self.kind.owner(),"operation":format!("{:?}",self.kind),"operation_id":self.id,"parent_id":self.parent,"event_kind":event});
        envelope["detail"] = detail;
        self.observation.emit(envelope);
    }

    /// Start a child with its own work totals; parent elapsed time remains inclusive.
    #[must_use]
    pub fn child(&self, kind: OperationKind, arguments: Value) -> Self {
        self.observation.operation_with_parent(kind, arguments, Some(self.id))
    }

    /// Add performed bytes, including retries and refused attempts, exactly once.
    pub fn work_bytes(&mut self, bytes: u64) {
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
    pub fn resources(&mut self, current: u64, cumulative: u64, accuracy: Accuracy) {
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
            self.high_water = Resource::unavailable();
            self.cumulative = Resource::unavailable();
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
            self.cumulative = Resource {
                value: Some(cumulative),
                accuracy,
                unit: "bytes",
            };
        }
    }

    /// Record full public progress content without affecting the relayed bytes.
    pub fn progress(&self, content: Value) {
        self.record("progress", content);
    }

    /// Complete once with a bounded outcome and full public result or error.
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
            "outcome":outcome,"work":{"value":if self.work_overflow {None}else{Some(self.work)},"accuracy":if self.work_overflow {"unavailable; counter overflow"}else{"exact"},"unit":"bytes","aggregation":"own increments only"},
            "resources":{"current":self.current,"high_water":self.high_water,"cumulative":self.cumulative,"cpu_seconds":{"value":null,"accuracy":"unavailable","unit":"seconds"},"allocation_bytes":{"value":null,"accuracy":"unavailable","unit":"bytes"}},
            "duration_aggregation":"inclusive; do not sum parent and child"});
        detail["result"] = result;
        self.record("completion", detail);
        metrics::with_local_recorder(&self.observation.recorder, || {
            metrics::counter!(format!("{}__completed_operations",self.kind.stem()),"outcome"=>outcome).increment(1);
            metrics::gauge!(format!("{}__active_operations", self.kind.stem())).decrement(1.0);
            if let Some(current) = self.current.value {
                metrics::gauge!(format!("{}__resource_current_bytes", self.kind.stem())).decrement(estimate(current));
            }
            if let Some(seconds) = elapsed {
                metrics::histogram!(format!("{}__elapsed_seconds", self.kind.stem())).record(seconds);
            }
            if !self.work_overflow {
                metrics::histogram!(format!("{}__workload_bytes", self.kind.stem())).record(estimate(self.work));
            }
        });
        self.finished = true;
    }
}
impl Drop for Operation {
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
        if self.1 > RECORD_LIMIT {
            self.2 = true;
        } else {
            self.0.insert(field.name().into(), value);
        }
    }
}
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let mut text = Limited(Vec::new());
        if fmt::write(&mut text, format_args!("{value:?}")).is_err() {
            self.2 = true;
            return;
        }
        let length = text.0.len();
        if let Ok(text) = String::from_utf8(text.0) {
            self.insert(field, Value::String(text), length);
        } else {
            self.2 = true;
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if value.len().saturating_add(self.1) > RECORD_LIMIT {
            self.2 = true;
        } else {
            self.insert(field, json!(value), value.len());
        }
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, json!(value), 20);
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, json!(value), 21);
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, json!(value), 5);
    }
}
struct SpanAccount {
    fields: Fields,
    started: Duration,
}
struct AccountingLayer(Observation);
impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for AccountingLayer {
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, context: Context<'_, S>) {
        if let Some(span) = context.span(id) {
            let mut fields = Fields::default();
            attributes.record(&mut fields);
            span.extensions_mut().insert(SpanAccount {
                fields,
                started: self.0.clock.elapsed(),
            });
        }
    }
    fn on_record(&self, id: &Id, values: &Record<'_>, context: Context<'_, S>) {
        if let Some(span) = context.span(id)
            && let Some(account) = span.extensions_mut().get_mut::<SpanAccount>()
        {
            values.record(&mut account.fields);
        }
    }
    fn on_event(&self, event: &tracing::Event<'_>, context: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        if fields.2 {
            self.0.lost.fetch_add(1, Ordering::Relaxed);
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
    fn on_close(&self, id: Id, context: Context<'_, S>) {
        if let Some(span) = context.span(&id)
            && let Some(account) = span.extensions().get::<SpanAccount>()
        {
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
    fn drop(&mut self) {
        if let Some(observation) = &self.0 {
            observation.summarize();
            observation.flush();
        }
    }
}

/// Compose one subscriber/accounting layer and one metrics recorder at executable startup.
/// Disabled observation installs nothing. Library operations never call this function.
///
/// # Errors
/// Refuses an existing global installation or an unavailable writer thread by name.
pub fn bootstrap(enabled: bool, debug: bool, default_level: tracing::Level) -> Result<BootstrapGuard, &'static str> {
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
    let started = Instant::now();
    let observation =
        Observation::with_writer(StderrSink, Arc::new(SystemClock(started))).map_err(|_| "observation writer unavailable")?;
    let selection = crate::tracing_filter(debug, default_level);
    let filter = tracing_subscriber::EnvFilter::try_new(&selection.directive)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(AccountingLayer(observation.clone()).with_filter(filter))
        .try_init()
        .map_err(|_| "subscriber already initialized")?;
    metrics::set_global_recorder(observation.recorder.clone()).map_err(|_| "metrics recorder already initialized")?;
    GLOBAL
        .set(observation.clone())
        .map_err(|_| "observation already initialized")?;
    let mut operation=observation.operation(OperationKind::Bootstrap,json!({"filter":selection.directive,"sampling":"filter only","queue_records":QUEUE_RECORDS,"record_capacity_bytes":RECORD_LIMIT}));
    operation.started = Duration::ZERO;
    operation.finish(
        Outcome::Success,
        json!({"subscriber":"accounting_layer","metrics_recorder":"json"}),
    );
    Ok(BootstrapGuard(Some(observation)))
}

struct StderrSink;
impl Write for StderrSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        crate::LockedStderrWriter::locked_stderr().write_all(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
