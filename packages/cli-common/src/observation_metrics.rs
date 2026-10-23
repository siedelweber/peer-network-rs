//! Bounded recorder for (´[ROOT-conv:observe:metrics]´).
//! Only the declared instruments and finite outcomes can allocate a series.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use metrics::{Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder, SharedString, Unit};
use serde_json::{Value, json};

include!("observation_operations.rs");

pub(super) const STEMS: [&str; 8] = [
    "clicommon__root__rule__observe__metering",
    "execwrap__root__rule__observe__privacy",
    "clicommon__root__dec__observe__sinks",
    "documents__root__rule__observe__spans",
    "interchange__root__rule__observe__spans",
    "clicommon__root__rule__observe__spans",
    "execwrap__root__rule__observe__spans",
    "records__root__sig__design__records",
];
pub(super) const OUTCOMES: [&str; 6] = ["success", "refusal", "error", "cancelled", "unwinding", "incomplete"];

// Justified: The metrics API uses floating-point samples; snapshots mark them estimated while completion records retain integer byte totals.
#[allow(clippy::cast_precision_loss)]
pub(super) fn estimate(value: u64) -> f64 {
    value as f64
}
const MEASURES: [(&str, &str, &str); 9] = [
    ("started_operations", "counter", "operations"),
    ("completed_operations", "counter", "operations"),
    ("work_bytes", "counter", "bytes"),
    ("work_operations", "counter", "operations"),
    ("active_operations", "gauge", "operations"),
    ("resource_current_bytes", "gauge", "bytes"),
    ("elapsed_seconds", "histogram", "seconds"),
    ("workload_bytes", "histogram", "bytes"),
    ("workload_operations", "histogram", "operations"),
];

// The records contract owns these additional instruments; other owners do not.
const RECORDS_MEASURES: [(&str, &str, &str); 8] = [
    ("assembly_steps", "counter", "count"),
    ("validated_records", "counter", "count"),
    ("resolved_references", "counter", "count"),
    ("refusals", "counter", "count"),
    ("active_validation", "gauge", "operations"),
    ("live_carrier_bytes", "gauge", "bytes"),
    ("records_per_boundary", "histogram", "count"),
    ("input_bytes", "histogram", "bytes"),
];

#[derive(Default)]
struct Totals {
    observed: bool,
    counter: u64,
    gauge: f64,
    count: u64,
    sum: f64,
    // Reviewed elapsed boundaries in seconds; workload uses byte boundaries.
    buckets: [u64; 5],
}

struct Instrument {
    kind: &'static str,
    unit: &'static str,
    bounds: [f64; 4],
    totals: Mutex<Totals>,
    lost: Arc<AtomicU64>,
    sdk: Option<SdkInstrument>,
}

enum SdkInstrument {
    Counter(opentelemetry::metrics::Counter<u64>),
    Gauge(opentelemetry::metrics::Gauge<f64>),
    Histogram(opentelemetry::metrics::Histogram<f64>),
}

impl Instrument {
    fn update(&self, action: impl FnOnce(&mut Totals)) {
        if let Ok(mut totals) = self.totals.try_lock() {
            totals.observed = true;
            action(&mut totals);
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl CounterFn for Instrument {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn increment(&self, value: u64) {
        self.update(|t| {
            if let Some(total) = t.counter.checked_add(value) {
                t.counter = total;
                if let Some(SdkInstrument::Counter(counter)) = &self.sdk {
                    counter.add(value, &[]);
                }
            } else {
                t.counter = u64::MAX;
                self.lost.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn absolute(&self, value: u64) {
        self.update(|t| {
            let delta = value.saturating_sub(t.counter);
            t.counter = t.counter.max(value);
            if let Some(SdkInstrument::Counter(counter)) = &self.sdk {
                counter.add(delta, &[]);
            }
        });
    }
}

impl GaugeFn for Instrument {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn increment(&self, value: f64) {
        if value.is_finite() {
            self.update(|t| {
                t.gauge += value;
                if let Some(SdkInstrument::Gauge(gauge)) = &self.sdk {
                    gauge.record(t.gauge, &[]);
                }
            });
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn decrement(&self, value: f64) {
        GaugeFn::increment(self, -value);
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn set(&self, value: f64) {
        if value.is_finite() {
            self.update(|t| {
                t.gauge = value;
                if let Some(SdkInstrument::Gauge(gauge)) = &self.sdk {
                    gauge.record(t.gauge, &[]);
                }
            });
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl HistogramFn for Instrument {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn record(&self, value: f64) {
        if !value.is_finite() || value < 0.0 {
            self.lost.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.update(|t| {
            t.count = t.count.saturating_add(1);
            t.sum += value;
            let bucket = self.bounds.iter().position(|b| value <= *b).unwrap_or(4);
            t.buckets[bucket] = t.buckets[bucket].saturating_add(1);
            if let Some(SdkInstrument::Histogram(histogram)) = &self.sdk {
                histogram.record(value, &[]);
            }
        });
    }
}

/// One local recorder shared by metrics API handles and JSON snapshots.
#[derive(Clone)]
pub(super) struct JsonRecorder {
    instruments: Arc<BTreeMap<(String, String, String), Arc<Instrument>>>,
    pub(super) lost: Arc<AtomicU64>,
}

impl JsonRecorder {
    pub(super) fn new() -> Self {
        Self::with_meter(None)
    }

    pub(super) fn with_meter(meter: Option<&opentelemetry::metrics::Meter>) -> Self {
        let lost = Arc::new(AtomicU64::new(0));
        let mut instruments = BTreeMap::new();
        for stem in STEMS {
            let extra: &[(&str, &str, &str)] = if stem == "records__root__sig__design__records" {
                &RECORDS_MEASURES
            } else {
                &[]
            };
            for (measure, kind, unit) in MEASURES.into_iter().chain(extra.iter().copied()) {
                let outcomes: &[&str] = if measure == "completed_operations" { &OUTCOMES } else { &[""] };
                let operations: &[&str] = if stem == "records__root__sig__design__records"
                    && matches!(measure, "started_operations" | "completed_operations")
                {
                    &RECORDS_OPERATIONS
                } else {
                    &[""]
                };
                for operation in operations {
                    for outcome in outcomes {
                        // The finite outcome is part of the SDK instrument name; no
                        // unbounded label can create a provider series.
                        let sdk_name = format!(
                            "{stem}__{measure}{}{}{}{}",
                            if operation.is_empty() { "" } else { "__" },
                            operation,
                            if outcome.is_empty() { "" } else { "__" },
                            outcome
                        );
                        let bounds = if unit == "seconds" {
                            [0.001, 0.01, 0.1, 1.0]
                        } else {
                            [1.0, 1024.0, 65_536.0, 1_048_576.0]
                        };
                        let sdk = meter.map(|meter| match kind {
                            "counter" => SdkInstrument::Counter(meter.u64_counter(sdk_name).with_unit(unit).build()),
                            "gauge" => SdkInstrument::Gauge(meter.f64_gauge(sdk_name).with_unit(unit).build()),
                            _ => SdkInstrument::Histogram(
                                meter
                                    .f64_histogram(sdk_name)
                                    .with_unit(unit)
                                    .with_boundaries(bounds.to_vec())
                                    .build(),
                            ),
                        });
                        instruments.insert(
                            (format!("{stem}__{measure}"), (*outcome).into(), (*operation).into()),
                            Arc::new(Instrument {
                                kind,
                                unit,
                                bounds,
                                totals: Mutex::new(Totals::default()),
                                lost: lost.clone(),
                                sdk,
                            }),
                        );
                    }
                }
            }
        }
        Self {
            instruments: Arc::new(instruments),
            lost,
        }
    }

    fn instrument(&self, key: &Key, kind: &str) -> Option<Arc<Instrument>> {
        let mut outcome = "";
        let mut operation = "";
        let mut seen = std::collections::BTreeSet::new();
        for label in key.labels() {
            if label.value().is_empty() || !seen.insert(label.key()) {
                self.lost.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            match label.key() {
                "outcome" => outcome = label.value(),
                "operation" => operation = label.value(),
                _ => {
                    self.lost.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
        }
        let instrument = self
            .instruments
            .iter()
            .find(|((name, attribute, op), instrument)| {
                name == key.name() && attribute == outcome && op == operation && instrument.kind == kind
            })
            .map(|(_, instrument)| instrument.clone());
        if instrument.is_none() {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
        instrument
    }

    fn describe(&self, key: &KeyName, unit: Option<Unit>, kind: &str) {
        let valid = self.instruments.iter().any(|((name, _, _), i)| {
            name == key.as_str()
                && i.kind == kind
                && unit.is_some_and(|u| u.as_str() == i.unit || (i.unit == "operations" && u == Unit::Count))
        });
        if !valid {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn snapshot(&self, full_trace: bool) -> Value {
        let mut rows = Vec::new();
        let mut unobserved = 0;
        for ((name, outcome, operation), instrument) in self.instruments.iter() {
            if let Ok(t) = instrument.totals.try_lock() {
                if !t.observed {
                    unobserved += 1;
                    if !full_trace {
                        continue;
                    }
                }
                // Operation-attributed records series are counters. Do not repeat
                // inapplicable histogram, gauge or resource fields per operation.
                if !operation.is_empty() {
                    rows.push(json!({"name":name,"kind":instrument.kind,"unit":instrument.unit,
                        "outcome":outcome,"operation":operation,"counter":t.counter}));
                    continue;
                }
                rows.push(
                    json!({"name":name,"kind":instrument.kind,"unit":instrument.unit,"outcome":outcome,"operation":operation,
                    "counter":if name.ends_with("work_bytes") && !t.observed {None}else{Some(t.counter)},"gauge":if name.ends_with("resource_current_bytes") && !t.observed {None}else{Some(t.gauge)},"count":t.count,"sum":t.sum,"buckets":t.buckets,
                    "resource_scope":"reported operation-owned bytes only; unavailable contexts excluded",
                    "boundaries":instrument.bounds,"bucket_aggregation":"disjoint; final bucket is above last boundary"}),
                );
            } else {
                self.lost.fetch_add(1, Ordering::Relaxed);
            }
        }
        json!({"instruments":rows,"declared_series":self.instruments.len(),"declared_but_unobserved":unobserved,"roster":if full_trace {"full"} else {"observed"},"lost_updates":self.lost.load(Ordering::Relaxed),"counter_accuracy":"exact_if_no_loss","floating_point_accuracy":"estimated"})
    }
}

impl Recorder for JsonRecorder {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, _description: SharedString) {
        self.describe(&key, unit, "counter");
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, _description: SharedString) {
        self.describe(&key, unit, "gauge");
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, _description: SharedString) {
        self.describe(&key, unit, "histogram");
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        self.instrument(key, "counter").map_or_else(Counter::noop, Counter::from_arc)
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        self.instrument(key, "gauge").map_or_else(Gauge::noop, Gauge::from_arc)
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        self.instrument(key, "histogram")
            .map_or_else(Histogram::noop, Histogram::from_arc)
    }
}
