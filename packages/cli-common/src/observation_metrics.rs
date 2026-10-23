//! Bounded recorder for (´[ROOT-conv:observe:metrics]´).
//! Only the declared instruments and finite outcomes can allocate a series.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use metrics::{Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder, SharedString, Unit};
use serde_json::{Value, json};

pub(super) const STEMS: [&str; 3] = [
    "clicommon__root__rule__observe__metering",
    "execwrap__root__rule__observe__privacy",
    "clicommon__root__dec__observe__sinks",
];
pub(super) const OUTCOMES: [&str; 6] = ["success", "refusal", "error", "cancelled", "unwinding", "incomplete"];

// Justified: The metrics API uses floating-point samples; snapshots mark them estimated while completion records retain integer byte totals.
#[allow(clippy::cast_precision_loss)]
pub(super) fn estimate(value: u64) -> f64 {
    value as f64
}
const MEASURES: [(&str, &str, &str); 7] = [
    ("started_operations", "counter", "operations"),
    ("completed_operations", "counter", "operations"),
    ("work_bytes", "counter", "bytes"),
    ("active_operations", "gauge", "operations"),
    ("resource_current_bytes", "gauge", "bytes"),
    ("elapsed_seconds", "histogram", "seconds"),
    ("workload_bytes", "histogram", "bytes"),
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
    fn increment(&self, value: u64) {
        self.update(|t| {
            if let Some(total) = t.counter.checked_add(value) {
                t.counter = total;
            } else {
                t.counter = u64::MAX;
                self.lost.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
    fn absolute(&self, value: u64) {
        self.update(|t| t.counter = t.counter.max(value));
    }
}

impl GaugeFn for Instrument {
    fn increment(&self, value: f64) {
        if value.is_finite() {
            self.update(|t| t.gauge += value);
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn decrement(&self, value: f64) {
        GaugeFn::increment(self, -value);
    }
    fn set(&self, value: f64) {
        if value.is_finite() {
            self.update(|t| t.gauge = value);
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl HistogramFn for Instrument {
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
        });
    }
}

/// One local recorder shared by metrics API handles and JSON snapshots.
#[derive(Clone)]
pub(super) struct JsonRecorder {
    instruments: Arc<BTreeMap<(String, String), Arc<Instrument>>>,
    pub(super) lost: Arc<AtomicU64>,
}

impl JsonRecorder {
    pub(super) fn new() -> Self {
        let lost = Arc::new(AtomicU64::new(0));
        let mut instruments = BTreeMap::new();
        for stem in STEMS {
            for (measure, kind, unit) in MEASURES {
                let outcomes: &[&str] = if measure == "completed_operations" { &OUTCOMES } else { &[""] };
                for outcome in outcomes {
                    instruments.insert(
                        (format!("{stem}__{measure}"), (*outcome).into()),
                        Arc::new(Instrument {
                            kind,
                            unit,
                            bounds: if unit == "seconds" {
                                [0.001, 0.01, 0.1, 1.0]
                            } else {
                                [1.0, 1024.0, 65_536.0, 1_048_576.0]
                            },
                            totals: Mutex::new(Totals::default()),
                            lost: lost.clone(),
                        }),
                    );
                }
            }
        }
        Self {
            instruments: Arc::new(instruments),
            lost,
        }
    }

    fn instrument(&self, key: &Key, kind: &str) -> Option<Arc<Instrument>> {
        let mut labels = key.labels();
        let outcome = match (labels.next(), labels.next()) {
            (None, None) => "",
            (Some(label), None) if label.key() == "outcome" => label.value(),
            _ => {
                self.lost.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        let instrument = self
            .instruments
            .iter()
            .find(|((name, attribute), instrument)| name == key.name() && attribute == outcome && instrument.kind == kind)
            .map(|(_, instrument)| instrument.clone());
        if instrument.is_none() {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
        instrument
    }

    fn describe(&self, key: &KeyName, unit: Option<Unit>, kind: &str) {
        let valid = self.instruments.iter().any(|((name, _), i)| {
            name == key.as_str()
                && i.kind == kind
                && unit.is_some_and(|u| u.as_str() == i.unit || (i.unit == "operations" && u == Unit::Count))
        });
        if !valid {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn snapshot(&self) -> Value {
        let mut rows = Vec::new();
        for ((name, outcome), instrument) in self.instruments.iter() {
            if let Ok(t) = instrument.totals.try_lock() {
                rows.push(
                    json!({"name":name,"kind":instrument.kind,"unit":instrument.unit,"outcome":outcome,
                    "counter":t.counter,"gauge":if name.ends_with("resource_current_bytes") && !t.observed {None}else{Some(t.gauge)},"count":t.count,"sum":t.sum,"buckets":t.buckets,
                    "resource_scope":"reported operation-owned bytes only; unavailable contexts excluded",
                    "boundaries":instrument.bounds,"bucket_aggregation":"disjoint; final bucket is above last boundary"}),
                );
            } else {
                self.lost.fetch_add(1, Ordering::Relaxed);
            }
        }
        json!({"instruments":rows,"lost_updates":self.lost.load(Ordering::Relaxed),"counter_accuracy":"exact_if_no_loss","floating_point_accuracy":"estimated"})
    }
}

impl Recorder for JsonRecorder {
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, _description: SharedString) {
        self.describe(&key, unit, "counter");
    }
    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, _description: SharedString) {
        self.describe(&key, unit, "gauge");
    }
    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, _description: SharedString) {
        self.describe(&key, unit, "histogram");
    }
    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        self.instrument(key, "counter").map_or_else(Counter::noop, Counter::from_arc)
    }
    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        self.instrument(key, "gauge").map_or_else(Gauge::noop, Gauge::from_arc)
    }
    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        self.instrument(key, "histogram")
            .map_or_else(Histogram::noop, Histogram::from_arc)
    }
}
