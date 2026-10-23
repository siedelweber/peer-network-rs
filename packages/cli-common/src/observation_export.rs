//! Bounded SDK bridge for (´[ROOT-proposal:observe:export]´).
//! Export credentials stay outside the SDK's ordinary endpoint and header types.
//! Transport implementations require the admission in (´[ROOT-inv:observe:secret-boundary]´).

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::time::Duration;

use opentelemetry::{KeyValue, metrics::MeterProvider, trace::TracerProvider};
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::{
    InstrumentKind, ManualReader, Pipeline, SdkMeterProvider, Temporality, data::ResourceMetrics, reader::MetricReader,
};
use opentelemetry_sdk::trace::{SdkTracerProvider, Span, SpanData, SpanExporter, SpanProcessor};

use crate::secrets::{PrivateString, SecretBox};

const CAPACITY: usize = 64;

/// Admitted transport receives a public OTLP request and a protected credential.
/// It must preserve secret typing in retained state and errors, enforce its own
/// bounded request lifetime, and never install a subscriber or emit observations.
pub trait ExportTransport: Send + Sync + fmt::Debug + 'static {
    /// Send public telemetry using an already secret-owned credential.
    ///
    /// # Errors
    /// The finite failure carries no private connection or authentication value.
    fn send(&self, request: Request<Bytes>, credential: &PrivateString) -> Result<Response<Bytes>, ExportFailure>;
}

/// Transport failures have no unprotected credential-bearing field.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum ExportFailure {
    /// Controlled connection failure.
    #[error("telemetry transport unavailable")]
    Unavailable,
    /// Controlled authentication refusal.
    #[error("telemetry authentication refused")]
    Refused,
}

/// Executable-owned export configuration; the SDK never receives credentials.
#[derive(Debug)]
pub struct ExportConfig {
    /// Admitted transport, including its protected connection configuration.
    pub transport: Arc<dyn ExportTransport>,
    /// Authentication material secret-typed by the caller at acquisition.
    pub credential: PrivateString,
}

#[derive(Debug)]
struct Client(Arc<ExportConfig>);
impl HttpClient for Client {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn send_bytes<'life0, 'async_trait>(
        &'life0 self,
        request: Request<Bytes>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Bytes>, HttpError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.0
                .transport
                .send(request, &self.0.credential)
                .map_err(|error| Box::new(error) as HttpError)
        })
    }
}

#[derive(Clone, Debug)]
struct Reader(Arc<ManualReader>);
impl MetricReader for Reader {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
        self.0.register_pipeline(pipeline);
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn collect(&self, metrics: &mut ResourceMetrics) -> OTelSdkResult {
        self.0.collect(metrics)
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn temporality(&self, kind: InstrumentKind) -> Temporality {
        self.0.temporality(kind)
    }
}

enum Message {
    Span(Box<SpanData>),
    Collect(mpsc::SyncSender<()>),
}

#[derive(Debug)]
struct Processor {
    sender: mpsc::SyncSender<Message>,
    lost: Arc<AtomicU64>,
}
impl SpanProcessor for Processor {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn on_start(&self, _: &mut Span, _: &opentelemetry::Context) {}
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn on_end(&self, span: SpanData) {
        if self.sender.try_send(Message::Span(Box::new(span))).is_err() {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
        Ok(())
    }
}

pub(super) struct Bridge {
    pub(super) meter_provider: SdkMeterProvider,
    tracer_provider: SdkTracerProvider,
    sender: mpsc::SyncSender<Message>,
    pub(super) lost: Arc<AtomicU64>,
    pub(super) failures: Arc<Mutex<Vec<String>>>,
    #[cfg(test)]
    reader: Reader,
}

impl Bridge {
    pub(super) fn new(config: ExportConfig) -> Result<Self, crate::observation::BootstrapError> {
        // Acquisition wraps the owned environment buffer immediately; only presence
        // is examined, and dependency builders never see a private header value.
        for signal in ["", "TRACES_", "METRICS_"] {
            for setting in ["HEADERS", "ENDPOINT", "TIMEOUT", "COMPRESSION", "PROTOCOL"] {
                let name = format!("OTEL_EXPORTER_OTLP_{signal}{setting}");
                let secret = std::env::var_os(&name).map(|value| SecretBox::new(value.into_encoded_bytes().into_boxed_slice()));
                if secret.is_some() {
                    return Err(crate::observation::EmissionConfigurationError::ExporterEnvironment(name).into());
                }
            }
        }
        let config = Arc::new(config);
        let mut span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint("http://export.invalid/v1/traces")
            .with_http_client(Client(config.clone()))
            .build()
            .map_err(|error| crate::observation::ObserverUnavailable::Exporter(error.to_string()))?;
        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint("http://export.invalid/v1/metrics")
            .with_http_client(Client(config))
            .build()
            .map_err(|error| crate::observation::ObserverUnavailable::Exporter(error.to_string()))?;
        let resource = opentelemetry_sdk::Resource::builder_empty()
            .with_attribute(KeyValue::new("service.name", "peer-network-command"))
            .build();
        span_exporter.set_resource(&resource);
        let reader = Reader(Arc::new(ManualReader::default()));
        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource.clone())
            .with_reader(reader.clone())
            .build();
        let (sender, receiver) = mpsc::sync_channel(CAPACITY);
        let lost = Arc::new(AtomicU64::new(0));
        let worker_lost = lost.clone();
        let failures = Arc::new(Mutex::new(Vec::new()));
        let worker_failures = failures.clone();
        let worker_reader = reader.clone();
        std::thread::Builder::new()
            .name("observation-export".into())
            .spawn(move || {
                use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
                while let Ok(message) = receiver.recv() {
                    let mut acknowledgement = None;
                    let result = match message {
                        Message::Span(span) => futures_executor::block_on(span_exporter.export(vec![*span])),
                        Message::Collect(done) => {
                            let mut metrics = ResourceMetrics::default();
                            let result = worker_reader
                                .collect(&mut metrics)
                                .and_then(|()| futures_executor::block_on(metric_exporter.export(&metrics)));
                            acknowledgement = Some(done);
                            result
                        }
                    };
                    if let Err(error) = result {
                        worker_lost.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut failures) = worker_failures.try_lock()
                            && failures.len() < CAPACITY
                        {
                            failures.push(error.to_string());
                        }
                    }
                    if let Some(done) = acknowledgement {
                        let _ignored = done.try_send(());
                    }
                }
            })
            .map_err(|error| crate::observation::ObserverUnavailable::Exporter(error.to_string()))?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(resource)
            .with_span_processor(Processor {
                sender: sender.clone(),
                lost: lost.clone(),
            })
            .build();
        Ok(Self {
            meter_provider,
            tracer_provider,
            sender,
            lost,
            failures,
            #[cfg(test)]
            reader,
        })
    }

    pub(super) fn meter(&self) -> opentelemetry::metrics::Meter {
        self.meter_provider.meter("peer-network-observation")
    }
    pub(super) fn tracer(&self) -> opentelemetry_sdk::trace::SdkTracer {
        self.tracer_provider.tracer("peer-network-observation")
    }
    // The production adapter receives only a completely serialized, size-checked
    // record. The unrestricted tracing adapter is confined to compatibility tests.
    pub(super) fn record(&self, bytes: &[u8]) {
        use opentelemetry::trace::{Span as _, Tracer as _};
        let Ok(record) = std::str::from_utf8(bytes) else {
            self.lost.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let mut delivery = self.tracer().start("proposal:observe:export");
        delivery.set_attribute(KeyValue::new("claim_owner", "ROOT"));
        delivery.set_attribute(KeyValue::new("claim_label", "proposal:observe:export"));
        delivery.set_attribute(KeyValue::new("execution_owner", "CLICOMMON"));
        delivery.set_attribute(KeyValue::new("record.json", record.to_owned()));
        delivery.set_attribute(KeyValue::new(
            "duration_semantics",
            "delivery only; operation timing is in record.json",
        ));
        delivery.end();
    }
    pub(super) fn flush(&self) {
        let (done, wait) = mpsc::sync_channel(1);
        if self.sender.try_send(Message::Collect(done)).is_err() || wait.recv_timeout(Duration::from_millis(100)).is_err() {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    pub(super) fn collected(&self) -> ResourceMetrics {
        let mut result = ResourceMetrics::default();
        self.reader.collect(&mut result).unwrap();
        result
    }
}
