use super::*;

/// Claim: When another subscriber already owns a fresh process, unavailable observation does not stop a successful command callback or change its exit; only invalid level configuration is a structural refusal.
/// ´claim:cli:unavailable-observation-preserves-command-execution´
/// ´test:unit:unavailable-observation´
#[test]
fn unavailable_observation() {
    if std::env::var_os("PN_TEST_EXISTING_SUBSCRIBER").is_some() {
        tracing::subscriber::set_global_default(tracing_subscriber::registry()).unwrap();
        let mut ran = false;
        let result = crate::run_no_stdout_command("fixture", false, tracing::Level::INFO, || {
            ran = true;
            Ok::<(), &str>(())
        });
        assert!(ran);
        assert_eq!(result, std::process::ExitCode::SUCCESS);
        for result in [
            crate::init_json_tracing(tracing::Level::INFO),
            crate::try_init_json_tracing(tracing::Level::INFO),
            crate::init_json_tracing_with_debug(false, tracing::Level::INFO),
            crate::try_init_json_tracing_with_debug(false, tracing::Level::INFO),
        ] {
            assert!(matches!(result, Err(BootstrapError::Unavailable(_))));
        }
    } else {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "observation::tests::unavailable_observation"])
            .env("PN_TEST_EXISTING_SUBSCRIBER", "1")
            .env("PN_OBSERVE_LEVEL", "default")
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stdout));
    }
}

/// Claim: Export bootstrap and legacy initialization helpers preserve typed configuration refusal for invalid emission settings, and exporter environment configuration is refused by name before any secret reaches an SDK builder.
/// ´claim:cli:all-bootstrap-routes-preserve-configuration-refusal´
/// ´test:unit:typed-export-bootstrap´
#[test]
fn typed_export_bootstrap() {
    if let Some(mode) = std::env::var_os("PN_TEST_EXPORT_CONFIGURATION") {
        let config = crate::observation_export::ExportConfig {
            transport: Arc::new(LocalExport::default()),
            credential: PrivateString::new(SecretRole::Authentication, SecretString::from("fixture-private-token")),
        };
        let result = bootstrap_with_export(true, false, tracing::Level::INFO, config);
        if mode == "level" {
            assert!(matches!(
                result,
                Err(BootstrapError::Configuration(EmissionConfigurationError::UnknownLevel))
            ));
            for result in [
                crate::init_json_tracing(tracing::Level::INFO),
                crate::try_init_json_tracing(tracing::Level::INFO),
                crate::init_json_tracing_with_debug(false, tracing::Level::INFO),
                crate::try_init_json_tracing_with_debug(false, tracing::Level::INFO),
            ] {
                assert!(matches!(result, Err(BootstrapError::Configuration(_))));
            }
        } else {
            assert!(
                matches!(result, Err(BootstrapError::Configuration(EmissionConfigurationError::ExporterEnvironment(name))) if name == "OTEL_EXPORTER_OTLP_HEADERS")
            );
        }
    } else {
        for mode in ["level", "export"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "observation::tests::typed_export_bootstrap"])
                .env("PN_TEST_EXPORT_CONFIGURATION", mode)
                .env("PN_OBSERVE_LEVEL", if mode == "level" { "invalid" } else { "default" });
            if mode == "export" {
                command.env("OTEL_EXPORTER_OTLP_HEADERS", "private-fixture");
            }
            let result = command.output().unwrap();
            assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stdout));
        }
    }
}

/// Claim: Default emission counts and times nested labelled work without constructing byte payloads or formatting Debug content, retains command completion with its injected elapsed time and outcome, and delivers warnings, errors and final counters without loss; only the named trace setting enables payload capture.
/// ´claim:cli:default-emission-retains-problems-and-cost´
/// ´test:unit:default-emission´
#[test]
fn default_emission() {
    struct MustNotFormat;
    impl fmt::Debug for MustNotFormat {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("default captured content")
        }
    }
    assert_eq!(emission_level(None), Ok(false));
    assert_eq!(emission_level(Some("default")), Ok(false));
    assert_eq!(emission_level(Some("trace")), Ok(true));
    assert_eq!(
        emission_level(Some("unknown")),
        Err(BootstrapError::Configuration(EmissionConfigurationError::UnknownLevel))
    );
    let (mut observation, clock, capture) = fixture();
    observation.full_trace = false;
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone(), None));
    tracing::subscriber::with_default(subscriber, || {
        let command = scope("CLICOMMON", "rule:observe:spans", "run_stdout_json_command", &MustNotFormat);
        let nested = scope("CLICOMMON", "rule:observe:spans", "nested", &MustNotFormat);
        clock.0.store(500, Ordering::Relaxed);
        assert_eq!(
            observation.capture(|| {
                let _encoded = public_bytes(b"must not be built");
                panic!("default built bytes")
            }),
            Value::Null
        );
        nested.finish_with(Outcome::Success, &MustNotFormat);
        tracing::warn!(message = "public warning");
        tracing::error!(message = "public error");
        clock.0.store(1500, Ordering::Relaxed);
        command.finish_with(Outcome::Success, &MustNotFormat);
    });
    drop(BootstrapGuard(Some(observation.clone())));
    let rows = records(&observation, &capture);
    assert_eq!(rows.len(), 5);
    assert_eq!(rows.iter().filter(|row| row["level"] == "WARN").count(), 1);
    assert_eq!(rows.iter().filter(|row| row["level"] == "ERROR").count(), 1);
    let completion = rows.iter().find(|row| row["kind"] == "metering").unwrap();
    assert_eq!(completion["detail"]["duration_seconds"], 1.5);
    assert_eq!(completion["detail"]["outcome"], "success");
    assert!(completion["detail"].get("result").is_none());
    assert!(rows.iter().all(|row| row["kind"] != "span_envelope"));
    let status = rows.iter().find(|row| row["kind"] == "observation_status").unwrap();
    assert_eq!(status["delivered_records"], 4);
    assert_eq!(status["lost_records"], 0);
    let metrics = &rows.iter().find(|row| row["kind"] == "metric_summary").unwrap()["metrics"];
    let series = metrics["instruments"].as_array().unwrap();
    let started = series
        .iter()
        .find(|r| r["name"] == "clicommon__root__rule__observe__spans__started_operations")
        .unwrap();
    assert_eq!(started["counter"], 1);
    let elapsed = series
        .iter()
        .find(|r| r["name"] == "clicommon__root__rule__observe__spans__elapsed_seconds")
        .unwrap();
    assert_eq!(elapsed["count"], 1);
    assert_eq!(elapsed["sum"], 0.5);
    assert!(metrics["declared_but_unobserved"].as_u64().unwrap() > 0);
    assert!(series.len() < usize::try_from(metrics["declared_series"].as_u64().unwrap()).unwrap());
}

/// Claim: At default, nested instrumented returns and scoped finishes each classify Ok as success and Err as error without formatting either payload, so returned work cannot be reported as incomplete merely because trace capture is disabled.
/// ´claim:cli:default-returns-retain-outcomes-without-payloads´
/// ´test:unit:default-return-outcomes´
#[test]
fn default_return_outcomes() {
    struct Payload;
    impl fmt::Debug for Payload {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("payload formatted");
        }
    }
    #[tracing::instrument(
        name = "rule:observe:spans",
        skip_all,
        ret,
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "returned"
        )
    )]
    fn returned(error: bool) -> Result<Payload, Payload> {
        if error { Err(Payload) } else { Ok(Payload) }
    }
    let (mut observation, _, capture) = fixture();
    observation.full_trace = false;
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone(), None));
    tracing::subscriber::with_default(subscriber, || {
        let parent = scope("CLICOMMON", "rule:observe:spans", "run_stdout_json_command", &());
        for error in [false, true] {
            assert_eq!(returned(error).is_err(), error);
            let nested = scope("CLICOMMON", "rule:observe:spans", "finished", &());
            let result: Result<Payload, Payload> = if error { Err(Payload) } else { Ok(Payload) };
            nested.finish(&result);
        }
        parent.finish_with(Outcome::Success, &());
    });
    observation.summarize();
    let (done, drained) = mpsc::sync_channel(1);
    observation.flush_sender.send(done).unwrap();
    observation.sender.send(Message::Wake).unwrap();
    drained.recv().unwrap();
    let rows = records(&observation, &capture);
    let summary = rows.iter().find(|row| row["kind"] == "metric_summary").unwrap();
    let series = summary["metrics"]["instruments"].as_array().unwrap();
    for outcome in ["success", "error"] {
        let completed = series
            .iter()
            .find(|row| row["name"] == "clicommon__root__rule__observe__spans__completed_operations" && row["outcome"] == outcome)
            .unwrap();
        assert_eq!(completed["counter"], 2);
    }
    assert!(
        !series
            .iter()
            .any(|row| row["outcome"] == "incomplete" && row["counter"].as_u64().is_some_and(|count| count > 0))
    );
}

/// Claim: At default and trace, an explicit refusal survives a later Err return event, while an unclassified Err remains an error, preserving the distinction between rejected input and a genuine failure.
/// ´claim:cli:explicit-refusal-precedes-return-inference´
/// ´test:unit:explicit-refusal-precedence´
#[test]
fn explicit_refusal_precedence() {
    for trace in [false, true] {
        let (mut observation, _, capture) = fixture();
        observation.full_trace = trace;
        let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone(), None));
        tracing::subscriber::with_default(subscriber, || {
            for refusal in [false, true] {
                let span = tracing::info_span!(
                    "rule:observe:spans",
                    execution_owner = "CLICOMMON",
                    source_item = "outcome-fixture"
                );
                let _entered = span.enter();
                if refusal {
                    tracing::event!(tracing::Level::TRACE, outcome = "refusal");
                }
                let mut unavailable_output: &mut [u8] = &mut [];
                let failure = unavailable_output.write_all(b"public").unwrap_err();
                assert_eq!(failure.kind(), io::ErrorKind::WriteZero);
                tracing::event!(tracing::Level::TRACE, r#return = ?Err::<(), _>(failure));
            }
        });
        observation.summarize();
        let (done, drained) = mpsc::sync_channel(1);
        observation.flush_sender.send(done).unwrap();
        observation.sender.send(Message::Wake).unwrap();
        drained.recv().unwrap();
        let rows = records(&observation, &capture);
        let summary = rows.iter().find(|row| row["kind"] == "metric_summary").unwrap();
        let mut instruments = summary["metrics"]["instruments"].clone();
        if instruments["encoding"] == "json" {
            use sha2::{Digest, Sha256};
            let artifact = &instruments["artifact"];
            let payload = std::fs::read(artifact["path"].as_str().unwrap()).unwrap();
            assert_eq!(artifact["length_bytes"], payload.len());
            assert_eq!(artifact["digest"], format!("{:x}", Sha256::digest(&payload)));
            instruments = serde_json::from_slice(&payload).unwrap();
        }
        for outcome in ["refusal", "error"] {
            let row = instruments
                .as_array()
                .unwrap()
                .iter()
                .find(|row| {
                    row["name"] == "clicommon__root__rule__observe__spans__completed_operations" && row["outcome"] == outcome
                })
                .unwrap();
            assert_eq!(row["counter"], 1);
        }
    }
}

/// Claim: Public byte representations preserve UTF-8, NUL and invalid UTF-8 exactly, and structural values retain constructors, field keys and escaped string contents rather than nesting Debug text.
/// ´claim:cli:public-content-encoding-is-lossless´
/// ´test:unit:public-content-encoding´
#[test]
fn public_content_encoding() {
    assert_eq!(
        public_bytes(b"hello\0"),
        json!({"encoding":"utf-8","data":"hello\0","length_bytes":6})
    );
    assert_eq!(
        public_bytes(&[255, 0, 128]),
        json!({"encoding":"base64","data":"/wCA","length_bytes":3})
    );
    assert_eq!(
        public_bytes(&[255]),
        json!({"encoding":"base64","data":"/w==","length_bytes":1})
    );
    assert_eq!(
        public_bytes(&[255, 0]),
        json!({"encoding":"base64","data":"/wA=","length_bytes":2})
    );
    let escaped = format!("\\u{{{:x}}}", u32::from('😀'));
    let value = content::structured(&format!("Ok(Example {{ value: \"a\\n{escaped}\", bytes: [255, 0, 128] }})"));
    assert_eq!(value["constructor"], "Ok");
    let entries = &value["arguments"][0]["fields"]["entries"];
    assert_eq!(entries[0], json!([{"atom":"value"},"a\n😀"]));
    assert_eq!(entries[1][1]["sequence_u8"], public_bytes(&[255, 0, 128]));
    assert_eq!(
        content::structured("Err(\"public\")"),
        json!({"constructor":"Err","arguments":["public"]})
    );
    assert_eq!(
        content::structured("custom representation")["content"]["data"],
        "custom representation"
    );
    let largest = u128::MAX.to_string();
    assert_eq!(content::structured(&largest), json!({"atom":largest}));
}

/// Claim: Above 64 KiB, a complete JSON value becomes a digest-verified artifact reference; repeat publication reuses one object and corrupt content is atomically repaired from a fresh synced file rather than trusted.
/// ´claim:cli:large-content-is-addressed-once´
/// ´test:unit:content-artifact-publication´
#[test]
fn content_artifact_publication() {
    let directory = tempfile::tempdir().unwrap();
    let original = json!({"payload":"x".repeat(65_536)});
    let mut first = original.clone();
    content::compact(&mut first, directory.path()).unwrap();
    let artifact = &first["payload"]["artifact"];
    let path = std::path::Path::new(artifact["path"].as_str().unwrap());
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), original["payload"]);
    assert_eq!(artifact["length_bytes"], bytes.len());
    assert_eq!(
        artifact["digest"],
        format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&bytes))
    );
    let mut second = original.clone();
    content::compact(&mut second, directory.path()).unwrap();
    assert_eq!(first, second);
    assert_eq!(std::fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    let mut wrapped = json!({"detail":{"duration_seconds":1,"result":original["payload"]}});
    content::compact(&mut wrapped, directory.path()).unwrap();
    assert_eq!(wrapped["detail"]["result"], first["payload"]);
    let mut another = json!({"detail":{"duration_seconds":2,"result":original["payload"]}});
    content::compact(&mut another, directory.path()).unwrap();
    assert_eq!(another["detail"]["result"], first["payload"]);
    assert_eq!(std::fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    std::fs::write(path, b"wrong").unwrap();
    content::compact(&mut original.clone(), directory.path()).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert!(content::root().unwrap().is_absolute());
    let mut small = json!({"payload":"small"});
    content::compact(&mut small, directory.path()).unwrap();
    assert_eq!(small, json!({"payload":"small"}));
}

/// Claim: A relative artifact root is fixed at observer initialization, so changing the command's working directory before delivery cannot redirect a large public payload into the new directory.
/// ´claim:cli:artifact-root-is-fixed-before-directory-change´
/// ´test:unit:artifact-root-survives-directory-change´
#[test]
fn artifact_root_survives_directory_change() {
    if std::env::var_os("PN_TEST_ARTIFACT_ROOT").is_some() {
        let initial = std::env::current_dir().unwrap();
        let (observation, _, capture) = fixture();
        let changed = initial.join("changed");
        std::fs::create_dir(&changed).unwrap();
        std::env::set_current_dir(&changed).unwrap();
        observation.emit(json!({"kind":"trace","payload":"x".repeat(65_536)}));
        let (done, drained) = mpsc::sync_channel(1);
        observation.flush_sender.send(done).unwrap();
        observation.sender.send(Message::Wake).unwrap();
        drained.recv().unwrap();
        let rows = records(&observation, &capture);
        let path = std::path::Path::new(rows[0]["payload"]["artifact"]["path"].as_str().unwrap());
        assert!(path.is_absolute());
        assert!(path.starts_with(initial.join("relative-observations")));
        assert!(path.is_file());
        assert!(!changed.join("relative-observations").exists());
    } else {
        let root = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "observation::tests::artifact_root_survives_directory_change"])
            .current_dir(root.path())
            .env("PN_TEST_ARTIFACT_ROOT", "1")
            .env("PN_OBSERVE_ARTIFACT_DIR", "relative-observations")
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    }
}

/// Claim: A return whose outer constructor is Err completes as error even when its serde JSON error payload requires lossless custom Debug fallback; outcome classification cannot depend on the inner formatting grammar.
/// ´claim:cli:custom-debug-errors-remain-errors´
/// ´test:unit:custom-debug-error-outcome´
#[test]
fn custom_debug_error_outcome() {
    let (observation, _, capture) = fixture();
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone(), None));
    tracing::subscriber::with_default(subscriber, || {
        let scope = scope("CLICOMMON", "rule:observe:spans", "error-fixture", &());
        let result = serde_json::from_str::<Value>("{");
        assert!(result.is_err());
        scope.finish(&result);
    });
    let rows = records(&observation, &capture);
    let completion = rows.iter().find(|r| r["event_kind"] == "completion").unwrap();
    assert_eq!(completion["detail"]["outcome"], "error");
    assert_eq!(completion["detail"]["result"]["representation"], "custom-debug");
    assert_ne!(content::structured("[REDACTED]"), content::structured("\"[REDACTED]\""));
}

/// Claim: A saturated ordinary queue cannot consume diagnostic, metric-summary, export-summary or drain-request capacity; rendezvous-controlled delivery observes these records and acknowledges the drain without extending a timeout.
/// ´claim:cli:summary-capacity-survives-ordinary-saturation´
/// ´test:unit:summary-capacity´
#[test]
fn summary_capacity() {
    struct Blocked {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
        summary: mpsc::SyncSender<()>,
        diagnostic: Arc<std::sync::atomic::AtomicBool>,
        export: Arc<std::sync::atomic::AtomicBool>,
        first: bool,
    }
    impl Write for Blocked {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.first {
                self.first = false;
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
            }
            let row: Value = serde_json::from_slice(bytes).unwrap();
            if row["level"] == "ERROR" {
                assert_eq!(row["message"], "complete public diagnostic");
                self.diagnostic.store(true, Ordering::Relaxed);
            }
            if row["kind"] == "metric_summary" {
                self.summary.send(()).unwrap();
            }
            if row["kind"] == "export_summary" {
                self.export.store(true, Ordering::Relaxed);
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (entered, entry) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let (summary, seen) = mpsc::sync_channel(1);
    let clock = Arc::new(ManualClock(AtomicU64::new(0)));
    let diagnostic = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let export = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut observation = Observation::with_writer(
        Blocked {
            entered,
            release: released,
            summary,
            diagnostic: diagnostic.clone(),
            export: export.clone(),
            first: true,
        },
        clock,
    )
    .unwrap();
    observation.full_trace = true;
    observation.emit(json!({"public":"first"}));
    entry.recv().unwrap();
    for i in 0..QUEUE_RECORDS {
        observation.emit(json!({"public":i}));
    }
    observation.emit(json!({"level":"ERROR","message":"complete public diagnostic"}));
    observation.emit(json!({"kind":"export_summary","lost_exports":1}));
    observation.summarize();
    let (done, drained) = mpsc::sync_channel(1);
    observation.flush_sender.try_send(done).unwrap();
    release.send(()).unwrap();
    seen.recv().unwrap();
    drained.recv().unwrap();
    assert!(diagnostic.load(Ordering::Relaxed));
    assert!(export.load(Ordering::Relaxed));
    assert_eq!(observation.lost.load(Ordering::Relaxed), 0);
}

/// Claim: With the writer stalled at guard drop and an injected drain timeout, the arranged backlog fits one worker iteration; after release the final status counts every preceding captured record and one deliberate reserved-channel drop, with delivered plus lost equal to the 71 attempted records excluding status.
/// ´claim:cli:status-counts-are-stamped-after-preceding-delivery´
/// ´test:unit:status-after-stalled-delivery´
#[test]
fn status_after_stalled_delivery() {
    struct Stalled {
        capture: Capture,
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
        status: mpsc::SyncSender<()>,
        first: bool,
    }
    impl Write for Stalled {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.first {
                self.first = false;
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
            }
            let result = self.capture.write(bytes)?;
            let row: Value = serde_json::from_slice(bytes).unwrap();
            if row["kind"] == "observation_status" {
                self.status.send(()).unwrap();
            }
            Ok(result)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let capture = Capture::default();
    let (entered, entry) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let (status, seen) = mpsc::sync_channel(1);
    let mut observation = Observation::with_writer(
        Stalled {
            capture: capture.clone(),
            entered,
            release: released,
            status,
            first: true,
        },
        Arc::new(ManualClock(AtomicU64::new(0))),
    )
    .unwrap();
    observation.full_trace = true;
    observation.refuse_drain_wait = true;
    observation.emit(json!({"public":"first"}));
    entry.recv_timeout(Duration::from_secs(30)).unwrap();
    for index in 0..59 {
        observation.emit(json!({"public":index}));
    }
    // Seed the reserved queues without redundant wakes: the ordinary queue
    // already guarantees that the worker will visit them after release.
    for index in 0..8 {
        observation
            .diagnostic_sender
            .try_send(serde_json::to_vec(&json!({"level":"WARN","public":index})).unwrap())
            .unwrap();
    }
    observation.emit(json!({"level":"WARN","public":"dropped"}));
    observation
        .summary_sender
        .try_send(serde_json::to_vec(&json!({"kind":"export_summary"})).unwrap())
        .unwrap();
    // 60 ordinary records, nine diagnostics (one dropped), export and metrics:
    // 71 attempts, with 69 records still queued behind the in-flight writer.
    drop(BootstrapGuard(Some(observation.clone())));
    release.send(()).unwrap();
    seen.recv_timeout(Duration::from_secs(30)).unwrap();
    let bytes = capture.0.lock().unwrap();
    let rows: Vec<Value> = bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    let status = rows.last().unwrap();
    assert_eq!(status["kind"], "observation_status");
    assert_eq!(status["delivered_records"], rows.len() - 1);
    assert_eq!(status["delivered_records"], 70);
    assert_eq!(status["lost_records"], 1);
    assert_eq!(
        status["delivered_records"].as_u64().unwrap() + status["lost_records"].as_u64().unwrap(),
        71
    );
    assert_eq!(status["drain_timeouts"], 1);
    assert_eq!(status["drain_unavailable"], 1);
}

/// Claim: A 241-record trace burst including its reserved metric summary survives a completely stalled writer without blocking the producer or losing records; final delivery counts equal captured rows after a rendezvous releases the writer.
/// ´claim:cli:trace-bursts-fit-the-bounded-queue´
/// ´test:unit:trace-burst-capacity´
#[test]
fn trace_burst_capacity() {
    struct Stalled {
        capture: Capture,
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
        status: mpsc::SyncSender<()>,
        first: bool,
    }
    impl Write for Stalled {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.first {
                self.first = false;
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
            }
            let result = self.capture.write(bytes)?;
            if serde_json::from_slice::<Value>(bytes).unwrap()["kind"] == "observation_status" {
                self.status.send(()).unwrap();
            }
            Ok(result)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let capture = Capture::default();
    let (entered, entry) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let (status, seen) = mpsc::sync_channel(1);
    let mut observation = Observation::with_writer(
        Stalled {
            capture: capture.clone(),
            entered,
            release: released,
            status,
            first: true,
        },
        Arc::new(ManualClock(AtomicU64::new(0))),
    )
    .unwrap();
    observation.full_trace = true;
    observation.refuse_drain_wait = true;
    observation.emit(json!({"kind":"trace","public":0}));
    entry.recv_timeout(Duration::from_secs(30)).unwrap();
    for index in 1..240 {
        observation.emit(json!({"kind":"trace","public":index}));
    }
    assert_eq!(observation.lost.load(Ordering::Relaxed), 0);
    drop(BootstrapGuard(Some(observation.clone())));
    release.send(()).unwrap();
    seen.recv_timeout(Duration::from_secs(30)).unwrap();
    let bytes = capture.0.lock().unwrap();
    let rows: Vec<Value> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|row| !row.is_empty())
        .map(|row| serde_json::from_slice(row).unwrap())
        .collect();
    assert_eq!(rows.len(), 242);
    let status = rows.last().unwrap();
    assert_eq!(status["kind"], "observation_status");
    assert_eq!(status["delivered_records"], 241);
    assert_eq!(status["lost_records"], 0);
    assert_eq!(status["delivered_records"], rows.len() - 1);
}

/// Claim: An injected drain timeout and an occupied drain-request slot report their own counters without inventing a lost record, preserving the distinction between delivery loss and a failed wait.
/// ´claim:cli:drain-timeouts-are-not-record-loss´
/// ´test:unit:drain-timeout-preserves-loss´
#[test]
fn drain_timeout_preserves_loss() {
    let (mut observation, _, _) = fixture();
    let (sender, _receiver) = mpsc::sync_channel(1);
    observation.flush_sender = sender;
    observation.refuse_drain_wait = true;
    observation.flush();
    assert_eq!(observation.drain_timeouts.load(Ordering::Relaxed), 1);
    assert_eq!(observation.lost.load(Ordering::Relaxed), 0);
    observation.flush();
    assert_eq!(observation.drain_unavailable.load(Ordering::Relaxed), 1);
    assert_eq!(observation.lost.load(Ordering::Relaxed), 0);
}
use crate::secrets::{PrivateBytes, PrivateString, SecretBox, SecretRole, SecretString};
use std::sync::Mutex;

/// Claim: A private connection aggregate stays secret-owned during acquisition and a failed parse, including its host and numeric port; diagnostics retain only its marker, and the secret carrier zeroizes the entire aggregate before its destructor observes it.
/// ´claim:cli:private-configuration-remains-owned-through-failure-and-drop´
/// ´test:unit:private-configuration´
#[test]
fn private_configuration() {
    use secrecy::{ExposeSecret, ExposeSecretMut, zeroize::Zeroize};
    use std::io::Read;
    struct Connection {
        bytes: [u8; 64],
        port: u16,
        erased: Arc<std::sync::atomic::AtomicBool>,
    }
    impl Zeroize for Connection {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            self.port.zeroize();
        }
    }
    impl Drop for Connection {
        fn drop(&mut self) {
            assert!(self.bytes.iter().all(|byte| *byte == 0));
            assert_eq!(self.port, 0);
            self.erased.store(true, Ordering::Relaxed);
        }
    }
    #[derive(Debug)]
    struct ParseFailure {
        configuration: SecretBox<Connection>,
    }
    fn parse_connection(mut configuration: SecretBox<Connection>, length: usize) -> Result<SecretBox<Connection>, ParseFailure> {
        let port = std::str::from_utf8(&configuration.expose_secret().bytes[..length])
            .ok()
            .and_then(|text| text.rsplit(':').next()?.parse::<u16>().ok());
        if let Some(port) = port {
            configuration.expose_secret_mut().port = port;
            Ok(configuration)
        } else {
            Err(ParseFailure { configuration })
        }
    }
    let erased = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut configuration = SecretBox::new(Box::new(Connection {
        bytes: [0; 64],
        port: 0,
        erased: erased.clone(),
    }));
    let mut reader = std::io::Cursor::new(b"private-host:user:credential:invalid-port");
    // Necessary read targets protected storage directly; the parser borrows it
    // only for validation, and the failure owns the same protected aggregate.
    let length = reader.read(&mut configuration.expose_secret_mut().bytes).unwrap();
    configuration.expose_secret_mut().port = 5432;
    let failure = parse_connection(configuration, length).unwrap_err();
    let diagnostic = format!("{failure:?}");
    assert!(!diagnostic.contains("private-host"));
    assert!(!diagnostic.contains("credential"));
    assert!(!diagnostic.contains("5432"));
    assert!(diagnostic.contains("REDACTED"));
    assert_eq!(failure.configuration.expose_secret().port, 5432);
    drop(failure);
    assert!(erased.load(Ordering::Relaxed));
}

#[derive(Debug, Default)]
struct LocalExport {
    requests: Mutex<Vec<(String, Vec<u8>)>>,
    fail: bool,
}
impl crate::observation_export::ExportTransport for LocalExport {
    fn send(
        &self,
        request: http::Request<bytes::Bytes>,
        credential: &PrivateString,
    ) -> Result<http::Response<bytes::Bytes>, crate::observation_export::ExportFailure> {
        use secrecy::ExposeSecret;
        // Necessary authentication comparison borrows the protected value and
        // neither stores it nor includes it in an error or dependency request.
        assert_eq!(credential.secret().expose_secret(), "fixture-private-token");
        assert!(!format!("{request:?}").contains("fixture-private-token"));
        self.requests
            .lock()
            .unwrap()
            .push((request.uri().path().to_owned(), request.body().to_vec()));
        if self.fail {
            Err(crate::observation_export::ExportFailure::Unavailable)
        } else {
            Ok(http::Response::new(bytes::Bytes::new()))
        }
    }
}

fn export_fixture(fail: bool) -> (Arc<crate::observation_export::Bridge>, Arc<LocalExport>) {
    let transport = Arc::new(LocalExport {
        fail,
        ..LocalExport::default()
    });
    let config = crate::observation_export::ExportConfig {
        transport: transport.clone(),
        credential: PrivateString::new(SecretRole::Authentication, SecretString::from("fixture-private-token")),
    };
    (Arc::new(crate::observation_export::Bridge::new(config).unwrap()), transport)
}

/// Claim: The JSON recorder forwards the same admitted byte increments into the SDK counter; the local OTLP transport receives metric and span payloads with no credential in the request, and controlled transport failure only increments export loss.
/// ´claim:cli:provider-bridge-preserves-counts-and-secret-boundary´
/// ´test:unit:provider-bridge´
#[test]
fn provider_bridge() {
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    let (bridge, transport) = export_fixture(false);
    let recorder = JsonRecorder::with_meter(Some(&bridge.meter()));
    metrics::with_local_recorder(&recorder, || {
        metrics::counter!(format!("{}__work_bytes", STEMS[0])).increment(7);
    });
    let measured = bridge.collected();
    let metric = measured
        .scope_metrics()
        .flat_map(opentelemetry_sdk::metrics::data::ScopeMetrics::metrics)
        .find(|metric| metric.name() == format!("{}__work_bytes", STEMS[0]))
        .unwrap();
    let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
        panic!("counter must retain its integer sum");
    };
    assert_eq!(
        sum.data_points()
            .map(opentelemetry_sdk::metrics::data::SumDataPoint::value)
            .collect::<Vec<_>>(),
        [7]
    );
    let snapshot = recorder.snapshot(true);
    assert_eq!(
        snapshot["instruments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == metric.name())
            .unwrap()["counter"],
        7
    );
    let subscriber = tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(bridge.tracer()));
    tracing::subscriber::with_default(subscriber, || {
        let _span = tracing::info_span!("rule:observe:spans", public_payload = "unfiltered-public-value").entered();
        tracing::info!(public_result = 23);
    });
    bridge.flush();
    let requests = transport.requests.lock().unwrap();
    assert!(requests.iter().any(|(path, body)| {
        path == "/v1/traces"
            && body
                .windows(b"unfiltered-public-value".len())
                .any(|bytes| bytes == b"unfiltered-public-value")
    }));
    assert!(requests.iter().any(|(path, body)| path == "/v1/metrics" && !body.is_empty()));
    assert_eq!(bridge.lost.load(Ordering::Relaxed), 0);
    let (failed, _) = export_fixture(true);
    let recorder = JsonRecorder::with_meter(Some(&failed.meter()));
    metrics::with_local_recorder(&recorder, || {
        metrics::counter!(format!("{}__work_bytes", STEMS[0])).increment(11);
    });
    failed.flush();
    assert_eq!(failed.lost.load(Ordering::Relaxed), 1);
    assert!(
        failed
            .failures
            .lock()
            .unwrap()
            .iter()
            .all(|error| !error.contains("fixture-private-token"))
    );
    let measured = failed.collected();
    let metric = measured
        .scope_metrics()
        .flat_map(opentelemetry_sdk::metrics::data::ScopeMetrics::metrics)
        .find(|metric| metric.name() == format!("{}__work_bytes", STEMS[0]))
        .unwrap();
    let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
        panic!("counter remains present after export failure");
    };
    assert_eq!(
        sum.data_points()
            .map(opentelemetry_sdk::metrics::data::SumDataPoint::value)
            .collect::<Vec<_>>(),
        [11]
    );
}

/// Claim: An instrumented future re-enters the same labelled parent only while polled, includes the injected suspension interval, and leaves the polling thread outside its span after both pending and ready polls.
/// ´claim:cli:async-context-follows-polls-not-thread-lifetime´
/// ´test:unit:async-context´
#[test]
fn async_context() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    use tracing::Instrument;
    let (observation, clock, capture) = fixture();
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone(), None));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!(
            "rule:observe:spans",
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "async-fixture"
        );
        let mut pending = true;
        let mut future = std::pin::pin!(
            async {
                std::future::poll_fn(|_| {
                    assert_eq!(tracing::Span::current().metadata().unwrap().name(), "rule:observe:spans");
                    if std::mem::take(&mut pending) {
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;
                tracing::info!("return" = 23);
                23
            }
            .instrument(span),
        );
        let mut context = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert!(tracing::Span::current().is_none());
        clock.0.store(250, Ordering::Relaxed);
        assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(23));
        assert!(tracing::Span::current().is_none());
    });
    let rows = records(&observation, &capture);
    let completion = rows.iter().find(|row| row["event_kind"] == "completion").unwrap();
    assert_eq!(completion["detail"]["duration_seconds"], 0.25);
    assert_eq!(completion["detail"]["outcome"], "success");
    assert_eq!(completion["detail"]["result"], 23);
}

/// Claim: A Debug implementation that attempts nested observation cannot recurse into the accounting layer; the outer public field remains complete and the bounded loss counter names the rejected recursive attempt.
/// ´claim:cli:recursive-observation-is-loss-not-recursion´
/// ´test:unit:recursive-observation´
#[test]
fn recursive_observation() {
    struct Recursive<'a>(&'a AtomicU64);
    impl std::fmt::Debug for Recursive<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            tracing::info!(nested = "attempt");
            assert!(Observing::enter(self.0).is_none());
            f.write_str("complete-public-field")
        }
    }
    let (observation, _, capture) = fixture();
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone(), None));
    tracing::subscriber::with_default(subscriber, || tracing::info!(payload=?Recursive(&observation.lost)));
    let rows = records(&observation, &capture);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["fields"]["payload"], json!({"atom":"complete-public-field"}));
    assert!(observation.lost.load(Ordering::Relaxed) > 0);
}

/// Claim: Dropping a polled but unfinished asynchronous operation closes its metering as cancelled, while no completion result is fabricated from the clock.
/// ´claim:cli:dropped-futures-record-cancellation-without-a-result´
/// ´test:unit:async-cancellation´
#[test]
fn async_cancellation() {
    use std::future::Future;
    use std::task::{Context, Waker};
    use tracing::Instrument;
    let (observation, _, capture) = fixture();
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone(), None));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!(
            "rule:observe:spans",
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "cancel-fixture",
            asynchronous = true
        );
        let mut future = std::pin::pin!(std::future::pending::<()>().instrument(span));
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    });
    let rows = records(&observation, &capture);
    let completion = rows.iter().find(|row| row["event_kind"] == "completion").unwrap();
    assert_eq!(completion["detail"]["outcome"], "cancelled");
    assert!(completion["detail"]["result"].is_null());
}

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
        {
            let mut observation = Observation::with_writer(capture.clone(), clock.clone()).unwrap();
            observation.full_trace = true;
            observation
        },
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
    parent.resources(12, Accuracy::Exact, 12, Accuracy::Exact);
    clock.0.store(100, Ordering::Relaxed);
    let mut child = parent.child(OperationKind::Child, json!({"argv":["child"]}));
    child.work_bytes(3);
    child.resources(5, Accuracy::Estimated, 8, Accuracy::Exact);
    child.resources(2, Accuracy::Exact, 10, Accuracy::Estimated);
    clock.0.store(350, Ordering::Relaxed);
    child.finish(Outcome::Refusal, json!({"reason":"fixture"}));
    parent.resources(2, Accuracy::Exact, 20, Accuracy::Exact);
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
    assert_eq!(completed[0]["detail"]["resources"]["cumulative"]["accuracy"], "estimated");
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
    let mut missing = observation.operation(OperationKind::Command, Value::Null);
    missing.resources(9, Accuracy::Exact, 12, Accuracy::Estimated);
    missing.resources(0, Accuracy::Unavailable, 15, Accuracy::Exact);
    missing.finish(Outcome::Success, Value::Null);
    let rows = records(&observation, &capture);
    let resources = &rows.last().unwrap()["detail"]["resources"];
    assert!(resources["current"]["value"].is_null());
    assert_eq!(resources["current"]["accuracy"], "unavailable");
    assert_eq!(resources["high_water"]["value"], 9);
    assert_eq!(resources["high_water"]["accuracy"], "exact");
    assert_eq!(resources["cumulative"]["value"], 15);
    assert_eq!(resources["cumulative"]["accuracy"], "exact");
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
    let snapshot = observation.recorder.snapshot(true);
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
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone(), None));
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
    metrics::with_local_recorder(&recorder, || {
        metrics::counter!("records__root__sig__design__records__started_operations", "operation" => "validate-record")
            .increment(1);
        metrics::counter!("records__root__sig__design__records__started_operations", "operation" => "unregistered").increment(1);
    });
    let snapshot = recorder.snapshot(true);
    assert!(serde_json::to_vec(&snapshot).unwrap().len() < 65_536);
    let rows = snapshot["instruments"].as_array().unwrap();
    assert_eq!(rows.len(), 161);
    assert!(!rows.iter().any(|row| row["operation"] == "unregistered"));
    assert_eq!(
        rows.iter()
            .find(|row| row["name"] == "records__root__sig__design__records__started_operations"
                && row["operation"] == "validate-record")
            .unwrap()["counter"],
        1
    );
    for stem in STEMS {
        let count = rows
            .iter()
            .filter(|row| row["name"].as_str().unwrap().starts_with(stem))
            .count();
        assert_eq!(
            count,
            if stem == "records__root__sig__design__records" {
                63
            } else {
                14
            }
        );
    }
    assert_eq!(snapshot["lost_updates"], 4);
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
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(
        observation.clone(),
        Some(tracing_subscriber::EnvFilter::new("off")),
    ));
    tracing::subscriber::with_default(subscriber, || {
        let mut operation = observation.operation(OperationKind::Command, json!({"argument":"public-token-value"}));
        tracing::info!(payload = "public-token-value", "filtered");
        operation.work_bytes(5);
        operation.finish(Outcome::Success, Value::Null);
    });
    let rows = records(&observation, &capture);
    assert!(!rows.iter().any(|r| r["kind"] == "trace"));
    assert_eq!(rows.last().unwrap()["detail"]["work"]["value"], 5);
    let subscriber = tracing_subscriber::registry().with(AccountingLayer(observation.clone(), None));
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

/// Claim: Exhausted byte capacity, full queues and disconnected sinks increment loss while terminal metrics still account success and zero active work; injected capacity proves refusal without large allocations or waits.
/// ´claim:cli:observation-loss-is-nonbinding´
/// ´test:unit:bounded-loss´
#[test]
fn bounded_loss() {
    let (observation, _, _) = fixture();
    observation.queued_bytes.store(CAPTURE_LIMIT as u64, Ordering::Relaxed);
    observation.emit(json!({"payload":"public"}));
    assert_eq!(observation.lost.load(Ordering::Relaxed), 1);
    observation.queued_bytes.store(0, Ordering::Relaxed);
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
    let snapshot = bounded.recorder.snapshot(true);
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
