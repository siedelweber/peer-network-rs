//! Real PostgreSQL transport evidence; the gate owns the isolated instance.
use crate::{Cause, Configuration, Refusal, ServerError, Session};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}
fn configuration(name: &str) -> Configuration {
    let root = std::env::var_os("PN_HOST_TEST_ROOT").expect("gate must provision PostgreSQL evidence");
    let mut file = std::fs::File::open(std::path::Path::new(&root).join(name)).unwrap();
    Configuration::acquire(Some("host-secured"), &mut file).unwrap()
}

fn limited_configuration() -> Configuration {
    let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
    let bytes = std::fs::read(std::path::Path::new(&root).join("unix.json")).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["user"] = "public_error_limit_role".into();
    value["password"] = "public-error-limit-password".into();
    Configuration::acquire(Some("host-secured"), &mut serde_json::to_vec(&value).unwrap().as_slice()).unwrap()
}

async fn error_setup() -> Session {
    let owner = Session::connect(configuration("unix.json")).await.unwrap();
    let exists = owner
        .client()
        .query_one("SELECT to_regclass('private_error_relation_983') IS NOT NULL", &[])
        .await
        .unwrap()
        .get::<_, bool>(0);
    if !exists {
        owner.client().batch_execute("CREATE TABLE private_error_relation_983 (value text CONSTRAINT private_error_constraint_284 UNIQUE); INSERT INTO private_error_relation_983 VALUES ('private_error_detail_692'); CREATE FUNCTION public_error_constraint() RETURNS void LANGUAGE plpgsql AS $$ BEGIN INSERT INTO private_error_relation_983 VALUES ('private_error_detail_692'); END $$").await.unwrap();
    }
    owner
}

static ERROR_FIXTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

async fn constraint_answer() {
    let session = Session::connect(configuration("unix.json")).await.unwrap();
    let error = session
        .client()
        .query_one("SELECT public_error_constraint()", &[])
        .await
        .unwrap_err();
    let expected = ServerError::Failed(Cause::ConstraintViolation);
    assert_eq!(
        session.take_server_error(),
        Some(expected),
        "private answer published before driver result"
    );
    assert_eq!(session.take_server_error(), None, "take clears the private answer");
    assert_eq!(
        session.last_refusal(),
        Some(Refusal::Server(expected)),
        "private error ends with its translated cause"
    );
    assert!(session.client().is_closed(), "private error ends the stream");
    let diagnostics = session.private_diagnostics().unwrap();
    assert_eq!(diagnostics.len(), 1);
    let rendered = format!("{expected} {expected:?} {error} {error:?} {session:?} {diagnostics:?}");
    for sentinel in [
        "private_error_relation_983",
        "private_error_constraint_284",
        "private_error_detail_692",
    ] {
        assert!(
            !rendered.contains(sentinel),
            "no diagnostic content in public representations"
        );
    }
}

/// Claim: A native private unique-constraint error publishes Failed(ConstraintViolation) before the driver returns, ends the relay with that value, and a take clears it; the driver error and public formatting retain none of the three distinct private diagnostic sentinels.
/// ´claim:host:server-error-private-answer´
/// ´test:unit:server-error-private-answer´
#[test]
fn server_error_private_answer() {
    let _fixture = ERROR_FIXTURE_LOCK.lock().unwrap();
    runtime().block_on(async {
        let owner = error_setup().await;
        constraint_answer().await;
        drop(owner);
    });
}

async fn login_answers() {
    for (file, cause) in [
        ("wrong-password.json", Cause::LoginRejected),
        ("unknown-role.json", Cause::LoginRejected),
        ("unknown-database.json", Cause::Misconfigured),
    ] {
        assert_eq!(
            Session::connect(configuration(file)).await.unwrap_err(),
            Refusal::Server(ServerError::Uncertain(cause)),
            "login error retains its own cause: {file}"
        );
    }
}

/// Claim: Native wrong-password, unknown-role and unknown-database login answers retain their distinct translated causes instead of one authentication refusal.
/// ´claim:host:server-error-login-answers´
/// ´test:unit:server-error-login-answers´
#[test]
fn server_error_login_answers() {
    runtime().block_on(login_answers());
}

/// Claim: A native zero role-connection allowance refuses login as Uncertain(Resources), with no diagnostic content in the refusal.
/// ´claim:host:server-error-login-resource´
/// ´test:unit:server-error-login-resource´
#[test]
fn server_error_login_resource() {
    runtime().block_on(async {
        let owner = Session::connect(configuration("unix.json")).await.unwrap();
        owner
            .client()
            .batch_execute("CREATE ROLE public_error_limit_role LOGIN CONNECTION LIMIT 0 PASSWORD 'public-error-limit-password'")
            .await
            .unwrap();
        let result = Session::connect(limited_configuration()).await;
        owner
            .client()
            .batch_execute("DROP ROLE public_error_limit_role")
            .await
            .unwrap();
        assert_eq!(
            result.unwrap_err(),
            Refusal::Server(ServerError::Uncertain(Cause::Resources)),
            "native connection allowance cause"
        );
    });
}

/// Claim: An owner-terminated native session publishes Uncertain(Unavailable), which covers both administrator termination and the same native code's unexpected postmaster-exit emissions.
/// ´claim:host:server-error-terminated-answer´
/// ´test:unit:server-error-terminated-answer´
#[test]
fn server_error_terminated_answer() {
    runtime().block_on(async {
        let owner = Session::connect(configuration("unix.json")).await.unwrap();
        let session = Session::connect(configuration("unix.json")).await.unwrap();
        let pid: i32 = session
            .client()
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        assert!(
            owner
                .client()
                .query_one("SELECT pg_terminate_backend($1,600000)", &[&pid])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        session.client().query_one("SELECT 1", &[]).await.unwrap_err();
        assert_eq!(
            session.take_server_error(),
            Some(ServerError::Uncertain(Cause::Unavailable)),
            "native termination answer precedes EOF"
        );
    });
}

async fn notice_answer() {
    let session = Session::connect(configuration("unix.json")).await.unwrap();
    let error = session
        .client()
        .batch_execute("DO $$ BEGIN RAISE NOTICE '%', current_user; END $$")
        .await
        .unwrap_err();
    assert_eq!(session.take_server_error(), None, "a private notice is not an error answer");
    assert_eq!(session.last_refusal(), Some(Refusal::PrivateDiagnostic));
    assert!(!format!("{error:?} {error} {:?}", session.private_diagnostics().unwrap()).contains("private_role_fixture_731"));
}

/// Claim: A native private notice terminates the relay as `PrivateDiagnostic` and records no server-error value.
/// ´claim:host:server-error-private-notice´
/// ´test:unit:server-error-private-notice´
#[test]
fn server_error_private_notice() {
    runtime().block_on(notice_answer());
}

/// Claim: The classified native constraint, login and notice cases have identical successful public outcomes under captured default and trace observation; private setup precedes capture and no private statement is submitted during it.
/// ´claim:host:server-error-observation-fixture´
/// ´test:unit:server-error-observation-fixture´
#[test]
fn server_error_observation_fixture() {
    let _fixture = ERROR_FIXTURE_LOCK.lock().unwrap();
    let runtime = runtime();
    let owner = runtime.block_on(error_setup());
    drop(owner);
    let guard = cli_common::observation::bootstrap(true, false, tracing::Level::WARN).unwrap();
    runtime.block_on(async {
        constraint_answer().await;
        login_answers().await;
        notice_answer().await;
    });
    drop(runtime);
    drop(guard);
    cli_common::emit(
        &serde_json::json!({"kind":"startup_status","store_link_case":"host-secured","result":"Ok(())","persistence":"disabled"}),
    )
    .unwrap();
}

/// Claim: PostgreSQL 19 RC 1 authenticates through SCRAM over both host-secured transports, while the driver sees public placeholders and preserves public extended-protocol values and SQL errors.
/// ´claim:host:real-service-preserves-public-statements´
/// ´test:unit:real-transports´
#[test]
fn real_transports() {
    runtime().block_on(async {
        for transport in ["unix.json", "tcp.json"] {
            let session = tokio::time::timeout(std::time::Duration::from_secs(600), Session::connect(configuration(transport))).await.expect("HANG awaiting PostgreSQL authenticated connection").unwrap();
            let retained = format!("{session:?} {:?}", session.client());
            for sentinel in ["private_role_fixture_731", "private_password_fixture_731", "private_database_fixture_731", "42100", "127.0.0.1", "host-postgres/socket"] {
                assert!(!retained.contains(sentinel));
            }
            let (driver, mut capture) = tokio::io::duplex(64);
            session.client().cancel_token().cancel_query_raw(driver, tokio_postgres::NoTls).await.unwrap();
            let mut cancellation = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut capture, &mut cancellation).await.unwrap();
            assert_eq!(cancellation, [0,0,0,16,4,210,22,46,0,0,0,1,0,0,0,2]);
            let version: String = session.client().query_one("SELECT version()", &[]).await.unwrap().get(0);
            assert!(version.starts_with(&format!("PostgreSQL {}", include_str!("../postgresql-target.txt").trim())), "unsupported test server");
            assert_eq!(session.client().query_one("SHOW TimeZone", &[]).await.unwrap().get::<_, String>(0), "UTC");
            assert_eq!(session.client().query_one("SHOW DateStyle", &[]).await.unwrap().get::<_, String>(0), "ISO, MDY");
            let row = session.client().query_one("SELECT $1::text, $2::int4", &[&"public_parameter_sentinel", &73_i32]).await.unwrap();
            assert_eq!(row.get::<_, String>(0), "public_parameter_sentinel");
            assert_eq!(row.get::<_, i32>(1), 73);
            let error = session.client().query_one("SELECT 1 / 0", &[]).await.unwrap_err();
            assert_eq!(error.code(), Some(&tokio_postgres::error::SqlState::DIVISION_BY_ZERO));
            assert_eq!(error.as_db_error().unwrap().message(), "division by zero");
            assert_eq!(session.take_server_error(), Some(ServerError::Failed(Cause::StatementRejected)), "public error answer is published before the driver result");
            assert_eq!(session.take_server_error(), None, "take clears the answer");
            assert!(session.private_diagnostics().unwrap().is_empty());
            session.client().batch_execute("BEGIN; CREATE TEMP TABLE public_fixture(value integer); INSERT INTO public_fixture VALUES (3); COMMIT; BEGIN; INSERT INTO public_fixture VALUES (4); ROLLBACK;").await.unwrap();
            assert_eq!(session.client().query_one("SELECT sum(value)::int4 FROM public_fixture", &[]).await.unwrap().get::<_, i32>(0), 3);
        }
    });
}

/// Claim: Wrong passwords, absent roles and absent databases fail inside the secret-owning authentication boundary, with no server echo in Debug, Display or source chains.
/// ´claim:host:real-authentication-errors-stay-bounded´
/// ´test:unit:real-authentication-refusals´
#[test]
fn real_authentication_refusals() {
    runtime().block_on(async {
        for name in [
            "wrong-password.json",
            "unknown-role.json",
            "unknown-database.json",
            "absent-socket.json",
            "refused-port.json",
            "unreachable-host.json",
        ] {
            let error = tokio::time::timeout(std::time::Duration::from_secs(600), Session::connect(configuration(name)))
                .await
                .expect("HANG awaiting PostgreSQL refused connection")
                .unwrap_err();
            let text = format!("{error:?} {error}");
            assert!(!text.contains("private_"));
            assert!(std::error::Error::source(&error).is_none());
        }
    });
}

/// Claim: The real backend capability cancels a running query while the driver's cancellation token remains a public placeholder and the same connection can recover.
/// ´claim:host:cancellation-keeps-the-backend-capability-private´
/// ´test:unit:real-cancellation´
#[test]
fn real_cancellation() {
    runtime().block_on(async {
        let session = Session::connect(configuration("unix.json")).await.unwrap();
        let client = session.client();
        let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await.unwrap().get(0);
        let observer = Session::connect(configuration("unix.json")).await.unwrap();
        // This lazy recursive stream has no final row. Its sleeps pace the fixture, not an assertion; only cancellation or hang containment ends it. PgSleep proves Execute reached the stream even if the observer is delayed.
        let statement = "WITH RECURSIVE pending(n) AS (SELECT 1 UNION ALL SELECT 1 FROM pending) SELECT count(*) FROM (SELECT pg_sleep(1) FROM pending) AS paced";
        let activity = "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND state = 'active' AND query = $2 AND wait_event = 'PgSleep')";
        assert!(
            !observer
                .client()
                .query_one(activity, &[&pid, &statement])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        let query = client.query_one(statement, &[]);
        let cancellation = async {
            loop {
                if observer
                    .client()
                    .query_one(activity, &[&pid, &statement])
                    .await
                    .unwrap()
                    .get::<_, bool>(0)
                {
                    break;
                }
                // Back off between observations; elapsed time does not authorize cancellation.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            session.cancel().await.unwrap();
        };
        // Poll both without a runtime macro dependency.
        let mut query = Box::pin(query);
        let mut cancellation = Box::pin(cancellation);
        let mut cancelled = false;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            std::future::poll_fn(|cx| {
                if !cancelled && cancellation.as_mut().poll(cx).is_ready() {
                    cancelled = true;
                }
                query.as_mut().poll(cx)
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("HANG awaiting the active paced stream and its cancellation result; last state=cancelled:{cancelled}"));
        assert!(cancelled);
        assert_eq!(
            result.unwrap_err().code(),
            Some(&tokio_postgres::error::SqlState::QUERY_CANCELED)
        );
        assert_eq!(session.take_server_error(), Some(ServerError::Failed(Cause::Cancelled)), "public cancellation retains its closed cause");
        assert_eq!(client.query_one("SELECT 17::int4", &[]).await.unwrap().get::<_, i32>(0), 17);
    });
}

/// Claim: Post-authentication errors and notices echoing the authenticated private role are retained whole as typed private data before the upstream driver can construct a printable database diagnostic.
/// ´claim:host:server-echo-is-private-before-driver-errors´
/// ´test:unit:private-server-echo´
#[test]
fn private_server_echo() {
    runtime().block_on(async {
        for statement in [
            "DO $$ BEGIN RAISE EXCEPTION '%', current_user; END $$",
            "DO $$ BEGIN RAISE NOTICE '%', current_user; END $$",
        ] {
            let session = Session::connect(configuration("unix.json")).await.unwrap();
            let error = session.client().batch_execute(statement).await.unwrap_err();
            assert!(!format!("{error:?} {error}").contains("private_role_fixture_731"));
            let private = session.private_diagnostics().unwrap();
            assert_eq!(private.len(), 1);
            assert!(format!("{private:?}").contains("[REDACTED]"));
            assert!(!format!("{private:?}").contains("private_role_fixture_731"));
        }
    });
}

/// Claim: Two real repeatable-read transactions preserve the public serialization-failure cause through the shim and permit rollback, rather than hiding transaction conflicts as connection loss.
/// ´claim:host:serialization-conflicts-retain-the-public-cause´
/// ´test:unit:serialization-conflict´
#[test]
fn serialization_conflict() {
    runtime().block_on(async {
        let first = Session::connect(configuration("unix.json")).await.unwrap();
        let second = Session::connect(configuration("tcp.json")).await.unwrap();
        first.client().batch_execute("CREATE TABLE public_serial_fixture (id integer PRIMARY KEY, value integer); INSERT INTO public_serial_fixture VALUES (1, 0)").await.unwrap();
        for session in [&first, &second] {
            session.client().batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ").await.unwrap();
            assert_eq!(session.client().query_one("SELECT value FROM public_serial_fixture WHERE id=$1", &[&1_i32]).await.unwrap().get::<_, i32>(0), 0);
        }
        first.client().execute("UPDATE public_serial_fixture SET value=$1 WHERE id=$2", &[&1_i32,&1_i32]).await.unwrap();
        first.client().batch_execute("COMMIT").await.unwrap();
        let error = second.client().execute("UPDATE public_serial_fixture SET value=$1 WHERE id=$2", &[&2_i32,&1_i32]).await.unwrap_err();
        assert_eq!(error.code(), Some(&tokio_postgres::error::SqlState::T_R_SERIALIZATION_FAILURE));
        assert_eq!(error.as_db_error().unwrap().message(), "could not serialize access due to concurrent update");
        assert_eq!(second.take_server_error(), Some(ServerError::Failed(Cause::Conflict)), "public serialization retains its closed cause");
        second.client().batch_execute("ROLLBACK").await.unwrap();
        first.client().batch_execute("DROP TABLE public_serial_fixture").await.unwrap();
    });
}

/// Claim: Losing the real backend closes the driver without a retained private diagnostic string, and dropping a session aborts the forwarding tasks while a query is pending.
/// ´claim:host:connection-loss-and-drop-retain-no-private-errors´
/// ´test:unit:connection-loss-and-drop´
#[test]
fn connection_loss_and_drop() {
    runtime().block_on(async {
        let session = Session::connect(configuration("unix.json")).await.unwrap();
        let error = session
            .client()
            .query_one("SELECT pg_terminate_backend(pg_backend_pid())", &[])
            .await
            .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private_role_fixture_731"));
        assert!(session.client().is_closed());
        let session = Session::connect(configuration("unix.json")).await.unwrap();
        let observer = Session::connect(configuration("unix.json")).await.unwrap();
        let key: i64 = session
            .client()
            .query_one("SELECT pg_backend_pid()::int8", &[])
            .await
            .unwrap()
            .get(0);
        observer
            .client()
            .query_one("SELECT pg_advisory_lock($1)", &[&key])
            .await
            .unwrap();
        // The observer holds the server-side query unfinished through the session drop; the first poll queues the request.
        let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[&key];
        let query = session.client().query_one("SELECT pg_advisory_lock($1)", parameters);
        let mut query = Box::pin(query);
        std::future::poll_fn(|cx| {
            assert!(query.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(query);
        drop(session);
        assert!(
            observer
                .client()
                .query_one("SELECT pg_advisory_unlock($1)", &[&key])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        tokio::task::yield_now().await;
    });
}

/// Claim: Both host-secured transports preserve every ordered row in a 4,096-row public result; elapsed time is reported as performance evidence and never changes the correctness verdict.
/// ´claim:host:multirow-relay-preserves-public-results´
/// ´test:unit:relay-throughput´
#[test]
fn relay_throughput() {
    runtime().block_on(async {
        for transport in ["unix.json", "tcp.json"] {
            let session = Session::connect(configuration(transport)).await.unwrap();
            let started = std::time::Instant::now();
            let rows = session
                .client()
                .query(
                    "SELECT value::int4, repeat('public-row-', 8) FROM generate_series(1, 4096) AS value ORDER BY value",
                    &[],
                )
                .await
                .unwrap();
            let elapsed = started.elapsed().as_secs_f64();
            assert_eq!(rows.len(), 4096);
            for (index, row) in rows.iter().enumerate() {
                assert_eq!(row.get::<_, i32>(0), i32::try_from(index + 1).unwrap());
                assert_eq!(row.get::<_, String>(1), "public-row-".repeat(8));
            }
            cli_common::emit(&serde_json::json!({"kind":"host_throughput", "transport":transport, "rows":4096, "wall_seconds":elapsed, "rows_per_second":4096.0/elapsed})).unwrap();
        }
    });
}

/// Claim: An oversized outbound driver frame returns the closed-connection class with its bounded refusal, after which the control observes absence of the real backend and its open transaction under hang containment; no real-network wall-time envelope is claimed.
/// ´claim:host:outbound-refusal-releases-the-session´
/// ´test:unit:outbound-refusal´
#[test]
fn outbound_refusal() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let session = Session::connect(configuration("unix.json")).await.unwrap();
            let checker = Session::connect(configuration("tcp.json")).await.unwrap();
            let pid: i32 = session
                .client()
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0);
            session.client().batch_execute("BEGIN").await.unwrap();
            let statement = " ".repeat(1_048_576);
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(600),
                session.client().batch_execute(&statement),
            )
            .await
            .expect("HANG awaiting outbound driver closure")
            .unwrap_err();
            assert!(error.is_closed());
            assert_eq!(session.last_refusal(), Some(crate::Refusal::RepresentationLimit));
            tokio::time::timeout(std::time::Duration::from_secs(600), async {
                loop {
                    let present: bool = checker
                        .client()
                        .query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)", &[&pid])
                        .await
                        .unwrap()
                        .get(0);
                    if !present {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("HANG awaiting refused backend absence");
        });
}
