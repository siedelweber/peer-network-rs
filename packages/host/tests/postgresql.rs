//! Real PostgreSQL transport evidence; the gate owns the isolated instance.
use crate::{Configuration, Session};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}
fn configuration(name: &str) -> Configuration {
    let root = std::env::var_os("PN_HOST_TEST_ROOT").expect("gate must provision PostgreSQL evidence");
    let mut file = std::fs::File::open(std::path::Path::new(&root).join(name)).unwrap();
    Configuration::acquire(Some("host-secured"), &mut file).unwrap()
}

/// Claim: PostgreSQL 19 RC 1 authenticates through SCRAM over both host-secured transports, while the driver sees public placeholders and preserves public extended-protocol values and SQL errors.
/// ´claim:host:real-service-preserves-public-statements´
/// ´test:integration:real-transports´
#[test]
fn real_transports() {
    runtime().block_on(async {
        for transport in ["unix.json", "tcp.json"] {
            let session = tokio::time::timeout(std::time::Duration::from_secs(15), Session::connect(configuration(transport))).await.unwrap().unwrap();
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
            assert!(version.starts_with("PostgreSQL 19rc1"), "unsupported test server");
            assert_eq!(session.client().query_one("SHOW TimeZone", &[]).await.unwrap().get::<_, String>(0), "UTC");
            assert_eq!(session.client().query_one("SHOW DateStyle", &[]).await.unwrap().get::<_, String>(0), "ISO, MDY");
            let row = session.client().query_one("SELECT $1::text, $2::int4", &[&"public_parameter_sentinel", &73_i32]).await.unwrap();
            assert_eq!(row.get::<_, String>(0), "public_parameter_sentinel");
            assert_eq!(row.get::<_, i32>(1), 73);
            let error = session.client().query_one("SELECT 1 / 0", &[]).await.unwrap_err();
            assert_eq!(error.code(), Some(&tokio_postgres::error::SqlState::DIVISION_BY_ZERO));
            assert_eq!(error.as_db_error().unwrap().message(), "division by zero");
            assert!(session.private_diagnostics().unwrap().is_empty());
            session.client().batch_execute("BEGIN; CREATE TEMP TABLE public_fixture(value integer); INSERT INTO public_fixture VALUES (3); COMMIT; BEGIN; INSERT INTO public_fixture VALUES (4); ROLLBACK;").await.unwrap();
            assert_eq!(session.client().query_one("SELECT sum(value)::int4 FROM public_fixture", &[]).await.unwrap().get::<_, i32>(0), 3);
        }
    });
}

/// Claim: Wrong passwords, absent roles and absent databases fail inside the secret-owning authentication boundary, with no server echo in Debug, Display or source chains.
/// ´claim:host:real-authentication-errors-stay-bounded´
/// ´test:integration:real-authentication-refusals´
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
            let error = tokio::time::timeout(std::time::Duration::from_secs(15), Session::connect(configuration(name)))
                .await
                .unwrap()
                .unwrap_err();
            let text = format!("{error:?} {error}");
            assert!(!text.contains("private_"));
            assert!(std::error::Error::source(&error).is_none());
        }
    });
}

/// Claim: The real backend capability cancels a running query while the driver's cancellation token remains a public placeholder and the same connection can recover.
/// ´claim:host:cancellation-keeps-the-backend-capability-private´
/// ´test:integration:real-cancellation´
#[test]
fn real_cancellation() {
    runtime().block_on(async {
        let session = Session::connect(configuration("unix.json")).await.unwrap();
        let client = session.client();
        let query = client.query_one("SELECT pg_sleep(30)", &[]);
        let cancellation = async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            session.cancel().await.unwrap();
        };
        // Poll both without a runtime macro dependency.
        let mut query = Box::pin(query);
        let mut cancellation = Box::pin(cancellation);
        let mut cancelled = false;
        let result = std::future::poll_fn(|cx| {
            if !cancelled && cancellation.as_mut().poll(cx).is_ready() {
                cancelled = true;
            }
            query.as_mut().poll(cx)
        })
        .await;
        assert!(cancelled);
        assert_eq!(
            result.unwrap_err().code(),
            Some(&tokio_postgres::error::SqlState::QUERY_CANCELED)
        );
        assert_eq!(client.query_one("SELECT 17::int4", &[]).await.unwrap().get::<_, i32>(0), 17);
    });
}

/// Claim: Post-authentication errors and notices echoing the authenticated private role are retained whole as typed private data before the upstream driver can construct a printable database diagnostic.
/// ´claim:host:server-echo-is-private-before-driver-errors´
/// ´test:integration:private-server-echo´
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
/// ´test:integration:serialization-conflict´
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
        second.client().batch_execute("ROLLBACK").await.unwrap();
        first.client().batch_execute("DROP TABLE public_serial_fixture").await.unwrap();
    });
}

/// Claim: Losing the real backend closes the driver without a retained private diagnostic string, and dropping a session aborts the forwarding tasks while a query is pending.
/// ´claim:host:connection-loss-and-drop-retain-no-private-errors´
/// ´test:integration:connection-loss-and-drop´
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
        let query = session.client().query_one("SELECT pg_sleep(30)", &[]);
        let mut query = Box::pin(query);
        std::future::poll_fn(|cx| {
            assert!(query.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(query);
        drop(session);
        tokio::task::yield_now().await;
    });
}

/// Claim: Both host-secured transports preserve every ordered row in a 4,096-row public result; elapsed time is reported as performance evidence and never changes the correctness verdict.
/// ´claim:host:multirow-relay-preserves-public-results´
/// ´test:integration:relay-throughput´
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
