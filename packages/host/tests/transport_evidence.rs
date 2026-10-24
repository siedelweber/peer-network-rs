//! Public fixture command for the secret transport's observation evidence.
use crate::{Configuration, Refusal, Session};
use serde_json::json;

/// Claim: The closed fixture statement set returns only declared public values while private service metadata remains unreachable through the production API; its observation mode cannot change its result.
/// ´claim:host:fixture-statements-preserve-the-public-result-boundary´
/// ´test:integration:public-transport´
#[test]
fn public_transport() {
    let guard = cli_common::observation::bootstrap(true, false, tracing::Level::WARN).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let result = runtime.block_on(exercise());
    drop(runtime);
    drop(guard);
    cli_common::emit(&json!({"kind":"startup_status","store_link_case":"host-secured","path_security":"operator responsibility","result":format!("{result:?}"),"persistence":"disabled"})).unwrap();
    assert!(result.is_ok());
}

async fn exercise() -> Result<(), Refusal> {
    crate::tests::relay_refusal_fixtures().await;
    for (case, expected) in [
        (None, Refusal::MissingCase),
        (Some("guarded"), Refusal::HeldCase),
        (Some("unknown"), Refusal::UnknownCase),
    ] {
        assert_eq!(
            Configuration::acquire(case, &mut b"private_unread_input".as_slice()).unwrap_err(),
            expected
        );
    }
    let root = std::env::var_os("PN_HOST_TEST_ROOT").ok_or(Refusal::ConfigurationIo)?;
    let mut file = std::fs::File::open(std::path::Path::new(&root).join("unix.json")).map_err(|_| Refusal::ConfigurationIo)?;
    let config = Configuration::acquire(Some("host-secured"), &mut file)?;
    let session = Session::connect(config).await?;
    let row = session
        .client()
        .query_one("SELECT $1::text AS public_value", &[&"public_result_sentinel_731"])
        .await
        .map_err(|_| Refusal::Protocol)?;
    assert_eq!(row.get::<_, String>(0), "public_result_sentinel_731");
    let error = session.client().query_one("SELECT 1 / 0", &[]).await.unwrap_err();
    assert_eq!(error.as_db_error().unwrap().message(), "division by zero");
    // An error is returned before its ReadyForQuery may be consumed. Complete a
    // public query before teardown so both observation modes count the same work.
    assert_eq!(
        session
            .client()
            .query_one("SELECT 1::int4", &[])
            .await
            .unwrap()
            .get::<_, i32>(0),
        1
    );
    drop(session);
    tokio::task::yield_now().await;
    for name in [
        "wrong-password",
        "unknown-role",
        "unknown-database",
        "absent-socket",
        "refused-port",
        "unreachable-host",
    ] {
        let mut file = std::fs::File::open(std::path::Path::new(&root).join(format!("{name}.json")))
            .map_err(|_| Refusal::ConfigurationIo)?;
        let config = Configuration::acquire(Some("host-secured"), &mut file)?;
        let refusal = Session::connect(config).await.unwrap_err();
        assert!(std::error::Error::source(&refusal).is_none());
    }
    Ok(())
}
