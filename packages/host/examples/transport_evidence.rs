//! Public fixture command for the secret transport's observation evidence.
use pn_host::{Configuration, Refusal, Session};
use serde_json::json;

fn main() {
    let guard = cli_common::observation::bootstrap(true, false, tracing::Level::WARN).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let result = runtime.block_on(exercise());
    drop(runtime);
    drop(guard);
    cli_common::emit(&json!({"kind":"startup_status","store_link_case":"host-secured","path_security":"operator responsibility","result":format!("{result:?}"),"persistence":"disabled"})).unwrap();
    if result.is_err() {
        cli_common::exit_with(cli_common::CommandExit::Failure);
    }
}

async fn exercise() -> Result<(), Refusal> {
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
