use super::*;

pub(super) async fn run(store: &mut ServerTree) {
    let f = forks();
    let scope = ServerReader::scope(f.main[0].event().0).unwrap();
    let scope = scope.text().unwrap();
    let root = f.main[0].event().1;
    let parent = f.main[1].event().1;
    let last = f.main[3].event().1;
    let key = f.main[0]
        .declarations()
        .iter()
        .find(|u| u.version.family == Family::Rule)
        .unwrap();
    let client = store.session.client();
    // A tiny fixture otherwise favours a sequential scan; this inspects whether
    // the recorded index can supply the closed request's ordering without a sort.
    client
        .batch_execute("SET enable_seqscan=off; SET enable_bitmapscan=off")
        .await
        .unwrap();
    for (statement, parameters) in [
        (
            Statement::ReadRoots,
            vec![&scope as &(dyn tokio_postgres::types::ToSql + Sync), &None::<&[u8]>, &2_i64],
        ),
        (Statement::ReadChildren, vec![&scope, &None::<&[u8]>, &2_i64, &&parent[..]]),
        (Statement::ReadResultCandidates, vec![&scope, &None::<&[u8]>, &2_i64]),
        (Statement::ReadEpochAsOf, vec![&scope, &&root[..], &3_i64]),
        (Statement::ReadEpochChunks, vec![&scope, &&last[..], &2_i64]),
        (Statement::ReadEpochReferences, vec![&scope, &&last[..], &100_i64]),
        (
            Statement::ReadAdmissionVersions,
            vec![&scope, &1_i64, &"rule", &key.version.key, &None::<&str>, &1_i64],
        ),
        (
            Statement::ReadAdmissionClosures,
            vec![&scope, &1_i64, &"rule", &key.version.key, &None::<&str>, &1_i64],
        ),
    ] {
        let sql = format!("EXPLAIN (COSTS OFF) {}", statement.sql());
        let rows = client.query(&sql, &parameters).await.unwrap();
        let plan = rows.iter().map(|row| row.get::<_, &str>(0)).collect::<Vec<_>>().join("\n");
        assert!(plan.contains("Limit"), "closed page has a limit: {sql}\n{plan}");
        assert!(plan.contains("Index"), "closed page uses the recorded index: {sql}\n{plan}");
        assert!(!plan.contains("Sort"), "index-ordered page needs no sort: {sql}\n{plan}");
        cli_common::emit(&serde_json::json!({"kind": "server_plan", "sql": sql, "plan": plan})).unwrap();
    }
    client
        .batch_execute("RESET enable_seqscan; RESET enable_bitmapscan")
        .await
        .unwrap();
}

pub(super) async fn surplus(store: &mut ServerTree) {
    let f = forks();
    let identity = f.main[0].event().1;
    let scope = f.main[0].event().0;
    let key = ServerReader::scope(scope).unwrap();
    let key = key.text().unwrap();
    let client = store.session.client();
    client
        .execute(
            "INSERT INTO pn_epoch_package_chunks VALUES($1,$2,1,$3)",
            &[&key, &&identity[..], &&[0u8][..]],
        )
        .await
        .unwrap();
    let mut reader = store.reader(allowance()).await.unwrap();
    assert_eq!(
        reader.exact(scope, *identity).await,
        Err(StorageError::CorruptHistory.into()),
        "surplus chunk refuses instead of reconstructing"
    );
    assert_eq!(reader.end().await, Err(StorageError::CorruptHistory.into()));
    store
        .session
        .client()
        .execute(
            "DELETE FROM pn_epoch_package_chunks WHERE scope=$1 AND identity=$2 AND ordinal=1",
            &[&key, &&identity[..]],
        )
        .await
        .unwrap();
    let mut reader = store.reader(allowance()).await.unwrap();
    let header = reader.header(key, *identity).await.unwrap();
    let used = reader.usage();
    reader.meter.limit.rows = used.rows;
    reset_fetches();
    assert_eq!(
        reader.package(key, &header).await,
        Err(StorageError::ReadLimit.into()),
        "surplus probe is admitted before request"
    );
    assert_eq!(fetches(), 0, "no chunk query before surplus admission");
    reader.first_refusal = Some(StorageError::ReadLimit.into());
    assert_eq!(reader.end().await, Err(StorageError::ReadLimit.into()));
}
