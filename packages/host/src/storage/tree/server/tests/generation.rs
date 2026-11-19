use super::*;

fn declared() -> super::super::super::Generation {
    super::super::super::tests::declared()
}

fn meter(rows: usize, bytes: usize) -> Meter {
    Meter {
        limit: ReadBudget { bytes, rows },
        used: Usage::default(),
    }
}

/// Claim: Explicit valid first-law input reaches its first index reservation, while prohibited ordinal, label, minimum and malformed delta keep their input refusal before a zero allowance is charged.
/// ´claim:history:tree-server-generation-input´
/// ´test:unit:tree-server-generation-input´
#[test]
fn tree_server_generation_input() {
    let valid = declared();
    let mut zero = meter(0, 0);
    assert!(matches!(
        super::super::generation::prepare(&valid, &mut zero),
        Err(Error::Storage(StorageError::ReadLimit))
    ));
    assert_eq!(zero.used, Usage::default());
    let mut generous = meter(100, 100_000);
    assert!(super::super::generation::prepare(&valid, &mut generous).is_ok());
    for invalid in [
        {
            let mut value = valid.clone();
            value.ordinal = 2;
            value
        },
        {
            let mut value = valid.clone();
            value.minimum = 2;
            value
        },
        {
            let mut value = valid.clone();
            value.label = String::from("future");
            value
        },
        {
            let mut value = valid.clone();
            value.versions.push(value.versions[0].clone());
            value
        },
    ] {
        let mut zero = meter(0, 0);
        assert!(matches!(
            super::super::generation::prepare(&invalid, &mut zero),
            Err(Error::InvalidAdmissionGeneration)
        ));
        assert_eq!(zero.used, Usage::default());
    }
}

fn reordered() -> super::super::super::Generation {
    let mut input = declared();
    input.versions[0].opens_at = 3;
    input.versions[1].edition = String::from("b");
    input.versions[1].opens_at = 1;
    input.versions[1].announced_at = 0;
    input.versions.push(super::super::super::super::Version {
        family: input.versions[0].family,
        key: input.versions[0].key.clone(),
        edition: String::from("c"),
        announced_at: 1,
        opens_at: 5,
        payload: None,
    });
    input.closures[0].closes_at = 5;
    input.closures.push(super::super::super::Closure {
        family: input.closures[0].family,
        key: input.closures[0].key.clone(),
        edition: String::from("b"),
        closes_at: 3,
    });
    input
}

/// Claim: Preparation preserves public edition order while reserving exactly the two input-index vectors and sorting version/closure write indices by opening/closing, including opposite public orders.
/// ´claim:history:tree-server-generation-plan´
/// ´test:unit:tree-server-generation-plan´
#[test]
fn tree_server_generation_plan() {
    let input = reordered();
    let original = input.clone();
    let mut meter = meter(100, 100_000);
    let plan = super::super::generation::prepare(&input, &mut meter).unwrap();
    assert_eq!(input, original);
    assert_eq!(plan.version_order, [1, 0, 2]);
    assert_eq!(plan.closure_order, [1, 0]);
    assert_eq!(plan.version_count, 3);
    assert_eq!(plan.closure_count, 2);
    assert_eq!(meter.used.rows, 0);
    assert_eq!(meter.used.allocation_bytes, 5 * std::mem::size_of::<usize>());
}

pub(super) async fn empty_tree() -> ServerTree {
    let mut owner = connect_named("storage-tree-reads.json").await;
    catalogue::open(&mut owner).await.unwrap();
    owner.client().batch_execute("TRUNCATE pn_epoch_debit_chunks,pn_epoch_result_debits,pn_epoch_debits,pn_epoch_references,pn_epoch_package_chunks,pn_epoch_results,pn_epoch_branches,pn_epoch_scopes,pn_admission_versions,pn_admission_closures,pn_admission_generations,pn_versions,pn_closures").await.unwrap();
    ServerTree::open(owner).await.unwrap()
}

async fn relation_count(store: &ServerTree, relation: &'static str) -> i64 {
    let sql = format!("SELECT count(*) FROM {relation}");
    store.session.client().query_one(&sql, &[]).await.unwrap().get(0)
}

/// Claim: A real first-generation transaction commits the complete header, version and closure rows with original payloads and introduction mappings, and writes no result row.
/// ´claim:history:tree-server-generation-install´
/// ´test:unit:tree-server-generation-install´
#[test]
fn tree_server_generation_install() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let mut store = empty_tree().await;
        let input = declared();
        assert_eq!(store.install_generation(&input, allowance(), &mut Usage::default()).await, Ok(true));
        let scope = ServerReader::scope(&input.scope).unwrap();
        let scope = scope.text().unwrap();
        let header = store.session.client().query_one("SELECT generation,label,previous,minimum,version_count,closure_count FROM pn_admission_generations WHERE scope=$1", &[&scope]).await.unwrap();
        assert_eq!(header.get::<_, i64>(0), 1);
        assert_eq!(header.get::<_, &str>(1), "unstable");
        assert_eq!(header.get::<_, Option<i64>>(2), None);
        assert_eq!(header.get::<_, i64>(3), 1);
        assert_eq!(header.get::<_, i64>(4), 2);
        assert_eq!(header.get::<_, i64>(5), 1);
        for (relation, expected) in [
            ("pn_versions", 2),
            ("pn_admission_versions", 2),
            ("pn_closures", 1),
            ("pn_admission_closures", 1),
            ("pn_epoch_results", 0),
            ("pn_epoch_scopes", 0),
            ("pn_epoch_branches", 0),
        ] {
            assert_eq!(relation_count(&store, relation).await, expected, "{relation}");
        }
        let rows = store.session.client().query("SELECT edition,payload,digest,disclosure FROM pn_versions ORDER BY edition", &[]).await.unwrap();
        for (row, original) in rows.iter().zip(&input.versions) {
            assert_eq!(row.get::<_, &str>(0), original.edition);
            let payload = original.payload.as_ref();
            assert_eq!(row.get::<_, Option<&[u8]>>(1), payload.map(|value| value.bytes.as_slice()));
            assert_eq!(row.get::<_, Option<&[u8]>>(2), payload.map(|value| value.digest.as_slice()));
            assert_eq!(row.get::<_, Option<&[u8]>>(3), payload.and_then(|value| value.disclosure.as_ref().map(<[u8; 32]>::as_slice)));
        }
        let mappings = store.session.client().query("SELECT scope,generation,family,key,edition FROM pn_admission_versions ORDER BY edition", &[]).await.unwrap();
        assert_eq!(mappings.len(), input.versions.len());
        for (row, original) in mappings.iter().zip(&input.versions) {
            assert_eq!(row.get::<_, &str>(0), scope);
            assert_eq!(row.get::<_, i64>(1), 1);
            assert_eq!(row.get::<_, &str>(2), original.family.name());
            assert_eq!(row.get::<_, &str>(3), original.key);
            assert_eq!(row.get::<_, &str>(4), original.edition);
        }
        let closures = store.session.client().query("SELECT scope,generation,family,key,edition FROM pn_admission_closures", &[]).await.unwrap();
        assert_eq!(closures.len(), 1);
        assert_eq!(closures[0].get::<_, &str>(0), scope);
        assert_eq!(closures[0].get::<_, i64>(1), 1);
        assert_eq!(closures[0].get::<_, &str>(2), input.closures[0].family.name());
        assert_eq!(closures[0].get::<_, &str>(3), input.closures[0].key);
        assert_eq!(closures[0].get::<_, &str>(4), input.closures[0].edition);
    });
}

/// Claim: Complete equal retry commits without INSERT or row change; a valid changed payload at the same scope and ordinal refuses `AdmissionGenerationConflict` without changing complete durable rows.
/// ´claim:history:tree-server-generation-retry´
/// ´test:unit:tree-server-generation-retry´
#[test]
fn tree_server_generation_retry() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let mut store = empty_tree().await;
        let input = declared();
        assert_eq!(
            store.install_generation(&input, allowance(), &mut Usage::default()).await,
            Ok(true)
        );
        let before = complete_snapshot(&mut store).await;
        store.generation_hook.points.clear();
        assert_eq!(
            store.install_generation(&input, allowance(), &mut Usage::default()).await,
            Ok(false)
        );
        assert!(
            !store
                .generation_hook
                .points
                .iter()
                .any(|point| point.starts_with("Insert") || *point == "Close")
        );
        assert_eq!(complete_snapshot(&mut store).await, before);
        let mut different = input.clone();
        different.versions[0].payload =
            Some(super::super::super::super::Payload::rule(&pn_interchange::Value::Unsigned(8)).unwrap());
        assert_eq!(
            store.install_generation(&different, allowance(), &mut Usage::default()).await,
            Err(Error::AdmissionGenerationConflict)
        );
        assert_eq!(complete_snapshot(&mut store).await, before);
    });
}

/// Claim: An injected refusal after one version introduction rolls back every provisional row, permits a fresh complete-state snapshot on the kept session, and a same-session retry commits the whole generation.
/// ´claim:history:tree-server-generation-cleanup´
/// ´test:unit:tree-server-generation-cleanup´
#[test]
fn tree_server_generation_cleanup() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let mut store = empty_tree().await;
        let input = declared();
        let before = complete_snapshot(&mut store).await;
        store.generation_hook.points.clear();
        store.generation_hook.stop_at = Some(8);
        assert_eq!(
            store.install_generation(&input, allowance(), &mut Usage::default()).await,
            Err(Error::Storage(StorageError::Injected))
        );
        assert_eq!(&store.generation_hook.points[6..], &["InsertAdmissionVersion", "Insert"]);
        assert_eq!(complete_snapshot(&mut store).await, before);
        store.generation_hook.stop_at = None;
        store.generation_hook.points.clear();
        assert_eq!(
            store.install_generation(&input, allowance(), &mut Usage::default()).await,
            Ok(true)
        );
        assert_ne!(complete_snapshot(&mut store).await, before);
    });
}
