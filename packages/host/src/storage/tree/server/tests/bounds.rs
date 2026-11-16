use super::super::super::roster::ReadContract;
use super::*;

#[derive(Clone, Copy, Debug)]
enum Query {
    Exact,
    AsOf,
    Roots,
    Children,
    Tips,
    EmptyTips,
}

async fn query(store: &mut ServerTree, kind: Query, budget: ReadBudget) -> (Result<(), Error>, Usage) {
    let f = forks();
    let scope = f.main[0].event().0;
    let mut reader = store.reader(budget).await.unwrap();
    let result = match kind {
        Query::Exact => reader.exact(scope, *f.main[3].event().1).await.map(|r| assert!(r.is_some())),
        Query::AsOf => reader
            .as_of(scope, *f.side[2].event().1, 2)
            .await
            .map(|r| assert!(r.is_some())),
        Query::Roots => reader.roots(scope, None, 2).await.map(|p| assert_eq!(p.identities.len(), 2)),
        Query::Children => reader
            .children(scope, *f.main[1].event().1, None, 2)
            .await
            .map(|p| assert_eq!(p.identities.len(), 2)),
        Query::Tips => reader.tips(scope, None, 6).await.map(|p| assert_eq!(p.identities.len(), 3)),
        Query::EmptyTips => {
            let mut ids: Vec<_> = [&f.main[0], &f.other_root[0], &f.main[1], &f.main[2], &f.side[2], &f.main[3]]
                .iter()
                .map(|r| *r.event().1)
                .collect();
            ids.sort_unstable();
            let i = ids.iter().position(|id| *id == *f.main[0].event().1).unwrap();
            let after = i.checked_sub(1).map(|i| ids[i]);
            reader.tips(scope, after, 1).await.map(|p| {
                assert!(p.identities.is_empty(), "empty advancing tip page");
                assert_eq!(p.after, Some(*f.main[0].event().1));
                assert!(!p.end);
            })
        }
    };
    (result, reader.usage())
}

pub(super) fn run(fixture: &Fixture<'_>) {
    let before = fixture.snapshot();
    let mut store = fixture.store.borrow_mut();
    fixture.runtime.block_on(async {
        for kind in [
            Query::EmptyTips,
            Query::Exact,
            Query::Children,
            Query::AsOf,
            Query::Tips,
            Query::Roots,
        ] {
            let (success, used) = query(&mut store, kind, allowance()).await;
            success.unwrap();
            let mut minima = allowance();
            let mut distinct = 0;
            for allocation in [false, true] {
                let mut low = 0;
                let mut high = if allocation { allowance().bytes } else { allowance().rows };
                while low < high {
                    let mid = low + (high - low) / 2;
                    let mut budget = allowance();
                    if allocation {
                        budget.bytes = mid;
                    } else {
                        budget.rows = mid;
                    }
                    let (result, usage) = query(&mut store, kind, budget).await;
                    distinct += 1;
                    assert!(
                        usage.rows <= budget.rows && usage.allocation_bytes <= budget.bytes,
                        "refusal usage stays admitted"
                    );
                    match result {
                        Ok(()) => high = mid,
                        Err(error) => {
                            assert_eq!(error, StorageError::ReadLimit.into(), "bounded read has no partial result");
                            low = mid + 1;
                        }
                    }
                }
                if allocation {
                    minima.bytes = low;
                } else {
                    minima.rows = low;
                }
                let mut below = allowance();
                if allocation {
                    below.bytes = low - 1;
                } else {
                    below.rows = low - 1;
                }
                reset_events();
                assert_eq!(
                    query(&mut store, kind, below).await.0,
                    Err(StorageError::ReadLimit.into()),
                    "one below the server charge plan"
                );
                if allocation && matches!(kind, Query::Exact | Query::AsOf) {
                    assert!(
                        events() > 0,
                        "late refusal follows provisional validation events without a result"
                    );
                }
            }
            assert_eq!(query(&mut store, kind, minima).await.0, Ok(()), "exact server charge plan");
            cli_common::emit(&serde_json::json!({
                "kind": "server_read_budget",
                "query": format!("{kind:?}"),
                "rows": minima.rows,
                "bytes": minima.bytes,
                "final_rows": used.rows,
                "final_bytes": used.allocation_bytes,
                "distinct_binary_ceilings": distinct
            }))
            .unwrap();
        }
    });
    drop(store);
    assert_eq!(
        fixture.snapshot(),
        before,
        "all server budget refusals preserve complete state"
    );
}

pub(super) async fn shapes(store: &mut ServerTree) {
    let f = forks();
    let scope = f.main[0].event().0;
    let mut reader = store.reader(ReadBudget { rows: 0, bytes: 0 }).await.unwrap();
    let mut oversized = scope.clone();
    oversized.history = "x".repeat(1025);
    assert_eq!(
        reader.exact(&oversized, [0; 32]).await,
        Err(StorageError::Representation.into())
    );
    assert_eq!(
        reader.as_of(scope, [0; 32], u64::MAX).await,
        Err(StorageError::Representation.into())
    );
    assert_eq!(
        reader.roots(scope, None, usize::MAX).await,
        Err(StorageError::Representation.into())
    );
    assert_eq!(reader.usage(), Usage::default(), "request shape precedes both admissions");
    drop(reader);
    let mut reader = store.reader(allowance()).await.unwrap();
    assert_eq!(
        reader.children(scope, *f.main[0].event().1, None, 0).await,
        Err(StorageError::ReadLimit.into())
    );
    assert_eq!(reader.usage(), Usage::default(), "zero page limit refuses without any charge");
    drop(reader);
    for (identity, expected) in [
        ([255; 32], Ok(None)),
        (*f.main[0].event().1, Err(StorageError::ReadLimit.into())),
    ] {
        let mut reader = store.reader(ReadBudget { bytes: 7, rows: 0 }).await.unwrap();
        reset_fetches();
        assert_eq!(
            reader.exact(scope, identity).await,
            expected,
            "exact existence precedes the header charge"
        );
        assert_eq!(
            reader.usage(),
            Usage {
                rows: 0,
                allocation_bytes: 7
            }
        );
        assert_eq!(fetches(), 1, "the existence exception delivers no header");
    }
}

pub(super) async fn delivery(store: &mut ServerTree) {
    let scope = "s".repeat(1024);
    let key = "k".repeat(1024);
    let edition = "e".repeat(1024);
    let payload = vec![42u8; 262_144];
    let hash = [1u8; 32];
    let client = store.session.client();
    client
        .execute(
            "INSERT INTO pn_admission_generations VALUES($1,1,'unstable',NULL,1,1,0)",
            &[&scope],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO pn_versions VALUES('rule',$1,$2,0,0,$3,$4,NULL)",
            &[&key, &edition, &payload, &&hash[..]],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO pn_admission_versions VALUES($1,1,'rule',$2,$3)",
            &[&scope, &key, &edition],
        )
        .await
        .unwrap();
    for (rows, bytes, ok) in [(2, 264_411, true), (1, 264_411, false), (2, 264_410, false)] {
        let mut reader = store.reader(ReadBudget { bytes, rows }).await.unwrap();
        reset_fetches();
        let result = reader
            .request(
                Statement::ReadAdmissionVersions,
                &[&scope, &1_i64, &"rule", &key, &None::<&str>, &1_i64],
                1,
                264_411,
                true,
            )
            .await;
        if ok {
            let delivered = result.unwrap();
            assert_eq!(delivered.len(), 1);
            assert_eq!(delivered[0].get::<_, &[u8]>(8).len(), 262_144);
            assert_eq!(fetches(), 1);
        } else {
            assert_eq!(
                result.err(),
                Some(StorageError::ReadLimit.into()),
                "maximum-field delivery refused before execution"
            );
            assert_eq!(fetches(), 0, "no delivery before admission");
        }
        cli_common::emit(&serde_json::json!({
            "kind": "server_delivery",
            "rows": rows,
            "bytes": bytes,
            "used_rows": reader.usage().rows,
            "used_bytes": reader.usage().allocation_bytes
        }))
        .unwrap();
    }
    let mut reader = store.reader(allowance()).await.unwrap();
    reset_fetches();
    assert_eq!(
        reader
            .request(Statement::HasEpoch, &[&scope, &&hash[..]], usize::MAX, 50, true)
            .await
            .unwrap_err(),
        StorageError::ReadLimit.into()
    );
    assert_eq!(fetches(), 0, "delivery product overflow precedes execution");
}

pub(super) async fn chunk_delivery(store: &mut ServerTree) {
    let f = forks();
    let id = f.main[0].event().1;
    let scope = ServerReader::scope(f.main[0].event().0).unwrap();
    let scope = scope.text().unwrap();
    let bytes = vec![37u8; 262_144];
    store
        .session
        .client()
        .execute(
            "UPDATE pn_epoch_package_chunks SET bytes=$3 WHERE scope=$1 AND identity=$2 AND ordinal=0",
            &[&scope, &&id[..], &bytes],
        )
        .await
        .unwrap();
    for budget in [
        ReadBudget { bytes: 262_173, rows: 2 },
        ReadBudget { bytes: 262_174, rows: 2 },
        ReadBudget { bytes: 262_174, rows: 1 },
    ] {
        let mut reader = store.reader(budget).await.unwrap();
        reset_fetches();
        let delivered = reader
            .request(Statement::ReadEpochChunks, &[&scope, &&id[..], &1_i64], 1, 262_174, true)
            .await;
        if budget.bytes == 262_174 && budget.rows == 2 {
            let rows = delivered.unwrap();
            assert_eq!(rows.len(), 1);
            let ordinal: i64 = rows[0].get(0);
            let length: i64 = rows[0].get(1);
            let payload: &[u8] = rows[0].get(2);
            assert_eq!((ordinal, length, payload.len()), (0, 262_144, 262_144));
            assert_eq!(
                2 + 3 * 4 + 8 + 8 + payload.len(),
                262_174,
                "binary chunk reaches its recorded delivery maximum"
            );
            assert_eq!(fetches(), 1);
        } else {
            assert_eq!(
                delivered.err(),
                Some(StorageError::ReadLimit.into()),
                "maximum-field delivery refused before execution"
            );
            assert_eq!(fetches(), 0, "chunk delivery is admitted before execution");
        }
    }
    store
        .session
        .client()
        .execute(
            "UPDATE pn_epoch_package_chunks SET bytes=$3 WHERE scope=$1 AND identity=$2 AND ordinal=0",
            &[&scope, &&id[..], &f.main[0].bytes()],
        )
        .await
        .unwrap();
}
