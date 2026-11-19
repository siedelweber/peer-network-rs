use super::super::super::tests::forks;
use super::*;

async fn installed() -> ServerTree {
    let mut store = super::generation::empty_tree().await;
    assert_eq!(
        store
            .install_generation(&forks().generation, allowance(), &mut Usage::default())
            .await,
        Ok(true)
    );
    store
}

async fn write<'a>(store: &mut ServerTree, input: &'a crate::admitted_result::position::Retained) -> ServerJudgement<'a> {
    let result = store
        .commit(input, Some("unstable"), allowance(), &mut Usage::default())
        .await;
    assert!(
        result.is_ok(),
        "depth {} refused {result:?}; points {:?}",
        input.event().3,
        store.generation_hook.points
    );
    result.unwrap()
}

/// Claim: The shared result predicates preserve missing, unsupported and overlength label refusals before any allowance is charged, and admit the explicit unstable label on a valid carrier.
/// ´claim:history:tree-server-result-input´
/// ´test:unit:tree-server-result-input´
#[test]
fn tree_server_result_input() {
    let input = &forks().main[0];
    assert_eq!(
        super::super::super::checked_result_input(input, None),
        Err(Error::MissingGenerationLabel)
    );
    assert_eq!(
        super::super::super::checked_result_input(input, Some("later")),
        Err(Error::UnknownGenerationLabel)
    );
    let overlong = "x".repeat(1025);
    assert_eq!(
        super::super::super::checked_result_input(input, Some(&overlong)),
        Err(Error::Storage(StorageError::Representation))
    );
    assert_eq!(
        super::super::super::checked_result_input(input, Some("unstable")),
        Ok("unstable")
    );
}

/// Claim: Real root, child, fork and independent-origin writes preserve complete package and debit bytes, selected origins, first-child continuation and the later branch descriptor in one fixed arrival order.
/// ´claim:history:tree-server-result-fork´
/// ´test:unit:tree-server-result-fork´
#[test]
fn tree_server_result_fork() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let f = forks();
        let mut store = installed().await;
        let mut model = MemoryTree::default();
        model
            .install_generation(&f.generation, allowance(), &mut Usage::default())
            .unwrap();
        for input in [
            &f.main[0],
            &f.other_root[0],
            &f.main[1],
            &f.main[2],
            &f.side_debit[2],
            &f.main[3],
        ] {
            let expected = model
                .commit(input, Some("unstable"), allowance(), &mut Usage::default())
                .unwrap();
            let actual = write(&mut store, input).await;
            assert!(actual.inserted);
            assert_eq!(actual.generation, expected.generation);
            assert_eq!(actual.selections, expected.selections);
            let mut reader = store.reader(allowance()).await.unwrap();
            let found = reader.exact(input.event().0, *input.event().1).await.unwrap().unwrap();
            reader.end().await.unwrap();
            assert_eq!(found.bytes, input.bytes());
            assert_eq!(found.parent, input.event().2.copied());
            assert_eq!(found.depth, input.event().3);
            assert_eq!(found.debits.len(), input.debits().len());
            let path = if input.event().1 == f.side_debit[2].event().1 {
                &f.side_debit[..3]
            } else if input.event().1 == f.other_root[0].event().1 {
                &f.other_root[..1]
            } else {
                &f.main[..usize::try_from(input.event().3).unwrap()]
            };
            for debit in &found.debits {
                let expected = input.debits().iter().find(|v| v.key.act == debit.act).unwrap();
                assert_eq!(debit.bytes, expected.bytes);
                let first = path
                    .iter()
                    .find(|r| r.debits().iter().any(|v| v.key.act == debit.act))
                    .unwrap();
                assert_eq!(
                    debit.origin,
                    *first.event().1,
                    "each act retains its branch-local introduction"
                );
            }
        }
        let key = ServerReader::scope(f.main[0].event().0).unwrap();
        let scope = key.text().unwrap();
        let first_row = store
            .session
            .client()
            .query_one(
                "SELECT segment FROM pn_epoch_results WHERE scope=$1 AND identity=$2",
                &[&scope, &&f.main[2].event().1[..]],
            )
            .await
            .unwrap();
        let first_segment: &[u8] = first_row.get(0);
        assert_eq!(first_segment, &f.main[0].event().1[..]);
        let side_row = store
            .session
            .client()
            .query_one(
                "SELECT segment FROM pn_epoch_results WHERE scope=$1 AND identity=$2",
                &[&scope, &&f.side_debit[2].event().1[..]],
            )
            .await
            .unwrap();
        let side_segment: &[u8] = side_row.get(0);
        assert_eq!(side_segment, &f.side_debit[2].event().1[..]);
        assert_eq!(
            store
                .session
                .client()
                .query_one("SELECT count(*) FROM pn_epoch_branches WHERE scope=$1", &[&scope])
                .await
                .unwrap()
                .get::<_, i64>(0),
            3
        );
    });
}

/// Claim: An exact retained side result returns unchanged without inserts or admission-history reads, while same-position changed bytes refuse `EpochConflict` and preserve the complete committed snapshot.
/// ´claim:history:tree-server-result-retry´
/// ´test:unit:tree-server-result-retry´
#[test]
fn tree_server_result_retry() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let f = forks();
        let mut store = installed().await;
        for input in [&f.main[0], &f.main[1], &f.side[2]] {
            write(&mut store, input).await;
        }
        let before = complete_snapshot(&mut store).await;
        store.generation_hook.points.clear();
        let result = write(&mut store, &f.side[2]).await;
        assert!(!result.inserted);
        assert_eq!(result.label, "unstable");
        assert_eq!(complete_snapshot(&mut store).await, before);
        assert!(!store.generation_hook.points.iter().any(|p| p.starts_with("Insert")
            || *p == "ReadAdmissionVersions"
            || *p == "ReadAdmissionClosures"
            || *p == "HasVersion"));
        assert_eq!(
            store
                .commit(&f.side_debit[2], Some("unstable"), allowance(), &mut Usage::default())
                .await,
            Err(Error::Storage(StorageError::EpochConflict))
        );
        assert_eq!(complete_snapshot(&mut store).await, before);
    });
}

/// Claim: A complete valid first generation lacking the carrier's selected unqualified version refuses `MissingSelectedVersion` and leaves every committed relation unchanged.
/// ´claim:history:tree-server-result-selection´
/// ´test:unit:tree-server-result-selection´
#[test]
fn tree_server_result_selection() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let f = forks();
        let mut store = super::generation::empty_tree().await;
        let mut generation = f.generation.clone();
        let wanted = f.main[0]
            .declarations()
            .iter()
            .find(|u| super::super::super::unqualified(u.version.family))
            .unwrap();
        generation.versions.retain(|v| v != &wanted.version);
        assert_eq!(
            store
                .install_generation(&generation, allowance(), &mut Usage::default())
                .await,
            Ok(true)
        );
        let before = complete_snapshot(&mut store).await;
        assert_eq!(
            store
                .commit(&f.main[0], Some("unstable"), allowance(), &mut Usage::default())
                .await,
            Err(Error::Storage(StorageError::MissingSelectedVersion))
        );
        assert_eq!(complete_snapshot(&mut store).await, before);
    });
}

/// Claim: A valid root under zero row and then zero allocation allowance refuses `ReadLimit` before the charged `ReadEpoch` request hook and leaves complete durable state unchanged.
/// ´claim:history:tree-server-result-admission´
/// ´test:unit:tree-server-result-admission´
#[test]
fn tree_server_result_admission() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let f = forks();
        let mut store = installed().await;
        let before = complete_snapshot(&mut store).await;
        for budget in [
            ReadBudget {
                rows: 0,
                bytes: 100_000_000,
            },
            ReadBudget { rows: 100_000, bytes: 0 },
        ] {
            store.generation_hook.points.clear();
            let mut usage = Usage::default();
            assert_eq!(
                store.commit(&f.main[0], Some("unstable"), budget, &mut usage).await,
                Err(Error::Storage(StorageError::ReadLimit))
            );
            assert!(!store.generation_hook.points.contains(&"ReadEpoch"));
            assert_eq!(usage, Usage::default());
            assert_eq!(complete_snapshot(&mut store).await, before);
        }
    });
}

/// Claim: Refusal immediately before the first reference insert rolls back provisional header, chunks and observations; a complete same-session snapshot is unchanged and a retry succeeds.
/// ´claim:history:tree-server-result-cleanup´
/// ´test:unit:tree-server-result-cleanup´
#[test]
fn tree_server_result_cleanup() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let f = forks();
        let mut store = installed().await;
        store.generation_hook.points.clear();
        write(&mut store, &f.main[0]).await;
        let stop_at = store
            .generation_hook
            .points
            .iter()
            .position(|p| *p == "InsertEpochReference")
            .unwrap()
            + 1;
        assert!(store.generation_hook.points[..stop_at].contains(&"InsertEpoch"));
        assert!(store.generation_hook.points[..stop_at].contains(&"InsertEpochChunk"));
        assert!(store.generation_hook.points[..stop_at].contains(&"Insert"));
        let mut store = installed().await;
        let before = complete_snapshot(&mut store).await;
        store.generation_hook.points.clear();
        store.generation_hook.stop_at = Some(stop_at);
        assert_eq!(
            store
                .commit(&f.main[0], Some("unstable"), allowance(), &mut Usage::default())
                .await,
            Err(Error::Storage(StorageError::Injected))
        );
        assert_eq!(store.generation_hook.points.last(), Some(&"InsertEpochReference"));
        assert_eq!(complete_snapshot(&mut store).await, before);
        store.generation_hook.stop_at = None;
        store.generation_hook.points.clear();
        assert!(write(&mut store, &f.main[0]).await.inserted);
        assert_ne!(complete_snapshot(&mut store).await, before);
    });
}
