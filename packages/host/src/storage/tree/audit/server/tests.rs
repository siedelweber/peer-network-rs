use super::super::{AuditBudget, AuditFailure, AuditUsage};
use crate::Session;
use crate::storage::tree::server::{ServerTree, tests};
use crate::storage::tree::{MemoryTree, Usage};
use crate::storage::{StorageError, catalogue};

async fn empty_store() -> ServerTree {
    let root = std::env::var_os("PN_HOST_TEST_ROOT").expect("registered PostgreSQL fixture root");
    let mut input =
        std::fs::File::open(std::path::Path::new(&root).join("storage-tree-audit.json")).expect("audit fixture configuration");
    let configuration = crate::Configuration::acquire(Some("host-secured"), &mut input).expect("fixture configuration accepted");
    let mut session = Session::connect(configuration).await.expect("audit fixture connection");
    catalogue::open(&mut session).await.expect("audit catalogue");
    session.client().batch_execute(
        "TRUNCATE pn_epoch_debit_chunks,pn_epoch_result_debits,pn_epoch_debits,pn_epoch_references,pn_epoch_package_chunks,pn_epoch_results,pn_epoch_branches,pn_epoch_scopes,pn_admission_versions,pn_admission_closures,pn_admission_generations,pn_versions,pn_closures"
    ).await.expect("empty audit fixture");
    ServerTree::open(session).await.expect("verified audit tree")
}

/// Claim: The complete empty server audit admits its stated row, allocation and logical ceilings, while one byte below the first history delivery boundary refuses before FETCH and a fresh invocation succeeds on the same session.
/// ´claim:history:tree-audit-server-limits´
/// ´test:unit:tree-audit-server-limits´
#[test]
fn tree_audit_server_limits() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let mut tree = empty_store().await;
        let value_size = std::mem::size_of::<pn_interchange::Value>();
        let sufficient = (2185 + 4 * value_size).max(266_584);
        let mut usage = AuditUsage::default();
        tests::reset_fetches();
        let refusal = tree
            .audit(
                AuditBudget {
                    page_rows: 1,
                    rows: 15,
                    allocation_bytes: 266_583,
                    retained_bytes: 0,
                    items: 5,
                },
                &mut usage,
            )
            .await
            .expect_err("one byte below first history delivery");
        assert!(matches!(
            refusal,
            AuditFailure::Refused {
                error: crate::storage::tree::Error::Storage(StorageError::ReadLimit),
                ..
            }
        ));
        assert_eq!(tests::fetches(), 0);
        let inventory = tree
            .audit(
                AuditBudget {
                    page_rows: 1,
                    rows: 15,
                    allocation_bytes: sufficient,
                    retained_bytes: 0,
                    items: 5,
                },
                &mut usage,
            )
            .await
            .expect("fresh complete empty audit");
        assert_eq!(inventory.counts(), (0, 0, 0, 0, 0, 5));
        assert_eq!(usage.rows, 14);
        assert_eq!(usage.allocation_bytes, 2185 + 4 * value_size);
        assert_eq!(usage.allocation_requests, 16);
        assert_eq!(tests::fetches(), 2);
    });
}

/// Claim: A server invocation returns the complete logical inventory of the empty, declaration-only two-scope and finite fork fixtures, matching the memory source without treating physical placement as an inventory field.
/// ´claim:history:tree-audit-server-inventory´
/// ´test:unit:tree-audit-server-inventory´
#[test]
fn tree_audit_server_inventory() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let mut tree = empty_store().await;
        let allowance = AuditBudget {
            page_rows: 64,
            rows: 1_000_000,
            allocation_bytes: 1_000_000_000,
            retained_bytes: 1_000_000_000,
            items: 10_000_000,
        };
        let mut usage = AuditUsage::default();
        let empty = tree.audit(allowance, &mut usage).await.expect("complete empty server audit");
        let expected = MemoryTree::default().audit(allowance, &mut AuditUsage::default()).unwrap();
        assert_eq!(empty.fields(), expected.fields());
        assert_eq!(empty.counts(), expected.counts());
        let first = crate::storage::tree::tests::declared();
        let mut second = crate::storage::tree::tests::declared();
        second.scope.history = "second".to_owned();
        for version in &mut second.versions {
            version.key = "5:6:second1:p1:e1:s1:k".to_owned();
        }
        for closure in &mut second.closures {
            closure.key = "5:6:second1:p1:e1:s1:k".to_owned();
        }
        let mut memory = MemoryTree::default();
        for generation in [&first, &second] {
            memory
                .install_generation(generation, crate::storage::tree::tests::budget(), &mut Usage::default())
                .unwrap();
            assert!(
                tree.install_generation(generation, crate::storage::tree::tests::budget(), &mut Usage::default())
                    .await
                    .unwrap()
            );
        }
        let server = tree
            .audit(allowance, &mut usage)
            .await
            .expect("complete declaration-only server audit");
        let expected = memory.audit(allowance, &mut AuditUsage::default()).unwrap();
        assert_eq!(server.fields(), expected.fields());
        assert_eq!(server.counts(), expected.counts());
        let fork_memory = tests::setup_named(false, "storage-tree-audit.json").await;
        let server = tree.audit(allowance, &mut usage).await.expect("complete fork server audit");
        let expected = fork_memory.audit(allowance, &mut AuditUsage::default()).unwrap();
        assert_eq!(server.fields(), expected.fields());
        assert_eq!(server.counts(), expected.counts());
    });
}

/// Claim: One complete history cursor pass uses only the one-row and sixty-four-row fetch rungs, includes its last row and terminal empty fetch, and leaves the cursor names reusable by a fresh invocation.
/// ´claim:history:tree-audit-server-cursor´
/// ´test:unit:tree-audit-server-cursor´
#[test]
fn tree_audit_server_cursor() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let mut tree = empty_store().await;
        let mut generation = crate::storage::tree::tests::declared();
        generation.versions.clear();
        generation.closures.clear();
        let key = "5:1:h1:p1:e1:s1:k";
        for at in 0..65u64 {
            let edition = format!("v{at:03}");
            generation.versions.push(crate::storage::Version {
                family: crate::storage::Family::Rule,
                key: key.to_owned(),
                edition: edition.clone(),
                announced_at: at,
                opens_at: at + 1,
                payload: None,
            });
            if at < 64 {
                generation.closures.push(crate::storage::tree::Closure {
                    family: crate::storage::Family::Rule,
                    key: key.to_owned(),
                    edition,
                    closes_at: at + 2,
                });
            }
        }
        assert!(
            tree.install_generation(&generation, crate::storage::tree::tests::budget(), &mut Usage::default())
                .await
                .unwrap()
        );
        let mut memory = MemoryTree::default();
        memory
            .install_generation(&generation, crate::storage::tree::tests::budget(), &mut Usage::default())
            .unwrap();
        let allowance = AuditBudget {
            page_rows: 64,
            rows: 1_000_000,
            allocation_bytes: 1_000_000_000,
            retained_bytes: 1_000_000_000,
            items: 10_000_000,
        };
        let expected = memory.audit(allowance, &mut AuditUsage::default()).unwrap();
        for (page_rows, expected_fetches) in [(1, 131), (64, 5), (64, 5)] {
            tests::reset_fetches();
            let mut usage = AuditUsage::default();
            let inventory = tree.audit(AuditBudget { page_rows, ..allowance }, &mut usage).await.unwrap();
            assert_eq!(inventory.fields(), expected.fields());
            assert_eq!(inventory.counts(), expected.counts());
            assert_eq!(tests::fetches(), expected_fetches);
        }
    });
}

/// Claim: A malformed signed package-chunk ordinal retains its original complete observed key, refuses `CorruptHistory` without inventory, and leaves the repaired fixture auditable.
/// ´claim:history:tree-audit-server-location´
/// ´test:unit:tree-audit-server-location´
#[test]
fn tree_audit_server_location() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let mut tree = empty_store().await;
        let memory = tests::setup_named(false, "storage-tree-audit.json").await;
        let (scope, identity) = tests::audit_root();
        let allowance = AuditBudget {
            page_rows: 64,
            rows: 1_000_000,
            allocation_bytes: 1_000_000_000,
            retained_bytes: 1_000_000_000,
            items: 10_000_000,
        };
        let mut usage = AuditUsage::default();
        let before = tree.audit(allowance, &mut usage).await.unwrap();
        assert_eq!(
            before.fields(),
            memory.audit(allowance, &mut AuditUsage::default()).unwrap().fields()
        );
        tests::audit_negative_chunk(&mut tree, &scope, identity).await;
        let failure = tree
            .audit(allowance, &mut usage)
            .await
            .expect_err("negative original ordinal refuses");
        let AuditFailure::Refused {
            error: crate::storage::tree::Error::Storage(StorageError::CorruptHistory),
            location,
        } = failure
        else {
            panic!("exact corruption class and location: {failure:?}");
        };
        assert_eq!(location.relation(), Some("pn_epoch_package_chunks"));
        assert_eq!(location.key_len(), 3);
        assert_eq!(location.key_text(0), Some(tests::audit_scope(&scope).as_str()));
        assert_eq!(location.key_bytes(1), Some(identity.as_slice()));
        assert_eq!(location.key_integer(2), Some(-1));
        tests::audit_clear_negative_chunk(&mut tree, &scope, identity).await;
        assert_eq!(tree.audit(allowance, &mut usage).await.unwrap().fields(), before.fields());
    });
}
