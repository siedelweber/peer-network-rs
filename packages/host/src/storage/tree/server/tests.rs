mod bounds;
mod branches;
mod generation;
mod plans;
mod result;
thread_local! {static FETCHES:std::cell::Cell<usize>=const {std::cell::Cell::new(0)};static EVENTS:std::cell::Cell<usize>=const {std::cell::Cell::new(0)};}
pub(super) fn validated_event() {
    EVENTS.set(EVENTS.get() + 1);
}
fn reset_events() {
    EVENTS.set(0);
}
fn events() -> usize {
    EVENTS.get()
}
pub(in crate::storage::tree) fn fetched() {
    FETCHES.set(FETCHES.get() + 1);
}
pub(in crate::storage::tree) fn reset_fetches() {
    FETCHES.set(0);
}
pub(in crate::storage::tree) fn fetches() -> usize {
    FETCHES.get()
}
use super::super::{MemoryTree, tests::forks};
use super::*;

fn allowance() -> ReadBudget {
    ReadBudget {
        rows: 100_000,
        bytes: 100_000_000,
    }
}

async fn session() -> Session {
    connect_named("storage-tree-reads.json").await
}

async fn connect_named(name: &str) -> Session {
    let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
    let mut file = std::fs::File::open(std::path::Path::new(&root).join(name)).unwrap();
    let configuration = crate::Configuration::acquire(Some("host-secured"), &mut file).unwrap();
    Session::connect(configuration).await.unwrap()
}

// This is explicit fixture installation, not the production writer. The functional
// reference supplies placement for each arrival order; no read consults this model.
async fn setup(reverse: bool) -> MemoryTree<'static> {
    setup_named(reverse, "storage-tree-reads.json").await
}

pub(in crate::storage::tree) async fn setup_named(reverse: bool, name: &str) -> MemoryTree<'static> {
    let f = forks();
    let mut model = MemoryTree::default();
    model
        .install_generation(&f.generation, allowance(), &mut Usage::default())
        .unwrap();
    let children = if reverse {
        [&f.side[2], &f.main[2]]
    } else {
        [&f.main[2], &f.side[2]]
    };
    for input in [&f.main[0], &f.other_root[0], &f.main[1]]
        .into_iter()
        .chain(children)
        .chain([&f.main[3]])
    {
        model
            .commit(input, Some("unstable"), allowance(), &mut Usage::default())
            .unwrap();
    }
    install(&model, &f.generation, name).await;
    model
}
async fn install(model: &MemoryTree<'_>, generation: &super::super::Generation, name: &str) {
    let mut owner = connect_named(name).await;
    catalogue::open(&mut owner).await.unwrap();
    let client = owner.client();
    client.batch_execute("TRUNCATE pn_epoch_debit_chunks,pn_epoch_result_debits,pn_epoch_debits,pn_epoch_references,pn_epoch_package_chunks,pn_epoch_results,pn_epoch_branches,pn_epoch_scopes,pn_admission_versions,pn_admission_closures,pn_admission_generations,pn_versions,pn_closures").await.unwrap();
    client.batch_execute("BEGIN; SET CONSTRAINTS ALL DEFERRED").await.unwrap();
    let scope = ServerReader::scope(&generation.scope).unwrap();
    let scope = scope.text().unwrap();
    client
        .execute(
            "INSERT INTO pn_admission_generations VALUES($1,1,'unstable',NULL,1,$2,$3)",
            &[
                &scope,
                &(signed(generation.versions.len())),
                &(signed(generation.closures.len())),
            ],
        )
        .await
        .unwrap();
    for version in generation.versions.iter().rev() {
        insert_version(&owner, version).await;
        client
            .execute(
                "INSERT INTO pn_admission_versions VALUES($1,1,$2,$3,$4)",
                &[&scope, &version.family.name(), &version.key, &version.edition],
            )
            .await
            .unwrap();
    }
    for closure in &generation.closures {
        client
            .execute(
                "INSERT INTO pn_closures VALUES($1,$2,$3,$4)",
                &[
                    &closure.family.name(),
                    &closure.key,
                    &closure.edition,
                    &(signed(closure.closes_at)),
                ],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO pn_admission_closures VALUES($1,1,$2,$3,$4)",
                &[&scope, &closure.family.name(), &closure.key, &closure.edition],
            )
            .await
            .unwrap();
    }
    populate_nodes(&owner, model, &generation.scope, scope).await;
    client.batch_execute("COMMIT").await.unwrap();
}

async fn insert_version(owner: &Session, version: &super::super::Version) {
    let payload = version.payload.as_ref();
    owner
        .client()
        .execute(
            "INSERT INTO pn_versions VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &version.family.name(),
                &version.key,
                &version.edition,
                &(signed(version.announced_at)),
                &(signed(version.opens_at)),
                &payload.map(|p| &p.bytes[..]),
                &payload.map(|p| &p.digest[..]),
                &payload.and_then(|p| p.disclosure.as_ref().map(|v| &v[..])),
            ],
        )
        .await
        .unwrap();
}

struct Fixture<'a> {
    runtime: &'a tokio::runtime::Runtime,
    store: std::cell::RefCell<ServerTree>,
}

impl super::super::roster::ReadContract for Fixture<'_> {
    fn snapshot(&self) -> String {
        let mut store = self.store.borrow_mut();
        self.runtime.block_on(async { complete_snapshot(&mut store).await })
    }
    fn read(
        &self,
        scope: &EpochScope,
        identity: Identity,
        depth: Option<u64>,
    ) -> Result<Option<super::super::roster::ReadView>, Error> {
        let mut store = self.store.borrow_mut();
        let result = self.runtime.block_on(async {
            let mut reader = store.reader(allowance()).await?;
            let result = match depth {
                Some(depth) => reader.as_of(scope, identity, depth).await,
                None => reader.exact(scope, identity).await,
            };
            let end = reader.end().await;
            if result.is_ok() {
                end?;
            }
            result
        })?;
        Ok(result.map(|value| super::super::roster::ReadView {
            identity: value.identity,
            parent: value.parent,
            depth: value.depth,
            label: value.label,
            generation: value.generation,
            bytes: value.bytes,
            selections: value
                .selections
                .into_iter()
                .map(|selected| (selected.use_, selected.origin))
                .collect(),
            debits: value
                .debits
                .into_iter()
                .map(|debit| {
                    (
                        crate::admitted_result::DebitKey {
                            scope: scope.clone(),
                            act: debit.act,
                        },
                        debit.writing_boundary,
                        debit.origin,
                        debit.bytes,
                    )
                })
                .collect(),
        }))
    }
}

async fn complete_snapshot(store: &mut ServerTree) -> String {
    // Test-only relation census: one freshly ended snapshot captures orphans as well as readable results.
    let transaction = store
        .session
        .client
        .snapshot(store.session.store_requests.clone())
        .await
        .unwrap();
    let mut snapshot = String::new();
    for relation in [
        "pn_store_identity",
        "pn_versions",
        "pn_closures",
        "pn_admission_generations",
        "pn_admission_versions",
        "pn_admission_closures",
        "pn_epoch_scopes",
        "pn_epoch_branches",
        "pn_epoch_results",
        "pn_epoch_package_chunks",
        "pn_epoch_references",
        "pn_epoch_debits",
        "pn_epoch_debit_chunks",
        "pn_epoch_result_debits",
    ] {
        let sql = format!("SELECT row_to_json(t)::text FROM {relation} t ORDER BY row_to_json(t)::text");
        for row in transaction.raw.as_ref().unwrap().query(&sql, &[]).await.unwrap() {
            let value: &str = row.get(0);
            writeln!(snapshot, "{relation} {value}").unwrap();
        }
    }
    transaction.commit().await.unwrap();
    snapshot
}

/// Claim: Explicit single-law server fixtures run the common fork read roster in both arrival orders through the production strict decoder, retaining complete package and vintage bytes, selection and debit origins and act order without changing stored state; this finite evidence establishes no writer atomicity, admission, audit, public label carrier or production budget.
/// ´claim:history:tree-server-reads´
/// ´test:unit:tree-server-reads´
#[test]
fn tree_server_reads() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for reverse in [false, true] {
        let model = runtime.block_on(setup(reverse));
        let fixture = Fixture {
            runtime: &runtime,
            store: std::cell::RefCell::new(runtime.block_on(async { ServerTree::open(session().await).await.unwrap() })),
        };
        drop(model);
        super::super::roster::read_assertions(&fixture);
    }
}

/// Claim: Root, child and bounded tip pages on two explicit server arrival orders equal the memory reference pages, including empty advancing tip pages and end cursors, without changing stored state.
/// ´claim:history:tree-server-pages´
/// ´test:unit:tree-server-pages´
#[test]
fn tree_server_pages() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for reverse in [false, true] {
        let model = runtime.block_on(setup(reverse));
        let fixture = Fixture {
            runtime: &runtime,
            store: std::cell::RefCell::new(runtime.block_on(async { ServerTree::open(session().await).await.unwrap() })),
        };
        let before = super::super::roster::ReadContract::snapshot(&fixture);
        runtime.block_on(page_assertions(&model, &mut fixture.store.borrow_mut()));
        assert_eq!(
            super::super::roster::ReadContract::snapshot(&fixture),
            before,
            "pages preserve complete state"
        );
    }
}

/// Claim: Explicit server fixtures preserve branch-relative exact and as-of results across nested forks, side branches and long empty interiors, with descriptor work determined by the named ancestry rather than segment length or side-branch count.
/// ´claim:history:tree-server-nested´
/// ´test:unit:tree-server-nested´
#[test]
fn tree_server_nested() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(branches::run());
}

/// Claim: A closure-bearing explicit server generation preserves the original selected edition under the one law.
/// ´claim:history:tree-server-closure´
/// ´test:unit:tree-server-closure´
#[test]
fn tree_server_closure() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(branches::closure());
}

/// Claim: Six server read and page shapes cross their adapter charge plan at exact and one-below row and allocation ceilings, including an empty advancing tip page and late refusal after validation events, with no reconstructed result on refusal and unchanged stored state.
/// ´claim:history:tree-server-limits´
/// ´test:unit:tree-server-limits´
#[test]
fn tree_server_limits() {
    with_fixture(|fixture| {
        bounds::run(fixture);
    });
}

/// Claim: Malformed server read requests refuse their own shape before any row or allocation allowance is charged, including a child page with zero limit at a generous allowance, without changing stored state.
/// ´claim:history:tree-server-shapes´
/// ´test:unit:tree-server-shapes´
#[test]
fn tree_server_shapes() {
    with_fixture(|fixture| {
        let before = super::super::roster::ReadContract::snapshot(fixture);
        fixture.runtime.block_on(bounds::shapes(&mut fixture.store.borrow_mut()));
        assert_eq!(
            super::super::roster::ReadContract::snapshot(fixture),
            before,
            "shapes preserves complete state"
        );
    });
}

/// Claim: The production server reader reserves maximum chunk and version delivery before execution, refuses one below each delivery boundary and checked reservation overflow with no fetch, and reconstructs the admitted complete chunk without changing its fixture.
/// ´claim:history:tree-server-delivery´
/// ´test:unit:tree-server-delivery´
#[test]
fn tree_server_delivery() {
    with_fixture(|fixture| {
        let before = super::super::roster::ReadContract::snapshot(fixture);
        fixture
            .runtime
            .block_on(bounds::chunk_delivery(&mut fixture.store.borrow_mut()));
        assert_eq!(
            super::super::roster::ReadContract::snapshot(fixture),
            before,
            "delivery preserves complete state"
        );
        fixture.runtime.block_on(bounds::delivery(&mut fixture.store.borrow_mut()));
    });
}

/// Claim: A charged bounded surplus probe delivers one excess package chunk to the production count check, which refuses corrupt history without reconstructing a result; restoring the explicit surplus leaves the complete fixture unchanged.
/// ´claim:history:tree-server-surplus´
/// ´test:unit:tree-server-surplus´
#[test]
fn tree_server_surplus() {
    with_fixture(|fixture| {
        let before = super::super::roster::ReadContract::snapshot(fixture);
        fixture.runtime.block_on(plans::surplus(&mut fixture.store.borrow_mut()));
        assert_eq!(
            super::super::roster::ReadContract::snapshot(fixture),
            before,
            "surplus preserves complete state"
        );
    });
}

/// Claim: Eight index-ordered closed server reads use LIMIT and an index without a sort on the explicit fixture with sequential and bitmap scans disabled; this witnesses index capability rather than a universal optimizer choice and leaves stored state unchanged.
/// ´claim:history:tree-server-plans´
/// ´test:unit:tree-server-plans´
#[test]
fn tree_server_plans() {
    with_fixture(|fixture| {
        let before = super::super::roster::ReadContract::snapshot(fixture);
        fixture.runtime.block_on(plans::run(&mut fixture.store.borrow_mut()));
        assert_eq!(
            super::super::roster::ReadContract::snapshot(fixture),
            before,
            "plans preserves complete state"
        );
    });
}

fn with_fixture(check: impl FnOnce(&Fixture<'_>)) {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(setup(false));
    let fixture = Fixture {
        runtime: &runtime,
        store: std::cell::RefCell::new(runtime.block_on(async { ServerTree::open(session().await).await.unwrap() })),
    };
    check(&fixture);
}

async fn page_assertions(model: &MemoryTree<'static>, store: &mut ServerTree) {
    let f = forks();
    let scope = f.main[0].event().0;
    let mut reader = store.reader(allowance()).await.unwrap();
    let mut reference = model.reader(allowance());
    assert_eq!(
        reader.roots(scope, None, 10).await.unwrap(),
        reference.roots(scope, None, 10).unwrap()
    );
    let parent = *f.main[1].event().1;
    assert_eq!(
        reader.children(scope, parent, None, 10).await.unwrap(),
        reference.children(scope, parent, None, 10).unwrap()
    );
    let mut cursor = None;
    loop {
        let page = reader.tips(scope, cursor, 1).await.unwrap();
        assert_eq!(page, reference.tips(scope, cursor, 1).unwrap());
        if page.end {
            break;
        }
        assert!(page.after > cursor, "an empty tip page advances by its candidate");
        cursor = page.after;
    }
    assert_eq!(reader.children(scope, [255; 32], None, 1).await, Err(Error::MissingTip));
    assert_eq!(
        reader.children(scope, parent, None, 0).await,
        Err(StorageError::ReadLimit.into())
    );
    assert_eq!(reader.end().await, Err(Error::MissingTip));
}

fn signed(value: impl TryInto<i64>) -> i64 {
    value
        .try_into()
        .unwrap_or_else(|_| panic!("fixture coordinate exceeds the layout"))
}

async fn populate_nodes(owner: &Session, model: &MemoryTree<'_>, identity_scope: &EpochScope, scope: &str) {
    let client = owner.client();
    for (_, root) in model.scopes.iter() {
        client
            .execute("INSERT INTO pn_epoch_scopes VALUES($1,$2)", &[&scope, &&root[..]])
            .await
            .unwrap();
    }
    let mut nodes: Vec<_> = model.results.iter().map(|(_, node)| node).collect();
    nodes.sort_by_key(|node| node.input.event().3);
    for node in nodes {
        populate_node(owner, model, identity_scope, scope, node).await;
    }
}
async fn populate_node(
    owner: &Session,
    model: &MemoryTree<'_>,
    identity_scope: &EpochScope,
    scope: &str,
    node: &super::super::Node<'_>,
) {
    let client = owner.client();
    let (_, identity, parent, depth) = node.input.event();
    if identity == &node.segment {
        let descriptor = model.segments.get(&(identity_scope, node.segment)).unwrap();
        client
            .execute(
                "INSERT INTO pn_epoch_branches VALUES($1,$2,$3,$4,$5,$6)",
                &[
                    &scope,
                    &&node.segment[..],
                    &(signed(descriptor.start)),
                    &descriptor.parent_segment.as_ref().map(|v| &v[..]),
                    &descriptor.fork.as_ref().map(|v| &v[..]),
                    &(signed(descriptor.cutoff)),
                ],
            )
            .await
            .unwrap();
    }
    let parent_segment = parent.map(|p| model.results.get(&(identity_scope, *p)).unwrap().segment);
    client
        .execute(
            "INSERT INTO pn_epoch_results VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$11)",
            &[
                &scope,
                &&identity[..],
                &(signed(depth)),
                &parent.map(|v| &v[..]),
                &parent.map(|_| signed(depth - 1)),
                &parent_segment.as_ref().map(|v| &v[..]),
                &&node.segment[..],
                &(signed(node.input.bytes().len())),
                &(signed(node.chunks.len())),
                &(signed(node.references.len())),
                &(signed(node.input.debits().len())),
            ],
        )
        .await
        .unwrap();
    for (ordinal, bytes) in node.chunks.iter().enumerate() {
        client
            .execute(
                "INSERT INTO pn_epoch_package_chunks VALUES($1,$2,$3,$4)",
                &[&scope, &&identity[..], &(signed(ordinal)), bytes],
            )
            .await
            .unwrap();
    }
    for version in &node.observations {
        insert_version(owner, version).await;
    }
    for reference in &node.references {
        let u = reference.use_;
        client
            .execute(
                "INSERT INTO pn_epoch_references VALUES($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &scope,
                    &&identity[..],
                    &(signed(u.selected_at)),
                    &u.version.family.name(),
                    &u.version.key,
                    &u.version.edition,
                    &&reference.origin[..],
                ],
            )
            .await
            .unwrap();
    }
    populate_debits(owner, scope, node).await;
}
async fn populate_debits(owner: &Session, scope: &str, node: &super::super::Node<'_>) {
    let client = owner.client();
    let (_, identity, _, depth) = node.input.event();
    for introduction in &node.introductions {
        let vintage = introduction.vintage;
        let act = &vintage.key.act;
        let sequence = act.sequence.to_string();
        client
            .execute(
                "INSERT INTO pn_epoch_debits VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
                &[
                    &scope,
                    &&identity[..],
                    &act.author,
                    &sequence,
                    &act.family,
                    &(signed(vintage.disclosure.boundary)),
                    &(signed(vintage.bytes.len())),
                    &(signed(introduction.chunks.len())),
                ],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO pn_epoch_result_debits VALUES($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &scope,
                    &&identity[..],
                    &&node.segment[..],
                    &(signed(depth)),
                    &act.author,
                    &sequence,
                    &act.family,
                ],
            )
            .await
            .unwrap();
        for (ordinal, bytes) in introduction.chunks.iter().enumerate() {
            client
                .execute(
                    "INSERT INTO pn_epoch_debit_chunks VALUES($1,$2,$3,$4,$5,$6,$7)",
                    &[
                        &scope,
                        &&identity[..],
                        &act.author,
                        &sequence,
                        &act.family,
                        &(signed(ordinal)),
                        bytes,
                    ],
                )
                .await
                .unwrap();
        }
    }
}

pub(in crate::storage::tree) async fn prepare_trace(name: &str) -> ServerTree {
    setup_named(false, name).await;
    ServerTree::open(connect_named(name).await).await.unwrap()
}

pub(in crate::storage::tree) async fn audit_negative_chunk(store: &mut ServerTree, scope: &EpochScope, identity: Identity) {
    let encoded = ServerReader::scope(scope).unwrap();
    let scope = encoded.text().unwrap();
    store
        .session
        .client()
        .batch_execute("ALTER TABLE public.pn_epoch_package_chunks DROP CONSTRAINT pn_epoch_package_chunks_ordinal_check")
        .await
        .unwrap();
    store
        .session
        .client()
        .execute(
            "INSERT INTO public.pn_epoch_package_chunks(scope,identity,ordinal,bytes) VALUES ($1,$2,-1,$3)",
            &[&scope, &&identity[..], &b"audit-damage".as_slice()],
        )
        .await
        .unwrap();
}

pub(in crate::storage::tree) fn audit_root() -> (EpochScope, Identity) {
    let fork = forks();
    let (scope, identity, _, _) = fork.main[0].event();
    (scope.clone(), *identity)
}

pub(in crate::storage::tree) fn audit_scope(scope: &EpochScope) -> String {
    ServerReader::scope(scope).unwrap().text().unwrap().to_owned()
}

pub(in crate::storage::tree) async fn audit_clear_negative_chunk(store: &mut ServerTree, scope: &EpochScope, identity: Identity) {
    let encoded = ServerReader::scope(scope).unwrap();
    let scope = encoded.text().unwrap();
    store
        .session
        .client()
        .execute(
            "DELETE FROM public.pn_epoch_package_chunks WHERE scope=$1 AND identity=$2 AND ordinal=-1",
            &[&scope, &&identity[..]],
        )
        .await
        .unwrap();
    store.session.client().batch_execute(
        "ALTER TABLE public.pn_epoch_package_chunks ADD CONSTRAINT pn_epoch_package_chunks_ordinal_check CHECK (ordinal >= 0)"
    ).await.unwrap();
}

pub(in crate::storage::tree) async fn trace_fixture(store: &mut ServerTree) {
    if std::env::var("PN_HOST_STORAGE_READER_TRACE").as_deref() == Ok("audit") {
        audit_trace_fixture(store).await;
        return;
    }
    let f = forks();
    let mut reader = store.reader(allowance()).await.unwrap();
    let encoded = ServerReader::scope(f.main[0].event().0).unwrap();
    let scope = encoded.text().unwrap();
    let root = f.main[0].event().1;
    let parent = f.main[1].event().1;
    let origin = f.main[2].event().1;
    let root_bytes = &root[..];
    let parent_bytes = &parent[..];
    let origin_bytes = &origin[..];
    let selected = f.main[0]
        .declarations()
        .iter()
        .find(|u| u.version.family == Family::Rule)
        .unwrap();
    let family = selected.version.family.name();
    let coordinate = signed(selected.selected_at);
    let act = &f.main[2].debits()[0].key.act;
    let sequence = act.sequence.to_string();
    // This trace witnesses one bounded invocation of each closed statement.
    // Whole-reader semantic controls run separately without duplicating their
    // many ancestor validations inside the finite complete-evidence capture.
    let requests: Vec<(Statement, Vec<StatementParameter<'_>>, usize)> = vec![
        (Statement::HasEpoch, vec![&scope, &root_bytes], 7),
        (Statement::HasChild, vec![&scope, &root_bytes], 7),
        (Statement::ReadScope, vec![&scope], 50),
        (Statement::ReadEpoch, vec![&scope, &root_bytes], 278),
        (Statement::ReadEpochAsOf, vec![&scope, &root_bytes, &3_i64], 278),
        (Statement::ReadBranch, vec![&scope, &root_bytes], 170),
        (Statement::ReadEpochChunks, vec![&scope, &root_bytes, &1_i64], 262_174),
        (Statement::ReadAdmissionGeneration, vec![&scope, &1_i64], 1102),
        (Statement::ReadEpochReferences, vec![&scope, &root_bytes, &1_i64], 264_459),
        (
            Statement::ReadEpochUse,
            vec![&scope, &root_bytes, &coordinate, &family, &selected.version.key],
            264_459,
        ),
        (
            Statement::ReadAdmissionVersions,
            vec![&scope, &1_i64, &family, &selected.version.key, &None::<&str>, &1_i64],
            264_411,
        ),
        (
            Statement::ReadAdmissionClosures,
            vec![&scope, &1_i64, &family, &selected.version.key, &None::<&str>, &1_i64],
            2143,
        ),
        (
            Statement::ReadEpochDebitKeys,
            vec![&scope, &root_bytes, &1_i64, &3_i64, &1_i64],
            2178,
        ),
        (
            Statement::ReadDebit,
            vec![&scope, &origin_bytes, &act.author, &sequence, &act.family],
            38,
        ),
        (
            Statement::ReadDebitChunks,
            vec![&scope, &origin_bytes, &act.author, &sequence, &act.family, &1_i64],
            262_174,
        ),
        (Statement::ReadRoots, vec![&scope, &None::<&[u8]>, &1_i64], 50),
        (
            Statement::ReadChildren,
            vec![&scope, &None::<&[u8]>, &1_i64, &parent_bytes],
            50,
        ),
        (Statement::ReadResultCandidates, vec![&scope, &None::<&[u8]>, &1_i64], 50),
    ];
    for (statement, parameters, maximum) in requests {
        reader.request(statement, &parameters, 1, maximum, true).await.unwrap();
    }
    reader.end().await.unwrap();
    // The writer's first install and equal retry witness its six closed additions
    // in the same public-content capture as the established tree reads.
    let generation = super::super::tests::declared();
    assert!(
        store
            .install_generation(&generation, allowance(), &mut Usage::default())
            .await
            .unwrap()
    );
    assert!(
        !store
            .install_generation(&generation, allowance(), &mut Usage::default())
            .await
            .unwrap()
    );
    // The eight result inserts use one rollback-only fixture so the complete
    // trace stays within its existing finite evidence bound.
    store.session.client().batch_execute(
        "TRUNCATE pn_epoch_debit_chunks,pn_epoch_result_debits,pn_epoch_debits,pn_epoch_references,pn_epoch_package_chunks,pn_epoch_results,pn_epoch_branches,pn_epoch_scopes"
    ).await.unwrap();
    trace_result_inserts(store, scope, &selected.version).await;
}

pub(in crate::storage::tree) async fn audit_trace_fixture(store: &mut ServerTree) {
    let f = forks();
    let encoded = ServerReader::scope(f.main[0].event().0).unwrap();
    let scope = encoded.text().unwrap();
    let root = f.main[0].event().1;
    let selected = f.main[0]
        .declarations()
        .iter()
        .find(|use_| use_.version.family == Family::Rule)
        .unwrap();
    let family = selected.version.family.name();
    // The complete server controls exercise populated audits. This finite
    // trace captures each closed statement once with a one-row page.
    let beginning = true;
    let page = 1_i64;
    let ordinal = 1_i64;
    let zero = 0_i64;
    let identity = &root[..];
    let edition = selected.version.edition.as_str();
    let key = selected.version.key.as_str();
    let author = "trace-author";
    let sequence = "1";
    let act_family = "trace-family";
    let pages: Vec<(Statement, Vec<StatementParameter<'_>>)> = vec![
        (
            Statement::AuditAdmissionGenerations,
            vec![&beginning, &scope, &ordinal, &page],
        ),
        (
            Statement::AuditAdmissionVersions,
            vec![&beginning, &family, &key, &edition, &page],
        ),
        (
            Statement::AuditAdmissionClosures,
            vec![&beginning, &family, &key, &edition, &page],
        ),
        (Statement::AuditScopes, vec![&beginning, &scope, &page]),
        (Statement::AuditResults, vec![&beginning, &scope, &identity, &page]),
        (Statement::AuditSegments, vec![&beginning, &scope, &identity, &page]),
        (
            Statement::AuditResultChunks,
            vec![&beginning, &scope, &identity, &zero, &page],
        ),
        (
            Statement::AuditReferences,
            vec![&beginning, &scope, &identity, &zero, &family, &key, &page],
        ),
        (
            Statement::AuditDebits,
            vec![&beginning, &scope, &identity, &author, &sequence, &act_family, &page],
        ),
        (
            Statement::AuditDebitChunks,
            vec![&beginning, &scope, &identity, &author, &sequence, &act_family, &zero, &page],
        ),
        (
            Statement::AuditIntroductions,
            vec![&beginning, &scope, &identity, &author, &sequence, &act_family, &page],
        ),
    ];
    let probes: Vec<(Statement, Vec<StatementParameter<'_>>)> = vec![
        (Statement::AuditKeyMultiplicityAdmissionGenerations, vec![&scope, &ordinal]),
        (
            Statement::AuditKeyMultiplicityAdmissionVersions,
            vec![&family, &key, &edition],
        ),
        (
            Statement::AuditKeyMultiplicityAdmissionClosures,
            vec![&family, &key, &edition],
        ),
        (Statement::AuditKeyMultiplicityScopes, vec![&scope]),
        (Statement::AuditKeyMultiplicityResults, vec![&scope, &identity]),
        (Statement::AuditKeyMultiplicitySegments, vec![&scope, &identity]),
        (Statement::AuditKeyMultiplicityResultChunks, vec![&scope, &identity, &zero]),
        (
            Statement::AuditKeyMultiplicityReferences,
            vec![&scope, &identity, &zero, &family, &key],
        ),
        (
            Statement::AuditKeyMultiplicityDebits,
            vec![&scope, &identity, &author, &sequence, &act_family],
        ),
        (
            Statement::AuditKeyMultiplicityDebitChunks,
            vec![&scope, &identity, &author, &sequence, &act_family, &zero],
        ),
        (
            Statement::AuditKeyMultiplicityIntroductions,
            vec![&scope, &identity, &author, &sequence, &act_family],
        ),
    ];
    submit_audit_trace(store, pages, probes).await;
}

async fn submit_audit_trace(
    store: &mut ServerTree,
    pages: Vec<(Statement, Vec<StatementParameter<'_>>)>,
    probes: Vec<(Statement, Vec<StatementParameter<'_>>)>,
) {
    let audit = store
        .session
        .client
        .snapshot(store.session.store_requests.clone())
        .await
        .unwrap();
    let _: i64 = audit.query_one(Statement::AuditStoreIdentity, &[]).await.unwrap().get(0);
    for (statement, parameters) in pages {
        audit.query(statement, &parameters).await.unwrap();
    }
    audit.batch_execute(Statement::AuditVersionsOpen).await.unwrap();
    audit.query(Statement::AuditVersionsFetchOne, &[]).await.unwrap();
    audit.query(Statement::AuditVersionsFetchSixtyFour, &[]).await.unwrap();
    audit.batch_execute(Statement::AuditVersionsClose).await.unwrap();
    audit.batch_execute(Statement::AuditClosuresOpen).await.unwrap();
    audit.query(Statement::AuditClosuresFetchOne, &[]).await.unwrap();
    audit.query(Statement::AuditClosuresFetchSixtyFour, &[]).await.unwrap();
    audit.batch_execute(Statement::AuditClosuresClose).await.unwrap();
    for (statement, parameters) in probes {
        let _: i64 = audit.query_one(statement, &parameters).await.unwrap().get(0);
    }
    audit.commit().await.unwrap();
}

async fn trace_result_inserts(store: &mut ServerTree, scope: &str, version: &super::super::Version) {
    let identity = [0xAA_u8; 32];
    let identity = &identity[..];
    let one = 1_i64;
    let zero = 0_i64;
    let absent_bytes: Option<&[u8]> = None;
    let absent_depth: Option<i64> = None;
    let chunk = &[1_u8][..];
    let author = "trace-author";
    let sequence = "1";
    let family = "trace-family";
    let transaction = store
        .session
        .client
        .transaction(store.session.store_requests.clone())
        .await
        .unwrap();
    trace_insert(&transaction, Statement::InsertScope, &[&scope, &identity]).await;
    trace_insert(
        &transaction,
        Statement::InsertBranch,
        &[&scope, &identity, &one, &absent_bytes, &absent_bytes, &zero],
    )
    .await;
    trace_insert(
        &transaction,
        Statement::InsertEpoch,
        &[
            &scope,
            &identity,
            &one,
            &absent_bytes,
            &absent_depth,
            &absent_bytes,
            &identity,
            &one,
            &one,
            &one,
            &one,
            &one,
        ],
    )
    .await;
    trace_insert(&transaction, Statement::InsertEpochChunk, &[&scope, &identity, &zero, &chunk]).await;
    trace_insert(
        &transaction,
        Statement::InsertEpochReference,
        &[
            &scope,
            &identity,
            &zero,
            &version.family.name(),
            &version.key,
            &version.edition,
            &identity,
        ],
    )
    .await;
    trace_insert(
        &transaction,
        Statement::InsertDebit,
        &[&scope, &identity, &author, &sequence, &family, &one, &one, &one],
    )
    .await;
    trace_insert(
        &transaction,
        Statement::InsertDebitChunk,
        &[&scope, &identity, &author, &sequence, &family, &zero, &chunk],
    )
    .await;
    trace_insert(
        &transaction,
        Statement::InsertEpochDebit,
        &[&scope, &identity, &identity, &one, &author, &sequence, &family],
    )
    .await;
    assert_eq!(
        transaction.refuse(StorageError::CorruptHistory).await,
        StorageError::CorruptHistory
    );
}

async fn trace_insert(transaction: &StatementTransaction<'_>, statement: Statement, params: &[StatementParameter<'_>]) {
    assert_eq!(transaction.execute(statement, params).await.unwrap(), 1);
}
