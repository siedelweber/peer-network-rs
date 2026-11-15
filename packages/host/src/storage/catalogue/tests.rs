use super::*;

mod bounds;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

async fn session(name: &str) -> Session {
    let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
    let mut file = std::fs::File::open(std::path::Path::new(&root).join(name)).unwrap();
    let config = crate::Configuration::acquire(Some("host-secured"), &mut file).unwrap();
    Session::connect(config).await.unwrap()
}

async fn shape(session: &Session) -> String {
    session.client().query_one("SELECT json_build_array((SELECT json_agg(x ORDER BY name) FROM (SELECT c.relname AS name,pg_get_indexdef(i.indexrelid) AS definition,i.indisvalid,i.indisready FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relnamespace='public'::regnamespace) x),(SELECT json_agg(x ORDER BY name) FROM (SELECT c.conname AS name,pg_get_constraintdef(c.oid) AS definition,c.conenforced,c.convalidated FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid WHERE r.relnamespace='public'::regnamespace) x),(SELECT json_agg(x ORDER BY relation,ordinal) FROM (SELECT r.relname AS relation,a.attnum AS ordinal,a.attname,format_type(a.atttypid,a.atttypmod) AS kind,a.attnotnull,a.attcollation FROM pg_attribute a JOIN pg_class r ON r.oid=a.attrelid WHERE r.relnamespace='public'::regnamespace AND r.relkind='r' AND a.attnum>0 AND NOT a.attisdropped) x))::text", &[]).await.unwrap().get(0)
}

/// Claim: The exact eleven-relation tree catalogue creates and reopens without repair; independent catalogue definition and execution-property variants refuse without changing their definitions, while first-layout and obsolete chain catalogues are not adopted.
/// ´claim:history:tree-catalogue-exact´
/// ´test:unit:tree-catalogue-exact´
#[test]
fn tree_catalogue_exact() {
    runtime().block_on(async {
        let mut connection = session("storage-tree-schema.json").await;
        open(&mut connection).await.unwrap();
        let owner = &connection;
        let original = shape(owner).await;
        open(&mut session("storage-tree-schema.json").await).await.unwrap();
        assert_eq!(shape(owner).await, original, "reopen never repairs");
        let variants = [
            ("ALTER TABLE pn_epoch_package_chunks ADD surplus bigint", "ALTER TABLE pn_epoch_package_chunks DROP surplus"),
            ("ALTER TABLE pn_epoch_results ALTER reference_count DROP NOT NULL", "ALTER TABLE pn_epoch_results ALTER reference_count SET NOT NULL"),
            ("ALTER TABLE pn_epoch_package_chunks ALTER ordinal TYPE integer", "ALTER TABLE pn_epoch_package_chunks ALTER ordinal TYPE bigint"),
            ("ALTER TABLE pn_admission_generations ALTER label TYPE text COLLATE \"POSIX\"", "ALTER TABLE pn_admission_generations ALTER label TYPE text COLLATE \"C\""),
            ("ALTER TABLE pn_epoch_package_chunks ADD CHECK (ordinal < 100)", "ALTER TABLE pn_epoch_package_chunks DROP CONSTRAINT pn_epoch_package_chunks_ordinal_check1"),
            ("ALTER TABLE pn_epoch_package_chunks DROP CONSTRAINT pn_epoch_package_chunks_ordinal_check", "ALTER TABLE pn_epoch_package_chunks ADD CHECK (ordinal >= 0)"),
            ("ALTER TABLE pn_epoch_package_chunks ALTER CONSTRAINT pn_epoch_package_chunks_ordinal_check NOT ENFORCED", "ALTER TABLE pn_epoch_package_chunks ALTER CONSTRAINT pn_epoch_package_chunks_ordinal_check ENFORCED"),
            ("ALTER TABLE pn_epoch_package_chunks ALTER CONSTRAINT pn_epoch_package_chunks_scope_identity_fkey DEFERRABLE INITIALLY DEFERRED", "ALTER TABLE pn_epoch_package_chunks ALTER CONSTRAINT pn_epoch_package_chunks_scope_identity_fkey NOT DEFERRABLE"),
            ("ALTER TABLE pn_epoch_scopes ALTER CONSTRAINT pn_epoch_scopes_scope_context_root_fkey INITIALLY IMMEDIATE", "ALTER TABLE pn_epoch_scopes ALTER CONSTRAINT pn_epoch_scopes_scope_context_root_fkey INITIALLY DEFERRED"),
            ("ALTER TABLE pn_epoch_package_chunks DROP CONSTRAINT pn_epoch_package_chunks_scope_identity_fkey; ALTER TABLE pn_epoch_package_chunks ADD FOREIGN KEY(scope,identity) REFERENCES pn_epoch_results(scope,identity) ON DELETE CASCADE", "ALTER TABLE pn_epoch_package_chunks DROP CONSTRAINT pn_epoch_package_chunks_scope_identity_fkey; ALTER TABLE pn_epoch_package_chunks ADD FOREIGN KEY(scope,identity) REFERENCES pn_epoch_results(scope,identity)"),
            ("ALTER TABLE pn_epoch_package_chunks DROP CONSTRAINT pn_epoch_package_chunks_scope_identity_fkey; ALTER TABLE pn_epoch_package_chunks ADD FOREIGN KEY(scope,identity) REFERENCES pn_epoch_results(scope,identity) MATCH FULL", "ALTER TABLE pn_epoch_package_chunks DROP CONSTRAINT pn_epoch_package_chunks_scope_identity_fkey; ALTER TABLE pn_epoch_package_chunks ADD FOREIGN KEY(scope,identity) REFERENCES pn_epoch_results(scope,identity)"),
            ("ALTER TABLE pn_admission_generations DROP CONSTRAINT pn_admission_generations_scope_label_key; ALTER TABLE pn_admission_generations ADD UNIQUE NULLS NOT DISTINCT(scope,label)", "ALTER TABLE pn_admission_generations DROP CONSTRAINT pn_admission_generations_scope_label_key; ALTER TABLE pn_admission_generations ADD UNIQUE(scope,label)"),
        ];
        for (change, restore) in variants {
            owner.client().batch_execute(change).await.unwrap();
            let changed = shape(owner).await;
            assert_eq!(open(&mut session("storage-tree-schema.json").await).await, Err(StorageError::IndexDefinition), "catalogue variant: {change}");
            assert_eq!(shape(owner).await, changed, "refusal leaves the changed catalogue intact");
            owner.client().batch_execute(restore).await.unwrap();
            open(&mut session("storage-tree-schema.json").await).await.unwrap();
        }
        for definition in [
            "ON pn_epoch_results(scope,identity,parent)",
            "ON pn_epoch_results(scope,parent,identity DESC)",
            "ON pn_epoch_results(scope,parent NULLS FIRST,identity)",
            "ON pn_epoch_results(scope COLLATE \"POSIX\",parent,identity)",
            "UNIQUE ON pn_epoch_results(scope,parent,identity)",
            "ON pn_epoch_results(scope,parent,identity) INCLUDE(depth)",
            "ON pn_epoch_results(scope,parent,identity) WHERE parent IS NOT NULL",
            "ON pn_epoch_results(scope,parent,(identity || ''::bytea))",
            "ON pn_epoch_branches(scope,parent_segment,segment)",
            "ON pn_epoch_results USING hash(identity)",
        ] {
            let (unique, definition) = definition.strip_prefix("UNIQUE ").map_or(("", definition), |definition| ("UNIQUE ", definition));
            owner.client().batch_execute(&format!("DROP INDEX pn_epoch_results_children; CREATE {unique}INDEX pn_epoch_results_children {definition}")).await.unwrap();
            let changed = shape(owner).await;
            assert_eq!(open(&mut session("storage-tree-schema.json").await).await, Err(StorageError::IndexDefinition), "index variant: {definition}");
            assert_eq!(shape(owner).await, changed);
            owner.client().batch_execute("DROP INDEX pn_epoch_results_children; CREATE INDEX pn_epoch_results_children ON pn_epoch_results(scope,parent,identity)").await.unwrap();
        }
        for field in ["indisvalid", "indisready"] {
            owner.client().batch_execute(&format!("UPDATE pg_index SET {field}=false WHERE indexrelid='pn_epoch_results_children'::regclass")).await.unwrap();
            let changed = shape(owner).await;
            assert_eq!(open(&mut session("storage-tree-schema.json").await).await, Err(StorageError::IndexDefinition), "index state: {field}");
            assert_eq!(shape(owner).await, changed, "index state remains unchanged: {field}");
            owner.client().batch_execute(&format!("UPDATE pg_index SET {field}=true WHERE indexrelid='pn_epoch_results_children'::regclass")).await.unwrap();
        }
        owner.client().batch_execute("CREATE INDEX surplus ON pn_epoch_results(depth)").await.unwrap();
        let changed = shape(owner).await;
        assert_eq!(open(&mut session("storage-tree-schema.json").await).await, Err(StorageError::IndexDefinition), "surplus index");
        assert_eq!(shape(owner).await, changed);
        owner.client().batch_execute("DROP INDEX surplus; DROP INDEX pn_epoch_results_children").await.unwrap();
        let changed = shape(owner).await;
        assert_eq!(open(&mut session("storage-tree-schema.json").await).await, Err(StorageError::IndexDefinition), "missing index");
        assert_eq!(shape(owner).await, changed);
        owner.client().batch_execute("CREATE INDEX pn_epoch_results_children ON pn_epoch_results(scope,parent,identity)").await.unwrap();
        open(&mut session("storage-tree-schema.json").await).await.unwrap();
        execution_properties(owner).await;
        owner.client().batch_execute("DROP TABLE public.pn_admission_generations,public.pn_admission_versions,public.pn_admission_closures,public.pn_epoch_scopes,public.pn_epoch_branches,public.pn_epoch_results,public.pn_epoch_package_chunks,public.pn_epoch_references,public.pn_epoch_debits,public.pn_epoch_debit_chunks,public.pn_epoch_result_debits,public.pn_closures,public.pn_versions,public.pn_store_identity").await.unwrap();
        owner.client().batch_execute(&Statement::Create.sql().replace("PRIMARY KEY(family,key,edition)", "PRIMARY KEY(key,family,edition)")).await.unwrap();
        owner.client().batch_execute(Statement::EnsureIndexes.sql()).await.unwrap();
        owner.client().batch_execute(CREATE).await.unwrap();
        owner.client().execute("INSERT INTO pn_store_identity VALUES($1)", &[&IDENTITY]).await.unwrap();
        let changed = shape(owner).await;
        assert_eq!(open(&mut session("storage-tree-schema.json").await).await, Err(StorageError::IndexDefinition), "history primary-key order is verified even when its foreign keys match");
        assert_eq!(shape(owner).await, changed);

        let foreign=session("storage-tree-foreign.json").await;
        foreign.client().batch_execute("CREATE TABLE fixture_foreign(value bigint)").await.unwrap();
        let before=shape(&foreign).await;
        assert_eq!(open(&mut session("storage-tree-foreign.json").await).await,Err(StorageError::SchemaIdentity),"tables without identity are never adopted");
        assert_eq!(shape(&foreign).await,before);
        foreign.client().batch_execute("DROP TABLE fixture_foreign").await.unwrap();
        let old = super::super::PostgresStore::open_store(session("storage-tree-foreign.json").await).await.unwrap();
        assert_eq!(open(&mut session("storage-tree-foreign.json").await).await, Err(StorageError::SchemaIdentity));
        old.session.client().batch_execute("UPDATE pn_store_identity SET identity='pn-host/effective-history/v2'; CREATE TABLE pn_epoch_results(scope text,boundary bigint,predecessor bigint)").await.unwrap();
        let before = shape(&old.session).await;
        assert_eq!(open(&mut session("storage-tree-foreign.json").await).await, Err(StorageError::IndexDefinition));
        assert_eq!(shape(&old.session).await, before, "obsolete chain catalogue is not migrated");
        cli_common::emit(&serde_json::json!({"kind":"tree_catalogue","variants":variants.len()+32,"refused_layouts":2})).unwrap();
    });
}

async fn execution_properties(owner: &Session) {
    owner
        .client()
        .batch_execute("CREATE FUNCTION public.fixture_trigger() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$")
        .await
        .unwrap();
    let variants = [
        (
            "ALTER TABLE pn_epoch_package_chunks DISABLE TRIGGER ALL",
            "ALTER TABLE pn_epoch_package_chunks ENABLE TRIGGER ALL",
        ),
        (
            "CREATE TRIGGER fixture_user BEFORE INSERT ON pn_epoch_package_chunks FOR EACH ROW EXECUTE FUNCTION fixture_trigger()",
            "DROP TRIGGER fixture_user ON pn_epoch_package_chunks",
        ),
        (
            "CREATE RULE fixture_rule AS ON INSERT TO pn_epoch_package_chunks DO ALSO NOTHING",
            "DROP RULE fixture_rule ON pn_epoch_package_chunks",
        ),
        (
            "ALTER TABLE pn_epoch_package_chunks ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE pn_epoch_package_chunks DISABLE ROW LEVEL SECURITY",
        ),
        (
            "ALTER TABLE pn_epoch_package_chunks FORCE ROW LEVEL SECURITY",
            "ALTER TABLE pn_epoch_package_chunks NO FORCE ROW LEVEL SECURITY",
        ),
        (
            "CREATE TABLE fixture_child() INHERITS(pn_epoch_package_chunks)",
            "DROP TABLE fixture_child",
        ),
        (
            "ALTER TABLE pn_epoch_package_chunks SET UNLOGGED",
            "ALTER TABLE pn_epoch_package_chunks SET LOGGED",
        ),
        (
            "ALTER INDEX pn_epoch_results_children RENAME TO fixture_renamed",
            "ALTER INDEX fixture_renamed RENAME TO pn_epoch_results_children",
        ),
        (
            "UPDATE pg_constraint SET convalidated=false WHERE conrelid='pn_epoch_package_chunks'::regclass AND conname='pn_epoch_package_chunks_ordinal_check'",
            "UPDATE pg_constraint SET convalidated=true WHERE conrelid='pn_epoch_package_chunks'::regclass AND conname='pn_epoch_package_chunks_ordinal_check'",
        ),
        (
            "UPDATE pg_attribute SET attnum=-99 WHERE attrelid='pn_epoch_results'::regclass AND attname='reference_count'; UPDATE pg_attribute SET attnum=11 WHERE attrelid='pn_epoch_results'::regclass AND attname='debit_count'; UPDATE pg_attribute SET attnum=12 WHERE attrelid='pn_epoch_results'::regclass AND attname='reference_count'",
            "UPDATE pg_attribute SET attnum=-99 WHERE attrelid='pn_epoch_results'::regclass AND attname='debit_count'; UPDATE pg_attribute SET attnum=11 WHERE attrelid='pn_epoch_results'::regclass AND attname='reference_count'; UPDATE pg_attribute SET attnum=12 WHERE attrelid='pn_epoch_results'::regclass AND attname='debit_count'",
        ),
    ];
    for (change, restore) in variants {
        owner.client().batch_execute(change).await.unwrap();
        let before = execution_shape(owner).await;
        assert_eq!(
            open(&mut session("storage-tree-schema.json").await).await,
            Err(StorageError::IndexDefinition),
            "execution property: {change}"
        );
        assert_eq!(
            execution_shape(owner).await,
            before,
            "execution-property refusal never repairs"
        );
        owner.client().batch_execute(restore).await.unwrap();
        open(&mut session("storage-tree-schema.json").await).await.unwrap();
    }
    history_properties(owner).await;
    owner.client().batch_execute("DROP FUNCTION fixture_trigger()").await.unwrap();
}

async fn execution_shape(owner: &Session) -> String {
    let rows: String=owner.client().query_one("SELECT json_build_array((SELECT json_agg(r ORDER BY oid) FROM pg_class r WHERE relnamespace='public'::regnamespace),(SELECT json_agg(t ORDER BY oid) FROM pg_trigger t WHERE tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace)),(SELECT json_agg(w ORDER BY oid) FROM pg_rewrite w WHERE ev_class IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace)),(SELECT json_agg(h ORDER BY inhrelid,inhseqno) FROM pg_inherits h),(SELECT json_agg(c ORDER BY oid) FROM pg_constraint c WHERE connamespace='public'::regnamespace))::text",&[]).await.unwrap().get(0);
    format!("{} {rows}", shape(owner).await)
}

async fn history_properties(owner: &Session) {
    for field in ["convalidated", "conenforced", "condeferrable", "condeferred"] {
        let value = matches!(field, "condeferrable" | "condeferred");
        owner
            .client()
            .batch_execute(&format!(
                "UPDATE pg_constraint SET {field}={value} WHERE conrelid='pn_versions'::regclass AND contype='p'"
            ))
            .await
            .unwrap();
        let before = execution_shape(owner).await;
        assert_eq!(
            open(&mut session("storage-tree-schema.json").await).await,
            Err(StorageError::IndexDefinition),
            "history constraint property: {field}"
        );
        assert_eq!(execution_shape(owner).await, before);
        owner
            .client()
            .batch_execute(&format!(
                "UPDATE pg_constraint SET {field}={} WHERE conrelid='pn_versions'::regclass AND contype='p'",
                !value
            ))
            .await
            .unwrap();
    }
    for field in ["indisvalid", "indisready", "indnullsnotdistinct"] {
        let value = field == "indnullsnotdistinct";
        owner
            .client()
            .batch_execute(&format!(
                "UPDATE pg_index SET {field}={value} WHERE indexrelid='pn_versions_pkey'::regclass"
            ))
            .await
            .unwrap();
        let before = execution_shape(owner).await;
        assert_eq!(
            open(&mut session("storage-tree-schema.json").await).await,
            Err(StorageError::IndexDefinition),
            "history index property: {field}"
        );
        assert_eq!(execution_shape(owner).await, before);
        owner
            .client()
            .batch_execute(&format!(
                "UPDATE pg_index SET {field}={} WHERE indexrelid='pn_versions_pkey'::regclass",
                !value
            ))
            .await
            .unwrap();
    }
}
