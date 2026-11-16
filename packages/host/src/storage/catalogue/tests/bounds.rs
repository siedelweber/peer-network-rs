use super::*;

const RELATIONS: [&str; 11] = [
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
];

fn public_text(size: usize, mut state: u64) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            char::from(alphabet[(state & 63) as usize])
        })
        .collect()
}

async fn attempt(session: &Session, sql: &str) -> String {
    session
        .client()
        .query_one("SELECT public.pn_fixture_attempt($1)", &[&sql])
        .await
        .unwrap()
        .get(0)
}

async fn runtime_session() -> Session {
    session("storage-tree-runtime.json").await
}

async fn populate(owner: &Session, seed: u64) {
    let scope = public_text(1024, 281 + seed);
    let key = public_text(1024, 282 + seed);
    let edition = public_text(1024, 283 + seed);
    let label = public_text(1024, 284 + seed);
    let root = vec![1_u8; 32];
    let child = vec![2_u8; 32];
    owner.client().batch_execute("BEGIN").await.unwrap();
    owner.client().execute("INSERT INTO pn_versions VALUES ('constants',$1,$2,0,9223372036854775807,NULL,NULL,NULL),('unsettled-recognition',$1,$2,0,9223372036854775807,NULL,NULL,$3)", &[&key,&edition,&root]).await.unwrap();
    owner.client().execute("INSERT INTO pn_closures VALUES ('constants',$1,$2,9223372036854775807),('unsettled-recognition',$1,$2,9223372036854775807)", &[&key,&edition]).await.unwrap();
    owner
        .client()
        .execute(
            "INSERT INTO pn_admission_generations VALUES($1,1,$2,NULL,1,9223372036854775807,9223372036854775807)",
            &[&scope, &label],
        )
        .await
        .unwrap();
    owner
        .client()
        .execute(
            "INSERT INTO pn_admission_versions VALUES($1,1,'constants',$2,$3)",
            &[&scope, &key, &edition],
        )
        .await
        .unwrap();
    owner
        .client()
        .execute(
            "INSERT INTO pn_admission_closures VALUES($1,1,'constants',$2,$3)",
            &[&scope, &key, &edition],
        )
        .await
        .unwrap();
    owner
        .client()
        .execute("INSERT INTO pn_epoch_scopes VALUES($1,$2)", &[&scope, &root])
        .await
        .unwrap();
    owner
        .client()
        .execute("INSERT INTO pn_epoch_branches VALUES($1,$2,1,NULL,NULL,0)", &[&scope, &root])
        .await
        .unwrap();
    owner.client().execute("INSERT INTO pn_epoch_results VALUES($1,$2,1,NULL,NULL,NULL,$2,1,9223372036854775807,9223372036854775807,9223372036854775807,9223372036854775807)", &[&scope,&root]).await.unwrap();
    owner
        .client()
        .execute(
            "INSERT INTO pn_epoch_results VALUES($1,$3,2,$2,1,$2,$2,1,1,1,0,0)",
            &[&scope, &root, &child],
        )
        .await
        .unwrap();
    owner
        .client()
        .execute(
            "INSERT INTO pn_epoch_package_chunks VALUES($1,$2,9223372036854775807,$3)",
            &[&scope, &root, &vec![4_u8; 262_144]],
        )
        .await
        .unwrap();
    owner
        .client()
        .execute(
            "INSERT INTO pn_epoch_references VALUES($1,$2,9223372036854775807,'unsettled-recognition',$3,$4,$2)",
            &[&scope, &root, &key, &edition],
        )
        .await
        .unwrap();
    populate_vintage(owner, seed, &root).await;
    owner.client().batch_execute("COMMIT").await.unwrap();
}

async fn populate_vintage(owner: &Session, seed: u64, root: &[u8]) {
    // The framed vintage budget includes its scope and three act fields.
    // This independent scope lets the vintage use its full 1,024 bytes.
    let small = format!("4:1:{seed}0:0:0:");
    let sequence = "18446744073709551615";
    let family = public_text(127, 285 + seed);
    let author = public_text(855, 286 + seed);
    assert_eq!(small.len() + author.len() + 4 + sequence.len() + 3 + family.len() + 4, 1024);
    owner
        .client()
        .execute(
            "INSERT INTO pn_admission_generations VALUES($1,1,'unstable',NULL,1,0,0);",
            &[&small],
        )
        .await
        .unwrap();
    owner
        .client()
        .execute("INSERT INTO pn_epoch_scopes VALUES($1,$2)", &[&small, &root])
        .await
        .unwrap();
    owner
        .client()
        .execute("INSERT INTO pn_epoch_branches VALUES($1,$2,1,NULL,NULL,0)", &[&small, &root])
        .await
        .unwrap();
    owner
        .client()
        .execute(
            "INSERT INTO pn_epoch_results VALUES($1,$2,1,NULL,NULL,NULL,$2,1,1,1,0,0)",
            &[&small, &root],
        )
        .await
        .unwrap();
    owner
        .client()
        .execute(
            "INSERT INTO pn_epoch_debits VALUES($1,$2,$3,$4,$5,9223372036854775807,9223372036854775807,9223372036854775807)",
            &[&small, &root, &author, &sequence, &family],
        )
        .await
        .unwrap();
    owner
        .client()
        .execute(
            "INSERT INTO pn_epoch_debit_chunks VALUES($1,$2,$3,$4,$5,9223372036854775807,$6)",
            &[&small, &root, &author, &sequence, &family, &vec![5_u8; 262_144]],
        )
        .await
        .unwrap();
    owner
        .client()
        .execute(
            "INSERT INTO pn_epoch_result_debits VALUES($1,$2,$2,1,$3,$4,$5)",
            &[&small, &root, &author, &sequence, &family],
        )
        .await
        .unwrap();
}

/// Claim: The real tree catalogue retains independent maximum text budgets through every index, whose leaf-entry sizes and current server limit are measured; owner and runtime constraint attempts agree, runtime catalogue verification and SELECT/INSERT succeed, its exact table and column SELECT/INSERT privilege set is checked on every tree relation, and UPDATE/DELETE and persistent DDL including schema creation refuse with SQLSTATE 42501.
/// ´claim:history:tree-catalogue-bounds-and-roles´
/// ´test:unit:tree-catalogue-bounds-and-roles´
#[test]
fn tree_catalogue_bounds_and_roles() {
    runtime().block_on(async {
        let mut connection = session("storage-tree-bounds.json").await;
        open(&mut connection).await.unwrap();
        let owner = &connection;
        owner.client().batch_execute("CREATE EXTENSION pageinspect; CREATE FUNCTION public.pn_fixture_attempt(command text) RETURNS text LANGUAGE plpgsql AS $$ BEGIN EXECUTE command; RETURN '00000'; EXCEPTION WHEN OTHERS THEN RETURN SQLSTATE; END $$; CREATE ROLE tree_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'public-tree-role-fixture'; REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT CONNECT ON DATABASE private_storage_tree_bounds_731 TO tree_runtime; GRANT USAGE ON SCHEMA public TO tree_runtime; GRANT SELECT ON pn_store_identity,pn_versions,pn_closures TO tree_runtime; GRANT INSERT ON pn_versions,pn_closures TO tree_runtime; GRANT MAINTAIN ON pn_versions TO tree_runtime").await.unwrap();
        for name in RELATIONS {
            owner.client().batch_execute(&format!("GRANT SELECT,INSERT ON {name} TO tree_runtime")).await.unwrap();
        }
        populate(owner, 0).await;
        let indexes = owner.client().query("SELECT c.relname::text FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_class r ON r.oid=i.indrelid WHERE r.relnamespace='public'::regnamespace ORDER BY c.relname", &[]).await.unwrap();
        for index in &indexes {
            let name: String=index.get(0);
            let sizes=owner.client().query("SELECT itemlen::int4 FROM bt_page_items($1,1)", &[&name]).await.unwrap();
            assert!(!sizes.is_empty(), "index has a measured entry: {name}");
            let maximum=sizes.iter().map(|r|r.get::<_,i32>(0)).max().unwrap();
            assert!(maximum<=2704,"entry fits pinned btree: {name} {maximum}");
            cli_common::emit(&serde_json::json!({"kind":"tree_index_size","index":name,"measured":maximum,"entries":sizes.len()})).unwrap();
        }
        measure_limit(owner).await;
        open(&mut runtime_session().await).await.unwrap();
        let runtime=runtime_session().await;
        populate(&runtime, 1).await;
        for (name, per_input) in RELATIONS.into_iter().zip([2_i64,1,1,2,2,3,1,1,1,1,1]) {
            let count: i64=runtime.client().query_one(&format!("SELECT count(*) FROM {name}"), &[]).await.unwrap().get(0);
            assert_eq!(count,2*per_input,"owner and runtime populate every relation: {name}");
            assert_eq!(attempt(&runtime,&format!("INSERT INTO {name} SELECT * FROM {name} WHERE false")).await,"00000","runtime INSERT privilege {name}");
            assert_eq!(attempt(&runtime,&format!("UPDATE {name} SET scope=scope")).await,"42501","runtime UPDATE {name}");
            assert_eq!(attempt(&runtime,&format!("DELETE FROM {name}")).await,"42501","runtime DELETE {name}");
            let privileges = runtime_privileges(&runtime, name).await;
            assert!(privileges,"runtime privilege set {name}");
        }
        owner.client().batch_execute("GRANT UPDATE(depth) ON pn_epoch_results TO tree_runtime").await.unwrap();
        assert!(!runtime_privileges(&runtime, "pn_epoch_results").await, "column UPDATE grant is outside runtime privileges");
        owner.client().batch_execute("REVOKE UPDATE(depth) ON pn_epoch_results FROM tree_runtime").await.unwrap();
        assert!(runtime_privileges(&runtime, "pn_epoch_results").await, "column grant restoration");
        for sql in ["CREATE SCHEMA forbidden", "CREATE TABLE public.forbidden(value bigint)","ALTER TABLE pn_epoch_results ADD forbidden bigint","CREATE SEQUENCE public.forbidden"] {
            assert_eq!(attempt(&runtime,sql).await,"42501","runtime DDL {sql}");
        }
        for sql in [
            "INSERT INTO pn_admission_generations VALUES('public-invalid',0,'unstable',NULL,1,0,0)",
            "INSERT INTO pn_admission_generations VALUES('public-invalid',1,'unstable',NULL,0,0,0)",
            "INSERT INTO pn_admission_generations VALUES('public-invalid',1,'unstable',NULL,1,-1,0)",
            "INSERT INTO pn_admission_generations VALUES('public-invalid',1,NULL,NULL,1,0,0)",
            "INSERT INTO pn_epoch_package_chunks VALUES('public-missing',decode(repeat('00',32),'hex'),0,decode('01','hex'))",
            "INSERT INTO pn_admission_versions VALUES('public-invalid',1,'marker-policy','k','e')",
            "INSERT INTO pn_admission_closures VALUES('public-invalid',1,'marker-policy','k','e')",
            "INSERT INTO pn_epoch_scopes VALUES('public-invalid',decode('00','hex'))",
            "INSERT INTO pn_epoch_branches VALUES('public-invalid',decode(repeat('00',32),'hex'),0,NULL,NULL,0)",
            "INSERT INTO pn_epoch_results VALUES('public-invalid',decode(repeat('00',32),'hex'),0,NULL,NULL,NULL,decode(repeat('00',32),'hex'),1,1,1,0,0)",
            "INSERT INTO pn_epoch_references VALUES('public-invalid',decode(repeat('00',32),'hex'),-1,'rule','k','e',decode(repeat('00',32),'hex'))",
            "INSERT INTO pn_epoch_debits VALUES('public-invalid',decode(repeat('00',32),'hex'),'a','00','Opinion',1,1,1)",
            "INSERT INTO pn_epoch_debit_chunks VALUES('public-invalid',decode(repeat('00',32),'hex'),'a','0','Opinion',-1,decode('01','hex'))",
            "INSERT INTO pn_epoch_result_debits VALUES('public-invalid',decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),0,'a','0','Opinion')",
        ] {
            let expected=if sql.contains("1,NULL,NULL,1,0,0") {"23502"} else if sql.contains("public-missing") {"23503"} else {"23514"};
            assert_eq!(attempt(owner,sql).await,expected,"owner constraint {sql}");
            assert_eq!(attempt(&runtime,sql).await,expected,"runtime constraint {sql}");
        }
        assert_eq!(attempt(&runtime,"INSERT INTO pn_admission_generations VALUES('runtime-public',1,'unstable',NULL,1,0,0)").await,"00000","runtime insertion granted");
        cli_common::emit(&serde_json::json!({"kind":"tree_catalogue_roles","indexed_relations":14,"indexes":indexes.len(),"runtime_relations":11})).unwrap();
        let raw = session("storage-tree-bounds.json").await;
        raw.client().batch_execute("SET log_error_verbosity='verbose'").await.unwrap();
        assert!(raw.client().query_one("SELECT $1::text", &[&"public\0bound-parameter"]).await.is_err(), "the service refuses U+0000 delivered as a bound parameter");
        assert_eq!(raw.last_refusal(), Some(crate::Refusal::PrivateDiagnostic), "the unclassified server diagnostic stays protected");
    });
}

async fn measure_limit(owner: &Session) {
    owner
        .client()
        .batch_execute(
            "CREATE TABLE fixture_limit(value text COLLATE \"C\"); CREATE INDEX fixture_limit_index ON fixture_limit(value)",
        )
        .await
        .unwrap();
    let mut low = 1_usize;
    let mut high = 4000_usize;
    while low + 1 < high {
        let length = usize::midpoint(low, high);
        let value = public_text(length, 723);
        let outcome = attempt(owner, &format!("INSERT INTO fixture_limit VALUES('{value}')")).await;
        if outcome == "00000" {
            low = length;
        } else {
            assert_eq!(outcome, "54000", "btree refusal class");
            high = length;
        }
        owner.client().batch_execute("TRUNCATE fixture_limit").await.unwrap();
    }
    let value = public_text(low, 723);
    owner
        .client()
        .execute("INSERT INTO fixture_limit VALUES($1)", &[&value])
        .await
        .unwrap();
    let limit: i32 = owner
        .client()
        .query_one("SELECT max(itemlen)::int4 FROM bt_page_items('fixture_limit_index',1)", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(limit, 2704, "pinned service btree limit read back");
    let value = public_text(high, 723);
    assert_eq!(
        attempt(owner, &format!("INSERT INTO fixture_limit VALUES('{value}')")).await,
        "54000",
        "next entry refuses"
    );
    cli_common::emit(&serde_json::json!({"kind":"tree_index_limit","measured":limit,"accepted_text":low,"refused_text":high,"largest_margin":limit-2136,"generation_margin":limit-2088})).unwrap();
    owner.client().batch_execute("DROP TABLE fixture_limit").await.unwrap();
}

async fn runtime_privileges(runtime: &Session, name: &str) -> bool {
    runtime.client().query_one("SELECT has_table_privilege(current_user,$1,'SELECT') AND has_table_privilege(current_user,$1,'INSERT') AND NOT has_table_privilege(current_user,$1,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AND NOT has_any_column_privilege(current_user,$1,'UPDATE,REFERENCES')", &[&name]).await.unwrap().get(0)
}
