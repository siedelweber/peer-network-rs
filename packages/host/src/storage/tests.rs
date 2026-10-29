use super::*;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}
async fn store(name: &str) -> PostgresStore {
    let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
    let mut file = std::fs::File::open(std::path::Path::new(&root).join(name)).unwrap();
    let config = crate::Configuration::acquire(Some("host-secured"), &mut file).unwrap();
    PostgresStore::open_store(Session::connect(config).await.unwrap())
        .await
        .unwrap()
}
fn version(family: Family, key: &str, edition: &str, at: u64, value: Option<u64>) -> Version {
    Version {
        family,
        key: key.into(),
        edition: edition.into(),
        announced_at: at,
        opens_at: at,
        payload: value.map(|v| {
            if family == Family::UnsettledRecognition {
                let input = Value::Unsigned(v);
                let commitment = digest(DISCLOSURE_RECIPE, &input.to_canonical_bytes());
                Payload::encoded(
                    family,
                    encoding::array([
                        encoding::text(DISCLOSURE_RECIPE),
                        Value::Bytes(commitment.to_vec().into()),
                        input,
                        Value::Null,
                    ]),
                    Some(commitment),
                )
                .unwrap()
            } else {
                Payload::encoded(family, Value::Unsigned(v), None).unwrap()
            }
        }),
    }
}
fn prior(edition: &str, at: u64) -> Predecessor {
    Predecessor {
        edition: edition.into(),
        closes_at: at,
    }
}
enum Adapter {
    Memory(MemoryStore),
    Postgres(PostgresStore),
}
impl Adapter {
    async fn append(&mut self, v: Version, p: Option<&Predecessor>) -> Result<bool, StorageError> {
        match self {
            Self::Memory(s) => s.append_effective_successor(v, p),
            Self::Postgres(s) => s.append_effective_successor(v, p).await,
        }
    }
    async fn load(&mut self, at: u64, required: &[(Family, String)]) -> Result<Boundary, StorageError> {
        match self {
            Self::Memory(s) => s.load_boundary(at, required),
            Self::Postgres(s) => s.load_boundary(at, required).await,
        }
    }
    async fn interrupted(&mut self, v: Version, p: &Predecessor, phase: u8) -> Result<bool, StorageError> {
        match self {
            Self::Memory(s) => {
                let mut scratch = s.history.clone();
                append(&mut scratch, v, Some(p))?;
                Err(StorageError::Injected)
            }
            Self::Postgres(s) => s.append_inner(v, Some(p), phase).await,
        }
    }
}
async fn selected(adapter: &mut Adapter, family: Family, at: u64, required: &[(Family, String)]) -> Version {
    adapter
        .load(at, required)
        .await
        .unwrap()
        .rows
        .into_iter()
        .find(|row| row.version.family == family)
        .unwrap()
        .version
}
async fn representation(adapter: &mut Adapter) {
    for (key, edition) in [
        ("k".repeat(1024), "edition".into()),
        ("edition-bound".into(), "e".repeat(1024)),
    ] {
        let input = version(Family::Rule, &key, &edition, 1, Some(1));
        assert!(adapter.append(input.clone(), None).await.unwrap());
        assert!(
            adapter
                .load(1, &[])
                .await
                .unwrap()
                .rows
                .iter()
                .any(|row| row.version == input)
        );
    }
    let mut invalid = vec![
        version(Family::Rule, "", "one", 1, Some(1)),
        version(Family::Rule, &"k".repeat(1025), "one", 1, Some(1)),
        version(Family::Rule, "long-edition", &"e".repeat(1025), 1, Some(1)),
        version(Family::Rule, "large-opening", "one", (i64::MAX as u64) + 1, Some(1)),
    ];
    let mut announced = version(Family::Rule, "late-announcement", "one", 1, Some(1));
    announced.announced_at = 2;
    invalid.push(announced);
    let mut foreign = version(Family::Rule, "foreign-payload", "one", 1, Some(1));
    foreign.payload = version(Family::Constants, "unused", "one", 1, Some(1)).payload;
    invalid.push(foreign);
    for input in invalid {
        assert_eq!(check(&input), Err(StorageError::Representation));
        assert_eq!(adapter.append(input, None).await, Err(StorageError::Representation));
    }
}
async fn conformance(mut adapter: Adapter, implementation: &str) {
    for family in [
        Family::Constants,
        Family::Rule,
        Family::MarkerPolicy,
        Family::Lineage,
        Family::BurnPublication,
        Family::UnsettledRecognition,
    ] {
        let key = family.name();
        let required = [(family, key.into())];
        let first = version(family, key, "one", 10, Some(7));
        assert!(adapter.append(first.clone(), None).await.unwrap());
        assert!(!adapter.append(first.clone(), None).await.unwrap());
        assert_eq!(
            adapter.append(version(family, key, "one", 10, Some(8)), None).await,
            Err(StorageError::EditionConflict)
        );
        assert!(
            adapter
                .load(9, &[])
                .await
                .unwrap()
                .rows
                .iter()
                .all(|r| r.version.family != family)
        );
        assert_eq!(adapter.load(9, &required).await, Err(StorageError::MissingRequired));
        let before = adapter.load(10, &required).await.unwrap();
        let second = version(family, key, "two", 20, Some(11));
        assert_eq!(
            adapter.append(second.clone(), Some(&prior("one", 19))).await,
            Err(StorageError::Gap)
        );
        assert_eq!(
            adapter.append(second.clone(), Some(&prior("one", 21))).await,
            Err(StorageError::Overlap)
        );
        assert_eq!(
            adapter.append(second.clone(), Some(&prior("foreign", 20))).await,
            Err(StorageError::Predecessor)
        );
        assert_eq!(
            adapter
                .append(version(family, key, "early", 10, Some(1)), Some(&prior("one", 10)))
                .await,
            Err(StorageError::Retroactive)
        );
        for phase in [1, 2] {
            assert_eq!(
                adapter.interrupted(second.clone(), &prior("one", 20), phase).await,
                Err(StorageError::Injected)
            );
            assert_eq!(selected(&mut adapter, family, 20, &required).await, first);
        }
        assert!(adapter.append(second.clone(), Some(&prior("one", 20))).await.unwrap());
        let old = adapter.load(10, &required).await.unwrap();
        let old_row = old.rows.iter().find(|r| r.version.family == family).unwrap();
        let original = before.rows.iter().find(|r| r.version.family == family).unwrap();
        assert_eq!(old_row.version, original.version); // appended closing fact does not alter earlier selected identity/value
        assert_eq!(selected(&mut adapter, family, 19, &required).await, first);
        assert_eq!(selected(&mut adapter, family, 20, &required).await, second);
        adapter
            .append(version(family, key, "withdrawn", 30, None), Some(&prior("two", 30)))
            .await
            .unwrap();
        assert_eq!(adapter.load(30, &required).await, Err(StorageError::MissingRequired));
        assert!(selected(&mut adapter, family, 30, &[]).await.payload.is_none());
        assert!(selected(&mut adapter, family, u64::MAX, &[]).await.payload.is_none());
        cli_common::emit(&serde_json::json!({"kind":"storage_conformance","implementation":implementation,"family":family.name(),"boundaries":[10,20,30],"causes":["edition-conflict","gap","overlap","predecessor","retroactive","missing-required"],"interruptions":2})).unwrap();
    }
    representation(&mut adapter).await;
}

/// Claim: The shared memory and PostgreSQL roster preserves six-family succession and rejects invalid representations at append, with exact 1,024-byte key and edition bounds; a separate non-owner runtime role appends, loads, audits and reopens with MAINTAIN while row updates and deletes refuse.
/// ´claim:history:atomic-effective-rows-preserve-earlier-verdicts´
/// ´test:unit:storage-contract´
#[test]
fn storage_contract() {
    runtime().block_on(async {
        conformance(Adapter::Memory(MemoryStore::default()), "memory").await;
        conformance(Adapter::Postgres(store("storage.json").await), "postgresql").await;
        runtime_role().await;
    });
}

// Fixture-only secret boundary: Only this isolated storage-role harness supplies these diagnostics.
// Caveat: The fixture server's private diagnostic is borrowed only to compare its SQLSTATE with the expected permission refusal; the borrow ends at the assertion and field comparison requires a slice.
// (´[ROOT-cav:observe:secret-host-storage-runtime-role-buffer-1]´)
// Justified: The fixture server's private diagnostic is borrowed only for its permission-refusal assertion; field comparison requires a slice.
#[allow(clippy::disallowed_methods)]
async fn runtime_role() {
    let owner = store("storage-role.json").await;
    owner.session.client().batch_execute("CREATE ROLE storage_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'public-role-fixture'; REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT CONNECT ON DATABASE private_storage_role_731 TO storage_runtime; GRANT USAGE ON SCHEMA public TO storage_runtime; GRANT SELECT ON public.pn_store_identity, public.pn_versions, public.pn_closures TO storage_runtime; GRANT INSERT ON public.pn_versions, public.pn_closures TO storage_runtime; GRANT MAINTAIN ON public.pn_versions TO storage_runtime").await.unwrap();
    let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
    let bytes = std::fs::read(std::path::Path::new(&root).join("storage-role.json")).unwrap();
    let mut config: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    config["user"] = "storage_runtime".into();
    config["password"] = "public-role-fixture".into();
    let bytes = serde_json::to_vec(&config).unwrap();
    let configuration = crate::Configuration::acquire(Some("host-secured"), &mut bytes.as_slice()).unwrap();
    let mut runtime = PostgresStore::open_store(Session::connect(configuration).await.unwrap())
        .await
        .unwrap();
    let one = version(Family::Rule, "role", "one", 10, Some(1));
    let two = version(Family::Rule, "role", "two", 20, Some(2));
    assert!(runtime.append_effective_successor(one, None).await.unwrap());
    assert!(
        runtime
            .append_effective_successor(two.clone(), Some(&prior("one", 20)))
            .await
            .unwrap()
    );
    assert!(
        !runtime
            .append_effective_successor(two.clone(), Some(&prior("one", 20)))
            .await
            .unwrap()
    );
    assert_eq!(runtime.load_boundary(20, &[]).await.unwrap().rows[0].version, two);
    runtime.audit_history().await.unwrap();
    drop(runtime);
    for sql in [
        "UPDATE public.pn_versions SET announced=19 WHERE key='role' AND edition='two'",
        "DELETE FROM public.pn_versions WHERE key='role' AND edition='two'",
    ] {
        let configuration = crate::Configuration::acquire(Some("host-secured"), &mut bytes.as_slice()).unwrap();
        let session = Session::connect(configuration).await.unwrap();
        session.client().execute(sql, &[]).await.unwrap_err();
        assert_eq!(session.last_refusal(), Some(crate::Refusal::PrivateDiagnostic));
        let diagnostics = session.private_diagnostics().unwrap();
        assert_eq!(diagnostics.len(), 1);
        // Inspect the fixture diagnostic in its existing private carrier: the shim
        // deliberately closes the stream before this error reaches the driver.
        assert!(
            diagnostics[0]
                .0
                .expose_bytes(/* (´[ROOT-cav:observe:secret-host-storage-runtime-role-buffer-1]´) */)
                .split(|byte| *byte == 0)
                .any(|field| field.strip_prefix(b"C") == Some(b"42501".as_slice()))
        );
    }
    let configuration = crate::Configuration::acquire(Some("host-secured"), &mut bytes.as_slice()).unwrap();
    let mut reopened = PostgresStore::open_store(Session::connect(configuration).await.unwrap())
        .await
        .unwrap();
    assert_eq!(reopened.load_boundary(20, &[]).await.unwrap().rows[0].version, two);
    reopened.audit_history().await.unwrap();
}

/// Claim: Two PostgreSQL successor writers holding the same predecessor serialize to one winner and one typed predecessor refusal; a fresh connection sees one complete history rather than two terminal versions.
/// ´claim:history:competing-successors-serialize´
/// ´test:unit:storage-competing-writers´
#[test]
fn storage_competing_writers() {
    runtime().block_on(async {
        let mut one = store("storage-race.json").await;
        let mut two = store("storage-race.json").await;
        one.append_effective_successor(version(Family::Rule, "race", "one", 1, Some(1)), None)
            .await
            .unwrap();
        let left = tokio::spawn(async move {
            one.append_effective_successor(version(Family::Rule, "race", "left", 2, Some(2)), Some(&prior("one", 2)))
                .await
        });
        let right = tokio::spawn(async move {
            two.append_effective_successor(version(Family::Rule, "race", "right", 2, Some(3)), Some(&prior("one", 2)))
                .await
        });
        let results = [left.await.unwrap(), right.await.unwrap()];
        assert_eq!(results.iter().filter(|v| **v == Ok(true)).count(), 1);
        assert_eq!(results.iter().filter(|v| **v == Err(StorageError::Predecessor)).count(), 1);
        let mut fresh = store("storage-race.json").await;
        assert_eq!(fresh.load_boundary(2, &[]).await.unwrap().rows.len(), 1);
    });
}

/// Claim: Replaying the same public version packages into a fresh database reproduces all logical as-of values and identities; no physical row order, observer state or private configuration is needed in the comparison.
/// ´claim:history:public-input-rebuild-preserves-boundaries´
/// ´test:unit:storage-rebuild´
#[test]
fn storage_rebuild() {
    runtime().block_on(async {
        let mut memory = MemoryStore::default();
        let mut postgres = store("storage-rebuild.json").await;
        for (edition, at, value, predecessor) in [
            ("a", 4, Some(10), None),
            ("b", 8, Some(20), Some(prior("a", 8))),
            ("c", 12, None, Some(prior("b", 12))),
        ] {
            let input = version(Family::Rule, "rebuild", edition, at, value);
            memory
                .append_effective_successor(input.clone(), predecessor.as_ref())
                .unwrap();
            postgres
                .append_effective_successor(input, predecessor.as_ref())
                .await
                .unwrap();
        }
        for at in [0, 3, 4, 7, 8, 11, 12, 99] {
            assert_eq!(
                memory.load_boundary(at, &[]).unwrap(),
                postgres.load_boundary(at, &[]).await.unwrap()
            );
        }
    });
}

fn validated(
    case: pn_records::test_support::burn::BurnCase,
) -> (
    pn_records::burn::ValidatedBurn,
    pn_records::burn::ValidatedPolicy,
    pn_records::burn::ValidatedMarkerHistory,
) {
    use pn_records::{Declaration, DeclarationContent, DeclarationId};
    let burn = pn_records::burn::validate_burn(case.burn).unwrap();
    let declarations = [
        Declaration {
            id: DeclarationId {
                namespace: "deployment".into(),
                name: "genesis".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: DeclarationContent::Deployment { genesis_at: 1 },
        },
        Declaration {
            id: DeclarationId {
                namespace: "marker".into(),
                name: "policy".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: pn_records::constants::marker_policy_declaration(&case.policy, &burn).unwrap(),
        },
    ];
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let records = pn_records::validate_record(&[], &history, &declarations).unwrap();
    let policy = pn_records::constants::bind_marker_policy(&records, case.policy, &burn).unwrap();
    let history =
        pn_records::burn::validate_marker_history(case.history, &policy, &pn_records::test_support::burn::FixtureVerifier)
            .unwrap();
    (burn, policy, history)
}

/// Claim: A recognition package retains its full validated disclosure and unsettled output; changing an unaccepted candidate's evidence changes its commitment even when the recognized prefix is unchanged, and a substituted disclosure-column digest refuses on read.
/// ´claim:history:recognition-retains-its-own-disclosure´
/// ´test:unit:storage-recognition-disclosure´
#[test]
fn storage_recognition_disclosure() {
    let mut case = pn_records::test_support::burn::generate(&[19]);
    case.history.markers[2].accepted =
        pn_records::burn::AcceptedSet::CompleteList(std::collections::BTreeSet::from(["absent".into()]));
    let (burn, policy, first) = validated(case.clone());
    let mut reversed = case.clone();
    reversed.history.records.reverse();
    reversed.history.markers.reverse();
    let (_, _, reversed) = validated(reversed);
    assert_eq!(
        Payload::recognition(&first).unwrap(),
        Payload::recognition(&reversed).unwrap()
    );
    case.history.markers[2].name = "changed-refused-candidate".into();
    let (_, _, second) = validated(case);
    assert_eq!(
        pn_records::burn::recognize_markers(&first).markers(),
        pn_records::burn::recognize_markers(&second).markers()
    );
    let a = Payload::recognition(&first).unwrap();
    let b = Payload::recognition(&second).unwrap();
    assert_ne!(a.disclosure, b.disclosure);
    verify_payload(a.family, a.bytes(), a.disclosure.as_ref().map(<[u8; 32]>::as_slice)).unwrap();
    assert_eq!(
        verify_payload(a.family, a.bytes(), b.disclosure.as_ref().map(<[u8; 32]>::as_slice)),
        Err(StorageError::CorruptHistory)
    );
    for payload in [
        Payload::burn_publication(&burn).unwrap(),
        Payload::marker_policy(&policy).unwrap(),
        Payload::lineage(&first).unwrap(),
        a,
        b,
    ] {
        assert_eq!(
            Value::from_canonical_bytes(payload.bytes()).unwrap().to_canonical_bytes(),
            payload.bytes()
        );
        assert_eq!(digest(PAYLOAD_RECIPE, payload.bytes()), payload.digest);
    }
}

async fn refuse_index(store: &PostgresStore, name: &str, definition: &str, correct: &str) {
    let unique = if definition.starts_with("UNIQUE ") { "UNIQUE " } else { "" };
    let invalid = definition.starts_with("INVALID ");
    let definition = definition
        .strip_prefix("UNIQUE ")
        .or_else(|| definition.strip_prefix("INVALID "))
        .unwrap_or(definition);
    let sql = format!("DROP INDEX public.{name}; CREATE {unique}INDEX {name} {definition}");
    store.session.client().batch_execute(&sql).await.unwrap();
    if invalid {
        store
            .session
            .client()
            .execute(
                "UPDATE pg_catalog.pg_index SET indisvalid=false WHERE indexrelid='public.pn_versions_opens'::regclass",
                &[],
            )
            .await
            .unwrap();
    }
    let before: String = store
        .session
        .client()
        .query_one("SELECT pg_get_indexdef(to_regclass($1))", &[&format!("public.{name}")])
        .await
        .unwrap()
        .get(0);
    let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
    let mut file = std::fs::File::open(std::path::Path::new(&root).join("storage-schema.json")).unwrap();
    let config = crate::Configuration::acquire(Some("host-secured"), &mut file).unwrap();
    assert_eq!(
        PostgresStore::open_store(Session::connect(config).await.unwrap())
            .await
            .unwrap_err(),
        StorageError::IndexDefinition
    );
    let after: String = store
        .session
        .client()
        .query_one("SELECT pg_get_indexdef(to_regclass($1))", &[&format!("public.{name}")])
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, after);
    if invalid {
        let valid: bool = store
            .session
            .client()
            .query_one(
                "SELECT indisvalid FROM pg_catalog.pg_index WHERE indexrelid='public.pn_versions_opens'::regclass",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(!valid);
    }
    store
        .session
        .client()
        .batch_execute(&format!("DROP INDEX public.{name}; CREATE INDEX {name} {correct}"))
        .await
        .unwrap();
}

/// Claim: Bootstrap refuses foreign schema identity and same-named read indexes with a wrong table, column, ordering, uniqueness, predicate, expression, included column, access method or validity; refusal preserves each mismatched definition, and the admitted definitions reopen without replacement.
/// ´claim:history:foreign-schema-refuses-without-migration´
/// ´test:unit:storage-schema-identity´
#[test]
fn storage_schema_identity() {
    runtime().block_on(async {
        let store = store("storage-schema.json").await;
        for (name, definition, correct) in [
            (
                "pn_versions_opens",
                "ON public.pn_versions(announced)",
                "ON public.pn_versions(opens)",
            ),
            (
                "pn_closures_closes",
                "ON public.pn_closures(edition)",
                "ON public.pn_closures(closes)",
            ),
            (
                "pn_versions_opens",
                "ON public.pn_versions(opens DESC)",
                "ON public.pn_versions(opens)",
            ),
            (
                "pn_versions_opens",
                "ON public.pn_closures(closes)",
                "ON public.pn_versions(opens)",
            ),
            (
                "pn_versions_opens",
                "UNIQUE ON public.pn_versions(opens)",
                "ON public.pn_versions(opens)",
            ),
            (
                "pn_versions_opens",
                "ON public.pn_versions(opens) WHERE opens > 0",
                "ON public.pn_versions(opens)",
            ),
            (
                "pn_versions_opens",
                "ON public.pn_versions((opens + 0))",
                "ON public.pn_versions(opens)",
            ),
            (
                "pn_versions_opens",
                "ON public.pn_versions(opens) INCLUDE (edition)",
                "ON public.pn_versions(opens)",
            ),
            (
                "pn_versions_opens",
                "ON public.pn_versions USING hash(opens)",
                "ON public.pn_versions(opens)",
            ),
            (
                "pn_versions_opens",
                "INVALID ON public.pn_versions(opens)",
                "ON public.pn_versions(opens)",
            ),
        ] {
            refuse_index(&store, name, definition, correct).await;
        }
        let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
        let mut file = std::fs::File::open(std::path::Path::new(&root).join("storage-schema.json")).unwrap();
        let config = crate::Configuration::acquire(Some("host-secured"), &mut file).unwrap();
        drop(
            PostgresStore::open_store(Session::connect(config).await.unwrap())
                .await
                .unwrap(),
        );
        store
            .session
            .client()
            .execute("UPDATE public.pn_store_identity SET identity='foreign-schema-fixture'", &[])
            .await
            .unwrap();
        let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
        let mut file = std::fs::File::open(std::path::Path::new(&root).join("storage-schema.json")).unwrap();
        let config = crate::Configuration::acquire(Some("host-secured"), &mut file).unwrap();
        assert_eq!(
            PostgresStore::open_store(Session::connect(config).await.unwrap())
                .await
                .unwrap_err(),
            StorageError::SchemaIdentity
        );
    });
}

/// Claim: Canonical storage retains the old bound controller and exact floor source at its old boundary after a later constants edition is appended, in both implementations.
/// This durable-carrier observation extends (´[RECORDS-claim:declarations:effective-editions-preserve-historical-constants]´).
/// ´claim:declarations:canonical-storage-preserves-selected-constants´
/// ´test:unit:storage-historical-constants´
#[test]
fn storage_historical_constants() {
    runtime().block_on(async {
        use pn_records::constants::{ConstantDefinition, EditionInput, bind_constants};
        use pn_records::numerics::{ComparisonLimits, ExactLimits, Floor, NumericContext};
        use pn_records::{Declaration, DeclarationContent, DeclarationId};
        let mut context = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
        let two = context.literal("2").unwrap();
        let unit = context.burn_per_action(&two, "burn").unwrap();
        let nu = context.numeraire("nu", &unit).unwrap();
        let declarations: Vec<_> = [(1, 10), (2, 20)]
            .into_iter()
            .map(|(edition, at)| Declaration {
                id: DeclarationId {
                    namespace: "numeric".into(),
                    name: "constants".into(),
                    edition,
                },
                announced_at: at,
                effective_at: at,
                content: DeclarationContent::Opaque,
            })
            .collect();
        let history = pn_records::validate_history(&[], &[]).unwrap();
        let records = pn_records::validate_record(&[], &history, &declarations).unwrap();
        let inputs: Vec<_> = declarations
            .iter()
            .map(|d| EditionInput {
                id: d.id.clone(),
                floor: if d.id.edition == 1 {
                    Floor::RationalThreeThirtySevenths
                } else {
                    Floor::RidgeImage
                },
                numeraire: nu.clone(),
                formula_edition: "formula".into(),
                controller_edition: format!("controller-{}", d.id.edition),
                constants: vec![ConstantDefinition::Literal {
                    name: "margin".into(),
                    value: two.clone(),
                }],
                permitted_overrides: vec![],
                domain_profiles: vec!["finite".into()],
                numerical_procedure: "exact-or-indecisive".into(),
                authentication_realization: "fixture".into(),
                publication_profile: "internal".into(),
            })
            .collect();
        let constants = bind_constants(&records, inputs).unwrap();
        let old = Payload::constants(constants.resolve("numeric", "constants", 10).unwrap()).unwrap();
        let new = Payload::constants(constants.resolve("numeric", "constants", 20).unwrap()).unwrap();
        assert_ne!(old.bytes(), new.bytes());
        for mut store in [
            Adapter::Memory(MemoryStore::default()),
            Adapter::Postgres(store("storage-constants.json").await),
        ] {
            for (edition, at, payload, predecessor) in [
                ("one", 10, old.clone(), None),
                ("two", 20, new.clone(), Some(prior("one", 20))),
            ] {
                store
                    .append(
                        Version {
                            family: Family::Constants,
                            key: "constants".into(),
                            edition: edition.into(),
                            announced_at: at,
                            opens_at: at,
                            payload: Some(payload),
                        },
                        predecessor.as_ref(),
                    )
                    .await
                    .unwrap();
            }
            let boundary = store.load(19, &[(Family::Constants, "constants".into())]).await.unwrap();
            assert_eq!(boundary.rows[0].version.payload, Some(old.clone()));
        }
    });
}

/// Claim: Thirteen fixed projections and component tables pin all six families, the disclosure, alternate policy and floor layouts, refused recognition and all cause spellings to independently encoded canonical bytes and SHA-256 literals; storage grants the opaque rule fixture no domain validity.
/// ´claim:history:storage-digest-domains-are-permanent´
/// ´test:unit:storage-digest-vectors´
#[test]
fn storage_digest_vectors() {
    use pn_records::constants::{ConstantDefinition, EditionInput, bind_constants};
    use pn_records::numerics::{ComparisonLimits, ExactLimits, Floor, NumericContext};
    use pn_records::{Declaration, DeclarationContent, DeclarationId};
    use std::fmt::Write;
    let mut context = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
    let two = context.literal("2").unwrap();
    let unit = context.burn_per_action(&two, "burn").unwrap();
    let nu = context.numeraire("nu", &unit).unwrap();
    let declarations: Vec<_> = [(1, 10), (2, 20)]
        .into_iter()
        .map(|(edition, at)| Declaration {
            id: DeclarationId {
                namespace: "numeric".into(),
                name: "constants".into(),
                edition,
            },
            announced_at: at,
            effective_at: at,
            content: DeclarationContent::Opaque,
        })
        .collect();
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let records = pn_records::validate_record(&[], &history, &declarations).unwrap();
    let inputs: Vec<_> = declarations
        .iter()
        .map(|d| EditionInput {
            id: d.id.clone(),
            floor: if d.id.edition == 1 {
                Floor::RationalThreeThirtySevenths
            } else {
                Floor::RidgeImage
            },
            numeraire: nu.clone(),
            formula_edition: "formula".into(),
            controller_edition: format!("controller-{}", d.id.edition),
            constants: vec![ConstantDefinition::Literal {
                name: "margin".into(),
                value: two.clone(),
            }],
            permitted_overrides: vec![],
            domain_profiles: vec!["finite".into()],
            numerical_procedure: "exact-or-indecisive".into(),
            authentication_realization: "fixture".into(),
            publication_profile: "internal".into(),
        })
        .collect();
    let constants = bind_constants(&records, inputs).unwrap();
    let constant_payload = Payload::constants(constants.resolve("numeric", "constants", 10).unwrap()).unwrap();

    let mut case = pn_records::test_support::burn::generate(&[19]);
    case.history.records.retain(|v| v.identity == "r0");
    case.history.markers.truncate(2);
    case.history.markers[1].lineage = std::collections::BTreeSet::from(["r0".into()]);
    let (burn, policy, history) = validated(case.clone());
    let disclosure = encoding::disclosure(&history).to_canonical_bytes();
    let payloads = [
        constant_payload,
        Payload::rule(&encoding::text("public-rule-v1")).unwrap(),
        Payload::marker_policy(&policy).unwrap(),
        Payload::lineage(&history).unwrap(),
        Payload::burn_publication(&burn).unwrap(),
        Payload::recognition(&history).unwrap(),
    ];
    let extra = variant_vectors(
        case,
        Payload::constants(constants.resolve("numeric", "constants", 20).unwrap()).unwrap(),
    );
    let vectors: serde_json::Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
    assert_eq!(vectors.as_array().unwrap().len(), 13);
    for row in vectors.as_array().unwrap() {
        let family = row["family"].as_str().unwrap();
        let actual = if let Some(bytes) = extra.get(family) {
            bytes.as_slice()
        } else if family == "disclosure" {
            disclosure.as_slice()
        } else {
            payloads.iter().find(|p| p.family.name() == family).unwrap().bytes()
        };
        let bytes: Vec<_> = row["canonical_bytes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
            .collect();
        assert_eq!(actual, bytes, "projection {family}");
        let mut text = String::new();
        for byte in digest(row["recipe"].as_str().unwrap(), actual) {
            write!(&mut text, "{byte:02x}").unwrap();
        }
        assert_eq!(text, row["digest"].as_str().unwrap(), "digest {family}");
    }
}

fn variant_vectors(
    case: pn_records::test_support::burn::BurnCase,
    ridge: Payload,
) -> std::collections::BTreeMap<&'static str, Vec<u8>> {
    use pn_records::burn::{AcceptedSet, BurnError as E, CandidateRule, Disclosure, Encoding, OperatorEvidence};
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("constants-ridge", ridge.bytes);
    let mut commitment = case.clone();
    pn_records::test_support::burn::committed(&mut commitment);
    commitment.policy.candidate_rule = CandidateRule::FirstValidInHistoryOrder;
    commitment.burn.evidence.operator = Some(OperatorEvidence::Bound {
        amount: commitment.history.records[0].amount.clone(),
        proof: "public operator bound proof".into(),
    });
    let (_, policy, history) = validated(commitment);
    extra.insert("commitment-policy", Payload::marker_policy(&policy).unwrap().bytes().to_vec());
    extra.insert("commitment-lineage", Payload::lineage(&history).unwrap().bytes().to_vec());
    let mut prefix = case.clone();
    prefix.policy.encoding = Encoding::WholePrefixAcceptAll;
    prefix.policy.candidate_rule = CandidateRule::FirstValidInHistoryOrder;
    for marker in &mut prefix.history.markers {
        marker.accepted = AcceptedSet::WholePrefix;
    }
    let (_, _, history) = validated(prefix);
    extra.insert("whole-prefix-lineage", Payload::lineage(&history).unwrap().bytes().to_vec());
    let mut refused = case;
    let mut competitor = refused.history.markers[1].clone();
    competitor.name = "competitor".into();
    competitor.history_position = 11;
    refused.history.markers.push(competitor);
    let (_, _, history) = validated(refused);
    extra.insert(
        "refused-recognition",
        Payload::recognition(&history).unwrap().bytes().to_vec(),
    );
    let causes = [
        E::PolicySelection(pn_records::ValidationError::InvalidSelectionKey(
            pn_records::DeclarationCause::EmptyNamespace,
        )),
        E::PolicyBinding,
        E::DeploymentBinding,
        E::PolicyDigest,
        E::UnsupportedPolicyRecipe,
        E::Publication(Disclosure::Bootstrap),
        E::EvidenceBinding,
        E::SampleCoverage,
        E::Units,
        E::Bootstrap,
        E::Policy,
        E::Buffer,
        E::Verifier,
        E::RecordIdentity,
        E::HistoryPolicy,
        E::HistoryPosition,
        E::Initial,
        E::Succession,
        E::MissingLineage,
        E::RegressedLineage,
        E::Encoding,
        E::MissingOpening,
        E::AmbiguousOpening,
        E::InvalidOpening,
        E::RegressedAcceptance,
        E::OutOfLineage,
        E::InvalidMember,
        E::InconsistentAlias,
    ];
    extra.insert(
        "cause-spellings",
        encoding::array([
            encoding::text(PAYLOAD_RECIPE),
            encoding::text("component-table"),
            encoding::array(causes.iter().map(encoding::cause)),
        ])
        .to_canonical_bytes(),
    );
    extra
}

/// Claim: The closed storage statement set returns retained public values through `DataRows` under observation, with deterministic bytes and exact transaction results; every invocation resets its dedicated fixture before observation so a retake exercises bootstrap again, and its private service configuration remains behind Session.
/// ´claim:history:closed-storage-statements-return-public-values´
/// ´test:unit:storage-runtime´
#[test]
fn storage_runtime() {
    let runtime = runtime();
    let fixture = std::env::var("PN_HOST_STORAGE_FIXTURE").unwrap_or_else(|_| "storage-trace-initial.json".into());
    // This database belongs only to this test. A prior capture must not turn
    // bootstrap coverage into reopen coverage on the next child invocation.
    runtime.block_on(async {
        let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
        let mut file = std::fs::File::open(std::path::Path::new(&root).join(&fixture)).unwrap();
        let config = crate::Configuration::acquire(Some("host-secured"), &mut file).unwrap();
        let session = Session::connect(config).await.unwrap();
        let initialized: bool = session
            .client()
            .query_one("SELECT to_regclass('public.pn_store_identity') IS NOT NULL", &[])
            .await
            .unwrap()
            .get(0);
        if initialized {
            session
                .client()
                .batch_execute("DROP TABLE public.pn_closures, public.pn_versions, public.pn_store_identity")
                .await
                .unwrap();
        }
    });
    let guard = cli_common::observation::bootstrap(true, false, tracing::Level::WARN).unwrap();
    runtime.block_on(async {
        let mut store = store(&fixture).await;
        let value = Payload::rule(&encoding::text("public_storage_payload_731")).unwrap();
        let one = Version {
            family: Family::Rule,
            key: "runtime".into(),
            edition: "one".into(),
            announced_at: 1,
            opens_at: 1,
            payload: Some(value.clone()),
        };
        store.append_effective_successor(one.clone(), None).await.unwrap();
        let mut two = one.clone();
        two.edition = "two".into();
        two.announced_at = 2;
        two.opens_at = 2;
        store.append_effective_successor(two, Some(&prior("one", 2))).await.unwrap();
        let boundary = store.load_boundary(1, &[(Family::Rule, "runtime".into())]).await.unwrap();
        assert_eq!(boundary.rows[0].version, one);
        if std::env::var_os("PN_HOST_STORAGE_PRIVATE_CONTROL").is_some() {
            let private: String = store
                .session
                .client()
                .query_one("SELECT current_user", &[])
                .await
                .unwrap()
                .get(0);
            assert_ne!(private.len(), 0);
        }
        store.audit_history().await.unwrap();
        // Drain the request queue before dropping the session and observer.
        store.load_boundary(2, &[]).await.unwrap();
    });
    drop(runtime);
    drop(guard);
    cli_common::emit(
        &serde_json::json!({"kind":"storage_result","public_value":"public_storage_payload_731","executable_persistence":false}),
    )
    .unwrap();
}

/// Claim: A fresh process reads the identical committed version after service restart; an existing edition remains idempotent without replacing its canonical payload.
/// ´claim:history:committed-bytes-survive-service-restart´
/// ´test:unit:storage-restart´
#[test]
fn storage_restart() {
    runtime().block_on(async {
        let mut store = store("storage-restart.json").await;
        let input = version(Family::Rule, "restart", "one", 1, Some(731));
        if std::env::var_os("PN_HOST_STORAGE_READ_ONLY_PROBE").is_none() {
            store.append_effective_successor(input.clone(), None).await.unwrap();
        }
        assert_eq!(
            store
                .load_boundary(1, &[(Family::Rule, "restart".into())])
                .await
                .unwrap()
                .rows[0]
                .version,
            input
        );
    });
}

/// Claim: Requested-key append and active-boundary reads preserve selected identities as unrelated retained history grows by two orders of magnitude; the full audit remains a separate operation, and timing is reported rather than asserted.
/// ´claim:history:bounded-reads-ignore-unrelated-history´
/// ´test:unit:storage-scaling´
#[test]
fn storage_scaling() {
    runtime().block_on(async {
        let mut store = store("storage-scaling.json").await;
        let mut count = 0;
        for size in [10, 100, 2000] {
            while count < size {
                let key = format!("unrelated-{count}");
                store.append_effective_successor(version(Family::Rule, &key, "one", 100, Some(7)), None).await.unwrap();
                count += 1;
            }
            let start = std::time::Instant::now();
            let key = format!("measured-{size}");
            store.append_effective_successor(version(Family::Rule, &key, "one", 1, Some(731)), None).await.unwrap();
            let append_wall = start.elapsed().as_secs_f64();
            let start = std::time::Instant::now();
            let boundary = store.load_boundary(1, &[(Family::Rule, key.clone())]).await.unwrap();
            let load_wall = start.elapsed().as_secs_f64();
            assert!(boundary.rows.iter().all(|r| r.version.key.starts_with("measured-")));
            assert!(boundary.rows.iter().any(|r| r.version.key == key));
            cli_common::emit(&serde_json::json!({"kind":"storage_scaling","retained_unrelated":size,"append_seconds":append_wall,"load_seconds":load_wall})).unwrap();
        }
        store.audit_history().await.unwrap();
        store.session.client().execute("UPDATE public.pn_versions SET payload=$1 WHERE key LIKE 'unrelated-%'", &[&vec![0_u8]]).await.unwrap();
        store.load_boundary(1, &[]).await.unwrap();
        store.append_effective_successor(version(Family::Rule, "after-unrelated-damage", "one", 2, Some(7)), None).await.unwrap();
        assert_eq!(store.audit_history().await, Err(StorageError::CorruptHistory));
    });
}

/// Claim: Deleted successors, shortened or overlapping closures, a deleted closed middle edition, compound tampering and damaged selected payloads refuse in both adapters at boundaries inside their defects; future damage is unread by load but refused by the full audit, including after the store was opened.
/// ´claim:history:boundary-tampering-is-not-absence´
/// ´test:unit:storage-tamper´
#[test]
fn storage_tamper() {
    runtime().block_on(async {
        for implementation in ["memory", "postgresql"] {
            let mut adapter = if implementation == "memory" { Adapter::Memory(MemoryStore::default()) }
                else { Adapter::Postgres(store("storage-tamper.json").await) };
            for (case, at) in [("deleted", 20), ("closes", 15), ("inside", 10), ("outside", 10),
                ("earlier-closure-deleted", 22), ("lengthened", 22), ("middle-deleted", 22), ("compound", 20)] {
                adapter.append(version(Family::Rule, case, "one", 10, Some(1)), None).await.unwrap();
                adapter.append(version(Family::Rule, case, "two", 20, Some(2)), Some(&prior("one", 20))).await.unwrap();
                if case == "middle-deleted" {
                    adapter.append(version(Family::Rule, case, "three", 30, Some(3)), Some(&prior("two", 30))).await.unwrap();
                }
                // A opens at 5 without a closure, B opens at 10 and closes at 20,
                // and its successor C is absent. Exactly one row remains active at 20.
                if case == "compound" {
                    match &mut adapter {
                        Adapter::Memory(s) => {
                            let rows = s.history.get_mut(&(Family::Rule, case.into())).unwrap();
                            rows[0].version.opens_at = 5;
                            rows[0].version.announced_at = 5;
                            rows[0].closes_at = None;
                            rows[1].version.opens_at = 10;
                            rows[1].version.announced_at = 10;
                            rows[1].closes_at = Some(20);
                        }
                        Adapter::Postgres(s) => {
                            s.session.client.fixture().batch_execute("UPDATE public.pn_versions SET opens=5,announced=5 WHERE key='compound' AND edition='one'; UPDATE public.pn_versions SET opens=10,announced=10 WHERE key='compound' AND edition='two'; DELETE FROM public.pn_closures WHERE key='compound'; INSERT INTO public.pn_closures VALUES ('rule','compound','two',20)").await.unwrap();
                        }
                    }
                }
                match &mut adapter {
                    Adapter::Memory(s) => {
                        let rows = s.history.get_mut(&(Family::Rule, case.into())).unwrap();
                        match case {
                            "deleted" => { rows.pop(); }
                            "closes" => rows[0].closes_at = Some(12),
                            "inside" => rows[0].version.payload.as_mut().unwrap().bytes = vec![0],
                            "earlier-closure-deleted" => rows[0].closes_at = None,
                            "lengthened" => rows[0].closes_at = Some(25),
                            "middle-deleted" => { rows.remove(1); }
                            "compound" => {},
                            _ => rows[1].version.payload.as_mut().unwrap().bytes = vec![0],
                        }
                    }
                    Adapter::Postgres(s) => {
                        if case == "middle-deleted" {
                            s.session.client.fixture().execute("DELETE FROM public.pn_closures WHERE key=$1 AND edition='two'", &[&case]).await.unwrap();
                        }
                        let sql = match case {
                            "deleted" | "middle-deleted" => "DELETE FROM public.pn_versions WHERE key=$1 AND edition='two'",
                            "closes" => "UPDATE public.pn_closures SET closes=12 WHERE key=$1",
                            "inside" => "UPDATE public.pn_versions SET payload=decode('00','hex') WHERE key=$1 AND edition='one'",
                            "earlier-closure-deleted" => "DELETE FROM public.pn_closures WHERE key=$1 AND edition='one'",
                            "lengthened" => "UPDATE public.pn_closures SET closes=25 WHERE key=$1 AND edition='one'",
                            "compound" => "SELECT 1 WHERE $1::text='compound'",
                            _ => "UPDATE public.pn_versions SET payload=decode('00','hex') WHERE key=$1 AND edition='two'",
                        };
                        s.session.client.fixture().execute(sql, &[&case]).await.unwrap();
                    }
                }
                let loaded = adapter.load(at, &[]).await;
                if case == "outside" { assert!(loaded.is_ok()); }
                else { assert_eq!(loaded, Err(StorageError::CorruptHistory)); }
                let audit = match &mut adapter {
                    Adapter::Memory(s) => s.audit_history(),
                    Adapter::Postgres(s) => s.audit_history().await,
                };
                assert_eq!(audit, Err(StorageError::CorruptHistory));
                cli_common::emit(&serde_json::json!({"kind":"storage_tamper","implementation":implementation,"case":case,"load":if case=="outside" {"unread"} else {"CorruptHistory"},"audit":"CorruptHistory"})).unwrap();
                match &mut adapter {
                    Adapter::Memory(s) => s.history.clear(),
                    Adapter::Postgres(s) => { s.session.client.fixture().batch_execute("TRUNCATE public.pn_closures, public.pn_versions").await.unwrap(); }
                }
            }
        }
    });
}

fn node_usage() -> Option<u64> {
    let group = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let relative = group.lines().find_map(|line| line.strip_prefix("0::"))?;
    let path = std::path::Path::new("/sys/fs/cgroup")
        .join(relative.trim_start_matches('/'))
        .join("cpu.stat");
    std::fs::read_to_string(path)
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("usage_usec "))?
        .parse()
        .ok()
}

/// Claim: Requested-chain append, live-key load and sparse-boundary load are measured through 100,000 retained rows, while the three actual read plans expose server work; every measured boundary and appended successor is checked independently of timing.
/// ´claim:history:storage-growth-has-executed-read-plans´
/// ´test:unit:storage-growth´
#[test]
fn storage_growth() {
    runtime().block_on(async {
        let mut store = store("storage-growth.json").await;
        let payload = Payload::rule(&Value::Unsigned(731)).unwrap();
        for axis in ["chain", "live", "total"] {
            for size in [1000_i64, 10_000, 100_000] {
                let client = store.session.client.fixture();
                client.batch_execute("TRUNCATE public.pn_closures, public.pn_versions").await.unwrap();
                let insert = match axis {
                    "chain" => "INSERT INTO public.pn_versions SELECT 'rule','chain',g::text,g,g,$2,$3,NULL FROM generate_series(1,$1::bigint) g",
                    "live" => "INSERT INTO public.pn_versions SELECT 'rule',g::text,'one',1,1,$2,$3,NULL FROM generate_series(1,$1::bigint) g",
                    _ => "INSERT INTO public.pn_versions SELECT 'rule',g::text,'one',100,100,$2,$3,NULL FROM generate_series(1,$1::bigint) g",
                };
                client.execute(insert, &[&size, &payload.bytes(), &payload.digest.as_slice()]).await.unwrap();
                if axis == "chain" {
                    client.execute("INSERT INTO public.pn_closures SELECT 'rule','chain',g::text,g+1 FROM generate_series(1,$1::bigint-1) g", &[&size]).await.unwrap();
                }
                client.batch_execute("ANALYZE public.pn_versions; ANALYZE public.pn_closures").await.unwrap();
                let usage = node_usage();
                let started = std::time::Instant::now();
                if axis == "chain" {
                    assert!(store.append_effective_successor(version(Family::Rule,"chain","next",u64::try_from(size+1).unwrap(),Some(731)),Some(&prior(&size.to_string(),u64::try_from(size+1).unwrap()))).await.unwrap());
                } else {
                    let boundary = store.load_boundary(1,&[]).await.unwrap();
                    assert_eq!(boundary.rows.len(), if axis == "live" { usize::try_from(size).unwrap() } else { 0 });
                }
                let wall = started.elapsed().as_secs_f64();
                let cores = usage.zip(node_usage()).map(|(start,end)| std::time::Duration::from_micros(end-start).as_secs_f64() / wall);
                cli_common::emit(&serde_json::json!({"kind":"storage_growth","axis":axis,"rows":size,"wall_seconds":wall,"node_cores":cores,"scope":"shared"})).unwrap();
                if size == 100_000 {
                    for statement in [Statement::ReadKey, Statement::ReadBoundary, Statement::ReadHistory] {
                        let sql = format!("EXPLAIN (ANALYZE, BUFFERS) {}",statement.sql());
                        let at = 1_i64;
                        let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = match statement {
                            Statement::ReadKey => vec![&"rule", &"chain"],
                            Statement::ReadBoundary => vec![&at],
                            _ => vec![],
                        };
                        let usage = node_usage();
                        let started = std::time::Instant::now();
                        let plan = store.session.client.fixture().query(&sql,&params).await.unwrap().iter().map(|r|r.get::<_,String>(0)).collect::<Vec<_>>();
                        let wall = started.elapsed().as_secs_f64();
                        let cores = usage.zip(node_usage()).map(|(start,end)| std::time::Duration::from_micros(end-start).as_secs_f64() / wall);
                        cli_common::emit(&serde_json::json!({"kind":"storage_read_plan","axis":axis,"statement":statement.sql(),"plan":plan,"wall_seconds":wall,"node_cores":cores,"scope":"shared"})).unwrap();
                    }
                }
            }
        }
    });
}
