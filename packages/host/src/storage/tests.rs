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
        cli_common::emit(&serde_json::json!({"kind":"storage_conformance","implementation":implementation,"family":family.name(),"boundaries":[10,20,30],"causes":["edition-conflict","gap","overlap","predecessor","retroactive","missing-required"],"interruptions":2})).unwrap();
    }
}

/// Claim: The same six-family succession roster preserves earlier selected bytes and identities in memory and PostgreSQL, with exact boundaries, explicit withdrawal, immutable editions and rollback at both interrupted write phases.
/// ´claim:history:atomic-effective-rows-preserve-earlier-verdicts´
/// ´test:unit:storage-contract´
#[test]
fn storage_contract() {
    runtime().block_on(async {
        conformance(Adapter::Memory(MemoryStore::default()), "memory").await;
        conformance(Adapter::Postgres(store("storage.json").await), "postgresql").await;
    });
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

/// Claim: A recorded foreign schema identity refuses before storage writes, while reopening the same admitted identity preserves the stored bytes without migration.
/// ´claim:history:foreign-schema-refuses-without-migration´
/// ´test:unit:storage-schema-identity´
#[test]
fn storage_schema_identity() {
    runtime().block_on(async {
        let store = store("storage-schema.json").await;
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

/// Claim: All six fixed validated family projections and the recognition disclosure match independently encoded canonical bytes and SHA-256 literals; changing field order, an enum spelling or a digest domain breaks durable recipe correspondence.
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
    let (burn, policy, history) = validated(case);
    let disclosure = encoding::disclosure(&history).to_canonical_bytes();
    let payloads = [
        constant_payload,
        Payload::rule(&encoding::text("public-rule-v1")).unwrap(),
        Payload::marker_policy(&policy).unwrap(),
        Payload::lineage(&history).unwrap(),
        Payload::burn_publication(&burn).unwrap(),
        Payload::recognition(&history).unwrap(),
    ];
    let vectors: serde_json::Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
    assert_eq!(vectors.as_array().unwrap().len(), 7);
    for row in vectors.as_array().unwrap() {
        let family = row["family"].as_str().unwrap();
        let actual = if family == "disclosure" {
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

/// Claim: The closed storage statement set returns retained public values through `DataRows` under observation, with deterministic bytes and exact transaction results; its private service configuration remains behind Session.
/// ´claim:history:closed-storage-statements-return-public-values´
/// ´test:unit:storage-runtime´
#[test]
fn storage_runtime() {
    let guard = cli_common::observation::bootstrap(true, false, tracing::Level::WARN).unwrap();
    let runtime = runtime();
    runtime.block_on(async {
        let fixture = std::env::var("PN_HOST_STORAGE_FIXTURE").unwrap_or_else(|_| "storage-trace-initial.json".into());
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
