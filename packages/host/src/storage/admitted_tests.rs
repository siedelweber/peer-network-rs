#[path = "../../tests/public/publication/base.rs"]
mod base;
#[path = "../../tests/public/publication/fixture.rs"]
mod fixture;

fn shared_fixture() -> &'static (base::publication::AdmittedPackage, fixture::Check) {
    static FIXTURE: std::sync::OnceLock<(base::publication::AdmittedPackage, fixture::Check)> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(fixture::complete)
}

pub(crate) fn shared_carrier() -> &'static crate::storage::AdmittedEpoch {
    static CARRIER: std::sync::OnceLock<crate::storage::AdmittedEpoch> = std::sync::OnceLock::new();
    CARRIER
        .get_or_init(|| crate::storage::AdmittedEpoch::from_package(&shared_fixture().0, &mut base::numeric(), limits()).unwrap())
}

pub(crate) fn first_carrier() -> &'static crate::storage::AdmittedEpoch {
    static FIRST: std::sync::OnceLock<crate::storage::AdmittedEpoch> = std::sync::OnceLock::new();
    FIRST.get_or_init(|| {
        let (package, verifier) = shared_fixture();
        let mut disclosure = package.disclosures();
        disclosure.frames.truncate(1);
        let first = base::d::restore(disclosure, verifier).unwrap();
        crate::storage::AdmittedEpoch::from_package(&first, &mut base::numeric(), limits()).unwrap()
    })
}

fn limits() -> base::Limits {
    base::Limits {
        work: 100_000_000,
        arithmetic_steps: 5_000_000,
        ..base::Limits::default()
    }
}

/// Claim: Admitted-only carrier construction preserves canonical package bytes, the structural event, all selected version projections and immutable debit vintages, and distinguishes complete content from event identity without selecting unused declarations.
/// ´claim:history:admitted-carrier-preserves-exact-projections´
/// ´test:unit:admitted-carrier-bytes´
#[test]
fn admitted_carrier_bytes() {
    let (package, verifier) = shared_fixture();
    let carrier = shared_carrier();
    let expected = crate::publication::encode(&package.disclosures(), &mut base::numeric(), limits()).unwrap();
    assert_eq!(carrier.bytes(), expected);
    let marker = &package.boundary().candidate().input().causes.bindings.last().unwrap().marker;
    assert_eq!(
        carrier.event(),
        &crate::admitted_result::EpochKey {
            scope: crate::admitted_result::EpochScope {
                history: marker.history.clone(),
                policy_identity: marker.policy_identity.clone(),
                policy_edition: marker.policy_edition.clone(),
                sequence: marker.sequence.clone()
            },
            boundary: marker.index,
        }
    );
    let mut renamed = marker.clone();
    renamed.name.push_str("-other-name");
    renamed.history_position += 100;
    assert_eq!(
        crate::admitted_result::event_key(&renamed),
        *carrier.event(),
        "marker aliases cannot evade an event conflict"
    );
    assert!(
        package.carrier().frames[0].sequence.len() > 1,
        "multi-act fixture must remain nontrivial"
    );
    assert!(package.carrier().frames[1].sequence.is_empty(), "the second epoch is empty");
    assert_declarations(carrier, package, verifier);
    assert_debits(carrier, package);

    let mut raw = package.disclosures();
    raw.causes.acts.reverse();
    raw.causes.declarations.reverse();
    let reordered = base::d::restore(raw.clone(), verifier).unwrap();
    let reordered = crate::admitted_result::AdmittedEpoch::from_package(&reordered, &mut base::numeric(), limits()).unwrap();
    assert!(
        carrier.same_content(&reordered),
        "set presentation is not retained-content variation"
    );

    let mut future = raw
        .causes
        .declarations
        .iter()
        .find(|d| d.id.namespace == "numeric")
        .unwrap()
        .clone();
    future.id.edition = 99;
    future.announced_at = 3;
    future.effective_at = 99;
    let mut edition = raw.causes.editions[0].clone();
    edition.id = future.id.clone();
    raw.causes.declarations.insert(0, future);
    raw.causes.editions.insert(0, edition);
    raw.causes.declarations.insert(
        1,
        base::Declaration {
            id: base::DeclarationId {
                namespace: "unused".into(),
                name: "present-but-not-selected".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: base::DeclarationContent::Opaque,
        },
    );
    assert!(
        !raw.causes.declarations.windows(2).all(|pair| pair[0].id < pair[1].id),
        "input reaches restoration unsorted"
    );
    let different = base::d::restore(raw, verifier).unwrap();
    let different = crate::admitted_result::AdmittedEpoch::from_package(&different, &mut base::numeric(), limits()).unwrap();
    assert_eq!(
        carrier.event(),
        different.event(),
        "additional unused public declarations leave the event key unchanged"
    );
    assert_eq!(
        carrier.declarations(),
        different.declarations(),
        "unused and future declarations must not become selected uses"
    );
    assert_eq!(carrier.debits(), different.debits());
    assert_ne!(carrier.bytes(), different.bytes());
    assert!(
        !carrier.same_content(&different),
        "same event with changed complete public content must conflict"
    );
    let mut tiny = limits();
    tiny.work = 1;
    assert!(matches!(
        crate::admitted_result::AdmittedEpoch::from_package(package, &mut base::numeric(), tiny),
        Err(crate::admitted_result::CarrierError::Encoding(
            crate::publication::Error::Arithmetic(_)
        ))
    ));
}

fn unframe(text: &str) -> Vec<&str> {
    let (count, mut rest) = text.split_once(':').unwrap();
    let count: usize = count.parse().unwrap();
    let mut fields = Vec::new();
    for _ in 0..count {
        let (length, value) = rest.split_once(':').unwrap();
        let length: usize = length.parse().unwrap();
        let (field, suffix) = value.split_at(length);
        fields.push(field);
        rest = suffix;
    }
    assert_eq!(rest, "");
    fields
}

fn assert_declarations(
    carrier: &crate::admitted_result::AdmittedEpoch,
    package: &base::publication::AdmittedPackage,
    verifier: &fixture::Check,
) {
    use crate::storage::{Family, Payload};
    let raw = package.carrier();
    let empty = base::validate_history(&[], &[]).unwrap();
    let declared = base::validate_record(&[], &empty, &raw.causes.declarations).unwrap();
    let document = pn_interchange::Document::from_canonical_bytes(carrier.bytes()).unwrap();
    let scope = &carrier.event().scope;
    let mut counts = std::collections::BTreeMap::new();
    for row in carrier.declarations() {
        *counts.entry(row.version.family).or_insert(0) += 1;
        let fields = unframe(&row.version.key);
        assert_eq!(
            &fields[..4],
            [&scope.history, &scope.policy_identity, &scope.policy_edition, &scope.sequence]
        );
        let expected = match row.version.family {
            Family::Rule | Family::Constants => assert_rule(row, package, &document, &fields),
            family => {
                assert_eq!(
                    row.selected_at, 2,
                    "observations select at terminal publication, not the observed frame"
                );
                assert_eq!(row.version.opens_at, 2);
                assert_eq!(row.version.announced_at, 2);
                assert_eq!(row.version.edition, "2");
                let boundary: u64 = fields[5].parse().unwrap();
                let frame = raw.frames.iter().find(|frame| frame.parameters.boundary == boundary).unwrap();
                let burn = base::burn::validate_burn(frame.burn.clone()).unwrap();
                let policy = base::constants::bind_marker_policy(&declared, frame.marker_policy.clone(), &burn).unwrap();
                let lineage = base::burn::validate_marker_history(frame.marker_history.clone(), &policy, verifier).unwrap();
                match family {
                    Family::MarkerPolicy | Family::BurnPublication => {
                        assert_eq!(fields.len(), 9);
                        assert_eq!(
                            fields[4],
                            if family == Family::MarkerPolicy {
                                "policy-observation"
                            } else {
                                "burn"
                            }
                        );
                        assert_eq!(
                            &fields[6..],
                            [&frame.burn.address_space, &frame.burn.edition, &frame.burn.sample_convention]
                        );
                        if family == Family::MarkerPolicy {
                            Payload::marker_policy(&policy).unwrap()
                        } else {
                            Payload::burn_publication(&burn).unwrap()
                        }
                    }
                    Family::Lineage | Family::UnsettledRecognition => {
                        assert_eq!(fields.len(), 12);
                        let r = frame.closure.markers.basis();
                        assert_eq!(
                            &fields[6..],
                            [
                                &r.history,
                                &r.policy_identity,
                                &r.policy_edition,
                                &r.verifier_profile,
                                &r.burn_publication_edition,
                                &r.sample_convention
                            ]
                        );
                        if family == Family::Lineage {
                            assert_eq!(fields[4], "lineage");
                            Payload::lineage(&lineage).unwrap()
                        } else {
                            assert_eq!(fields[4], "recognition");
                            Payload::recognition(&lineage).unwrap()
                        }
                    }
                    _ => unreachable!(),
                }
            }
        };
        assert_eq!(
            row.version.payload.as_ref().unwrap(),
            &expected,
            "complete payload comparison for {:?}",
            row.version.family
        );
    }
    assert_eq!(
        counts,
        std::collections::BTreeMap::from([
            (Family::Constants, 2),
            (Family::Rule, 4),
            (Family::MarkerPolicy, 2),
            (Family::Lineage, 2),
            (Family::BurnPublication, 2),
            (Family::UnsettledRecognition, 2),
        ])
    );
}

fn assert_rule(
    row: &crate::admitted_result::DeclarationUse,
    package: &base::publication::AdmittedPackage,
    document: &pn_interchange::Document,
    fields: &[&str],
) -> crate::storage::Payload {
    use crate::storage::{Family, Payload};
    let raw = package.carrier();
    assert_eq!(fields.len(), 7);
    assert_eq!(
        fields[4],
        if row.version.family == Family::Rule {
            "declaration"
        } else {
            "constants"
        }
    );
    let d = raw
        .causes
        .declarations
        .iter()
        .find(|d| d.id.namespace == fields[5] && d.id.name == fields[6] && d.id.edition.to_string() == row.version.edition)
        .unwrap();
    assert_eq!(row.version.announced_at, d.announced_at);
    assert_eq!(row.version.opens_at, d.effective_at);
    if row.version.family == Family::Constants {
        let binding = package
            .boundary()
            .candidate()
            .input()
            .causes
            .bindings
            .iter()
            .find(|b| b.inputs.parameters().boundary == row.selected_at)
            .unwrap();
        Payload::constants(binding.inputs.constants()).unwrap()
    } else {
        if d.id.namespace == "numeric" {
            assert!([1, 2].contains(&row.selected_at));
        } else {
            assert_eq!(row.selected_at, raw.frames[0].marker_policy.genesis_at);
        }
        let encoded_id = crate::storage_payload::array([
            crate::storage_payload::text(&d.id.namespace),
            crate::storage_payload::text(&d.id.name),
            crate::storage_payload::text(&d.id.edition.to_string()),
        ]);
        let item = crate::admitted_result::array(crate::admitted_result::item(document, 8, &[0]).unwrap())
            .unwrap()
            .iter()
            .find(|v| crate::admitted_result::array(v).unwrap()[0] == encoded_id)
            .unwrap();
        Payload::rule(&pn_interchange::Value::Bytes(item.to_canonical_bytes().into())).unwrap()
    }
}

fn assert_debits(carrier: &crate::admitted_result::AdmittedEpoch, package: &base::publication::AdmittedPackage) {
    let raw = package.disclosures();
    let expected = &raw.frames.last().unwrap().compiled.ledger.debits;
    assert!(expected.len() > 1);
    assert_eq!(carrier.debits().len(), expected.len());
    let document = pn_interchange::Document::from_canonical_bytes(carrier.bytes()).unwrap();
    let pn_interchange::Value::Map(map) = crate::admitted_result::item(&document, 3, &[raw.frames.len() - 1, 3]).unwrap() else {
        panic!("ledger debit map")
    };
    for debit in carrier.debits() {
        assert_eq!(&debit.key.scope, &carrier.event().scope);
        assert_eq!(&debit.disclosure, &expected[&debit.key.act]);
        assert_eq!(
            debit.disclosure.boundary, 1,
            "an empty successor does not rewrite the writing vintage"
        );
        let act = &debit.key.act;
        let id = crate::storage_payload::array([
            crate::storage_payload::text(&act.author),
            crate::storage_payload::text(&act.sequence.to_string()),
            crate::storage_payload::text(&act.family),
        ]);
        assert_eq!(
            debit.bytes,
            map.iter().find(|(key, _)| **key == id).unwrap().1.to_canonical_bytes()
        );
    }
}

/// Claim: A real admitted carrier does not activate PostgreSQL epoch persistence; the existing operation refuses `EpochResultHeld`.
/// ´claim:history:admitted-carrier-keeps-postgresql-held´
/// ´test:unit:admitted-carrier-postgresql-held´
#[test]
fn admitted_carrier_postgresql_held() {
    let carrier = shared_carrier();
    let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
    let mut file = std::fs::File::open(std::path::Path::new(&root).join("storage.json")).unwrap();
    let configuration = crate::Configuration::acquire(Some("host-secured"), &mut file).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let session = crate::Session::connect(configuration).await.unwrap();
            let mut store = crate::storage::PostgresStore::open_store(session).await.unwrap();
            assert_eq!(
                store.commit_admitted_epoch(carrier).await,
                Err(crate::storage::StorageError::EpochResultHeld)
            );
        });
}

pub(crate) fn conflicting_carrier() -> crate::storage::AdmittedEpoch {
    let (package, verifier) = shared_fixture();
    let mut raw = package.disclosures();
    raw.frames.truncate(1);
    raw.causes.declarations.insert(
        0,
        base::Declaration {
            id: base::DeclarationId {
                namespace: "unused".into(),
                name: "conflict".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: base::DeclarationContent::Opaque,
        },
    );
    let admitted = base::d::restore(raw, verifier).unwrap();
    crate::storage::AdmittedEpoch::from_package(&admitted, &mut base::numeric(), limits()).unwrap()
}
