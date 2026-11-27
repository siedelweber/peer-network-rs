use pn_act_authentication::common::{
    ActDocument, ActDocumentName, BudgetReason, CommonError, Limits, WitnessedActDocument, WitnessedActDocumentName,
    act_approval_message, registry,
};
use pn_interchange::{Coordinate, NamespaceLabel, Registry, Theory};

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn word(text: &str) -> [u8; 32] {
    bytes(text).try_into().unwrap()
}

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../common-documents.json")).unwrap()
}

fn limits() -> Limits {
    Limits {
        input_bytes: 1024,
        output_bytes: 1024,
        canonical_allocation_bytes: 8192,
        max_pairs: 0,
        collection_allocation_bytes: 0,
    }
}

fn canonical_threshold(mut accepts: impl FnMut(usize) -> bool) -> usize {
    let mut low = 0;
    let mut high = limits().canonical_allocation_bytes;
    while low < high {
        let mid = low.midpoint(high);
        if accepts(mid) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    low
}

fn act(row: &serde_json::Value) -> ActDocument {
    let members = row["members"].as_array().unwrap();
    ActDocument::new(
        word(members[0].as_str().unwrap()),
        word(members[1].as_str().unwrap()),
        word(members[2].as_str().unwrap()),
        word(members[3].as_str().unwrap()),
        word(members[4].as_str().unwrap()),
        word(members[5].as_str().unwrap()),
        word(members[6].as_str().unwrap()),
    )
}

fn witness(row: &serde_json::Value) -> WitnessedActDocument {
    let members = row["members"].as_array().unwrap();
    WitnessedActDocument::new(
        word(members[0].as_str().unwrap()),
        word(members[1].as_str().unwrap()),
        word(members[2].as_str().unwrap()),
        word(members[3].as_str().unwrap()),
    )
}

fn expected(name: &str) -> CommonError {
    match name {
        "Canonical" => CommonError::Canonical,
        "Count" => CommonError::Count,
        "MemberWidth" => CommonError::MemberWidth,
        "MemberType" => CommonError::MemberType,
        "Namespace" => CommonError::Namespace,
        "Body" => CommonError::Body,
        "OperationVersion" => CommonError::OperationVersion,
        "OperationPatch" => CommonError::OperationPatch,
        _ => panic!("unexpected fixture refusal {name}"),
    }
}

fn act_input_output_boundaries(value: ActDocument, canonical: &[u8]) {
    let mut limited = limits();
    limited.input_bytes = canonical.len() - 1;
    assert!(matches!(
        ActDocument::decode_strict(canonical, limited),
        Err(CommonError::UnavailableBudget {
            reason: BudgetReason::InputBytes,
            charged_bytes: 0
        })
    ));
    limited = limits();
    limited.output_bytes = canonical.len() - 1;
    assert!(matches!(
        value.encode(limited),
        Err(CommonError::UnavailableBudget {
            reason: BudgetReason::OutputBytes,
            charged_bytes: 0
        })
    ));
}

/// Claim: The act's complete canonical bytes and digest match an independent encoder, and ordered malformed neighbours refuse without repair.
/// ´claim:authentication:common-act-canonical´
/// ´test:integration:common-act-canonical´
#[test]
fn common_act_canonical() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().unwrap();
    let first = act(&cases[0]);
    let second = act(&cases[1]);
    for row in &cases[..2] {
        let value = act(row);
        let canonical = bytes(row["canonical"].as_str().unwrap());
        let name = ActDocumentName::from_bytes(word(row["name"].as_str().unwrap()));
        assert_eq!(value.encode(limits()).unwrap(), canonical);
        assert_eq!(ActDocument::decode_strict(&canonical, limits()), Ok(value));
        assert_eq!(value.name(limits()), Ok(name));
        assert_eq!(value.matches_name(name, limits()), Ok(true));
        assert_eq!(act_approval_message(&value, limits()), Ok(*name.as_bytes()));
    }
    assert_ne!(first, second);
    assert_eq!(first.matches_name(second.name(limits()).unwrap(), limits()), Ok(false));
    for row in fixture["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["role"] == "act")
    {
        assert_eq!(
            ActDocument::decode_strict(&bytes(row["canonical"].as_str().unwrap()), limits()),
            Err(expected(row["expected"].as_str().unwrap())),
            "{}",
            row["label"]
        );
    }
    let canonical = bytes(cases[0]["canonical"].as_str().unwrap());
    act_input_output_boundaries(first, &canonical);
    let encode_charge = canonical_threshold(|ceiling| {
        first
            .encode(Limits {
                canonical_allocation_bytes: ceiling,
                ..limits()
            })
            .is_ok()
    });
    let decode_charge = canonical_threshold(|ceiling| {
        ActDocument::decode_strict(
            &canonical,
            Limits {
                canonical_allocation_bytes: ceiling,
                ..limits()
            },
        )
        .is_ok()
    });
    for (charge, read) in [(encode_charge, false), (decode_charge, true)] {
        assert!(charge > 0);
        let at = Limits {
            canonical_allocation_bytes: charge,
            ..limits()
        };
        let below = Limits {
            canonical_allocation_bytes: charge - 1,
            ..limits()
        };
        let above = Limits {
            canonical_allocation_bytes: charge + 1,
            ..limits()
        };
        if read {
            assert_eq!(ActDocument::decode_strict(&canonical, at), Ok(first));
            assert!(matches!(
                ActDocument::decode_strict(&canonical, below),
                Err(CommonError::UnavailableBudget {
                    reason: BudgetReason::CanonicalAllocation,
                    ..
                })
            ));
            assert_eq!(ActDocument::decode_strict(&canonical, above), Ok(first));
        } else {
            assert_eq!(first.encode(at), Ok(canonical.clone()));
            assert!(matches!(
                first.encode(below),
                Err(CommonError::UnavailableBudget {
                    reason: BudgetReason::CanonicalAllocation,
                    ..
                })
            ));
            assert_eq!(first.encode(above), Ok(canonical.clone()));
        }
    }
}

/// Claim: The witnessed act's exact unsigned bytes and name match an independent encoder, and malformed neighbours refuse before patch selection.
/// ´claim:authentication:common-witness-canonical´
/// ´test:integration:common-witness-canonical´
#[test]
fn common_witness_canonical() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().unwrap();
    for row in &cases[2..] {
        let value = witness(row);
        let canonical = bytes(row["canonical"].as_str().unwrap());
        let name = WitnessedActDocumentName::from_bytes(word(row["name"].as_str().unwrap()));
        assert_eq!(value.encode(limits()).unwrap(), canonical);
        assert_eq!(WitnessedActDocument::decode_strict(&canonical, limits()), Ok(value));
        assert_eq!(value.name(limits()), Ok(name));
        assert_eq!(value.matches_name(name, limits()), Ok(true));
    }
    for row in fixture["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["role"] == "witness")
    {
        assert_eq!(
            WitnessedActDocument::decode_strict(&bytes(row["canonical"].as_str().unwrap()), limits()),
            Err(expected(row["expected"].as_str().unwrap())),
            "{}",
            row["label"]
        );
    }
    let value = witness(&cases[2]);
    let canonical = bytes(cases[2]["canonical"].as_str().unwrap());
    let supplied_other = WitnessedActDocumentName::from_bytes(word(cases[3]["name"].as_str().unwrap()));
    assert_eq!(value.matches_name(supplied_other, limits()), Ok(false));
    let encode_charge = canonical_threshold(|ceiling| {
        value
            .encode(Limits {
                canonical_allocation_bytes: ceiling,
                ..limits()
            })
            .is_ok()
    });
    let decode_charge = canonical_threshold(|ceiling| {
        WitnessedActDocument::decode_strict(
            &canonical,
            Limits {
                canonical_allocation_bytes: ceiling,
                ..limits()
            },
        )
        .is_ok()
    });
    for (charge, read) in [(encode_charge, false), (decode_charge, true)] {
        assert!(charge > 0);
        let at = Limits {
            canonical_allocation_bytes: charge,
            ..limits()
        };
        let below = Limits {
            canonical_allocation_bytes: charge - 1,
            ..limits()
        };
        let above = Limits {
            canonical_allocation_bytes: charge + 1,
            ..limits()
        };
        if read {
            assert_eq!(WitnessedActDocument::decode_strict(&canonical, at), Ok(value));
            assert!(matches!(
                WitnessedActDocument::decode_strict(&canonical, below),
                Err(CommonError::UnavailableBudget {
                    reason: BudgetReason::CanonicalAllocation,
                    ..
                })
            ));
            assert_eq!(WitnessedActDocument::decode_strict(&canonical, above), Ok(value));
        } else {
            assert_eq!(value.encode(at), Ok(canonical.clone()));
            assert!(matches!(
                value.encode(below),
                Err(CommonError::UnavailableBudget {
                    reason: BudgetReason::CanonicalAllocation,
                    ..
                })
            ));
            assert_eq!(value.encode(above), Ok(canonical.clone()));
        }
    }
}

/// Claim: The two embedded published theory objects and coordinates are exactly those acquired from their source files.
/// ´claim:authentication:common-auth-registry´
/// ´test:integration:common-auth-registry´
#[test]
fn common_auth_registry() {
    let actual = registry().unwrap();
    let mut expected = Registry::new();
    for (name, source) in [
        ("org.peer-network.test.act", include_str!("../../schema/common-act.cddl")),
        (
            "org.peer-network.test.act.witness",
            include_str!("../../schema/common-witnessed-act.cddl"),
        ),
    ] {
        let label = NamespaceLabel::parse(name).unwrap();
        let coordinate = Coordinate::new(label, 1, 0);
        expected.acquire(coordinate.clone(), Theory::parse(source).unwrap()).unwrap();
        assert_eq!(
            actual.theory(&coordinate).unwrap().source(),
            expected.theory(&coordinate).unwrap().source()
        );
        assert_eq!(actual.theory(&coordinate).unwrap().coordinate(), (1, 0));
    }
}
