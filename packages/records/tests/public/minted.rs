use pn_records::{
    CandidateAct, IdentifierClass, Layout, PublicReference, ReferenceOrigin, Removal, Role, ValidationError,
    resolve_public_reference, validate_history, validate_record,
};

use super::common::{act, named, resolved};

fn genesis(family: &str, layout: Layout) -> CandidateAct {
    let mut input = act(1, layout);
    input.id.family = family.into();
    let terminal = if layout == Layout::Binary { Role::Binary } else { Role::T };
    for leg in &mut input.legs {
        leg.id.act = input.id.clone();
        if leg.id.role == terminal {
            leg.target = PublicReference::Minted(input.id.clone());
        }
    }
    if family == "Publish" && layout == Layout::Binary {
        input.body.license = Some(pn_records::LicenseQualifiers {
            attribution: pn_records::LicenseDegree {
                numerator: 1,
                denominator: 2,
            },
            provenance: pn_records::LicenseDegree {
                numerator: 2,
                denominator: 3,
            },
        });
    }
    input
}

/// Claim: Minted references resolve from complete self-minting terminal targets in the six genesis families, including their own batch act; missing genesis, ordinary acts, wrong families, wrong layout and externally injected minted names cannot supply a node. Opening removal preserves resolution and duplicate act identity cannot mint again.
/// ´claim:acts:minted-references-require-self-minting-genesis´
/// ´test:integration:minted-resolution´
#[test]
fn minted_resolution() {
    for (family, layout) in [
        ("Publish", Layout::Binary),
        ("Owner", Layout::Binary),
        ("Participant", Layout::Paired),
        ("Review", Layout::Paired),
        ("Send", Layout::Paired),
        ("Bid", Layout::Paired),
    ] {
        let mut input = genesis(family, layout);
        let reference = PublicReference::Minted(input.id.clone());
        let batch = validate_record(std::slice::from_ref(&input), &resolved(), &[]).unwrap();
        assert_eq!(resolve_public_reference(&batch, &reference), Ok(ReferenceOrigin::Batch));
        let history = validate_history(std::slice::from_ref(&input), &[named("left"), named("right")]).unwrap();
        let replay = validate_record(&[], &history, &[]).unwrap();
        assert_eq!(resolve_public_reference(&replay, &reference), Ok(ReferenceOrigin::History));
        let mut consumer = act(2, Layout::Binary);
        consumer.legs[0].target = reference.clone();
        assert!(validate_record(&[consumer.clone()], &history, &[]).is_ok());
        let dangling = validate_record(&[consumer.clone()], &resolved(), &[]).unwrap();
        assert_eq!(
            resolve_public_reference(&dangling, &reference),
            Err(ValidationError::UnresolvedReference(reference.clone()))
        );
        consumer.protocol_references.push(reference.clone());
        assert_eq!(
            validate_record(&[consumer], &resolved(), &[]).unwrap_err(),
            ValidationError::UnresolvedReference(reference.clone())
        );
        assert_eq!(
            validate_record(std::slice::from_ref(&input), &history, &[]).unwrap_err(),
            ValidationError::DuplicateAct(input.id.clone())
        );
        if layout == Layout::Paired {
            let mut a_only = input.clone();
            for leg in &mut a_only.legs {
                leg.target = if leg.id.role == Role::A {
                    reference.clone()
                } else {
                    named("right")
                };
            }
            let ordinary = validate_record(&[a_only.clone()], &resolved(), &[]).unwrap();
            assert_eq!(
                resolve_public_reference(&ordinary, &reference),
                Err(ValidationError::UnresolvedReference(reference.clone()))
            );
            let history = validate_history(&[a_only], &[named("left"), named("right")]).unwrap();
            assert_eq!(
                resolve_public_reference(&validate_record(&[], &history, &[]).unwrap(), &reference),
                Err(ValidationError::UnresolvedReference(reference.clone()))
            );
        }
        input.projections.content = Removal::Tombstoned((6, 1));
        let removed = validate_history(std::slice::from_ref(&input), &[named("left"), named("right")]).unwrap();
        assert_eq!(
            resolve_public_reference(&validate_record(&[], &removed, &[]).unwrap(), &reference),
            Ok(ReferenceOrigin::History)
        );
        for leg in &mut input.legs {
            leg.target = named("right");
        }
        input.body.license = None;
        let ordinary = validate_record(&[input], &resolved(), &[]).unwrap();
        assert_eq!(
            resolve_public_reference(&ordinary, &reference),
            Err(ValidationError::UnresolvedReference(reference.clone()))
        );
        assert_eq!(
            validate_history(&[], std::slice::from_ref(&reference)).unwrap_err(),
            ValidationError::InvalidReference(reference)
        );
    }
    for (family, layout) in [
        ("Affinity", Layout::Binary),
        ("Publish", Layout::Paired),
        ("Bid", Layout::Binary),
    ] {
        let input = genesis(family, layout);
        let reference = PublicReference::Minted(input.id.clone());
        let batch = validate_record(&[input], &resolved(), &[]).unwrap();
        assert_eq!(
            resolve_public_reference(&batch, &reference),
            Err(ValidationError::UnresolvedReference(reference))
        );
    }
}

/// Claim: The minted constructor is distinct from act, edge and external-name references, ordered after those existing variants; its identity contains only the genesis act identifier. Node constructor classes distinguish grounded, named and minted terms without treating act, edge or foreign namespaces as nodes, and malformed minted identifiers refuse resolution.
/// ´claim:acts:minted-identity-is-a-distinct-structural-constructor´
/// ´test:integration:minted-identity´
#[test]
fn minted_identity() {
    let input = genesis("Publish", Layout::Binary);
    let reference = PublicReference::Minted(input.id.clone());
    let external = PublicReference::Named {
        namespace: "mint".into(),
        name: format!("{:?}", input.id),
    };
    let expected = vec![
        PublicReference::Act(input.id.clone()),
        PublicReference::Edge(input.legs[0].id.clone()),
        external.clone(),
        reference.clone(),
    ];
    let mut actual = expected.clone();
    actual.reverse();
    actual.sort();
    actual.dedup();
    assert_eq!(actual, expected);
    assert_eq!(reference.identifier_class(), Some(IdentifierClass::Minted));
    assert_eq!(external.identifier_class(), None);
    assert_eq!(expected[0].identifier_class(), None);
    assert_eq!(expected[1].identifier_class(), None);
    for (namespace, class) in [
        ("addr", IdentifierClass::Grounded),
        ("prof", IdentifierClass::Grounded),
        ("name", IdentifierClass::Named),
    ] {
        assert_eq!(
            PublicReference::Named {
                namespace: namespace.into(),
                name: "a".into()
            }
            .identifier_class(),
            Some(class)
        );
    }
    let batch = validate_record(std::slice::from_ref(&input), &resolved(), &[]).unwrap();
    let mut malformed = input.id.clone();
    malformed.author.clear();
    let malformed = PublicReference::Minted(malformed);
    assert_eq!(
        resolve_public_reference(&batch, &malformed),
        Err(ValidationError::InvalidReference(malformed))
    );
    let mut second = genesis("Publish", Layout::Binary);
    second.id.sequence += 1;
    assert_ne!(reference, PublicReference::Minted(second.id));
    let mut moved = input;
    moved.finalization_epoch += 1;
    moved.authoritative_position += 1;
    moved.logical_time += 1;
    assert_eq!(reference, PublicReference::Minted(moved.id));
}

/// Claim: Grounded and public-name endpoints need no supplied lookup entry, while act and edge protocol references require their complete target. There is no license namespace exemption; supplied names assert lookup availability only, and malformed node terms still refuse.
/// ´claim:acts:reference-admission-distinguishes-node-terms-and-protocol-targets´
/// ´test:integration:reference-classes´
#[test]
fn reference_classes() {
    for namespace in ["addr", "prof", "name"] {
        let reference = PublicReference::Named {
            namespace: namespace.into(),
            name: "unregistered".into(),
        };
        let mut input = act(1, Layout::Binary);
        input.protocol_references.clear();
        input.legs[0].source = reference.clone();
        input.legs[0].target = reference.clone();
        let empty = validate_history(&[], &[]).unwrap();
        let batch = validate_record(std::slice::from_ref(&input), &empty, &[]).unwrap();
        assert_eq!(
            resolve_public_reference(&batch, &reference),
            Err(ValidationError::UnresolvedReference(reference.clone()))
        );
        assert!(validate_history(std::slice::from_ref(&input), &[]).is_ok());
        let supplied = validate_history(&[], std::slice::from_ref(&reference)).unwrap();
        let batch = validate_record(std::slice::from_ref(&input), &supplied, &[]).unwrap();
        assert_eq!(resolve_public_reference(&batch, &reference), Ok(ReferenceOrigin::History));
        input.legs[0].target = PublicReference::Named {
            namespace: namespace.into(),
            name: String::new(),
        };
        assert!(validate_record(&[input], &empty, &[]).is_err());
    }
    let target = act(1, Layout::Binary);
    for reference in [
        PublicReference::Act(target.id.clone()),
        PublicReference::Edge(target.legs[0].id.clone()),
    ] {
        let mut consumer = act(2, Layout::Binary);
        consumer.protocol_references = vec![reference.clone()];
        assert_eq!(
            validate_record(std::slice::from_ref(&consumer), &resolved(), &[]).unwrap_err(),
            ValidationError::UnresolvedReference(reference.clone())
        );
        let batch = validate_record(&[target.clone(), consumer.clone()], &resolved(), &[]).unwrap();
        assert_eq!(resolve_public_reference(&batch, &reference), Ok(ReferenceOrigin::Batch));
        let history = validate_history(std::slice::from_ref(&target), &[named("left"), named("right")]).unwrap();
        let batch = validate_record(&[consumer], &history, &[]).unwrap();
        assert_eq!(resolve_public_reference(&batch, &reference), Ok(ReferenceOrigin::History));
    }
    let mut input = genesis("Publish", Layout::Binary);
    input.protocol_references = vec![PublicReference::Named {
        namespace: "license".into(),
        name: "unlisted terms".into(),
    }];
    assert!(validate_record(std::slice::from_ref(&input), &resolved(), &[]).is_err());
    input.protocol_references = vec![PublicReference::Named {
        namespace: "license".into(),
        name: String::new(),
    }];
    assert!(validate_record(&[input], &resolved(), &[]).is_err());
}

/// Claim: Content genesis retains one exact attribution/provenance pair, with both degrees in the nonnegative unit interval and positive denominators. Missing genesis pairs, misplaced pairs and invalid bounds refuse; payload removal preserves the pair without interpreting its license meaning.
/// ´claim:acts:content-genesis-retains-bounded-license-pair´
/// ´test:integration:genesis-license-pair´
#[test]
fn genesis_license_pair() {
    use pn_records::{InvalidCause, LicenseDegree, LicenseQualifiers};
    let base = genesis("Publish", Layout::Binary);
    for (a, o) in [(0, 0), (0, 6), (6, 0), (6, 6), (1, 2), (3, 5)] {
        let pair = LicenseQualifiers {
            attribution: LicenseDegree {
                numerator: a,
                denominator: 6,
            },
            provenance: LicenseDegree {
                numerator: o,
                denominator: 6,
            },
        };
        let mut input = base.clone();
        input.body.license = Some(pair);
        let batch = validate_record(std::slice::from_ref(&input), &resolved(), &[]).unwrap();
        assert_eq!(batch.acts()[0].body().license, Some(pair));
        input.projections.content = Removal::Tombstoned((6, 1));
        let removed = validate_history(&[input], &[named("left"), named("right")]).unwrap();
        assert_eq!(removed.acts()[0].body().license, Some(pair));
    }
    let mut invalid = Vec::new();
    for attribution in [true, false] {
        for (numerator, denominator) in [(-1, 2), (3, 2), (0, 0), (0, -1), (i64::MIN, 1), (i64::MAX, 1)] {
            let mut input = base.clone();
            let pair = input.body.license.as_mut().unwrap();
            let degree = LicenseDegree { numerator, denominator };
            if attribution {
                pair.attribution = degree;
            } else {
                pair.provenance = degree;
            }
            invalid.push(input);
        }
    }
    let mut missing = base.clone();
    missing.body.license = None;
    invalid.push(missing);
    let mut ordinary = base.clone();
    ordinary.legs[0].target = PublicReference::Minted(pn_records::ActId {
        sequence: 99,
        ..ordinary.id.clone()
    });
    invalid.push(ordinary);
    for (family, layout) in [
        ("Owner", Layout::Binary),
        ("Participant", Layout::Paired),
        ("Review", Layout::Paired),
        ("Send", Layout::Paired),
        ("Bid", Layout::Paired),
        ("Affinity", Layout::Binary),
    ] {
        let mut input = genesis(family, layout);
        input.body.license = base.body.license;
        invalid.push(input);
    }
    for input in invalid {
        let expected = ValidationError::InvalidRepresentation {
            act: input.id.clone(),
            cause: InvalidCause::LicenseQualifiers,
        };
        assert_eq!(
            validate_record(std::slice::from_ref(&input), &resolved(), &[]).unwrap_err(),
            expected
        );
        assert_eq!(
            validate_history(&[input], &[named("left"), named("right")]).unwrap_err(),
            expected
        );
    }
}
