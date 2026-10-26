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
        input.projections.content = Removal::Tombstoned((6, 1));
        let removed = validate_history(std::slice::from_ref(&input), &[named("left"), named("right")]).unwrap();
        assert_eq!(
            resolve_public_reference(&validate_record(&[], &removed, &[]).unwrap(), &reference),
            Ok(ReferenceOrigin::History)
        );
        for leg in &mut input.legs {
            leg.target = named("right");
        }
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
