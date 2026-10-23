mod common;
use common::{act, named, resolved};
use pn_records::{
    Declaration, DeclarationId, InvalidCause, Layout, PublicReference, ReferenceOrigin, Removal, Role, ValidationError,
    resolve_public_reference, select_effective_declaration, validate_record,
};

/// Claim: Distinct structural act identifiers preserve parallel endpoint-equal projections, while an identical repeated act or repeated parent/role edge refuses ambiguity instead of silently deduplicating input.
/// ´claim:acts:duplicates-refuse-and-parallel-identities-survive´
/// ´test:integration:structural-duplicates´
#[test]
fn structural_duplicates() {
    let first = act(1, Layout::Binary);
    let second = act(2, Layout::Binary);
    let records = [first.clone(), second];
    assert_eq!(validate_record(&records, &resolved(), &[]).unwrap().acts().len(), 2);
    assert_ne!(records[0].legs[0].id, records[1].legs[0].id);
    let duplicate = [first.clone(), first.clone()];
    assert_eq!(
        validate_record(&duplicate, &resolved(), &[]).unwrap_err(),
        ValidationError::DuplicateAct(first.id.clone())
    );
    let mut repositioned = first.clone();
    repositioned.authoritative_position += 100;
    assert_eq!(
        validate_record(&[first.clone(), repositioned], &resolved(), &[]).unwrap_err(),
        ValidationError::DuplicateAct(first.id.clone())
    );
    let mut repeated = first;
    repeated.legs.push(repeated.legs[0].clone());
    let expected = ValidationError::DuplicateEdge(repeated.legs[0].id.clone());
    assert_eq!(validate_record(&[repeated], &resolved(), &[]).unwrap_err(), expected);
}

/// Claim: Removing either required paired role refuses that exact missing co-leg through the public validator, so this completeness check cannot admit a candidate with either required role absent.
/// ´claim:acts:both-co-legs-are-required´
/// ´test:integration:missing-co-legs´
#[test]
fn missing_co_legs() {
    for missing in [Role::A, Role::T] {
        let mut record = act(1, Layout::Paired);
        record.legs.retain(|p| p.id.role != missing);
        let expected = ValidationError::MissingCoLeg {
            act: record.id.clone(),
            role: missing,
        };
        assert_eq!(validate_record(&[record], &resolved(), &[]).unwrap_err(), expected);
    }
}

/// Claim: A tombstoned dependency retains its identity and cannot erase an immutable protocol reference; the absent protocol target refuses even when both projection endpoints resolve.
/// ´claim:acts:protocol-references-outlive-dependency-removal´
/// ´test:integration:required-references´
#[test]
fn required_references() {
    let mut record = act(1, Layout::Binary);
    record.projections.dependency = Removal::Tombstoned(9);
    let edge = PublicReference::Edge(record.legs[0].id.clone());
    record.protocol_references.push(edge.clone());
    record.protocol_references.push(named("missing"));
    assert_eq!(
        validate_record(&[record.clone()], &resolved(), &[]).unwrap_err(),
        ValidationError::UnresolvedReference(named("missing"))
    );
    let mut available = resolved();
    available.insert(named("missing"));
    let records = [record.clone()];
    let view = validate_record(&records, &available, &[]).unwrap();
    assert_eq!(view.acts(), &[record]);
    assert_eq!(resolve_public_reference(&view, &edge), Ok(ReferenceOrigin::Batch));
}

/// Claim: Each malformed identity, quantity, authentication, parent, role or reference fixture refuses its exact typed cause; author and family exist only in the structural identity, preventing a second conflicting carrier copy.
/// ´claim:acts:invalid-local-fields-refuse´
/// ´test:integration:invalid-local-fields´
#[test]
fn invalid_local_fields() {
    for (case, cause) in [
        (0, InvalidCause::EmptyFamily),
        (1, InvalidCause::EmptyUnit),
        (2, InvalidCause::EmptyAuthor),
        (3, InvalidCause::ProjectionParent),
        (4, InvalidCause::DuplicateQuantityName),
        (5, InvalidCause::EmptyQuantityName),
        (6, InvalidCause::EmptyAuthentication),
        (7, InvalidCause::ProjectionRole),
        (8, InvalidCause::ReferenceComponent),
        (9, InvalidCause::ProjectionParent),
    ] {
        let mut record = act(1, Layout::Binary);
        match case {
            0 => record.id.family.clear(),
            1 => record.body.quantities[0].1.unit.clear(),
            2 => record.id.author.clear(),
            3 => record.legs[0].id.act.sequence = 2,
            4 => record.body.quantities.push(record.body.quantities[0].clone()),
            5 => record.body.quantities[0].0.clear(),
            6 => record.authentication_evidence.clear(),
            7 => record.legs[0].id.role = Role::A,
            8 => record.legs[0].source = named(""),
            _ => record.legs[0].id.act.family = "different-family".into(),
        }
        let expected = ValidationError::InvalidRepresentation {
            act: record.id.clone(),
            cause,
        };
        assert_eq!(
            validate_record(&[record], &resolved(), &[]).unwrap_err(),
            expected,
            "fixture {case}"
        );
        let error: &dyn std::error::Error = &expected;
        assert_ne!(error.to_string(), "");
    }
}

/// Claim: Neither paired leg can own a removal fact, content and dependency tombstones must follow acceptance, and a later act-owned dependency tombstone preserves both structural legs and their public identities.
/// ´claim:acts:removal-belongs-to-act-projections´
/// ´test:integration:projection-removal´
#[test]
fn projection_removal() {
    for role in [Role::A, Role::T] {
        for state in [Removal::Live, Removal::Tombstoned(9)] {
            let mut record = act(1, Layout::Paired);
            record.legs.iter_mut().find(|p| p.id.role == role).unwrap().removal = Some(state);
            let expected = ValidationError::InvalidRepresentation {
                act: record.id.clone(),
                cause: InvalidCause::CoLegRemoval,
            };
            assert_eq!(validate_record(&[record], &resolved(), &[]).unwrap_err(), expected);
        }
    }
    for position in [0, 7, 8] {
        for content in [false, true] {
            let mut record = act(1, Layout::Paired);
            if content {
                record.projections.content = Removal::Tombstoned(position);
            } else {
                record.projections.dependency = Removal::Tombstoned(position);
            }
            let expected = ValidationError::InvalidRepresentation {
                act: record.id.clone(),
                cause: InvalidCause::TombstonePosition,
            };
            assert_eq!(validate_record(&[record], &resolved(), &[]).unwrap_err(), expected);
        }
    }
    let mut record = act(1, Layout::Paired);
    record.projections.dependency = Removal::Tombstoned(9);
    let records = [record];
    let view = validate_record(&records, &resolved(), &[]).unwrap();
    assert_eq!(view.acts()[0].legs.len(), 2);
    for leg in &view.acts()[0].legs {
        assert_eq!(leg.removal, None);
        assert_eq!(
            resolve_public_reference(&view, &PublicReference::Edge(leg.id.clone())),
            Ok(ReferenceOrigin::Batch)
        );
    }
}

/// Claim: Accepted history forbids reintroducing an act identity, while a validated batch resolves its own act and leg identities and retained history names; missing and malformed required queries return their distinct typed refusals.
/// ´claim:acts:references-resolve-against-accepted-history´
/// ´test:integration:reference-resolution´
#[test]
fn reference_resolution() {
    let records = [act(1, Layout::Binary)];
    let identity = PublicReference::Act(records[0].id.clone());
    let mut history = resolved();
    history.insert(identity.clone());
    assert_eq!(
        validate_record(&records, &history, &[]).unwrap_err(),
        ValidationError::DuplicateAct(records[0].id.clone())
    );
    let view = validate_record(&records, &resolved(), &[]).unwrap();
    assert_eq!(resolve_public_reference(&view, &identity), Ok(ReferenceOrigin::Batch));
    assert_eq!(resolve_public_reference(&view, &named("left")), Ok(ReferenceOrigin::History));
    assert_eq!(
        resolve_public_reference(&view, &named("absent")),
        Err(ValidationError::UnresolvedReference(named("absent")))
    );
    assert_eq!(
        resolve_public_reference(&view, &named("")),
        Err(ValidationError::InvalidReference(named("")))
    );
    history.insert(named(""));
    assert_eq!(
        validate_record(&records, &history, &[]).unwrap_err(),
        ValidationError::InvalidReference(named(""))
    );
}

fn declaration(edition: u64, announced_at: u64, effective_at: u64) -> Declaration {
    Declaration {
        id: DeclarationId {
            namespace: "rules".into(),
            name: "edition".into(),
            edition,
        },
        announced_at,
        effective_at,
    }
}

/// Claim: As-of selection preserves the old opaque edition before a successor takes effect, selects the successor at its boundary independently of input order or edition number, and refuses a key with no effective edition; declaration contents remain outside this fixture.
/// ´claim:acts:opaque-editions-preserve-as-of-selection´
/// ´test:integration:effective-declarations´
#[test]
fn effective_declarations() {
    let old = declaration(100, 1, 2);
    let new = declaration(1, 3, 5);
    let future = declaration(200, 8, 10);
    for editions in [
        vec![old.clone(), new.clone(), future.clone()],
        vec![future.clone(), new.clone(), old.clone()],
    ] {
        let view = validate_record(&[], &resolved(), &editions).unwrap();
        for boundary in [2, 3, 4] {
            assert_eq!(select_effective_declaration(&view, "rules", "edition", boundary), Ok(&old));
        }
        for boundary in [5, 8, 9] {
            assert_eq!(select_effective_declaration(&view, "rules", "edition", boundary), Ok(&new));
        }
        assert_eq!(select_effective_declaration(&view, "rules", "edition", 10), Ok(&future));
        assert_eq!(
            select_effective_declaration(&view, "rules", "edition", 1),
            Err(ValidationError::MissingDeclaration {
                namespace: "rules".into(),
                name: "edition".into(),
                boundary: 1
            })
        );
        assert_eq!(
            select_effective_declaration(&view, "other", "edition", 10),
            Err(ValidationError::MissingDeclaration {
                namespace: "other".into(),
                name: "edition".into(),
                boundary: 10
            })
        );
    }
}

/// Claim: Declaration validation refuses duplicate edition identities, ambiguous simultaneous successors, empty keys and an effective boundary before announcement, so as-of selection cannot silently choose by vector order.
/// ´claim:acts:ambiguous-declaration-histories-refuse´
/// ´test:integration:invalid-declarations´
#[test]
fn invalid_declarations() {
    let old = declaration(1, 1, 2);
    assert_eq!(
        validate_record(&[], &resolved(), &[old.clone(), old.clone()]).unwrap_err(),
        ValidationError::DuplicateDeclaration(old.id.clone())
    );
    let conflicting = declaration(2, 1, 2);
    assert_eq!(
        validate_record(&[], &resolved(), &[old.clone(), conflicting.clone()]).unwrap_err(),
        ValidationError::AmbiguousDeclaration(conflicting.id)
    );
    let mut no_name = declaration(3, 1, 2);
    no_name.id.name.clear();
    let mut no_namespace = declaration(3, 1, 2);
    no_namespace.id.namespace.clear();
    for bad in [declaration(3, 4, 2), no_name, no_namespace] {
        let expected = ValidationError::InvalidDeclaration(bad.id.clone());
        assert_eq!(validate_record(&[], &resolved(), &[bad]).unwrap_err(), expected);
    }
}
