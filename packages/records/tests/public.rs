mod common;
use common::{act, named, resolved};
use pn_records::{Layout, Removal, Role, ValidationError, validate_record};

/// Claim: Distinct structural act identifiers preserve parallel endpoint-equal projections, while an identical repeated act or repeated parent/role edge refuses ambiguity instead of silently deduplicating input.
/// ´claim:acts:duplicates-refuse-and-parallel-identities-survive´
/// ´test:integration:structural-duplicates´
#[test]
fn structural_duplicates() {
    let first = act(1, Layout::Binary);
    let second = act(2, Layout::Binary);
    let records = [first.clone(), second];
    assert_eq!(validate_record(&records, &resolved()).unwrap().acts().len(), 2);
    assert_ne!(records[0].mandatory[0].id, records[1].mandatory[0].id);
    let duplicate = [first.clone(), first.clone()];
    assert_eq!(
        validate_record(&duplicate, &resolved()).unwrap_err(),
        ValidationError::DuplicateAct(first.id.clone())
    );
    let mut repeated = first;
    repeated.mandatory.push(repeated.mandatory[0].clone());
    let expected = ValidationError::DuplicateEdge(repeated.mandatory[0].id.clone());
    assert_eq!(validate_record(&[repeated], &resolved()).unwrap_err(), expected);
}

/// Claim: Removing either required paired role refuses that exact missing co-leg through the public validator, so a half act cannot become an accounting unit.
/// ´claim:acts:both-co-legs-are-required´
/// ´test:integration:missing-co-legs´
#[test]
fn missing_co_legs() {
    for missing in [Role::A, Role::T] {
        let mut record = act(1, Layout::Paired);
        record.mandatory.retain(|p| p.id.role != missing);
        let expected = ValidationError::MissingCoLeg {
            act: record.id.clone(),
            role: missing,
        };
        assert_eq!(validate_record(&[record], &resolved()).unwrap_err(), expected);
    }
}

/// Claim: A tombstoned dependency retains its identity and cannot erase an immutable protocol reference; the absent protocol target refuses even when both projection endpoints resolve.
/// ´claim:acts:protocol-references-outlive-dependency-removal´
/// ´test:integration:required-references´
#[test]
fn required_references() {
    let mut record = act(1, Layout::Binary);
    record.removable = std::mem::take(&mut record.mandatory);
    record.removable[0].removal = Removal::Tombstoned(9);
    record.protocol_references.push(named("missing"));
    assert_eq!(
        validate_record(&[record.clone()], &resolved()).unwrap_err(),
        ValidationError::UnresolvedReference(named("missing"))
    );
    let mut available = resolved();
    available.insert(named("missing"));
    let records = [record.clone()];
    assert_eq!(validate_record(&records, &available).unwrap().acts(), &[record]);
}

/// Claim: Empty identity or unit fields, conflicting author, wrong projection parent and removal of a mandatory leg each refuse as a typed local representation error, without claiming cryptographic authentication or family formation.
/// ´claim:acts:invalid-local-fields-refuse´
/// ´test:integration:invalid-local-fields´
#[test]
fn invalid_local_fields() {
    for field in 0..5 {
        let mut record = act(1, Layout::Binary);
        match field {
            0 => record.id.family.clear(),
            1 => record.body.quantities[0].1.unit.clear(),
            2 => record.author = "other".into(),
            3 => record.mandatory[0].id.act.sequence = 2,
            _ => record.mandatory[0].removal = Removal::Tombstoned(9),
        }
        assert!(matches!(
            validate_record(&[record], &resolved()),
            Err(ValidationError::InvalidRepresentation { .. })
        ));
    }
}
