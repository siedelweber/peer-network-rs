mod common;

/// Claim: Public validation and boundary assembly preserve two distinct paired act identities as two complete acts with four owned legs, preventing public consumers from counting a co-leg as an act.
/// (´claim:acts:complete-acts-are-counted-once´)
/// ´test:integration:whole-act-boundary´
#[test]
fn whole_act_boundary() {
    let candidates = [
        common::act(1, pn_records::Layout::Paired),
        common::act(2, pn_records::Layout::Paired),
    ];
    let records = pn_records::validate_record(&candidates, &common::resolved(), &[]).unwrap();
    let boundary = pn_records::assemble_boundary_inputs(&records, 8).unwrap();
    assert_eq!(boundary.acts().len(), 2);
    assert_eq!(boundary.acts().iter().map(|act| act.legs().len()).sum::<usize>(), 4);
    assert_ne!(boundary.acts()[0].id(), boundary.acts()[1].id());
}
use common::{act, named, resolved};
use pn_records::{
    Declaration, DeclarationCause, DeclarationId, DependencyProjection, DependencyStatus, InvalidCause, Layout, PublicReference,
    ReferenceOrigin, Removal, Role, ValidationError, resolve_public_reference, select_effective_declaration, validate_history,
    validate_record,
};
use pn_records::{DependencyCause, MAX_DEPENDENCIES, assemble_boundary_inputs, dependency_status};

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
    record.projections.dependency = DependencyProjection::Tombstoned(9);
    let edge = PublicReference::Edge(record.legs[0].id.clone());
    record.protocol_references.push(edge.clone());
    record.protocol_references.push(named("missing"));
    assert_eq!(
        validate_record(&[record.clone()], &resolved(), &[]).unwrap_err(),
        ValidationError::UnresolvedReference(named("missing"))
    );
    let available = validate_history(&[], &[named("left"), named("right"), named("missing")]).unwrap();
    let records = [record.clone()];
    let view = validate_record(&records, &available, &[]).unwrap();
    assert_eq!(view.acts()[0].id(), &record.id);
    assert_eq!(view.acts()[0].projections(), &record.projections);
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
                record.projections.dependency = DependencyProjection::Tombstoned(position);
            }
            let expected = ValidationError::InvalidRepresentation {
                act: record.id.clone(),
                cause: InvalidCause::TombstonePosition,
            };
            assert_eq!(validate_record(&[record], &resolved(), &[]).unwrap_err(), expected);
        }
    }
    let mut record = act(1, Layout::Paired);
    record.projections.dependency = DependencyProjection::Tombstoned(9);
    let records = [record];
    let view = validate_record(&records, &resolved(), &[]).unwrap();
    assert_eq!(view.acts()[0].legs().len(), 2);
    for leg in view.acts()[0].legs() {
        assert_eq!(dependency_status(&view, leg.id()), Ok(DependencyStatus::Tombstoned(9)));
        assert_eq!(
            resolve_public_reference(&view, &PublicReference::Edge(leg.id().clone())),
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
    let history = validate_history(&records, &[named("left"), named("right")]).unwrap();
    assert_eq!(
        validate_record(&records, &history, &[]).unwrap_err(),
        ValidationError::DuplicateAct(records[0].id.clone())
    );
    let view = validate_record(&records, &resolved(), &[]).unwrap();
    assert_eq!(resolve_public_reference(&view, &identity), Ok(ReferenceOrigin::Batch));
    let leg = PublicReference::Edge(records[0].legs[0].id.clone());
    assert_eq!(resolve_public_reference(&view, &leg), Ok(ReferenceOrigin::Batch));
    assert_eq!(
        validate_history(&[], std::slice::from_ref(&leg)).unwrap_err(),
        ValidationError::InvalidReference(leg)
    );
    assert_eq!(resolve_public_reference(&view, &named("left")), Ok(ReferenceOrigin::History));
    assert_eq!(
        resolve_public_reference(&view, &named("absent")),
        Err(ValidationError::UnresolvedReference(named("absent")))
    );
    assert_eq!(
        resolve_public_reference(&view, &named("")),
        Err(ValidationError::InvalidReference(named("")))
    );
    assert_eq!(
        validate_history(&records, &[named("")]).unwrap_err(),
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
    let view = validate_record(&[], &resolved(), &[]).unwrap();
    assert_eq!(
        select_effective_declaration(&view, "", "key", 1),
        Err(ValidationError::InvalidSelectionKey(DeclarationCause::EmptyNamespace))
    );
    assert_eq!(
        select_effective_declaration(&view, "rules", "", 1),
        Err(ValidationError::InvalidSelectionKey(DeclarationCause::EmptyName))
    );
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
    for (bad, cause) in [
        (declaration(3, 4, 2), DeclarationCause::LateAnnouncement),
        (no_name, DeclarationCause::EmptyName),
        (no_namespace, DeclarationCause::EmptyNamespace),
    ] {
        let expected = ValidationError::InvalidDeclaration {
            id: bad.id.clone(),
            cause,
        };
        assert_eq!(validate_record(&[], &resolved(), &[bad]).unwrap_err(), expected);
    }
}

/// Claim: Dependency content distinguishes complete empty from missing tombstoned data, rejects empty Full, excessive, duplicate, unsorted and self lists, and only act identifiers can enter the declared dependency vector.
/// ´claim:acts:dependency-lists-have-canonical-content´
/// ´test:integration:dependency-content´
#[test]
fn dependency_content() {
    let mut parent = act(1, Layout::Binary);
    parent.authoritative_position = 1;
    let mut other = act(2, Layout::Binary);
    other.authoritative_position = 2;
    let history = validate_history(&[other.clone(), parent.clone()], &[named("left"), named("right")]).unwrap();
    let root = act(3, Layout::Paired);
    let cases = [
        (vec![], DependencyCause::EmptyFull),
        (vec![parent.id.clone(), parent.id.clone()], DependencyCause::NonCanonical),
        (vec![other.id.clone(), parent.id.clone()], DependencyCause::NonCanonical),
        (vec![root.id.clone()], DependencyCause::SelfDependency),
        (
            (0..=MAX_DEPENDENCIES)
                .map(|n| {
                    let mut id = parent.id.clone();
                    id.sequence = u64::try_from(n).unwrap();
                    id
                })
                .collect(),
            DependencyCause::TooMany,
        ),
    ];
    for (dependencies, cause) in cases {
        let mut candidate = root.clone();
        candidate.projections.dependency = DependencyProjection::Full(dependencies);
        let expected = ValidationError::Dependency {
            act: root.id.clone(),
            dependency: (cause == DependencyCause::SelfDependency).then(|| root.id.clone()),
            cause,
        };
        assert_eq!(validate_record(&[candidate], &history, &[]).unwrap_err(), expected);
    }
    let empty = validate_record(std::slice::from_ref(&root), &history, &[]).unwrap();
    assert_eq!(
        dependency_status(&empty, empty.acts()[0].legs()[0].id()),
        Ok(DependencyStatus::FullEmpty)
    );
    let mut full = root;
    full.projections.dependency = DependencyProjection::Full(vec![parent.id, other.id]);
    let view = validate_record(&[full], &history, &[]).unwrap();
    assert!(
        view.acts()[0]
            .legs()
            .iter()
            .all(|leg| dependency_status(&view, leg.id()) == Ok(DependencyStatus::Full))
    );
}

/// Claim: Declared dependencies resolve in history or earlier proposals with identical strict placement rules; missing, equal-position and later targets refuse, independently of input order.
/// ´claim:acts:dependencies-require-earlier-accepted-acts´
/// ´test:integration:dependency-placement´
#[test]
fn dependency_placement() {
    let parent = act(1, Layout::Binary);
    let mut root = act(2, Layout::Binary);
    root.projections.dependency = DependencyProjection::Full(vec![parent.id.clone()]);
    assert_eq!(
        validate_record(std::slice::from_ref(&root), &resolved(), &[]).unwrap_err(),
        ValidationError::Dependency {
            act: root.id.clone(),
            dependency: Some(parent.id.clone()),
            cause: DependencyCause::Missing
        }
    );
    let history = validate_history(std::slice::from_ref(&parent), &[named("left"), named("right")]).unwrap();
    for position in [7, 8] {
        root.authoritative_position = position;
        assert_eq!(
            validate_record(std::slice::from_ref(&root), &history, &[]).unwrap_err(),
            ValidationError::Dependency {
                act: root.id.clone(),
                dependency: Some(parent.id.clone()),
                cause: DependencyCause::NotEarlier
            }
        );
    }
    root.authoritative_position = 9;
    assert!(validate_record(std::slice::from_ref(&root), &history, &[]).is_ok());
    for proposed in [[root.clone(), parent.clone()], [parent.clone(), root.clone()]] {
        assert!(validate_record(&proposed, &resolved(), &[]).is_ok());
    }
}

/// Claim: Whole validated history derives an act and both co-leg identities together, refuses edge-only history input and reintroduced identities through the validated snapshot.
/// ´claim:acts:history-owns-its-structural-references´
/// ´test:integration:whole-history´
#[test]
fn whole_history() {
    let parent = act(1, Layout::Paired);
    let edge = PublicReference::Edge(parent.legs[0].id.clone());
    assert_eq!(
        validate_history(&[], std::slice::from_ref(&edge)).unwrap_err(),
        ValidationError::InvalidReference(edge.clone())
    );
    let history = validate_history(std::slice::from_ref(&parent), &[named("left"), named("right")]).unwrap();
    let view = validate_record(&[], &history, &[]).unwrap();
    assert_eq!(dependency_status(&view, &parent.legs[0].id), Ok(DependencyStatus::FullEmpty));
    let mut missing = parent.legs[0].id.clone();
    missing.act.sequence += 1;
    assert_eq!(
        dependency_status(&view, &missing),
        Err(ValidationError::UnresolvedReference(PublicReference::Edge(missing.clone())))
    );
    missing.act.author.clear();
    assert_eq!(
        dependency_status(&view, &missing),
        Err(ValidationError::InvalidReference(PublicReference::Edge(missing)))
    );
    for reference in [
        PublicReference::Act(parent.id.clone()),
        edge,
        PublicReference::Edge(parent.legs[1].id.clone()),
    ] {
        assert_eq!(resolve_public_reference(&view, &reference), Ok(ReferenceOrigin::History));
    }
    assert_eq!(
        validate_record(std::slice::from_ref(&parent), &history, &[]).unwrap_err(),
        ValidationError::DuplicateAct(parent.id)
    );
}

/// Claim: Principal closures contain precisely each proposal and its causal ancestors outside fixed history; shared in-epoch ancestors overlap, shared history ancestors do not, declared dependencies do not join closures, and their union equals all proposals regardless of input order.
/// ´claim:acts:overlapping-closures-retain-complete-inputs´
/// ´test:integration:overlapping-closures´
#[test]
fn overlapping_closures() {
    use std::collections::BTreeSet;
    let mut history_parent = act(1, Layout::Paired);
    history_parent.authoritative_position = 1;
    history_parent.projections.dependency = DependencyProjection::Tombstoned(2);
    let history = validate_history(std::slice::from_ref(&history_parent), &[named("left"), named("right")]).unwrap();
    let mut shared = act(2, Layout::Paired);
    shared.authoritative_position = 10;
    shared.body.asserted_parents = vec![history_parent.id.clone()];
    let mut left = act(3, Layout::Paired);
    left.authoritative_position = 11;
    left.body.asserted_parents = vec![shared.id.clone()];
    let mut right = act(4, Layout::Binary);
    right.authoritative_position = 12;
    right.body.asserted_parents = vec![shared.id.clone()];
    let mut chain = act(5, Layout::Binary);
    chain.authoritative_position = 13;
    chain.body.asserted_parents = vec![left.id.clone()];
    let mut separate = act(6, Layout::Binary);
    separate.authoritative_position = 14;
    separate.body.asserted_parents = vec![history_parent.id.clone()];
    separate.projections.dependency = DependencyProjection::Full(vec![left.id.clone()]);
    for reversed in [false, true] {
        let mut proposals = vec![shared.clone(), left.clone(), right.clone(), chain.clone(), separate.clone()];
        if reversed {
            proposals.reverse();
        }
        let view = validate_record(&proposals, &history, &[]).unwrap();
        let inputs = assemble_boundary_inputs(&view, 10).unwrap();
        assert_eq!(inputs.boundary(), 10);
        let expected = [vec![2], vec![2, 3], vec![2, 4], vec![2, 3, 5], vec![6]];
        for (closure, ids) in inputs.closures().iter().zip(expected) {
            assert_eq!(closure.members().iter().map(|id| id.sequence).collect::<Vec<_>>(), ids);
        }
        let union: BTreeSet<_> = inputs
            .closures()
            .iter()
            .flat_map(|closure| closure.members().iter())
            .collect();
        assert_eq!(union, proposals.iter().map(|act| &act.id).collect());
        assert_eq!(inputs.acts().iter().map(|act| act.id()).collect::<BTreeSet<_>>(), union);
        assert!(
            inputs
                .closures()
                .iter()
                .all(|closure| !closure.members().contains(&history_parent.id))
        );
        assert_eq!(inputs.acts()[0].legs().len(), 2);
        assert_eq!(inputs.acts()[1].legs().len(), 2);
        assert_eq!(inputs.work(), Some(23));
    }
}

/// Claim: Assembly refuses history on or beyond the fixed cut and proposals before it, while a history dependency tombstone neither refuses assembly nor enters a proposal's closure.
/// ´claim:acts:incomplete-boundary-inputs-refuse´
/// ´test:integration:boundary-refusals´
#[test]
fn boundary_refusals() {
    let mut parent = act(1, Layout::Binary);
    parent.authoritative_position = 1;
    let mut root = act(2, Layout::Paired);
    root.authoritative_position = 10;
    root.body.asserted_parents = vec![parent.id.clone()];
    root.projections.dependency = DependencyProjection::Full(vec![parent.id.clone()]);
    let history = validate_history(std::slice::from_ref(&parent), &[named("left"), named("right")]).unwrap();
    let view = validate_record(std::slice::from_ref(&root), &history, &[]).unwrap();
    for (cut, id) in [(1, parent.id.clone()), (11, root.id.clone())] {
        assert_eq!(
            assemble_boundary_inputs(&view, cut).unwrap_err(),
            ValidationError::Dependency {
                act: id,
                dependency: None,
                cause: DependencyCause::BoundaryPlacement,
            }
        );
    }
    parent.projections.dependency = DependencyProjection::Tombstoned(2);
    let history = validate_history(std::slice::from_ref(&parent), &[named("left"), named("right")]).unwrap();
    let view = validate_record(std::slice::from_ref(&root), &history, &[]).unwrap();
    let inputs = assemble_boundary_inputs(&view, 10).unwrap();
    assert_eq!(inputs.acts().len(), 1);
    assert_eq!(inputs.closures()[0].members(), vec![root.id]);
}

/// Claim: Asserted parents are canonical structural identifiers independent of removable dependency content; missing, self, duplicate, unsorted, excessive and non-earlier parents refuse their typed cause, while an earlier in-epoch parent is accepted.
/// ´claim:acts:asserted-parents-are-canonical-and-earlier´
/// ´test:integration:asserted-parents´
#[test]
fn asserted_parents() {
    use pn_records::{MAX_ASSERTED_PARENTS, ParentCause};
    let mut parent = act(1, Layout::Binary);
    parent.authoritative_position = 10;
    let mut root = act(2, Layout::Paired);
    root.authoritative_position = 11;
    let other = act(3, Layout::Binary);
    let cases = [
        (vec![other.id.clone()], Some(other.id.clone()), ParentCause::Missing),
        (vec![root.id.clone()], Some(root.id.clone()), ParentCause::SelfParent),
        (vec![parent.id.clone(), parent.id.clone()], None, ParentCause::NonCanonical),
        (vec![other.id.clone(), parent.id.clone()], None, ParentCause::NonCanonical),
        (vec![parent.id.clone(); MAX_ASSERTED_PARENTS + 1], None, ParentCause::TooMany),
    ];
    for (parents, target, cause) in cases {
        root.body.asserted_parents = parents;
        assert_eq!(
            validate_record(&[root.clone(), parent.clone()], &resolved(), &[]).unwrap_err(),
            ValidationError::Parent {
                act: root.id.clone(),
                parent: target,
                cause
            }
        );
    }
    root.body.asserted_parents = vec![parent.id.clone()];
    for position in [11, 12] {
        parent.authoritative_position = position;
        assert_eq!(
            validate_record(&[root.clone(), parent.clone()], &resolved(), &[]).unwrap_err(),
            ValidationError::Parent {
                act: root.id.clone(),
                parent: Some(parent.id.clone()),
                cause: ParentCause::NotEarlier
            }
        );
    }
    parent.authoritative_position = 10;
    assert!(validate_record(&[root, parent], &resolved(), &[]).is_ok());
}
