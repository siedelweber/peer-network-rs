//! Focused fixture replay controls.

use super::*;
use crate::admitted_carrier_tests::{base, fixture, tree_fixture};

struct Fixture {
    verifier: fixture::Check,
    generation: Generation,
    root_bytes: Vec<u8>,
    child_bytes: Vec<u8>,
    root_scope: EpochScope,
    root_identity: Identity,
    child_identity: Identity,
    root_uses: Vec<AssertedUse>,
    child_uses: Vec<AssertedUse>,
}

fn limits() -> disclosures::Limits {
    disclosures::Limits {
        work: 100_000_000,
        arithmetic_steps: 5_000_000,
        ..disclosures::Limits::default()
    }
}

fn fixture() -> Fixture {
    let (child, verifier) = fixture::complete();
    let mut raw = child.disclosures();
    raw.frames.truncate(1);
    let root = disclosures::restore(raw, &verifier).unwrap();
    let root_position =
        Position::from_package(&root, None, RECIPE, usize::MAX, &mut EncodingUsage::default(), |_| Ok(())).unwrap();
    let child_position = Position::from_package(
        &child,
        Some(&root_position),
        RECIPE,
        usize::MAX,
        &mut EncodingUsage::default(),
        |_| Ok(()),
    )
    .unwrap();
    let root_retained = Retained::from_position(&root_position, &mut base::numeric(), limits()).unwrap();
    let child_retained = Retained::from_position(&child_position, &mut base::numeric(), limits()).unwrap();
    let root_identity = *root_retained.event().1;
    let child_identity = *child_retained.event().1;
    let root_uses = root_retained
        .declarations()
        .iter()
        .cloned()
        .map(|declaration| AssertedUse {
            declaration,
            origin: root_identity,
        })
        .collect();
    let child_uses = child_retained
        .declarations()
        .iter()
        .cloned()
        .map(|declaration| {
            let origin = if super::super::unqualified(declaration.version.family)
                && root_retained.declarations().iter().any(|prior| prior == &declaration)
            {
                root_identity
            } else {
                child_identity
            };
            AssertedUse { declaration, origin }
        })
        .collect();
    let mut versions: Vec<_> = root_retained
        .declarations()
        .iter()
        .chain(child_retained.declarations())
        .filter(|use_| super::super::unqualified(use_.version.family))
        .map(|use_| use_.version.clone())
        .collect();
    versions.sort_by(|a, b| (a.family.name(), &a.key, &a.edition).cmp(&(b.family.name(), &b.key, &b.edition)));
    versions.dedup();
    let root_scope = root_retained.event().0.clone();
    Fixture {
        verifier,
        generation: Generation {
            scope: root_scope.clone(),
            ordinal: 1,
            minimum: 1,
            label: "unstable".into(),
            versions,
            closures: Vec::new(),
        },
        root_bytes: publication::encode(&root.disclosures(), &mut base::numeric(), limits()).unwrap(),
        child_bytes: publication::encode(&child.disclosures(), &mut base::numeric(), limits()).unwrap(),
        root_scope,
        root_identity,
        child_identity,
        root_uses,
        child_uses,
    }
}

fn budget() -> ReadBudget {
    ReadBudget {
        rows: 1_000_000,
        bytes: 100_000_000,
    }
}

fn audit_budget() -> AuditBudget {
    AuditBudget {
        page_rows: 10_000,
        rows: 1_000_000,
        allocation_bytes: 100_000_000,
        retained_bytes: 100_000_000,
        items: 1_000_000,
    }
}

fn assertions(f: &Fixture) -> (ReplayAssertion<'_>, ReplayAssertion<'_>) {
    (
        ReplayAssertion {
            label: Some("unstable"),
            ordinal: 1,
            scope: f.root_scope.clone(),
            identity: f.root_identity,
            parent: None,
            depth: 1,
            uses: &f.root_uses,
        },
        ReplayAssertion {
            label: Some("unstable"),
            ordinal: 1,
            scope: f.root_scope.clone(),
            identity: f.child_identity,
            parent: Some(f.root_identity),
            depth: 2,
            uses: &f.child_uses,
        },
    )
}

fn prepare_fixture(f: &Fixture) -> PreparedReplay {
    let (root, child) = assertions(f);
    let entries = [
        ReplayEntry {
            bytes: &f.child_bytes,
            assertion: child,
        },
        ReplayEntry {
            bytes: &f.root_bytes,
            assertion: root.clone(),
        },
        ReplayEntry {
            bytes: &f.root_bytes,
            assertion: root,
        },
    ];
    let mut numeric = base::numeric();
    let mut usage = EncodingUsage::default();
    let mut reserve = |_| Ok(());
    prepare(
        ReplayInput {
            generations: std::slice::from_ref(&f.generation),
            entries: &entries,
        },
        &f.verifier,
        &mut ReplayPreparation {
            numeric: &mut numeric,
            encoding_usage: &mut usage,
            reservation: &mut reserve,
            limits: limits(),
            position_ceiling: usize::MAX,
        },
    )
    .unwrap()
}

struct ForkFixture {
    verifier: tree_fixture::Check,
    generations: Vec<Generation>,
    bytes: Vec<Vec<u8>>,
    scopes: Vec<EpochScope>,
    identities: Vec<Identity>,
    uses: Vec<Vec<AssertedUse>>,
}

fn fork_generation(retained: &[Retained], members: &[usize]) -> Generation {
    let mut versions: Vec<_> = members
        .iter()
        .flat_map(|&index| retained[index].declarations())
        .filter(|use_| super::super::unqualified(use_.version.family))
        .map(|use_| use_.version.clone())
        .collect();
    versions.sort_by(|a, b| (a.family.name(), &a.key, &a.edition).cmp(&(b.family.name(), &b.key, &b.edition)));
    versions.dedup();
    Generation {
        scope: retained[members[0]].event().0.clone(),
        ordinal: 1,
        minimum: 1,
        label: "unstable".into(),
        versions,
        closures: Vec::new(),
    }
}

fn fork_fixture() -> ForkFixture {
    let (packages, verifier) = tree_fixture::tree_fork_fixture();
    let mut positions = Vec::new();
    for (index, package) in packages.iter().enumerate() {
        let parent = matches!(index, 1 | 2).then(|| &positions[0]);
        let position =
            Position::from_package(package, parent, RECIPE, usize::MAX, &mut EncodingUsage::default(), |_| Ok(())).unwrap();
        positions.push(position);
    }
    let retained: Vec<_> = positions
        .iter()
        .map(|position| Retained::from_position(position, &mut base::numeric(), limits()).unwrap())
        .collect();
    let scopes: Vec<_> = retained.iter().map(|value| value.event().0.clone()).collect();
    let identities: Vec<_> = retained.iter().map(|value| *value.event().1).collect();
    let uses = retained
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .declarations()
                .iter()
                .cloned()
                .map(|declaration| {
                    let origin = if matches!(index, 1 | 2)
                        && super::super::unqualified(declaration.version.family)
                        && retained[0].declarations().contains(&declaration)
                    {
                        identities[0]
                    } else {
                        identities[index]
                    };
                    AssertedUse { declaration, origin }
                })
                .collect()
        })
        .collect();
    let bytes = packages
        .iter()
        .map(|package| publication::encode(&package.disclosures(), &mut base::numeric(), limits()).unwrap())
        .collect();
    ForkFixture {
        verifier,
        generations: vec![fork_generation(&retained, &[0, 1, 2]), fork_generation(&retained, &[3])],
        bytes,
        scopes,
        identities,
        uses,
    }
}

fn fork_assertions(f: &ForkFixture) -> Vec<ReplayAssertion<'_>> {
    (0..4)
        .map(|index| ReplayAssertion {
            label: Some("unstable"),
            ordinal: 1,
            scope: f.scopes[index].clone(),
            identity: f.identities[index],
            parent: matches!(index, 1 | 2).then_some(f.identities[0]),
            depth: if matches!(index, 1 | 2) { 2 } else { 1 },
            uses: &f.uses[index],
        })
        .collect()
}

fn prepare_entries(
    f: &Fixture,
    generations: &[Generation],
    entries: &[ReplayEntry<'_>],
) -> Result<PreparedReplay, Box<ReplayFailure>> {
    let mut numeric = base::numeric();
    let mut usage = EncodingUsage::default();
    let mut reserve = |_| Ok(());
    prepare(
        ReplayInput { generations, entries },
        &f.verifier,
        &mut ReplayPreparation {
            numeric: &mut numeric,
            encoding_usage: &mut usage,
            reservation: &mut reserve,
            limits: limits(),
            position_ceiling: usize::MAX,
        },
    )
    .map_err(Box::new)
}

fn refusal(f: &Fixture, generations: &[Generation], entries: &[ReplayEntry<'_>]) -> ReplayFailure {
    match prepare_entries(f, generations, entries) {
        Ok(_) => panic!("invalid input unexpectedly prepared"),
        Err(failure) => *failure,
    }
}

fn root_entry<'a>(f: &'a Fixture, assertion: ReplayAssertion<'a>) -> ReplayEntry<'a> {
    ReplayEntry {
        bytes: &f.root_bytes,
        assertion,
    }
}

fn changed_document(
    document: &pn_interchange::Document,
    key: u64,
    path: &[usize],
    replacement: &pn_interchange::Value,
) -> Vec<u8> {
    use pn_interchange::{Array, ContentKey, Document, Value};
    fn replace(value: &Value, path: &[usize], replacement: &Value) -> Value {
        if let Some((first, rest)) = path.split_first() {
            let Value::Array(values) = value else {
                panic!("fixture path is not an array")
            };
            let mut items = values.as_slice().to_vec();
            items[*first] = replace(&items[*first], rest, replacement);
            Value::Array(Array::new(items))
        } else {
            replacement.clone()
        }
    }
    let mut content = document.content().clone();
    content.insert(
        ContentKey::new(key).unwrap(),
        replace(document.content().get(key).unwrap(), path, replacement),
    );
    Document::new(document.envelope().clone(), content).to_canonical_bytes()
}

fn schedule(prepared: &PreparedReplay) -> ReplaySchedule {
    let (generations, results) = prepared.counts();
    ReplaySchedule {
        installation: vec![budget(); generations],
        commit: vec![budget(); results],
        target_read: vec![budget(); results],
        reference_read: Vec::new(),
        opening_audit: None,
        final_audit: audit_budget(),
    }
}

fn assert_framed_order(fixture: &ForkFixture, prepared: &PreparedReplay) {
    assert_eq!(prepared.counts(), (2, 4));
    assert_eq!(
        prepared.declaration_scopes().collect::<Vec<_>>(),
        vec![&fixture.scopes[3], &fixture.scopes[0]]
    );
    let mut children = [fixture.identities[1], fixture.identities[2]];
    children.sort_unstable();
    assert_eq!(
        prepared.commit_order().map(|(_, identity, _)| identity).collect::<Vec<_>>(),
        vec![fixture.identities[3], fixture.identities[0], children[0], children[1]],
        "ready roots and siblings use framed scope then identity bytes"
    );
    let mut in_first_scope = [fixture.identities[0], fixture.identities[1], fixture.identities[2]];
    in_first_scope.sort_unstable();
    assert_eq!(
        prepared.reader_order().map(|(_, identity, _)| identity).collect::<Vec<_>>(),
        vec![fixture.identities[3], in_first_scope[0], in_first_scope[1], in_first_scope[2]]
    );
}

fn framed_test_key(scope: &EpochScope) -> String {
    use std::fmt::Write as _;
    let mut key = String::from("4:");
    for field in super::super::fields(scope) {
        write!(&mut key, "{}:{field}", field.len()).unwrap();
    }
    key
}

fn assert_framed_digit_boundary(scope: &EpochScope, short: usize, long: usize) {
    let mut left = scope.clone();
    let mut right = scope.clone();
    left.history = "x".repeat(short);
    right.history = "x".repeat(long);
    assert_eq!(
        super::super::framed_scope_cmp(&left, &right),
        framed_test_key(&left).cmp(&framed_test_key(&right))
    );
}

/// Claim: Independent restoration of the complete explicitly labelled fixture input produces the expected audited memory tree, exact bytes and tip-relative history through the ordinary writers.
/// ´claim:history:rebuild-restores-labelled-input´
/// ´test:unit:rebuild-restores-labelled-input´
#[test]
fn rebuild_restores_labelled_input() {
    let fixture = fork_fixture();
    assert_eq!(fixture.scopes[0].history, "aa");
    assert_eq!(fixture.scopes[3].history, "b");
    assert!(fixture.scopes[0] < fixture.scopes[3], "derived field order puts aa first");
    assert_eq!(
        super::super::framed_scope_cmp(&fixture.scopes[0], &fixture.scopes[3]),
        std::cmp::Ordering::Greater,
        "framed key order puts b first"
    );
    assert_eq!(fixture.scopes[0], fixture.scopes[1]);
    assert_eq!(fixture.scopes[0], fixture.scopes[2]);
    assert_framed_digit_boundary(&fixture.scopes[0], 9, 10);
    assert_framed_digit_boundary(&fixture.scopes[0], 1, 10);
    let assertions = fork_assertions(&fixture);
    let entries = [2, 3, 1, 0, 0].map(|index| ReplayEntry {
        bytes: &fixture.bytes[index],
        assertion: assertions[index].clone(),
    });
    let mut numeric = base::numeric();
    let mut encoding_usage = EncodingUsage::default();
    let mut reserve = |_| Ok(());
    let prepared = prepare(
        ReplayInput {
            generations: &fixture.generations,
            entries: &entries,
        },
        &fixture.verifier,
        &mut ReplayPreparation {
            numeric: &mut numeric,
            encoding_usage: &mut encoding_usage,
            reservation: &mut reserve,
            limits: limits(),
            position_ceiling: usize::MAX,
        },
    )
    .unwrap();
    assert_framed_order(&fixture, &prepared);
    let schedule = schedule(&prepared);
    let mut usage = ReplayUsage::default();
    let completed = replay_memory(
        &prepared,
        &mut ReplayExecution {
            schedule: &schedule,
            usage: &mut usage,
        },
    )
    .unwrap();
    assert_eq!(completed.inventory().counts().0, 2);
    assert_eq!(completed.inventory().counts().3, 4);
    let mut reader = completed.reader(budget());
    for index in 0..4 {
        let read = reader
            .exact(&fixture.scopes[index], fixture.identities[index])
            .unwrap()
            .unwrap();
        assert_eq!(read.bytes, fixture.bytes[index]);
        assert_eq!(read.parent, assertions[index].parent);
        assert_eq!(read.depth, assertions[index].depth);
        assert_eq!(read.selections.len(), fixture.uses[index].len());
        for (actual, expected) in read.selections.iter().zip(&fixture.uses[index]) {
            assert_eq!(actual.use_, &expected.declaration);
            assert_eq!(actual.origin, expected.origin);
        }
    }
    for index in [1, 2] {
        assert_eq!(
            reader
                .as_of(&fixture.scopes[index], fixture.identities[index], 1)
                .unwrap()
                .unwrap()
                .identity,
            fixture.identities[0]
        );
        assert_eq!(
            reader
                .as_of(&fixture.scopes[index], fixture.identities[index], 2)
                .unwrap()
                .unwrap()
                .identity,
            fixture.identities[index]
        );
    }
    let sibling = reader.exact(&fixture.scopes[2], fixture.identities[2]).unwrap().unwrap();
    assert!(
        sibling.debits.iter().any(|debit| debit.origin == fixture.identities[2]),
        "the sibling's local vintage keeps its own origin"
    );
    let first_child = reader.exact(&fixture.scopes[1], fixture.identities[1]).unwrap().unwrap();
    assert!(first_child.debits.iter().all(|debit| debit.origin != fixture.identities[2]));
}

/// Claim: Each listed preparation refusal preserves its distinct phase and cause. The list excludes Retention pending the replay-interface design owner's scoped selection revision; prepare has no target parameter, so unchanged target follows from API shape rather than an executed mutation assertion.
/// ´claim:history:rebuild-input-refusals´
/// ´test:unit:rebuild-input-refusals´
#[test]
fn rebuild_input_refusals() {
    let f = fixture();
    let (root, _) = assertions(&f);
    let declared = std::slice::from_ref(&f.generation);
    let valid = [root_entry(&f, root)];
    assert!(prepare_entries(&f, declared, &valid).is_ok(), "passing neighbour");
    check_inspection_refusals(&f);
    check_declaration_refusals(&f);
    check_parent_and_comparison_refusals(&f);
    check_decoding_refusals(&f);
}

fn check_inspection_refusals(f: &Fixture) {
    use pn_interchange::{Content, ContentKey, Document, Envelope, NamespaceLabel, Version as EnvelopeVersion};
    let (root, _) = assertions(f);
    let declared = std::slice::from_ref(&f.generation);
    let invalid_bytes = [0xff];
    let failure = refusal(
        f,
        declared,
        &[ReplayEntry {
            bytes: &invalid_bytes,
            assertion: root.clone(),
        }],
    );
    assert_eq!(failure.phase, ReplayPhase::Inspection);
    assert!(matches!(failure.cause, ReplayCause::Decode(publication::Error::Encoding)));
    let document = Document::from_canonical_bytes(&f.root_bytes).unwrap();
    let edition = Document::new(
        Envelope::new(
            NamespaceLabel::parse("org.peer-network.other").unwrap(),
            EnvelopeVersion::new(1, 0, 0),
        ),
        document.content().clone(),
    )
    .to_canonical_bytes();
    let failure = refusal(
        f,
        declared,
        &[ReplayEntry {
            bytes: &edition,
            assertion: root.clone(),
        }],
    );
    assert_eq!(failure.phase, ReplayPhase::Inspection);
    assert!(matches!(failure.cause, ReplayCause::Decode(publication::Error::Edition)));
    let patch = Document::new(
        Envelope::new(document.envelope().label().clone(), EnvelopeVersion::new(1, 0, 1)),
        document.content().clone(),
    )
    .to_canonical_bytes();
    let failure = refusal(
        f,
        declared,
        &[ReplayEntry {
            bytes: &patch,
            assertion: root.clone(),
        }],
    );
    assert_eq!(failure.phase, ReplayPhase::Inspection);
    assert!(matches!(failure.cause, ReplayCause::Decode(publication::Error::Patch)));
    let mut missing = Content::new();
    for field in 3..=8 {
        missing.insert(
            ContentKey::new(field).unwrap(),
            document.content().get(field).unwrap().clone(),
        );
    }
    let shape = Document::new(document.envelope().clone(), missing).to_canonical_bytes();
    let failure = refusal(
        f,
        declared,
        &[ReplayEntry {
            bytes: &shape,
            assertion: root.clone(),
        }],
    );
    assert_eq!(failure.phase, ReplayPhase::Inspection);
    assert!(matches!(failure.cause, ReplayCause::Decode(publication::Error::Shape)));
}

fn check_declaration_refusals(f: &Fixture) {
    let (root, _) = assertions(f);
    let declared = std::slice::from_ref(&f.generation);
    let valid = [root_entry(f, root.clone())];
    let mut absent = root.clone();
    absent.label = None;
    let failure = refusal(f, declared, &[root_entry(f, absent)]);
    assert_eq!(failure.phase, ReplayPhase::Declaration);
    assert!(matches!(failure.cause, ReplayCause::Tree(TreeError::MissingGenerationLabel)));
    let mut unknown = root.clone();
    unknown.label = Some("other");
    let failure = refusal(f, declared, &[root_entry(f, unknown)]);
    assert_eq!(failure.phase, ReplayPhase::Declaration);
    assert!(matches!(failure.cause, ReplayCause::Tree(TreeError::UnknownGenerationLabel)));
    let long_label = "a".repeat(1025);
    let mut over_bound = root.clone();
    over_bound.label = Some(&long_label);
    let failure = refusal(f, declared, &[root_entry(f, over_bound)]);
    assert_eq!(failure.phase, ReplayPhase::Declaration);
    assert!(matches!(
        failure.cause,
        ReplayCause::Tree(TreeError::Storage(StorageError::Representation))
    ));
    let mut bad_scope = root.clone();
    bad_scope.scope.history.push('\0');
    let failure = refusal(f, declared, &[root_entry(f, bad_scope)]);
    assert_eq!(failure.phase, ReplayPhase::Declaration);
    assert!(matches!(
        failure.cause,
        ReplayCause::Tree(TreeError::Storage(StorageError::Representation))
    ));
    let mut invalid_generation = f.generation.clone();
    invalid_generation.ordinal = 2;
    let failure = refusal(f, &[invalid_generation], &valid);
    assert_eq!(failure.phase, ReplayPhase::Declaration);
    assert!(matches!(
        failure.cause,
        ReplayCause::Tree(TreeError::InvalidAdmissionGeneration)
    ));
    let mut different = f.generation.clone();
    different.versions.pop();
    let failure = refusal(f, &[f.generation.clone(), different], &valid);
    assert_eq!(failure.phase, ReplayPhase::Declaration);
    assert!(matches!(
        failure.cause,
        ReplayCause::Tree(TreeError::AdmissionGenerationConflict)
    ));
    let failure = refusal(f, &[], &[]);
    assert_eq!(failure.phase, ReplayPhase::Declaration);
    assert!(matches!(
        failure.cause,
        ReplayCause::Tree(TreeError::InvalidAdmissionGeneration)
    ));
    let mut missing_scope = root.clone();
    missing_scope.scope.history.push_str("-other");
    let failure = refusal(f, declared, &[root_entry(f, missing_scope)]);
    assert_eq!(failure.phase, ReplayPhase::Declaration);
    assert!(matches!(
        failure.cause,
        ReplayCause::Tree(TreeError::InvalidAdmissionGeneration)
    ));
    let mut wrong_ordinal = root.clone();
    wrong_ordinal.ordinal = 2;
    let failure = refusal(f, declared, &[root_entry(f, wrong_ordinal)]);
    assert_eq!(failure.phase, ReplayPhase::Association);
    assert!(matches!(failure.cause, ReplayCause::Association(Association::Ordinal)));
}

fn check_parent_and_comparison_refusals(f: &Fixture) {
    let (root, child) = assertions(f);
    let declared = std::slice::from_ref(&f.generation);
    let mut conflicting = root.clone();
    conflicting.depth = 2;
    let failure = refusal(f, declared, &[root_entry(f, root.clone()), root_entry(f, conflicting)]);
    assert_eq!(failure.phase, ReplayPhase::ParentIndex);
    assert!(matches!(failure.cause, ReplayCause::ConflictingDuplicate));
    let failure = refusal(
        f,
        declared,
        &[ReplayEntry {
            bytes: &f.child_bytes,
            assertion: child.clone(),
        }],
    );
    assert_eq!(failure.phase, ReplayPhase::ParentIndex);
    assert!(matches!(failure.cause, ReplayCause::MissingParent));
    let mut cyclic_root = root.clone();
    cyclic_root.parent = Some(f.child_identity);
    let failure = refusal(
        f,
        declared,
        &[
            root_entry(f, cyclic_root),
            ReplayEntry {
                bytes: &f.child_bytes,
                assertion: child.clone(),
            },
        ],
    );
    assert_eq!(failure.phase, ReplayPhase::ParentIndex);
    assert!(matches!(failure.cause, ReplayCause::ParentCycle));

    let mut wrong_identity = root.clone();
    wrong_identity.identity[0] ^= 1;
    let failure = refusal(f, declared, &[root_entry(f, wrong_identity)]);
    assert_eq!(failure.phase, ReplayPhase::PrewriteComparison);
    assert!(matches!(failure.cause, ReplayCause::Mismatch(Mismatch::Identity)));
    let mut wrong_depth = root.clone();
    wrong_depth.depth = 2;
    let failure = refusal(f, declared, &[root_entry(f, wrong_depth)]);
    assert_eq!(failure.phase, ReplayPhase::PrewriteComparison);
    assert!(matches!(failure.cause, ReplayCause::Mismatch(Mismatch::Depth)));
    let mut wrong_scope = root.clone();
    wrong_scope.scope.sequence.push_str("-other");
    let other_generation = Generation {
        scope: wrong_scope.scope.clone(),
        versions: Vec::new(),
        closures: Vec::new(),
        ..f.generation.clone()
    };
    let failure = refusal(f, &[f.generation.clone(), other_generation], &[root_entry(f, wrong_scope)]);
    assert_eq!(failure.phase, ReplayPhase::PrewriteComparison);
    assert!(matches!(failure.cause, ReplayCause::Mismatch(Mismatch::Scope)));
    let mut wrong_references = f.root_uses.clone();
    wrong_references.pop();
    let mut assertion = root.clone();
    assertion.uses = &wrong_references;
    let failure = refusal(f, declared, &[root_entry(f, assertion)]);
    assert_eq!(failure.phase, ReplayPhase::PrewriteComparison);
    assert!(matches!(failure.cause, ReplayCause::Mismatch(Mismatch::References)));
    let mut wrong_coordinates = f.root_uses.clone();
    wrong_coordinates[0].declaration.selected_at += 1;
    let mut assertion = root.clone();
    assertion.uses = &wrong_coordinates;
    let failure = refusal(f, declared, &[root_entry(f, assertion)]);
    assert_eq!(failure.phase, ReplayPhase::PrewriteComparison);
    assert!(matches!(failure.cause, ReplayCause::Mismatch(Mismatch::Coordinates)));
}

fn check_decoding_refusals(f: &Fixture) {
    use pn_interchange::{Document, Value};
    let (root, child) = assertions(f);
    let declared = std::slice::from_ref(&f.generation);
    let valid = [root_entry(f, root.clone())];
    let child_document = Document::from_canonical_bytes(&f.child_bytes).unwrap();
    let semantic = changed_document(&child_document, 8, &[2, 1], &Value::Text("01".to_owned().into()));
    let failure = refusal(
        f,
        declared,
        &[
            root_entry(f, root.clone()),
            ReplayEntry {
                bytes: &semantic,
                assertion: child.clone(),
            },
        ],
    );
    assert_eq!(failure.phase, ReplayPhase::Decode);
    assert!(matches!(
        failure.cause,
        ReplayCause::Decode(publication::Error::CanonicalNumber)
    ));

    let (child_package, _) = fixture::complete();
    let mut supplied_stop = child_package.disclosures();
    supplied_stop.frames.truncate(1);
    supplied_stop.frames[0].standing.fence.attempts[0].stop = AttemptStop::WorkLimit;
    let stop_bytes = publication::encode(&supplied_stop, &mut base::numeric(), limits()).unwrap();
    let failure = refusal(
        f,
        declared,
        &[ReplayEntry {
            bytes: &stop_bytes,
            assertion: root.clone(),
        }],
    );
    assert_eq!(failure.phase, ReplayPhase::SuppliedEvidence);
    assert!(matches!(failure.cause, ReplayCause::SuppliedWorkStop));

    let mut disallowed = child_package.disclosures();
    disallowed.frames.truncate(1);
    disallowed.frames[0].realization.edition.push_str("-wrong");
    let disallowed_bytes = publication::encode(&disallowed, &mut base::numeric(), limits()).unwrap();
    let failure = refusal(
        f,
        declared,
        &[ReplayEntry {
            bytes: &disallowed_bytes,
            assertion: root.clone(),
        }],
    );
    assert_eq!(failure.phase, ReplayPhase::Restore);
    assert!(matches!(failure.cause, ReplayCause::Restore(_)));

    let mut numeric = base::numeric();
    let mut encoding_usage = EncodingUsage::default();
    let mut denied_reservation = |_| Err(());
    let Err(failure) = prepare(
        ReplayInput {
            generations: declared,
            entries: &valid,
        },
        &f.verifier,
        &mut ReplayPreparation {
            numeric: &mut numeric,
            encoding_usage: &mut encoding_usage,
            reservation: &mut denied_reservation,
            limits: limits(),
            position_ceiling: usize::MAX,
        },
    ) else {
        panic!("denied position reservation prepared")
    };
    assert_eq!(failure.phase, ReplayPhase::Position);
    assert!(matches!(failure.cause, ReplayCause::Position(_)));
}

/// Claim: The selected reachable memory execution refusals retain their phase, cause and target disposition.
/// ´claim:history:rebuild-memory-execution-refusals´
/// ´test:unit:rebuild-memory-execution-refusals´
#[test]
fn rebuild_memory_execution_refusals() {
    let f = fixture();
    let prepared = prepare_fixture(&f);
    let mut missing_slot = schedule(&prepared);
    missing_slot.commit.pop();
    let mut usage = ReplayUsage::default();
    let Err(failure) = replay_memory(
        &prepared,
        &mut ReplayExecution {
            schedule: &missing_slot,
            usage: &mut usage,
        },
    ) else {
        panic!("missing slot accepted")
    };
    assert_eq!(failure.phase, ReplayPhase::ExecutionStart);
    assert!(matches!(failure.cause, ReplayCause::ResourcesUnspecified));
    assert_eq!(failure.disposition, TargetDisposition::NotTouched);
    assert_eq!(usage.installation.len(), 0);

    let (root, mut child) = assertions(&f);
    let wrong_uses = f
        .child_uses
        .iter()
        .cloned()
        .map(|mut use_| {
            use_.origin[0] ^= 1;
            use_
        })
        .collect::<Vec<_>>();
    child.uses = &wrong_uses;
    let entries = [
        root_entry(&f, root),
        ReplayEntry {
            bytes: &f.child_bytes,
            assertion: child,
        },
    ];
    let wrong_origin = prepare_entries(&f, std::slice::from_ref(&f.generation), &entries).unwrap();
    let wrong_schedule = schedule(&wrong_origin);
    let mut usage = ReplayUsage::default();
    let Err(failure) = replay_memory(
        &wrong_origin,
        &mut ReplayExecution {
            schedule: &wrong_schedule,
            usage: &mut usage,
        },
    ) else {
        panic!("wrong origin accepted")
    };
    assert_eq!(failure.phase, ReplayPhase::PostcommitComparison);
    assert!(matches!(failure.cause, ReplayCause::Mismatch(Mismatch::Origins)));
    assert_eq!(failure.disposition, TargetDisposition::MustDiscard);
    assert!(usage.commit[1].is_some());

    let mut usage = ReplayUsage::default();
    let passing = schedule(&prepared);
    assert!(
        replay_memory(
            &prepared,
            &mut ReplayExecution {
                schedule: &passing,
                usage: &mut usage
            }
        )
        .is_ok()
    );
}
