use super::*;

thread_local! {
    static REQUESTS: std::cell::RefCell<Option<Vec<usize>>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn allocation_request(bytes: usize) {
    REQUESTS.with_borrow_mut(|requests| {
        if let Some(requests) = requests {
            requests.push(bytes);
        }
    });
}

pub(super) fn budget() -> ReadBudget {
    ReadBudget {
        bytes: 1_000_000,
        rows: 10_000,
    }
}
fn declared() -> Generation {
    Generation {
        scope: EpochScope {
            history: "h".into(),
            policy_identity: "p".into(),
            policy_edition: "e".into(),
            sequence: "s".into(),
        },
        ordinal: 1,
        minimum: 1,
        label: "unstable".into(),
        versions: vec![
            Version {
                family: Family::Rule,
                key: "5:1:h1:p1:e1:s1:k".into(),
                edition: "a".into(),
                announced_at: 0,
                opens_at: 1,
                payload: Some(super::super::Payload::rule(&pn_interchange::Value::Unsigned(7)).unwrap()),
            },
            Version {
                family: Family::Rule,
                key: "5:1:h1:p1:e1:s1:k".into(),
                edition: "z".into(),
                announced_at: 1,
                opens_at: 3,
                payload: None,
            },
        ],
        closures: vec![Closure {
            family: Family::Rule,
            key: "5:1:h1:p1:e1:s1:k".into(),
            edition: "a".into(),
            closes_at: 3,
        }],
    }
}

/// Claim: Nine explicit generation inputs and a result label containing U+0000 refuse Representation before either budget unit is charged, leaving the complete memory tree unchanged; private act-column validation refuses U+0000 in author and family, while text nested inside a bytea payload remains outside the text-column rule.
/// ´claim:history:tree-stored-text-domain´
/// ´test:unit:tree-stored-text-domain´
#[test]
fn tree_stored_text_domain() {
    for field in [8, 2, 6, 0, 7, 4, 1, 5, 3] {
        let mut input = declared();
        match field {
            0 => input.scope.history.push('\0'),
            1 => input.scope.policy_identity.push('\0'),
            2 => input.scope.policy_edition.push('\0'),
            3 => input.scope.sequence.push('\0'),
            4 => input.label.push('\0'),
            5 => input.versions[0].key.push('\0'),
            6 => input.versions[0].edition.push('\0'),
            7 => input.closures[0].key.push('\0'),
            8 => input.closures[0].edition.push('\0'),
            _ => unreachable!("nine declared fields"),
        }
        let mut store = MemoryTree::default();
        let before = snapshot(&store);
        let mut usage = Usage::default();
        assert_eq!(
            store.install_generation(&input, ReadBudget { rows: 0, bytes: 0 }, &mut usage),
            Err(Error::Storage(StorageError::Representation)),
            "stored text field {field}"
        );
        assert_eq!(usage, Usage::default());
        assert_eq!(snapshot(&store), before);
    }
    let mut input = declared();
    input.versions[0].payload =
        Some(super::super::Payload::rule(&pn_interchange::Value::Text(String::from("public\0payload").into())).unwrap());
    let mut store = MemoryTree::default();
    assert_eq!(
        store.install_generation(&input, budget(), &mut Usage::default()),
        Ok(true),
        "bytea payload is outside the text column domain"
    );
    let root = &forks().main[0];
    let mut store = MemoryTree::default();
    let before = snapshot(&store);
    let mut usage = Usage::default();
    assert_eq!(
        store.commit(root, Some("unstable\0"), ReadBudget { rows: 0, bytes: 0 }, &mut usage),
        Err(Error::Storage(StorageError::Representation))
    );
    assert_eq!(usage, Usage::default());
    assert_eq!(snapshot(&store), before);
    for act in [
        pn_records::ActId {
            author: "public\0author".into(),
            sequence: 0,
            family: "Opinion".into(),
        },
        pn_records::ActId {
            author: "public-author".into(),
            sequence: 0,
            family: "Opinion\0".into(),
        },
    ] {
        assert_eq!(
            super::super::stored_act(&act),
            Err(StorageError::Representation),
            "private act-column boundary"
        );
    }
}
pub(super) fn snapshot(store: &MemoryTree<'_>) -> String {
    format!("{store:?}")
}

fn generation_limits(input: &Generation) {
    let mut store = MemoryTree::default();
    let mut usage = Usage::default();
    REQUESTS.with_borrow_mut(|requests| *requests = Some(Vec::new()));
    assert_eq!(store.install_generation(input, budget(), &mut usage), Ok(true));
    let requests = REQUESTS.with_borrow_mut(|requests| requests.take().unwrap());
    assert_eq!(requests.iter().sum::<usize>(), usage.allocation_bytes);
    let mut prefix = 0;
    for request in requests {
        prefix += request;
        let mut store = MemoryTree::default();
        let before = snapshot(&store);
        assert_eq!(
            store.install_generation(
                input,
                ReadBudget {
                    bytes: prefix - 1,
                    ..budget()
                },
                &mut Usage::default()
            ),
            Err(Error::Storage(StorageError::ReadLimit))
        );
        assert_eq!(snapshot(&store), before);
    }
    let mut store = MemoryTree::default();
    assert_eq!(
        store.install_generation(
            input,
            ReadBudget {
                rows: usage.rows,
                bytes: usage.allocation_bytes
            },
            &mut Usage::default()
        ),
        Ok(true)
    );
}

/// Claim: Explicit single-law declarations install their complete versions and closures atomically in effect order independently of declared edition order; equal retries leave the whole state unchanged and every staged interruption leaves an empty state that accepts the same declaration on retry.
/// ´claim:history:tree-generation-atomic´
/// ´test:unit:tree-generation-atomic´
#[test]
fn tree_generation_atomic() {
    let declaration = declared();
    let mut store = MemoryTree::default();
    let mut meter = Meter {
        limit: budget(),
        used: Usage::default(),
    };
    let mut events = Vec::new();
    assert_eq!(
        store.install(&declaration, &mut meter, &mut |w| {
            events.push(w);
            Ok(())
        }),
        Ok(true)
    );
    assert_eq!(
        events,
        vec![
            Write::Generation,
            Write::Version(0),
            Write::VersionIntroduction(0),
            Write::Version(1),
            Write::VersionIntroduction(1),
            Write::Closure(0),
            Write::ClosureIntroduction(0),
            Write::Publish
        ]
    );
    assert_eq!(store.generations[0].declaration, &declaration);
    assert_eq!(store.generations[0].versions, vec![0, 1]);
    assert_eq!(store.generations[0].closures, vec![0]);
    let before = snapshot(&store);
    assert_eq!(
        store.install_generation(&declaration, budget(), &mut Usage::default()),
        Ok(false)
    );
    assert_eq!(snapshot(&store), before, "equal declaration retry changes no retained field");
    for stop in 0..events.len() {
        let mut store = MemoryTree::default();
        let before = snapshot(&store);
        let mut seen = 0;
        let mut meter = Meter {
            limit: budget(),
            used: Usage::default(),
        };
        let result = store.install(&declaration, &mut meter, &mut |_| {
            let refusal = seen == stop;
            seen += 1;
            if refusal { Err(StorageError::Injected.into()) } else { Ok(()) }
        });
        assert_eq!(result, Err(Error::Storage(StorageError::Injected)));
        assert_eq!(snapshot(&store), before, "each interrupted declaration has no durable prefix");
        assert_eq!(
            store.install_generation(&declaration, budget(), &mut Usage::default()),
            Ok(true)
        );
        assert_eq!(store.generations[0].declaration, &declaration);
    }
    let mut reordered = declaration.clone();
    reordered.versions[0].edition = "z".into();
    reordered.versions[1].edition = "a".into();
    reordered.versions.swap(0, 1);
    reordered.closures[0].edition = "z".into();
    let mut other = MemoryTree::default();
    let mut writes = Vec::new();
    assert_eq!(
        other.install(&reordered, &mut meter, &mut |w| {
            writes.push(w);
            Ok(())
        }),
        Ok(true)
    );
    assert_eq!(
        writes[1..5],
        [
            Write::Version(1),
            Write::VersionIntroduction(1),
            Write::Version(0),
            Write::VersionIntroduction(0)
        ],
        "writes follow opening order, not edition order"
    );
    assert_eq!(other.generations[0].versions, vec![0, 1]);
}

fn key_refusals() {
    for key in [
        "5:1:h1:p1:e1:s1:kx",
        "05:1:h1:p1:e1:s1:k",
        "5:01:h1:p1:e1:s1:k",
        "5:1:h1:p1:e1:s2:k",
    ] {
        let mut input = declared();
        input.versions[0].key = key.into();
        let mut store = MemoryTree::default();
        let before = snapshot(&store);
        let mut usage = Usage::default();
        assert_eq!(
            store.install_generation(&input, ReadBudget { rows: 0, bytes: 0 }, &mut usage),
            Err(Error::InvalidAdmissionGeneration)
        );
        assert_eq!(usage, Usage::default());
        assert_eq!(snapshot(&store), before);
    }
}

/// Claim: The single-law writer rejects malformed framed keys and prohibited ordinals, labels and minima before either allowance is charged, distinguishes conflicting valid deltas, and charges valid input at the first requested row or allocation with checked accumulation overflow.
/// ´claim:history:tree-generation-refusals´
/// ´test:unit:tree-generation-refusals´
#[test]
fn tree_generation_refusals() {
    key_refusals();
    let declaration = declared();
    generation_limits(&declaration);
    let mut wrong_ordinal = declaration.clone();
    wrong_ordinal.ordinal = 2;
    let mut wrong_label = declaration.clone();
    wrong_label.label = "later".into();
    let mut wrong_minimum = declaration.clone();
    wrong_minimum.minimum = 0;
    // Distinct invalid inputs are deliberately not delivered in field order.
    for input in [&wrong_label, &wrong_minimum, &wrong_ordinal] {
        for budget in [
            budget(),
            ReadBudget { rows: 0, ..budget() },
            ReadBudget { bytes: 0, ..budget() },
        ] {
            let mut store = MemoryTree::default();
            let before = snapshot(&store);
            let mut usage = Usage::default();
            assert_eq!(
                store.install_generation(input, budget, &mut usage),
                Err(Error::InvalidAdmissionGeneration),
                "self-contained invalid declaration precedes either budget"
            );
            assert_eq!(usage, Usage::default());
            assert_eq!(snapshot(&store), before);
        }
    }
    let mut conflict = declaration.clone();
    conflict.versions[0].payload = None;
    let mut store = MemoryTree::default();
    assert_eq!(
        store.install_generation(&declaration, budget(), &mut Usage::default()),
        Ok(true)
    );
    let before = snapshot(&store);
    assert_eq!(
        store.install_generation(&conflict, budget(), &mut Usage::default()),
        Err(Error::AdmissionGenerationConflict),
        "different valid delta cannot replace an installed generation"
    );
    assert_eq!(snapshot(&store), before);
    for limit in [ReadBudget { rows: 0, ..budget() }, ReadBudget { bytes: 0, ..budget() }] {
        let mut store = MemoryTree::default();
        let before = snapshot(&store);
        assert_eq!(
            store.install_generation(&declaration, limit, &mut Usage::default()),
            Err(Error::Storage(StorageError::ReadLimit)),
            "valid declaration refuses at its first charged step"
        );
        assert_eq!(snapshot(&store), before);
    }
    let mut meter = Meter {
        limit: ReadBudget {
            rows: usize::MAX,
            bytes: usize::MAX,
        },
        used: Usage {
            rows: usize::MAX,
            allocation_bytes: usize::MAX,
        },
    };
    let mut fetched = false;
    assert_eq!(
        meter.row(|| {
            fetched = true;
        }),
        Err(Error::Storage(StorageError::ReadLimit)),
        "row accumulation overflow is a limit refusal"
    );
    assert!(!fetched, "overflow refuses before the row operation");
    assert_eq!(
        meter.allocation(1),
        Err(Error::Storage(StorageError::ReadLimit)),
        "allocation accumulation overflow is a limit refusal"
    );
}

fn carriers() -> &'static (Retained, Retained, Generation) {
    use crate::admitted_carrier_tests::{base, fixture};
    use crate::admitted_result::position::{Position, RECIPE};
    static VALUES: std::sync::OnceLock<(Retained, Retained, Generation)> = std::sync::OnceLock::new();
    VALUES.get_or_init(|| {
        let (child, verifier) = fixture::complete();
        let mut raw = child.disclosures();
        raw.frames.truncate(1);
        let root = pn_epoch::publication::disclosures::restore(raw, &verifier).unwrap();
        let root_position = Position::from_package(
            &root,
            None,
            RECIPE,
            usize::MAX,
            &mut pn_interchange::EncodingUsage::default(),
            |_| Ok(()),
        )
        .unwrap();
        let child_position = Position::from_package(
            &child,
            Some(&root_position),
            RECIPE,
            usize::MAX,
            &mut pn_interchange::EncodingUsage::default(),
            |_| Ok(()),
        )
        .unwrap();
        let limits = || pn_epoch::publication::disclosures::Limits {
            work: 100_000_000,
            arithmetic_steps: 5_000_000,
            ..pn_epoch::publication::disclosures::Limits::default()
        };
        let root = Retained::from_position(&root_position, &mut base::numeric(), limits()).unwrap();
        let child = Retained::from_position(&child_position, &mut base::numeric(), limits()).unwrap();
        let mut versions: Vec<_> = root
            .declarations()
            .iter()
            .chain(child.declarations())
            .filter(|u| unqualified(u.version.family))
            .map(|u| u.version.clone())
            .collect();
        versions.sort_by(|a, b| declaration_key(a).cmp(&declaration_key(b)));
        versions.dedup();
        let generation = Generation {
            scope: root.event().0.clone(),
            ordinal: 1,
            minimum: 1,
            label: "unstable".into(),
            versions,
            closures: Vec::new(),
        };
        (root, child, generation)
    })
}

/// Claim: The tree writer accepts supplied admitted root and child carriers with complete recorded selections and original debit introductions; retries return the same judgement without reading a generation, and every staged write interruption preserves the complete prior state before successful retry.
/// ´claim:history:tree-writer-atomic´
/// ´test:unit:tree-writer-atomic´
#[test]
fn tree_writer_atomic() {
    let (root, child, generation) = carriers();
    let mut store = MemoryTree::default();
    assert_eq!(
        store.install_generation(generation, budget(), &mut Usage::default()),
        Ok(true)
    );
    let mut events = Vec::new();
    let mut meter = Meter {
        limit: budget(),
        used: Usage::default(),
    };
    assert!(
        store
            .commit_inner(root, Some("unstable"), &mut meter, &mut |w| {
                events.push(w);
                Ok(())
            })
            .unwrap()
            .inserted
    );
    assert!(events.contains(&Write::Scope) && events.contains(&Write::Segment));
    index_events(&events);
    assert!(events.iter().any(|w| matches!(w, Write::DebitChunk(_, _))));
    assert_eq!(
        store.results[&(root.event().0, *root.event().1)].references.len(),
        root.declarations().len()
    );
    let before = snapshot(&store);
    assert!(
        !store
            .commit(root, Some("unstable"), budget(), &mut Usage::default())
            .unwrap()
            .inserted
    );
    assert_eq!(
        snapshot(&store),
        before,
        "complete retry leaves every retained field unchanged"
    );
    let saved = std::mem::take(&mut store.generations);
    assert_eq!(
        store
            .commit(root, Some("unstable"), budget(), &mut Usage::default())
            .map(|j| j.inserted),
        Ok(false),
        "retry reads no generation and never rejudges recorded selections"
    );
    store.generations = saved;
    assert!(
        store
            .commit(child, Some("unstable"), budget(), &mut Usage::default())
            .unwrap()
            .inserted
    );
    assert!(
        store.results[&(child.event().0, *child.event().1)].introductions.is_empty(),
        "inherited debits are not copied into the child"
    );
    for selection in &store.results[&(child.event().0, *child.event().1)].references {
        if unqualified(selection.use_.version.family)
            && root
                .declarations()
                .iter()
                .any(|u| coordinate(u) == coordinate(selection.use_))
        {
            assert_eq!(
                selection.origin,
                *root.event().1,
                "a child inherits the parent's recorded use"
            );
        }
    }
    for stop in 0..events.len() {
        let mut store = MemoryTree::default();
        assert_eq!(
            store.install_generation(generation, budget(), &mut Usage::default()),
            Ok(true)
        );
        let before = snapshot(&store);
        let mut seen = 0;
        let mut meter = Meter {
            limit: budget(),
            used: Usage::default(),
        };
        let result = store
            .commit_inner(root, Some("unstable"), &mut meter, &mut |_| {
                let refuse = seen == stop;
                seen += 1;
                if refuse { Err(StorageError::Injected.into()) } else { Ok(()) }
            })
            .map(|j| j.inserted);
        assert_eq!(result, Err(Error::Storage(StorageError::Injected)));
        assert_eq!(snapshot(&store), before, "an interrupted root publishes no partial result");
        assert!(
            store
                .commit(root, Some("unstable"), budget(), &mut Usage::default())
                .unwrap()
                .inserted
        );
    }
}

/// Claim: Writer accounting begins at the supplied retained carrier: missing and foreign labels refuse before either charge, while valid input refuses at the first requested row or allocation beyond a zero allowance, preserving the complete store.
/// ´claim:history:tree-writer-input-budget´
/// ´test:unit:tree-writer-input-budget´
#[test]
fn tree_writer_input_budget() {
    let (root, _, generation) = carriers();
    for limit in [
        budget(),
        ReadBudget { rows: 0, ..budget() },
        ReadBudget { bytes: 0, ..budget() },
    ] {
        for (label, expected) in [
            (None, Error::MissingGenerationLabel),
            (Some("foreign"), Error::UnknownGenerationLabel),
        ] {
            let mut store = MemoryTree::default();
            assert_eq!(
                store.install_generation(generation, budget(), &mut Usage::default()),
                Ok(true)
            );
            let before = snapshot(&store);
            let mut used = Usage::default();
            assert_eq!(store.commit(root, label, limit, &mut used), Err(expected));
            assert_eq!(used, Usage::default(), "malformed input precedes either charged unit");
            assert_eq!(snapshot(&store), before);
        }
        if limit.rows == budget().rows && limit.bytes == budget().bytes {
            continue;
        }
        let mut store = MemoryTree::default();
        assert_eq!(
            store.install_generation(generation, budget(), &mut Usage::default()),
            Ok(true)
        );
        let before = snapshot(&store);
        let mut used = Usage::default();
        assert_eq!(
            store.commit(root, Some("unstable"), limit, &mut used),
            Err(Error::Storage(StorageError::ReadLimit)),
            "the supplied valid carrier reaches the first charged step"
        );
        assert_eq!(used.allocation_bytes, 0);
        assert_eq!(
            used.rows,
            if limit.rows == 0 { 0 } else { 3 },
            "zero allocation reaches exactly the result, context and generation probes before reconstruction"
        );
        assert_eq!(snapshot(&store), before);
    }
}

pub(super) struct Forks {
    pub(super) main: Vec<Retained>,
    pub(super) side: Vec<Retained>,
    pub(super) side_debit: Vec<Retained>,
    pub(super) other_root: Vec<Retained>,
    pub(super) other_context: Vec<Retained>,
    pub(super) other_binding: Vec<Retained>,
    pub(super) generation: Generation,
}
fn retain_chain(packages: &[pn_epoch::publication::AdmittedPackage]) -> Vec<Retained> {
    use crate::admitted_result::position::{Position, RECIPE};
    let mut previous = None;
    let mut output = Vec::new();
    for package in packages {
        let position = Position::from_package(
            package,
            previous.as_ref(),
            RECIPE,
            usize::MAX,
            &mut pn_interchange::EncodingUsage::default(),
            |_| Ok(()),
        )
        .unwrap();
        let retained = Retained::from_position(
            &position,
            &mut crate::admitted_carrier_tests::base::numeric(),
            pn_epoch::publication::disclosures::Limits {
                work: 100_000_000,
                arithmetic_steps: 5_000_000,
                ..pn_epoch::publication::disclosures::Limits::default()
            },
        )
        .unwrap();
        output.push(retained);
        previous = Some(position);
    }
    output
}
pub(super) fn forks() -> &'static Forks {
    static FORKS: std::sync::OnceLock<Forks> = std::sync::OnceLock::new();
    FORKS.get_or_init(|| {
        use crate::admitted_carrier_tests::tree_fixture::tree_sequence;
        let main = retain_chain(&tree_sequence(&[100, 200, 300, 400], Some(3)));
        let side = retain_chain(&tree_sequence(&[100, 200, 301], None));
        let side_debit = retain_chain(&tree_sequence(&[100, 200, 301], Some(3)));
        let other_binding = retain_chain(&tree_sequence(&[100, 200, 300, 400], None));
        let other_root = retain_chain(&tree_sequence(&[101], None));
        let other_context = retain_chain(&tree_sequence(&[102], None));
        let mut versions: Vec<_> = main
            .iter()
            .chain(&side)
            .chain(&side_debit)
            .chain(&other_root)
            .flat_map(Retained::declarations)
            .filter(|u| unqualified(u.version.family))
            .map(|u| u.version.clone())
            .collect();
        versions.sort_by(|a, b| declaration_key(a).cmp(&declaration_key(b)));
        versions.dedup();
        let generation = Generation {
            scope: main[0].event().0.clone(),
            ordinal: 1,
            minimum: 1,
            label: "unstable".into(),
            versions,
            closures: vec![],
        };
        Forks {
            main,
            side,
            side_debit,
            other_root,
            other_context,
            other_binding,
            generation,
        }
    })
}

/// Claim: Publicly admitted fixture packages form two roots and a fork with independent debit origins; a child inherits only its ancestors' complete vintages and original selections, a side retry is unchanged, and differing context or same-position content refuses without writing. The first child continues its parent segment without a descriptor and the later child opens one while preserving the first-child row; each admission has exactly its complete placement and direct-child entries.
/// ´claim:history:tree-writer-forks´
/// ´test:unit:tree-writer-forks´
#[test]
fn tree_writer_forks() {
    super::roster::fork_conformance::<MemoryTree<'static>>();
}

fn missing_law<'a>(store: &mut MemoryTree<'a>, child: &'a Retained) {
    let generations = std::mem::take(&mut store.generations);
    let before = snapshot(store);
    assert_eq!(
        store.commit(child, Some("unstable"), budget(), &mut Usage::default()),
        Err(Error::Storage(StorageError::CorruptHistory)),
        "a retained parent with no installed law is damaged state"
    );
    assert_eq!(snapshot(store), before);
    store.generations = generations;
}

/// Claim: Missing, mismatched and inactive exact references retain distinct writer refusals; a missing proposed parent refuses as input, whereas a damaged retained law or descriptor refuses as corrupt history at the private boundary. The shared roster reaches a public alternate-parent binding and private depth, inherited-use, qualified-presence and both vintage-conflict branches; private equal-byte retry projection damage refuses corrupt history, with every retained field unchanged.
/// ´claim:history:tree-writer-refusals´
/// ´test:unit:tree-writer-refusals´
#[test]
fn tree_writer_refusals() {
    super::roster::refusal_conformance::<MemoryTree<'static>>();
    let (root, child, generation) = carriers();
    let selected = root
        .declarations()
        .iter()
        .find(|u| u.version.family == Family::Rule && u.version.opens_at < u.selected_at)
        .unwrap();
    let index = generation.versions.iter().position(|v| v == &selected.version).unwrap();
    let mut missing = generation.clone();
    missing.versions.remove(index);
    let mut mismatch = generation.clone();
    mismatch.versions[index].payload = Some(super::super::Payload::rule(&pn_interchange::Value::Unsigned(91)).unwrap());
    let mut inactive = generation.clone();
    let mut successor = selected.version.clone();
    successor.edition.push_str("-successor");
    successor.opens_at = selected.selected_at;
    successor.announced_at = successor.opens_at;
    // The selected edition opens before its selection coordinate in this admitted fixture.
    assert!(selected.version.opens_at < selected.selected_at);
    inactive.closures.push(Closure {
        family: successor.family,
        key: successor.key.clone(),
        edition: selected.version.edition.clone(),
        closes_at: successor.opens_at,
    });
    inactive.versions.push(successor);
    inactive.versions.sort_by(|a, b| declaration_key(a).cmp(&declaration_key(b)));
    for (input, refusal) in [
        (&inactive, StorageError::SelectedVersionNotEffective),
        (&missing, StorageError::MissingSelectedVersion),
        (&mismatch, StorageError::SelectedContentMismatch),
    ] {
        let mut store = MemoryTree::default();
        assert_eq!(store.install_generation(input, budget(), &mut Usage::default()), Ok(true));
        let before = snapshot(&store);
        assert_eq!(
            store.commit(root, Some("unstable"), budget(), &mut Usage::default()),
            Err(Error::Storage(refusal)),
            "exact reference refusal is preserved"
        );
        assert_eq!(snapshot(&store), before);
    }
    let mut store = MemoryTree::default();
    assert_eq!(
        store.install_generation(generation, budget(), &mut Usage::default()),
        Ok(true)
    );
    let before = snapshot(&store);
    assert_eq!(
        store.commit(child, Some("unstable"), budget(), &mut Usage::default()),
        Err(Error::PredecessorMismatch)
    );
    assert_eq!(snapshot(&store), before);
    assert_eq!(
        store
            .commit(root, Some("unstable"), budget(), &mut Usage::default())
            .map(|j| j.inserted),
        Ok(true)
    );
    store.results.get_mut(&(root.event().0, *root.event().1)).unwrap().label = "foreign";
    let before = snapshot(&store);
    assert_eq!(
        store.commit(child, Some("unstable"), budget(), &mut Usage::default()),
        Err(Error::Storage(StorageError::CorruptHistory)),
        "private stored-parent law damage is not an input-label refusal"
    );
    assert_eq!(snapshot(&store), before);
    store.results.get_mut(&(root.event().0, *root.event().1)).unwrap().label = "unstable";
    missing_law(&mut store, child);
    assert_eq!(
        store
            .commit(child, Some("unstable"), budget(), &mut Usage::default())
            .map(|j| j.inserted),
        Ok(true)
    );
    store.segments.get_mut(&(root.event().0, *root.event().1)).unwrap().first = *child.event().1;
    let before = snapshot(&store);
    assert_eq!(
        store.commit(child, Some("unstable"), budget(), &mut Usage::default()),
        Err(Error::Storage(StorageError::CorruptHistory)),
        "private descriptor first must belong at the segment start"
    );
    assert_eq!(snapshot(&store), before);
}

fn allocation_limits<'a>(requests: &[usize], setup: &impl Fn() -> MemoryTree<'a>, input: &'a Retained) {
    let limits: Vec<_> = requests
        .iter()
        .scan(0, |sum, request| {
            *sum += request;
            Some(*sum - 1)
        })
        .collect();
    // Descending ceilings reach the writer unsorted, with one distinct prefix per request.
    for bytes in limits.into_iter().rev() {
        let mut store = setup();
        let before = snapshot(&store);
        let mut usage = Usage::default();
        assert_eq!(
            store.commit(input, Some("unstable"), ReadBudget { bytes, ..budget() }, &mut usage),
            Err(Error::Storage(StorageError::ReadLimit)),
            "each reconstruction request refuses before publication"
        );
        assert!(usage.allocation_bytes <= bytes);
        assert_eq!(snapshot(&store), before);
    }
}

/// Claim: For the supplied root, child and exact retry, every row ceiling below measured usage and each admitted allocation-request prefix one below its need refuse without a write, exact allowances succeed, and a zero allocation limit reaches no vector reservation; the prefix observation records reservation requests, not an allocator census.
/// ´claim:history:tree-writer-limits´
/// ´test:unit:tree-writer-limits´
#[test]
fn tree_writer_limits() {
    let (root, child, generation) = carriers();
    for prior in [2, 0, 1] {
        let setup = || {
            let mut store = MemoryTree::default();
            assert_eq!(
                store.install_generation(generation, budget(), &mut Usage::default()),
                Ok(true)
            );
            if prior != 0 {
                assert_eq!(
                    store
                        .commit(root, Some("unstable"), budget(), &mut Usage::default())
                        .map(|j| j.inserted),
                    Ok(true)
                );
            }
            store
        };
        let input = if prior == 1 { child } else { root };
        let mut store = setup();
        let mut usage = Usage::default();
        REQUESTS.with_borrow_mut(|requests| *requests = Some(Vec::new()));
        assert_eq!(
            store
                .commit(input, Some("unstable"), budget(), &mut usage)
                .map(|j| j.inserted),
            Ok(prior != 2)
        );
        let requests = REQUESTS.with_borrow_mut(|requests| requests.take().unwrap());
        assert_eq!(requests.iter().sum::<usize>(), usage.allocation_bytes);
        allocation_limits(&requests, &setup, input);
        for rows in 0..usage.rows {
            let mut store = setup();
            let before = snapshot(&store);
            assert_eq!(
                store.commit(
                    input,
                    Some("unstable"),
                    ReadBudget { rows, ..budget() },
                    &mut Usage::default()
                ),
                Err(Error::Storage(StorageError::ReadLimit)),
                "each row boundary refuses before publication"
            );
            assert_eq!(snapshot(&store), before);
        }
        let mut store = setup();
        let before = snapshot(&store);
        assert_eq!(
            store.commit(
                input,
                Some("unstable"),
                ReadBudget {
                    bytes: usage.allocation_bytes - 1,
                    ..budget()
                },
                &mut Usage::default()
            ),
            Err(Error::Storage(StorageError::ReadLimit))
        );
        assert_eq!(snapshot(&store), before);
        let mut exact = Usage::default();
        assert_eq!(
            store
                .commit(
                    input,
                    Some("unstable"),
                    ReadBudget {
                        rows: usage.rows,
                        bytes: usage.allocation_bytes
                    },
                    &mut exact
                )
                .map(|j| j.inserted),
            Ok(prior != 2)
        );
        assert_eq!(exact, usage, "exact admitted requests reproduce the successful path");
    }
    let mut meter = Meter {
        limit: ReadBudget { rows: 0, bytes: 0 },
        used: Usage::default(),
    };
    let mut fetched = false;
    assert_eq!(
        meter.row(|| {
            fetched = true;
        }),
        Err(Error::Storage(StorageError::ReadLimit))
    );
    assert!(!fetched, "row is not fetched before admission");
    let mut output: Vec<u8> = Vec::new();
    assert_eq!(meter.reserve(&mut output, 1), Err(Error::Storage(StorageError::ReadLimit)));
    assert_eq!(output.capacity(), 0, "allocation is not executed before admission");
}

/// Claim: Each staged mutation of an ordinary child, a fork with a new debit origin, and a second root can be interrupted with the complete store unchanged and a successful retry; the placement and direct-child entries are staged mutations, and mutation order ends with all introduction memberships before publication.
/// ´claim:history:tree-writer-interruptions´
/// ´test:unit:tree-writer-interruptions´
#[test]
fn tree_writer_interruptions() {
    super::roster::interruption_conformance::<MemoryTree<'static>>();
}

/// Claim: Structural signed-range and key bounds refuse as Representation before either charge; an absent installed generation refuses as `UnknownGenerationLabel`, while a descriptor naming a first result in another segment is private-boundary `CorruptHistory`, with no changed retained state.
/// ´claim:history:tree-writer-ranges´
/// ´test:unit:tree-writer-ranges´
#[test]
fn tree_writer_ranges() {
    let original = declared();
    let mut ordinal = original.clone();
    ordinal.ordinal = u64::MAX;
    let mut minimum = original.clone();
    minimum.minimum = u64::MAX;
    let mut label = original.clone();
    label.label = "x".repeat(1025);
    let mut scope = original.clone();
    scope.scope.history = "x".repeat(1025);
    let mut coordinate = original.clone();
    coordinate.versions[0].opens_at = u64::MAX;
    let mut closure = original.clone();
    closure.closures[0].closes_at = u64::MAX;
    for input in [&closure, &label, &scope, &minimum, &coordinate, &ordinal] {
        let mut store = MemoryTree::default();
        let before = snapshot(&store);
        let mut usage = Usage::default();
        assert_eq!(
            store.install_generation(input, ReadBudget { rows: 0, bytes: 0 }, &mut usage),
            Err(Error::Storage(StorageError::Representation))
        );
        assert_eq!(usage, Usage::default());
        assert_eq!(snapshot(&store), before);
    }
    let fixture = forks();
    let root = &fixture.main[0];
    let other = &fixture.other_root[0];
    let mut store = MemoryTree::default();
    let before = snapshot(&store);
    assert_eq!(
        store.commit(root, Some("unstable"), budget(), &mut Usage::default()),
        Err(Error::UnknownGenerationLabel)
    );
    assert_eq!(snapshot(&store), before);
    assert_eq!(
        store.install_generation(&fixture.generation, budget(), &mut Usage::default()),
        Ok(true)
    );
    for input in [root, other] {
        assert_eq!(
            store
                .commit(input, Some("unstable"), budget(), &mut Usage::default())
                .map(|j| j.inserted),
            Ok(true)
        );
    }
    assert_ne!(
        store.results[&(root.event().0, *root.event().1)].segment,
        store.results[&(other.event().0, *other.event().1)].segment
    );
    store.segments.get_mut(&(root.event().0, *root.event().1)).unwrap().first = *other.event().1;
    let before = snapshot(&store);
    assert_eq!(
        store.commit(root, Some("unstable"), budget(), &mut Usage::default()),
        Err(Error::Storage(StorageError::CorruptHistory)),
        "descriptor first must be a member of its own segment"
    );
    assert_eq!(snapshot(&store), before);
}

/// Claim: The ordered index's sole node reservation site admits the exact requested size before its site hook, refuses one below it, and publishes 64 distinct unsorted keys with ordered bounded range delivery and balanced height without further heap requests at publication; this is a reservation-site control, not an allocator census.
/// ´claim:history:tree-index-reservations´
/// ´test:unit:tree-index-reservations´
#[test]
fn tree_index_reservations() {
    let bytes = Index::<u64, u64>::request_size();
    let mut meter = Meter {
        limit: ReadBudget {
            rows: 0,
            bytes: bytes - 1,
        },
        used: Usage::default(),
    };
    index::ALLOCATIONS.with(|n| n.set(0));
    assert!(matches!(
        Index::<u64, u64>::prepare(17, &mut meter),
        Err(Error::Storage(StorageError::ReadLimit))
    ));
    assert_eq!(
        index::ALLOCATIONS.with(std::cell::Cell::get),
        0,
        "index allocation site follows admission"
    );
    assert_eq!(meter.used, Usage::default());
    let mut tree = Index::default();
    let mut meter = Meter {
        limit: ReadBudget {
            rows: 0,
            bytes: bytes * 64,
        },
        used: Usage::default(),
    };
    for key in (0..64_u64).map(|n| n ^ 0x25) {
        let slot = Index::prepare(key, &mut meter).unwrap();
        let admitted = index::ALLOCATIONS.with(std::cell::Cell::get);
        tree.publish(slot, key + 100);
        assert_eq!(
            index::ALLOCATIONS.with(std::cell::Cell::get),
            admitted,
            "publication executes no index reservation site"
        );
        assert!(tree.balanced(), "each insertion preserves the logarithmic height invariant");
    }
    assert_eq!(tree.len(), 64);
    assert_eq!(meter.used.allocation_bytes, bytes * 64);
    assert_eq!(index::ALLOCATIONS.with(std::cell::Cell::get), 64);
    assert_eq!(
        tree.iter().map(|(&k, &v)| (k, v)).collect::<Vec<_>>(),
        (0..64_u64).map(|k| (k, k + 100)).collect::<Vec<_>>()
    );
    let mut selected = Vec::new();
    assert_eq!(
        tree.visit(&7, &12, &mut |&k, &v| {
            selected.push((k, v));
            Ok(())
        }),
        Ok(())
    );
    assert_eq!(selected, (7..=12_u64).map(|k| (k, k + 100)).collect::<Vec<_>>());
}

fn index_damage(input: &Retained, parent: &Retained, generation: &Generation) {
    use super::roster::{Contract, Damage};
    for damage in [Damage::MissingPlacement, Damage::ForeignPlacement, Damage::MissingChild] {
        let mut store = MemoryTree::default();
        assert_eq!(Contract::install(&mut store, generation), Ok(true));
        assert_eq!(store.write(parent), Ok(true));
        assert_eq!(store.write(input), Ok(true));
        let before = snapshot(&store);
        let mut expected = store.index_rows();
        let (scope, identity, ancestor, depth) = input.event();
        let key = (scope.clone(), store.results[&(scope, *identity)].segment, depth);
        match damage {
            Damage::MissingPlacement => {
                expected.placements.remove(&key);
            }
            Damage::ForeignPlacement => {
                expected.placements.insert(key, *parent.event().1);
            }
            Damage::MissingChild => {
                expected.children.remove(&(scope.clone(), ancestor.copied(), *identity));
            }
            _ => unreachable!("three private index damage shapes"),
        }
        let old_rows = store.immutable_rows();
        store.damage(input, parent, damage);
        assert_ne!(snapshot(&store), before, "private adapter changes the requested index");
        assert_eq!(
            store.index_rows(),
            expected,
            "private adapter preserves every other index entry"
        );
        for (key, value) in store.immutable_rows() {
            if !key.starts_with("placement:") && !key.starts_with("direct-child:") {
                assert_eq!(old_rows.get(&key), Some(&value), "private index damage preserves other rows");
            }
        }
    }
}

/// Claim: Every result of a 32-result segment with no debit introductions after its root and three children of one parent has its complete placement and direct-child entry, including roots; an equal retry changes no retained field and executes no index publication site. Three private damage-adapter shapes alter only a missing or foreign placement entry or a missing child entry; these inspections claim no reader corruption refusal.
/// ´claim:history:tree-result-indexes´
/// ´test:unit:tree-result-indexes´
#[test]
fn tree_result_indexes() {
    use super::roster::{Contract, IndexRows};
    use crate::admitted_carrier_tests::tree_fixture::tree_sequence;
    let positions: Vec<_> = (1..=32).map(|n| n * 100).collect();
    let chain = retain_chain(&tree_sequence(&positions, None));
    let third = retain_chain(&tree_sequence(&[100, 200, 375], None));
    let fixture = forks();
    let mut store = MemoryTree::default();
    assert_eq!(Contract::install(&mut store, &fixture.generation), Ok(true));
    let mut expected = IndexRows::default();
    let allowance = ReadBudget {
        rows: 1_000_000,
        bytes: 100_000_000,
    };
    // Arrival is ancestry-valid and is not sorted by either index's identity key.
    for input in chain.iter().chain([&fixture.side[2], &third[2]]) {
        let old = store.immutable_rows();
        assert_eq!(
            store
                .commit(input, Some("unstable"), allowance, &mut Usage::default())
                .map(|j| j.inserted),
            Ok(true)
        );
        let (scope, identity, parent, depth) = input.event();
        let segment = if chain.iter().any(|v| v.event().1 == identity) {
            *chain[0].event().1
        } else {
            *identity
        };
        expected.placements.insert((scope.clone(), segment, depth), *identity);
        expected.children.insert((scope.clone(), parent.copied(), *identity));
        assert_eq!(
            store.index_rows(),
            expected,
            "complete indexes include empty interiors and later siblings"
        );
        let after = store.immutable_rows();
        for (key, value) in old {
            assert_eq!(
                after.get(&key),
                Some(&value),
                "index maintenance preserves every existing row"
            );
        }
        let before = snapshot(&store);
        let publications = index::PUBLICATIONS.with(std::cell::Cell::get);
        assert_eq!(
            store
                .commit(input, Some("unstable"), allowance, &mut Usage::default())
                .map(|j| j.inserted),
            Ok(false)
        );
        assert_eq!(snapshot(&store), before);
        assert_eq!(
            index::PUBLICATIONS.with(std::cell::Cell::get),
            publications,
            "exact retry executes no index publication"
        );
    }
    assert_eq!(
        store
            .introductions
            .iter()
            .map(|(key, value)| (*key, *value))
            .collect::<Vec<_>>(),
        vec![((chain[0].event().0, *chain[0].event().1, 1), *chain[0].event().1)],
        "placement preserves the root-only sparse debit index"
    );
    assert_eq!(
        store.children.get(&(chain[1].event().0, *chain[1].event().1)),
        Some(chain[2].event().1)
    );
    assert_eq!(store.placements.len(), 34);
    assert_eq!(store.direct_children.len(), 34);
    index_damage(&chain[1], &chain[0], &fixture.generation);
}

pub(super) fn index_events(events: &[Write]) {
    assert_eq!(
        events.iter().filter(|&&w| w == Write::Placement).count(),
        1,
        "placement is an interruption point"
    );
    assert_eq!(
        events.iter().filter(|&&w| w == Write::DirectChild).count(),
        1,
        "direct child is an interruption point"
    );
}

fn read_budget() -> ReadBudget {
    ReadBudget {
        rows: 100_000,
        bytes: 100_000_000,
    }
}

fn read_store() -> MemoryTree<'static> {
    let f = forks();
    let mut store = MemoryTree::default();
    assert_eq!(
        store.install_generation(&f.generation, read_budget(), &mut Usage::default()),
        Ok(true)
    );
    for input in [&f.main[0], &f.main[1], &f.side[2], &f.main[2], &f.main[3], &f.other_root[0]] {
        assert!(
            store
                .commit(input, Some("unstable"), read_budget(), &mut Usage::default())
                .is_ok()
        );
    }
    store
}

/// Claim: Twelve unsorted worked-example queries in each sibling arrival order distinguish both tips below and above a fork, clamp above each tip, preserve exact bytes and each selection and debit origin, return debits in act order, and leave the complete store unchanged; unknown exact identities are absent and unknown tips refuse separately.
/// ´claim:history:tree-read-branches´
/// ´test:unit:tree-read-branches´
#[test]
fn tree_read_branches() {
    super::roster::read_conformance::<MemoryTree<'static>>();
}

/// Claim: Root, child, candidate and tip pages use identity byte order within their fixed scope and parent, advance empty tip pages by inspected candidates, share one cumulative session, and preserve the store; fixture arrival is not sorted by identity.
/// ´claim:history:tree-read-pages´
/// ´test:unit:tree-read-pages´
#[test]
fn tree_read_pages() {
    let f = forks();
    let store = read_store();
    let scope = f.main[0].event().0;
    let before = snapshot(&store);
    let mut reader = store.reader(read_budget());
    let mut roots = vec![*f.main[0].event().1, *f.other_root[0].event().1];
    roots.sort_unstable();
    assert_eq!(reader.roots(scope, None, 10).unwrap().identities, roots);
    let mut children = vec![*f.main[2].event().1, *f.side[2].event().1];
    children.sort_unstable();
    assert_eq!(
        reader.children(scope, *f.main[1].event().1, None, 10).unwrap().identities,
        children,
        "all siblings are ordered by identity"
    );
    assert_eq!(reader.children(scope, [255; 32], None, 1), Err(Error::MissingTip));
    let all = reader.candidates(scope, None, 100).unwrap().identities;
    assert_eq!(all.len(), 6);
    assert!(all.windows(2).all(|w| w[0] < w[1]));
    let mut cursor = None;
    let mut tips = Vec::new();
    let mut empty = 0;
    loop {
        let page = reader.tips(scope, cursor, 1).unwrap();
        if page.end {
            break;
        }
        assert!(page.after > cursor, "every inspected candidate advances");
        if page.identities.is_empty() {
            empty += 1;
        }
        tips.extend(page.identities);
        cursor = page.after;
    }
    let mut expected = vec![*f.main[3].event().1, *f.side[2].event().1, *f.other_root[0].event().1];
    expected.sort_unstable();
    assert_eq!(tips, expected);
    assert_eq!(empty, 3, "non-tip pages advance without output");
    assert!(reader.usage().rows > all.len());
    assert_eq!(snapshot(&store), before);
    reversed_arrival_pages();
}

fn reversed_arrival_pages() {
    let f = forks();
    let mut root_inputs = [&f.main[0], &f.other_root[0]];
    let mut child_inputs = [&f.main[2], &f.side[2]];
    root_inputs.sort_unstable_by(|a, b| b.event().1.cmp(a.event().1));
    child_inputs.sort_unstable_by(|a, b| b.event().1.cmp(a.event().1));
    assert!(root_inputs[0].event().1 > root_inputs[1].event().1);
    assert!(child_inputs[0].event().1 > child_inputs[1].event().1);
    let mut store = MemoryTree::default();
    assert_eq!(
        store.install_generation(&f.generation, read_budget(), &mut Usage::default()),
        Ok(true)
    );
    for input in root_inputs.into_iter().chain([&f.main[1]]).chain(child_inputs) {
        assert!(
            store
                .commit(input, Some("unstable"), read_budget(), &mut Usage::default())
                .is_ok()
        );
    }
    let before = snapshot(&store);
    let scope = f.main[0].event().0;
    let mut reader = store.reader(read_budget());
    assert_eq!(
        reader.roots(scope, None, 10).unwrap().identities,
        vec![*root_inputs[1].event().1, *root_inputs[0].event().1],
        "root order is not arrival order"
    );
    assert_eq!(
        reader.children(scope, *f.main[1].event().1, None, 10).unwrap().identities,
        vec![*child_inputs[1].event().1, *child_inputs[0].event().1],
        "child order is not arrival order"
    );
    assert_eq!(snapshot(&store), before);
}

/// Claim: Missing placement, foreign placement and missing child entries refuse `CorruptHistory` through private damage on exact reads, without changing any retained state; these are the three evidenced reader damage shapes only.
/// ´claim:history:tree-read-index-damage´
/// ´test:unit:tree-read-index-damage´
#[test]
fn tree_read_index_damage() {
    use super::roster::{Contract, Damage};
    let f = forks();
    for damage in [Damage::MissingPlacement, Damage::ForeignPlacement, Damage::MissingChild] {
        let mut store = read_store();
        store.damage(&f.main[3], &f.main[2], damage);
        let before = snapshot(&store);
        assert_eq!(
            store.reader(read_budget()).exact(f.main[3].event().0, *f.main[3].event().1),
            Err(Error::Storage(StorageError::CorruptHistory)),
            "damaged index membership refuses"
        );
        assert_eq!(snapshot(&store), before);
    }
}

fn read_limits(store: &MemoryTree<'_>, input: &Retained, depth: u64, expected_usage: Usage) {
    REQUESTS.with_borrow_mut(|a| *a = Some(Vec::new()));
    let mut reader = store.reader(read_budget());
    let expected = reader.as_of(input.event().0, *input.event().1, depth).unwrap();
    let used = reader.usage();
    assert_eq!(used, expected_usage, "reader helper probes and returned requests are pinned");
    let requests = REQUESTS.with_borrow_mut(|a| a.take().unwrap());
    assert_eq!(requests.iter().sum::<usize>(), used.allocation_bytes);
    let before = snapshot(store);
    for rows in (0..used.rows).rev() {
        let mut reader = store.reader(ReadBudget {
            rows,
            bytes: read_budget().bytes,
        });
        assert_eq!(
            reader.as_of(input.event().0, *input.event().1, depth),
            Err(Error::Storage(StorageError::ReadLimit)),
            "every row ceiling refuses without a partial result"
        );
        assert!(reader.usage().rows <= rows);
    }
    let mut sum = 0;
    for request in requests {
        sum += request;
        if request == 0 {
            continue;
        }
        let mut reader = store.reader(ReadBudget {
            rows: read_budget().rows,
            bytes: sum - 1,
        });
        assert_eq!(
            reader.as_of(input.event().0, *input.event().1, depth),
            Err(Error::Storage(StorageError::ReadLimit)),
            "every buffer ceiling refuses without a partial result"
        );
        assert!(reader.usage().allocation_bytes < sum);
    }
    let mut reader = store.reader(ReadBudget {
        rows: used.rows,
        bytes: used.allocation_bytes,
    });
    assert_eq!(reader.as_of(input.event().0, *input.event().1, depth), Ok(expected));
    assert_eq!(snapshot(store), before);
}

/// Claim: Every row and reservation prefix of the executed continuation and fork read paths meets a refusing ceiling, exact allowance succeeds and late refusal returns no result; no fetched header is delivered before row admission.
/// ´claim:history:tree-read-limits´
/// ´test:unit:tree-read-limits´
#[test]
fn tree_read_limits() {
    let store = read_store();
    let f = forks();
    read_limits(
        &store,
        &f.main[3],
        4,
        Usage {
            rows: 186,
            allocation_bytes: 188_606,
        },
    );
    read_limits(
        &store,
        &f.main[3],
        2,
        Usage {
            rows: 110,
            allocation_bytes: 84_491,
        },
    );
    read_limits(
        &store,
        &f.side[2],
        3,
        Usage {
            rows: 137,
            allocation_bytes: 122_730,
        },
    );
    let mut reader = store.reader(ReadBudget { rows: 0, bytes: 0 });
    assert_eq!(reader.exact(f.main[0].event().0, [255; 32]), Ok(None));
    super::read::FETCHES.with(|n| n.set(0));
    assert_eq!(
        reader.exact(f.main[0].event().0, *f.main[0].event().1),
        Err(Error::Storage(StorageError::ReadLimit))
    );
    assert_eq!(
        super::read::FETCHES.with(std::cell::Cell::get),
        0,
        "header fetch follows budget admission"
    );
    assert_eq!(reader.usage(), Usage::default());
}

/// Claim: Two nested forks resolve independently of long empty interiors and side-branch arrival; descriptor traversal visits only the nesting of forks, while returned reconstruction has its own charges, and later results leave earlier exact bytes and selections unchanged.
/// ´claim:history:tree-read-nested´
/// ´test:unit:tree-read-nested´
#[test]
fn tree_read_nested() {
    use crate::admitted_carrier_tests::tree_fixture::tree_sequence;
    let main = retain_chain(&tree_sequence(
        &[100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200],
        None,
    ));
    let side = retain_chain(&tree_sequence(&[100, 200, 301, 401, 501, 601], None));
    let nested = retain_chain(&tree_sequence(&[100, 200, 301, 402, 502, 602], None));
    let f = forks();
    let mut store = MemoryTree::default();
    assert!(
        store
            .install_generation(&f.generation, read_budget(), &mut Usage::default())
            .is_ok()
    );
    for input in &main[..3] {
        assert!(
            store
                .commit(input, Some("unstable"), read_budget(), &mut Usage::default())
                .is_ok()
        );
    }
    let before = store
        .reader(read_budget())
        .exact(main[1].event().0, *main[1].event().1)
        .unwrap();
    let whole_before = [true, false].map(|exact| whole_read_usage(&store, &main[2], &main[1], exact));
    assert_read_usage(whole_before[0], 99, 84_347, "whole exact read has the pinned request usage");
    assert_read_usage(whole_before[1], 105, 84_395, "whole as-of read has the pinned request usage");
    for input in side.iter().skip(2).chain(nested.iter().skip(3)).chain(main.iter().skip(3)) {
        assert!(
            store
                .commit(input, Some("unstable"), read_budget(), &mut Usage::default())
                .is_ok()
        );
    }
    let snapshot_before = snapshot(&store);
    let whole_after = [true, false].map(|exact| whole_read_usage(&store, &main[11], &main[1], exact));
    assert_eq!(whole_after, whole_before, "whole reads ignore empty length and side branches");
    let side_usage = whole_read_usage(&store, &side[5], &main[1], false);
    let nested_usage = whole_read_usage(&store, &nested[5], &main[1], false);
    let nested_exact = whole_read_usage(&store, &nested[5], &nested[5], true);
    assert_read_usage(nested_exact, 246, 268_227, "nested exact admits empty introduction descents");
    assert!(
        side_usage.rows > whole_after[1].rows && nested_usage.rows > side_usage.rows,
        "whole read visits grow with nested forks"
    );
    assert!(
        side_usage.allocation_bytes > whole_after[1].allocation_bytes
            && nested_usage.allocation_bytes > side_usage.allocation_bytes,
        "whole read range requests grow with nested forks"
    );
    for depth in [6, 2, 4, 1, 5, 3] {
        let expected = if depth <= 2 { &main[depth - 1] } else { &nested[depth - 1] };
        assert_eq!(
            store
                .reader(read_budget())
                .as_of(expected.event().0, *nested[5].event().1, depth as u64)
                .unwrap()
                .unwrap()
                .identity,
            *expected.event().1,
            "nested fork cutoffs preserve ancestry"
        );
    }
    for depth in [11, 4, 8, 3, 7] {
        assert_eq!(
            store
                .reader(read_budget())
                .as_of(main[0].event().0, *main[11].event().1, depth as u64)
                .unwrap()
                .unwrap()
                .identity,
            *main[depth - 1].event().1
        );
    }
    assert_eq!(
        store
            .reader(read_budget())
            .exact(main[1].event().0, *main[1].event().1)
            .unwrap(),
        before
    );
    assert_eq!(snapshot(&store), snapshot_before);
}

fn assert_read_usage(actual: Usage, rows: usize, allocation_bytes: usize, message: &str) {
    assert_eq!(actual, Usage { rows, allocation_bytes }, "{message}");
}

fn whole_read_usage(store: &MemoryTree<'_>, tip: &Retained, expected: &Retained, exact: bool) -> Usage {
    let mut reader = store.reader(read_budget());
    let result = if exact {
        reader.exact(expected.event().0, *expected.event().1)
    } else {
        reader.as_of(tip.event().0, *tip.event().1, expected.event().3)
    }
    .unwrap()
    .unwrap();
    assert_eq!(result.identity, *expected.event().1);
    reader.usage()
}

/// Claim: A generation with an explicit later edition and closure resolves retained uses at their original coordinates, not to the current edition; its fork read crosses every row and allocation ceiling without partial output or changed state.
/// ´claim:history:tree-read-closure´
/// ´test:unit:tree-read-closure´
#[test]
fn tree_read_closure() {
    let f = forks();
    let mut generation = f.generation.clone();
    let use_ = f.main[0]
        .declarations()
        .iter()
        .find(|u| unqualified(u.version.family))
        .unwrap();
    let mut later = use_.version.clone();
    later.edition.push_str("-later");
    later.opens_at = f
        .main
        .iter()
        .chain(&f.side)
        .flat_map(Retained::declarations)
        .filter(|u| u.version.family == use_.version.family && u.version.key == use_.version.key)
        .map(|u| u.selected_at)
        .max()
        .unwrap()
        + 1;
    generation.closures.push(Closure {
        family: use_.version.family,
        key: use_.version.key.clone(),
        edition: use_.version.edition.clone(),
        closes_at: later.opens_at,
    });
    generation.versions.push(later);
    generation
        .versions
        .sort_by(|a, b| declaration_key(a).cmp(&declaration_key(b)));
    let mut store = MemoryTree::default();
    assert_eq!(
        store.install_generation(&generation, read_budget(), &mut Usage::default()),
        Ok(true)
    );
    for input in [&f.main[0], &f.main[1], &f.side[2], &f.main[2], &f.main[3]] {
        assert!(
            store
                .commit(input, Some("unstable"), read_budget(), &mut Usage::default())
                .is_ok()
        );
    }
    let got = store
        .reader(read_budget())
        .exact(f.main[3].event().0, *f.main[3].event().1)
        .unwrap()
        .unwrap();
    assert!(
        got.selections.iter().any(|s| s.use_ == use_),
        "the recorded edition survives a later effective edition"
    );
    read_limits(
        &store,
        &f.main[3],
        4,
        Usage {
            rows: 198,
            allocation_bytes: 188_606,
        },
    );
}

/// Claim: Enumeration shares the caller session's allowance across statements; every row ceiling below completion refuses, and the final allocation boundary of each supplied root, child, candidate and tip page refuses one below and succeeds exactly, including an empty advancing tip page.
/// ´claim:history:tree-read-page-limits´
/// ´test:unit:tree-read-page-limits´
#[test]
fn tree_read_page_limits() {
    let f = forks();
    let store = read_store();
    let before = snapshot(&store);
    let scope = f.main[0].event().0;
    let mut candidates = [&f.main[0], &f.main[1], &f.side[2], &f.main[2], &f.main[3], &f.other_root[0]].map(|r| *r.event().1);
    candidates.sort_unstable();
    let empty_index = candidates
        .iter()
        .position(|id| [&f.main[0], &f.main[1], &f.main[2]].iter().any(|r| r.event().1 == id))
        .unwrap();
    let empty_after = empty_index.checked_sub(1).map(|i| candidates[i]);
    for kind in [3, 0, 4, 2, 1] {
        let query = |reader: &mut super::read::Reader<'_, '_>| match kind {
            0 => reader.roots(scope, None, 2),
            1 => reader.children(scope, *f.main[1].event().1, None, 2),
            2 => reader.candidates(scope, None, 3),
            4 => reader.tips(scope, empty_after, 1),
            _ => reader.tips(scope, None, 3),
        };
        let mut reader = store.reader(read_budget());
        let expected = query(&mut reader).unwrap();
        if kind == 4 {
            assert!(expected.identities.is_empty(), "the swept tip page is empty");
            assert_eq!(expected.after, Some(candidates[empty_index]), "the swept empty page advances");
        }
        let used = reader.usage();
        for rows in (0..used.rows).rev() {
            assert_eq!(
                query(&mut store.reader(ReadBudget {
                    rows,
                    bytes: read_budget().bytes
                })),
                Err(Error::Storage(StorageError::ReadLimit)),
                "page row admission precedes visits"
            );
        }
        assert_eq!(
            query(&mut store.reader(ReadBudget {
                rows: used.rows,
                bytes: used.allocation_bytes - 1
            })),
            Err(Error::Storage(StorageError::ReadLimit))
        );
        assert_eq!(
            query(&mut store.reader(ReadBudget {
                rows: used.rows,
                bytes: used.allocation_bytes
            })),
            Ok(expected)
        );
    }
    let mut reader = store.reader(ReadBudget {
        rows: 1,
        bytes: read_budget().bytes,
    });
    assert!(reader.has_child(scope, *f.main[0].event().1).unwrap());
    assert_eq!(
        reader.has_child(scope, *f.main[0].event().1),
        Err(Error::Storage(StorageError::ReadLimit)),
        "statements share one meter"
    );
    assert_eq!(snapshot(&store), before, "page limits leave complete state unchanged");
}

/// Claim: Zero page work refuses without a visit, and unrepresentable page limits, signed depths and scopes refuse as representation before a zero allowance can admit any stored-state visit or buffer.
/// ´claim:history:tree-read-shapes´
/// ´test:unit:tree-read-shapes´
#[test]
fn tree_read_shapes() {
    let f = forks();
    let store = read_store();
    let before = snapshot(&store);
    let scope = f.main[0].event().0;
    let mut generous = store.reader(read_budget());
    assert_eq!(
        generous.children(scope, *f.main[0].event().1, None, 0),
        Err(Error::Storage(StorageError::ReadLimit)),
        "zero child page refuses with a generous allowance"
    );
    assert_eq!(generous.usage(), Usage::default(), "zero child page admits no work");
    let zero = ReadBudget { rows: 0, bytes: 0 };
    let mut reader = store.reader(zero);
    assert_eq!(
        reader.roots(scope, None, 0),
        Err(Error::Storage(StorageError::ReadLimit)),
        "zero page work refuses without admission"
    );
    assert_eq!(reader.usage(), Usage::default());
    assert_eq!(
        reader.roots(scope, None, usize::MAX),
        Err(Error::Storage(StorageError::Representation)),
        "page representation wins before admission"
    );
    assert_eq!(reader.usage(), Usage::default());
    assert_eq!(
        reader.as_of(scope, *f.main[0].event().1, i64::MAX as u64 + 1),
        Err(Error::Storage(StorageError::Representation)),
        "depth representation wins before admission"
    );
    assert_eq!(reader.usage(), Usage::default());
    let mut oversized = scope.clone();
    oversized.history = "x".repeat(1025);
    assert_eq!(
        reader.exact(&oversized, *f.main[0].event().1),
        Err(Error::Storage(StorageError::Representation)),
        "scope representation wins before admission"
    );
    assert_eq!(reader.usage(), Usage::default());
    assert_eq!(snapshot(&store), before);
}
