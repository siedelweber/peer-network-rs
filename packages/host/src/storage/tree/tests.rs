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

/// Claim: Publicly admitted fixture packages form two roots and a fork with independent debit origins; a child inherits only its ancestors' complete vintages and original selections, a side retry is unchanged, and differing context or same-position content refuses without writing. The first child continues its parent segment without a descriptor and the later child opens one while preserving the first-child row.
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

/// Claim: Each staged mutation of an ordinary child, a fork with a new debit origin, and a second root can be interrupted with the complete store unchanged and a successful retry; mutation order ends with all introduction memberships before publication.
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
