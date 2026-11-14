use super::tests::{budget, forks, snapshot};
use super::{DeclarationUse, Error, Generation, Identity, MemoryTree, Retained, StorageError, Usage, Write};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct IndexRows {
    pub placements: BTreeMap<(super::EpochScope, Identity, u64), Identity>,
    pub children: BTreeSet<(super::EpochScope, Option<Identity>, Identity)>,
}

type Debit = (pn_records::ActId, Identity, Vec<u8>);

#[derive(Debug, PartialEq, Eq)]
pub(super) struct DescriptorView {
    first: Identity,
    start: u64,
    parent_segment: Option<Identity>,
    fork: Option<Identity>,
    cutoff: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Placement {
    segment: Identity,
    descriptor: Option<DescriptorView>,
    first_child: Option<Identity>,
}

// This test-only contract exposes complete snapshots and interruption boundaries,
// not a production reader. A server adapter can run these assertions unchanged.
pub(super) trait Contract<'a>: Default {
    fn install(&mut self, input: &'a Generation) -> Result<bool, Error>;
    fn write(&mut self, input: &'a Retained) -> Result<bool, Error>;
    fn staged(&mut self, input: &'a Retained, stop: Option<usize>) -> (Result<bool, Error>, Vec<Write>);
    fn snapshot(&self) -> String;
    fn immutable_rows(&self) -> BTreeMap<String, String>;
    fn origins(&self, input: &Retained) -> Result<Vec<Debit>, Error>;
    fn selections(&self, input: &Retained) -> Vec<(DeclarationUse, Identity)>;
    fn placement(&self, input: &Retained) -> Placement;
    fn index_rows(&self) -> IndexRows;
    fn damage(&mut self, input: &'a Retained, parent: &'a Retained, damage: Damage);
}
impl<'a> Contract<'a> for MemoryTree<'a> {
    fn index_rows(&self) -> IndexRows {
        IndexRows {
            placements: self
                .placements
                .iter()
                .map(|((s, g, d), v)| (((*s).clone(), *g, *d), *v))
                .collect(),
            children: self
                .direct_children
                .iter()
                .map(|((s, p, i), ())| ((*s).clone(), *p, *i))
                .collect(),
        }
    }
    fn placement(&self, input: &Retained) -> Placement {
        let key = (input.event().0, *input.event().1);
        Placement {
            segment: self.results[&key].segment,
            descriptor: self.segments.get(&key).map(|d| DescriptorView {
                first: d.first,
                start: d.start,
                parent_segment: d.parent_segment,
                fork: d.fork,
                cutoff: d.cutoff,
            }),
            first_child: self.children.get(&key).copied(),
        }
    }
    fn damage(&mut self, input: &'a Retained, parent: &'a Retained, damage: Damage) {
        let (scope, identity, ancestor, depth) = input.event();
        if matches!(
            damage,
            Damage::MissingPlacement | Damage::ForeignPlacement | Damage::MissingChild
        ) {
            let segment = self.results[&(scope, *identity)].segment;
            match damage {
                Damage::MissingPlacement => self.placements.erase(&(scope, segment, depth)),
                Damage::ForeignPlacement => *self.placements.get_mut(&(scope, segment, depth)).unwrap() = *parent.event().1,
                Damage::MissingChild => self.direct_children.erase(&(scope, ancestor.copied(), *identity)),
                _ => unreachable!("index damage only"),
            }
            return;
        }
        if matches!(damage, Damage::Observation) {
            let version = &input
                .declarations()
                .iter()
                .find(|u| !super::unqualified(u.version.family))
                .unwrap()
                .version;
            let slot = super::Index::prepare(
                (version.family, version.key.as_str(), version.edition.as_str()),
                &mut super::Meter {
                    limit: budget(),
                    used: Usage::default(),
                },
            )
            .unwrap();
            self.observations.publish(slot, version);
            return;
        }
        let row = self.results.get_mut(&(parent.event().0, *parent.event().1)).unwrap();
        match damage {
            Damage::ParentDepth => row.input = &forks().main[0],
            Damage::InheritedUse | Damage::RetryUse => {
                let selected = row
                    .references
                    .iter_mut()
                    .find(|r| super::unqualified(r.use_.version.family))
                    .unwrap();
                let mut changed = selected.use_.clone();
                changed.version.edition.push_str("-damaged");
                selected.use_ = Box::leak(Box::new(changed));
            }
            Damage::DebitBytes => {
                let introduction = row.introductions.first_mut().unwrap();
                let mut bytes = introduction.vintage.bytes.clone();
                *bytes.last_mut().unwrap() ^= 1;
                introduction.chunks = vec![Box::leak(bytes.into_boxed_slice())];
            }
            Damage::DebitAct => {
                let introduction = row.introductions.first_mut().unwrap();
                let mut vintage = introduction.vintage.clone();
                vintage.key.act.sequence += 50;
                introduction.vintage = Box::leak(Box::new(vintage));
            }
            Damage::Observation | Damage::MissingPlacement | Damage::ForeignPlacement | Damage::MissingChild => {
                unreachable!("handled before borrowing the result")
            }
        }
    }
    fn install(&mut self, input: &'a Generation) -> Result<bool, Error> {
        self.install_generation(input, budget(), &mut Usage::default())
    }
    fn write(&mut self, input: &'a Retained) -> Result<bool, Error> {
        self.commit(input, Some("unstable"), budget(), &mut Usage::default())
            .map(|j| j.inserted)
    }
    fn staged(&mut self, input: &'a Retained, stop: Option<usize>) -> (Result<bool, Error>, Vec<Write>) {
        let mut events = Vec::new();
        let result = self
            .commit_inner(
                input,
                Some("unstable"),
                &mut super::Meter {
                    limit: budget(),
                    used: Usage::default(),
                },
                &mut |event| {
                    let refuse = stop == Some(events.len());
                    events.push(event);
                    if refuse { Err(StorageError::Injected.into()) } else { Ok(()) }
                },
            )
            .map(|j| j.inserted);
        (result, events)
    }
    fn snapshot(&self) -> String {
        snapshot(self)
    }
    fn immutable_rows(&self) -> BTreeMap<String, String> {
        let mut rows = BTreeMap::new();
        for (key, value) in self.results.iter() {
            rows.insert(format!("result:{key:?}"), format!("{value:?}"));
        }
        for (key, value) in self.scopes.iter() {
            rows.insert(format!("scope:{key:?}"), format!("{value:?}"));
        }
        for (key, value) in self.segments.iter() {
            rows.insert(format!("segment:{key:?}"), format!("{value:?}"));
        }
        for (key, value) in self.observations.iter() {
            rows.insert(format!("observation:{key:?}"), format!("{value:?}"));
        }
        for (key, value) in self.introductions.iter() {
            rows.insert(format!("origin:{key:?}"), format!("{value:?}"));
        }
        for (key, value) in self.children.iter() {
            rows.insert(format!("child:{key:?}"), format!("{value:?}"));
        }
        for (key, value) in self.placements.iter() {
            rows.insert(format!("placement:{key:?}"), format!("{value:?}"));
        }
        for (key, value) in self.direct_children.iter() {
            rows.insert(format!("direct-child:{key:?}"), format!("{value:?}"));
        }
        for generation in &self.generations {
            rows.insert(
                format!("generation:{:?}", generation.declaration.scope),
                format!("{generation:?}"),
            );
        }
        rows
    }
    fn origins(&self, input: &Retained) -> Result<Vec<Debit>, Error> {
        let row = self
            .results
            .get(&(input.event().0, *input.event().1))
            .ok_or(StorageError::CorruptHistory)?;
        Ok(self
            .ancestor_debits(
                row,
                &mut super::Meter {
                    limit: budget(),
                    used: Usage::default(),
                },
            )?
            .into_iter()
            .map(|d| (d.vintage.key.act.clone(), d.origin, d.vintage.bytes.clone()))
            .collect())
    }
    fn selections(&self, input: &Retained) -> Vec<(DeclarationUse, Identity)> {
        self.results[&(input.event().0, *input.event().1)]
            .references
            .iter()
            .map(|r| (r.use_.clone(), r.origin))
            .collect()
    }
}

pub(super) fn fork_conformance<A: Contract<'static>>() {
    let fixture = forks();
    let [root, ancestor, left, descendant] = fixture.main.as_slice() else {
        panic!("four declared inputs")
    };
    let right = &fixture.side[2];
    let mut store = A::default();
    assert_eq!(store.install(&fixture.generation), Ok(true));
    let mut expected_indexes = IndexRows::default();
    for input in [root, ancestor, right, left, descendant, &fixture.other_root[0]] {
        let before = store.immutable_rows();
        assert_eq!(store.write(input), Ok(true), "a new sibling or root is accepted");
        let (scope, identity, parent, depth) = input.event();
        expected_indexes
            .placements
            .insert((scope.clone(), store.placement(input).segment, depth), *identity);
        expected_indexes.children.insert((scope.clone(), parent.copied(), *identity));
        assert_eq!(
            store.index_rows(),
            expected_indexes,
            "every result has exactly its placement and direct-child entry"
        );
        let after = store.immutable_rows();
        for (key, row) in before {
            assert_eq!(
                after.get(&key),
                Some(&row),
                "a fork neither rewrites nor rekeys any retained row"
            );
        }
    }
    fork_placement(&store);
    let expected = left.debits().iter().find(|v| v.key.act.sequence == 3).unwrap();
    let domain = store.origins(descendant).unwrap();
    assert_eq!(
        domain
            .iter()
            .find(|(act, _, _)| act == &expected.key.act)
            .map(|(_, origin, bytes)| (*origin, bytes.as_slice())),
        Some((*left.event().1, expected.bytes.as_slice())),
        "the introduction stays at B above B"
    );
    assert!(
        !store
            .origins(right)
            .unwrap()
            .iter()
            .any(|(act, _, _)| act == &expected.key.act),
        "a sibling's debit is absent"
    );
    for (selection, origin) in store.selections(descendant) {
        if super::unqualified(selection.version.family)
            && root
                .declarations()
                .iter()
                .any(|u| super::coordinate(u) == super::coordinate(&selection))
        {
            assert_eq!(origin, *root.event().1, "a descendant keeps the original judgement use");
        }
    }
    let before = store.snapshot();
    assert_eq!(store.write(right), Ok(false), "side retry is unchanged");
    assert_eq!(store.snapshot(), before);
    assert_eq!(
        store.write(&fixture.side_debit[2]),
        Err(Error::Storage(StorageError::EpochConflict)),
        "same position with different content conflicts"
    );
    assert_eq!(store.snapshot(), before);
    assert_eq!(store.write(&fixture.other_context[0]), Err(Error::ContextConflict));
    assert_eq!(store.snapshot(), before);
    let mut independent = A::default();
    assert_eq!(independent.install(&fixture.generation), Ok(true));
    for input in [root, ancestor, left, &fixture.side_debit[2]] {
        assert_eq!(independent.write(input), Ok(true));
    }
    for (input, origin) in [(left, *left.event().1), (&fixture.side_debit[2], *right.event().1)] {
        assert_eq!(
            independent
                .origins(input)
                .unwrap()
                .iter()
                .find(|(act, _, _)| act == &expected.key.act)
                .map(|(_, id, _)| *id),
            Some(origin),
            "the same act has independent origins on siblings"
        );
    }
}

fn fork_placement<A: Contract<'static>>(store: &A) {
    let fixture = forks();
    let [root, ancestor, left, descendant] = fixture.main.as_slice() else {
        panic!("four declared inputs")
    };
    let right = &fixture.side[2];
    assert_eq!(
        store.placement(ancestor).first_child,
        Some(*right.event().1),
        "the first child remains C"
    );
    assert_eq!(
        store.placement(right),
        Placement {
            segment: *root.event().1,
            descriptor: None,
            first_child: None,
        },
        "the first child continues without a descriptor"
    );
    assert_eq!(
        store.placement(left),
        Placement {
            segment: *left.event().1,
            descriptor: Some(DescriptorView {
                first: *left.event().1,
                start: 3,
                parent_segment: Some(*root.event().1),
                fork: Some(*ancestor.event().1),
                cutoff: 2
            }),
            first_child: Some(*descendant.event().1),
        },
        "the later child opens exactly its own fork descriptor"
    );
}

pub(super) fn interruption_conformance<A: Contract<'static>>() {
    let fixture = forks();
    let [root, ancestor, left, _] = fixture.main.as_slice() else {
        panic!("four declared inputs")
    };
    for input in [&fixture.other_root[0], &fixture.side_debit[2], ancestor] {
        let setup = || {
            let mut store = A::default();
            assert_eq!(store.install(&fixture.generation), Ok(true));
            for prior in [root, ancestor, left] {
                if input.event().1 == ancestor.event().1 && prior.event().1 != root.event().1 {
                    break;
                }
                assert_eq!(store.write(prior), Ok(true));
            }
            store
        };
        let mut store = setup();
        let (result, events) = store.staged(input, None);
        assert_eq!(result, Ok(true));
        assert_eq!(events.last(), Some(&Write::Publish));
        for stop in 0..events.len() {
            let mut store = setup();
            let before = store.snapshot();
            assert_eq!(store.staged(input, Some(stop)).0, Err(Error::Storage(StorageError::Injected)));
            assert_eq!(
                store.snapshot(),
                before,
                "every interrupted staged mutation rolls back the whole candidate"
            );
            assert_eq!(store.write(input), Ok(true));
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Damage {
    MissingPlacement,
    ForeignPlacement,
    MissingChild,
    ParentDepth,
    InheritedUse,
    Observation,
    DebitBytes,
    DebitAct,
    RetryUse,
}

fn damaged<A: Contract<'static>>(damage: Damage, retry: bool, expected: Error) {
    let fixture = forks();
    let [root, ancestor, parent, child] = fixture.main.as_slice() else {
        panic!("four declared inputs")
    };
    let mut store = A::default();
    assert_eq!(store.install(&fixture.generation), Ok(true));
    for input in [root, ancestor] {
        assert_eq!(store.write(input), Ok(true));
    }
    let (input, damaged_parent) = if matches!(damage, Damage::ParentDepth) {
        (parent, ancestor)
    } else {
        assert_eq!(store.write(parent), Ok(true));
        (if retry { parent } else { child }, parent)
    };
    store.damage(input, damaged_parent, damage);
    let before = store.snapshot();
    assert_eq!(
        store.write(input),
        Err(expected),
        "private refusal: {damage:?}, retry={retry}"
    );
    assert_eq!(store.snapshot(), before, "private refusal changes no retained row");
}

pub(super) fn refusal_conformance<A: Contract<'static>>() {
    // These are stored-state damage controls, not contradictory public packages.
    for (damage, expected) in [
        (Damage::Observation, Error::Storage(StorageError::CorruptHistory)),
        (Damage::DebitAct, Error::Storage(StorageError::DebitConflict)),
        (Damage::InheritedUse, Error::Storage(StorageError::SelectedContentMismatch)),
        (Damage::ParentDepth, Error::Storage(StorageError::CorruptHistory)),
        (Damage::DebitBytes, Error::Storage(StorageError::DebitConflict)),
    ] {
        damaged::<A>(damage, false, expected);
    }
    for damage in [Damage::DebitAct, Damage::RetryUse, Damage::DebitBytes] {
        damaged::<A>(damage, true, Error::Storage(StorageError::CorruptHistory));
    }
    let fixture = forks();
    let mut store = A::default();
    assert_eq!(store.install(&fixture.generation), Ok(true));
    for input in &fixture.main[..3] {
        assert_eq!(store.write(input), Ok(true));
    }
    let before = store.snapshot();
    assert_eq!(
        store.write(&fixture.other_binding[3]),
        Err(Error::PredecessorMismatch),
        "admitted alternate parent content cannot replace the retained binding"
    );
    assert_eq!(store.snapshot(), before);
}
