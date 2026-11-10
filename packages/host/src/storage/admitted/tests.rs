use super::*;
use crate::storage::{Family, Predecessor, Version};

// The roster uses this adapter boundary; PostgreSQL supplies the same operations
// and complete logical snapshot in its cut, without changing the assertions.
trait Contract: Sized {
    fn from_snapshot(snapshot: (History, State)) -> Self;
    fn implementation(&self) -> &'static str;
    fn snapshot(&self) -> (History, State);
    fn public_commit(&mut self, input: &AdmittedEpoch) -> Result<bool, StorageError>;
    fn append(&mut self, version: Version, predecessor: Option<&Predecessor>) -> Result<bool, StorageError>;
    fn commit(&mut self, input: &AdmittedEpoch, stop: Option<usize>) -> (Result<bool, StorageError>, Vec<Write>);
    fn read(&self, key: &EpochKey, budget: ReadBudget) -> Result<Option<EpochRead<'_>>, StorageError>;
    fn as_of(&self, key: &EpochKey, budget: ReadBudget) -> Result<Option<EpochRead<'_>>, StorageError>;
    fn measured_read(&self, key: &EpochKey, budget: ReadBudget) -> (Result<Option<EpochRead<'_>>, StorageError>, ReadMeter);
}
impl Contract for MemoryStore {
    fn read(&self, key: &EpochKey, budget: ReadBudget) -> Result<Option<EpochRead<'_>>, StorageError> {
        self.read_admitted_epoch(key, budget)
    }
    fn as_of(&self, key: &EpochKey, budget: ReadBudget) -> Result<Option<EpochRead<'_>>, StorageError> {
        self.read_admitted_as_of(key, budget)
    }
    fn measured_read(&self, key: &EpochKey, budget: ReadBudget) -> (Result<Option<EpochRead<'_>>, StorageError>, ReadMeter) {
        let mut meter = ReadMeter::default();
        let result = self.read_epoch_inner(key, budget, &mut meter);
        (result, meter)
    }
    fn public_commit(&mut self, input: &AdmittedEpoch) -> Result<bool, StorageError> {
        self.commit_admitted_epoch(input)
    }
    fn from_snapshot((history, admitted): (History, State)) -> Self {
        Self { history, admitted }
    }
    fn implementation(&self) -> &'static str {
        "memory"
    }
    fn snapshot(&self) -> (History, State) {
        // Test-only complete logical state, not the bounded public read.
        (self.history.clone(), self.admitted.clone())
    }
    fn append(&mut self, version: Version, predecessor: Option<&Predecessor>) -> Result<bool, StorageError> {
        self.append_effective_successor(version, predecessor)
    }
    fn commit(&mut self, input: &AdmittedEpoch, stop: Option<usize>) -> (Result<bool, StorageError>, Vec<Write>) {
        let mut writes = Vec::new();
        let result = self.commit_epoch_inner(input, &mut |write| {
            writes.push(write);
            if stop == Some(writes.len()) {
                Err(StorageError::Injected)
            } else {
                Ok(())
            }
        });
        (result, writes)
    }
}
fn seeded<A: Contract>(carrier: &AdmittedEpoch) -> A {
    let mut store = A::from_snapshot((History::new(), State::default()));
    for use_ in carrier.declarations().iter().rev() {
        assert!(store.append(use_.version.clone(), None).is_ok());
    }
    store
}
fn unchanged<A: Contract>(store: &mut A, input: &AdmittedEpoch, expected: StorageError) {
    let before = store.snapshot();
    assert_eq!(
        store.public_commit(input),
        Err(expected),
        "{} public refusal",
        store.implementation()
    );
    assert_eq!(
        store.snapshot(),
        before,
        "{} public refusal changed logical state",
        store.implementation()
    );
    let (result, writes) = store.commit(input, None);
    assert_eq!(result, Err(expected), "{} refusal", store.implementation());
    assert!(writes.is_empty(), "{} refusal wrote a relation", store.implementation());
    assert_eq!(
        store.snapshot(),
        before,
        "{} refusal changed logical state",
        store.implementation()
    );
}
fn retries<A: Contract>(store: &mut A, input: &AdmittedEpoch, conflict: &AdmittedEpoch) -> Vec<Write> {
    let (result, writes) = store.commit(input, None);
    assert_eq!(result, Ok(true), "{} commit", store.implementation());
    let before = store.snapshot();
    let (result, retry_writes) = store.commit(input, None);
    assert_eq!(result, Ok(false), "{} retry", store.implementation());
    assert!(
        retry_writes.is_empty(),
        "{} retry reapplied a vintage or result",
        store.implementation()
    );
    assert_eq!(
        store.snapshot(),
        before,
        "{} retry changed logical state",
        store.implementation()
    );
    unchanged(store, conflict, StorageError::EpochConflict);
    writes
}
fn interruptions<A: Contract>(make: impl Fn() -> A, input: &AdmittedEpoch, writes: &[Write]) {
    let mut committed = make();
    assert_eq!(committed.commit(input, None).0, Ok(true));
    let expected = committed.snapshot();
    let mut public = make();
    assert_eq!(public.public_commit(input), Ok(true));
    assert_eq!(public.snapshot(), expected, "{} public commit", public.implementation());
    assert_eq!(public.public_commit(input), Ok(false));
    assert_eq!(public.snapshot(), expected, "{} public retry", public.implementation());
    for stop in 1..=writes.len() {
        let mut store = make();
        let before = store.snapshot();
        let (result, observed) = store.commit(input, Some(stop));
        assert_eq!(
            result,
            Err(StorageError::Injected),
            "{} boundary {stop}",
            store.implementation()
        );
        assert_eq!(observed, writes[..stop], "{} write order", store.implementation());
        assert_eq!(
            store.snapshot(),
            before,
            "{} partial result visible at boundary {stop}",
            store.implementation()
        );
        assert_eq!(store.commit(input, None).0, Ok(true));
        assert_eq!(store.snapshot(), expected, "{} interrupted retry", store.implementation());
    }
}

/// Claim: The memory admitted transaction checks every selected family, commits all staged relations together, recognizes complete retries without writes, preserves debit vintages and refuses history changes that invalidate selected uses.
/// ´claim:history:admitted-memory-transaction-is-atomic´
/// ´test:unit:admitted-memory-contract´
#[test]
fn admitted_memory_contract() {
    conformance::<MemoryStore>();
}
fn conformance<A: Contract>() {
    let first = crate::admitted_carrier_tests::first_carrier();
    let later = crate::admitted_carrier_tests::shared_carrier();
    let conflict = crate::admitted_carrier_tests::conflicting_carrier();
    assert_eq!(first.event(), conflict.event());
    assert!(!first.same_content(&conflict));
    reference_refusals::<A>(first);
    let mut store = seeded::<A>(first);
    let writes = retries(&mut store, first, &conflict);
    interruptions(|| seeded::<A>(first), first, &writes);
    let vintages = store.snapshot().1.debits;
    // Observation versions advance at publication time; rule selections retain
    // their original coordinates. Feed the uses in reverse, not sorted order.
    for use_ in later.declarations().iter().rev() {
        let key = (use_.version.family, use_.version.key.clone());
        let snapshot = store.snapshot();
        let prior = snapshot
            .0
            .get(&key)
            .and_then(|rows| rows.last())
            .filter(|r| r.version.edition != use_.version.edition)
            .map(|r| Predecessor {
                edition: r.version.edition.clone(),
                closes_at: use_.version.opens_at,
            });
        assert!(store.append(use_.version.clone(), prior.as_ref()).is_ok());
    }
    let prepared = store.snapshot();
    let (result, later_writes) = store.commit(later, None);
    assert_eq!(result, Ok(true));
    assert_eq!(
        store.snapshot().1.debits,
        vintages,
        "{} later epoch rewrote a vintage",
        store.implementation()
    );
    assert!(
        !later_writes
            .iter()
            .any(|w| matches!(w, Write::Debit(_) | Write::DebitChunk(_, _)))
    );
    interruptions(|| A::from_snapshot(prepared.clone()), later, &later_writes);
    let mut different = prepared;
    let debit = different.1.debits.values_mut().next().unwrap();
    debit.chunks[0][0] ^= 1;
    unchanged(&mut A::from_snapshot(different), later, StorageError::DebitConflict);

    let use_ = later
        .declarations()
        .iter()
        .find(|u| u.version.family == Family::Rule && u.selected_at > u.version.opens_at)
        .unwrap();
    let mut successor = use_.version.clone();
    successor.edition = "guard-successor".into();
    successor.opens_at = use_.selected_at;
    let before = store.snapshot();
    let predecessor = Predecessor {
        edition: use_.version.edition.clone(),
        closes_at: successor.opens_at,
    };
    assert_eq!(
        store.append(successor.clone(), Some(&predecessor)),
        Err(StorageError::HistoricalSelectionConflict)
    );
    assert_eq!(store.snapshot(), before, "{} guard changed history", store.implementation());
    successor.opens_at = later.event().boundary + 1;
    let predecessor = Predecessor {
        closes_at: successor.opens_at,
        ..predecessor
    };
    assert_eq!(store.append(successor, Some(&predecessor)), Ok(true));
    assert_eq!(
        store.snapshot().1,
        before.1,
        "{} later declaration changed admitted results",
        store.implementation()
    );
    assert_eq!(
        (writes.len(), later_writes.len()),
        (16, 18),
        "{} complete boundary roster",
        store.implementation()
    );
}

fn reference_refusals<A: Contract>(first: &AdmittedEpoch) {
    let mut families = std::collections::BTreeSet::new();
    let mut refusal_count = 0;
    for use_ in first.declarations().iter().rev() {
        if !families.insert(use_.version.family) {
            continue;
        }
        let key = (use_.version.family, use_.version.key.clone());
        for kind in 0..4 {
            let mut snapshot = seeded::<A>(first).snapshot();
            let rows = snapshot.0.get_mut(&key).unwrap();
            let expected = match kind {
                0 => {
                    rows.clear();
                    StorageError::MissingSelectedVersion
                }
                1 => {
                    rows[0].version.payload = None;
                    StorageError::MissingSelectedVersion
                }
                2 => {
                    rows[0].version.payload.as_mut().unwrap().bytes.push(0);
                    StorageError::SelectedContentMismatch
                }
                _ => {
                    rows[0].closes_at = Some(use_.selected_at);
                    StorageError::SelectedVersionNotEffective
                }
            };
            unchanged(&mut A::from_snapshot(snapshot), first, expected);
            refusal_count += 1;
        }
    }
    assert_eq!(families.len(), 6);
    assert_eq!(refusal_count, 24);
}

/// Claim: Retained admitted memory reads preserve historical bytes, selections and vintages, refuse corrupt counts, and enforce explicit reconstruction bounds before each allocation and row visit.
/// ´claim:history:admitted-reads-preserve-bounded-history´
/// ´test:unit:admitted-memory-reads´
#[test]
fn admitted_memory_reads() {
    read_conformance::<MemoryStore>();
}

fn assert_retained<A: Contract>(store: &A, input: &AdmittedEpoch) {
    let budget = ReadBudget {
        bytes: usize::MAX,
        rows: usize::MAX,
    };
    for read in [store.read(input.event(), budget), store.as_of(input.event(), budget)] {
        let read = read
            .unwrap_or_else(|cause| panic!("{} historical read refused: {cause:?}", store.implementation()))
            .unwrap();
        assert_eq!(
            read.event.as_ref(),
            input.event(),
            "{} retained event",
            store.implementation()
        );
        assert_eq!(read.bytes, input.bytes(), "{} historical bytes", store.implementation());
        assert_eq!(
            read.references.as_ref(),
            input.declarations(),
            "{} historical selections",
            store.implementation()
        );
        assert_eq!(
            read.debits.len(),
            input.debits().len(),
            "{} vintage count",
            store.implementation()
        );
        for (actual, expected) in read.debits.iter().zip(input.debits()) {
            assert_eq!(actual.key.as_ref(), &expected.key, "{} vintage key", store.implementation());
            assert_eq!(actual.bytes, expected.bytes, "{} vintage bytes", store.implementation());
        }
    }
}

fn read_conformance<A: Contract>() {
    let first = crate::admitted_carrier_tests::first_carrier();
    let later = crate::admitted_carrier_tests::shared_carrier();
    let mut store = seeded::<A>(first);
    assert_eq!(store.public_commit(first), Ok(true));
    assert_retained(&store, first);
    read_limits(&store, first);
    corrupt_counts::<A>(&store, first);
    // Reverse declaration order reaches append unsorted; no sorting shortcut.
    for use_ in later.declarations().iter().rev() {
        let snapshot = store.snapshot();
        let prior = snapshot
            .0
            .get(&(use_.version.family, use_.version.key.clone()))
            .and_then(|v| v.last())
            .filter(|row| row.version.edition != use_.version.edition)
            .map(|row| Predecessor {
                edition: row.version.edition.clone(),
                closes_at: use_.version.opens_at,
            });
        assert!(store.append(use_.version.clone(), prior.as_ref()).is_ok());
    }
    assert_eq!(store.public_commit(later), Ok(true));
    assert_retained(&store, first);
    assert_retained(&store, later);
    read_limits(&store, later);
    corrupt_counts::<A>(&store, later);
    let reference = first
        .declarations()
        .iter()
        .find(|u| u.version.family == Family::Rule)
        .unwrap();
    let mut successor = reference.version.clone();
    successor.opens_at = later.event().boundary + 1;
    successor.edition = "read-future".into();
    successor.payload = Some(crate::storage::Payload::rule(&pn_interchange::Value::Bool(true)).unwrap());
    let prior = Predecessor {
        edition: reference.version.edition.clone(),
        closes_at: successor.opens_at,
    };
    assert_eq!(store.append(successor, Some(&prior)), Ok(true));
    assert_retained(&store, first);
    assert_retained(&store, later);
    read_boundaries(&store, first, later);
}

fn read_boundaries<A: Contract>(store: &A, first: &AdmittedEpoch, later: &AdmittedEpoch) {
    let budget = ReadBudget {
        bytes: usize::MAX,
        rows: usize::MAX,
    };
    let mut key = first.event().clone();
    key.boundary = 0;
    assert_eq!(
        store.as_of(&key, budget),
        Ok(None),
        "{} before opening",
        store.implementation()
    );
    for (at, expected) in [
        (first.event().boundary, first),
        (later.event().boundary, later),
        (later.event().boundary + 1, later),
    ] {
        key.boundary = at;
        let read = store.as_of(&key, budget).unwrap().unwrap();
        assert_eq!(
            read.event.as_ref(),
            expected.event(),
            "{} as-of boundary {at}",
            store.implementation()
        );
        assert_eq!(
            read.predecessor.as_deref(),
            if expected.event() == first.event() {
                None
            } else {
                Some(first.event())
            }
        );
    }
    assert_eq!(
        store.read(&key, budget),
        Ok(None),
        "{} no synthesized event",
        store.implementation()
    );
    key.scope.history.push_str("-absent");
    assert_eq!(
        store.as_of(&key, budget),
        Ok(None),
        "{} scope isolation",
        store.implementation()
    );
}

fn read_limits<A: Contract>(store: &A, input: &AdmittedEpoch) {
    let (expected, used) = store.measured_read(
        input.event(),
        ReadBudget {
            bytes: usize::MAX,
            rows: usize::MAX,
        },
    );
    assert!(expected.as_ref().unwrap().is_some());
    let exact = ReadBudget {
        bytes: used.allocated,
        rows: used.visited,
    };
    assert_eq!(
        store.read(input.event(), exact),
        expected,
        "{} exact budget",
        store.implementation()
    );
    for budget in [
        ReadBudget {
            bytes: exact.bytes - 1,
            ..exact
        },
        ReadBudget {
            rows: exact.rows - 1,
            ..exact
        },
        ReadBudget { rows: 0, ..exact },
        ReadBudget { bytes: 0, ..exact },
    ] {
        let (result, meter) = store.measured_read(input.event(), budget);
        assert_eq!(
            result,
            Err(StorageError::ReadLimit),
            "{} under-budget cause",
            store.implementation()
        );
        assert!(
            meter.allocated <= budget.bytes,
            "{} allocation crossed budget",
            store.implementation()
        );
        assert!(meter.visited <= budget.rows, "{} walk crossed budget", store.implementation());
    }
}

fn corrupt_counts<A: Contract>(store: &A, input: &AdmittedEpoch) {
    for kind in 0..10 {
        let (history, mut state) = store.snapshot();
        let row = state.results.get_mut(input.event()).unwrap();
        match kind {
            0 => row.bytes += 1,
            1 => row.chunk_count += 1,
            2 => row.reference_count += 1,
            3 => row.debit_count += 1,
            4 => state.debits.values_mut().next().unwrap().bytes += 1,
            5 => state.debits.values_mut().next().unwrap().chunk_count += 1,
            6 => row.chunks[0].clear(),
            7 => {
                state.debits.remove(&row.membership[0]);
            }
            8 => row.references.swap(0, 1),
            _ => row.membership[1] = row.membership[0].clone(),
        }
        let broken = A::from_snapshot((history, state));
        let budget = ReadBudget {
            bytes: usize::MAX,
            rows: usize::MAX,
        };
        assert_eq!(
            broken.read(input.event(), budget),
            Err(StorageError::CorruptHistory),
            "{} corrupt count {kind}",
            broken.implementation()
        );
        assert_eq!(
            broken.as_of(input.event(), budget),
            Err(StorageError::CorruptHistory),
            "{} corrupt as-of count {kind}",
            broken.implementation()
        );
    }
}
