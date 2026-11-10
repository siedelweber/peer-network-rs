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
}
impl Contract for MemoryStore {
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
