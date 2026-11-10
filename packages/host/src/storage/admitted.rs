//! Atomic memory projection of the admitted-result contract.
//! (´[ROOT-amend:storage:admitted-transaction]´)
use super::{
    AdmittedEpoch, DebitKey, DeclarationUse, EpochKey, History, MAX_PACKAGE, MemoryStore, StorageError, TransactionMeter,
    classified, verify_row,
};
use std::borrow::Cow;
use std::collections::BTreeMap;

/// Explicit reconstruction limits; no production allowance is implied.
/// Bytes bound cumulative requested heap bytes for reconstruction, rows bound fetched rows.
/// Index lookup and observation are outside reconstruction accounting.
/// (´[ROOT-amend:storage:admitted-reads]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadBudget {
    pub bytes: usize,
    pub rows: usize,
}

/// Retained public debit encoding, not a newly checked numerical value.
/// (´[ROOT-amend:storage:admitted-reads]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedDebit<'a> {
    pub key: Cow<'a, DebitKey>,
    pub bytes: Vec<u8>,
}

/// A retained read is public evidence, never an admitted capability.
/// Memory borrows immutable identities and selections; another store may own them.
/// (´[ROOT-amend:storage:admitted-reads]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRead<'a> {
    pub event: Cow<'a, EpochKey>,
    pub predecessor: Option<Cow<'a, EpochKey>>,
    pub bytes: Vec<u8>,
    pub references: Cow<'a, [DeclarationUse]>,
    pub debits: Vec<RetainedDebit<'a>>,
}

#[derive(Default)]
struct ReadMeter {
    rows: usize,
    bytes: usize,
    visited: usize,
    allocated: usize,
}
impl ReadMeter {
    fn row<T>(&mut self, limit: ReadBudget, fetch: impl FnOnce() -> T) -> Result<T, StorageError> {
        self.rows = self.rows.checked_add(1).ok_or(StorageError::ReadLimit)?;
        if self.rows > limit.rows {
            return Err(StorageError::ReadLimit);
        }
        self.visited += 1;
        Ok(fetch())
    }
    fn allocation(&mut self, bytes: usize, limit: ReadBudget) -> Result<(), StorageError> {
        self.bytes = self.bytes.checked_add(bytes).ok_or(StorageError::ReadLimit)?;
        if self.bytes > limit.bytes {
            return Err(StorageError::ReadLimit);
        }
        self.allocated += bytes;
        Ok(())
    }
}

fn read_chunks(
    parts: &[Vec<u8>],
    count: usize,
    bytes: usize,
    budget: ReadBudget,
    meter: &mut ReadMeter,
) -> Result<Vec<u8>, StorageError> {
    if count != parts.len() || bytes == 0 || bytes.div_ceil(MAX_PACKAGE) != count {
        return Err(StorageError::CorruptHistory);
    }
    if count > budget.rows.saturating_sub(meter.rows) || bytes > budget.bytes.saturating_sub(meter.bytes) {
        return Err(StorageError::ReadLimit);
    }
    meter.allocation(bytes, budget)?;
    let mut output = Vec::with_capacity(bytes);
    for (index, part) in parts.iter().enumerate() {
        let part = meter.row(budget, || part)?;
        if part.is_empty()
            || part.len() > MAX_PACKAGE
            || (index + 1 < count && part.len() != MAX_PACKAGE)
            || part.len() > bytes.saturating_sub(output.len())
        {
            return Err(StorageError::CorruptHistory);
        }
        output.extend_from_slice(part);
    }
    if output.len() != bytes {
        return Err(StorageError::CorruptHistory);
    }
    Ok(output)
}

fn selected(history: &History, uses: &[DeclarationUse]) -> Result<(), StorageError> {
    for use_ in uses {
        let expected = &use_.version;
        let rows = history
            .get(&(expected.family, expected.key.clone()))
            .ok_or(StorageError::MissingSelectedVersion)?;
        let row = rows
            .iter()
            .find(|row| row.version.edition == expected.edition)
            .ok_or(StorageError::MissingSelectedVersion)?;
        if row.version.payload.is_none() {
            return Err(StorageError::MissingSelectedVersion);
        }
        if row.version != *expected {
            return Err(StorageError::SelectedContentMismatch);
        }
        verify_row(row)?;
        let active: Vec<_> = rows
            .iter()
            .filter(|row| row.version.opens_at <= use_.selected_at && row.closes_at.is_none_or(|end| use_.selected_at < end))
            .collect();
        if active.len() > 1 {
            return Err(StorageError::CorruptHistory);
        }
        if active.first().is_none_or(|actual| actual.version.edition != expected.edition) {
            return Err(StorageError::SelectedVersionNotEffective);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct State {
    results: BTreeMap<EpochKey, ResultRow>,
    debits: BTreeMap<DebitKey, DebitRow>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ResultRow {
    predecessor: Option<EpochKey>,
    bytes: usize,
    chunk_count: usize,
    reference_count: usize,
    debit_count: usize,
    chunks: Vec<Vec<u8>>,
    references: Vec<DeclarationUse>,
    membership: Vec<DebitKey>,
    bindings: Vec<pn_epoch::publication::disclosures::Binding>,
    markers: Vec<pn_epoch::publication::disclosures::Marker>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct DebitRow {
    bytes: usize,
    chunk_count: usize,
    chunks: Vec<Vec<u8>>,
}
// Each event names a concrete relational write, including every chunk.
// The test adapter can map these boundaries to its PostgreSQL transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Write {
    Result,
    PackageChunk(usize),
    Reference(usize),
    Debit(DebitKey),
    DebitChunk(DebitKey, usize),
    Membership(usize),
}
fn chunks(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes.chunks(MAX_PACKAGE).map(<[u8]>::to_vec).collect()
}
fn complete(chunks: &[Vec<u8>], count: usize, bytes: usize) -> Result<Vec<u8>, StorageError> {
    if chunks.len() != count
        || chunks.iter().any(|part| part.is_empty() || part.len() > MAX_PACKAGE)
        || chunks
            .iter()
            .take(count.saturating_sub(1))
            .any(|part| part.len() != MAX_PACKAGE)
        || chunks.iter().try_fold(0usize, |sum, part| sum.checked_add(part.len())) != Some(bytes)
    {
        return Err(StorageError::CorruptHistory);
    }
    Ok(chunks.concat())
}
impl State {
    fn equal(&self, row: &ResultRow, input: &AdmittedEpoch) -> Result<bool, StorageError> {
        let bytes = complete(&row.chunks, row.chunk_count, row.bytes)?;
        if row.references.len() != row.reference_count || row.membership.len() != row.debit_count {
            return Err(StorageError::CorruptHistory);
        }
        let mut vintages = Vec::new();
        for key in &row.membership {
            let debit = self.debits.get(key).ok_or(StorageError::CorruptHistory)?;
            vintages.push((key, complete(&debit.chunks, debit.chunk_count, debit.bytes)?));
        }
        Ok(bytes == input.bytes()
            && row.references == input.declarations()
            && vintages == input.debits().iter().map(|v| (&v.key, v.bytes.clone())).collect::<Vec<_>>()
            && row.bindings == input.prefix().0
            && row.markers == input.prefix().1)
    }
    fn predecessor(&self, input: &AdmittedEpoch) -> Result<Option<EpochKey>, StorageError> {
        let key = input.event();
        if key.boundary == 1 {
            return Ok(None);
        }
        let prior = EpochKey {
            scope: key.scope.clone(),
            boundary: key.boundary - 1,
        };
        let row = self.results.get(&prior).ok_or(StorageError::Predecessor)?;
        if !input.prefix().0.starts_with(&row.bindings) || !input.prefix().1.starts_with(&row.markers) {
            return Err(StorageError::EpochConflict);
        }
        Ok(Some(prior))
    }
    fn validate(&self, history: &History, input: &AdmittedEpoch) -> Result<Option<EpochKey>, StorageError> {
        let prior = self.predecessor(input)?;
        selected(history, input.declarations())?;
        for vintage in input.debits() {
            if let Some(row) = self.debits.get(&vintage.key)
                && complete(&row.chunks, row.chunk_count, row.bytes)? != vintage.bytes
            {
                return Err(StorageError::DebitConflict);
            }
        }
        Ok(prior)
    }
    pub(super) fn guard(&self, history: &History) -> Result<(), StorageError> {
        for result in self.results.values() {
            selected(history, &result.references).map_err(|_| StorageError::HistoricalSelectionConflict)?;
        }
        Ok(())
    }
}
impl MemoryStore {
    /// Read one retained event without decoding or re-admitting its package.
    /// (´[ROOT-amend:storage:admitted-reads]´)
    /// # Errors
    /// Refuses reconstruction beyond the explicit budget, or inconsistent retained rows.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::admitted::MemoryStore::read_admitted_epoch"
        ),
        ret
    )]
    pub fn read_admitted_epoch(&self, key: &EpochKey, budget: ReadBudget) -> Result<Option<EpochRead<'_>>, StorageError> {
        let result = self.read_epoch_inner(key, budget, &mut ReadMeter::default());
        classified(result)
    }

    fn read_epoch_inner(
        &self,
        key: &EpochKey,
        budget: ReadBudget,
        meter: &mut ReadMeter,
    ) -> Result<Option<EpochRead<'_>>, StorageError> {
        let Some((event, row)) = self.admitted.results.get_key_value(key) else {
            return Ok(None);
        };
        let row = meter.row(budget, || row)?;
        let valid_predecessor = match &row.predecessor {
            None => event.boundary == 1,
            Some(prior) => {
                prior.scope == event.scope
                    && prior.boundary.checked_add(1) == Some(event.boundary)
                    && self.admitted.results.contains_key(prior)
            }
        };
        if !valid_predecessor {
            return Err(StorageError::CorruptHistory);
        }
        if row.references.len() != row.reference_count
            || row.membership.len() != row.debit_count
            || row.chunks.len() != row.chunk_count
        {
            return Err(StorageError::CorruptHistory);
        }
        let minimum_rows = row
            .reference_count
            .checked_add(row.debit_count)
            .and_then(|n| n.checked_add(row.chunk_count))
            .ok_or(StorageError::CorruptHistory)?;
        if minimum_rows > budget.rows.saturating_sub(meter.rows) || row.bytes > budget.bytes.saturating_sub(meter.bytes) {
            return Err(StorageError::ReadLimit);
        }
        let bytes = read_chunks(&row.chunks, row.chunk_count, row.bytes, budget, meter)?;
        let mut previous = None;
        for reference in &row.references {
            let reference = meter.row(budget, || reference)?;
            let expected = &reference.version;
            let ordinal = (expected.family, &expected.key, &expected.edition, reference.selected_at);
            if previous.is_some_and(|prior| prior >= ordinal) {
                return Err(StorageError::CorruptHistory);
            }
            previous = Some(ordinal);
            meter.allocation(expected.key.len(), budget)?;
            let versions = self
                .history
                .get(&(expected.family, expected.key.clone()))
                .ok_or(StorageError::CorruptHistory)?;
            // The stored opening coordinate locates the immutable version, not
            // the latest declaration. Effective histories are ordered by opening.
            let mut found = None;
            let mut low = 0;
            let mut high = versions.len();
            while low < high {
                let middle = low + (high - low) / 2;
                let candidate = meter.row(budget, || &versions[middle])?;
                match candidate.version.opens_at.cmp(&expected.opens_at) {
                    std::cmp::Ordering::Less => low = middle + 1,
                    std::cmp::Ordering::Greater => high = middle,
                    std::cmp::Ordering::Equal => {
                        found = Some(candidate);
                        break;
                    }
                }
            }
            let actual = found.ok_or(StorageError::CorruptHistory)?;
            if actual.version != *expected
                || actual.version.opens_at > reference.selected_at
                || actual.closes_at.is_some_and(|end| reference.selected_at >= end)
            {
                return Err(StorageError::CorruptHistory);
            }
            // Expected payloads came from the admitted carrier and cannot be
            // mutated through the public store. Equality checks all bytes; the
            // original digest is checked without allocating a decoded value.
            let payload = actual.version.payload.as_ref().ok_or(StorageError::CorruptHistory)?;
            if payload.digest != super::digest(super::PAYLOAD_RECIPE, &payload.bytes) {
                return Err(StorageError::CorruptHistory);
            }
        }
        let capacity = row
            .debit_count
            .checked_mul(std::mem::size_of::<RetainedDebit<'_>>())
            .ok_or(StorageError::CorruptHistory)?;
        meter.allocation(capacity, budget)?;
        let mut debits = Vec::with_capacity(row.debit_count);
        let mut previous = None;
        for key in &row.membership {
            let key = meter.row(budget, || key)?;
            if key.scope != event.scope || previous.is_some_and(|prior| prior >= key) {
                return Err(StorageError::CorruptHistory);
            }
            previous = Some(key);
            let debit = meter
                .row(budget, || self.admitted.debits.get(key))?
                .ok_or(StorageError::CorruptHistory)?;
            let bytes = read_chunks(&debit.chunks, debit.chunk_count, debit.bytes, budget, meter)?;
            debits.push(RetainedDebit {
                key: Cow::Borrowed(key),
                bytes,
            });
        }
        Ok(Some(EpochRead {
            event: Cow::Borrowed(event),
            predecessor: row.predecessor.as_ref().map(Cow::Borrowed),
            bytes,
            references: Cow::Borrowed(&row.references),
            debits,
        }))
    }

    /// Read the last retained event at or before the requested boundary in one scope.
    /// (´[ROOT-amend:storage:admitted-reads]´)
    /// # Errors
    /// Refuses reconstruction beyond the explicit budget, or inconsistent retained rows.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::admitted::MemoryStore::read_admitted_as_of"
        ),
        ret
    )]
    pub fn read_admitted_as_of(&self, key: &EpochKey, budget: ReadBudget) -> Result<Option<EpochRead<'_>>, StorageError> {
        let result = match self.admitted.results.range(..=key).next_back() {
            Some((event, _)) if event.scope == key.scope => self.read_epoch_inner(event, budget, &mut ReadMeter::default()),
            _ => Ok(None),
        };
        classified(result)
    }

    /// Commit one complete admitted event, or recognize an equal retry without writes.
    /// (´[ROOT-amend:storage:admitted-transaction]´)
    /// # Errors
    /// Refuses missing or mismatched selections, invalid succession, or conflicting content/vintages.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::admitted::MemoryStore::commit_admitted_epoch"
        ),
        ret
    )]
    pub fn commit_admitted_epoch(&mut self, input: &AdmittedEpoch) -> Result<bool, StorageError> {
        let result = self.commit_epoch_inner(input, &mut |_| Ok(()));
        classified(result)
    }
    fn commit_epoch_inner(
        &mut self,
        input: &AdmittedEpoch,
        boundary: &mut impl FnMut(Write) -> Result<(), StorageError>,
    ) -> Result<bool, StorageError> {
        if let Some(row) = self.admitted.results.get(input.event()) {
            return if self.admitted.equal(row, input)? {
                Ok(false)
            } else {
                Err(StorageError::EpochConflict)
            };
        }
        let predecessor = self.admitted.validate(&self.history, input)?;
        let mut next = self.admitted.clone();
        let mut meter = TransactionMeter::new();
        let package_chunks = chunks(input.bytes());
        let row = ResultRow {
            predecessor,
            bytes: input.bytes().len(),
            chunk_count: package_chunks.len(),
            reference_count: input.declarations().len(),
            debit_count: input.debits().len(),
            chunks: Vec::new(),
            references: Vec::new(),
            membership: Vec::new(),
            bindings: input.prefix().0.to_vec(),
            markers: input.prefix().1.to_vec(),
        };
        next.results.insert(input.event().clone(), row);
        boundary(Write::Result)?;
        let row = next.results.get_mut(input.event()).ok_or(StorageError::CorruptHistory)?;
        for (i, chunk) in package_chunks.into_iter().enumerate() {
            row.chunks.push(chunk);
            boundary(Write::PackageChunk(i))?;
        }
        for (i, reference) in input.declarations().iter().enumerate() {
            row.references.push(reference.clone());
            boundary(Write::Reference(i))?;
        }
        for vintage in input.debits() {
            if next.debits.contains_key(&vintage.key) {
                continue;
            }
            let parts = chunks(&vintage.bytes);
            let row = DebitRow {
                bytes: vintage.bytes.len(),
                chunk_count: parts.len(),
                chunks: Vec::new(),
            };
            next.debits.insert(vintage.key.clone(), row);
            boundary(Write::Debit(vintage.key.clone()))?;
            let row = next.debits.get_mut(&vintage.key).ok_or(StorageError::CorruptHistory)?;
            for (i, chunk) in parts.into_iter().enumerate() {
                row.chunks.push(chunk);
                boundary(Write::DebitChunk(vintage.key.clone(), i))?;
            }
        }
        let row = next.results.get_mut(input.event()).ok_or(StorageError::CorruptHistory)?;
        for (i, vintage) in input.debits().iter().enumerate() {
            row.membership.push(vintage.key.clone());
            boundary(Write::Membership(i))?;
        }
        if !next.equal(next.results.get(input.event()).ok_or(StorageError::CorruptHistory)?, input)? {
            return Err(StorageError::CorruptHistory);
        }
        self.admitted = next;
        meter.commit();
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
