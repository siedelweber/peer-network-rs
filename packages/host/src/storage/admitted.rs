//! Atomic memory projection of the admitted-result contract.
//! (´[ROOT-amend:storage:admitted-transaction]´)
use super::{
    AdmittedEpoch, DebitKey, DeclarationUse, EpochKey, History, MAX_PACKAGE, MemoryStore, StorageError, TransactionMeter,
    classified, verify_row,
};
use std::collections::BTreeMap;

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
