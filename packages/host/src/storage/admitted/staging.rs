//! The staged write is its interruption boundary, not a paired caller convention.
//! (´[ROOT-amend:storage:admitted-transaction]´)
use super::{AdmittedEpoch, DebitKey, DebitRow, DeclarationUse, EpochKey, ResultRow, State, StorageError, Write};

pub(super) enum Mutation {
    Result(ResultRow),
    PackageChunk(Vec<u8>),
    Reference(DeclarationUse),
    Debit(DebitKey, DebitRow),
    DebitChunk(DebitKey, Vec<u8>),
    Membership(DebitKey),
}

// No mutable state accessor exists. Callers can apply a write or publish the
// complete verified stage, but cannot add a write around the boundary primitive.
pub(super) struct Stage {
    state: State,
    event: EpochKey,
}

impl Stage {
    pub(super) fn new(prior: &State, event: &EpochKey) -> Self {
        Self {
            state: prior.clone(),
            event: event.clone(),
        }
    }

    pub(super) fn write(
        &mut self,
        value: Mutation,
        boundary: &mut impl FnMut(Write) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let point = match value {
            Mutation::Result(row) => {
                self.state.results.insert(self.event.clone(), row);
                Write::Result
            }
            Mutation::PackageChunk(bytes) => {
                let row = self.state.results.get_mut(&self.event).ok_or(StorageError::CorruptHistory)?;
                let index = row.chunks.len();
                row.chunks.push(bytes);
                Write::PackageChunk(index)
            }
            Mutation::Reference(reference) => {
                let row = self.state.results.get_mut(&self.event).ok_or(StorageError::CorruptHistory)?;
                let index = row.references.len();
                row.references.push(reference);
                Write::Reference(index)
            }
            Mutation::Debit(key, row) => {
                self.state.debits.insert(key.clone(), row);
                Write::Debit(key)
            }
            Mutation::DebitChunk(key, bytes) => {
                let row = self.state.debits.get_mut(&key).ok_or(StorageError::CorruptHistory)?;
                let index = row.chunks.len();
                row.chunks.push(bytes);
                Write::DebitChunk(key, index)
            }
            Mutation::Membership(key) => {
                let row = self.state.results.get_mut(&self.event).ok_or(StorageError::CorruptHistory)?;
                let index = row.membership.len();
                row.membership.push(key);
                Write::Membership(index)
            }
        };
        boundary(point)
    }

    pub(super) fn publish(self, target: &mut State, input: &AdmittedEpoch) -> Result<(), StorageError> {
        let row = self.state.results.get(&self.event).ok_or(StorageError::CorruptHistory)?;
        if !self.state.equal(row, input)? {
            return Err(StorageError::CorruptHistory);
        }
        *target = self.state;
        Ok(())
    }
}
