//! Closed server reads on one caller-owned snapshot and cumulative allowance.
//! (´[ROOT-amend:storage:admitted-reads]´)

use std::fmt::Write;

use super::super::{DISCLOSURE_RECIPE, Family, PAYLOAD_RECIPE, Payload, Version, digest};
use super::super::{Session, Statement, StatementParameter, StatementRow, StatementTransaction, catalogue, observed};
use super::{EpochScope, Error, Generation, Identity, Meter, Page, Range, ReadBudget, StorageError, Usage, fields, scope_check};
use crate::admitted_result::DeclarationUse;

mod content;
mod generation;
mod projection;
mod spans;
#[cfg(test)]
mod tests;

/// A verified tree catalogue, without a result-write capability.
/// (´[ROOT-amend:storage:admitted-layout]´)
#[derive(Debug)]
pub struct ServerTree {
    session: Session,
    #[cfg(test)]
    generation_hook: generation::Hook,
}

impl ServerTree {
    /// Verify the exact catalogue before exposing its closed reader.
    /// (´[ROOT-amend:storage:admitted-layout]´)
    /// # Errors
    /// Refuses another catalogue or a transport failure, without repairing an occupied store.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerTree::open",
            asynchronous = true
        ),
        ret
    )]
    pub async fn open(mut session: Session) -> Result<Self, StorageError> {
        catalogue::open(&mut session).await?;
        Ok(Self {
            session,
            #[cfg(test)]
            generation_hook: generation::Hook::default(),
        })
    }

    /// Begin a read-only repeatable snapshot with an explicit allowance.
    /// (´[ROOT-amend:storage:admitted-reads]´)
    /// # Errors
    /// Refuses a transport failure before any tree read.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerTree::reader",
            asynchronous = true
        ),
        ret
    )]
    pub async fn reader(&mut self, budget: ReadBudget) -> Result<ServerReader<'_>, Error> {
        let transaction = self.session.client.snapshot(self.session.store_requests.clone()).await?;
        Ok(ServerReader {
            transaction,
            first_refusal: None,
            meter: Meter {
                limit: budget,
                used: Usage::default(),
            },
        })
    }

    /// Install one explicit first admission generation in a locked atomic transaction.
    /// (´[ROOT-amend:storage:admitted-transaction]´)
    /// # Errors
    /// Refuses invalid input, damaged retained rows, allowance exhaustion or a wrapped request failure.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerTree::install_generation",
            asynchronous = true
        ),
        ret
    )]
    pub async fn install_generation(&mut self, input: &Generation, budget: ReadBudget, usage: &mut Usage) -> Result<bool, Error> {
        generation::install(self, input, budget, usage).await
    }
}

/// A borrowed server snapshot; every page shares this reader's cumulative meter.
/// Delivery reservations cover bounded binary `DataRow` bodies, not relay frames or driver bookkeeping.
/// (´[ROOT-amend:storage:admitted-reads]´)
pub struct ServerReader<'a> {
    transaction: StatementTransaction<'a>,
    meter: Meter,
    first_refusal: Option<Error>,
}

/// A complete retained selection and its original judgement's result identity.
/// (´[ROOT-amend:storage:admitted-reads]´)
#[derive(Debug, PartialEq, Eq)]
pub struct ServerSelection {
    pub use_: DeclarationUse,
    pub origin: Identity,
}

/// Exact retained debit bytes and their unique introduction on the selected ancestor path.
/// (´[ROOT-amend:storage:admitted-reads]´)
#[derive(Debug, PartialEq, Eq)]
pub struct ServerDebit {
    pub act: pn_records::ActId,
    pub origin: Identity,
    pub writing_boundary: u64,
    pub bytes: Vec<u8>,
}

/// Untrusted retained public evidence, validated for storage consistency without granting admission.
/// (´[ROOT-amend:storage:admitted-reads]´)
#[derive(Debug, PartialEq, Eq)]
pub struct ServerResult {
    pub identity: Identity,
    pub parent: Option<Identity>,
    pub depth: u64,
    pub label: String,
    pub generation: u64,
    pub bytes: Vec<u8>,
    pub selections: Vec<ServerSelection>,
    pub debits: Vec<ServerDebit>,
}

impl std::fmt::Debug for ServerReader<'_> {
    /// Summarize only public usage counters, never the session or its capabilities.
    /// (´[ROOT-amend:storage:admitted-reads]´)
    /// Justified: Formatting inherits the reader's bounded operation observation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerReader")
            .field("usage", &self.meter.used)
            .finish_non_exhaustive()
    }
}

impl ServerReader<'_> {
    fn record<T>(&mut self, result: &Result<T, Error>) {
        if let Err(error) = result
            && self.first_refusal.is_none()
            && !self.transaction.state.retired()
        {
            self.first_refusal = Some(*error);
        }
    }

    /// End the snapshot with one wrapped commit or explicit cleanup rollback.
    /// (´[ROOT-amend:storage:relay-termination]´)
    /// # Errors
    /// Retains the first store-decided read refusal, or reports the ending refusal.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerReader < '_ >::end",
            asynchronous = true
        ),
        ret
    )]
    pub async fn end(self) -> Result<(), Error> {
        if let Some(primary) = self.first_refusal {
            Err(self.transaction.refuse(primary).await)
        } else {
            self.transaction.commit().await.map_err(Into::into)
        }
    }
    /// Observe admitted work, including reservations retained on refusal.
    /// (´[ROOT-amend:storage:admitted-reads]´)
    /// Justified: Counter observation inherits the enclosing read operation and performs no storage work.
    #[must_use]
    pub fn usage(&self) -> Usage {
        self.meter.used
    }

    /// Read one retained identity without granting an admitted-package capability.
    /// (´[ROOT-amend:storage:admitted-reads]´)
    /// # Errors
    /// Refuses malformed scope, corrupt retained consistency, transport failure or a cumulative limit.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerReader < '_ >::exact",
            asynchronous = true
        ),
        ret
    )]
    pub async fn exact(&mut self, scope: &EpochScope, identity: Identity) -> Result<Option<ServerResult>, Error> {
        let result = async {
            scope_check(scope)?;
            let key = Self::scope(scope)?;
            let key = key.text()?;
            // The initial bounded existence exception reserves only its boolean delivery.
            self.meter.allocation(7)?;
            #[cfg(test)]
            tests::fetched();
            let rows = observed(self.transaction.query(Statement::HasEpoch, &[&key, &&identity[..]])).await?;
            if rows.len() != 1 {
                return Err(StorageError::CorruptHistory.into());
            }
            let exists: bool = rows[0].try_get(0).map_err(|_| StorageError::CorruptHistory)?;
            if !exists {
                return Ok(None);
            }
            let header = self.header(key, identity).await?;
            let result = self.reconstruct(scope, key, header).await?;
            Ok(Some(result))
        }
        .await;
        self.record(&result);
        result
    }

    /// Resolve a depth only on the named tip's ancestor path, clamping at the tip.
    /// (´[ROOT-amend:storage:tree-branches]´)
    /// # Errors
    /// Refuses malformed requests, an absent tip, corrupt retained consistency, transport failure or a limit.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerReader < '_ >::as_of",
            asynchronous = true
        ),
        ret
    )]
    pub async fn as_of(&mut self, scope: &EpochScope, tip: Identity, depth: u64) -> Result<Option<ServerResult>, Error> {
        let result = async {
            scope_check(scope)?;
            i64::try_from(depth).map_err(|_| StorageError::Representation)?;
            let key = Self::scope(scope)?;
            let key = key.text()?;
            let rows = self.request(Statement::ReadEpoch, &[&key, &&tip[..]], 1, 278, false).await?;
            let tip = Header::read(rows.first().ok_or(Error::MissingTip)?)?;
            let ranges = self.ranges(key, &tip).await?;
            let depth = depth.min(tip.depth);
            let Some(range) = ranges.iter().find(|range| range.start <= depth && depth <= range.end) else {
                return Ok(None);
            };
            let ceiling = i64::try_from(depth).map_err(|_| StorageError::Representation)?;
            let rows = self
                .request(
                    Statement::ReadEpochAsOf,
                    &[&key, &&range.segment[..], &ceiling],
                    1,
                    278,
                    false,
                )
                .await?;
            let header = Header::read(rows.first().ok_or(StorageError::CorruptHistory)?)?;
            if header.segment != range.segment || header.depth != depth {
                return Err(StorageError::CorruptHistory.into());
            }
            let result = self.reconstruct(scope, key, header).await?;
            Ok(Some(result))
        }
        .await;
        self.record(&result);
        result
    }

    async fn reconstruct(&mut self, scope: &EpochScope, key: &str, header: Header) -> Result<ServerResult, Error> {
        let label = self.generation(key, header.generation).await?;
        let ranges = self.ranges(key, &header).await?;
        let bytes = self.package(key, &header).await?;
        let validated = spans::Validated::new(&bytes, &mut self.meter)?;
        let selections = self.selections(key, &header, &ranges).await?;
        let debits = self.debits(key, &header, &ranges).await?;
        projection::validate(scope, &header, &validated, &selections, &debits, &mut self.meter)?;
        let rows = self.request(Statement::ReadScope, &[&key], 1, 50, false).await?;
        let root = identity(rows.first().ok_or(StorageError::CorruptHistory)?, 0, 1)?;
        let root_header = self.header(key, root).await?;
        if root_header.depth != 1 || root_header.parent.is_some() {
            return Err(StorageError::CorruptHistory.into());
        }
        let root_bytes = self.package(key, &root_header).await?;
        let root_value = spans::Validated::new(&root_bytes, &mut self.meter)?;
        projection::context(&validated, &root_value)?;
        if let Some(parent) = header.parent {
            let parent = self.header(key, parent).await?;
            if parent.depth.checked_add(1) != Some(header.depth) || Some(parent.segment) != header.parent_segment {
                return Err(StorageError::CorruptHistory.into());
            }
            self.generation(key, parent.generation).await?;
            let parent_bytes = self.package(key, &parent).await?;
            let parent_value = spans::Validated::new(&parent_bytes, &mut self.meter)?;
            projection::extends(&validated, &parent_value)?;
        }
        for debit in &debits {
            if debit.origin != header.identity {
                let origin = self.header(key, debit.origin).await?;
                let origin_bytes = self.package(key, &origin).await?;
                let origin_value = spans::Validated::new(&origin_bytes, &mut self.meter)?;
                projection::debit_origin(&origin_value, debit)?;
            }
        }
        Ok(ServerResult {
            identity: header.identity,
            parent: header.parent,
            depth: header.depth,
            label,
            generation: header.generation,
            bytes,
            selections,
            debits,
        })
    }

    async fn header(&mut self, scope: &str, identity: Identity) -> Result<Header, Error> {
        let rows = self
            .request(Statement::ReadEpoch, &[&scope, &&identity[..]], 1, 278, false)
            .await?;
        let row = rows.first().ok_or(StorageError::CorruptHistory)?;
        let header = Header::read(row)?;
        if header.identity != identity {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(header)
    }

    async fn ranges(&mut self, scope: &str, tip: &Header) -> Result<Vec<Range>, Error> {
        let mut segment = tip.segment;
        let mut cutoff = tip.depth;
        let mut ranges = Vec::new();
        loop {
            let rows = self
                .request(Statement::ReadBranch, &[&scope, &&segment[..]], 1, 170, false)
                .await?;
            let row = rows.first().ok_or(StorageError::CorruptHistory)?;
            let declared = identity(row, 0, 1)?;
            let start = positive(row, 2)?;
            let parent_segment = optional_identity(row, 3, 4)?;
            let fork = optional_identity(row, 5, 6)?;
            let fork_depth = unsigned(row, 7)?;
            let first = self.header(scope, segment).await?;
            if declared != segment
                || first.segment != segment
                || first.depth != start
                || first.parent != fork
                || first.parent_segment != parent_segment
                || start > cutoff
            {
                return Err(StorageError::CorruptHistory.into());
            }
            self.meter.reserve(&mut ranges, 1)?;
            ranges.push(Range {
                segment,
                start,
                end: cutoff,
            });
            match (parent_segment, fork) {
                (None, None) if start == 1 && fork_depth == 0 => break,
                (Some(parent_segment), Some(parent)) if fork_depth.checked_add(1) == Some(start) => {
                    let parent = self.header(scope, parent).await?;
                    if parent.segment != parent_segment || parent.depth != fork_depth {
                        return Err(StorageError::CorruptHistory.into());
                    }
                    segment = parent_segment;
                    cutoff = fork_depth;
                }
                _ => return Err(StorageError::CorruptHistory.into()),
            }
        }
        Ok(ranges)
    }

    async fn package(&mut self, scope: &str, header: &Header) -> Result<Vec<u8>, Error> {
        let count = usize::try_from(header.chunks).map_err(|_| StorageError::ReadLimit)?;
        let length = usize::try_from(header.bytes).map_err(|_| StorageError::ReadLimit)?;
        let limit = count.checked_add(1).ok_or(StorageError::ReadLimit)?;
        let parameter = i64::try_from(limit).map_err(|_| StorageError::ReadLimit)?;
        let mut output = Vec::new();
        self.meter.reserve(&mut output, length)?;
        let rows = self
            .request(
                Statement::ReadEpochChunks,
                &[&scope, &&header.identity[..], &parameter],
                limit,
                262_174,
                true,
            )
            .await?;
        if rows.len() != count {
            return Err(StorageError::CorruptHistory.into());
        }
        for (ordinal, row) in rows.iter().enumerate() {
            let part = bytes(row, 2, 1, 262_144)?;
            if unsigned(row, 0)? != ordinal as u64 || part.is_empty() || part.len() > length.saturating_sub(output.len()) {
                return Err(StorageError::CorruptHistory.into());
            }
            output.extend_from_slice(part);
        }
        if output.len() != length {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(output)
    }

    async fn generation(&mut self, scope: &str, ordinal: u64) -> Result<String, Error> {
        if ordinal != 1 {
            return Err(StorageError::CorruptHistory.into());
        }
        let rows = self
            .request(Statement::ReadAdmissionGeneration, &[&scope, &1_i64], 1, 1102, false)
            .await?;
        let row = rows.first().ok_or(StorageError::CorruptHistory)?;
        let previous: Option<i64> = row.try_get(1).map_err(|_| StorageError::CorruptHistory)?;
        let label = text(row, 5, 6, 1024)?;
        if positive(row, 0)? != ordinal || positive(row, 2)? != 1 || previous.is_some() || label != "unstable" {
            return Err(StorageError::CorruptHistory.into());
        }
        unsigned(row, 3)?;
        unsigned(row, 4)?;
        self.copy_text(label)
    }

    fn copy_text(&mut self, text: &str) -> Result<String, Error> {
        copy_text(&mut self.meter, text)
    }

    fn version(&mut self, row: &StatementRow, start: usize) -> Result<Version, Error> {
        decode_version(&mut self.meter, row, start)
    }
}

fn copy_text(meter: &mut Meter, text: &str) -> Result<String, Error> {
    meter.allocation(text.len())?;
    let mut output = String::with_capacity(text.len());
    output.push_str(text);
    Ok(output)
}

fn decode_version(meter: &mut Meter, row: &StatementRow, start: usize) -> Result<Version, Error> {
    let family = family(text(row, start, start + 1, 21)?)?;
    let key = copy_text(meter, text(row, start + 2, start + 3, 1024)?)?;
    let edition = copy_text(meter, text(row, start + 4, start + 5, 1024)?)?;
    let announced_at = unsigned(row, start + 6)?;
    let opens_at = unsigned(row, start + 7)?;
    if key.is_empty() || edition.is_empty() || announced_at > opens_at {
        return Err(StorageError::CorruptHistory.into());
    }
    let content = optional_bytes(row, start + 8, start + 9, 262_144)?;
    let stored_digest = optional_identity(row, start + 10, start + 11)?;
    let disclosure = optional_identity(row, start + 12, start + 13)?;
    let payload = match (content, stored_digest) {
        (None, None) if disclosure.is_none() => None,
        (Some(content), Some(stored_digest)) => {
            let validated = spans::Validated::new(content, meter)?;
            let envelope = validated.root()?.array(3)?;
            if envelope.field(0)?.text()? != PAYLOAD_RECIPE
                || envelope.field(1)?.text()? != family.name()
                || digest(PAYLOAD_RECIPE, content) != stored_digest
            {
                return Err(StorageError::CorruptHistory.into());
            }
            if family == Family::UnsettledRecognition {
                let body = envelope.field(2)?.array(4)?;
                let input = body.field(2)?;
                let expected = digest(DISCLOSURE_RECIPE, input.bytes());
                if body.field(0)?.text()? != DISCLOSURE_RECIPE
                    || body.field(1)?.blob()? != expected
                    || disclosure != Some(expected)
                {
                    return Err(StorageError::CorruptHistory.into());
                }
            } else if disclosure.is_some() {
                return Err(StorageError::CorruptHistory.into());
            }
            let mut bytes = Vec::new();
            meter.reserve(&mut bytes, content.len())?;
            bytes.extend_from_slice(content);
            Some(Payload {
                family,
                bytes,
                digest: stored_digest,
                disclosure,
            })
        }
        _ => return Err(StorageError::CorruptHistory.into()),
    };
    Ok(Version {
        family,
        key,
        edition,
        announced_at,
        opens_at,
        payload,
    })
}

impl ServerReader<'_> {
    fn selection(&mut self, row: &StatementRow) -> Result<ServerSelection, Error> {
        Ok(ServerSelection {
            use_: DeclarationUse {
                selected_at: unsigned(row, 0)?,
                version: self.version(row, 3)?,
            },
            origin: identity(row, 1, 2)?,
        })
    }

    async fn selections(&mut self, scope: &str, header: &Header, ranges: &[Range]) -> Result<Vec<ServerSelection>, Error> {
        let count = usize::try_from(header.references).map_err(|_| StorageError::ReadLimit)?;
        let limit = count.checked_add(1).ok_or(StorageError::ReadLimit)?;
        let parameter = i64::try_from(limit).map_err(|_| StorageError::ReadLimit)?;
        let rows = self
            .request(
                Statement::ReadEpochReferences,
                &[&scope, &&header.identity[..], &parameter],
                limit,
                264_459,
                true,
            )
            .await?;
        if rows.len() != count {
            return Err(StorageError::CorruptHistory.into());
        }
        let mut output = Vec::new();
        self.meter.reserve(&mut output, count)?;
        for row in &rows {
            let current = self.selection(row)?;
            if output
                .last()
                .is_some_and(|previous: &ServerSelection| sql_order(previous) >= sql_order(&current))
            {
                return Err(StorageError::CorruptHistory.into());
            }
            self.selection_origin(scope, header, ranges, &current).await?;
            output.push(current);
        }
        output.sort_unstable_by(|a, b| {
            (
                a.use_.version.family,
                &a.use_.version.key,
                &a.use_.version.edition,
                a.use_.selected_at,
            )
                .cmp(&(
                    b.use_.version.family,
                    &b.use_.version.key,
                    &b.use_.version.edition,
                    b.use_.selected_at,
                ))
        });
        Ok(output)
    }

    async fn use_at(&mut self, scope: &str, owner: Identity, wanted: &DeclarationUse) -> Result<ServerSelection, Error> {
        let coordinate = i64::try_from(wanted.selected_at).map_err(|_| StorageError::CorruptHistory)?;
        let version = &wanted.version;
        let rows = self
            .request(
                Statement::ReadEpochUse,
                &[&scope, &&owner[..], &coordinate, &version.family.name(), &version.key],
                1,
                264_459,
                false,
            )
            .await?;
        self.selection(rows.first().ok_or(StorageError::CorruptHistory)?)
    }

    async fn selection_origin(
        &mut self,
        scope: &str,
        header: &Header,
        ranges: &[Range],
        selected: &ServerSelection,
    ) -> Result<(), Error> {
        let version = &selected.use_.version;
        if selected.origin != header.identity {
            let origin = self.header(scope, selected.origin).await?;
            if !ranges
                .iter()
                .any(|range| range.segment == origin.segment && range.start <= origin.depth && origin.depth <= range.end)
            {
                return Err(StorageError::CorruptHistory.into());
            }
            self.generation(scope, origin.generation).await?;
            let original = self.use_at(scope, selected.origin, &selected.use_).await?;
            let parent = self
                .use_at(scope, header.parent.ok_or(StorageError::CorruptHistory)?, &selected.use_)
                .await?;
            if original != *selected || parent != *selected {
                return Err(StorageError::CorruptHistory.into());
            }
        }
        if super::unqualified(version.family) {
            self.effective(scope, &selected.use_).await?;
        } else if selected.origin != header.identity
            || version.opens_at != header.depth
            || version.announced_at != header.depth
            || selected.use_.selected_at != header.depth
        {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(())
    }

    async fn effective(&mut self, scope: &str, selected: &DeclarationUse) -> Result<(), Error> {
        let wanted = &selected.version;
        let mut versions = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let rows = self
                .request(
                    Statement::ReadAdmissionVersions,
                    &[&scope, &1_i64, &wanted.family.name(), &wanted.key, &cursor.as_deref(), &1_i64],
                    1,
                    264_411,
                    true,
                )
                .await?;
            let Some(row) = rows.first() else { break };
            if positive(row, 14)? != 1 {
                return Err(StorageError::CorruptHistory.into());
            }
            let version = self.version(row, 0)?;
            if version.family != wanted.family
                || version.key != wanted.key
                || cursor.as_ref().is_some_and(|prior| *prior >= version.edition)
            {
                return Err(StorageError::CorruptHistory.into());
            }
            cursor = Some(self.copy_text(&version.edition)?);
            self.meter.reserve(&mut versions, 1)?;
            versions.push((version, None));
        }
        cursor = None;
        loop {
            let rows = self
                .request(
                    Statement::ReadAdmissionClosures,
                    &[&scope, &1_i64, &wanted.family.name(), &wanted.key, &cursor.as_deref(), &1_i64],
                    1,
                    2143,
                    true,
                )
                .await?;
            let Some(row) = rows.first() else { break };
            let edition = text(row, 4, 5, 1024)?;
            if family(text(row, 0, 1, 21)?)? != wanted.family
                || text(row, 2, 3, 1024)? != wanted.key
                || positive(row, 7)? != 1
                || cursor.as_deref().is_some_and(|prior| prior >= edition)
            {
                return Err(StorageError::CorruptHistory.into());
            }
            let entry = versions
                .iter_mut()
                .find(|(version, _)| version.edition == edition)
                .ok_or(StorageError::CorruptHistory)?;
            if entry.1.replace(unsigned(row, 6)?).is_some() {
                return Err(StorageError::CorruptHistory.into());
            }
            cursor = Some(self.copy_text(edition)?);
        }
        versions.sort_unstable_by_key(|(version, _)| version.opens_at);
        for (index, (version, closes)) in versions.iter().enumerate() {
            let next = versions.get(index + 1);
            if *closes != next.map(|(version, _)| version.opens_at)
                || closes.is_some_and(|close| close <= version.opens_at)
                || next.is_some_and(|(next, _)| next.announced_at < version.announced_at)
            {
                return Err(StorageError::CorruptHistory.into());
            }
        }
        let mut matching = versions.iter().filter(|(version, close)| {
            version.opens_at <= selected.selected_at && close.is_none_or(|end| selected.selected_at < end)
        });
        let (version, _) = matching.next().ok_or(StorageError::CorruptHistory)?;
        if version != wanted || version.payload.is_none() || matching.next().is_some() {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(())
    }

    async fn debits(&mut self, scope: &str, header: &Header, ranges: &[Range]) -> Result<Vec<ServerDebit>, Error> {
        let count = usize::try_from(header.debits).map_err(|_| StorageError::ReadLimit)?;
        let limit = count.checked_add(1).ok_or(StorageError::ReadLimit)?;
        let parameter = i64::try_from(limit).map_err(|_| StorageError::ReadLimit)?;
        let mut output = Vec::new();
        self.meter.reserve(&mut output, count)?;
        for range in ranges {
            let start = i64::try_from(range.start).map_err(|_| StorageError::CorruptHistory)?;
            let end = i64::try_from(range.end).map_err(|_| StorageError::CorruptHistory)?;
            let rows = self
                .request(
                    Statement::ReadEpochDebitKeys,
                    &[&scope, &&range.segment[..], &start, &end, &parameter],
                    limit,
                    2178,
                    true,
                )
                .await?;
            if rows.len() > count.saturating_sub(output.len()) {
                return Err(StorageError::CorruptHistory.into());
            }
            let mut previous = None;
            for row in &rows {
                let origin = identity(row, 0, 1)?;
                let depth = positive(row, 2)?;
                let author = text(row, 3, 4, 1024)?;
                let sequence = text(row, 5, 6, 20)?;
                let family = text(row, 7, 8, 1024)?;
                let numeric_sequence = decimal(sequence)?;
                let order = (author, numeric_sequence, family, origin);
                if previous.is_some_and(|prior| prior >= order) {
                    return Err(StorageError::CorruptHistory.into());
                }
                previous = Some(order);
                let origin_header = self.header(scope, origin).await?;
                if origin_header.depth != depth
                    || origin_header.segment != range.segment
                    || depth < range.start
                    || depth > range.end
                {
                    return Err(StorageError::CorruptHistory.into());
                }
                let debit = self.debit(scope, origin, author, sequence, family).await?;
                output.push(debit);
            }
        }
        if output.len() != count {
            return Err(StorageError::CorruptHistory.into());
        }
        output.sort_unstable_by(|a, b| a.act.cmp(&b.act));
        if output.windows(2).any(|pair| pair[0].act == pair[1].act) {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(output)
    }

    async fn debit(
        &mut self,
        scope: &str,
        origin: Identity,
        author: &str,
        sequence: &str,
        family: &str,
    ) -> Result<ServerDebit, Error> {
        let rows = self
            .request(
                Statement::ReadDebit,
                &[&scope, &&origin[..], &author, &sequence, &family],
                1,
                38,
                false,
            )
            .await?;
        let row = rows.first().ok_or(StorageError::CorruptHistory)?;
        let writing_boundary = positive(row, 0)?;
        let length = usize::try_from(positive(row, 1)?).map_err(|_| StorageError::ReadLimit)?;
        let count = usize::try_from(positive(row, 2)?).map_err(|_| StorageError::ReadLimit)?;
        let limit = count.checked_add(1).ok_or(StorageError::ReadLimit)?;
        let parameter = i64::try_from(limit).map_err(|_| StorageError::ReadLimit)?;
        let mut output = Vec::new();
        self.meter.reserve(&mut output, length)?;
        let rows = self
            .request(
                Statement::ReadDebitChunks,
                &[&scope, &&origin[..], &author, &sequence, &family, &parameter],
                limit,
                262_174,
                true,
            )
            .await?;
        if rows.len() != count {
            return Err(StorageError::CorruptHistory.into());
        }
        for (ordinal, row) in rows.iter().enumerate() {
            let part = bytes(row, 2, 1, 262_144)?;
            if unsigned(row, 0)? != ordinal as u64 || part.is_empty() || part.len() > length.saturating_sub(output.len()) {
                return Err(StorageError::CorruptHistory.into());
            }
            output.extend_from_slice(part);
        }
        if output.len() != length {
            return Err(StorageError::CorruptHistory.into());
        }
        let validated = spans::Validated::new(&output, &mut self.meter)?;
        if decimal(validated.root()?.array(3)?.field(1)?.text()?)? != writing_boundary {
            return Err(StorageError::CorruptHistory.into());
        }
        let act = pn_records::ActId {
            author: self.copy_text(author)?,
            sequence: decimal(sequence)?,
            family: self.copy_text(family)?,
        };
        Ok(ServerDebit {
            act,
            origin,
            writing_boundary,
            bytes: output,
        })
    }

    async fn request(
        &mut self,
        statement: Statement,
        params: &[StatementParameter<'_>],
        limit: usize,
        maximum: usize,
        probe: bool,
    ) -> Result<Vec<StatementRow>, Error> {
        read_request(
            &self.transaction,
            &mut self.meter,
            statement,
            params,
            (limit, maximum, probe),
            || Ok(()),
        )
        .await
    }

    fn scope(scope: &EpochScope) -> Result<Scope, Error> {
        scope_check(scope)?;
        let mut encoded = Scope {
            bytes: [0; 1024],
            len: 0,
        };
        encoded.write_str("4:").map_err(|_| StorageError::Representation)?;
        for field in fields(scope) {
            write!(encoded, "{}:{field}", field.len()).map_err(|_| StorageError::Representation)?;
        }
        Ok(encoded)
    }

    async fn existence(&mut self, scope: &str, identity: Identity, child: bool) -> Result<bool, Error> {
        let statement = if child { Statement::HasChild } else { Statement::HasEpoch };
        let rows = self.request(statement, &[&scope, &&identity[..]], 1, 7, false).await?;
        let row = rows.first().ok_or(StorageError::CorruptHistory)?;
        row.try_get(0).map_err(|_| StorageError::CorruptHistory.into())
    }

    /// Read roots by identity bytes within one scope, independently of cross-parent order.
    /// (´[ROOT-amend:storage:tree-enumeration]´)
    /// # Errors
    /// Refuses malformed requests, damaged delivered rows, transport failure or an allowance limit.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerReader < '_ >::roots",
            asynchronous = true
        ),
        ret
    )]
    pub async fn roots(&mut self, scope: &EpochScope, after: Option<Identity>, limit: usize) -> Result<Page, Error> {
        let result = self.page(scope, None, after, limit, Statement::ReadRoots).await;
        self.record(&result);
        result
    }

    /// Read all direct children in identity byte order, with a charged parent-existence check.
    /// (´[ROOT-amend:storage:tree-enumeration]´)
    /// # Errors
    /// Also refuses an absent parent as `MissingTip`.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerReader < '_ >::children",
            asynchronous = true
        ),
        ret
    )]
    pub async fn children(
        &mut self,
        scope: &EpochScope,
        parent: Identity,
        after: Option<Identity>,
        limit: usize,
    ) -> Result<Page, Error> {
        let result = self.page(scope, Some(parent), after, limit, Statement::ReadChildren).await;
        self.record(&result);
        result
    }

    /// Read bounded identity candidates without filtering any branch.
    /// (´[ROOT-amend:storage:tree-enumeration]´)
    /// # Errors
    /// Refuses malformed requests, damaged delivered rows, transport failure or an allowance limit.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerReader < '_ >::candidates",
            asynchronous = true
        ),
        ret
    )]
    pub async fn candidates(&mut self, scope: &EpochScope, after: Option<Identity>, limit: usize) -> Result<Page, Error> {
        let result = self.page(scope, None, after, limit, Statement::ReadResultCandidates).await;
        self.record(&result);
        result
    }

    async fn page(
        &mut self,
        scope: &EpochScope,
        parent: Option<Identity>,
        after: Option<Identity>,
        limit: usize,
        statement: Statement,
    ) -> Result<Page, Error> {
        super::read::page_shape(scope, limit)?;
        let encoded = Self::scope(scope)?;
        let scope = encoded.text()?;
        if let Some(parent) = parent
            && !self.existence(scope, parent, false).await?
        {
            return Err(Error::MissingTip);
        }
        let boundary = after.as_ref().map(|value| &value[..]);
        let ceiling = i64::try_from(limit).map_err(|_| StorageError::Representation)?;
        let rows = if let Some(parent) = parent {
            self.request(statement, &[&scope, &boundary, &ceiling, &&parent[..]], limit, 50, true)
                .await?
        } else {
            self.request(statement, &[&scope, &boundary, &ceiling], limit, 50, true)
                .await?
        };
        let mut page = Page {
            identities: Vec::new(),
            after,
            end: rows.len() < limit,
        };
        self.meter.reserve(&mut page.identities, rows.len())?;
        for row in rows {
            let identity = bytes(&row, 0, 1, 32)?.try_into().map_err(|_| StorageError::CorruptHistory)?;
            if page.after.is_some_and(|previous| previous >= identity) {
                return Err(StorageError::CorruptHistory.into());
            }
            page.identities.push(identity);
            page.after = Some(identity);
        }
        Ok(page)
    }

    /// Probe whether a candidate has any direct child in this snapshot.
    /// (´[ROOT-amend:storage:tree-enumeration]´)
    /// # Errors
    /// Refuses malformed scope, transport failure or an allowance limit.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerReader < '_ >::has_child",
            asynchronous = true
        ),
        ret
    )]
    pub async fn has_child(&mut self, scope: &EpochScope, parent: Identity) -> Result<bool, Error> {
        let result = async {
            scope_check(scope)?;
            let scope = Self::scope(scope)?;
            self.existence(scope.text()?, parent, true).await
        }
        .await;
        self.record(&result);
        result
    }

    /// Inspect a bounded candidate page, advancing even if every candidate has children.
    /// (´[ROOT-amend:storage:tree-enumeration]´)
    /// # Errors
    /// Refuses malformed requests, damaged delivered rows, transport failure or an allowance limit.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::tree::server::ServerReader < '_ >::tips",
            asynchronous = true
        ),
        ret
    )]
    pub async fn tips(&mut self, scope: &EpochScope, after: Option<Identity>, limit: usize) -> Result<Page, Error> {
        let result = async {
            let candidates = self.candidates(scope, after, limit).await?;
            let mut page = Page {
                identities: Vec::new(),
                after: candidates.after,
                end: candidates.end,
            };
            self.meter.reserve(&mut page.identities, candidates.identities.len())?;
            for identity in candidates.identities {
                if !self.has_child(scope, identity).await? {
                    page.identities.push(identity);
                }
            }
            Ok(page)
        }
        .await;
        self.record(&result);
        result
    }
}

async fn read_request(
    transaction: &StatementTransaction<'_>,
    meter: &mut Meter,
    statement: Statement,
    params: &[StatementParameter<'_>],
    shape: (usize, usize, bool),
    before: impl FnOnce() -> Result<(), Error>,
) -> Result<Vec<StatementRow>, Error> {
    let (limit, maximum, probe) = shape;
    if probe {
        meter.row(|| ())?;
    }
    let reserved = limit.checked_mul(maximum).ok_or(StorageError::ReadLimit)?;
    let rows = meter.used.rows.checked_add(limit).ok_or(StorageError::ReadLimit)?;
    if rows > meter.limit.rows {
        return Err(StorageError::ReadLimit.into());
    }
    meter.allocation(reserved)?;
    meter.used.rows = rows;
    before()?;
    #[cfg(test)]
    tests::fetched();
    let result = observed(transaction.query(statement, params)).await?;
    if result.len() > limit {
        return Err(StorageError::CorruptHistory.into());
    }
    let unused = limit - result.len();
    meter.used.rows -= unused;
    meter.used.allocation_bytes -= unused * maximum;
    Ok(result)
}

struct Header {
    identity: Identity,
    parent: Option<Identity>,
    parent_segment: Option<Identity>,
    segment: Identity,
    depth: u64,
    generation: u64,
    bytes: u64,
    chunks: u64,
    references: u64,
    debits: u64,
}
impl Header {
    fn read(row: &StatementRow) -> Result<Self, Error> {
        let result = Self {
            identity: identity(row, 0, 1)?,
            depth: positive(row, 2)?,
            parent: optional_identity(row, 3, 4)?,
            parent_segment: optional_identity(row, 6, 7)?,
            segment: identity(row, 8, 9)?,
            generation: positive(row, 10)?,
            bytes: positive(row, 11)?,
            chunks: positive(row, 12)?,
            references: unsigned(row, 13)?,
            debits: unsigned(row, 14)?,
        };
        let parent_depth: Option<i64> = row.try_get(5).map_err(|_| StorageError::CorruptHistory)?;
        if result.depth == 1 {
            if result.parent.is_some()
                || result.parent_segment.is_some()
                || parent_depth.is_some()
                || result.identity != result.segment
            {
                return Err(StorageError::CorruptHistory.into());
            }
        } else if result.parent.is_none()
            || result.parent_segment.is_none()
            || parent_depth != i64::try_from(result.depth - 1).ok()
        {
            return Err(StorageError::CorruptHistory.into());
        }
        if result.identity != result.segment && result.parent_segment != Some(result.segment) {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(result)
    }
}

fn unsigned(row: &StatementRow, field: usize) -> Result<u64, Error> {
    let value: i64 = row.try_get(field).map_err(|_| StorageError::CorruptHistory)?;
    u64::try_from(value).map_err(|_| StorageError::CorruptHistory.into())
}
fn positive(row: &StatementRow, field: usize) -> Result<u64, Error> {
    let value = unsigned(row, field)?;
    if value == 0 {
        return Err(StorageError::CorruptHistory.into());
    }
    Ok(value)
}
fn identity(row: &StatementRow, value: usize, length: usize) -> Result<Identity, Error> {
    bytes(row, value, length, 32)?
        .try_into()
        .map_err(|_| StorageError::CorruptHistory.into())
}
fn optional_identity(row: &StatementRow, value: usize, length: usize) -> Result<Option<Identity>, Error> {
    let data: Option<&[u8]> = row.try_get(value).map_err(|_| StorageError::CorruptHistory)?;
    let length: Option<i64> = row.try_get(length).map_err(|_| StorageError::CorruptHistory)?;
    match (data, length) {
        (None, None) => Ok(None),
        (Some(data), Some(32)) => data.try_into().map(Some).map_err(|_| StorageError::CorruptHistory.into()),
        _ => Err(StorageError::CorruptHistory.into()),
    }
}
fn text(row: &StatementRow, value: usize, length: usize, maximum: usize) -> Result<&str, Error> {
    let length = unsigned(row, length)?;
    let value: &str = row.try_get(value).map_err(|_| StorageError::CorruptHistory)?;
    if length > maximum as u64 || length != value.len() as u64 || value.contains('\0') {
        return Err(StorageError::CorruptHistory.into());
    }
    Ok(value)
}

struct Scope {
    bytes: [u8; 1024],
    len: usize,
}
impl std::fmt::Write for Scope {
    /// Justified: Fixed-stack request framing inherits the reader's operation and owns no secret.
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(std::fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}
impl Scope {
    fn text(&self) -> Result<&str, Error> {
        std::str::from_utf8(&self.bytes[..self.len]).map_err(|_| StorageError::Representation.into())
    }
}

fn bytes(row: &StatementRow, value: usize, length: usize, maximum: usize) -> Result<&[u8], Error> {
    let length = unsigned(row, length)?;
    let result: &[u8] = row.try_get(value).map_err(|_| StorageError::CorruptHistory)?;
    if length > maximum as u64 || length != result.len() as u64 {
        return Err(StorageError::CorruptHistory.into());
    }
    Ok(result)
}

fn optional_bytes(row: &StatementRow, value: usize, length: usize, maximum: usize) -> Result<Option<&[u8]>, Error> {
    let result: Option<&[u8]> = row.try_get(value).map_err(|_| StorageError::CorruptHistory)?;
    let stored_length: Option<i64> = row.try_get(length).map_err(|_| StorageError::CorruptHistory)?;
    match (result, stored_length) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => bytes(row, value, length, maximum).map(Some),
        _ => Err(StorageError::CorruptHistory.into()),
    }
}
fn family(name: &str) -> Result<Family, Error> {
    match name {
        "constants" => Ok(Family::Constants),
        "rule" => Ok(Family::Rule),
        "marker-policy" => Ok(Family::MarkerPolicy),
        "lineage" => Ok(Family::Lineage),
        "burn-publication" => Ok(Family::BurnPublication),
        "unsettled-recognition" => Ok(Family::UnsettledRecognition),
        _ => Err(StorageError::CorruptHistory.into()),
    }
}

fn sql_order(selected: &ServerSelection) -> (u64, &str, &str, &str) {
    (
        selected.use_.selected_at,
        selected.use_.version.family.name(),
        &selected.use_.version.key,
        &selected.use_.version.edition,
    )
}

fn decimal(text: &str) -> Result<u64, Error> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0')) {
        return Err(StorageError::CorruptHistory.into());
    }
    text.parse().map_err(|_| StorageError::CorruptHistory.into())
}

#[cfg(test)]
pub(super) async fn prepare_trace(name: &str) -> ServerTree {
    tests::prepare_trace(name).await
}
#[cfg(test)]
pub(super) async fn trace_fixture(store: &mut ServerTree) {
    tests::trace_fixture(store).await;
}
