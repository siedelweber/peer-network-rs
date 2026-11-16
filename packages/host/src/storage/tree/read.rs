//! Bounded reconstruction and keyset enumeration of one immutable memory snapshot.
//! (´[ROOT-amend:storage:admitted-reads]´)
use super::{
    DebitVintage, EpochScope, Error, Identity, Installed, MemoryTree, Meter, Node, Range, ReadBudget, Selected, StorageError,
    Usage, coordinate, scope_check, unqualified,
};

/// Public retained evidence; this does not reconstruct an admitted capability.
/// Observation and caller cloning of the returned evidence are outside the meter.
/// (´[ROOT-amend:storage:admitted-reads]´)
#[derive(Debug, PartialEq, Eq)]
pub struct ResultRead<'a> {
    pub identity: Identity,
    pub parent: Option<Identity>,
    pub depth: u64,
    pub label: &'a str,
    pub generation: u64,
    pub bytes: Vec<u8>,
    pub selections: Vec<Selected<'a>>,
    pub debits: Vec<DebitRead<'a>>,
}

/// A complete vintage and its introduction on the selected ancestor path.
/// (´[ROOT-amend:storage:admitted-debits]´)
#[derive(Debug, PartialEq, Eq)]
pub struct DebitRead<'a> {
    pub vintage: &'a DebitVintage,
    pub origin: Identity,
    pub bytes: Vec<u8>,
}

/// An exclusive continuation cursor is the last inspected candidate, including on an empty tip page.
/// (´[ROOT-amend:storage:tree-enumeration]´)
#[derive(Debug, PartialEq, Eq)]
pub struct Page {
    pub identities: Vec<Identity>,
    pub after: Option<Identity>,
    pub end: bool,
}

/// Caller-owned snapshot and cumulative meter. Borrow this session across all pages or audit phases.
/// The immutable store borrow prevents publication during its lifetime.
/// (´[ROOT-amend:storage:tree-enumeration]´)
pub struct Reader<'s, 'a> {
    store: &'s MemoryTree<'a>,
    meter: Meter,
}

impl<'a> MemoryTree<'a> {
    /// Pin the memory state with an explicit cumulative allowance, without fetching a row.
    /// (´[ROOT-amend:storage:admitted-reads]´)
    /// Justified: This creates a borrowed session only; its operations observe their own requests.
    #[must_use]
    pub fn reader(&self, budget: ReadBudget) -> Reader<'_, 'a> {
        Reader {
            store: self,
            meter: Meter {
                limit: budget,
                used: Usage::default(),
            },
        }
    }
}

impl<'s, 'a> Reader<'s, 'a> {
    /// Admitted row visits and exact allocation requests, including after a refusal.
    /// (´[ROOT-amend:storage:admitted-reads]´)
    /// Justified: Reading counters performs no storage work and inherits the session operation.
    #[must_use]
    pub fn usage(&self) -> Usage {
        self.meter.used
    }

    /// Read an exact identity, returning absence without delivering an unknown header.
    /// (´[ROOT-amend:storage:admitted-reads]´)
    /// # Errors
    /// Refuses malformed scope ranges, corrupt retained content or a cumulative read limit.
    pub fn exact(&mut self, scope: &EpochScope, identity: Identity) -> Result<Option<ResultRead<'a>>, Error> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::tree::read::Reader < 's , 'a >::exact",
            &(scope, identity),
        );
        let result = self.exact_inner(scope, identity);
        operation.finish(&result);
        result
    }
    fn exact_inner(&mut self, scope: &EpochScope, identity: Identity) -> Result<Option<ResultRead<'a>>, Error> {
        scope_check(scope)?;
        // Existence only: no header delivery, reconstruction or row charge on absence.
        if !self.store.results.contains_key(&(scope, identity)) {
            return Ok(None);
        }
        let row = self.header(scope, identity)?;
        self.reconstruct(row).map(Some)
    }
    /// Resolve a depth on the named tip's ancestor path, clamped at that tip.
    /// (´[ROOT-amend:storage:tree-branches]´)
    /// # Errors
    /// Refuses malformed ranges, an absent tip, corrupt placement or a cumulative read limit.
    pub fn as_of(&mut self, scope: &EpochScope, tip: Identity, depth: u64) -> Result<Option<ResultRead<'a>>, Error> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::tree::read::Reader < 's , 'a >::as_of",
            &(scope, tip, depth),
        );
        let result = self.as_of_inner(scope, tip, depth);
        operation.finish(&result);
        result
    }
    fn as_of_inner(&mut self, scope: &EpochScope, tip: Identity, depth: u64) -> Result<Option<ResultRead<'a>>, Error> {
        scope_check(scope)?;
        if depth > i64::MAX as u64 {
            return Err(StorageError::Representation.into());
        }
        let tip = self
            .meter
            .row(|| self.store.results.get(&(scope, tip)))?
            .ok_or(Error::MissingTip)?;
        let ranges = self.ranges(tip)?;
        let depth = depth.min(tip.input.event().3);
        let Some(range) = ranges.iter().find(|r| r.start <= depth && depth <= r.end) else {
            return Ok(None);
        };
        let identity = self
            .meter
            .row(|| self.store.placements.get(&(scope, range.segment, depth)).copied())?
            .ok_or(StorageError::CorruptHistory)?;
        let row = self.header(scope, identity)?;
        if row.segment != range.segment || row.input.event().3 != depth {
            return Err(StorageError::CorruptHistory.into());
        }
        self.reconstruct(row).map(Some)
    }
    fn header(&mut self, scope: &EpochScope, identity: Identity) -> Result<&'s Node<'a>, Error> {
        let row = self
            .meter
            .row(|| {
                #[cfg(test)]
                FETCHES.with(|n| n.set(n.get() + 1));
                self.store.results.find_by(|(s, i)| (*s, *i).cmp(&(scope, identity)))
            })?
            .ok_or(StorageError::CorruptHistory)?;
        if row.input.event().0 != scope || *row.input.event().1 != identity {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(row)
    }
    fn placement(&mut self, row: &Node<'a>) -> Result<(), Error> {
        let (scope, identity, parent, depth) = row.input.event();
        let actual = self.meter.row(|| self.store.placements.get(&(scope, row.segment, depth)))?;
        if actual != Some(identity) {
            return Err(StorageError::CorruptHistory.into());
        }
        if !self
            .meter
            .row(|| self.store.direct_children.contains_key(&(scope, parent.copied(), *identity)))?
        {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(())
    }
    pub(super) fn ranges(&mut self, tip: &Node<'a>) -> Result<Vec<Range>, Error> {
        let scope = tip.input.event().0;
        let mut segment = tip.segment;
        let mut cutoff = tip.input.event().3;
        let mut ranges = Vec::new();
        loop {
            let d = self
                .meter
                .row(|| self.store.segments.get(&(scope, segment)))?
                .ok_or(StorageError::CorruptHistory)?;
            let first = self.header(scope, d.first)?;
            if d.first != segment
                || first.segment != segment
                || first.input.event().3 != d.start
                || first.input.event().2.copied() != d.fork
                || d.start > cutoff
            {
                return Err(StorageError::CorruptHistory.into());
            }
            self.placement(first)?;
            self.meter.reserve(&mut ranges, 1)?;
            ranges.push(Range {
                segment,
                start: d.start,
                end: cutoff,
            });
            match (d.parent_segment, d.fork) {
                (None, None) if d.start == 1 && d.cutoff == 0 => break,
                (Some(parent_segment), Some(parent)) => {
                    let parent = self.header(scope, parent)?;
                    if parent.segment != parent_segment
                        || parent.input.event().3 != d.cutoff
                        || d.cutoff.checked_add(1) != Some(d.start)
                    {
                        return Err(StorageError::CorruptHistory.into());
                    }
                    segment = parent_segment;
                    cutoff = d.cutoff;
                }
                _ => return Err(StorageError::CorruptHistory.into()),
            }
        }
        Ok(ranges)
    }
    fn law(&mut self, row: &Node<'a>) -> Result<&'s Installed<'a>, Error> {
        let generation = self
            .store
            .installed(row.input.event().0, &mut self.meter)?
            .ok_or(StorageError::CorruptHistory)?;
        if row.label != "unstable"
            || row.generation != 1
            || generation.declaration.ordinal != row.generation
            || generation.declaration.label != row.label
            || generation.declaration.minimum != 1
        {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(generation)
    }
    fn reconstruct(&mut self, row: &'s Node<'a>) -> Result<ResultRead<'a>, Error> {
        let (scope, identity, parent, depth) = row.input.event();
        self.placement(row)?;
        let ranges = self.ranges(row)?;
        self.law(row)?;
        let parent = parent.map(|p| self.header(scope, *p)).transpose()?;
        if let Some(parent) = parent {
            self.law(parent)?;
            if parent.input.event().3.checked_add(1) != Some(depth) || !row.input.extends(parent.input) {
                return Err(StorageError::CorruptHistory.into());
            }
        } else if depth != 1 {
            return Err(StorageError::CorruptHistory.into());
        }
        let bytes = copy_bytes(&row.chunks, row.input.bytes(), &mut self.meter)?;
        if row.references.len() != row.input.declarations().len() {
            return Err(StorageError::CorruptHistory.into());
        }
        let mut selections = Vec::new();
        self.meter.reserve(&mut selections, row.references.len())?;
        for (reference, expected) in row.references.iter().zip(row.input.declarations()) {
            let reference = self.meter.row(|| reference)?;
            if reference.use_ != expected {
                return Err(StorageError::CorruptHistory.into());
            }
            let origin = self.header(scope, reference.origin)?;
            if !ranges
                .iter()
                .any(|r| r.segment == origin.segment && r.start <= origin.input.event().3 && origin.input.event().3 <= r.end)
            {
                return Err(StorageError::CorruptHistory.into());
            }
            let original = self
                .meter
                .row(|| {
                    origin
                        .reference_index
                        .binary_search_by(|&i| coordinate(origin.references[i].use_).cmp(&coordinate(expected)))
                        .ok()
                        .map(|i| &origin.references[origin.reference_index[i]])
                })?
                .ok_or(StorageError::CorruptHistory)?;
            if original.origin != reference.origin || original.use_ != expected {
                return Err(StorageError::CorruptHistory.into());
            }
            if unqualified(expected.version.family) {
                let generation = self.law(origin)?;
                MemoryTree::selected_with_probes(generation, expected, &mut self.meter, true).map_err(|e| match e {
                    Error::Storage(StorageError::ReadLimit) => e,
                    _ => StorageError::CorruptHistory.into(),
                })?;
                let inherited = parent
                    .map(|p| {
                        self.meter.row(|| {
                            p.reference_index
                                .binary_search_by(|&i| coordinate(p.references[i].use_).cmp(&coordinate(expected)))
                                .ok()
                                .map(|i| &p.references[p.reference_index[i]])
                        })
                    })
                    .transpose()?
                    .flatten();
                if inherited.is_some_and(|p| p.origin != reference.origin || p.use_ != expected)
                    || (inherited.is_none() && reference.origin != *identity)
                {
                    return Err(StorageError::CorruptHistory.into());
                }
            } else {
                let actual = self.meter.row(|| {
                    self.store
                        .observations
                        .get(&(expected.version.family, &expected.version.key, &expected.version.edition))
                })?;
                if actual.copied() != Some(&expected.version) || reference.origin != *identity {
                    return Err(StorageError::CorruptHistory.into());
                }
            }
            selections.push(*reference);
        }
        let debits = self.debits(row)?;
        Ok(ResultRead {
            identity: *identity,
            parent: row.input.event().2.copied(),
            depth,
            label: row.label,
            generation: row.generation,
            bytes,
            selections,
            debits,
        })
    }
    fn debits(&mut self, row: &'s Node<'a>) -> Result<Vec<DebitRead<'a>>, Error> {
        let introductions = self.store.ancestor_debits_with_probes(row, &mut self.meter, true)?;
        if introductions.len() != row.input.debits().len() {
            return Err(StorageError::CorruptHistory.into());
        }
        let mut debits = Vec::new();
        self.meter.reserve(&mut debits, introductions.len())?;
        for introduction in introductions {
            let expected = row
                .input
                .debits()
                .iter()
                .find(|d| d.key.act == introduction.vintage.key.act)
                .ok_or(StorageError::CorruptHistory)?;
            let bytes = copy_bytes(&introduction.chunks, &expected.bytes, &mut self.meter)?;
            if introduction.vintage != expected {
                return Err(StorageError::CorruptHistory.into());
            }
            debits.push(DebitRead {
                vintage: introduction.vintage,
                origin: introduction.origin,
                bytes,
            });
        }
        debits.sort_unstable_by(|a, b| a.vintage.key.act.cmp(&b.vintage.key.act));
        Ok(debits)
    }
    /// Read roots in identity byte order, independently of cross-parent index ordering.
    /// (´[ROOT-amend:storage:tree-enumeration]´)
    /// # Errors
    /// Refuses malformed scope or limit, corrupt delivered rows, or a cumulative read limit.
    pub fn roots(&mut self, scope: &EpochScope, after: Option<Identity>, limit: usize) -> Result<Page, Error> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::tree::read::Reader < 's , 'a >::roots",
            &(scope, after, limit),
        );
        let result = self.children_inner(scope, None, after, limit);
        operation.finish(&result);
        result
    }
    /// Read all direct children in identity byte order, not arrival order.
    /// (´[ROOT-amend:storage:tree-enumeration]´)
    /// # Errors
    /// Refuses malformed scope or limit, an absent parent, corrupt delivered rows, or a read limit.
    pub fn children(
        &mut self,
        scope: &EpochScope,
        parent: Identity,
        after: Option<Identity>,
        limit: usize,
    ) -> Result<Page, Error> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::tree::read::Reader < 's , 'a >::children",
            &(scope, parent, after, limit),
        );
        let result = self.children_inner(scope, Some(parent), after, limit);
        operation.finish(&result);
        result
    }
    fn children_inner(
        &mut self,
        scope: &EpochScope,
        parent: Option<Identity>,
        after: Option<Identity>,
        limit: usize,
    ) -> Result<Page, Error> {
        page_shape(scope, limit)?;
        if let Some(parent) = parent
            && !self.meter.row(|| self.store.results.contains_key(&(scope, parent)))?
        {
            return Err(Error::MissingTip);
        }
        let mut page = Page {
            identities: Vec::new(),
            after,
            end: false,
        };
        for _ in 0..limit {
            let next = self.meter.row(|| {
                self.store
                    .direct_children
                    .seek(&(scope, parent, page.after.unwrap_or([0; 32])), page.after.is_some())
            })?;
            let Some(((s, p, identity), ())) = next.filter(|((s, p, _), ())| *s == scope && *p == parent) else {
                page.end = true;
                break;
            };
            let row = self.header(s, *identity)?;
            if row.input.event().2.copied() != *p {
                return Err(StorageError::CorruptHistory.into());
            }
            self.placement(row)?;
            self.meter.reserve(&mut page.identities, 1)?;
            page.identities.push(*identity);
            page.after = Some(*identity);
        }
        Ok(page)
    }
    /// Read bounded result candidates in identity byte order on this snapshot and meter.
    /// (´[ROOT-amend:storage:tree-enumeration]´)
    /// # Errors
    /// Refuses malformed scope or limit, corrupt delivered rows, or a cumulative read limit.
    pub fn candidates(&mut self, scope: &EpochScope, after: Option<Identity>, limit: usize) -> Result<Page, Error> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::tree::read::Reader < 's , 'a >::candidates",
            &(scope, after, limit),
        );
        let result = self.candidates_inner(scope, after, limit);
        operation.finish(&result);
        result
    }
    fn candidates_inner(&mut self, scope: &EpochScope, after: Option<Identity>, limit: usize) -> Result<Page, Error> {
        page_shape(scope, limit)?;
        let mut page = Page {
            identities: Vec::new(),
            after,
            end: false,
        };
        for _ in 0..limit {
            let next = self.meter.row(|| {
                self.store
                    .results
                    .seek(&(scope, page.after.unwrap_or([0; 32])), page.after.is_some())
            })?;
            let Some(((s, identity), row)) = next.filter(|((s, _), _)| *s == scope) else {
                page.end = true;
                break;
            };
            if row.input.event().0 != *s || row.input.event().1 != identity {
                return Err(StorageError::CorruptHistory.into());
            }
            self.placement(row)?;
            self.meter.reserve(&mut page.identities, 1)?;
            page.identities.push(*identity);
            page.after = Some(*identity);
        }
        Ok(page)
    }
    /// Perform one charged indexed child-existence probe for a candidate on this snapshot.
    /// (´[ROOT-amend:storage:tree-enumeration]´)
    /// # Errors
    /// Refuses malformed scope or a cumulative read limit.
    pub fn has_child(&mut self, scope: &EpochScope, parent: Identity) -> Result<bool, Error> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::tree::read::Reader < 's , 'a >::has_child",
            &(scope, parent),
        );
        let result = self.has_child_inner(scope, parent);
        operation.finish(&result);
        result
    }
    fn has_child_inner(&mut self, scope: &EpochScope, parent: Identity) -> Result<bool, Error> {
        scope_check(scope)?;
        self.meter.row(|| {
            self.store
                .direct_children
                .seek(&(scope, Some(parent), [0; 32]), false)
                .is_some_and(|((s, p, _), ())| *s == scope && *p == Some(parent))
        })
    }
    /// Inspect at most the candidate limit, advancing even when every candidate has a child.
    /// (´[ROOT-amend:storage:tree-enumeration]´)
    /// # Errors
    /// Refuses malformed scope or limit, corrupt delivered rows, or a cumulative read limit.
    pub fn tips(&mut self, scope: &EpochScope, after: Option<Identity>, limit: usize) -> Result<Page, Error> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::tree::read::Reader < 's , 'a >::tips",
            &(scope, after, limit),
        );
        let result = self.tips_inner(scope, after, limit);
        operation.finish(&result);
        result
    }
    fn tips_inner(&mut self, scope: &EpochScope, after: Option<Identity>, limit: usize) -> Result<Page, Error> {
        let candidates = self.candidates_inner(scope, after, limit)?;
        let mut tips = Page {
            identities: Vec::new(),
            after: candidates.after,
            end: candidates.end,
        };
        for candidate in candidates.identities {
            if !self.has_child_inner(scope, candidate)? {
                self.meter.reserve(&mut tips.identities, 1)?;
                tips.identities.push(candidate);
            }
        }
        Ok(tips)
    }
}

fn copy_bytes(parts: &[&[u8]], expected: &[u8], meter: &mut Meter) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    meter.reserve(&mut bytes, expected.len())?;
    for part in parts {
        let part = meter.row(|| *part)?;
        if part.is_empty() || part.len() > super::super::MAX_PACKAGE || part.len() > expected.len().saturating_sub(bytes.len()) {
            return Err(StorageError::CorruptHistory.into());
        }
        bytes.extend_from_slice(part);
    }
    if bytes != expected {
        return Err(StorageError::CorruptHistory.into());
    }
    Ok(bytes)
}

#[cfg(test)]
thread_local! { pub(super) static FETCHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

pub(super) fn page_shape(scope: &EpochScope, limit: usize) -> Result<(), Error> {
    scope_check(scope)?;
    if i64::try_from(limit).is_err() {
        return Err(StorageError::Representation.into());
    }
    if limit == 0 {
        return Err(StorageError::ReadLimit.into());
    }
    Ok(())
}
