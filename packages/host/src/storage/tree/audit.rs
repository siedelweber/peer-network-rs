//! Complete snapshot reconciliation over independently collected tree domains.
//! (´[ROOT-amend:storage:tree-audit]´)

use super::{Closure, Error, Generation, Identity, Meter, coordinate, unqualified};
use crate::storage::{DebitVintage, DeclarationUse, EpochScope, ReadBudget, StorageError, Version};
use pn_interchange::Value;
use pn_records::ActId;

mod memory;
mod output;
#[cfg(test)]
mod tests;

/// Explicit ceilings for a complete audit invocation.
/// (´[ROOT-amend:storage:tree-audit]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditBudget {
    pub page_rows: usize,
    pub rows: usize,
    pub allocation_bytes: usize,
    pub retained_bytes: usize,
    pub items: usize,
}

/// Cumulative work and logical retention consumed by one audit attempt.
/// (´[ROOT-amend:storage:tree-audit]´)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditUsage {
    pub rows: usize,
    pub allocation_bytes: usize,
    pub retained_bytes: usize,
    pub items: usize,
    pub allocation_requests: usize,
}

/// An owned diagnostic with borrowed, allocation-free scalar inspection.
/// (´[ROOT-amend:storage:tree-audit]´)
#[derive(Clone, PartialEq, Eq)]
pub struct AuditLocation {
    state: LocationState,
    backing: Vec<u8>,
    relation_len: u8,
    kinds: [LocationKind; 6],
    slots: [u64; 6],
    used: u8,
}

impl std::fmt::Debug for AuditLocation {
    /// Justified: Location formatting inspects an already published audit outcome.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.state {
            LocationState::NotRead => formatter.write_str("NotRead"),
            LocationState::OverBound => formatter.write_str("OverBound"),
            LocationState::Row => formatter
                .debug_struct("Row")
                .field("relation", &self.relation())
                .field("key", &LocationKey(self))
                .finish_non_exhaustive(),
        }
    }
}

struct LocationKey<'a>(&'a AuditLocation);

impl std::fmt::Debug for LocationKey<'_> {
    /// Justified: Location key formatting borrows an already published diagnostic.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = formatter.debug_list();
        for at in 0..usize::from(self.0.used) {
            match self.0.kinds[at] {
                LocationKind::Text => {
                    list.entry(&self.0.key_text(at).ok_or(std::fmt::Error)?);
                }
                LocationKind::Bytes => {
                    list.entry(&self.0.key_bytes(at).ok_or(std::fmt::Error)?);
                }
                LocationKind::UnsignedInteger | LocationKind::SignedInteger => {
                    list.entry(&self.0.key_integer(at).ok_or(std::fmt::Error)?);
                }
                LocationKind::Null => {
                    list.entry(&"null");
                }
                LocationKind::Empty => {}
            }
        }
        list.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocationState {
    Row,
    NotRead,
    OverBound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocationKind {
    Empty,
    Text,
    Bytes,
    UnsignedInteger,
    SignedInteger,
    Null,
}

impl AuditLocation {
    fn unavailable(state: LocationState) -> Self {
        Self {
            state,
            backing: Vec::new(),
            relation_len: 0,
            kinds: [LocationKind::Empty; 6],
            slots: [0; 6],
            used: 0,
        }
    }

    /// The fixed relation or memory-index tag, when a complete key was read.
    /// Justified: Location inspection borrows an already published audit outcome.
    #[must_use]
    pub fn relation(&self) -> Option<&str> {
        (self.state == LocationState::Row)
            .then(|| std::str::from_utf8(&self.backing[..usize::from(self.relation_len)]).ok())
            .flatten()
    }

    /// Number of ordered scalar positions in the complete observed key.
    /// Justified: Location inspection borrows an already published audit outcome.
    #[must_use]
    pub fn key_len(&self) -> usize {
        usize::from(self.used)
    }

    /// Borrow a text scalar at a key position.
    /// Justified: Location inspection borrows an already published audit outcome.
    #[must_use]
    pub fn key_text(&self, at: usize) -> Option<&str> {
        (self.kinds.get(at) == Some(&LocationKind::Text))
            .then(|| {
                self.range(at)
                    .and_then(|range| std::str::from_utf8(&self.backing[range]).ok())
            })
            .flatten()
    }

    /// Borrow a byte-string scalar at a key position.
    /// Justified: Location inspection borrows an already published audit outcome.
    #[must_use]
    pub fn key_bytes(&self, at: usize) -> Option<&[u8]> {
        (self.kinds.get(at) == Some(&LocationKind::Bytes))
            .then(|| self.range(at).map(|range| &self.backing[range]))
            .flatten()
    }

    /// Inspect an integer scalar at a key position.
    /// Justified: Location inspection borrows an already published audit outcome.
    #[must_use]
    pub fn key_integer(&self, at: usize) -> Option<i128> {
        match self.kinds.get(at)? {
            LocationKind::UnsignedInteger => self.slots.get(at).copied().map(i128::from),
            LocationKind::SignedInteger => self
                .slots
                .get(at)
                .copied()
                .map(|value| i128::from(i64::from_ne_bytes(value.to_ne_bytes()))),
            _ => None,
        }
    }

    /// Whether an observed nullable position was null.
    /// Justified: Location inspection borrows an already published audit outcome.
    #[must_use]
    pub fn key_is_null(&self, at: usize) -> bool {
        self.kinds.get(at) == Some(&LocationKind::Null)
    }

    /// Whether no complete key had been read.
    /// Justified: Location inspection borrows an already published audit outcome.
    #[must_use]
    pub fn is_not_read(&self) -> bool {
        self.state == LocationState::NotRead
    }

    /// Whether the observed key exceeded a recorded bound.
    /// Justified: Location inspection borrows an already published audit outcome.
    #[must_use]
    pub fn is_over_bound(&self) -> bool {
        self.state == LocationState::OverBound
    }

    fn range(&self, at: usize) -> Option<std::ops::Range<usize>> {
        let packed = *self.slots.get(at)?;
        let start = usize::try_from(packed >> 32).ok()?;
        let end = usize::try_from(packed & u64::from(u32::MAX)).ok()?;
        (start <= end && end <= self.backing.len()).then_some(start..end)
    }
}

#[derive(Clone, Copy)]
pub(super) enum SitePart<'a> {
    Empty,
    Scope(&'a EpochScope),
    Text(&'a str, usize),
    Identity(Identity),
    Decimal(u64),
    Integer(u64),
    Signed(i64),
    Null,
}

impl SitePart<'_> {
    fn length(self) -> usize {
        match self {
            Self::Decimal(value) => decimal_length(value),
            Self::Text(value, _) => value.len(),
            _ => 0,
        }
    }
}

#[derive(Clone, Copy)]
// Justified: The inline borrowed key avoids an allocation while a refusal is being chosen.
#[allow(clippy::large_enum_variant)]
pub(super) enum AuditSite<'a> {
    NotRead,
    Row {
        relation: &'static str,
        slots: [SitePart<'a>; 6],
    },
}

impl<'a> AuditSite<'a> {
    fn row(relation: &'static str, parts: &[SitePart<'a>]) -> Self {
        let mut slots = [SitePart::Empty; 6];
        slots[..parts.len()].copy_from_slice(parts);
        Self::Row { relation, slots }
    }
}

/// A tree refusal or an allocator refusal after admitted capacity.
/// (´[ROOT-amend:storage:tree-audit]´)
#[derive(Debug, PartialEq, Eq)]
pub enum AuditFailure {
    Refused { error: Error, location: AuditLocation },
    Allocation { location: AuditLocation },
}

/// Owned complete logical state of one audited snapshot.
/// The value tree is an inspection view, not an admitted external encoding.
/// (´[ROOT-amend:storage:tree-audit]´)
#[derive(Debug, PartialEq, Eq)]
pub struct AuditInventory {
    tree: Value,
    generations: usize,
    histories: usize,
    scopes: usize,
    results: usize,
    logical_bytes: usize,
    logical_items: usize,
}

impl AuditInventory {
    /// Borrow the complete logical field tree in its decided order.
    /// (´[ROOT-amend:storage:tree-audit]´)
    #[doc = "Justified: Immutable audit inventory inspection inherits the enclosing audit observation."]
    #[must_use]
    pub fn fields(&self) -> &Value {
        &self.tree
    }

    /// Observe the four collection counts and the logical byte and slot totals.
    /// (´[ROOT-amend:storage:tree-audit]´)
    #[doc = "Justified: Immutable audit inventory inspection inherits the enclosing audit observation."]
    #[must_use]
    pub const fn counts(&self) -> (usize, usize, usize, usize, usize, usize) {
        (
            self.generations,
            self.histories,
            self.scopes,
            self.results,
            self.logical_bytes,
            self.logical_items,
        )
    }
}

pub(super) struct AuditMeter {
    core: Meter,
    retained_bytes: usize,
    items: usize,
    bytes_limit: usize,
    items_limit: usize,
    requests: usize,
    diagnostic: Vec<u8>,
}

impl AuditMeter {
    pub(super) fn new(budget: AuditBudget) -> Self {
        Self {
            core: Meter {
                limit: ReadBudget {
                    rows: budget.rows,
                    bytes: budget.allocation_bytes,
                },
                used: super::Usage::default(),
            },
            retained_bytes: 0,
            items: 0,
            bytes_limit: budget.retained_bytes,
            items_limit: budget.items,
            requests: 0,
            diagnostic: Vec::new(),
        }
    }

    pub(super) fn begin(&mut self, budget: AuditBudget) -> Result<(), AuditFailure> {
        if budget.page_rows == 0 {
            return Err(Self::refused_unavailable(StorageError::ReadLimit, LocationState::NotRead));
        }
        // Reserve bounded diagnostic work before inspecting any stored domain.
        self.allocation(2127, AuditSite::NotRead)?;
        self.diagnostic.try_reserve_exact(2127).map_err(|_| AuditFailure::Allocation {
            location: AuditLocation::unavailable(LocationState::NotRead),
        })
    }

    pub(super) fn usage(&self) -> AuditUsage {
        AuditUsage {
            rows: self.core.used.rows,
            allocation_bytes: self.core.used.allocation_bytes,
            retained_bytes: self.retained_bytes,
            items: self.items,
            allocation_requests: self.requests,
        }
    }

    fn refused_unavailable(error: StorageError, state: LocationState) -> AuditFailure {
        AuditFailure::Refused {
            error: Error::Storage(error),
            location: AuditLocation::unavailable(state),
        }
    }

    // Justified: One publication path checks every key bound before copying into the initial reservation.
    #[allow(clippy::too_many_lines)]
    fn publish(&mut self, site: AuditSite<'_>) -> AuditLocation {
        let AuditSite::Row { relation, slots } = site else {
            return AuditLocation::unavailable(match site {
                AuditSite::NotRead => LocationState::NotRead,
                AuditSite::Row { .. } => unreachable!(),
            });
        };
        let used = slots.iter().position(|part| matches!(part, SitePart::Empty)).unwrap_or(6);
        let mut length = relation.len();
        for part in &slots[..used] {
            let part_len = match part {
                SitePart::Scope(scope) => match scope_key_length(scope) {
                    Ok(length) => length,
                    Err(_) => return AuditLocation::unavailable(LocationState::OverBound),
                },
                SitePart::Text(value, bound) => {
                    if value.len() > *bound {
                        return AuditLocation::unavailable(LocationState::OverBound);
                    }
                    value.len()
                }
                SitePart::Identity(_) => 32,
                SitePart::Decimal(value) => decimal_length(*value),
                _ => 0,
            };
            let Some(next) = length.checked_add(part_len) else {
                return AuditLocation::unavailable(LocationState::OverBound);
            };
            length = next;
        }
        // The text form retains a server row's original decimal bytes, including malformed text.
        if matches!(
            relation,
            "pn_epoch_debits" | "pn_epoch_debit_chunks" | "pn_epoch_result_debits"
        ) {
            let [
                SitePart::Scope(scope),
                SitePart::Identity(_),
                SitePart::Text(author, _),
                sequence @ (SitePart::Decimal(_) | SitePart::Text(_, 20)),
                SitePart::Text(family, _),
                ..,
            ] = slots
            else {
                return AuditLocation::unavailable(LocationState::OverBound);
            };
            let Some(framed) = scope_key_length(scope)
                .ok()
                .and_then(|total| total.checked_add(author.len()))
                .and_then(|total| total.checked_add(sequence.length()))
                .and_then(|total| total.checked_add(family.len()))
                .and_then(|total| total.checked_add(decimal_length(author.len() as u64)))
                .and_then(|total| total.checked_add(decimal_length(sequence.length() as u64)))
                .and_then(|total| total.checked_add(decimal_length(family.len() as u64)))
                .and_then(|total| total.checked_add(3))
            else {
                return AuditLocation::unavailable(LocationState::OverBound);
            };
            if framed > 1024 {
                return AuditLocation::unavailable(LocationState::OverBound);
            }
        }
        if length > 2127 || used > 6 {
            return AuditLocation::unavailable(LocationState::OverBound);
        }
        self.diagnostic.extend_from_slice(relation.as_bytes());
        let mut kinds = [LocationKind::Empty; 6];
        let mut directory = [0u64; 6];
        for (at, part) in slots[..used].iter().enumerate() {
            let start = self.diagnostic.len();
            kinds[at] = match part {
                SitePart::Scope(scope) => {
                    append_decimal(&mut self.diagnostic, 4);
                    self.diagnostic.push(b':');
                    for field in super::fields(scope) {
                        append_decimal(&mut self.diagnostic, u64::try_from(field.len()).expect("bounded scope field"));
                        self.diagnostic.push(b':');
                        self.diagnostic.extend_from_slice(field.as_bytes());
                    }
                    LocationKind::Text
                }
                SitePart::Text(value, _) => {
                    self.diagnostic.extend_from_slice(value.as_bytes());
                    LocationKind::Text
                }
                SitePart::Identity(value) => {
                    self.diagnostic.extend_from_slice(value);
                    LocationKind::Bytes
                }
                SitePart::Decimal(value) => {
                    append_decimal(&mut self.diagnostic, *value);
                    LocationKind::Text
                }
                SitePart::Integer(value) => {
                    directory[at] = *value;
                    if i64::try_from(*value).is_ok() {
                        LocationKind::SignedInteger
                    } else {
                        LocationKind::UnsignedInteger
                    }
                }
                SitePart::Signed(value) => {
                    directory[at] = u64::from_ne_bytes(value.to_ne_bytes());
                    LocationKind::SignedInteger
                }
                SitePart::Null => LocationKind::Null,
                SitePart::Empty => LocationKind::Empty,
            };
            if matches!(kinds[at], LocationKind::Text | LocationKind::Bytes) {
                let start = u64::try_from(start).expect("bounded diagnostic offset");
                let end = u64::try_from(self.diagnostic.len()).expect("bounded diagnostic offset");
                directory[at] = (start << 32) | end;
            }
        }
        AuditLocation {
            state: LocationState::Row,
            backing: std::mem::take(&mut self.diagnostic),
            relation_len: u8::try_from(relation.len()).expect("fixed relation tag length"),
            kinds,
            slots: directory,
            used: u8::try_from(used).expect("fixed diagnostic slot count"),
        }
    }

    pub(super) fn refused(&mut self, error: StorageError, site: AuditSite<'_>) -> AuditFailure {
        AuditFailure::Refused {
            error: Error::Storage(error),
            location: self.publish(site),
        }
    }

    pub(super) fn allocated(&mut self, site: AuditSite<'_>) -> AuditFailure {
        AuditFailure::Allocation {
            location: self.publish(site),
        }
    }

    pub(super) fn visit(&mut self, location: AuditSite<'_>) -> Result<(), AuditFailure> {
        self.visit_at(location).map(|_| ())
    }

    fn visit_at<'a>(&mut self, location: AuditSite<'a>) -> Result<AuditSite<'a>, AuditFailure> {
        if let Err(error) = self.core.row(|| ()) {
            return Err(AuditFailure::Refused {
                error,
                location: self.publish(location),
            });
        }
        Ok(location)
    }

    pub(super) fn allocation<'a>(&mut self, bytes: usize, location: AuditSite<'a>) -> Result<AuditSite<'a>, AuditFailure> {
        if let Err(error) = self.core.allocation(bytes) {
            return Err(AuditFailure::Refused {
                error,
                location: self.publish(location),
            });
        }
        self.requests = self
            .requests
            .checked_add(1)
            .ok_or_else(|| self.refused(StorageError::ReadLimit, location))?;
        Ok(location)
    }

    pub(super) fn reserve<T>(
        &mut self,
        out: &mut Vec<T>,
        additional: usize,
        location: AuditSite<'_>,
    ) -> Result<(), AuditFailure> {
        let needed = out
            .len()
            .checked_add(additional)
            .ok_or_else(|| self.refused(StorageError::ReadLimit, location))?;
        if needed <= out.capacity() {
            return Ok(());
        }
        let bytes = needed
            .checked_mul(std::mem::size_of::<T>())
            .ok_or_else(|| self.refused(StorageError::ReadLimit, location))?;
        let location = self.allocation(bytes, location)?;
        out.try_reserve_exact(additional).map_err(|_| self.allocated(location))
    }

    pub(super) fn retain(&mut self, bytes: usize, slots: usize, location: AuditSite<'_>) -> Result<(), AuditFailure> {
        let next_bytes = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or_else(|| self.refused(StorageError::ReadLimit, location))?;
        let next_items = self
            .items
            .checked_add(slots)
            .ok_or_else(|| self.refused(StorageError::ReadLimit, location))?;
        if next_bytes > self.bytes_limit || next_items > self.items_limit {
            return Err(self.refused(StorageError::ReadLimit, location));
        }
        self.retained_bytes = next_bytes;
        self.items = next_items;
        Ok(())
    }

    pub(super) fn can_retain(&mut self, bytes: usize, slots: usize, location: AuditSite<'_>) -> Result<(), AuditFailure> {
        let next_bytes = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or_else(|| self.refused(StorageError::ReadLimit, location))?;
        let next_items = self
            .items
            .checked_add(slots)
            .ok_or_else(|| self.refused(StorageError::ReadLimit, location))?;
        if next_bytes > self.bytes_limit || next_items > self.items_limit {
            return Err(self.refused(StorageError::ReadLimit, location));
        }
        Ok(())
    }

    pub(super) fn key(&mut self, scope: &EpochScope, site: AuditSite<'_>) -> Result<String, AuditFailure> {
        let length = scope_key_length(scope)?;
        self.allocation(length, site)?;
        let mut key = String::new();
        key.try_reserve_exact(length).map_err(|_| self.allocated(site))?;
        key.push_str("4:");
        for field in super::fields(scope) {
            use std::fmt::Write as _;
            write!(key, "{}:{field}", field.len()).map_err(|_| self.refused(StorageError::CorruptHistory, site))?;
        }
        Ok(key)
    }
}

fn scope_key_length(scope: &EpochScope) -> Result<usize, AuditFailure> {
    let mut length = 2usize;
    for field in super::fields(scope) {
        length = length
            .checked_add(field.len())
            .and_then(|n| {
                n.checked_add(
                    if field.is_empty() {
                        1
                    } else {
                        field.len().ilog10() as usize + 1
                    } + 1,
                )
            })
            .ok_or_else(|| AuditMeter::refused_unavailable(StorageError::CorruptHistory, LocationState::OverBound))?;
    }
    if length > 1024 {
        return Err(AuditMeter::refused_unavailable(
            StorageError::CorruptHistory,
            LocationState::OverBound,
        ));
    }
    Ok(length)
}

fn append_decimal(target: &mut Vec<u8>, mut number: u64) {
    let mut digits = [0u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + u8::try_from(number % 10).expect("decimal digit");
        number /= 10;
        if number == 0 {
            break;
        }
    }
    target.extend_from_slice(&digits[start..]);
}

fn decimal_length(value: u64) -> usize {
    if value == 0 { 1 } else { value.ilog10() as usize + 1 }
}

fn scope_location(scope: &EpochScope) -> AuditSite<'_> {
    AuditSite::row("pn_epoch_scopes", &[SitePart::Scope(scope)])
}

fn descriptor_location(scope: &EpochScope, segment: Identity) -> AuditSite<'_> {
    AuditSite::row("pn_epoch_branches", &[SitePart::Scope(scope), SitePart::Identity(segment)])
}

fn result_slot_location<'a>(scope: &'a EpochScope, identity: Identity, relation: &'static str, slot: usize) -> AuditSite<'a> {
    AuditSite::row(
        relation,
        &[
            SitePart::Scope(scope),
            SitePart::Identity(identity),
            SitePart::Integer(slot as u64),
        ],
    )
}

fn result_index_location<'a>(scope: &'a EpochScope, identity: Identity, relation: &'static str) -> AuditSite<'a> {
    AuditSite::row(relation, &[SitePart::Scope(scope), SitePart::Identity(identity)])
}

fn placement_location<'a>(scope: &'a EpochScope, segment: Identity, depth: u64, relation: &'static str) -> AuditSite<'a> {
    let depth = match i64::try_from(depth) {
        Ok(value) => SitePart::Signed(value),
        Err(_) => SitePart::Integer(depth),
    };
    AuditSite::row(relation, &[SitePart::Scope(scope), SitePart::Identity(segment), depth])
}

fn child_location(scope: &EpochScope, parent: Option<Identity>, identity: Identity) -> AuditSite<'_> {
    AuditSite::row(
        "memory.direct_children",
        &[
            SitePart::Scope(scope),
            parent.map_or(SitePart::Null, SitePart::Identity),
            SitePart::Identity(identity),
        ],
    )
}

fn version_location<'a>(family: crate::storage::Family, key: &'a str, edition: &'a str, relation: &'static str) -> AuditSite<'a> {
    AuditSite::row(
        relation,
        &[
            SitePart::Text(family.name(), 21),
            SitePart::Text(key, 1024),
            SitePart::Text(edition, 1024),
        ],
    )
}

fn reference_location<'a>(scope: &'a EpochScope, identity: Identity, use_: &'a DeclarationUse) -> AuditSite<'a> {
    AuditSite::row(
        "pn_epoch_references",
        &[
            SitePart::Scope(scope),
            SitePart::Identity(identity),
            SitePart::Integer(use_.selected_at),
            SitePart::Text(use_.version.family.name(), 21),
            SitePart::Text(&use_.version.key, 1024),
        ],
    )
}

fn vintage_location<'a>(
    vintage: &'a DebitVintage,
    origin: Identity,
    relation: &'static str,
    slot: Option<usize>,
) -> AuditSite<'a> {
    debit_location(&vintage.key.scope, origin, &vintage.key.act, relation, slot)
}

fn debit_location<'a>(
    scope: &'a EpochScope,
    origin: Identity,
    act: &'a ActId,
    relation: &'static str,
    slot: Option<usize>,
) -> AuditSite<'a> {
    let mut parts = [SitePart::Empty; 6];
    parts[0] = SitePart::Scope(scope);
    parts[1] = SitePart::Identity(origin);
    parts[2] = SitePart::Text(&act.author, 1024);
    parts[3] = SitePart::Decimal(act.sequence);
    parts[4] = SitePart::Text(&act.family, 1024);
    if let Some(slot) = slot {
        parts[5] = SitePart::Integer(slot as u64);
        AuditSite::Row { relation, slots: parts }
    } else {
        AuditSite::Row { relation, slots: parts }
    }
}

fn result_location(scope: &EpochScope, identity: Identity) -> AuditSite<'_> {
    AuditSite::row("pn_epoch_results", &[SitePart::Scope(scope), SitePart::Identity(identity)])
}

fn generation_location<'a>(generation: &'a RawGeneration<'_>, relation: &'static str, slot: Option<usize>) -> AuditSite<'a> {
    let scope = SitePart::Text(&generation.key, 1024);
    let ordinal = SitePart::Integer(generation.declaration.ordinal);
    if let Some(slot) = slot {
        AuditSite::row(relation, &[scope, ordinal, SitePart::Integer(slot as u64)])
    } else {
        AuditSite::row(relation, &[scope, ordinal])
    }
}

fn generation_source_location(scope: &EpochScope, ordinal: u64) -> AuditSite<'_> {
    AuditSite::row(
        "pn_admission_generations",
        &[SitePart::Scope(scope), SitePart::Integer(ordinal)],
    )
}

fn generation_slot_location<'a>(scope: &'a EpochScope, ordinal: u64, relation: &'static str, slot: usize) -> AuditSite<'a> {
    AuditSite::row(
        relation,
        &[
            SitePart::Scope(scope),
            SitePart::Integer(ordinal),
            SitePart::Integer(slot as u64),
        ],
    )
}

pub(super) struct RawGeneration<'a> {
    pub key: String,
    pub declaration: &'a Generation,
    pub versions: Vec<&'a Version>,
    pub closures: Vec<&'a Closure>,
}

pub(super) struct RawScope<'a> {
    pub key: String,
    pub scope: &'a EpochScope,
    pub pointer: Identity,
}

pub(super) struct RawDescriptor<'a> {
    pub key: String,
    pub scope: &'a EpochScope,
    pub segment: Identity,
    pub first: Identity,
    pub start: u64,
    pub parent_segment: Option<Identity>,
    pub fork: Option<Identity>,
    pub cutoff: u64,
}

pub(super) struct RawSelection<'a> {
    pub use_: &'a DeclarationUse,
    pub origin: Identity,
}

pub(super) struct RawDebit<'a> {
    pub scope: &'a EpochScope,
    pub origin: Identity,
    pub act: &'a ActId,
    pub bytes: &'a [u8],
}

pub(super) struct RawExpectedDebit<'a> {
    pub act: &'a ActId,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy)]
pub(super) struct RawObservation<'a> {
    pub family: crate::storage::Family,
    pub key: &'a str,
    pub edition: &'a str,
    pub version: &'a Version,
}

pub(super) struct RawResult<'a> {
    pub key: String,
    pub scope: &'a EpochScope,
    pub identity: Identity,
    pub parent: Option<Identity>,
    pub depth: u64,
    pub segment: Identity,
    pub package: &'a [u8],
    pub label: &'a str,
    pub generation: u64,
    pub selections: Vec<RawSelection<'a>>,
    pub selection_order: Vec<usize>,
    pub observations: Vec<&'a crate::storage::Version>,
    pub local: Vec<RawDebit<'a>>,
    pub expected_debits: Vec<RawExpectedDebit<'a>>,
}

pub(super) struct Collected<'a> {
    pub generations: Vec<RawGeneration<'a>>,
    pub scopes: Vec<RawScope<'a>>,
    pub results: Vec<RawResult<'a>>,
    pub descriptors: Vec<RawDescriptor<'a>>,
}

/// Adapter-specific scans and physical checks; the graph, history, content order,
/// logical field tree and capacity reconciliation below are shared with the server.
pub(super) trait AuditSource<'a> {
    fn collect(&'a self, meter: &mut AuditMeter) -> Result<Collected<'a>, AuditFailure>;
    fn check_identity(&self, meter: &mut AuditMeter) -> Result<(), AuditFailure>;
    fn check_shapes(&self, rows: &Collected<'_>, meter: &mut AuditMeter) -> Result<(), AuditFailure>;
    fn check_generation_indices(&self, rows: &mut Collected<'a>, meter: &mut AuditMeter) -> Result<(), AuditFailure>;
    fn collect_descriptors(&'a self, rows: &mut Collected<'a>, meter: &mut AuditMeter) -> Result<(), AuditFailure>;
    fn check_reference_index(&self, rows: &Collected<'_>, meter: &mut AuditMeter) -> Result<(), AuditFailure>;
    fn check_segments(
        &self,
        rows: &Collected<'_>,
        children: &[Vec<usize>],
        segment_order: &[usize],
        meter: &mut AuditMeter,
    ) -> Result<(), AuditFailure>;
    fn check_content(
        &self,
        row: &RawResult<'_>,
        parent: Option<&RawResult<'_>>,
        meter: &mut AuditMeter,
    ) -> Result<(), AuditFailure>;
    fn context(&self, row: &RawResult<'_>, meter: &mut AuditMeter) -> Result<Value, AuditFailure>;
    fn collect_observations(&'a self, meter: &mut AuditMeter) -> Result<Vec<RawObservation<'a>>, AuditFailure>;
    fn check_enumeration(
        &self,
        rows: &Collected<'_>,
        children: &[Vec<usize>],
        meter: &mut AuditMeter,
    ) -> Result<(), AuditFailure>;
}

pub(super) fn reconcile<'a>(source: &'a impl AuditSource<'a>, meter: &mut AuditMeter) -> Result<AuditInventory, AuditFailure> {
    source.check_identity(meter)?;
    let mut rows = source.collect(meter)?;
    rows.generations.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    rows.scopes.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    rows.results
        .sort_unstable_by(|a, b| (&a.key, a.identity).cmp(&(&b.key, b.identity)));
    source.check_shapes(&rows, meter)?;
    check_generation(&rows, meter)?;
    source.check_generation_indices(&mut rows, meter)?;
    check_joins(&rows, meter)?;
    check_scope_roots(&rows, meter)?;
    let parents = parent_forest(&rows, meter)?;
    let ranks = ancestry_ranks(&rows, &parents, meter)?;
    let segment_order = check_descriptors(source, &mut rows, &parents, meter)?;
    source.check_segments(&rows, &ranks.children, &segment_order, meter)?;
    source.check_reference_index(&rows, meter)?;
    let (debits, mut contexts) = check_content(source, &rows, &parents, &ranks, meter)?;
    let observations = source.collect_observations(meter)?;
    check_observations(&rows, &observations, meter)?;
    source.check_enumeration(&rows, &ranks.children, meter)?;
    materialize(&rows, &parents, &ranks.children, &debits, &mut contexts, meter)
}

fn check_scope_roots(rows: &Collected<'_>, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
    for scope in &rows.scopes {
        let site = scope_location(scope.scope);
        meter.visit(site)?;
        meter.visit(site)?;
        let root = rows
            .results
            .binary_search_by(|row| (&row.key, row.identity).cmp(&(&scope.key, scope.pointer)))
            .ok()
            .and_then(|index| rows.results.get(index));
        if root.is_none_or(|row| row.parent.is_some()) {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
    }
    Ok(())
}

// Justified: One sorted member index reconciles every descriptor before physical indexes.
#[allow(clippy::too_many_lines)]
fn check_descriptors<'a>(
    source: &'a impl AuditSource<'a>,
    rows: &mut Collected<'a>,
    parents: &[Option<usize>],
    meter: &mut AuditMeter,
) -> Result<Vec<usize>, AuditFailure> {
    let mut segment_order = Vec::new();
    meter.reserve(&mut segment_order, rows.results.len(), AuditSite::NotRead)?;
    segment_order.extend(0..rows.results.len());
    segment_order.sort_unstable_by_key(|&at| {
        let row = &rows.results[at];
        (&row.key, row.segment, row.depth, row.identity)
    });
    source.collect_descriptors(rows, meter)?;
    rows.descriptors
        .sort_unstable_by(|a, b| (&a.key, a.segment).cmp(&(&b.key, b.segment)));
    let mut descriptor_count = 0usize;
    for descriptor in &rows.descriptors {
        let site = descriptor_location(descriptor.scope, descriptor.segment);
        descriptor_count = descriptor_count
            .checked_add(1)
            .ok_or_else(|| meter.refused(StorageError::ReadLimit, site))?;
        meter.visit(site)?;
        let first_index = segment_order.partition_point(|&at| {
            let row = &rows.results[at];
            (row.key.as_str(), row.segment) < (descriptor.key.as_str(), descriptor.segment)
        });
        meter.visit(site)?;
        let last_index = segment_order.partition_point(|&at| {
            let row = &rows.results[at];
            (row.key.as_str(), row.segment) <= (descriptor.key.as_str(), descriptor.segment)
        });
        let group = &segment_order[first_index..last_index];
        let Some(&first_at) = group.first() else {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        };
        let first = &rows.results[first_at];
        if descriptor.first != first.identity
            || descriptor.segment != first.identity
            || descriptor.start != first.depth
            || descriptor.fork != first.parent
            || descriptor.cutoff != first.depth - 1
        {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        let actual_parent_segment = parents[first_at].map(|at| rows.results[at].segment);
        if descriptor.parent_segment != actual_parent_segment {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        for pair in group.windows(2) {
            let before = &rows.results[pair[0]];
            let after = &rows.results[pair[1]];
            let location = result_location(after.scope, after.identity);
            meter.visit(location)?;
            if before.depth.checked_add(1) != Some(after.depth) || after.parent != Some(before.identity) {
                return Err(meter.refused(StorageError::CorruptHistory, location));
            }
        }
    }
    if descriptor_count > rows.results.len() {
        return Err(meter.refused(StorageError::CorruptHistory, AuditSite::NotRead));
    }
    for row in &rows.results {
        let site = result_location(row.scope, row.identity);
        meter.visit(site)?;
        meter.visit(site)?;
        if rows
            .descriptors
            .binary_search_by(|descriptor| (&descriptor.key, descriptor.segment).cmp(&(&row.key, row.segment)))
            .is_err()
        {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
    }
    Ok(segment_order)
}

fn check_joins(rows: &Collected<'_>, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
    for row in &rows.results {
        let site = result_location(row.scope, row.identity);
        meter.visit(site)?;
        meter.visit(site)?;
        if rows.scopes.binary_search_by(|scope| scope.key.cmp(&row.key)).is_err() {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        meter.visit(site)?;
        let Some(generation) = rows
            .generations
            .binary_search_by(|generation| generation.key.cmp(&row.key))
            .ok()
            .map(|at| &rows.generations[at])
        else {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        };
        if row.generation != generation.declaration.ordinal || row.label != generation.declaration.label {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
    }
    Ok(())
}

fn check_generation(rows: &Collected<'_>, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
    for generation in &rows.generations {
        let location = generation_location(generation, "pn_admission_generations", None);
        let location = meter.visit_at(location)?;
        if generation.declaration.check().is_err() {
            return Err(meter.refused(StorageError::CorruptHistory, location));
        }
    }
    Ok(())
}

fn parent_forest(rows: &Collected<'_>, meter: &mut AuditMeter) -> Result<Vec<Option<usize>>, AuditFailure> {
    let mut parents = Vec::new();
    meter.reserve(&mut parents, rows.results.len(), AuditSite::NotRead)?;
    for row in &rows.results {
        let location = result_location(row.scope, row.identity);
        meter.visit(location)?;
        if row.depth == 0 || (row.parent.is_none() != (row.depth == 1)) {
            return Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)));
        }
        let parent = if let Some(identity) = row.parent {
            {
                let location = result_location(row.scope, row.identity);
                meter.visit(location)?;
            }
            let at = rows
                .results
                .binary_search_by(|candidate| (&candidate.key, candidate.identity).cmp(&(&row.key, identity)))
                .map_err(|_| meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)))?;
            if rows.results[at].depth.checked_add(1) != Some(row.depth) {
                return Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)));
            }
            Some(at)
        } else {
            None
        };
        parents.push(parent);
    }
    Ok(parents)
}

struct Ranks {
    entry: Vec<usize>,
    exit: Vec<usize>,
    children: Vec<Vec<usize>>,
}

fn ancestry_ranks(rows: &Collected<'_>, parents: &[Option<usize>], meter: &mut AuditMeter) -> Result<Ranks, AuditFailure> {
    let count = rows.results.len();
    let mut children: Vec<Vec<usize>> = Vec::new();
    meter.reserve(&mut children, count, AuditSite::NotRead)?;
    children.resize_with(count, Vec::new);
    let mut roots = Vec::new();
    meter.reserve(&mut roots, count, AuditSite::NotRead)?;
    for (at, parent) in parents.iter().enumerate() {
        {
            let location = result_location(rows.results[at].scope, rows.results[at].identity);
            meter.visit(location)?;
        }
        if let Some(parent) = parent {
            let location = result_location(rows.results[at].scope, rows.results[at].identity);
            meter.reserve(&mut children[*parent], 1, location)?;
            children[*parent].push(at);
        } else {
            roots.push(at);
        }
    }
    let mut entry = Vec::new();
    let mut exit = Vec::new();
    meter.reserve(&mut entry, count, AuditSite::NotRead)?;
    meter.reserve(&mut exit, count, AuditSite::NotRead)?;
    entry.resize(count, 0);
    exit.resize(count, 0);
    let mut stack = Vec::new();
    let stack_capacity = count
        .checked_mul(2)
        .ok_or_else(|| meter.refused(StorageError::ReadLimit, AuditSite::NotRead))?;
    meter.reserve(&mut stack, stack_capacity, AuditSite::NotRead)?;
    let mut tick = 0usize;
    for root in roots.into_iter().rev() {
        stack.push((root, false));
    }
    while let Some((at, leaving)) = stack.pop() {
        {
            let location = result_location(rows.results[at].scope, rows.results[at].identity);
            meter.visit(location)?;
        }
        tick = tick
            .checked_add(1)
            .ok_or_else(|| meter.refused(StorageError::ReadLimit, AuditSite::NotRead))?;
        if leaving {
            exit[at] = tick;
        } else {
            entry[at] = tick;
            stack.push((at, true));
            for child in children[at].iter().rev() {
                stack.push((*child, false));
            }
        }
    }
    Ok(Ranks { entry, exit, children })
}

type ContentState<'a> = (Vec<Vec<RawDebit<'a>>>, Vec<Option<Value>>);

// Justified: The depth-ordered content pass keeps origin and debit refusal order visible in one item.
#[allow(clippy::too_many_lines)]
fn check_content<'a>(
    source: &impl AuditSource<'a>,
    rows: &Collected<'a>,
    parents: &[Option<usize>],
    ranks: &Ranks,
    meter: &mut AuditMeter,
) -> Result<ContentState<'a>, AuditFailure> {
    let mut order: Vec<usize> = Vec::new();
    meter.reserve(&mut order, rows.results.len(), AuditSite::NotRead)?;
    order.extend(0..rows.results.len());
    order.sort_unstable_by(|&a, &b| {
        (rows.results[a].depth, &rows.results[a].key, rows.results[a].identity).cmp(&(
            rows.results[b].depth,
            &rows.results[b].key,
            rows.results[b].identity,
        ))
    });
    let mut debits: Vec<Vec<RawDebit<'a>>> = Vec::new();
    meter.reserve(&mut debits, rows.results.len(), AuditSite::NotRead)?;
    debits.resize_with(rows.results.len(), Vec::new);
    let mut contexts = Vec::new();
    meter.reserve(&mut contexts, rows.scopes.len(), AuditSite::NotRead)?;
    contexts.resize_with(rows.scopes.len(), || None);
    for at in order {
        let row = &rows.results[at];
        let location = result_location(row.scope, row.identity);
        meter.visit(location)?;
        let parent = parents[at].map(|i| &rows.results[i]);
        source.check_content(row, parent, meter)?;
        let mut observed = row.observations.iter();
        for selection in &row.selections {
            if !unqualified(selection.use_.version.family) {
                let site = reference_location(row.scope, row.identity, selection.use_);
                meter.visit(site)?;
                let Some(version) = observed.next() else {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                };
                if *version != &selection.use_.version {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
            }
        }
        if observed.next().is_some() {
            return Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)));
        }
        for selection in &row.selections {
            let site = reference_location(row.scope, row.identity, selection.use_);
            meter.visit(site)?;
            let expected_origin = if unqualified(selection.use_.version.family) {
                let inherited = if let Some(prior) = parent {
                    meter.visit(site)?;
                    prior
                        .selection_order
                        .binary_search_by(|&index| coordinate(prior.selections[index].use_).cmp(&coordinate(selection.use_)))
                        .ok()
                        .map(|index| &prior.selections[prior.selection_order[index]])
                } else {
                    None
                };
                inherited.map_or(row.identity, |prior| prior.origin)
            } else {
                row.identity
            };
            if selection.origin != expected_origin {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
        }
        meter.visit(result_location(row.scope, row.identity))?;
        let scope_at = rows
            .scopes
            .binary_search_by(|candidate| candidate.key.cmp(&row.key))
            .map_err(|_| meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)))?;
        if parent.is_none() {
            let context = source.context(row, meter)?;
            if contexts[scope_at].is_none() {
                contexts[scope_at] = Some(context);
            } else if contexts[scope_at].as_ref() != Some(&context) {
                return Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)));
            }
        }
        if let Some(parent_at) = parents[at] {
            let (inherited, current) = if parent_at < at {
                let (before, after) = debits.split_at_mut(at);
                (&before[parent_at], &mut after[0])
            } else {
                let (before, after) = debits.split_at_mut(parent_at);
                (&after[0], &mut before[at])
            };
            let location = result_location(row.scope, row.identity);
            let capacity = inherited
                .len()
                .checked_add(row.local.len())
                .ok_or_else(|| meter.refused(StorageError::ReadLimit, location))?;
            meter.reserve(current, capacity, location)?;
            for debit in inherited {
                {
                    let location = result_location(row.scope, row.identity);
                    meter.visit(location)?;
                }
                current.push(RawDebit {
                    scope: debit.scope,
                    origin: debit.origin,
                    act: debit.act,
                    bytes: debit.bytes,
                });
            }
        } else {
            let location = result_location(row.scope, row.identity);
            meter.reserve(&mut debits[at], row.local.len(), location)?;
        }
        for debit in &row.local {
            {
                let location = result_location(row.scope, row.identity);
                meter.visit(location)?;
            }
            if debit.origin != row.identity || debit.scope != row.scope {
                return Err(meter.refused(
                    StorageError::CorruptHistory,
                    debit_location(debit.scope, debit.origin, debit.act, "pn_epoch_result_debits", None),
                ));
            }
            debits[at].push(RawDebit {
                scope: debit.scope,
                origin: debit.origin,
                act: debit.act,
                bytes: debit.bytes,
            });
        }
        debits[at].sort_unstable_by(|a, b| a.act.cmp(b.act));
        for pair in debits[at].windows(2) {
            let site = debit_location(pair[1].scope, pair[1].origin, pair[1].act, "pn_epoch_result_debits", None);
            meter.visit(site)?;
            if pair[0].act == pair[1].act {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
        }
        if debits[at].len() != row.expected_debits.len() {
            return Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)));
        }
        for (actual, expected) in debits[at].iter().zip(&row.expected_debits) {
            let site = debit_location(actual.scope, actual.origin, actual.act, "pn_epoch_result_debits", None);
            meter.visit(site)?;
            if actual.act != expected.act || actual.bytes != expected.bytes {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
        }
        for selection in &row.selections {
            {
                let location = result_location(row.scope, row.identity);
                meter.visit(location)?;
            }
            let origin = rows
                .results
                .binary_search_by(|candidate| (&candidate.key, candidate.identity).cmp(&(&row.key, selection.origin)))
                .map_err(|_| meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)))?;
            if !(ranks.entry[origin] <= ranks.entry[at] && ranks.exit[at] <= ranks.exit[origin]) {
                return Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)));
            }
        }
    }
    Ok((debits, contexts))
}

fn check_observations(rows: &Collected<'_>, actual: &[RawObservation<'_>], meter: &mut AuditMeter) -> Result<(), AuditFailure> {
    let capacity = rows.results.iter().try_fold(0usize, |total, row| {
        total
            .checked_add(row.observations.len())
            .ok_or_else(|| meter.refused(StorageError::ReadLimit, result_location(row.scope, row.identity)))
    })?;
    let mut expected = Vec::new();
    meter.reserve(&mut expected, capacity, AuditSite::NotRead)?;
    for row in &rows.results {
        for version in &row.observations {
            meter.visit(result_location(row.scope, row.identity))?;
            expected.push(RawObservation {
                family: version.family,
                key: &version.key,
                edition: &version.edition,
                version,
            });
        }
    }
    expected.sort_unstable_by(|a, b| (a.family, a.key, a.edition).cmp(&(b.family, b.key, b.edition)));
    for pair in expected.windows(2) {
        let site = version_location(pair[1].family, pair[1].key, pair[1].edition, "memory.observations");
        meter.visit(site)?;
        if (pair[0].family, pair[0].key, pair[0].edition) == (pair[1].family, pair[1].key, pair[1].edition) {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
    }
    for (index, observed) in actual.iter().enumerate() {
        let site = version_location(observed.family, observed.key, observed.edition, "memory.observations");
        meter.visit(site)?;
        let Some(wanted) = expected.get(index) else {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        };
        if (observed.family, observed.key, observed.edition) != (wanted.family, wanted.key, wanted.edition)
            || observed.version != wanted.version
        {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
    }
    if let Some(missing) = expected.get(actual.len()) {
        return Err(meter.refused(
            StorageError::CorruptHistory,
            version_location(missing.family, missing.key, missing.edition, "memory.observations"),
        ));
    }
    Ok(())
}

fn materialize(
    rows: &Collected<'_>,
    parents: &[Option<usize>],
    children: &[Vec<usize>],
    debits: &[Vec<RawDebit<'_>>],
    contexts: &mut [Option<Value>],
    meter: &mut AuditMeter,
) -> Result<AuditInventory, AuditFailure> {
    output::materialize(rows, parents, children, debits, contexts, meter)
}
