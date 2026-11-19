//! The additive single-law memory transaction; the chain store retains its contract.
//! (´[ROOT-amend:storage:admitted-transaction]´)

use super::{EpochScope, Family, ReadBudget, StorageError, Version};
use crate::admitted_result::{DebitVintage, DeclarationUse, position::Retained};
use index::Index;

mod index;
mod read;
pub use read::{DebitRead, Page, Reader, ResultRead};
mod audit;
pub use audit::{AuditBudget, AuditFailure, AuditInventory, AuditLocation, AuditUsage};
mod server;
pub use server::{ServerDebit, ServerJudgement, ServerReader, ServerResult, ServerSelection, ServerTree};
mod stage;

type Identity = [u8; 32];
type PlacementKey<'a> = (&'a EpochScope, Identity, u64);
type ChildKey<'a> = (&'a EpochScope, Option<Identity>, Identity);

/// An appended closure in an explicitly declared admission generation.
/// (´[ROOT-dec:storage:branch-declaration-authority]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Closure {
    pub family: Family,
    pub key: String,
    pub edition: String,
    pub closes_at: u64,
}

/// Complete declared input, with no default law, ordinal, minimum or delta.
/// (´[ROOT-dec:storage:branch-declaration-authority]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Generation {
    pub scope: EpochScope,
    pub ordinal: u64,
    pub minimum: u64,
    pub label: String,
    pub versions: Vec<Version>,
    pub closures: Vec<Closure>,
}

/// Tree input refusals remain distinct from damaged retained state and allowance exhaustion.
/// (´[ROOT-amend:storage:admitted-transaction]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAdmissionGeneration,
    AdmissionGenerationConflict,
    MissingGenerationLabel,
    UnknownGenerationLabel,
    ContextConflict,
    PredecessorMismatch,
    MissingTip,
    Storage(StorageError),
}

impl From<StorageError> for Error {
    /// Preserve the existing storage refusal without adding a new interpretation.
    /// (´[ROOT-amend:storage:admitted-transaction]´)
    /// Justified: Pure refusal wrapping inherits the caller's transaction observation.
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

/// Exact admitted requests, exposed without claiming an allocator census.
/// (´[ROOT-amend:storage:admitted-transaction]´)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub rows: usize,
    pub allocation_bytes: usize,
}

struct Meter {
    limit: ReadBudget,
    used: Usage,
}
impl Meter {
    fn row<T>(&mut self, fetch: impl FnOnce() -> T) -> Result<T, Error> {
        let next = self.used.rows.checked_add(1).ok_or(StorageError::ReadLimit)?;
        if next > self.limit.rows {
            return Err(StorageError::ReadLimit.into());
        }
        self.used.rows = next;
        Ok(fetch())
    }
    fn allocation(&mut self, bytes: usize) -> Result<(), Error> {
        let next = self.used.allocation_bytes.checked_add(bytes).ok_or(StorageError::ReadLimit)?;
        if next > self.limit.bytes {
            return Err(StorageError::ReadLimit.into());
        }
        #[cfg(test)]
        tests::allocation_request(bytes);
        self.used.allocation_bytes = next;
        Ok(())
    }
    fn reserve<T>(&mut self, out: &mut Vec<T>, additional: usize) -> Result<(), Error> {
        let capacity = out.len().checked_add(additional).ok_or(StorageError::ReadLimit)?;
        if capacity <= out.capacity() {
            return Ok(());
        }
        self.allocation(
            capacity
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(StorageError::ReadLimit)?,
        )?;
        out.reserve_exact(additional);
        Ok(())
    }
}

fn fields(scope: &EpochScope) -> [&str; 4] {
    [&scope.history, &scope.policy_identity, &scope.policy_edition, &scope.sequence]
}
fn scope_check(scope: &EpochScope) -> Result<(), Error> {
    let mut bytes = 2usize;
    for field in fields(scope) {
        super::stored_text(field)?;
        let digits = if field.is_empty() {
            1
        } else {
            field.len().ilog10() as usize + 1
        };
        bytes = bytes
            .checked_add(field.len())
            .and_then(|n| n.checked_add(digits + 1))
            .ok_or(StorageError::Representation)?;
    }
    if bytes > 1024 {
        return Err(StorageError::Representation.into());
    }
    Ok(())
}
fn member_scope(key: &str, scope: &EpochScope) -> bool {
    let Some((count, mut remaining)) = key.split_once(':') else {
        return false;
    };
    let Ok(count_value) = count.parse::<usize>() else {
        return false;
    };
    if count_value < 4 || count.starts_with('0') || count.starts_with('+') {
        return false;
    }
    let mut expected = fields(scope).into_iter();
    for _ in 0..count_value {
        let Some((size, rest)) = remaining.split_once(':') else {
            return false;
        };
        if size.starts_with('+') || (size.len() > 1 && size.starts_with('0')) {
            return false;
        }
        let Ok(size) = size.parse::<usize>() else { return false };
        let Some(value) = rest.get(..size) else { return false };
        if expected.next().is_some_and(|expected| value != expected) {
            return false;
        }
        let Some(rest) = rest.get(size..) else { return false };
        remaining = rest;
    }
    remaining.is_empty()
}
fn declaration_key(v: &Version) -> (&str, &str, &str) {
    (v.family.name(), &v.key, &v.edition)
}
fn closure_key(v: &Closure) -> (&str, &str, &str) {
    (v.family.name(), &v.key, &v.edition)
}
fn unqualified(family: Family) -> bool {
    matches!(family, Family::Rule | Family::Constants)
}
impl Generation {
    fn check(&self) -> Result<(), Error> {
        Self::check_parts(
            &self.scope,
            self.ordinal,
            self.minimum,
            &self.label,
            &self.versions,
            &self.closures,
        )
    }

    fn check_parts(
        scope: &EpochScope,
        ordinal: u64,
        minimum: u64,
        label: &str,
        versions: &[Version],
        closures: &[Closure],
    ) -> Result<(), Error> {
        scope_check(scope)?;
        super::stored_text(label)?;
        if ordinal > i64::MAX as u64 || minimum > i64::MAX as u64 || label.len() > 1024 {
            return Err(StorageError::Representation.into());
        }
        if ordinal != 1 || minimum != 1 || label != "unstable" {
            return Err(Error::InvalidAdmissionGeneration);
        }
        for v in versions {
            super::check(v)?;
            if !unqualified(v.family) || !member_scope(&v.key, scope) {
                return Err(Error::InvalidAdmissionGeneration);
            }
        }
        if versions.windows(2).any(|w| declaration_key(&w[0]) >= declaration_key(&w[1]))
            || closures.windows(2).any(|w| closure_key(&w[0]) >= closure_key(&w[1]))
        {
            return Err(Error::InvalidAdmissionGeneration);
        }
        for c in closures {
            super::stored_text(&c.key)?;
            super::stored_text(&c.edition)?;
            if c.closes_at > i64::MAX as u64 || c.key.len() > 1024 || c.edition.len() > 1024 {
                return Err(StorageError::Representation.into());
            }
            if !unqualified(c.family) || c.key.is_empty() || c.edition.is_empty() || !member_scope(&c.key, scope) {
                return Err(Error::InvalidAdmissionGeneration);
            }
            let Some(predecessor) = versions.iter().find(|v| declaration_key(v) == closure_key(c)) else {
                return Err(Error::InvalidAdmissionGeneration);
            };
            let Some(successor) = versions
                .iter()
                .find(|v| v.family == c.family && v.key == c.key && v.opens_at == c.closes_at)
            else {
                return Err(Error::InvalidAdmissionGeneration);
            };
            if predecessor.opens_at >= successor.opens_at || predecessor.announced_at > successor.announced_at {
                return Err(Error::InvalidAdmissionGeneration);
            }
        }
        for v in versions {
            if versions
                .iter()
                .any(|w| w.family == v.family && w.key == v.key && w.edition != v.edition && w.opens_at == v.opens_at)
            {
                return Err(Error::InvalidAdmissionGeneration);
            }
            let next = versions
                .iter()
                .filter(|w| w.family == v.family && w.key == v.key && w.opens_at > v.opens_at)
                .min_by_key(|w| w.opens_at);
            let close = closures.iter().find(|c| closure_key(c) == declaration_key(v));
            if next.map(|w| w.opens_at) != close.map(|c| c.closes_at) {
                return Err(Error::InvalidAdmissionGeneration);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Write {
    Generation,
    Version(usize),
    VersionIntroduction(usize),
    Closure(usize),
    ClosureIntroduction(usize),
    Publish,
    Scope,
    Segment,
    Result,
    Placement,
    DirectChild,
    PackageChunk(usize),
    Observation(usize),
    Reference(usize),
    Debit(usize),
    DebitChunk(usize, usize),
    Membership(usize),
}

#[derive(Debug)]
struct Installed<'a> {
    declaration: &'a Generation,
    versions: Vec<usize>,
    closures: Vec<usize>,
}

/// A functional reference retaining immutable caller capabilities for its lifetime.
/// No generation or label is installed by Default; all declarations are explicit inputs.
/// (´[ROOT-amend:storage:admitted-transaction]´)
#[derive(Debug, Default)]
pub struct MemoryTree<'a> {
    generations: Vec<Installed<'a>>,
    scopes: Index<&'a EpochScope, Identity>,
    segments: Index<(&'a EpochScope, Identity), Descriptor>,
    results: Index<(&'a EpochScope, Identity), Node<'a>>,
    placements: Index<PlacementKey<'a>, Identity>,
    direct_children: Index<ChildKey<'a>, ()>,
    children: Index<(&'a EpochScope, Identity), Identity>,
    observations: Index<(Family, &'a str, &'a str), &'a Version>,
    introductions: Index<(&'a EpochScope, Identity, u64), Identity>,
}

/// The retained selection and the result whose original judgement it preserves.
/// (´[ROOT-dec:storage:branch-declaration-authority]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selected<'a> {
    pub use_: &'a DeclarationUse,
    pub origin: [u8; 32],
}

/// A commit returns the exact recorded judgement, including on an unchanged retry.
/// (´[ROOT-dec:storage:public-generation-label]´)
#[derive(Debug, PartialEq, Eq)]
pub struct Judgement<'a> {
    pub label: &'a str,
    pub generation: u64,
    pub selections: &'a [Selected<'a>],
    pub inserted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Descriptor {
    first: Identity,
    start: u64,
    parent_segment: Option<Identity>,
    fork: Option<Identity>,
    cutoff: u64,
}
#[derive(Debug)]
struct Node<'a> {
    input: &'a Retained,
    label: &'a str,
    generation: u64,
    segment: Identity,
    chunks: Vec<&'a [u8]>,
    references: Vec<Selected<'a>>,
    reference_index: Vec<usize>,
    observations: Vec<&'a Version>,
    introductions: Vec<Introduction<'a>>,
}
#[derive(Clone, Debug)]
struct Introduction<'a> {
    origin: Identity,
    vintage: &'a DebitVintage,
    chunks: Vec<&'a [u8]>,
    member: bool,
}

#[derive(Clone, Copy)]
struct Range {
    segment: Identity,
    start: u64,
    end: u64,
}

fn coordinate(use_: &DeclarationUse) -> (Family, &str, u64) {
    (use_.version.family, &use_.version.key, use_.selected_at)
}

fn retained_bytes(parts: &[&[u8]], retained_length: usize, expected: &[u8], meter: &mut Meter) -> Result<bool, Error> {
    let mut bytes = Vec::new();
    meter.reserve(&mut bytes, retained_length)?;
    for part in parts {
        let part = meter.row(|| *part)?;
        if part.is_empty() || part.len() > super::MAX_PACKAGE || part.len() > retained_length.saturating_sub(bytes.len()) {
            return Err(StorageError::CorruptHistory.into());
        }
        bytes.extend_from_slice(part);
    }
    if bytes.len() != retained_length {
        return Err(StorageError::CorruptHistory.into());
    }
    Ok(bytes == expected)
}

fn checked_result_input<'a>(input: &Retained, label: Option<&'a str>) -> Result<&'a str, Error> {
    let (scope, _, parent, depth) = input.event();
    let label = label.ok_or(Error::MissingGenerationLabel)?;
    scope_check(scope)?;
    super::stored_text(label)?;
    super::stored_projection(input.declarations(), input.debits())?;
    if label.len() > 1024 || depth > i64::MAX as u64 {
        return Err(StorageError::Representation.into());
    }
    if label != "unstable" {
        return Err(Error::UnknownGenerationLabel);
    }
    if depth == 0 || (depth == 1) != parent.is_none() {
        return Err(Error::PredecessorMismatch);
    }
    if input
        .debits()
        .iter()
        .any(|vintage| i64::try_from(vintage.disclosure.boundary).is_err())
    {
        return Err(StorageError::Representation.into());
    }
    Ok(label)
}

impl<'a> MemoryTree<'a> {
    /// Reconcile one immutable memory tree into a complete owned logical inventory.
    /// (´[ROOT-amend:storage:tree-audit]´)
    /// # Errors
    /// Refuses the first damaged domain, exhausted allowance or admitted allocator refusal.
    pub fn audit(&self, budget: AuditBudget, usage: &mut AuditUsage) -> Result<AuditInventory, AuditFailure> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::tree::MemoryTree < 'a >::audit",
            &(budget,),
        );
        *usage = AuditUsage::default();
        let mut meter = audit::AuditMeter::new(budget);
        let result = meter.begin(budget).and_then(|()| audit::reconcile(self, &mut meter));
        *usage = meter.usage();
        operation.finish(&result);
        result
    }

    /// Commit a caller-owned retaining carrier under its explicit public label.
    /// Construction of the input is outside this budget; no carrier is reconstructed here.
    /// The store retains immutable borrows, so input custody outlives the store.
    /// (´[ROOT-amend:storage:admitted-transaction]´)
    /// # Errors
    /// Refuses input labels, incompatible ancestry, selected versions or vintages, damaged
    /// retained state, and each request beyond the caller's row or allocation allowance.
    /// # Panics
    /// Panics only if a private prepared-index invariant is broken, which caller input cannot arrange.
    pub fn commit(
        &mut self,
        input: &'a Retained,
        label: Option<&'a str>,
        budget: ReadBudget,
        usage: &mut Usage,
    ) -> Result<Judgement<'_>, Error> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::tree::MemoryTree < 'a >::commit",
            &(input, label, budget),
        );
        let mut meter = Meter {
            limit: budget,
            used: Usage::default(),
        };
        let result = self.commit_inner(input, label, &mut meter, &mut |_| Ok(()));
        *usage = meter.used;
        operation.finish(&result);
        result
    }

    fn commit_inner(
        &mut self,
        input: &'a Retained,
        label: Option<&'a str>,
        meter: &mut Meter,
        point: &mut impl FnMut(Write) -> Result<(), Error>,
    ) -> Result<Judgement<'_>, Error> {
        let (scope, identity, parent, depth) = input.event();
        let label = checked_result_input(input, label)?;
        let existing = meter.row(|| self.results.get(&(scope, *identity)))?;
        if let Some(existing) = existing {
            self.equal(existing, input, label, meter)?;
            return Ok(Judgement {
                label: existing.label,
                generation: existing.generation,
                selections: &existing.references,
                inserted: false,
            });
        }
        let context = meter.row(|| self.scopes.get(&scope))?;
        if let Some(context) = context {
            let first = meter
                .row(|| self.results.get(&(scope, *context)))?
                .ok_or(StorageError::CorruptHistory)?;
            if first.input.event().2.is_some() {
                return Err(StorageError::CorruptHistory.into());
            }
            if !input.same_context(first.input) {
                return Err(Error::ContextConflict);
            }
        }
        let prior = match parent {
            Some(parent) => {
                let prior = meter
                    .row(|| self.results.get(&(scope, *parent)))?
                    .ok_or(Error::PredecessorMismatch)?;
                if prior.input.event().3.checked_add(1) != Some(depth) {
                    return Err(StorageError::CorruptHistory.into());
                }
                if !input.extends(prior.input) {
                    return Err(Error::PredecessorMismatch);
                }
                Some(prior)
            }
            None => None,
        };
        let inherited = match prior {
            Some(prior) => self.ancestor_debits(prior, meter)?,
            None => Vec::new(),
        };
        let generation = self.installed(scope, meter)?.ok_or(if context.is_some() || prior.is_some() {
            Error::Storage(StorageError::CorruptHistory)
        } else {
            Error::UnknownGenerationLabel
        })?;
        if generation.declaration.ordinal != 1
            || generation.declaration.minimum != 1
            || generation.declaration.label != "unstable"
        {
            return Err(StorageError::CorruptHistory.into());
        }
        if prior.is_some_and(|p| p.generation != 1 || p.label != generation.declaration.label) {
            return Err(StorageError::CorruptHistory.into());
        }
        let (references, local) = self.resolve(input, prior, generation, &inherited, meter)?;
        let continuation = match parent {
            Some(parent) => !meter.row(|| self.children.contains_key(&(scope, *parent)))?,
            None => false,
        };
        let segment = if continuation {
            prior.ok_or(StorageError::CorruptHistory)?.segment
        } else {
            *identity
        };
        let descriptor = (!continuation).then_some(Descriptor {
            first: *identity,
            start: depth,
            parent_segment: prior.map(|p| p.segment),
            fork: parent.copied(),
            cutoff: depth - 1,
        });
        let plan = stage::Plan {
            input,
            generation: generation.declaration,
            segment,
            descriptor,
            new_scope: context.is_none(),
            references,
            local,
        };
        let slots = Publication::prepare(&plan, continuation, meter)?;
        // Admit the final result-slot lookup before staging: returning the judgement
        // executes that lookup without a fallible charge after publication.
        meter.row(|| ())?;
        let stage = stage::result(&plan, meter, point)?;
        Ok(self.publish(stage, descriptor, slots))
    }

    fn publish(&mut self, staged: stage::Staged<'a>, descriptor: Option<Descriptor>, slots: Publication<'a>) -> Judgement<'_> {
        let stage = staged.node;
        let (scope, identity, _, _) = stage.input.event();
        self.placements.publish(slots.placement, staged.placement.1);
        self.direct_children.publish(slots.direct_child, ());
        if let (Some(slot), Some(descriptor)) = (slots.segment, descriptor) {
            self.segments.publish(slot, descriptor);
        }
        if let Some(slot) = slots.scope {
            self.scopes.publish(slot, *identity);
        }
        if let Some(slot) = slots.child {
            self.children.publish(slot, *identity);
        }
        for (slot, &version) in slots.observations.into_iter().zip(&stage.observations) {
            self.observations.publish(slot, version);
        }
        if let Some(slot) = slots.introductions {
            self.introductions.publish(slot, *identity);
        }
        self.results.publish(slots.result, stage);
        let row = self
            .results
            .get(&(scope, *identity))
            .expect("published result slot has its value");
        Judgement {
            label: row.label,
            generation: row.generation,
            selections: &row.references,
            inserted: true,
        }
    }

    fn resolve(
        &self,
        input: &'a Retained,
        prior: Option<&Node<'a>>,
        generation: &Installed<'a>,
        inherited: &[&Introduction<'a>],
        meter: &mut Meter,
    ) -> Result<(Vec<Selected<'a>>, Vec<&'a DebitVintage>), Error> {
        let identity = input.event().1;
        let mut references = Vec::new();
        meter.reserve(&mut references, input.declarations().len())?;
        for use_ in input.declarations() {
            let origin = if unqualified(use_.version.family) {
                let inherited = prior
                    .map(|p| {
                        meter.row(|| {
                            p.reference_index
                                .binary_search_by(|&i| coordinate(p.references[i].use_).cmp(&coordinate(use_)))
                                .ok()
                                .map(|at| &p.references[p.reference_index[at]])
                        })
                    })
                    .transpose()?
                    .flatten();
                if let Some(inherited) = inherited {
                    if inherited.use_ != use_ {
                        return Err(StorageError::SelectedContentMismatch.into());
                    }
                    inherited.origin
                } else {
                    *identity
                }
            } else {
                if meter.row(|| {
                    self.observations
                        .contains_key(&(use_.version.family, &use_.version.key, &use_.version.edition))
                })? {
                    return Err(StorageError::CorruptHistory.into());
                }
                *identity
            };
            if unqualified(use_.version.family) {
                Self::selected(generation, use_, meter)?;
            }
            references.push(Selected { use_, origin });
        }
        let mut local = Vec::new();
        meter.reserve(&mut local, input.debits().len())?;
        for vintage in input.debits() {
            if let Some(old) = inherited.iter().find(|old| old.vintage.key.act == vintage.key.act) {
                if !retained_bytes(&old.chunks, old.vintage.bytes.len(), &vintage.bytes, meter)? {
                    return Err(StorageError::DebitConflict.into());
                }
            } else {
                local.push(vintage);
            }
        }
        if inherited
            .iter()
            .any(|old| !input.debits().iter().any(|v| v.key.act == old.vintage.key.act))
        {
            return Err(StorageError::DebitConflict.into());
        }
        Ok((references, local))
    }

    fn selected(generation: &Installed<'_>, use_: &DeclarationUse, meter: &mut Meter) -> Result<(), Error> {
        Self::selected_with_probes(generation, use_, meter, false)
    }

    // The reader opts into probe admission; the writer's established row charges stay unchanged.
    fn selected_with_probes(
        generation: &Installed<'_>,
        use_: &DeclarationUse,
        meter: &mut Meter,
        probes: bool,
    ) -> Result<(), Error> {
        let expected = &use_.version;
        let mut exact = None;
        let mut active = None;
        let key = (expected.family.name(), expected.key.as_str());
        let before = |index: usize, inclusive: bool| {
            let v = &generation.declaration.versions[index];
            let candidate = (v.family.name(), v.key.as_str());
            if inclusive { candidate <= key } else { candidate < key }
        };
        if probes {
            meter.row(|| ())?;
        }
        let start = generation.versions.partition_point(|&i| before(i, false));
        let end = generation.versions.partition_point(|&i| before(i, true));
        for &index in &generation.versions[start..end] {
            let v = meter
                .row(|| generation.declaration.versions.get(index))?
                .ok_or(StorageError::CorruptHistory)?;
            if v.family != expected.family || v.key != expected.key {
                continue;
            }
            if v.edition == expected.edition {
                exact = Some(v);
            }
            if probes {
                meter.row(|| ())?;
            }
            let end = generation
                .closures
                .binary_search_by(|&i| closure_key(&generation.declaration.closures[i]).cmp(&declaration_key(v)))
                .ok()
                .map(|i| meter.row(|| generation.declaration.closures[generation.closures[i]].closes_at))
                .transpose()?;
            if v.opens_at <= use_.selected_at && end.is_none_or(|e| use_.selected_at < e) {
                if active.is_some() {
                    return Err(StorageError::CorruptHistory.into());
                }
                active = Some(v);
            }
        }
        let exact = exact
            .filter(|v| v.payload.is_some())
            .ok_or(StorageError::MissingSelectedVersion)?;
        if exact != expected {
            return Err(StorageError::SelectedContentMismatch.into());
        }
        if active != Some(exact) {
            return Err(StorageError::SelectedVersionNotEffective.into());
        }
        Ok(())
    }

    fn ancestor_debits<'s>(&'s self, tip: &'s Node<'a>, meter: &mut Meter) -> Result<Vec<&'s Introduction<'a>>, Error> {
        self.ancestor_debits_with_probes(tip, meter, false)
    }

    fn ancestor_debits_with_probes<'s>(
        &'s self,
        tip: &'s Node<'a>,
        meter: &mut Meter,
        probes: bool,
    ) -> Result<Vec<&'s Introduction<'a>>, Error> {
        let scope = tip.input.event().0;
        let mut ranges = Vec::new();
        let mut segment = tip.segment;
        let mut cutoff = tip.input.event().3;
        loop {
            let descriptor = meter
                .row(|| self.segments.get(&(scope, segment)))?
                .ok_or(StorageError::CorruptHistory)?;
            let first = meter
                .row(|| self.results.get(&(scope, descriptor.first)))?
                .ok_or(StorageError::CorruptHistory)?;
            if first.segment != segment
                || descriptor.first != segment
                || first.input.event().3 != descriptor.start
                || first.input.event().2.copied() != descriptor.fork
                || descriptor.start > cutoff
            {
                return Err(StorageError::CorruptHistory.into());
            }
            meter.reserve(&mut ranges, 1)?;
            ranges.push(Range {
                segment,
                start: descriptor.start,
                end: cutoff,
            });
            match (descriptor.parent_segment, descriptor.fork) {
                (None, None) if descriptor.start == 1 && descriptor.cutoff == 0 => break,
                (Some(parent_segment), Some(parent)) => {
                    let parent = meter
                        .row(|| self.results.get(&(scope, parent)))?
                        .ok_or(StorageError::CorruptHistory)?;
                    if parent.segment != parent_segment
                        || parent.input.event().3 != descriptor.cutoff
                        || descriptor.cutoff.checked_add(1) != Some(descriptor.start)
                    {
                        return Err(StorageError::CorruptHistory.into());
                    }
                    segment = parent_segment;
                    cutoff = descriptor.cutoff;
                }
                _ => return Err(StorageError::CorruptHistory.into()),
            }
        }
        let mut result: Vec<&Introduction<'_>> = Vec::new();
        for range in ranges {
            if probes {
                meter.row(|| ())?;
            }
            self.introductions.visit(
                &(scope, range.segment, range.start),
                &(scope, range.segment, range.end),
                &mut |_, identity| {
                    let row = meter
                        .row(|| self.results.get(&(scope, *identity)))?
                        .ok_or(StorageError::CorruptHistory)?;
                    for introduction in &row.introductions {
                        let introduction = meter.row(|| introduction)?;
                        if !introduction.member
                            || introduction.origin != *row.input.event().1
                            || &introduction.vintage.key.scope != scope
                            || result.iter().any(|r| r.vintage.key.act == introduction.vintage.key.act)
                        {
                            return Err(StorageError::CorruptHistory.into());
                        }
                        meter.reserve(&mut result, 1)?;
                        result.push(introduction);
                    }
                    Ok(())
                },
            )?;
        }
        Ok(result)
    }

    fn equal(&self, row: &Node<'a>, input: &Retained, label: &str, meter: &mut Meter) -> Result<(), Error> {
        if row.label != "unstable" || row.generation != 1 {
            return Err(StorageError::CorruptHistory.into());
        }
        if row.label != label
            || row.input.event() != input.event()
            || !retained_bytes(&row.chunks, row.input.bytes().len(), input.bytes(), meter)?
        {
            return Err(StorageError::EpochConflict.into());
        }
        if row.references.len() != input.declarations().len() {
            return Err(StorageError::CorruptHistory.into());
        }
        for (actual, expected) in row.references.iter().zip(input.declarations()) {
            let actual = meter.row(|| actual)?;
            if actual.use_ != expected {
                return Err(StorageError::CorruptHistory.into());
            }
        }
        let debits = self.ancestor_debits(row, meter)?;
        if debits.len() != input.debits().len() {
            return Err(StorageError::CorruptHistory.into());
        }
        for debit in debits {
            let expected = input
                .debits()
                .iter()
                .find(|v| v.key.act == debit.vintage.key.act)
                .ok_or(StorageError::CorruptHistory)?;
            if !retained_bytes(&debit.chunks, debit.vintage.bytes.len(), &expected.bytes, meter)? {
                return Err(StorageError::CorruptHistory.into());
            }
        }
        Ok(())
    }
    /// Install the explicit first generation atomically, or compare an unchanged retry.
    /// The immutable input remains caller-owned; reads and staging reservations are metered.
    /// (´[ROOT-dec:storage:branch-declaration-authority]´)
    /// # Errors
    /// Refuses malformed or prohibited generations, a conflicting delta, or a storage limit.
    pub fn install_generation(&mut self, input: &'a Generation, budget: ReadBudget, usage: &mut Usage) -> Result<bool, Error> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::tree::MemoryTree < 'a >::install_generation",
            &(input, budget),
        );
        let mut meter = Meter {
            limit: budget,
            used: Usage::default(),
        };
        let result = self.install(input, &mut meter, &mut |_| Ok(()));
        *usage = meter.used;
        operation.finish(&result);
        result
    }

    fn install(
        &mut self,
        input: &'a Generation,
        meter: &mut Meter,
        point: &mut impl FnMut(Write) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        input.check()?;
        let existing = meter.row(|| {
            self.generations
                .binary_search_by(|g| g.declaration.scope.cmp(&input.scope))
                .ok()
                .map(|i| &self.generations[i])
        })?;
        if let Some(existing) = existing {
            for version in &existing.declaration.versions {
                meter.row(|| version)?;
            }
            for closure in &existing.declaration.closures {
                meter.row(|| closure)?;
            }
            return if existing.declaration == input {
                Ok(false)
            } else {
                Err(Error::AdmissionGenerationConflict)
            };
        }
        meter.reserve(&mut self.generations, 1)?;
        let stage = stage::generation(input, meter, point)?;
        let offset = self.generations.partition_point(|g| g.declaration.scope < input.scope);
        self.generations.insert(offset, stage);
        Ok(true)
    }

    fn installed(&self, scope: &EpochScope, meter: &mut Meter) -> Result<Option<&Installed<'a>>, Error> {
        meter.row(|| {
            self.generations
                .binary_search_by(|g| g.declaration.scope.cmp(scope))
                .ok()
                .map(|i| &self.generations[i])
        })
    }
}

#[cfg(test)]
mod roster;
#[cfg(test)]
mod tests;

struct Publication<'a> {
    placement: index::Slot<PlacementKey<'a>, Identity>,
    direct_child: index::Slot<ChildKey<'a>, ()>,
    result: index::Slot<(&'a EpochScope, Identity), Node<'a>>,
    scope: Option<index::Slot<&'a EpochScope, Identity>>,
    segment: Option<index::Slot<(&'a EpochScope, Identity), Descriptor>>,
    child: Option<index::Slot<(&'a EpochScope, Identity), Identity>>,
    observations: Vec<index::Slot<(Family, &'a str, &'a str), &'a Version>>,
    introductions: Option<index::Slot<(&'a EpochScope, Identity, u64), Identity>>,
}
impl<'a> Publication<'a> {
    fn prepare(plan: &stage::Plan<'a>, continuation: bool, meter: &mut Meter) -> Result<Self, Error> {
        let (scope, identity, parent, depth) = plan.input.event();
        let result = Index::prepare((scope, *identity), meter)?;
        let placement = Index::prepare((scope, plan.segment, depth), meter)?;
        let direct_child = Index::prepare((scope, parent.copied(), *identity), meter)?;
        let scope_slot = plan.new_scope.then(|| Index::prepare(scope, meter)).transpose()?;
        let segment = plan
            .descriptor
            .map(|_| Index::prepare((scope, plan.segment), meter))
            .transpose()?;
        let child = if continuation {
            parent.map(|p| Index::prepare((scope, *p), meter)).transpose()?
        } else {
            None
        };
        let mut observations = Vec::new();
        meter.reserve(
            &mut observations,
            plan.input
                .declarations()
                .iter()
                .filter(|u| !unqualified(u.version.family))
                .count(),
        )?;
        for use_ in plan.input.declarations().iter().filter(|u| !unqualified(u.version.family)) {
            observations.push(Index::prepare(
                (use_.version.family, use_.version.key.as_str(), use_.version.edition.as_str()),
                meter,
            )?);
        }
        let introductions = (!plan.local.is_empty())
            .then(|| Index::prepare((scope, plan.segment, depth), meter))
            .transpose()?;
        Ok(Self {
            placement,
            direct_child,
            result,
            scope: scope_slot,
            segment,
            child,
            observations,
            introductions,
        })
    }
}

#[cfg(test)]
pub(super) async fn prepare_reader_trace(name: &str) -> ServerTree {
    server::prepare_trace(name).await
}
#[cfg(test)]
pub(super) async fn reader_trace_fixture(store: &mut ServerTree) {
    server::trace_fixture(store).await;
}
