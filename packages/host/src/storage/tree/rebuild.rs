//! Explicitly premised fixture replay, prepared before any target write.
//! (´[ROOT-amend:storage:fixture-replay-interface]´)

use super::{
    AuditBudget, AuditFailure, AuditInventory, AuditUsage, EpochScope, Error as TreeError, Generation, MemoryTree, ReadBudget,
    Reader, ServerResult, ServerTree, StorageError, Usage, check_result_label_bound, check_result_label_name,
    compare_generation_declaration, generation_parts, require_result_label, scope_check,
};
use crate::admitted_result::{
    DeclarationUse,
    position::{self, Position, RECIPE, Retained},
};
use crate::publication::{self, Inspected};
use pn_epoch::publication::{self as epoch_publication, AdmittedPackage, Verifier, disclosures};
use pn_interchange::EncodingUsage;
use pn_records::{numerics::NumericContext, solve::AttemptStop};

type Identity = [u8; 32];

/// One asserted selected declaration and its explicitly asserted origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertedUse {
    pub declaration: DeclarationUse,
    pub origin: Identity,
}

/// A complete asserted result, separate from a store judgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayAssertion<'a> {
    pub label: Option<&'a str>,
    pub ordinal: u64,
    pub scope: EpochScope,
    pub identity: Identity,
    pub parent: Option<Identity>,
    pub depth: u64,
    pub uses: &'a [AssertedUse],
}

/// Original bytes and their independently supplied assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayEntry<'a> {
    pub bytes: &'a [u8],
    pub assertion: ReplayAssertion<'a>,
}

/// Finite borrowed fixture input; none of its borrows survive preparation.
#[derive(Clone, Copy, Debug)]
pub struct ReplayInput<'a> {
    pub generations: &'a [Generation],
    pub entries: &'a [ReplayEntry<'a>],
}

/// The existing numerical, position and reservation resources of one preparation.
pub struct ReplayPreparation<'a> {
    pub numeric: &'a mut NumericContext,
    pub encoding_usage: &'a mut EncodingUsage,
    pub reservation: &'a mut dyn FnMut(usize) -> Result<(), ()>,
    pub limits: disclosures::Limits,
    pub position_ceiling: usize,
}

/// The receiving phase in which a distinct cause was first observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayPhase {
    Inspection,
    Declaration,
    Association,
    ParentIndex,
    Decode,
    SuppliedEvidence,
    Restore,
    Position,
    Retention,
    PrewriteComparison,
    ExecutionStart,
    TargetOpening,
    Installation,
    Commit,
    PostcommitComparison,
    Audit,
    FinalComparison,
}

/// The supplied or observed key at a replay refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayCoordinate {
    Declaration(usize),
    Entry(usize),
    Key(EpochScope, Identity),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Association {
    Label,
    Scope,
    Ordinal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch {
    Bytes,
    Identity,
    Scope,
    Depth,
    References,
    Coordinates,
    Judgement,
    Origins,
    Inventory,
    TipRead,
}

/// Existing owner causes remain nested, not recast as stored corruption.
#[derive(Debug)]
pub enum ReplayCause {
    Decode(publication::Error),
    Tree(TreeError),
    Association(Association),
    ConflictingDuplicate,
    MissingParent,
    ParentCycle,
    SuppliedWorkStop,
    Restore(epoch_publication::Error),
    Position(position::Error),
    Retain(crate::admitted_result::CarrierError),
    Mismatch(Mismatch),
    ResourcesUnspecified,
    ReferenceMismatch,
    TargetNotEmpty,
    TargetInterference,
    Audit(AuditFailure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetDisposition {
    NotTouched,
    RejectedNonempty,
    MustDiscard,
}

#[derive(Debug)]
pub struct ReplayFailure {
    pub phase: ReplayPhase,
    pub coordinate: Option<ReplayCoordinate>,
    pub cause: ReplayCause,
    pub disposition: TargetDisposition,
}

fn refuse(phase: ReplayPhase, coordinate: Option<ReplayCoordinate>, cause: ReplayCause) -> ReplayFailure {
    ReplayFailure {
        phase,
        coordinate,
        cause,
        disposition: TargetDisposition::NotTouched,
    }
}

fn key(entry: &ReplayEntry<'_>) -> ReplayCoordinate {
    ReplayCoordinate::Key(entry.assertion.scope.clone(), entry.assertion.identity)
}

fn supplied_work_stop(disclosure: &disclosures::Disclosure) -> bool {
    let has_stop = |standing: &pn_records::conserved::SolveRecord| {
        standing
            .fence
            .attempts
            .iter()
            .any(|attempt| attempt.stop == AttemptStop::WorkLimit)
    };
    disclosure
        .frames
        .iter()
        .any(|frame| has_stop(&frame.standing) || frame.closure.final_gates.standing.as_ref().is_some_and(has_stop))
}

/// Complete all preparation phases before making any target available.
/// (´[ROOT-amend:storage:fixture-replay-interface]´)
/// # Errors
/// Returns the first phase-ordered typed refusal and no prepared owner.
// Justified: The admitted failure table keeps nested owner errors in its required owned representation.
#[expect(clippy::result_large_err)]
pub fn prepare(
    input: ReplayInput<'_>,
    verifier: &impl Verifier,
    resources: &mut ReplayPreparation<'_>,
) -> Result<PreparedReplay, ReplayFailure> {
    let operation = cli_common::observation::scope(
        "HOST",
        "sig:design:storage",
        "storage::tree::rebuild::prepare",
        &(input.generations.len(), input.entries.len()),
    );
    let result = prepare_inner(input, verifier, resources);
    operation.finish(&result.as_ref().map(|_| ()));
    result
}

// Justified: The admitted owned errors and ordered preparation phases preserve the required table and first refusal.
#[expect(clippy::result_large_err, clippy::too_many_lines)]
fn prepare_inner(
    input: ReplayInput<'_>,
    verifier: &impl Verifier,
    resources: &mut ReplayPreparation<'_>,
) -> Result<PreparedReplay, ReplayFailure> {
    let mut inspected: Vec<Inspected> = Vec::with_capacity(input.entries.len());
    for (index, entry) in input.entries.iter().enumerate() {
        inspected.push(publication::inspect(entry.bytes).map_err(|cause| {
            refuse(
                ReplayPhase::Inspection,
                Some(ReplayCoordinate::Entry(index)),
                ReplayCause::Decode(cause),
            )
        })?);
    }

    for (index, entry) in input.entries.iter().enumerate() {
        let assertion = &entry.assertion;
        let label = require_result_label(assertion.label).map_err(|cause| {
            refuse(
                ReplayPhase::Declaration,
                Some(ReplayCoordinate::Entry(index)),
                ReplayCause::Tree(cause),
            )
        })?;
        scope_check(&assertion.scope)
            .and_then(|()| super::super::stored_text(label).map_err(TreeError::from))
            .and_then(|()| check_result_label_bound(label))
            .and_then(|()| {
                if assertion.depth > i64::MAX as u64 {
                    Err(StorageError::Representation.into())
                } else {
                    Ok(())
                }
            })
            .and_then(|()| check_result_label_name(label))
            .map_err(|cause| {
                refuse(
                    ReplayPhase::Declaration,
                    Some(ReplayCoordinate::Entry(index)),
                    ReplayCause::Tree(cause),
                )
            })?;
    }

    let mut generations: Vec<Generation> = Vec::new();
    for (index, declaration) in input.generations.iter().enumerate() {
        declaration.check().map_err(|cause| {
            refuse(
                ReplayPhase::Declaration,
                Some(ReplayCoordinate::Declaration(index)),
                ReplayCause::Tree(cause),
            )
        })?;
        if let Some(existing) = generations
            .iter()
            .find(|g| g.scope == declaration.scope && g.ordinal == declaration.ordinal)
        {
            compare_generation_declaration(generation_parts(existing), generation_parts(declaration)).map_err(|cause| {
                refuse(
                    ReplayPhase::Declaration,
                    Some(ReplayCoordinate::Declaration(index)),
                    ReplayCause::Tree(cause),
                )
            })?;
        } else {
            generations.push(declaration.clone());
        }
    }
    if generations.is_empty() {
        return Err(refuse(
            ReplayPhase::Declaration,
            None,
            ReplayCause::Tree(TreeError::InvalidAdmissionGeneration),
        ));
    }
    for (index, entry) in input.entries.iter().enumerate() {
        if !generations.iter().any(|g| g.scope == entry.assertion.scope) {
            return Err(refuse(
                ReplayPhase::Declaration,
                Some(ReplayCoordinate::Entry(index)),
                ReplayCause::Tree(TreeError::InvalidAdmissionGeneration),
            ));
        }
    }
    generations.sort_by(|a, b| super::framed_scope_cmp(&a.scope, &b.scope));

    for (index, entry) in input.entries.iter().enumerate() {
        let declaration = generations
            .iter()
            .find(|g| g.scope == entry.assertion.scope)
            .expect("declaration checked above");
        if entry.assertion.ordinal != declaration.ordinal {
            return Err(refuse(
                ReplayPhase::Association,
                Some(ReplayCoordinate::Entry(index)),
                ReplayCause::Association(Association::Ordinal),
            ));
        }
    }

    let mut sorted: Vec<usize> = (0..input.entries.len()).collect();
    sorted.sort_by(|a, b| {
        let a = &input.entries[*a].assertion;
        let b = &input.entries[*b].assertion;
        super::framed_scope_cmp(&a.scope, &b.scope).then_with(|| a.identity.cmp(&b.identity))
    });
    let mut unique: Vec<usize> = Vec::new();
    for index in sorted {
        if let Some(previous) = unique.last().copied() {
            let a = &input.entries[previous];
            let b = &input.entries[index];
            if a.assertion.scope == b.assertion.scope && a.assertion.identity == b.assertion.identity {
                if a != b {
                    return Err(refuse(
                        ReplayPhase::ParentIndex,
                        Some(key(b)),
                        ReplayCause::ConflictingDuplicate,
                    ));
                }
                continue;
            }
        }
        unique.push(index);
    }
    for index in &unique {
        let entry = &input.entries[*index];
        if let Some(parent) = entry.assertion.parent
            && !unique.iter().any(|other| {
                let candidate = &input.entries[*other].assertion;
                candidate.scope == entry.assertion.scope && candidate.identity == parent
            })
        {
            return Err(refuse(ReplayPhase::ParentIndex, Some(key(entry)), ReplayCause::MissingParent));
        }
    }
    let mut order: Vec<usize> = Vec::with_capacity(unique.len());
    while order.len() < unique.len() {
        let ready = unique.iter().copied().find(|index| {
            if order.contains(index) {
                return false;
            }
            let entry = &input.entries[*index].assertion;
            entry.parent.is_none_or(|parent| {
                order.iter().any(|previous| {
                    let prior = &input.entries[*previous].assertion;
                    prior.scope == entry.scope && prior.identity == parent
                })
            })
        });
        let Some(index) = ready else {
            let unresolved = unique
                .iter()
                .find(|index| !order.contains(index))
                .expect("not all results ordered");
            return Err(refuse(
                ReplayPhase::ParentIndex,
                Some(key(&input.entries[*unresolved])),
                ReplayCause::ParentCycle,
            ));
        };
        order.push(index);
    }

    let mut disclosures = Vec::with_capacity(order.len());
    for index in &order {
        disclosures.push(
            publication::decode_inspected(&inspected[*index], resources.numeric, resources.limits.clone()).map_err(|cause| {
                refuse(
                    ReplayPhase::Decode,
                    Some(key(&input.entries[*index])),
                    ReplayCause::Decode(cause),
                )
            })?,
        );
    }
    for (ordinal, disclosure) in disclosures.iter().enumerate() {
        if supplied_work_stop(disclosure) {
            return Err(refuse(
                ReplayPhase::SuppliedEvidence,
                Some(key(&input.entries[order[ordinal]])),
                ReplayCause::SuppliedWorkStop,
            ));
        }
    }
    let mut packages: Vec<AdmittedPackage> = Vec::with_capacity(order.len());
    for (ordinal, disclosure) in disclosures.into_iter().enumerate() {
        packages.push(disclosures::restore(disclosure, verifier).map_err(|cause| {
            refuse(
                ReplayPhase::Restore,
                Some(key(&input.entries[order[ordinal]])),
                ReplayCause::Restore(cause),
            )
        })?);
    }

    let mut positions = Vec::with_capacity(order.len());
    for (ordinal, index) in order.iter().enumerate() {
        let assertion = &input.entries[*index].assertion;
        let parent = assertion.parent.and_then(|identity| {
            positions.iter().enumerate().find_map(|(previous, _)| {
                let candidate = &input.entries[order[previous]].assertion;
                (candidate.scope == assertion.scope && candidate.identity == identity).then_some(previous)
            })
        });
        let position = Position::from_package(
            &packages[ordinal],
            parent.map(|previous| &positions[previous]),
            RECIPE,
            resources.position_ceiling,
            resources.encoding_usage,
            &mut *resources.reservation,
        )
        .map_err(|cause| {
            refuse(
                ReplayPhase::Position,
                Some(key(&input.entries[*index])),
                ReplayCause::Position(cause),
            )
        })?;
        positions.push(position);
    }
    let mut results = Vec::with_capacity(order.len());
    for (ordinal, index) in order.iter().enumerate() {
        let retained =
            Retained::from_position(&positions[ordinal], resources.numeric, resources.limits.clone()).map_err(|cause| {
                refuse(
                    ReplayPhase::Retention,
                    Some(key(&input.entries[*index])),
                    ReplayCause::Retain(cause),
                )
            })?;
        let assertion = &input.entries[*index].assertion;
        results.push(PreparedResult {
            retained,
            label: assertion.label.expect("label checked above").to_owned(),
            ordinal: assertion.ordinal,
            asserted: assertion.uses.to_vec(),
        });
    }
    drop(positions);
    drop(packages);

    for (ordinal, index) in order.iter().enumerate() {
        let entry = &input.entries[*index];
        let asserted = &entry.assertion;
        let retained = &results[ordinal].retained;
        let (scope, identity, parent, depth) = retained.event();
        let mismatch = if retained.bytes() != entry.bytes {
            Some(Mismatch::Bytes)
        } else if *identity != asserted.identity {
            Some(Mismatch::Identity)
        } else if scope != &asserted.scope {
            Some(Mismatch::Scope)
        } else if depth != asserted.depth || parent.copied() != asserted.parent {
            Some(Mismatch::Depth)
        } else if retained.declarations().len() != asserted.uses.len()
            || retained
                .declarations()
                .iter()
                .zip(asserted.uses)
                .any(|(actual, expected)| actual.version != expected.declaration.version)
        {
            Some(Mismatch::References)
        } else if retained
            .declarations()
            .iter()
            .zip(asserted.uses)
            .any(|(actual, expected)| actual.selected_at != expected.declaration.selected_at)
        {
            Some(Mismatch::Coordinates)
        } else {
            None
        };
        if let Some(mismatch) = mismatch {
            return Err(refuse(
                ReplayPhase::PrewriteComparison,
                Some(key(entry)),
                ReplayCause::Mismatch(mismatch),
            ));
        }
    }
    let mut reader_order: Vec<usize> = (0..results.len()).collect();
    reader_order.sort_by(|a, b| {
        let a = results[*a].retained.event();
        let b = results[*b].retained.event();
        super::framed_scope_cmp(a.0, b.0).then_with(|| a.1.cmp(b.1))
    });
    Ok(PreparedReplay {
        generations,
        results,
        reader_order,
    })
}

struct PreparedResult {
    retained: Retained,
    label: String,
    ordinal: u64,
    asserted: Vec<AssertedUse>,
}

/// Owned, immutable result and declaration input after all pre-write checks.
pub struct PreparedReplay {
    generations: Vec<Generation>,
    results: Vec<PreparedResult>,
    reader_order: Vec<usize>,
}

impl PreparedReplay {
    /// Coalesced declaration and result counts for a caller's complete schedule.
    /// Justified: Immutable prepared replay inspection inherits the enclosing preparation observation.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.generations.len(), self.results.len())
    }

    /// Framed declaration order used by installation budgets.
    /// Justified: Immutable prepared replay inspection inherits the enclosing preparation observation.
    pub fn declaration_scopes(&self) -> impl Iterator<Item = &EpochScope> {
        self.generations.iter().map(|g| &g.scope)
    }

    /// Parent-before-child order used by commit budgets.
    /// Justified: Immutable prepared replay inspection inherits the enclosing preparation observation.
    pub fn commit_order(&self) -> impl Iterator<Item = (&EpochScope, Identity, u64)> {
        self.results.iter().map(|r| {
            let (scope, identity, _, depth) = r.retained.event();
            (scope, *identity, depth)
        })
    }

    /// Framed scope and identity order used by reader budgets.
    /// Justified: Immutable prepared replay inspection inherits the enclosing preparation observation.
    pub fn reader_order(&self) -> impl Iterator<Item = (&EpochScope, Identity, u64)> {
        self.reader_order.iter().map(|index| {
            let (scope, identity, _, depth) = self.results[*index].retained.event();
            (scope, *identity, depth)
        })
    }
}

/// Call-indexed allowances; the whole route shape is checked before a target exists.
pub struct ReplaySchedule {
    pub installation: Vec<ReadBudget>,
    pub commit: Vec<ReadBudget>,
    pub target_read: Vec<ReadBudget>,
    pub reference_read: Vec<ReadBudget>,
    pub opening_audit: Option<AuditBudget>,
    pub final_audit: AuditBudget,
}

/// Retained usage of every attempted call; absent slots were not attempted.
#[derive(Default)]
pub struct ReplayUsage {
    pub installation: Vec<Option<Usage>>,
    pub commit: Vec<Option<Usage>>,
    pub target_read: Vec<Option<Usage>>,
    pub reference_read: Vec<Option<Usage>>,
    pub opening_audit: Option<AuditUsage>,
    pub final_audit: Option<AuditUsage>,
}

pub struct ReplayExecution<'a> {
    pub schedule: &'a ReplaySchedule,
    pub usage: &'a mut ReplayUsage,
}

/// A completed, audited memory reference borrows its prepared owner for every retained writer input.
pub struct CompletedMemory<'p> {
    prepared: &'p PreparedReplay,
    tree: MemoryTree<'p>,
    inventory: AuditInventory,
}

/// An in-process server replay whose complete target inventory was compared with memory.
pub struct ReplayComplete {
    inventory: AuditInventory,
}

impl ReplayComplete {
    /// Inspect the successfully compared target inventory.
    /// Justified: Immutable replay completion inspection inherits the enclosing server replay observation.
    #[must_use]
    pub fn inventory(&self) -> &AuditInventory {
        &self.inventory
    }
}

impl<'p> CompletedMemory<'p> {
    /// Justified: Immutable replay completion inspection inherits the enclosing memory replay observation.
    #[must_use]
    pub fn inventory(&self) -> &AuditInventory {
        &self.inventory
    }

    /// Justified: A completed memory reader inherits the enclosing memory replay observation.
    #[must_use]
    pub fn reader(&self, budget: ReadBudget) -> Reader<'_, 'p> {
        self.tree.reader(budget)
    }

    /// Justified: Immutable prepared owner inspection inherits the enclosing memory replay observation.
    #[must_use]
    pub fn prepared(&self) -> &PreparedReplay {
        self.prepared
    }
}

fn after_write(phase: ReplayPhase, coordinate: Option<ReplayCoordinate>, cause: ReplayCause) -> ReplayFailure {
    ReplayFailure {
        phase,
        coordinate,
        cause,
        disposition: TargetDisposition::MustDiscard,
    }
}

fn result_key(result: &PreparedResult) -> ReplayCoordinate {
    let (scope, identity, _, _) = result.retained.event();
    ReplayCoordinate::Key(scope.clone(), *identity)
}

fn expected_debit_origin(
    prepared: &PreparedReplay,
    index: usize,
    vintage: &crate::admitted_result::DebitVintage,
) -> Option<Identity> {
    let mut current = Some(index);
    let mut origin = None;
    while let Some(at) = current {
        let result = &prepared.results[at];
        if result.retained.debits().iter().any(|candidate| candidate == vintage) {
            origin = Some(*result.retained.event().1);
        }
        let (scope, _, parent, _) = result.retained.event();
        current = parent.and_then(|parent| {
            prepared.results.iter().position(|candidate| {
                let (other_scope, identity, _, _) = candidate.retained.event();
                other_scope == scope && identity == parent
            })
        });
    }
    origin
}

fn read_matches(prepared: &PreparedReplay, index: usize, read: &super::ResultRead<'_>) -> bool {
    let expected = &prepared.results[index];
    let (scope, identity, parent, depth) = expected.retained.event();
    if read.identity != *identity
        || read.parent != parent.copied()
        || read.depth != depth
        || read.label != expected.label
        || read.generation != expected.ordinal
        || read.bytes != expected.retained.bytes()
        || read.selections.len() != expected.asserted.len()
        || read.debits.len() != expected.retained.debits().len()
    {
        return false;
    }
    if read
        .selections
        .iter()
        .zip(&expected.asserted)
        .any(|(actual, asserted)| actual.use_ != &asserted.declaration || actual.origin != asserted.origin)
    {
        return false;
    }
    if read.debits.iter().any(|actual| {
        actual.vintage.key.scope != *scope
            || !expected.retained.debits().iter().any(|vintage| {
                vintage == actual.vintage
                    && vintage.bytes == actual.bytes
                    && expected_debit_origin(prepared, index, vintage) == Some(actual.origin)
            })
    }) {
        return false;
    }
    true
}

fn same_logical_read(scope: &EpochScope, memory: Option<&super::ResultRead<'_>>, server: Option<&ServerResult>) -> bool {
    match (memory, server) {
        (None, None) => true,
        (Some(memory), Some(server)) => {
            memory.identity == server.identity
                && memory.parent == server.parent
                && memory.depth == server.depth
                && memory.label == server.label
                && memory.generation == server.generation
                && memory.bytes == server.bytes
                && memory.selections.len() == server.selections.len()
                && memory
                    .selections
                    .iter()
                    .zip(&server.selections)
                    .all(|(left, right)| left.use_ == &right.use_ && left.origin == right.origin)
                && memory.debits.len() == server.debits.len()
                && memory.debits.iter().zip(&server.debits).all(|(left, right)| {
                    left.vintage.key.scope == *scope
                        && left.vintage.key.act == right.act
                        && left.vintage.disclosure.boundary == right.writing_boundary
                        && left.origin == right.origin
                        && left.bytes == right.bytes
                })
        }
        _ => false,
    }
}

fn ancestor_at(prepared: &PreparedReplay, tip_index: usize, depth: u64) -> Option<usize> {
    let mut current = Some(tip_index);
    while let Some(index) = current {
        let (scope, _, parent, actual_depth) = prepared.results[index].retained.event();
        if actual_depth == depth {
            return Some(index);
        }
        current = parent.and_then(|parent| {
            prepared.results.iter().position(|candidate| {
                let (other_scope, identity, _, _) = candidate.retained.event();
                other_scope == scope && identity == parent
            })
        });
    }
    None
}

/// Replay into a fresh internal memory target, then audit and compare every exact and tip-relative read.
/// (´[ROOT-amend:storage:fixture-replay-interface]´)
/// # Errors
/// Reports the first writer, audit or comparison refusal with the target disposition.
// Justified: The admitted failure table keeps nested owner errors in its required owned representation.
#[expect(clippy::result_large_err)]
pub fn replay_memory<'p>(
    prepared: &'p PreparedReplay,
    resources: &mut ReplayExecution<'_>,
) -> Result<CompletedMemory<'p>, ReplayFailure> {
    let operation = cli_common::observation::scope(
        "HOST",
        "sig:design:storage",
        "storage::tree::rebuild::replay_memory",
        &prepared.counts(),
    );
    let result = replay_memory_inner(prepared, resources);
    operation.finish(&result.as_ref().map(|_| ()));
    result
}

// Justified: The admitted owned errors and fixed writer schedule preserve the required table and call order.
#[expect(clippy::result_large_err, clippy::too_many_lines)]
fn replay_memory_inner<'p>(
    prepared: &'p PreparedReplay,
    resources: &mut ReplayExecution<'_>,
) -> Result<CompletedMemory<'p>, ReplayFailure> {
    let (generations, results) = prepared.counts();
    *resources.usage = ReplayUsage::default();
    if resources.schedule.installation.len() != generations
        || resources.schedule.commit.len() != results
        || resources.schedule.target_read.len() != results
        || !resources.schedule.reference_read.is_empty()
        || resources.schedule.opening_audit.is_some()
    {
        return Err(refuse(ReplayPhase::ExecutionStart, None, ReplayCause::ResourcesUnspecified));
    }
    resources.usage.installation.resize(generations, None);
    resources.usage.commit.resize(results, None);
    resources.usage.target_read.resize(results, None);
    let mut tree = MemoryTree::default();
    for (index, generation) in prepared.generations.iter().enumerate() {
        let mut usage = Usage::default();
        let attempt = tree.install_generation(generation, resources.schedule.installation[index], &mut usage);
        resources.usage.installation[index] = Some(usage);
        let inserted = attempt.map_err(|cause| after_write(ReplayPhase::Installation, None, ReplayCause::Tree(cause)))?;
        if !inserted {
            return Err(after_write(ReplayPhase::Installation, None, ReplayCause::TargetInterference));
        }
    }
    for (index, result) in prepared.results.iter().enumerate() {
        let mut usage = Usage::default();
        let attempt = tree.commit(
            &result.retained,
            Some(&result.label),
            resources.schedule.commit[index],
            &mut usage,
        );
        resources.usage.commit[index] = Some(usage);
        let judgement =
            attempt.map_err(|cause| after_write(ReplayPhase::Commit, Some(result_key(result)), ReplayCause::Tree(cause)))?;
        if !judgement.inserted {
            return Err(after_write(
                ReplayPhase::Commit,
                Some(result_key(result)),
                ReplayCause::TargetInterference,
            ));
        }
        if judgement.label != result.label
            || judgement.generation != result.ordinal
            || judgement.selections.len() != result.asserted.len()
            || judgement
                .selections
                .iter()
                .zip(&result.asserted)
                .any(|(actual, expected)| actual.use_ != &expected.declaration)
        {
            return Err(after_write(
                ReplayPhase::PostcommitComparison,
                Some(result_key(result)),
                ReplayCause::Mismatch(Mismatch::Judgement),
            ));
        }
        if judgement
            .selections
            .iter()
            .zip(&result.asserted)
            .any(|(actual, expected)| actual.origin != expected.origin)
        {
            return Err(after_write(
                ReplayPhase::PostcommitComparison,
                Some(result_key(result)),
                ReplayCause::Mismatch(Mismatch::Origins),
            ));
        }
    }
    let mut audit_usage = AuditUsage::default();
    let audited = tree.audit(resources.schedule.final_audit, &mut audit_usage);
    resources.usage.final_audit = Some(audit_usage);
    let inventory = audited.map_err(|cause| after_write(ReplayPhase::Audit, None, ReplayCause::Audit(cause)))?;
    for (slot, index) in prepared.reader_order.iter().copied().enumerate() {
        let result = &prepared.results[index];
        let (scope, identity, _, depth) = result.retained.event();
        let mut reader = tree.reader(resources.schedule.target_read[slot]);
        let compared = (|| {
            let exact = reader.exact(scope, *identity)?;
            if !exact.as_ref().is_some_and(|read| read_matches(prepared, index, read)) {
                return Ok(Some(Mismatch::Bytes));
            }
            for height in 0..=depth {
                let actual = reader.as_of(scope, *identity, height)?;
                let expected = ancestor_at(prepared, index, height);
                if !matches!((actual.as_ref(), expected), (None, None))
                    && !matches!((actual.as_ref(), expected), (Some(read), Some(expected)) if read_matches(prepared, expected, read))
                {
                    return Ok(Some(Mismatch::TipRead));
                }
            }
            Ok(None)
        })();
        resources.usage.target_read[slot] = Some(reader.usage());
        let mismatch = compared.map_err(|cause| {
            after_write(
                ReplayPhase::FinalComparison,
                Some(result_key(result)),
                ReplayCause::Tree(cause),
            )
        })?;
        if let Some(mismatch) = mismatch {
            return Err(after_write(
                ReplayPhase::FinalComparison,
                Some(result_key(result)),
                ReplayCause::Mismatch(mismatch),
            ));
        }
    }
    Ok(CompletedMemory {
        prepared,
        tree,
        inventory,
    })
}

/// Replay the same prepared input into an exclusively reserved empty server target.
/// (´[ROOT-amend:storage:fixture-replay-interface]´)
/// # Errors
/// Returns the first typed opening, writer, audit or paired-read refusal with its target disposition.
// Justified: The admitted failure table keeps nested owner errors in its required owned representation.
#[expect(clippy::result_large_err)]
pub async fn replay_server(
    prepared: &PreparedReplay,
    target: &mut ServerTree,
    reference: &CompletedMemory<'_>,
    resources: &mut ReplayExecution<'_>,
) -> Result<ReplayComplete, ReplayFailure> {
    let operation = cli_common::observation::scope(
        "HOST",
        "sig:design:storage",
        "storage::tree::rebuild::replay_server",
        &prepared.counts(),
    );
    let result = replay_server_inner(prepared, target, reference, resources).await;
    operation.finish(&result.as_ref().map(|_| ()));
    result
}

// Justified: The admitted owned errors and fixed server schedule keep every call and its first refusal in one visible order.
#[expect(clippy::result_large_err, clippy::too_many_lines)]
async fn replay_server_inner(
    prepared: &PreparedReplay,
    target: &mut ServerTree,
    reference: &CompletedMemory<'_>,
    resources: &mut ReplayExecution<'_>,
) -> Result<ReplayComplete, ReplayFailure> {
    let (generations, results) = prepared.counts();
    *resources.usage = ReplayUsage::default();
    if resources.schedule.installation.len() != generations
        || resources.schedule.commit.len() != results
        || resources.schedule.target_read.len() != results
        || resources.schedule.reference_read.len() != results
        || resources.schedule.opening_audit.is_none()
    {
        return Err(refuse(ReplayPhase::ExecutionStart, None, ReplayCause::ResourcesUnspecified));
    }
    if !std::ptr::eq(prepared, reference.prepared) {
        return Err(refuse(ReplayPhase::ExecutionStart, None, ReplayCause::ReferenceMismatch));
    }
    resources.usage.installation.resize(generations, None);
    resources.usage.commit.resize(results, None);
    resources.usage.target_read.resize(results, None);
    resources.usage.reference_read.resize(results, None);

    let mut opening_usage = AuditUsage::default();
    let opening = target
        .audit(resources.schedule.opening_audit.unwrap(), &mut opening_usage)
        .await;
    resources.usage.opening_audit = Some(opening_usage);
    let opening = opening.map_err(|cause| refuse(ReplayPhase::TargetOpening, None, ReplayCause::Audit(cause)))?;
    if opening.counts().0 != 0 || opening.counts().1 != 0 || opening.counts().2 != 0 || opening.counts().3 != 0 {
        return Err(ReplayFailure {
            phase: ReplayPhase::TargetOpening,
            coordinate: None,
            cause: ReplayCause::TargetNotEmpty,
            disposition: TargetDisposition::RejectedNonempty,
        });
    }

    for (index, generation) in prepared.generations.iter().enumerate() {
        let mut usage = Usage::default();
        let attempt = target
            .install_generation(generation, resources.schedule.installation[index], &mut usage)
            .await;
        resources.usage.installation[index] = Some(usage);
        let inserted = attempt.map_err(|cause| after_write(ReplayPhase::Installation, None, ReplayCause::Tree(cause)))?;
        if !inserted {
            return Err(after_write(ReplayPhase::Installation, None, ReplayCause::TargetInterference));
        }
    }
    for (index, result) in prepared.results.iter().enumerate() {
        let mut usage = Usage::default();
        let attempt = target
            .commit(
                &result.retained,
                Some(&result.label),
                resources.schedule.commit[index],
                &mut usage,
            )
            .await;
        resources.usage.commit[index] = Some(usage);
        let judgement =
            attempt.map_err(|cause| after_write(ReplayPhase::Commit, Some(result_key(result)), ReplayCause::Tree(cause)))?;
        if !judgement.inserted {
            return Err(after_write(
                ReplayPhase::Commit,
                Some(result_key(result)),
                ReplayCause::TargetInterference,
            ));
        }
        if judgement.label != result.label
            || judgement.generation != result.ordinal
            || judgement.selections.len() != result.asserted.len()
            || judgement
                .selections
                .iter()
                .zip(&result.asserted)
                .any(|(actual, expected)| actual.use_ != &expected.declaration)
        {
            return Err(after_write(
                ReplayPhase::PostcommitComparison,
                Some(result_key(result)),
                ReplayCause::Mismatch(Mismatch::Judgement),
            ));
        }
        if judgement
            .selections
            .iter()
            .zip(&result.asserted)
            .any(|(actual, expected)| actual.origin != expected.origin)
        {
            return Err(after_write(
                ReplayPhase::PostcommitComparison,
                Some(result_key(result)),
                ReplayCause::Mismatch(Mismatch::Origins),
            ));
        }
    }

    let mut audit_usage = AuditUsage::default();
    let audited = target.audit(resources.schedule.final_audit, &mut audit_usage).await;
    resources.usage.final_audit = Some(audit_usage);
    let inventory = audited.map_err(|cause| after_write(ReplayPhase::Audit, None, ReplayCause::Audit(cause)))?;
    if inventory != *reference.inventory() {
        return Err(after_write(
            ReplayPhase::FinalComparison,
            None,
            ReplayCause::Mismatch(Mismatch::Inventory),
        ));
    }

    for (slot, index) in prepared.reader_order.iter().copied().enumerate() {
        let result = &prepared.results[index];
        let (scope, identity, _, depth) = result.retained.event();
        let mut memory_reader = reference.reader(resources.schedule.reference_read[slot]);
        let opened = target.reader(resources.schedule.target_read[slot]).await;
        let mut server_reader = match opened {
            Ok(reader) => reader,
            Err(cause) => {
                resources.usage.reference_read[slot] = Some(memory_reader.usage());
                resources.usage.target_read[slot] = Some(Usage::default());
                return Err(after_write(
                    ReplayPhase::FinalComparison,
                    Some(result_key(result)),
                    ReplayCause::Tree(cause),
                ));
            }
        };
        let compared: Result<Option<Mismatch>, TreeError> = async {
            let memory = memory_reader.exact(scope, *identity)?;
            let server = server_reader.exact(scope, *identity).await?;
            if !same_logical_read(scope, memory.as_ref(), server.as_ref()) {
                return Ok(Some(Mismatch::Bytes));
            }
            for height in 0..=depth {
                let memory = memory_reader.as_of(scope, *identity, height)?;
                let server = server_reader.as_of(scope, *identity, height).await?;
                if !same_logical_read(scope, memory.as_ref(), server.as_ref()) {
                    return Ok(Some(Mismatch::TipRead));
                }
            }
            Ok(None)
        }
        .await;
        resources.usage.reference_read[slot] = Some(memory_reader.usage());
        resources.usage.target_read[slot] = Some(server_reader.usage());
        let ended = server_reader.end().await;
        match compared {
            Err(cause) => {
                return Err(after_write(
                    ReplayPhase::FinalComparison,
                    Some(result_key(result)),
                    ReplayCause::Tree(cause),
                ));
            }
            Ok(Some(mismatch)) => {
                return Err(after_write(
                    ReplayPhase::FinalComparison,
                    Some(result_key(result)),
                    ReplayCause::Mismatch(mismatch),
                ));
            }
            Ok(None) => ended.map_err(|cause| {
                after_write(
                    ReplayPhase::FinalComparison,
                    Some(result_key(result)),
                    ReplayCause::Tree(cause),
                )
            })?,
        }
    }
    Ok(ReplayComplete { inventory })
}

#[cfg(test)]
mod tests;
