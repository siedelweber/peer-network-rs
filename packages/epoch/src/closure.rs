//! Whole membership and consecutive marker registration around atomic admission.
//! (´[ROOT-alg:design:closure-registration]´)

use crate::{admission, package, schedules, solve};
use pn_graph::{DependencyBlocks, registration::RegistrationVerifier};
use pn_records::{CandidateAct, CandidateLeg, PublicReference, burn::RecognizedMarkers};
use std::collections::BTreeSet;

/// One candidate, its declared whole-act partition, led schedule and preceding close.
/// No demand set or timestamp-derived claim of earliest determination is supplied.
/// (´[ROOT-alg:design:closure-registration]´)
#[derive(Debug)]
pub struct ClosureInput<'a> {
    pub candidate: &'a package::CandidateContext,
    pub partition: &'a DependencyBlocks,
    pub schedule: &'a schedules::CheckedSchedule,
    pub previous: Option<&'a ClosedBoundary>,
}

/// Replayable public closure evidence; a standalone record grants no admission authority.
/// (´[ROOT-alg:design:closure-registration]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosureRecord {
    pub markers: RecognizedMarkers,
    pub bindings: Vec<package::EpochBinding>,
    pub statement: package::ClosureStatement,
    pub partition: DependencyBlocks,
    pub final_gates: admission::FinalEvidence,
    pub schedule: schedules::Record,
}

/// A registered local close, constructed only after membership and final admission pass.
/// It does not persist or authenticate a deployment publication.
/// (´[ROOT-alg:design:closure-registration]´)
#[derive(Debug)]
pub struct ClosedBoundary {
    admitted: package::AdmittedBoundary,
    record: ClosureRecord,
}

/// Closure, evidence and operational failures are not unresolved numeric comparisons.
/// (´[ROOT-alg:design:closure-registration]´)
#[derive(Debug, thiserror::Error)]
pub enum ClosureError {
    #[error("closure requires the next recognized marker, without skipping or repeating")]
    MarkerOrder,
    #[error("closure components do not retain one common predecessor context")]
    Context,
    #[error("the supplied partition omits, repeats or separates a dependent block")]
    Membership,
    #[error("candidate dependency formation: {0}")]
    Records(#[source] Box<pn_records::ValidationError>),
    #[error("dependent-set partition: {0}")]
    Partition(#[from] pn_graph::PartitionError),
    #[error("final admission: {0}")]
    Admission(#[source] Box<admission::FinalRefusal>),
    #[error("closure replay evidence differs")]
    Evidence,
}

fn raw(act: &pn_records::ValidatedAct) -> CandidateAct {
    CandidateAct {
        commitments: act.commitments().cloned(),
        id: act.id().clone(),
        body: act.body().clone(),
        legs: act
            .legs()
            .iter()
            .map(|leg| CandidateLeg {
                id: leg.id().clone(),
                source: leg.source().clone(),
                target: leg.target().clone(),
                removal: None,
            })
            .collect(),
        projections: act.projections().clone(),
        protocol_references: act.protocol_references().to_vec(),
        authentication_evidence: act.authentication_evidence().to_vec(),
        finalization_epoch: act.finalization_epoch(),
        authoritative_position: act.authoritative_position(),
        logical_time: act.logical_time(),
    }
}

fn records(candidate: &package::CandidateContext) -> Result<pn_records::ValidatedRecords, ClosureError> {
    let source = &candidate.input().causes;
    let boundary = source.bindings.last().ok_or(ClosureError::MarkerOrder)?.marker.index;
    let all: Vec<_> = source.history.acts().iter().map(raw).collect();
    let names: BTreeSet<_> = all
        .iter()
        .flat_map(|act| {
            act.legs
                .iter()
                .flat_map(|leg| [&leg.source, &leg.target])
                .chain(act.protocol_references.iter())
        })
        .filter(|name| matches!(name, PublicReference::Named { .. }))
        .cloned()
        .collect();
    let (past, proposed): (Vec<_>, Vec<_>) = all.into_iter().partition(|act| act.finalization_epoch < boundary);
    let history = pn_records::validate_history(&past, &names.into_iter().collect::<Vec<_>>())
        .map_err(|e| ClosureError::Records(Box::new(e)))?;
    pn_records::validate_record(&proposed, &history, &[]).map_err(|e| ClosureError::Records(Box::new(e)))
}

/// Revalidate current proposed dependencies against the fixed pre-epoch history and
/// consume the existing graph exact-cover partition. Earlier current blocks never become history.
/// (´[ROOT-alg:design:closure-registration]´)
/// # Errors
/// Returns a missing-current-parent, co-leg, placement or exact-cover refusal.
#[tracing::instrument(
    name = "alg:design:admission",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "alg:design:admission",
        source_item = "closure::partition"
    ),
    ret
)]
pub fn partition(candidate: &package::CandidateContext) -> Result<DependencyBlocks, ClosureError> {
    let records = records(candidate)?;
    let boundary = candidate
        .input()
        .causes
        .bindings
        .last()
        .ok_or(ClosureError::MarkerOrder)?
        .marker
        .index;
    let inputs = pn_records::assemble_boundary_inputs(&records, (boundary, 1)).map_err(|e| ClosureError::Records(Box::new(e)))?;
    Ok(pn_graph::partition_dependencies(&inputs)?.1)
}

fn block_sets(blocks: &DependencyBlocks) -> Option<BTreeSet<BTreeSet<pn_records::ActId>>> {
    let mut seen = BTreeSet::new();
    let mut result = BTreeSet::new();
    for block in blocks {
        if block.is_empty() || !block.iter().all(|act| seen.insert(act.clone())) {
            return None;
        }
        result.insert(block.iter().cloned().collect());
    }
    Some(result)
}

fn context(input: &ClosureInput<'_>) -> Result<DependencyBlocks, ClosureError> {
    let source = &input.candidate.input().causes;
    let last = source.bindings.last().ok_or(ClosureError::MarkerOrder)?;
    let previous = input.previous.map(|prior| &prior.admitted.candidate().input().causes);
    let expected = previous.map_or(Some(1), |prior| {
        prior.bindings.last().and_then(|p| p.marker.index.checked_add(1))
    });
    if Some(last.marker.index) != expected {
        return Err(ClosureError::MarkerOrder);
    }
    if previous.is_some_and(|prior| !package::same_prefix(prior, source)) {
        return Err(ClosureError::Context);
    }
    let schedule = input.schedule.record();
    if let Some(previous) = input.previous {
        let closure = &input.candidate.input().closure;
        if closure.opened_at != previous.record.statement.determined_at
            || closure.policy.clock != previous.record.statement.policy.clock
        {
            return Err(ClosureError::Context);
        }
        let prior = &previous.record.schedule;
        if schedule.declaration != prior.declaration
            || schedule.initial != prior.initial
            || schedule.publications.get(..prior.publications.len()) != Some(prior.publications.as_slice())
        {
            return Err(ClosureError::Context);
        }
    } else if schedule.initial.boundary != 1 {
        return Err(ClosureError::Context);
    }
    let expected = partition(input.candidate)?;
    if block_sets(input.partition) != block_sets(&expected) {
        return Err(ClosureError::Membership);
    }
    Ok(expected)
}

/// Bind a complete candidate to consecutive marker registration, the declared partition,
/// attested closure conditions and all final gates without changing the preceding close.
/// Candidate verification already checked the declared closure verifier against this exact input.
/// (´[ROOT-alg:design:closure-registration]´)
/// # Errors
/// Refuses marker order, changed predecessor context, incomplete blocks or any final gate.
#[tracing::instrument(
    name = "alg:design:admission",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "alg:design:admission",
        source_item = "closure::close"
    ),
    ret
)]
pub fn close(
    input: &ClosureInput<'_>,
    procedure: &admission::FinalProcedure,
    registration: &impl RegistrationVerifier,
    published: &impl solve::ProcedureVerifier,
    numeric: pn_records::numerics::NumericContext,
) -> Result<ClosedBoundary, ClosureError> {
    let partition = context(input)?;
    let admitted = admission::admit(input.candidate, input.schedule, procedure, registration, published, numeric)
        .map_err(|e| ClosureError::Admission(Box::new(e)))?;
    let source = &input.candidate.input().causes;
    let record = ClosureRecord {
        markers: source.markers.clone(),
        bindings: source.bindings.clone(),
        statement: input.candidate.input().closure.clone(),
        partition,
        final_gates: admitted.evidence().clone(),
        schedule: input.schedule.record().clone(),
    };
    Ok(ClosedBoundary { admitted, record })
}

/// Independently recompute closure and final admission against the supplied common context.
/// A valid numerical record from another context is refused before it can supply a gate.
/// (´[ROOT-alg:design:closure-registration]´)
/// # Errors
/// Refuses a context or evidence substitution and every refusal of close.
#[tracing::instrument(
    name = "alg:design:admission",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "alg:design:admission",
        source_item = "closure::replay"
    ),
    ret
)]
pub fn replay(
    input: &ClosureInput<'_>,
    procedure: &admission::FinalProcedure,
    registration: &impl RegistrationVerifier,
    published: &impl solve::ProcedureVerifier,
    numeric: pn_records::numerics::NumericContext,
    supplied: &ClosureRecord,
) -> Result<ClosedBoundary, ClosureError> {
    let source = &input.candidate.input().causes;
    if supplied.schedule != *input.schedule.record()
        || supplied.markers != source.markers
        || supplied.bindings != source.bindings
        || supplied.statement != input.candidate.input().closure
    {
        return Err(ClosureError::Context);
    }
    let result = close(input, procedure, registration, published, numeric)?;
    if result.record != *supplied {
        return Err(ClosureError::Evidence);
    }
    Ok(result)
}

impl ClosedBoundary {
    pub(crate) fn admitted(&self) -> &package::AdmittedBoundary {
        &self.admitted
    }

    /// Borrow the immutable registered record; this access creates no authority.
    /// (´[ROOT-alg:design:closure-registration]´)
    /// Justified: Immutable evidence access inherits complete closure and admission.
    #[must_use]
    pub fn record(&self) -> &ClosureRecord {
        &self.record
    }
}
