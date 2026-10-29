//! Complete-act inputs for scoped settlement recognition.
//! (´def:formation:title-inputs´)

use std::collections::{BTreeMap, BTreeSet};

use pn_records::{ActId, PublicReference, SettlementReferences, ValidatedHistory};

use crate::formation::{FormationGraph, validate_formation};
use crate::registration::{RegistrationError, RegistrationVerifier};

/// Structural indexes derived after whole-history formation revalidation.
/// These public values are evidence outputs, not a reusable validation token.
/// (´def:formation:title-inputs´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TitleInputs {
    /// Every complete authored identity, including parallel records.
    pub acts: BTreeSet<ActId>,
    /// Self-minting Item terms and their genesis Owner acts.
    pub genesis: BTreeMap<PublicReference, ActId>,
    /// Each Bid identity and the Item named by its A-leg.
    pub bids: BTreeMap<ActId, PublicReference>,
    /// Accept and Ratify identities with their exact structural references.
    pub settlements: BTreeMap<ActId, SettlementReferences>,
}

/// Revalidate all families before deriving complete-act title indexes.
/// Opening removal changes neither these indexes nor structural identity.
/// This operation makes no recognition, time-compliance or title verdict.
/// (´def:formation:title-inputs´)
///
/// # Errors
/// Returns the whole-result formation refusal for an incomplete, altered or
/// unauthorized graph or history, including unauthorized opening removal.
#[tracing::instrument(
    name = "alg:design:formation",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:formation",
        source_item = "title::title_inputs"
    ),
    ret
)]
pub fn title_inputs(
    graph: &FormationGraph,
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
) -> Result<TitleInputs, RegistrationError> {
    let result = validate_formation(graph, history, verifier).map(|()| {
        let mut inputs = TitleInputs {
            acts: BTreeSet::new(),
            genesis: BTreeMap::new(),
            bids: BTreeMap::new(),
            settlements: BTreeMap::new(),
        };
        for act in history.acts() {
            inputs.acts.insert(act.id().clone());
            if let Some(references) = &act.body().settlement {
                inputs.settlements.insert(act.id().clone(), references.clone());
            }
            for leg in act.legs() {
                if act.id().family == "Owner" && leg.target() == &PublicReference::Minted(act.id().clone()) {
                    inputs.genesis.insert(leg.target().clone(), act.id().clone());
                }
                if act.id().family == "Bid" && leg.id().role == pn_records::Role::A {
                    inputs.bids.insert(act.id().clone(), leg.target().clone());
                }
            }
        }
        inputs
    });
    if result.is_err() {
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}

/// One boundary's derived recognition premises and resulting title certificate.
/// Missing owners are represented explicitly by None for encountered Item terms.
/// (´def:formation:boundary-title´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TitleBoundary {
    /// Immediately preceding ownership and consumption, extended by fresh genesis.
    pub premises: crate::recognition::RecognitionContext,
    /// Complete attempted-candidate evidence, including non-binding attempts.
    pub candidates: Vec<crate::recognition::SettlementEvidence>,
    /// Certified owners after this boundary; unresolved genesis remains None.
    pub certificate: BTreeMap<PublicReference, Option<String>>,
    /// All records consumed through this boundary, not just whole-triple keys.
    pub consumed: BTreeSet<ActId>,
}

/// Pure full replay; public evidence is not a token authorizing publication.
/// (´def:formation:boundary-title´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TitleReplay {
    /// Requested final boundary.
    pub epoch: u64,
    /// Final certificate, including void entries for unresolved Item terms.
    pub certificate: BTreeMap<PublicReference, Option<String>>,
    /// Distinct records permanently excluded from later recognition.
    pub consumed: BTreeSet<ActId>,
    /// Boundary-by-boundary recognition premises and fold evidence.
    pub boundaries: Vec<TitleBoundary>,
    /// Persistent recognized-event evidence, independent of the final owner.
    pub events: Vec<TitleEvent>,
}

/// Revalidate complete formation and replay compliant boundary title and consumption.
/// New genesis supplies the fresh-thread owner when its epoch first enters history;
/// ordinary Owner acts never replace title. No certificate is published by this API.
/// (´def:formation:boundary-title´)
///
/// # Errors
/// Returns whole-result formation refusal or the recognition hold for unavailable or
/// mismatched recurrence evidence. No partial certificate escapes an unsuccessful replay.
#[tracing::instrument(
    name = "alg:design:title",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:title",
        source_item = "title::replay_title"
    ),
    ret
)]
pub fn replay_title(
    graph: &FormationGraph,
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
    epoch: u64,
) -> Result<TitleReplay, crate::recognition::RecognitionError> {
    let result = title_inputs(graph, history, verifier)
        .map_err(crate::recognition::RecognitionError::Formation)
        .and_then(|inputs| fold_title(graph, history, verifier, &inputs, epoch));
    if result.is_err() {
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}

fn fold_title(
    graph: &FormationGraph,
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
    inputs: &TitleInputs,
    epoch: u64,
) -> Result<TitleReplay, crate::recognition::RecognitionError> {
    use crate::recognition::{RecognitionContext, RecognitionError, recognize_settlements};
    let acts: BTreeMap<_, _> = history.acts().iter().map(|act| (act.id(), act)).collect();
    let holds: Vec<_> = history
        .time_evidence()
        .iter()
        .filter(|evidence| {
            acts.get(&evidence.act).is_some_and(|act| act.finalization_epoch() <= epoch)
                && evidence.verdict != pn_records::TimeVerdict::Matches
        })
        .cloned()
        .collect();
    if !holds.is_empty() {
        return Err(RecognitionError::Held(holds));
    }
    let mut replay = TitleReplay {
        epoch,
        certificate: BTreeMap::new(),
        consumed: BTreeSet::new(),
        boundaries: vec![],
        events: vec![],
    };
    introduce_items(&mut replay.certificate, history, inputs, 0);
    for boundary in 1..=epoch {
        introduce_items(&mut replay.certificate, history, inputs, boundary);
        let premises = RecognitionContext {
            epoch: boundary,
            prior_epoch: boundary - 1,
            owners: replay
                .certificate
                .iter()
                .filter_map(|(item, owner)| owner.as_ref().map(|owner| (item.clone(), owner.clone())))
                .collect(),
            consumed: replay.consumed.clone(),
        };
        let candidates = recognize_settlements(graph, history, verifier, &premises)?;
        let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for candidate in &candidates {
            if candidate.recognized
                && let Some(item) = &candidate.item
            {
                groups.entry(item.clone()).or_default().push(candidate);
            }
        }
        for (item, members) in groups {
            if let [sole] = members.as_slice() {
                replay.certificate.insert(item.clone(), Some(sole.acts[0].author.clone()));
            }
            let outcome = if members.len() == 1 {
                TitleOutcome::Transferred
            } else {
                TitleOutcome::Conflict
            };
            for member in members {
                replay.events.push(TitleEvent {
                    epoch: boundary,
                    item: item.clone(),
                    acts: member.acts.clone(),
                    buyer: member.acts[0].author.clone(),
                    seller: member.acts[1].author.clone(),
                    outcome,
                });
                replay.consumed.extend(member.acts.iter().cloned());
            }
        }
        replay.boundaries.push(TitleBoundary {
            premises,
            candidates,
            certificate: replay.certificate.clone(),
            consumed: replay.consumed.clone(),
        });
    }
    Ok(replay)
}

fn introduce_items(
    certificate: &mut BTreeMap<PublicReference, Option<String>>,
    history: &ValidatedHistory,
    inputs: &TitleInputs,
    epoch: u64,
) {
    for act in history.acts().iter().filter(|act| act.finalization_epoch() == epoch) {
        for endpoint in act.legs().iter().flat_map(|leg| [leg.source(), leg.target()]) {
            if matches!(endpoint, PublicReference::Minted(id) if id.family == "Owner") {
                certificate.entry(endpoint.clone()).or_insert(None);
            }
        }
        let minted = PublicReference::Minted(act.id().clone());
        if inputs.genesis.contains_key(&minted) {
            certificate.insert(minted, Some(act.id().author.clone()));
        }
    }
}

/// Outcome of a recognized, unchallenged candidate at its Ratify boundary.
/// (´def:formation:title-events´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TitleOutcome {
    /// The sole candidate transferred title at that boundary.
    Transferred,
    /// Two or more candidates consumed their records without a transfer.
    Conflict,
}

/// Event-persistent input for a later epoch compiler, never a standing value.
/// (´def:formation:title-events´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TitleEvent {
    /// Boundary that consumed the candidate.
    pub epoch: u64,
    /// Item whose title was considered.
    pub item: PublicReference,
    /// Exact Bid, Accept and Ratify identities.
    pub acts: [ActId; 3],
    /// Candidate's buyer, including in a conflicting event.
    pub buyer: String,
    /// Candidate's seller, authorized by the preceding boundary.
    pub seller: String,
    /// Whether recognition actually transferred title.
    pub outcome: TitleOutcome,
}

/// Caller-supplied final-set decision; graph establishes no admission verdict.
/// (´def:formation:title-events´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalSetDecision {
    /// Caller selected this final set; return its pure fold evidence.
    Selected,
    /// Caller rejected this final set; discard its computed certificate and events.
    Rejected,
}

/// Evaluate a proposed final history through the same compliant title fold.
/// Admission is an explicit caller premise, not a result of this function.
/// A rejected set returns None and publishes no certificate or transfer event.
/// The operation performs no publication, including for a selected set.
/// (´def:formation:title-events´)
///
/// # Errors
/// Returns whole-result formation refusal or the scoped recurrence hold before
/// any candidate-set certificate is returned. Rejection does not bypass validation.
#[tracing::instrument(
    name = "alg:design:title",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:title",
        source_item = "title::evaluate_candidate_title"
    ),
    ret
)]
pub fn evaluate_candidate_title(
    graph: &FormationGraph,
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
    epoch: u64,
    decision: FinalSetDecision,
) -> Result<Option<TitleReplay>, crate::recognition::RecognitionError> {
    let result = title_inputs(graph, history, verifier)
        .map_err(crate::recognition::RecognitionError::Formation)
        .and_then(|inputs| fold_title(graph, history, verifier, &inputs, epoch))
        .map(|replay| match decision {
            FinalSetDecision::Selected => Some(replay),
            FinalSetDecision::Rejected => None,
        });
    if result.is_err() {
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}
