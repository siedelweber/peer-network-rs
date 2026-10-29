//! Six-clause settlement evidence on the scoped compliant prefix.
//! (´def:formation:settlement-recognition´)

use std::collections::{BTreeMap, BTreeSet};

use pn_records::{
    ActId, Position, PublicReference, SettlementReferences, TimeEvidence, TimeVerdict, ValidatedAct, ValidatedHistory,
};

use crate::formation::FormationGraph;
use crate::registration::{RegistrationError, RegistrationVerifier};
use crate::title::{TitleInputs, title_inputs};

/// Supplied preceding-boundary certificate and consumption premises.
/// Deriving these premises by the title fold remains a separate operation.
/// (´def:formation:settlement-recognition´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecognitionContext {
    /// Boundary whose Ratify records are considered.
    pub epoch: u64,
    /// Boundary of the supplied owner map; must immediately precede epoch.
    pub prior_epoch: u64,
    /// Certified owners, including genesis owners for fresh threads.
    pub owners: BTreeMap<PublicReference, String>,
    /// Records consumed at earlier boundaries, whatever their fold outcome.
    pub consumed: BTreeSet<ActId>,
}

/// The six named clauses, in the paper's order.
/// (´def:formation:settlement-recognition´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecognitionClause {
    /// Three complete acts belong to the cumulative boundary set.
    Completeness,
    /// Both settles pointers and the exact accepts pointer agree.
    ReferenceBinding,
    /// The Accept author is the preceding certified owner.
    Authorization,
    /// No effective buyer Withdraw defeats this candidate.
    BuyerConsent,
    /// No effective seller Rescind defeats this candidate.
    SellerConsent,
    /// The referenced handshake chain is earlier in placement and time.
    WellFormedness,
}

/// One exact candidate, its clause verdicts and their structural witnesses.
/// Recognition does not imply a unique winner or a title transfer.
/// (´def:formation:settlement-recognition´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementEvidence {
    /// Bid, exact Accept and Ratify, in handshake order.
    pub acts: [ActId; 3],
    /// Accept-role and Ratify-role metadata, including the exact non-binding target.
    pub references: [Option<SettlementReferences>; 2],
    /// Published placement and retained time for the three chain witnesses.
    pub chain: [(Position, u64); 3],
    /// Item named by a valid Bid; absent for a wrong-family settles target.
    pub item: Option<PublicReference>,
    /// Supplied prior owner, absent when the certificate resolves no owner.
    pub prior_owner: Option<String>,
    /// Six clause verdicts, without short-circuiting failed consent.
    pub clauses: BTreeMap<RecognitionClause, bool>,
    /// Buyer Withdraw identities at or before the Ratify boundary.
    pub withdrawals: Vec<ActId>,
    /// Seller Rescind identities at or before the Ratify boundary.
    pub rescissions: Vec<ActId>,
    /// Candidate records already consumed at an earlier boundary.
    pub consumed: BTreeSet<ActId>,
    /// All clauses hold and no candidate record was previously consumed.
    pub recognized: bool,
}

/// A structural refusal or an explicit absence of a scoped recognition verdict.
/// (´def:formation:settlement-recognition´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecognitionError {
    /// Whole-history formation failed before any candidate evidence was emitted.
    #[error("title input formation refused: {0}")]
    Formation(RegistrationError),
    /// The supplied owner map names a different preceding boundary.
    #[error("recognition requires the immediately preceding certificate")]
    Boundary,
    /// The prefix lacks the carried, matching recurrence evidence required here.
    /// Faulted time and parent correspondence remain held by the design questions.
    #[error("recognition held outside the compliant-history scope")]
    Held(Vec<TimeEvidence>),
}

/// Revalidate complete acts and enumerate exact settlement candidates at a boundary.
/// The prior certificate and consumption set are explicit caller premises, not
/// reconstructed or authenticated by this predicate. No title fold executes.
/// (´def:formation:settlement-recognition´)
///
/// # Errors
/// Refuses altered or unauthorized formation and mismatched certificate boundaries.
/// Returns Held, with no candidate verdicts, unless every prefix act has carried,
/// matching recurrence evidence. Neither open ordering question is resolved here.
#[tracing::instrument(
    name = "alg:design:recognition",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:recognition",
        source_item = "recognition::recognize_settlements"
    ),
    ret
)]
pub fn recognize_settlements(
    graph: &FormationGraph,
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
    context: &RecognitionContext,
) -> Result<Vec<SettlementEvidence>, RecognitionError> {
    let result = title_inputs(graph, history, verifier)
        .map_err(RecognitionError::Formation)
        .and_then(|inputs| recognize(&inputs, history, context));
    if result.is_err() {
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}

fn recognize(
    inputs: &TitleInputs,
    history: &ValidatedHistory,
    context: &RecognitionContext,
) -> Result<Vec<SettlementEvidence>, RecognitionError> {
    if context.prior_epoch.checked_add(1) != Some(context.epoch) {
        return Err(RecognitionError::Boundary);
    }
    let acts: BTreeMap<_, _> = history.acts().iter().map(|act| (act.id(), act)).collect();
    let holds: Vec<_> = history
        .time_evidence()
        .iter()
        .filter(|evidence| {
            acts.get(&evidence.act)
                .is_some_and(|act| act.finalization_epoch() <= context.epoch)
                && evidence.verdict != TimeVerdict::Matches
        })
        .cloned()
        .collect();
    if !holds.is_empty() {
        return Err(RecognitionError::Held(holds));
    }
    let mut output = Vec::new();
    for (id, references) in &inputs.settlements {
        if let SettlementReferences::Ratify { settles, accepts } = references
            && let (Some(bid), Some(accept), Some(ratify)) = (acts.get(settles), acts.get(accepts), acts.get(id))
            && ratify.finalization_epoch() == context.epoch
        {
            output.push(candidate_evidence(
                [bid, accept, ratify],
                inputs.bids.get(settles),
                history,
                context,
            ));
        }
    }
    Ok(output)
}

fn candidate_evidence(
    [bid, accept, ratify]: [&ValidatedAct; 3],
    item: Option<&PublicReference>,
    history: &ValidatedHistory,
    context: &RecognitionContext,
) -> SettlementEvidence {
    let offer = PublicReference::Minted(bid.id().clone());
    let withdrawals = cancellations(history, "Withdraw", &bid.id().author, &offer, context.epoch);
    let rescissions = cancellations(history, "Rescind", &accept.id().author, &offer, context.epoch);
    let prior_owner = item.and_then(|item| context.owners.get(item)).cloned();
    let bound = item.is_some()
        && bid.id().family == "Bid"
        && accept.id().family == "Accept"
        && ratify.id().author == bid.id().author
        && actor_target(accept, &bid.id().author)
        && actor_target(ratify, &accept.id().author)
        && accept.body().settlement.as_ref()
            == Some(&SettlementReferences::Accept {
                settles: bid.id().clone(),
            })
        && ratify.body().settlement.as_ref()
            == Some(&SettlementReferences::Ratify {
                settles: bid.id().clone(),
                accepts: accept.id().clone(),
            });
    let clauses = BTreeMap::from([
        (
            RecognitionClause::Completeness,
            [bid, accept, ratify]
                .iter()
                .all(|act| act.finalization_epoch() <= context.epoch),
        ),
        (RecognitionClause::ReferenceBinding, bound),
        (
            RecognitionClause::Authorization,
            prior_owner.as_ref() == Some(&accept.id().author),
        ),
        (RecognitionClause::BuyerConsent, withdrawals.is_empty()),
        (RecognitionClause::SellerConsent, rescissions.is_empty()),
        (
            RecognitionClause::WellFormedness,
            earlier(bid, accept) && earlier(accept, ratify),
        ),
    ]);
    let acts = [bid.id().clone(), accept.id().clone(), ratify.id().clone()];
    let consumed: BTreeSet<_> = acts.iter().filter(|id| context.consumed.contains(*id)).cloned().collect();
    let recognized = clauses.values().all(|passed| *passed) && consumed.is_empty();
    SettlementEvidence {
        acts,
        references: [accept.body().settlement.clone(), ratify.body().settlement.clone()],
        chain: [bid, accept, ratify].map(|act| (act.position(), act.logical_time())),
        item: item.cloned(),
        prior_owner,
        clauses,
        withdrawals,
        rescissions,
        consumed,
        recognized,
    }
}

fn earlier(parent: &ValidatedAct, child: &ValidatedAct) -> bool {
    parent.position() < child.position() && parent.logical_time() < child.logical_time()
}

fn cancellations(history: &ValidatedHistory, family: &str, author: &str, offer: &PublicReference, epoch: u64) -> Vec<ActId> {
    let mut ids: Vec<_> = history
        .acts()
        .iter()
        .filter(|act| {
            act.id().family == family
                && act.id().author == author
                && act.finalization_epoch() <= epoch
                && act.legs().iter().any(|leg| leg.target() == offer)
        })
        .map(|act| act.id().clone())
        .collect();
    ids.sort();
    ids
}

fn actor_target(act: &ValidatedAct, actor: &str) -> bool {
    act.legs().first().is_some_and(|leg| {
        leg.target()
            == &PublicReference::Named {
                namespace: "addr".into(),
                name: actor.into(),
            }
    })
}
