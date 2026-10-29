//! Six-clause settlement evidence on the scoped compliant prefix.
//! (´def:formation:settlement-recognition´)

use std::collections::{BTreeMap, BTreeSet};

use pn_records::{ActId, PublicReference, SettlementReferences, TimeEvidence, ValidatedAct, ValidatedHistory};

use crate::formation::{FormationGraph, reconstruct_replay};
use crate::metadata::ActMetadata;
use crate::registration::{RegistrationError, RegistrationVerifier};
use crate::title::{TitleInputs, indexed_inputs};

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
    /// The referenced handshake chain is earlier in published placement.
    WellFormedness,
}

/// Family party correspondence, provisionally filed under reference binding.
/// The paper's choice of clause remains held.
/// (´[ROOT-open:design:settlement-partner-clause]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartnerEvidence {
    /// The Ratify author is the Bid author.
    pub ratify_author_is_buyer: bool,
    /// The Accept targets the Bid author.
    pub accept_target_is_buyer: bool,
    /// The Ratify targets the Accept author.
    pub ratify_target_is_seller: bool,
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
    /// Family and exact act-reference binding, independently of party correspondence.
    pub targets_bind: bool,
    /// Party correspondence evidence, distinct from target binding failures.
    pub partners: PartnerEvidence,
    /// Published placement and retained time for the three chain witnesses.
    pub chain: [Option<ActMetadata>; 3],
    /// Observer-specific recomputation and stamp evidence, never a replacement stamp.
    pub times: [Option<TimeEvidence>; 3],
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
}

/// Revalidate complete acts and enumerate exact settlement candidates at a boundary.
/// The prior certificate and consumption set are explicit caller premises, not
/// reconstructed or authenticated by this predicate. No title fold executes.
/// (´def:formation:settlement-recognition´)
///
/// # Errors
/// Refuses altered or unauthorized formation and mismatched certificate boundaries.
/// Unavailable time and stamp faults remain evidence, never recognition premises.
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
    let result = reconstruct_replay(history, verifier)
        .and_then(|expected| crate::registration::compare_graph(graph, &expected))
        .map_err(RecognitionError::Formation)
        .and_then(|()| recognize(&indexed_inputs(history), history, context));
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
    let mut output = Vec::new();
    for (id, references) in &inputs.settlements {
        if let SettlementReferences::Ratify { settles, accepts } = references
            && let Some(ratify) = acts.get(id)
            && ratify.finalization_epoch() == context.epoch
        {
            output.push(candidate_evidence(
                [acts.get(settles).copied(), acts.get(accepts).copied(), Some(*ratify)],
                [settles.clone(), accepts.clone(), id.clone()],
                inputs.bids.get(settles),
                history,
                context,
            ));
        }
    }
    Ok(output)
}

fn candidate_evidence(
    [bid, accept, ratify]: [Option<&ValidatedAct>; 3],
    acts: [ActId; 3],
    item: Option<&PublicReference>,
    history: &ValidatedHistory,
    context: &RecognitionContext,
) -> SettlementEvidence {
    let offer = PublicReference::Minted(acts[0].clone());
    let withdrawals = cancellations(history, "Withdraw", &acts[0].author, &offer, context.epoch);
    let rescissions = cancellations(history, "Rescind", &acts[1].author, &offer, context.epoch);
    let prior_owner = item.and_then(|item| context.owners.get(item)).cloned();
    let partners = PartnerEvidence {
        ratify_author_is_buyer: ratify
            .zip(bid)
            .is_some_and(|(ratify, bid)| ratify.id().author == bid.id().author),
        accept_target_is_buyer: accept
            .zip(bid)
            .is_some_and(|(accept, bid)| actor_target(accept, &bid.id().author)),
        ratify_target_is_seller: ratify
            .zip(accept)
            .is_some_and(|(ratify, accept)| actor_target(ratify, &accept.id().author)),
    };
    let targets_bind = item.is_some()
        && bid.is_some_and(|bid| bid.id().family == "Bid")
        && accept.is_some_and(|accept| {
            accept.id().family == "Accept"
                && accept.body().settlement
                    == Some(SettlementReferences::Accept {
                        settles: acts[0].clone(),
                    })
        })
        && ratify.is_some_and(|ratify| {
            ratify.body().settlement
                == Some(SettlementReferences::Ratify {
                    settles: acts[0].clone(),
                    accepts: acts[1].clone(),
                })
        });
    let clauses = BTreeMap::from([
        (
            RecognitionClause::Completeness,
            [bid, accept, ratify]
                .iter()
                .all(|act| act.is_some_and(|act| act.finalization_epoch() <= context.epoch)),
        ),
        (
            RecognitionClause::ReferenceBinding,
            targets_bind
                && partners.ratify_author_is_buyer
                && partners.accept_target_is_buyer
                && partners.ratify_target_is_seller,
        ),
        (
            RecognitionClause::Authorization,
            accept.is_some_and(|accept| prior_owner.as_ref() == Some(&accept.id().author)),
        ),
        (RecognitionClause::BuyerConsent, withdrawals.is_empty()),
        (RecognitionClause::SellerConsent, rescissions.is_empty()),
        (
            RecognitionClause::WellFormedness,
            bid.zip(accept).is_some_and(|(bid, accept)| earlier(bid, accept))
                && accept.zip(ratify).is_some_and(|(accept, ratify)| earlier(accept, ratify)),
        ),
    ]);
    let consumed: BTreeSet<_> = acts.iter().filter(|id| context.consumed.contains(*id)).cloned().collect();
    let recognized = clauses.values().all(|passed| *passed) && consumed.is_empty();
    SettlementEvidence {
        acts,
        references: [
            accept.and_then(|act| act.body().settlement.clone()),
            ratify.and_then(|act| act.body().settlement.clone()),
        ],
        targets_bind,
        partners,
        chain: [bid, accept, ratify].map(|act| act.map(ActMetadata::from_act)),
        times: [bid, accept, ratify].map(|act| {
            act.and_then(|act| ActMetadata::from_act(act).evidence(act.id(), history))
                .cloned()
        }),
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
    ActMetadata::from_act(parent).position < ActMetadata::from_act(child).position
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
