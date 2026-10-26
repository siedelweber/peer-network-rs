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
