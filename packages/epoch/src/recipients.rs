//! Person routing from cumulative cells and persistent title events.
//! (´def:compiler:recipient-resolution´)

use std::collections::BTreeSet;

use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use pn_graph::{registration::RegistrationVerifier, title::TitleOutcome};
use pn_records::{PublicReference, Role, ValidatedHistory};

use crate::cells::{CellError, StandingCell, fold_cells};

/// One complete cell and its resolved Actor or author's retention channel.
/// This is destination evidence, not a coefficient or allocation.
/// (´def:compiler:recipient-resolution´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedCell {
    pub cell: StandingCell,
    pub recipient: String,
}

/// Whole-result cell, title or bounded exact-arithmetic refusal.
/// (´def:compiler:recipient-resolution´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecipientError {
    #[error("cell compilation: {0}")]
    Cells(#[from] CellError),
    #[error("title replay: {0}")]
    Title(#[from] pn_graph::recognition::RecognitionError),
    #[error("exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

/// Derive recipients from one completed history, retaining every compiled member.
/// (´[ROOT-sig:design:epoch]´)
/// # Errors
/// Refuses the entire result on cell or title validation failure or exact-arithmetic exhaustion. No partial allocation is returned.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "recipients::resolve_recipients"
    ),
    ret
)]
pub fn resolve_recipients(
    history: &ValidatedHistory,
    boundary: u64,
    verifier: &impl RegistrationVerifier,
    limits: Limits,
) -> Result<Vec<ResolvedCell>, RecipientError> {
    let cells = fold_cells(history, boundary, verifier, limits.clone())?;
    let graph = pn_graph::formation::reconstruct_replay(history, verifier).map_err(CellError::from)?;
    let title = pn_graph::title::replay_title(&graph, history, verifier, boundary)?;
    let anchors: BTreeSet<_> = history
        .acts()
        .iter()
        .filter(|act| act.position().0 <= boundary && act.id().family == "Registration")
        .map(|act| act.id().author.as_str())
        .collect();
    let mut budget = Budget::new(limits)?;
    let mut output = Vec::new();
    for cell in cells {
        let mut positive = true;
        for spelling in cell.coordinates.values() {
            let coordinate = Rational::parse(spelling, &mut budget)?;
            positive &= !coordinate.is_negative() && !coordinate.is_zero();
        }
        let target = if positive {
            match cell.identity.family.as_str() {
                "Opinion" => profile(&cell, Role::Binary),
                "Reference" | "Invitation" => profile(&cell, Role::T),
                "Accept" | "Ratify" => title.events.iter().find_map(|event| {
                    if event.outcome != TitleOutcome::Transferred {
                        return None;
                    }
                    // A successful event survives both record consumption and resale.
                    // A later attempt reusing a member creates no new event.
                    if cell.identity.family == "Accept" && cell.members.contains(&event.acts[1]) {
                        Some(event.buyer.as_str())
                    } else if cell.identity.family == "Ratify" && cell.members.contains(&event.acts[2]) {
                        Some(event.seller.as_str())
                    } else {
                        None
                    }
                }),
                _ => None,
            }
        } else {
            None
        };
        let recipient = target
            .filter(|target| anchors.contains(target))
            .unwrap_or(&cell.identity.author)
            .to_owned();
        output.push(ResolvedCell { cell, recipient });
    }
    Ok(output)
}

fn profile(cell: &StandingCell, role: Role) -> Option<&str> {
    cell.identity.incidence.iter().find_map(|(candidate, _, target)| {
        if *candidate == role
            && let PublicReference::Named { namespace, name } = target
            && namespace == "prof"
        {
            Some(name.as_str())
        } else {
            None
        }
    })
}
