//! Order-free complete-act cells and exact sum-then-clip coordinates.
//! (´def:compiler:standing-cells´)

use std::collections::{BTreeMap, BTreeSet};

use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use pn_graph::registration::{RegistrationError, RegistrationVerifier};
use pn_records::{ActId, PublicReference, Role, ValidatedAct, ValidatedHistory};

/// Full semantic incidence; no act identity is replaced by an edge identity.
/// (´def:compiler:standing-cells´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CellIdentity {
    pub author: String,
    pub family: String,
    pub incidence: Vec<(Role, PublicReference, PublicReference)>,
    /// Excluded families retain one cell for each authored identity.
    pub singleton: Option<ActId>,
}

/// One coefficient input with every independently counted and debited member.
/// Exact coordinates are normalized rational spellings, not publication bytes.
/// (´def:compiler:standing-cells´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingCell {
    pub identity: CellIdentity,
    pub members: BTreeSet<ActId>,
    pub coordinates: BTreeMap<String, String>,
}

/// Whole-result formation, edition hold or bounded exact-arithmetic refusal.
/// (´def:compiler:standing-cells´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CellError {
    #[error("formation: {0}")]
    Formation(#[from] RegistrationError),
    #[error("exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
    #[error("boundary zero is not a compiling epoch")]
    Boundary,
    #[error("Invitation withdrawal awaits the next minor edition")]
    InvitationEdition,
}

/// Revalidate complete history and partition one epoch without consuming its acts.
/// (´def:compiler:standing-cells´)
/// # Errors
/// Refuses the whole result on formation failure, an Invitation cell or a resource limit.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "cells::fold_cells"
    ),
    ret
)]
pub fn fold_cells(
    history: &ValidatedHistory,
    boundary: u64,
    verifier: &impl RegistrationVerifier,
    limits: Limits,
) -> Result<Vec<StandingCell>, CellError> {
    if boundary == 0 {
        return Err(CellError::Boundary);
    }
    pn_graph::formation::reconstruct_replay(history, verifier)?;
    let mut budget = Budget::new(limits)?;
    let mut cells: BTreeMap<CellIdentity, (BTreeSet<ActId>, BTreeMap<String, Rational>)> = BTreeMap::new();
    for act in history.acts().iter().filter(|act| act.position().0 == boundary) {
        if act.id().family == "Invitation" {
            return Err(CellError::InvitationEdition);
        }
        let mut incidence: Vec<_> = act
            .legs()
            .iter()
            .map(|leg| (leg.id().role, leg.source().clone(), leg.target().clone()))
            .collect();
        incidence.sort();
        let identity = CellIdentity {
            author: act.id().author.clone(),
            family: act.id().family.clone(),
            incidence,
            singleton: (!matches!(act.id().family.as_str(), "Opinion" | "Reference")).then(|| act.id().clone()),
        };
        let (members, sums) = cells.entry(identity).or_default();
        members.insert(act.id().clone());
        for name in mandatory(&act.id().family) {
            let value = coordinate(act, name, &mut budget)?;
            let sum = if let Some(old) = sums.get(*name) {
                old.add(&value, &mut budget)?
            } else {
                value
            };
            sums.insert((*name).into(), sum);
        }
    }
    cells
        .into_iter()
        .map(|(identity, (members, sums))| {
            let coordinates = sums
                .into_iter()
                .map(|(name, sum)| Ok((name, clip(&sum, &mut budget)?)))
                .collect::<Result<_, CellError>>()?;
            Ok(StandingCell {
                identity,
                members,
                coordinates,
            })
        })
        .collect()
}

fn mandatory(family: &str) -> &'static [&'static str] {
    crate::coefficients::MANDATORY_COORDINATES
        .iter()
        .find(|(name, _)| *name == family)
        .map_or(&[], |(_, names)| *names)
}

fn coordinate(act: &ValidatedAct, name: &str, budget: &mut Budget) -> Result<Rational, CellError> {
    let field = |suffix| {
        act.body()
            .quantities
            .iter()
            .find(|(key, _)| key == &format!("{name}.{suffix}"))
            .map(|(_, value)| value.value)
            .ok_or(RegistrationError::Incidence)
    };
    Ok(Rational::parse(
        &format!("{}/{}", field("numerator")?, field("denominator")?),
        budget,
    )?)
}

fn clip(value: &Rational, budget: &mut Budget) -> Result<String, CellError> {
    let one = Rational::parse("1", budget)?;
    let negative = Rational::parse("-1", budget)?;
    if one.sub(value, budget)?.is_negative() {
        return Ok("1".into());
    }
    if value.sub(&negative, budget)?.is_negative() {
        return Ok("-1".into());
    }
    Ok(value.exact_string(budget)?)
}
