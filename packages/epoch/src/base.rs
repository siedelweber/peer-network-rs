//! Unnormalized allocation on the closed anchored-Actor index.
//! (´def:compiler:base-allocation´)

use std::collections::{BTreeMap, BTreeSet};

use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use pn_graph::registration::RegistrationVerifier;
use pn_records::{DeclarationId, ValidatedHistory};

use crate::{
    CompilerInputs, InputError,
    cells::CellIdentity,
    coefficients::{CoefficientError, coefficient},
    recipients::{RecipientError, resolve_recipients},
};

/// A positive irrational term retained without an approximate base entry.
/// (´def:compiler:base-allocation´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldCoefficient {
    pub cell: CellIdentity,
    pub radicand: String,
    pub domain_factor: String,
}

/// Exact magnitude or an explicitly incomplete magnitude with its missing evidence.
/// (´def:compiler:base-allocation´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseScore {
    Exact(String),
    Held {
        exact_part: String,
        terms: Vec<HeldCoefficient>,
    },
}

/// One sparse entry, retaining contributing cells even when their weight is zero.
/// (´def:compiler:base-allocation´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseEntry {
    pub score: BaseScore,
    pub cells: BTreeSet<CellIdentity>,
}

/// Sparse, unnormalized rows; only anchored Actors own rows and columns.
/// (´def:compiler:base-allocation´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseAllocation {
    pub boundary: u64,
    pub edition: DeclarationId,
    pub rows: BTreeMap<String, BTreeMap<String, BaseEntry>>,
}

/// Structural refusals are distinct from an entry's retained irrational hold.
/// (´def:compiler:base-allocation´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BaseError {
    #[error("recipient derivation: {0}")]
    Recipients(#[from] RecipientError),
    #[error("coefficient: {0}")]
    Coefficient(#[from] CoefficientError),
    #[error("bound parameters: {0}")]
    Input(#[from] InputError),
    #[error("exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
    #[error("cell source or recipient is outside the anchored Actor index")]
    ActorIndex,
}

/// Derive the base from complete cells, with no member multiplier or row normalization.
/// (´[ROOT-alg:design:base]´)
/// # Errors
/// Refuses malformed history, an unclosed Actor index or exhausted exact arithmetic.
/// Irrational coefficients hold only their dependent entries, with explicit terms.
#[tracing::instrument(
    name = "alg:design:base",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "alg:design:base",
        source_item = "base::compile_base"
    ),
    ret
)]
pub fn compile_base(
    inputs: &CompilerInputs,
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
    limits: Limits,
) -> Result<BaseAllocation, BaseError> {
    let boundary = inputs.parameters().boundary;
    let resolved = resolve_recipients(history, boundary, verifier, limits.clone())?;
    let anchors: BTreeSet<_> = history
        .acts()
        .iter()
        .filter(|act| act.position().0 <= boundary && act.id().family == "Registration")
        .map(|act| act.id().author.clone())
        .collect();
    let mut budget = Budget::new(limits.clone())?;
    let self_base =
        crate::constant(inputs.constants(), &inputs.parameters().self_base, &mut budget)?.exact_string(&mut budget)?;
    let mut rows: BTreeMap<_, _> = anchors
        .iter()
        .map(|actor| {
            (
                actor.clone(),
                BTreeMap::from([(
                    actor.clone(),
                    BaseEntry {
                        score: BaseScore::Exact(self_base.clone()),
                        cells: BTreeSet::new(),
                    },
                )]),
            )
        })
        .collect();
    for resolved in resolved {
        let identity = resolved.cell.identity.clone();
        if !anchors.contains(&identity.author) || !anchors.contains(&resolved.recipient) {
            return Err(BaseError::ActorIndex);
        }
        let profile = inputs
            .parameters()
            .profiles
            .iter()
            .find(|profile| profile.family == identity.family)
            .ok_or(InputError::MissingProfile)?;
        let mut factor = Rational::parse("0", &mut budget)?;
        for (domain, name) in &profile.weights {
            let weight = crate::constant(inputs.constants(), name, &mut budget)?;
            if weight.is_zero() {
                continue;
            }
            let domain_name = inputs
                .parameters()
                .domain_weights
                .get(domain)
                .ok_or(InputError::UnknownDomain)?;
            let domain_weight = crate::constant(inputs.constants(), domain_name, &mut budget)?;
            factor = factor.add(&weight.mul(&domain_weight, &mut budget)?, &mut budget)?;
        }
        let row = rows.get_mut(&identity.author).ok_or(BaseError::ActorIndex)?;
        let entry = row.entry(resolved.recipient).or_insert(BaseEntry {
            score: BaseScore::Exact("0".into()),
            cells: BTreeSet::new(),
        });
        entry.cells.insert(identity.clone());
        // A zero published domain factor removes dependence on the coefficient.
        if factor.is_zero() {
            continue;
        }
        match coefficient(&resolved.cell, limits.clone()) {
            Ok(value) => {
                let value = Rational::parse(&value, &mut budget)?.mul(&factor, &mut budget)?;
                let exact = match &mut entry.score {
                    BaseScore::Exact(value) | BaseScore::Held { exact_part: value, .. } => value,
                };
                *exact = Rational::parse(exact, &mut budget)?
                    .add(&value, &mut budget)?
                    .exact_string(&mut budget)?;
            }
            Err(CoefficientError::Irrational { radicand }) => {
                let term = HeldCoefficient {
                    cell: identity,
                    radicand,
                    domain_factor: factor.exact_string(&mut budget)?,
                };
                match &mut entry.score {
                    BaseScore::Exact(value) => {
                        entry.score = BaseScore::Held {
                            exact_part: value.clone(),
                            terms: vec![term],
                        }
                    }
                    BaseScore::Held { terms, .. } => terms.push(term),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(BaseAllocation {
        boundary,
        edition: inputs.parameters().edition.clone(),
        rows,
    })
}
