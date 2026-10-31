//! Frozen width-fence preparation and declared, independently evaluated rung attempts.
//! (´def:compiler:fence-search´)

mod attempts;

use crate::solve::BoundProcedure;
use nrz_cas::{Rational, limits::Budget};
use pn_graph::numeric::activation::fence::Inputs;
use pn_records::{
    primitive::Outcome,
    solve::{Bounds, Evidence, Precision},
};
use std::collections::BTreeMap;

/// A successful choice or an operational stop, with every executed request retained.
/// (´def:compiler:fence-search´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Search {
    pub evidence: Evidence,
    pub selected: Option<String>,
    pub operational_stop: Option<Outcome>,
}

/// Preparation and scope refusals are not mathematical fence failures.
/// (´def:compiler:fence-search´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("fence declaration does not bind a supported reference profile")]
    Profile,
    #[error("inverse-gain wall remains held under open:design:reference-wall-route")]
    ReferenceWall,
    #[error("procedure: {0}")]
    Procedure(#[from] crate::solve::ProcedureError),
    #[error("numerical request: {0}")]
    Numeric(#[from] pn_graph::numeric::Error),
    #[error("constant profile: {0}")]
    Input(#[from] crate::InputError),
    #[error("exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

fn prepare(bound: &BoundProcedure<'_>) -> Result<(Inputs, BTreeMap<String, Bounds>), Error> {
    let (state, procedure) = bound.inputs();
    let profile = procedure.fence.as_ref().ok_or(Error::Profile)?;
    let declared = state.package().input().inputs.last().ok_or(Error::Profile)?;
    let policy = procedure.enclosure.as_ref().ok_or(Error::Profile)?;
    let mut budget = Budget::new(policy.operation.clone())?;
    let bleed = crate::constant(declared.constants(), &profile.bleed_squared, &mut budget)?;
    if bleed != Rational::parse("1/400", &mut budget)? {
        return Err(Error::Profile);
    }
    let depth = state.view().support.by_depth.keys().next_back().copied().unwrap_or(0);
    if Rational::parse(&profile.shape.len().to_string(), &mut budget)?
        != crate::constant(declared.constants(), &declared.parameters().hop_limit, &mut budget)?
    {
        return Err(Error::Profile);
    }
    let mut cumulative = Rational::parse("0", &mut budget)?;
    let mut previous: Option<Rational> = None;
    for (index, name) in profile.shape.iter().enumerate() {
        let value = crate::constant(declared.constants(), name, &mut budget)?;
        if value.is_negative()
            || previous
                .as_ref()
                .map(|p| value.compare(p, &mut budget))
                .transpose()?
                .is_some_and(std::cmp::Ordering::is_gt)
        {
            return Err(Error::Profile);
        }
        if index < depth {
            cumulative = cumulative.add(&value, &mut budget)?;
        }
        previous = Some(value);
    }
    let mut width = Rational::parse("0", &mut budget)?;
    let mut hull = BTreeMap::new();
    for (actor, range) in &state.view().support.ranges {
        let next = Rational::parse(&range.width, &mut budget)?;
        if next.compare(&width, &mut budget)?.is_gt() {
            width = next;
        }
        hull.insert(
            actor.clone(),
            Bounds {
                lower: range.minimum.clone(),
                upper: range.maximum.clone(),
            },
        );
    }
    Ok((
        Inputs {
            wall: state
                .package()
                .input()
                .prices
                .last()
                .ok_or(Error::Profile)?
                .wall()
                .exact()
                .into(),
            bleed_squared: bleed.exact_string(&mut budget)?,
            width: width.exact_string(&mut budget)?,
            cumulative_tilt: cumulative.exact_string(&mut budget)?,
            margin: procedure.margin.clone(),
        },
        hull,
    ))
}

/// Run the published sequence from fresh stores and choose the greatest proved passing rung.
/// (´[ROOT-alg:design:rungs]´)
/// # Errors
/// Refuses a malformed or held profile and preparation or expected-scope errors.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "fence::search"
    ),
    ret
)]
pub fn search(bound: &BoundProcedure<'_>, interrupt_at: Option<u64>) -> Result<Search, Error> {
    bound.preflight()?;
    let (_, procedure) = bound.inputs();
    let Precision::AbsoluteWidthBits(sequence) = &procedure.precision else {
        return Err(Error::Profile);
    };
    let (prepared, hull) = prepare(bound)?;
    let mut result = Search {
        evidence: Evidence {
            hull,
            attempts: Vec::new(),
            residual: None,
            primitives: Vec::new(),
        },
        selected: None,
        operational_stop: None,
    };
    for rung in &procedure.grid {
        let stop = attempts::run(procedure, sequence, &prepared, rung, interrupt_at, &mut result.evidence)?;
        if let Some(stop) = stop {
            result.operational_stop = Some(stop);
            break;
        }
        if result
            .evidence
            .attempts
            .last()
            .is_some_and(|a| a.completion == pn_records::solve::Completion::Pass)
        {
            result.selected = Some(rung.clone());
            break;
        }
    }
    Ok(result)
}
