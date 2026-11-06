//! Frozen width-fence preparation and declared, independently evaluated rung attempts.
//! (´def:compiler:fence-search´)

use super::attempts;

use crate::solve::compact::BoundProcedure;
use nrz_cas::{Rational, limits::Budget};
use pn_graph::numeric::activation::fence::Inputs;
use pn_records::{
    primitive::{PrimitiveEvidence, PrimitiveRecord, Query},
    solve::{Bounds, Evidence, Precision},
};
use std::collections::BTreeMap;

use super::{Error, Search};

pub(crate) fn prepare(bound: &BoundProcedure<'_>) -> Result<(Inputs, BTreeMap<String, Bounds>), Error> {
    let (state, procedure) = bound.inputs();
    let profile = procedure.fence.as_ref().ok_or(Error::Profile)?;
    let declared = state.package().input().inputs.last().ok_or(Error::Profile)?;
    let policy = procedure.enclosure.as_ref().ok_or(Error::Profile)?;
    let mut budget = Budget::new(policy.operation.clone())?;
    let bleed = crate::constant(declared.constants(), &profile.bleed_squared, &mut budget)?;
    if bleed != Rational::parse("1/400", &mut budget)? {
        return Err(Error::Profile);
    }
    let depth = state.view().support.depth;
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
            wall: bound.enclosed_wall().map_or_else(
                || {
                    state
                        .package()
                        .input()
                        .prices
                        .last()
                        .ok_or(Error::Profile)
                        .map(|price| price.wall().exact().into())
                },
                |wall| Ok(wall.lower.clone()),
            )?,
            bleed_squared: bleed.exact_string(&mut budget)?,
            width: width.exact_string(&mut budget)?,
            cumulative_tilt: cumulative.exact_string(&mut budget)?,
            margin: procedure.margin.clone(),
        },
        hull,
    ))
}

fn question(procedure: &pn_records::solve::Procedure, prepared: &Inputs, rung: &str) -> Result<Query, Error> {
    let policy = procedure.enclosure.as_ref().ok_or(Error::Profile)?;
    let mut budget = Budget::new(policy.operation.clone())?;
    let mut input = prepared.clone();
    input.cumulative_tilt = Rational::parse(rung, &mut budget)?
        .mul(&Rational::parse(&prepared.cumulative_tilt, &mut budget)?, &mut budget)?
        .exact_string(&mut budget)?;
    Ok(pn_graph::numeric::activation::fence::query(procedure, &input)?)
}

/// Rebuild a rung's question from the frozen package before replaying its supplied attachment.
/// (´def:compiler:fence-search´)
/// # Errors
/// Refuses undeclared rungs or precisions, changed queries, missing attachments and invalid evidence.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "fence::compact::replay"
    ),
    ret
)]
pub fn replay(bound: &BoundProcedure<'_>, rung: &str, record: &PrimitiveRecord) -> Result<PrimitiveEvidence, Error> {
    bound.preflight()?;
    let (_, procedure) = bound.inputs();
    let Precision::AbsoluteWidthBits(sequence) = &procedure.precision else {
        return Err(Error::Profile);
    };
    if !procedure.grid.iter().any(|value| value == rung) || !sequence.contains(&record.precision) {
        return Err(Error::Profile);
    }
    let (prepared, _) = prepare(bound)?;
    if procedure.fence.as_ref().is_some_and(|profile| profile.inverse_wall) && bound.enclosed_wall().is_none() {
        return Err(Error::ReferenceWall);
    }
    let expected = question(procedure, &prepared, rung)?;
    if expected != record.query {
        return Err(Error::Profile);
    }
    let mut policy = procedure.clone();
    policy.enclosure.as_mut().ok_or(Error::Profile)?.refinement.precision = record.precision;
    Ok(pn_graph::numeric::replay(
        &policy,
        &expected,
        record.evidence.attachment.as_ref().ok_or(Error::Profile)?,
        None,
    )?)
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
        source_item = "fence::compact::search"
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
        let stop = attempts::run(
            procedure,
            sequence,
            &prepared,
            rung,
            interrupt_at,
            &mut result.evidence,
            bound.enclosed_wall().is_some(),
        )?;
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
