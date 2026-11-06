//! Applied-dyadic revision two, retaining independent original-scope replay.
//! (´[ROOT-rule:design:evaluation-schedule]´)
mod driver;
mod fence;
mod map;
pub mod records;
mod residual;
use crate::solve::compact::BoundProcedure;
pub use driver::{Accounting, Record, replay, solve};
use pn_records::solve::Bounds;
use std::collections::BTreeMap;
fn hull(bound: &BoundProcedure<'_>) -> BTreeMap<String, Bounds> {
    bound
        .inputs()
        .0
        .view()
        .support
        .ranges
        .iter()
        .map(|(actor, r)| {
            (
                actor.clone(),
                Bounds {
                    lower: r.minimum.clone(),
                    upper: r.maximum.clone(),
                },
            )
        })
        .collect()
}

/// A threshold verdict uses certified bounds, never a comparison tolerance.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Threshold {
    Pass,
    Fail,
    Indecisive,
}
/// One-map evidence is separate from full iteration replay.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimCheck {
    pub residual: records::ResidualRound,
    pub thresholds: BTreeMap<String, Threshold>,
    pub work: u64,
}
/// Check an approximate point with one map, its residual and declared thresholds.
/// The supplied accepted fence is independently checked against the compact state.
/// This does not replay proposal history or certify controller delivery.
/// (´[ROOT-alg:design:residual]´)
/// # Errors
/// Refuses unproved fences, points outside the invariant hull, undeclared precision,
/// changed Actor sets, and exhausted resources. Straddles remain INDECISIVE.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "conserved::compact::check_claim"
    ),
    ret
)]
pub fn check_claim(
    bound: &BoundProcedure<'_>,
    accepted: &crate::fence::Search,
    point: &BTreeMap<String, String>,
    precision: u32,
    thresholds: &BTreeMap<String, String>,
) -> Result<ClaimCheck, super::Error> {
    use super::Error;
    use nrz_cas::{Location, Rational, limits::Budget};
    bound.preflight()?;
    let p = bound.inputs().1;
    let pn_records::solve::Precision::AbsoluteWidthBits(sequence) = &p.precision else {
        return Err(Error::Scope);
    };
    if !sequence.contains(&precision) || thresholds.keys().ne(point.keys()) {
        return Err(Error::Scope);
    }
    let rung = accepted.selected.as_deref().ok_or(Error::Scope)?;
    let contraction = fence::fence(bound, &accepted.evidence, rung)?;
    let hull = hull(bound);
    let mut limits = p.enclosure.as_ref().ok_or(Error::Scope)?.operation.clone();
    limits.work = p.maximum_replay_work;
    let mut b = Budget::new(limits)?;
    super::point_in_hull(point, &hull, &mut b)?;
    let mut context = map::Context::new(
        bound,
        rung,
        precision,
        p.maximum_replay_work.checked_sub(b.usage().work).ok_or(Error::Scope)?,
    )?;
    let image = context.run(
        point,
        p.maximum_replay_work.checked_sub(b.usage().work).ok_or(Error::Scope)?,
        None,
    )?;
    b.work(image.work, Location::new("one-map claimed equilibrium"))?;
    let residual = residual::assemble(image, &hull, &contraction, &mut b)?;
    let mut verdicts = BTreeMap::new();
    for (actor, bound) in &residual.standing {
        let threshold = Rational::parse(&thresholds[actor], &mut b)?;
        let lo = Rational::parse(&bound.lower, &mut b)?;
        let hi = Rational::parse(&bound.upper, &mut b)?;
        let verdict = if !lo.compare(&threshold, &mut b)?.is_lt() {
            Threshold::Pass
        } else if hi.compare(&threshold, &mut b)?.is_lt() {
            Threshold::Fail
        } else {
            Threshold::Indecisive
        };
        verdicts.insert(actor.clone(), verdict);
    }
    Ok(ClaimCheck {
        residual,
        thresholds: verdicts,
        work: b.usage().work,
    })
}
