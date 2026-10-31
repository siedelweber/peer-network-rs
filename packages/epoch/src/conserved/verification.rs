//! Bind the separate full-emission verification route to frozen rational ledger inputs.
//! (´[ROOT-alg:design:residual]´)
use super::Error;
use crate::{base::BaseScore, solve::BoundProcedure};
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    burn::Address,
    conserved::{VerificationEdge, VerificationInput, VerificationSource},
    primitive::Range,
};

/// Reconstruct a full-emission verification declaration without changing the frozen solve.
/// (´[ROOT-alg:design:residual]´)
/// # Errors
/// Refuses unsupported base sums, nonuniform retention, depleted emission or an unbound wall.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "conserved::verification::verification_declaration"
    ),
    ret
)]
pub fn verification_declaration(bound: &BoundProcedure<'_>, rung: &str, endpoint_bits: u32) -> Result<VerificationInput, Error> {
    bound.preflight()?;
    let (state, p) = bound.inputs();
    let (fence, _) = crate::fence::prepare(bound)?;
    let profile = p.fence.as_ref().ok_or(Error::Scope)?;
    if !p.grid.iter().any(|v| v == rung) || profile.inverse_wall && bound.enclosed_wall().is_none() {
        return Err(Error::Scope);
    }
    let frozen = state.package().input().inputs.last().ok_or(Error::Scope)?;
    let mut b = Budget::new(p.enclosure.as_ref().ok_or(Error::Scope)?.operation.clone())?;
    let mut sources = Vec::new();
    let mut edges = Vec::new();
    let mut retention = None;
    for (name, row) in &state.view().base.rows {
        let source = &state.view().support.sources[name];
        if Rational::parse(&source.emission, &mut b)? != Rational::parse("1", &mut b)? {
            return Err(Error::Scope);
        }
        sources.push(VerificationSource {
            name: name.clone(),
            count: state.view().ledger.counts[&Address(name.clone())].0.to_string(),
            intercept: source.reduced_rate.clone(),
            slope: "0".into(),
        });
        for (target, entry) in row {
            let BaseScore::Exact(value) = &entry.score else {
                return Err(Error::Scope);
            };
            let value = Rational::parse(value, &mut b)?;
            if name == target {
                if retention.as_ref().is_some_and(|r| r != &value) {
                    return Err(Error::Scope);
                }
                retention = Some(value);
            } else if !value.is_zero() {
                edges.push(VerificationEdge {
                    source: name.clone(),
                    target: target.clone(),
                    radicand: value.mul(&value, &mut b)?.exact_string(&mut b)?,
                });
            }
        }
    }
    let depth = state.view().support.by_depth.keys().next_back().copied().unwrap_or(0);
    let shape = profile
        .shape
        .iter()
        .take(depth)
        .map(|name| Ok(crate::constant(frozen.constants(), name, &mut b)?.exact_string(&mut b)?))
        .collect::<Result<Vec<_>, Error>>()?;
    let depth_mass = frozen
        .parameters()
        .depth_mass
        .iter()
        .take(depth)
        .map(|name| Ok(crate::constant(frozen.constants(), name, &mut b)?.exact_string(&mut b)?))
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(VerificationInput {
        sources,
        edges,
        wall: bound.enclosed_wall().cloned().unwrap_or(Range {
            lower: fence.wall.clone(),
            upper: fence.wall,
        }),
        shape,
        depth_mass,
        retention: retention.ok_or(Error::Scope)?.exact_string(&mut b)?,
        strength: rung.into(),
        endpoint_bits,
    })
}
