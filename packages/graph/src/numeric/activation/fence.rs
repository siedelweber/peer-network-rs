//! The evaluated width fence retains the deployed wall gain, not the clean screen.
//! (´def:numerics:width-fence´)

use super::{Error, Quantity, Request};
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    primitive::{Goal, Node, Query, Range},
    solve::Procedure,
};

/// Exact public inputs already joined by the epoch owner to its frozen compiler output.
/// (´def:numerics:width-fence´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub wall: String,
    pub bleed_squared: String,
    pub width: String,
    pub cumulative_tilt: String,
    pub margin: String,
}

/// Build the original question `mu * 2 * G_wall * S_deep * W <= 1`.
/// (´[ROOT-alg:design:fence]´)
/// # Errors
/// Refuses malformed domains, unavailable primitives or exhausted preparation resources.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::fence::query"
    ),
    ret
)]
pub fn query(procedure: &Procedure, input: &Inputs) -> Result<Query, Error> {
    super::super::preflight(procedure)?;
    let policy = procedure.enclosure.as_ref().ok_or(Error::Unsupported)?;
    let mut budget = Budget::new(policy.operation.clone())?;
    let width = super::nonnegative(&input.width, &mut budget)?;
    let tilt = super::nonnegative(&input.cumulative_tilt, &mut budget)?;
    let margin = super::nonnegative(&input.margin, &mut budget)?;
    if !margin.compare(&Rational::parse("1", &mut budget)?, &mut budget)?.is_gt() {
        return Err(Error::Declaration);
    }
    if width.is_zero() || tilt.is_zero() {
        return Ok(Query {
            coordinates: Vec::new(),
            nodes: vec![Node::Rational("0".into())],
            target: 0,
            goal: Goal::AtMost("1".into()),
        });
    }
    let request = Request {
        standing: Range {
            lower: input.wall.clone(),
            upper: input.wall.clone(),
        },
        bleed_squared: input.bleed_squared.clone(),
        wall: None,
        quantity: Quantity::ResponsiveLogGain,
    };
    let mut result = super::query(&request, &mut budget)?;
    for factor in ["2", &input.margin, &input.width, &input.cumulative_tilt] {
        let scalar = super::push(&mut result.nodes, Node::Rational(factor.into()));
        result.target = super::push(&mut result.nodes, Node::Multiply(result.target, scalar));
    }
    result.goal = Goal::AtMost("1".into());
    Ok(result)
}
