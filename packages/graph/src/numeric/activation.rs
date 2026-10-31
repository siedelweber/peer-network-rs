//! Responsive activation and its wall clamp, with separate deployed and clean gains.
//! (´def:numerics:activation´)

use super::Error;
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    primitive::{Attachment, Goal, Node, PrimitiveRecord, Query, Range},
    solve::Procedure,
};

/// Distinct formula requests; a generalized slope is never a smooth derivative.
/// (´def:numerics:activation´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Quantity {
    Responsive,
    Clamped,
    Hop { strength: String, shape: String },
    ResponsiveLogGain,
    CleanScreenLogGain,
    GeneralizedLogGain,
}

/// Public reduced-standing box and declared squared bleed; a wall is an exact rational.
/// (´def:numerics:activation´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub standing: Range,
    pub bleed_squared: String,
    pub wall: Option<String>,
    pub quantity: Quantity,
}

/// Formula inputs retained beside the original scalar query and checked attachment.
/// (´def:numerics:activation´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub input: Request,
    pub primitive: PrimitiveRecord,
}

fn push(nodes: &mut Vec<Node>, node: Node) -> usize {
    let index = nodes.len();
    nodes.push(node);
    index
}

fn nonnegative(text: &str, budget: &mut Budget) -> Result<Rational, Error> {
    let value = Rational::parse(text, budget)?;
    if value.is_negative() {
        return Err(Error::Declaration);
    }
    Ok(value)
}

fn validate(input: &Request, budget: &mut Budget) -> Result<Option<String>, Error> {
    let lower = nonnegative(&input.standing.lower, budget)?;
    let upper = nonnegative(&input.standing.upper, budget)?;
    let one = Rational::parse("1", budget)?;
    let bleed = nonnegative(&input.bleed_squared, budget)?;
    if lower.compare(&upper, budget)?.is_gt() || !bleed.compare(&one, budget)?.is_lt() {
        return Err(Error::Declaration);
    }
    let clamped = matches!(
        input.quantity,
        Quantity::Clamped | Quantity::Hop { .. } | Quantity::GeneralizedLogGain
    );
    if clamped != input.wall.is_some() {
        return Err(Error::Declaration);
    }
    if let Some(wall) = &input.wall
        && nonnegative(wall, budget)?.is_zero()
    {
        return Err(Error::Declaration);
    }
    if matches!(input.quantity, Quantity::ResponsiveLogGain | Quantity::CleanScreenLogGain) && lower.is_zero() {
        return Err(Error::Declaration);
    }
    if let Quantity::Hop { strength, shape } = &input.quantity {
        return Ok(Some(
            nonnegative(strength, budget)?
                .mul(&nonnegative(shape, budget)?, budget)?
                .exact_string(budget)?,
        ));
    }
    Ok(None)
}

fn core(nodes: &mut Vec<Node>, p: usize, beta: usize, bleed: usize, one: usize) -> usize {
    let temperature = push(nodes, Node::Multiply(beta, p));
    let sigmoid = push(nodes, Node::Sigmoid(temperature));
    let t = push(nodes, Node::Tanh(p));
    let leaked = push(nodes, Node::Multiply(bleed, t));
    let remaining = push(nodes, Node::Subtract(one, leaked));
    let radicand = push(nodes, Node::Multiply(t, remaining));
    let root = push(nodes, Node::SquareRoot(radicand));
    push(nodes, Node::Multiply(sigmoid, root))
}

fn query(input: &Request, budget: &mut Budget) -> Result<Query, Error> {
    let exponent = validate(input, budget)?;
    let mut nodes = vec![Node::Coordinate(0), Node::Rational("1".into()), Node::Rational("2".into())];
    let logarithm = push(&mut nodes, Node::Logarithm(2));
    let beta = push(&mut nodes, Node::Multiply(2, logarithm));
    let clean = input.quantity == Quantity::CleanScreenLogGain;
    let bleed = push(
        &mut nodes,
        Node::Rational(if clean { "0".into() } else { input.bleed_squared.clone() }),
    );
    let x = if let Some(wall) = &input.wall {
        let wall = push(&mut nodes, Node::Rational(wall.clone()));
        push(&mut nodes, Node::Clamp(0, wall))
    } else {
        0
    };
    let denominator = push(&mut nodes, Node::Add(1, x));
    let p = push(&mut nodes, Node::Divide(x, denominator));
    let q = core(&mut nodes, p, beta, bleed, 1);
    let mut value = if clean {
        q
    } else {
        let normalization = core(&mut nodes, 1, beta, bleed, 1);
        let normalized = push(&mut nodes, Node::Divide(q, normalization));
        let square = push(&mut nodes, Node::SquareRoot(normalized));
        push(&mut nodes, Node::SquareRoot(square))
    };
    if let Some(exponent) = exponent {
        value = push(&mut nodes, Node::PositivePower(value, exponent));
    }
    if matches!(
        input.quantity,
        Quantity::ResponsiveLogGain | Quantity::CleanScreenLogGain | Quantity::GeneralizedLogGain
    ) {
        let logarithm = push(&mut nodes, Node::Logarithm(value));
        value = push(
            &mut nodes,
            if input.quantity == Quantity::GeneralizedLogGain {
                Node::GeneralizedDerivative(logarithm, 0)
            } else {
                Node::Derivative(logarithm, 0)
            },
        );
    }
    Ok(Query {
        coordinates: vec![input.standing.clone()],
        nodes,
        target: value,
        goal: Goal::Width,
    })
}

fn run(
    procedure: &Procedure,
    input: &Request,
    evidence: Option<&Attachment>,
    interrupt_at: Option<u64>,
) -> Result<Evaluation, Error> {
    super::preflight(procedure)?;
    let policy = procedure.enclosure.as_ref().ok_or(Error::Unsupported)?;
    if let Some(evidence) = evidence {
        super::schemas(&evidence.schemas)?;
    }
    let mut budget = Budget::new(policy.operation.clone())?;
    let query = query(input, &mut budget)?;
    let checked = super::run_budget(procedure, &query, evidence, interrupt_at, &mut budget)?;
    Ok(Evaluation {
        input: input.clone(),
        primitive: PrimitiveRecord {
            query,
            precision: policy.refinement.precision,
            evidence: checked,
        },
    })
}

/// Evaluate the declared activation formula in one fresh bounded scalar request.
/// (´[ROOT-alg:design:enclosures]´)
/// # Errors
/// Refuses invalid domains, unavailable primitives and exhausted construction work.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::evaluate"
    ),
    ret
)]
pub fn evaluate(procedure: &Procedure, input: &Request, interrupt_at: Option<u64>) -> Result<Evaluation, Error> {
    run(procedure, input, None, interrupt_at)
}

/// Rebuild the formula from expected inputs before independently checking its certificate.
/// (´[ROOT-rule:design:backend-evidence]´)
/// # Errors
/// Refuses an input change that alters the rebuilt query, an invalid certificate, domain or policy.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::replay"
    ),
    ret
)]
pub fn replay(
    procedure: &Procedure,
    input: &Request,
    evidence: &Attachment,
    interrupt_at: Option<u64>,
) -> Result<Evaluation, Error> {
    run(procedure, input, Some(evidence), interrupt_at)
}
