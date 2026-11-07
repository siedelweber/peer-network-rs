//! Responsive activation and its wall clamp, with separate deployed and clean gains.
//! (´def:numerics:activation´)

pub mod bounded;
pub mod fence;
pub mod monotone;
pub mod sharing;

use super::Error;
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    primitive::{Attachment, Goal, Node, PrimitiveRecord, Query, Range},
    solve::Procedure,
};

/// Distinct formula requests; a generalized slope is never a smooth derivative.
/// (´def:numerics:activation´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Quantity {
    Responsive,
    Clamped,
    Hop { strength: String, shape: String },
    ResponsiveLogGain,
    CleanScreenLogGain,
    GeneralizedLogGain,
}

/// Public standing box and bleed, with either a rational or independent enclosed wall.
/// (´def:numerics:activation´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Request {
    pub standing: Range,
    pub bleed_squared: String,
    pub wall: Option<String>,
    pub wall_enclosure: Option<Range>,
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

fn wall_binding(procedure: &Procedure, input: &Request, budget: &mut Budget) -> Result<(), Error> {
    if let Some(wall) = &input.wall_enclosure {
        let k = procedure
            .enclosure
            .as_ref()
            .ok_or(Error::Unsupported)?
            .refinement
            .reduction_ceiling;
        let scale = 1_u64.checked_shl(k).filter(|v| *v > 2).ok_or(Error::Declaration)?;
        let minimum = Rational::parse("1", budget)?.div(&Rational::parse(&(scale - 2).to_string(), budget)?, budget)?;
        if Rational::parse(&wall.lower, budget)?.compare(&minimum, budget)?.is_lt() {
            return Err(Error::Declaration);
        }
    }
    Ok(())
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
    if clamped != (input.wall.is_some() || input.wall_enclosure.is_some())
        || (input.wall.is_some() && input.wall_enclosure.is_some())
    {
        return Err(Error::Declaration);
    }
    if let Some(wall) = &input.wall
        && nonnegative(wall, budget)?.is_zero()
    {
        return Err(Error::Declaration);
    }
    if let Some(wall) = &input.wall_enclosure {
        let a = nonnegative(&wall.lower, budget)?;
        let z = nonnegative(&wall.upper, budget)?;
        if a.is_zero() || a.compare(&z, budget)?.is_gt() {
            return Err(Error::Declaration);
        }
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

fn log_core(nodes: &mut Vec<Node>, p: usize, beta: usize, bleed: usize, one: usize) -> usize {
    let temperature = push(nodes, Node::Multiply(beta, p));
    let sigmoid = push(nodes, Node::Sigmoid(temperature));
    let t = push(nodes, Node::Tanh(p));
    let leaked = push(nodes, Node::Multiply(bleed, t));
    let remaining = push(nodes, Node::Subtract(one, leaked));
    let log_t = push(nodes, Node::Logarithm(t));
    let log_remaining = push(nodes, Node::Logarithm(remaining));
    let sum = push(nodes, Node::Add(log_t, log_remaining));
    let half = push(nodes, Node::Rational("1/2".into()));
    let log_root = push(nodes, Node::Multiply(half, sum));
    let log_sigmoid = push(nodes, Node::Logarithm(sigmoid));
    push(nodes, Node::Add(log_sigmoid, log_root))
}

pub(super) fn query(input: &Request, budget: &mut Budget) -> Result<Query, Error> {
    shared_query(input, budget, None)
}

fn shared_query(input: &Request, budget: &mut Budget, constants: Option<&[Range; 2]>) -> Result<Query, Error> {
    let exponent = validate(input, budget)?;
    let mut nodes = vec![Node::Coordinate(0), Node::Rational("1".into()), Node::Rational("2".into())];
    let beta = if constants.is_some() {
        push(&mut nodes, Node::Coordinate(1))
    } else {
        let logarithm = push(&mut nodes, Node::Logarithm(2));
        push(&mut nodes, Node::Multiply(2, logarithm))
    };
    let clean = input.quantity == Quantity::CleanScreenLogGain;
    let bleed = push(
        &mut nodes,
        Node::Rational(if clean { "0".into() } else { input.bleed_squared.clone() }),
    );
    let x = if let Some(wall) = &input.wall {
        let wall = push(&mut nodes, Node::Rational(wall.clone()));
        push(&mut nodes, Node::Clamp(0, wall))
    } else if input.wall_enclosure.is_some() {
        let index = if constants.is_some() { 3 } else { 1 };
        let wall = push(&mut nodes, Node::Coordinate(index));
        push(&mut nodes, Node::Clamp(0, wall))
    } else {
        0
    };
    let denominator = push(&mut nodes, Node::Add(1, x));
    let reciprocal = push(&mut nodes, Node::Divide(1, denominator));
    let p = push(&mut nodes, Node::Subtract(1, reciprocal));
    let gain = matches!(input.quantity, Quantity::ResponsiveLogGain | Quantity::GeneralizedLogGain);
    let mut value = if gain {
        log_core(&mut nodes, p, beta, bleed, 1)
    } else if clean {
        core(&mut nodes, p, beta, bleed, 1)
    } else {
        let q = core(&mut nodes, p, beta, bleed, 1);
        let normalization = if constants.is_some() {
            push(&mut nodes, Node::Coordinate(2))
        } else {
            core(&mut nodes, 1, beta, bleed, 1)
        };
        let normalized = push(&mut nodes, Node::Divide(q, normalization));
        if input.wall.is_some() || input.wall_enclosure.is_some() || !Rational::parse(&input.standing.lower, budget)?.is_zero() {
            push(&mut nodes, Node::PositivePower(normalized, "1/4".into()))
        } else {
            let square = push(&mut nodes, Node::SquareRoot(normalized));
            push(&mut nodes, Node::SquareRoot(square))
        }
    };
    if let Some(exponent) = exponent {
        value = push(&mut nodes, Node::PositivePower(value, exponent));
    }
    if matches!(
        input.quantity,
        Quantity::ResponsiveLogGain | Quantity::CleanScreenLogGain | Quantity::GeneralizedLogGain
    ) {
        let logarithm = if gain {
            let quarter = push(&mut nodes, Node::Rational("1/4".into()));
            push(&mut nodes, Node::Multiply(quarter, value))
        } else {
            push(&mut nodes, Node::Logarithm(value))
        };
        value = push(
            &mut nodes,
            if input.quantity == Quantity::GeneralizedLogGain {
                Node::GeneralizedDerivative(logarithm, 0)
            } else {
                Node::Derivative(logarithm, 0)
            },
        );
    }
    let mut coordinates = vec![input.standing.clone()];
    if let Some(constants) = constants {
        coordinates.extend_from_slice(constants);
    }
    if let Some(wall) = &input.wall_enclosure {
        coordinates.push(wall.clone());
    }
    Ok(Query {
        coordinates,
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
    wall_binding(procedure, input, &mut budget)?;
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
