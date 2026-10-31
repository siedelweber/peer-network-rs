//! Original ordered real scopes with exact rational parsing and no caller assumptions.

use super::Error;
use nrz_cas::{
    Cas, Handle, Rational, Reference,
    domain::{AmbientDomain, ContextDraft, HeaderDraft, RegionDraft, RegionExpr},
    enclosure::{CoordinateBound, EnclosureGoal, EnclosureRequest, Interval},
    limits::Budget,
    syntax::{AtomicSort, Branch, Declaration, Draft, Environment, ExpressionDraft, Field, Operator, Sort},
};
use pn_records::{
    primitive::{Goal, Node, Query},
    solve::{Primitive, Procedure},
};

fn real() -> Sort {
    Sort::Value(AtomicSort::Scalar(Field::Real))
}

fn term(cas: &mut Cas, header: &Handle, operator: Operator, operands: Vec<Handle>, budget: &mut Budget) -> Result<Handle, Error> {
    let draft = Draft::Expression(ExpressionDraft {
        space: None,
        operator,
        sort: real(),
        header: Reference::Existing(header.clone()),
        scope: Vec::new(),
        binding: None,
        operands: operands.into_iter().map(Reference::Existing).collect(),
    });
    cas.admit(&[draft], budget)?.into_iter().next().ok_or(Error::Declaration)
}

fn required(node: &Node) -> Primitive {
    match node {
        Node::SquareRoot(_) => Primitive::Root,
        Node::Logarithm(_) => Primitive::Logarithm,
        Node::Exponential(_) => Primitive::Exponential,
        Node::Sigmoid(_) => Primitive::Sigmoid,
        Node::Tanh(_) => Primitive::Tanh,
        Node::PositivePower(_, _) => Primitive::Power,
        Node::Derivative(_, _) => Primitive::SmoothDerivative,
        Node::Clamp(_, _) | Node::GeneralizedDerivative(_, _) => Primitive::ClampGeneralized,
        _ => Primitive::Rational,
    }
}

fn binary(node: &Node) -> Option<(Operator, usize, usize)> {
    match *node {
        Node::Add(a, b) => Some((Operator::Add, a, b)),
        Node::Subtract(a, b) => Some((Operator::Sub, a, b)),
        Node::Multiply(a, b) => Some((Operator::Mul, a, b)),
        Node::Divide(a, b) => Some((Operator::Div, a, b)),
        Node::Clamp(a, b) => Some((Operator::ClampFloor, a, b)),
        _ => None,
    }
}

fn expression(
    cas: &mut Cas,
    header: &Handle,
    nodes: &[Handle],
    coordinates: &[Handle],
    node: &Node,
    budget: &mut Budget,
) -> Result<Handle, Error> {
    let get = |index: usize| nodes.get(index).cloned().ok_or(Error::Declaration);
    if let Some((operator, a, b)) = binary(node) {
        return term(cas, header, operator, vec![get(a)?, get(b)?], budget);
    }
    let (operator, operands) = match node {
        Node::Rational(text) => (Operator::Rational(Rational::parse(text, budget)?), Vec::new()),
        Node::Coordinate(index) => return coordinates.get(*index).cloned().ok_or(Error::Declaration),
        Node::Negate(a) => (Operator::Neg, vec![get(*a)?]),
        Node::Logarithm(a) => (Operator::NaturalLog, vec![get(*a)?]),
        Node::Exponential(a) => (Operator::Exponential, vec![get(*a)?]),
        Node::Sigmoid(a) => (Operator::Sigmoid, vec![get(*a)?]),
        Node::Tanh(a) => (Operator::Tanh, vec![get(*a)?]),
        Node::SquareRoot(a) => {
            let half = Rational::parse("1/2", budget)?;
            let exponent = term(cas, header, Operator::Rational(half), Vec::new(), budget)?;
            (Operator::GeneralPower(Branch::StrictReal), vec![get(*a)?, exponent])
        }
        Node::PositivePower(a, text) => {
            let exponent = Rational::parse(text, budget)?;
            let exponent = term(cas, header, Operator::Rational(exponent), Vec::new(), budget)?;
            (Operator::PositivePower, vec![get(*a)?, exponent])
        }
        Node::Derivative(a, coordinate) | Node::GeneralizedDerivative(a, coordinate) => {
            if *coordinate >= coordinates.len() {
                return Err(Error::Declaration);
            }
            let name = format!("x{coordinate}");
            let operator = if matches!(node, Node::Derivative(_, _)) {
                Operator::Derivative(name)
            } else {
                Operator::GeneralizedDerivative(name)
            };
            (operator, vec![get(*a)?])
        }
        _ => return Err(Error::Declaration),
    };
    term(cas, header, operator, operands, budget)
}

pub(super) fn build(procedure: &Procedure, query: &Query, budget: &mut Budget) -> Result<(Cas, EnclosureRequest), Error> {
    let policy = procedure.enclosure.as_ref().ok_or(Error::Unsupported)?;
    let node_count = u64::try_from(query.nodes.len()).map_err(|_| Error::Declaration)?;
    let coordinates = u64::try_from(query.coordinates.len()).map_err(|_| Error::Declaration)?;
    if node_count > policy.operation.proof_nodes.min(policy.store.proof_nodes)
        || coordinates > policy.operation.matrix_entries.min(policy.store.matrix_entries)
    {
        return Err(Error::Declaration);
    }
    if query.target.checked_add(1) != Some(query.nodes.len()) {
        return Err(Error::Declaration);
    }
    for node in &query.nodes {
        if !procedure.primitives.contains(&required(node)) {
            return Err(Error::Unsupported);
        }
    }
    let mut environment = Environment::default();
    for index in 0..query.coordinates.len() {
        let key = format!("x{index}");
        environment.declarations.push(Declaration {
            display_name: key.clone(),
            key,
            sort: real(),
        });
    }
    let mut cas = Cas::new(policy.store.clone())?;
    let drafts = [
        Draft::Header(HeaderDraft::Core(environment)),
        Draft::Region(RegionDraft {
            header: Reference::Local(0),
            scope: Vec::new(),
            ambient: AmbientDomain::Assignments,
            expression: RegionExpr::Ambient,
        }),
        Draft::Context(ContextDraft::Root {
            header: Reference::Local(0),
            admissible: Reference::Local(1),
            assumptions: Vec::new(),
        }),
    ];
    let [header, _, context]: [Handle; 3] = cas.admit(&drafts, budget)?.try_into().map_err(|_| Error::Declaration)?;
    let mut coordinates = Vec::new();
    let mut bounds = Vec::new();
    for (index, range) in query.coordinates.iter().enumerate() {
        let coordinate = term(&mut cas, &header, Operator::Free(format!("x{index}")), Vec::new(), budget)?;
        let interval = Interval::new(
            Rational::parse(&range.lower, budget)?,
            Rational::parse(&range.upper, budget)?,
            budget,
        )?;
        bounds.push(CoordinateBound {
            coordinate: coordinate.clone(),
            interval,
        });
        coordinates.push(coordinate);
    }
    let mut nodes = Vec::new();
    for node in &query.nodes {
        nodes.push(expression(&mut cas, &header, &nodes, &coordinates, node, budget)?);
    }
    let target = nodes.get(query.target).cloned().ok_or(Error::Declaration)?;
    let goal = match &query.goal {
        Goal::Width => EnclosureGoal::Width,
        Goal::AtMost(text) => EnclosureGoal::AtMost(Rational::parse(text, budget)?),
        Goal::LessThan(text) => EnclosureGoal::LessThan(Rational::parse(text, budget)?),
        Goal::Equal(text) => EnclosureGoal::Equal(Rational::parse(text, budget)?),
    };
    Ok((
        cas,
        EnclosureRequest {
            target,
            context,
            coordinates: bounds,
            goal,
        },
    ))
}
