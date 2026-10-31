//! Interval forward differentiation of the mathematical transport, not its rounding.
//! (´[ROOT-alg:design:residual]´)
use super::{
    Error,
    arithmetic::Arithmetic,
    map::{Engine, Prepared},
};
use crate::numeric::activation::{self, Quantity, Request};
use nrz_cas::enclosure::Interval;
use pn_records::{
    conserved::VerificationInput,
    primitive::{Node, Range},
};

pub(super) struct Dual {
    pub value: Interval,
    pub gradient: Vec<Interval>,
}

fn constant(value: Interval, zero: &Interval, dimensions: usize) -> Dual {
    Dual {
        value,
        gradient: vec![zero.clone(); dimensions],
    }
}

fn add(a: &Dual, b: &Dual, arithmetic: &mut Arithmetic) -> Result<Dual, Error> {
    let value = arithmetic.add(&a.value, &b.value)?;
    let gradient = a
        .gradient
        .iter()
        .zip(&b.gradient)
        .map(|(a, b)| arithmetic.add(a, b))
        .collect::<Result<_, _>>()?;
    Ok(Dual { value, gradient })
}

fn multiply(a: &Dual, b: &Dual, arithmetic: &mut Arithmetic) -> Result<Dual, Error> {
    let value = arithmetic.mul(&a.value, &b.value)?;
    let mut gradient = Vec::new();
    for (left, right) in a.gradient.iter().zip(&b.gradient) {
        let first = arithmetic.mul(left, &b.value)?;
        let second = arithmetic.mul(&a.value, right)?;
        gradient.push(arithmetic.add(&first, &second)?);
    }
    Ok(Dual { value, gradient })
}

fn divide(a: &Dual, b: &Dual, arithmetic: &mut Arithmetic) -> Result<Dual, Error> {
    let value = arithmetic.div(&a.value, &b.value)?;
    let squared = arithmetic.mul(&b.value, &b.value)?;
    let mut gradient = Vec::new();
    for (left, right) in a.gradient.iter().zip(&b.gradient) {
        let first = arithmetic.mul(left, &b.value)?;
        let second = arithmetic.mul(&a.value, right)?;
        let numerator = arithmetic.sub(&first, &second)?;
        gradient.push(arithmetic.div(&numerator, &squared)?);
    }
    Ok(Dual { value, gradient })
}

fn activations(
    engine: &mut Engine<'_>,
    input: &VerificationInput,
    coordinates: &[Range],
    active: &[usize],
    shape: &str,
) -> Result<Vec<Dual>, Error> {
    let zero = engine.arithmetic.scalar("0")?;
    let mut result = Vec::new();
    for (index, coordinate) in coordinates.iter().enumerate() {
        let request = Request {
            standing: coordinate.clone(),
            bleed_squared: "1/400".into(),
            wall: None,
            wall_enclosure: Some(input.wall.clone()),
            quantity: Quantity::Hop {
                strength: input.strength.clone(),
                shape: shape.into(),
            },
        };
        let mut query = activation::query(&request, &mut engine.arithmetic.budget)?;
        let value = engine.query(query.clone())?;
        let mut value = constant(value, &zero, active.len());
        if let Some(column) = active.iter().position(|i| *i == index) {
            query.nodes.push(Node::GeneralizedDerivative(query.target, 0));
            query.target = query.nodes.len() - 1;
            value.gradient[column] = engine.query(query)?;
        }
        result.push(value);
    }
    Ok(result)
}

fn hop(engine: &mut Engine<'_>, prepared: &Prepared, values: &[Dual], dimensions: usize) -> Result<Vec<Vec<Dual>>, Error> {
    let arithmetic = &mut engine.arithmetic;
    let zero = arithmetic.scalar("0")?;
    let mut result = Vec::new();
    for (i, row) in prepared.base.iter().enumerate() {
        let mut sum = constant(zero.clone(), &zero, dimensions);
        let mut normalized = Vec::new();
        for (j, value) in row.iter().enumerate() {
            let base = constant(value.clone(), &zero, dimensions);
            let value = if i == j {
                base
            } else {
                multiply(&base, &values[j], arithmetic)?
            };
            sum = add(&sum, &value, arithmetic)?;
            normalized.push(value);
        }
        result.push(
            normalized
                .iter()
                .map(|v| divide(v, &sum, arithmetic))
                .collect::<Result<_, _>>()?,
        );
    }
    Ok(result)
}

fn product(
    left: &[Vec<Dual>],
    right: &[Vec<Dual>],
    arithmetic: &mut Arithmetic,
    dimensions: usize,
) -> Result<Vec<Vec<Dual>>, Error> {
    let zero = arithmetic.scalar("0")?;
    let mut result = Vec::new();
    for row in left {
        let mut next = Vec::new();
        for (j, _) in right.iter().enumerate() {
            let mut sum = constant(zero.clone(), &zero, dimensions);
            for (k, value) in row.iter().enumerate() {
                let term = multiply(value, &right[k][j], arithmetic)?;
                sum = add(&sum, &term, arithmetic)?;
            }
            next.push(sum);
        }
        result.push(next);
    }
    Ok(result)
}

pub(super) fn image(
    engine: &mut Engine<'_>,
    input: &VerificationInput,
    coordinates: &[Range],
    prepared: &Prepared,
    active: &[usize],
) -> Result<Vec<Dual>, Error> {
    let size = coordinates.len();
    if size != input.sources.len() {
        return Err(Error::Declaration);
    }
    let zero = engine.arithmetic.scalar("0")?;
    let one = engine.arithmetic.scalar("1")?;
    let mut accumulated = Vec::new();
    let mut mixture = Vec::new();
    for i in 0..size {
        accumulated.push(
            (0..size)
                .map(|j| constant(if i == j { one.clone() } else { zero.clone() }, &zero, active.len()))
                .collect::<Vec<_>>(),
        );
        mixture.push(
            (0..size)
                .map(|_| constant(zero.clone(), &zero, active.len()))
                .collect::<Vec<_>>(),
        );
    }
    for (shape, mass) in input.shape.iter().zip(&input.depth_mass) {
        let values = activations(engine, input, coordinates, active, shape)?;
        let hop = hop(engine, prepared, &values, active.len())?;
        accumulated = product(&accumulated, &hop, &mut engine.arithmetic, active.len())?;
        let arithmetic = &mut engine.arithmetic;
        let mass = constant(arithmetic.scalar(mass)?, &zero, active.len());
        for (row, products) in mixture.iter_mut().zip(&accumulated) {
            for (value, term) in row.iter_mut().zip(products) {
                let term = multiply(term, &mass, arithmetic)?;
                *value = add(value, &term, arithmetic)?;
            }
        }
    }
    let arithmetic = &mut engine.arithmetic;
    let mut result = Vec::new();
    for (j, sources) in prepared.support.iter().enumerate() {
        if sources.len() == 1 {
            result.push(constant(prepared.rates[j].clone(), &zero, active.len()));
            continue;
        }
        let mut numerator = constant(zero.clone(), &zero, active.len());
        let mut denominator = constant(zero.clone(), &zero, active.len());
        for (u, row) in mixture.iter().enumerate() {
            let count = constant(prepared.counts[u].clone(), &zero, active.len());
            let count = multiply(&row[j], &count, arithmetic)?;
            denominator = add(&denominator, &count, arithmetic)?;
            let rate = constant(prepared.rates[u].clone(), &zero, active.len());
            let weighted = multiply(&count, &rate, arithmetic)?;
            numerator = add(&numerator, &weighted, arithmetic)?;
        }
        result.push(divide(&numerator, &denominator, arithmetic)?);
    }
    Ok(result)
}
