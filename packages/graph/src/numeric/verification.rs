//! Separately declared image-first verification over rational endpoint boxes.
//! (´[ROOT-alg:design:residual]´)

mod arithmetic;
mod map;

use super::Error;
use arithmetic::{Arithmetic, magnitude};
use nrz_cas::{Rational, enclosure::Interval, limits::Budget};
use pn_records::{
    conserved::{BoxMapRecord, TwoMapRecord, VerificationInput},
    primitive::Range,
    solve::Procedure,
};

fn budget(p: &Procedure) -> Result<Budget, Error> {
    super::preflight(p)?;
    Ok(Budget::new(
        p.enclosure.as_ref().ok_or(Error::Declaration)?.operation.clone(),
    )?)
}

/// Evaluate the declared full-emission map on the complete independent coordinate box.
/// (´[ROOT-alg:design:residual]´)
/// # Errors
/// Refuses malformed inputs, unsupported branches, an unproved fence or exhausted resources.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::verification::evaluate_box"
    ),
    ret
)]
pub fn evaluate_box(p: &Procedure, input: &VerificationInput, coordinates: &[Range]) -> Result<BoxMapRecord, Error> {
    map::run(p, input, coordinates, None)
}

/// Rebuild every box-map question and independently check its attachment.
/// (´[ROOT-alg:design:residual]´)
/// # Errors
/// Refuses a changed declaration, coordinate, query, attachment or derived result.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::verification::replay_box"
    ),
    ret
)]
pub fn replay_box(
    p: &Procedure,
    input: &VerificationInput,
    coordinates: &[Range],
    record: &BoxMapRecord,
) -> Result<BoxMapRecord, Error> {
    if &record.input != input || record.coordinates != coordinates {
        return Err(Error::Declaration);
    }
    map::run(p, input, coordinates, Some(record))
}

fn residual(a: &[Range], z: &[Range], c: &Rational, arithmetic: &mut Arithmetic) -> Result<Rational, Error> {
    if a.len() != z.len() {
        return Err(Error::Declaration);
    }
    let mut maximum = Rational::parse("0", &mut arithmetic.budget)?;
    for (a, z) in a.iter().zip(z) {
        let left = arithmetic.range(a)?;
        let right = arithmetic.range(z)?;
        let difference = arithmetic.sub(&left, &right)?;
        let bound = magnitude(&difference, &mut arithmetic.budget)?;
        if bound.compare(&maximum, &mut arithmetic.budget)?.is_gt() {
            maximum = bound;
        }
    }
    let one = Rational::parse("1", &mut arithmetic.budget)?;
    if c.is_negative() || !c.compare(&one, &mut arithmetic.budget)?.is_lt() {
        return Err(Error::Declaration);
    }
    Ok(maximum.div(&one.sub(c, &mut arithmetic.budget)?, &mut arithmetic.budget)?)
}

fn assemble(p: &Procedure, first: BoxMapRecord, second: BoxMapRecord) -> Result<TwoMapRecord, Error> {
    if first.contraction != second.contraction || first.coordinates.iter().any(|v| v.lower != v.upper) {
        return Err(Error::Declaration);
    }
    let mut a = Arithmetic {
        budget: budget(p)?,
        bits: first.input.endpoint_bits,
    };
    let c = Rational::parse(&first.contraction, &mut a.budget)?;
    let mut comparison = first.coordinates.clone();
    for (index, value) in comparison.iter_mut().enumerate() {
        if first.singleton[index] {
            *value = first.hull[index].clone();
        } else {
            let point = a.range(value)?;
            let inner = a.range(&first.inner_hull[index])?;
            if point.lower().compare(inner.lower(), &mut a.budget)?.is_lt()
                || point.upper().compare(inner.upper(), &mut a.budget)?.is_gt()
            {
                return Err(Error::Declaration);
            }
        }
    }
    let one_map = residual(&first.image, &comparison, &c, &mut a)?;
    let radius = residual(&second.image, &first.image, &c, &mut a)?;
    let mut enclosure = Vec::new();
    for value in &first.image {
        let value = a.range(value)?;
        let interval = Interval::new(
            value.lower().sub(&radius, &mut a.budget)?,
            value.upper().add(&radius, &mut a.budget)?,
            &mut a.budget,
        )?;
        enclosure.push(a.encode(&interval)?);
    }
    let radius = radius.exact_string(&mut a.budget)?;
    let one_map_radius = one_map.exact_string(&mut a.budget)?;
    Ok(TwoMapRecord {
        first,
        second,
        radius,
        one_map_radius,
        enclosure,
        assembly_work: a.budget.usage().work,
    })
}

/// Certify y=F(z), then F(Y), and bound the residual about the exact image y.
/// (´[ROOT-alg:design:residual]´)
/// # Errors
/// Refuses a nonpoint candidate, failed map/fence evidence or resource exhaustion.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::verification::two_map"
    ),
    ret
)]
pub fn two_map(p: &Procedure, input: &VerificationInput, candidate: &[Range]) -> Result<TwoMapRecord, Error> {
    let first = evaluate_box(p, input, candidate)?;
    let second = evaluate_box(p, input, &first.image)?;
    assemble(p, first, second)
}

/// Independently replay both maps and reconstruct both reported residual radii.
/// (´[ROOT-alg:design:residual]´)
/// # Errors
/// Refuses altered scope, evidence or residual outputs.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::verification::replay_two_map"
    ),
    ret
)]
pub fn replay_two_map(
    p: &Procedure,
    input: &VerificationInput,
    candidate: &[Range],
    record: &TwoMapRecord,
) -> Result<TwoMapRecord, Error> {
    let first = replay_box(p, input, candidate, &record.first)?;
    let second = replay_box(p, input, &first.image, &record.second)?;
    let result = assemble(p, first, second)?;
    if result.radius != record.radius || result.one_map_radius != record.one_map_radius || result.enclosure != record.enclosure {
        return Err(Error::Declaration);
    }
    Ok(result)
}
