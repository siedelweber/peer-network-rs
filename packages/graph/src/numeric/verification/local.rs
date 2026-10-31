//! A separate local inclusion with a deterministic identity preconditioner.
//! (´[ROOT-alg:design:residual]´)
use super::{
    Error,
    arithmetic::{Arithmetic, magnitude},
    budget, dual,
    map::{self, Engine, Prepared},
    replay_two_map,
};
use nrz_cas::{Rational, enclosure::Interval};
use pn_records::{
    conserved::{LocalDeclaration, LocalRecord, LocalVerdict, TwoMapRecord, VerificationInput},
    primitive::Range,
    solve::Procedure,
};

struct Neighborhood {
    active: Vec<usize>,
    center: Vec<Range>,
    domain: Vec<Range>,
    radius: Rational,
    above_wall: bool,
    inside_hull: bool,
}

fn identity(active: &[usize]) -> Vec<Vec<String>> {
    active
        .iter()
        .map(|i| active.iter().map(|j| if i == j { "1".into() } else { "0".into() }).collect())
        .collect()
}

fn domain(
    engine: &mut Engine<'_>,
    input: &VerificationInput,
    record: &TwoMapRecord,
    declaration: &LocalDeclaration,
    prepared: &Prepared,
) -> Result<Neighborhood, Error> {
    let arithmetic = &mut engine.arithmetic;
    let one = Rational::parse("1", &mut arithmetic.budget)?;
    let two = Rational::parse("2", &mut arithmetic.budget)?;
    let inflation = Rational::parse(&declaration.inflation, &mut arithmetic.budget)?;
    let padding = Rational::parse(&declaration.padding, &mut arithmetic.budget)?;
    if !inflation.compare(&one, &mut arithmetic.budget)?.is_gt() || padding.is_zero() || padding.is_negative() {
        return Err(Error::Declaration);
    }
    let active: Vec<_> = prepared
        .support
        .iter()
        .enumerate()
        .filter(|(_, v)| v.len() > 1)
        .map(|(i, _)| i)
        .collect();
    if active.is_empty() {
        return Err(Error::Declaration);
    }
    let maximum = usize::try_from(
        engine
            .policy
            .enclosure
            .as_ref()
            .ok_or(Error::Declaration)?
            .operation
            .proof_nodes,
    )
    .map_err(|_| Error::Declaration)?;
    if active
        .len()
        .checked_mul(input.sources.len())
        .and_then(|n| n.checked_mul(input.sources.len()))
        .and_then(|n| n.checked_mul(input.shape.len() + 3))
        .is_none_or(|n| n > maximum)
    {
        return Err(Error::Declaration);
    }
    let mut uncertainty = Rational::parse("0", &mut arithmetic.budget)?;
    let mut center = Vec::new();
    for (i, image) in record.first.image.iter().enumerate() {
        let image = arithmetic.range(image)?;
        let midpoint = image
            .lower()
            .add(image.upper(), &mut arithmetic.budget)?
            .div(&two, &mut arithmetic.budget)?;
        if active.contains(&i) {
            let half = image
                .upper()
                .sub(image.lower(), &mut arithmetic.budget)?
                .div(&two, &mut arithmetic.budget)?;
            if half.compare(&uncertainty, &mut arithmetic.budget)?.is_gt() {
                uncertainty = half;
            }
            let point = Interval::singleton(&midpoint, &mut arithmetic.budget)?;
            center.push(arithmetic.encode(&point)?);
        } else {
            center.push(arithmetic.encode(&prepared.rates[i])?);
        }
    }
    let residual = Rational::parse(&record.radius, &mut arithmetic.budget)?;
    let radius = residual
        .add(&uncertainty, &mut arithmetic.budget)?
        .mul(&inflation, &mut arithmetic.budget)?
        .add(&padding, &mut arithmetic.budget)?;
    let wall = arithmetic.range(&input.wall)?;
    let mut domain = center.clone();
    let mut above_wall = true;
    let mut inside_hull = true;
    for i in &active {
        let point = arithmetic.range(&center[*i])?;
        let range = Interval::new(
            point.lower().sub(&radius, &mut arithmetic.budget)?,
            point.upper().add(&radius, &mut arithmetic.budget)?,
            &mut arithmetic.budget,
        )?;
        above_wall &= range.lower().compare(wall.upper(), &mut arithmetic.budget)?.is_gt();
        let inner = arithmetic.range(&prepared.inner_hull[*i])?;
        inside_hull &= !range.lower().compare(inner.lower(), &mut arithmetic.budget)?.is_lt()
            && !range.upper().compare(inner.upper(), &mut arithmetic.budget)?.is_gt();
        domain[*i] = arithmetic.encode(&range)?;
    }
    Ok(Neighborhood {
        active,
        center,
        domain,
        radius,
        above_wall,
        inside_hull,
    })
}

fn inclusion(
    engine: &mut Engine<'_>,
    input: &VerificationInput,
    prepared: &Prepared,
    domain: &Neighborhood,
    declaration: &LocalDeclaration,
) -> Result<LocalRecord, Error> {
    let image = map::image(engine, input, &domain.center, prepared)?;
    let differential = dual::image(engine, input, &domain.domain, prepared, &domain.active)?;
    let arithmetic = &mut engine.arithmetic;
    let mut asserted = image;
    let mut jacobian = Vec::new();
    let mut norm = Rational::parse("0", &mut arithmetic.budget)?;
    let mut radius = norm.clone();
    let mut included = domain.above_wall && domain.inside_hull;
    for i in &domain.active {
        let mut value = arithmetic.range(&asserted[*i])?;
        let mut row = Vec::new();
        let mut row_norm = Rational::parse("0", &mut arithmetic.budget)?;
        for (j, derivative) in domain.active.iter().zip(&differential[*i].gradient) {
            let box_value = arithmetic.range(&domain.domain[*j])?;
            let center = arithmetic.range(&domain.center[*j])?;
            let delta = arithmetic.sub(&box_value, &center)?;
            let term = arithmetic.mul(derivative, &delta)?;
            value = arithmetic.add(&value, &term)?;
            let absolute = magnitude(derivative, &mut arithmetic.budget)?;
            row_norm = row_norm.add(&absolute, &mut arithmetic.budget)?;
            row.push(arithmetic.encode(derivative)?);
        }
        if row_norm.compare(&norm, &mut arithmetic.budget)?.is_gt() {
            norm = row_norm;
        }
        let box_value = arithmetic.range(&domain.domain[*i])?;
        included &= value.lower().compare(box_value.lower(), &mut arithmetic.budget)?.is_gt()
            && value.upper().compare(box_value.upper(), &mut arithmetic.budget)?.is_lt();
        let center = arithmetic.range(&domain.center[*i])?;
        let deviation = arithmetic.sub(&value, &center)?;
        let bound = magnitude(&deviation, &mut arithmetic.budget)?;
        if bound.compare(&radius, &mut arithmetic.budget)?.is_gt() {
            radius = bound;
        }
        asserted[*i] = arithmetic.encode(&value)?;
        jacobian.push(row);
    }
    let one = Rational::parse("1", &mut arithmetic.budget)?;
    included &= norm.compare(&one, &mut arithmetic.budget)?.is_lt();
    let preconditioner = identity(&domain.active);
    let norm = norm.exact_string(&mut arithmetic.budget)?;
    let radius = radius.exact_string(&mut arithmetic.budget)?;
    let inflation_radius = domain.radius.exact_string(&mut arithmetic.budget)?;
    Ok(LocalRecord {
        declaration: declaration.clone(),
        active: domain.active.clone(),
        center: domain.center.clone(),
        domain: domain.domain.clone(),
        preconditioner,
        preconditioner_denominator: "1".into(),
        jacobian,
        asserted,
        jacobian_norm: norm,
        inflation_radius,
        image_radius: radius,
        above_wall: domain.above_wall,
        verdict: if included {
            LocalVerdict::Included
        } else {
            LocalVerdict::Unresolved
        },
        primitives: std::mem::take(&mut engine.records),
        work: arithmetic.budget.usage().work,
    })
}

fn run(
    p: &Procedure,
    input: &VerificationInput,
    residual: &TwoMapRecord,
    declaration: &LocalDeclaration,
    supplied: Option<&LocalRecord>,
) -> Result<LocalRecord, Error> {
    let mut local_policy = p.clone();
    let limits = local_policy.enclosure.as_mut().ok_or(Error::Declaration)?;
    if declaration.maximum_work > limits.operation.work || declaration.maximum_work == 0 {
        return Err(Error::Declaration);
    }
    limits.operation.work = declaration.maximum_work;
    let mut engine = Engine {
        arithmetic: Arithmetic {
            budget: budget(&local_policy)?,
            bits: input.endpoint_bits,
        },
        policy: &local_policy,
        supplied: supplied.map(|r| r.primitives.as_slice()),
        records: Vec::new(),
    };
    let prepared = map::prepare(&mut engine, input)?;
    let domain = domain(&mut engine, input, residual, declaration, &prepared)?;
    if supplied.is_some_and(|r| {
        r.declaration != *declaration
            || r.active != domain.active
            || r.domain != domain.domain
            || r.center != domain.center
            || r.preconditioner != identity(&domain.active)
            || r.preconditioner_denominator != "1"
    }) {
        return Err(Error::Declaration);
    }
    let result = inclusion(&mut engine, input, &prepared, &domain, declaration)?;
    if let Some(supplied) = supplied {
        let mut expected = supplied.clone();
        expected.work = result.work;
        expected.primitives.clone_from(&result.primitives);
        if expected != result || supplied.primitives.len() != result.primitives.len() {
            return Err(Error::Declaration);
        }
    }
    Ok(result)
}

/// Corroborate a replayed two-map residual with a separate local inclusion verdict.
/// (´[ROOT-alg:design:residual]´)
/// # Errors
/// Refuses malformed declarations, unverified residual evidence or exhausted Work.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::verification::local::local_check"
    ),
    ret
)]
pub fn local_check(
    p: &Procedure,
    input: &VerificationInput,
    candidate: &[Range],
    residual: &TwoMapRecord,
    declaration: &LocalDeclaration,
) -> Result<LocalRecord, Error> {
    replay_two_map(p, input, candidate, residual)?;
    run(p, input, residual, declaration, None)
}

/// Rebuild the box, identity preconditioner, all derivative queries and asserted image.
/// (´[ROOT-alg:design:residual]´)
/// # Errors
/// Refuses changed preconditioner, box, asserted coordinate, scalar premise or input.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::verification::local::replay_local"
    ),
    ret
)]
pub fn replay_local(
    p: &Procedure,
    input: &VerificationInput,
    candidate: &[Range],
    residual: &TwoMapRecord,
    declaration: &LocalDeclaration,
    record: &LocalRecord,
) -> Result<LocalRecord, Error> {
    replay_two_map(p, input, candidate, residual)?;
    run(p, input, residual, declaration, Some(record))
}
