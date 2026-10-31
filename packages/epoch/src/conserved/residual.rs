//! Rational projection, deterministic grid proposals and the one-map residual check.
//! (´[ROOT-alg:design:residual]´)
use super::Error;
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    conserved::{MapRecord, ResidualRound},
    solve::Bounds,
};
use std::collections::BTreeMap;

fn project(value: Rational, range: &Bounds, b: &mut Budget) -> Result<Rational, Error> {
    let lo = Rational::parse(&range.lower, b)?;
    let hi = Rational::parse(&range.upper, b)?;
    if value.compare(&lo, b)?.is_lt() {
        Ok(lo)
    } else if value.compare(&hi, b)?.is_gt() {
        Ok(hi)
    } else {
        Ok(value)
    }
}

pub(super) fn projected(
    point: &BTreeMap<String, String>,
    hull: &BTreeMap<String, Bounds>,
    b: &mut Budget,
) -> Result<BTreeMap<String, String>, Error> {
    if point.keys().ne(hull.keys()) {
        return Err(Error::Scope);
    }
    point
        .iter()
        .map(|(actor, value)| {
            Ok((
                actor.clone(),
                project(Rational::parse(value, b)?, &hull[actor], b)?.exact_string(b)?,
            ))
        })
        .collect()
}

fn round(value: &Rational, grid: &Rational, b: &mut Budget) -> Result<Rational, Error> {
    let units = value.div(grid, b)?;
    let lower = nrz_cas::enclosure::Interval::singleton(&units, b)?
        .coarsen(0, b)?
        .lower()
        .clone();
    let distance = units.sub(&lower, b)?;
    let chosen = if distance.compare(&Rational::parse("1/2", b)?, b)?.is_gt() {
        lower.add(&Rational::parse("1", b)?, b)?
    } else {
        lower
    };
    Ok(chosen.mul(grid, b)?)
}

pub(super) fn proposal(
    image: &BTreeMap<String, Bounds>,
    hull: &BTreeMap<String, Bounds>,
    grid: &Rational,
    b: &mut Budget,
) -> Result<BTreeMap<String, String>, Error> {
    if image.keys().ne(hull.keys()) {
        return Err(Error::Scope);
    }
    let two = Rational::parse("2", b)?;
    image
        .iter()
        .map(|(actor, value)| {
            let midpoint = Rational::parse(&value.lower, b)?
                .add(&Rational::parse(&value.upper, b)?, b)?
                .div(&two, b)?;
            Ok((
                actor.clone(),
                round(&project(midpoint, &hull[actor], b)?, grid, b)?.exact_string(b)?,
            ))
        })
        .collect()
}

pub(super) fn grid(value: &str, ceiling: u32, b: &mut Budget) -> Result<Rational, Error> {
    let value = Rational::parse(value, b)?;
    let mut current = Rational::parse("1", b)?;
    let two = Rational::parse("2", b)?;
    for _ in 0..=ceiling {
        if current == value {
            return Ok(value);
        }
        current = current.div(&two, b)?;
    }
    Err(Error::Scope)
}

fn absolute(value: Rational, b: &mut Budget) -> Result<Rational, Error> {
    Ok(if value.is_negative() { value.negated(b)? } else { value })
}

fn intersection(a: &Bounds, lo: Rational, hi: Rational, b: &mut Budget) -> Result<Bounds, Error> {
    let left = Rational::parse(&a.lower, b)?;
    let right = Rational::parse(&a.upper, b)?;
    let lo = if lo.compare(&left, b)?.is_gt() { lo } else { left };
    let hi = if hi.compare(&right, b)?.is_lt() { hi } else { right };
    if lo.compare(&hi, b)?.is_gt() {
        return Err(Error::Residual);
    }
    Ok(Bounds {
        lower: lo.exact_string(b)?,
        upper: hi.exact_string(b)?,
    })
}

pub(super) fn assemble(
    record: MapRecord,
    hull: &BTreeMap<String, Bounds>,
    c: &Rational,
    b: &mut Budget,
) -> Result<ResidualRound, Error> {
    super::point_in_hull(&record.point, hull, b)?;
    if record.image.keys().ne(record.point.keys()) {
        return Err(Error::Map);
    }
    let one = Rational::parse("1", b)?;
    if c.is_negative() || !c.compare(&one, b)?.is_lt() {
        return Err(Error::Residual);
    }
    let mut r = Rational::parse("0", b)?;
    for (actor, value) in &record.image {
        let z = Rational::parse(&record.point[actor], b)?;
        for endpoint in [&value.lower, &value.upper] {
            let distance = absolute(Rational::parse(endpoint, b)?.sub(&z, b)?, b)?;
            if distance.compare(&r, b)?.is_gt() {
                r = distance;
            }
        }
    }
    let radius = r.div(&one.sub(c, b)?, b)?;
    let contracted = c.mul(&radius, b)?;
    let mut standing = BTreeMap::new();
    for (actor, value) in &record.image {
        let z = Rational::parse(&record.point[actor], b)?;
        let first = intersection(&hull[actor], z.sub(&radius, b)?, z.add(&radius, b)?, b)?;
        let final_range = intersection(
            &first,
            Rational::parse(&value.lower, b)?.sub(&contracted, b)?,
            Rational::parse(&value.upper, b)?.add(&contracted, b)?,
            b,
        )?;
        standing.insert(actor.clone(), final_range);
    }
    Ok(ResidualRound {
        proposals: Vec::new(),
        certified: record,
        residual: r.exact_string(b)?,
        contraction: c.exact_string(b)?,
        radius: radius.exact_string(b)?,
        standing,
        candidate_work: 0,
        work: 0,
    })
}
