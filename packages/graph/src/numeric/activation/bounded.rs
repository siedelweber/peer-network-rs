//! Bounded dyadic elementary operations, with explicit finite-plan refusals.
//! (´def:numerics:activation´)
use nrz_cas::{Rational, enclosure::Interval, limits::Budget};

/// A refused numerical plan supplies no approximate scalar authority.
/// (´def:numerics:activation´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    OutsideDomain,
    BelowNormalOperand,
    NonDyadicExponent,
    TargetNotCertifiable,
}

/// Resource exhaustion remains distinct from a fallback-eligible plan refusal.
/// (´def:numerics:activation´)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bounded activation plan: {0:?}")]
    Refused(Refusal),
    #[error("bounded activation arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

fn integer(n: i64, b: &mut Budget) -> Result<Rational, Error> {
    Ok(Rational::from_ratio(n, 1, b)?)
}
fn unit(bits: u32, b: &mut Budget) -> Result<Rational, Error> {
    Ok(integer(2, b)?.pow(-i64::from(bits), b)?)
}
fn scalar(n: i64, b: &mut Budget) -> Result<Interval, Error> {
    Ok(Interval::singleton(&integer(n, b)?, b)?)
}
fn refused(reason: Refusal) -> Error {
    Error::Refused(reason)
}

fn domain(value: &Interval, lower: i64, upper: i64, b: &mut Budget) -> Result<(), Error> {
    if value.lower().compare(&integer(lower, b)?, b)?.is_lt() || value.upper().compare(&integer(upper, b)?, b)?.is_gt() {
        return Err(refused(Refusal::OutsideDomain));
    }
    normal(value, b)
}
fn normal(value: &Interval, b: &mut Budget) -> Result<(), Error> {
    for endpoint in [value.lower(), value.upper()] {
        let magnitude = if endpoint.is_negative() {
            endpoint.negated(b)?
        } else {
            endpoint.clone()
        };
        b.work(1, nrz_cas::Location::new("normal operand bit classification"))?;
        let (numerator, denominator) = magnitude.component_bits();
        if !magnitude.is_zero() && denominator.saturating_sub(numerator) > 1021 {
            let chunk = unit(128, b)?;
            let mut normal = unit(126, b)?;
            for _ in 0..7 {
                normal = normal.mul(&chunk, b)?;
            }
            if magnitude.compare(&normal, b)?.is_lt() {
                return Err(refused(Refusal::BelowNormalOperand));
            }
        }
    }
    Ok(())
}

fn attained(value: &Interval, precision: u32, relative: bool, b: &mut Budget) -> Result<bool, Error> {
    let mut target = unit(precision, b)?;
    if relative {
        let magnitude = if value.upper().is_negative() {
            value.upper().negated(b)?
        } else if !value.lower().is_negative() {
            value.lower().clone()
        } else {
            return Ok(false);
        };
        target = target.mul(&magnitude, b)?;
    }
    Ok(!value.width(b)?.compare(&target, b)?.is_gt())
}

// For x in [-2,0], terms decrease from the first nonconstant term onward.
// Consecutive alternating partial sums bound exp(x), or exp(x)-1 when the
// constant is omitted. Interval partial sums include every rounding error.
fn exponential_endpoint(
    value: &Rational,
    precision: u32,
    grid: u32,
    terms: u32,
    minus_one: bool,
    b: &mut Budget,
) -> Result<Interval, Error> {
    if value.is_zero() {
        return scalar(i64::from(!minus_one), b);
    }
    let x = Interval::singleton(value, b)?.coarsen(grid, b)?;
    let mut term = scalar(1, b)?;
    let mut sum = scalar(i64::from(!minus_one), b)?;
    let mut previous = sum.clone();
    for index in 1..=terms {
        let reciprocal = scalar(i64::from(index), b)?.reciprocal(grid, b)?;
        term = term.mul(&x, grid, b)?.mul(&reciprocal, grid, b)?;
        sum = sum.add(&term, grid, b)?;
        if index >= 2 {
            let (lower, upper) = if index % 2 == 0 {
                (&previous, &sum)
            } else {
                (&sum, &previous)
            };
            let enclosure = Interval::new(lower.lower().clone(), upper.upper().clone(), b)?;
            if attained(&enclosure, precision, minus_one, b)? {
                return Ok(enclosure);
            }
        }
        previous = sum.clone();
    }
    Err(refused(Refusal::TargetNotCertifiable))
}

/// Evaluate exp or expm1, certifying error separately at each endpoint.
/// No range reduction or nonzero expm1 switch is used by this finite plan.
/// (´def:numerics:activation´)
/// # Errors
/// Refuses domain, subnormal operands, unattained targets and exhausted resources.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::bounded::exponential"
    ),
    ret
)]
pub fn exponential(
    value: &Interval,
    precision: u32,
    grid: u32,
    terms: u32,
    minus_one: bool,
    b: &mut Budget,
) -> Result<Interval, Error> {
    domain(value, -2, 0, b)?;
    let lower = exponential_endpoint(value.lower(), precision, grid, terms, minus_one, b)?;
    let upper = exponential_endpoint(value.upper(), precision, grid, terms, minus_one, b)?;
    Ok(Interval::new(lower.lower().clone(), upper.upper().clone(), b)?)
}

/// Positive square root by a bounded dyadic bisection and exact squared checks.
/// (´def:numerics:activation´)
/// # Errors
/// Refuses domain, subnormal operands, unattained targets and exhausted resources.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::bounded::square_root"
    ),
    ret
)]
pub fn square_root(value: &Interval, grid: u32, b: &mut Budget) -> Result<Interval, Error> {
    domain(value, 0, 2, b)?;
    let lower = root_endpoint(value.lower(), grid, b)?;
    let upper = root_endpoint(value.upper(), grid, b)?;
    Ok(Interval::new(lower.lower().clone(), upper.upper().clone(), b)?)
}
fn root_endpoint(value: &Rational, grid: u32, b: &mut Budget) -> Result<Interval, Error> {
    if value.is_zero() {
        return scalar(0, b);
    }
    let mut lower = integer(0, b)?;
    let mut upper = integer(2, b)?;
    let half = Rational::from_ratio(1, 2, b)?;
    for _ in 0..=grid {
        let middle = lower.add(&upper, b)?.mul(&half, b)?;
        match middle.mul(&middle, b)?.compare(value, b)? {
            std::cmp::Ordering::Equal => return Ok(Interval::singleton(&middle, b)?),
            std::cmp::Ordering::Less => lower = middle,
            std::cmp::Ordering::Greater => upper = middle,
        }
    }
    Ok(Interval::new(lower, upper, b)?)
}

/// Monotone endpoint sigmoid with an independently checked absolute target.
/// (´def:numerics:activation´)
/// # Errors
/// Refuses domain, subnormal operands, unattained targets and exhausted resources.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::bounded::sigmoid"
    ),
    ret
)]
pub fn sigmoid(value: &Interval, precision: u32, grid: u32, terms: u32, b: &mut Budget) -> Result<Interval, Error> {
    domain(value, 0, 2, b)?;
    let mut endpoints = Vec::new();
    for point in [value.lower(), value.upper()] {
        let negative = point.negated(b)?;
        let inner = precision
            .checked_add(2)
            .ok_or_else(|| refused(Refusal::TargetNotCertifiable))?;
        let e = exponential_endpoint(&negative, inner, grid, terms, false, b)?;
        let result = scalar(1, b)?.add(&e, grid, b)?.reciprocal(grid, b)?;
        if !attained(&result, precision, false, b)? {
            return Err(refused(Refusal::TargetNotCertifiable));
        }
        endpoints.push(result);
    }
    Ok(Interval::new(endpoints[0].lower().clone(), endpoints[1].upper().clone(), b)?)
}

/// Cancellation-free tanh from expm1, with relative endpoint targets and exact zero.
/// (´def:numerics:activation´)
/// # Errors
/// Refuses domain, subnormal operands, unattained targets and exhausted resources.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::bounded::tanh"
    ),
    ret
)]
pub fn tanh(value: &Interval, precision: u32, grid: u32, terms: u32, b: &mut Budget) -> Result<Interval, Error> {
    domain(value, 0, 1, b)?;
    let mut endpoints = Vec::new();
    for point in [value.lower(), value.upper()] {
        if point.is_zero() {
            endpoints.push(scalar(0, b)?);
            continue;
        }
        let negative = point.mul(&integer(-2, b)?, b)?;
        let inner = precision
            .checked_add(2)
            .ok_or_else(|| refused(Refusal::TargetNotCertifiable))?;
        let e = exponential_endpoint(&negative, inner, grid, terms, true, b)?;
        let minus = scalar(0, b)?.sub(&e, grid, b)?;
        let result = minus.mul(&scalar(2, b)?.add(&e, grid, b)?.reciprocal(grid, b)?, grid, b)?;
        if !attained(&result, precision, true, b)? {
            return Err(refused(Refusal::TargetNotCertifiable));
        }
        endpoints.push(result);
    }
    Ok(Interval::new(endpoints[0].lower().clone(), endpoints[1].upper().clone(), b)?)
}

/// Exact dyadic exponents use repeated roots, integer powering and signed inversion.
/// (´def:numerics:activation´)
/// # Errors
/// Refuses a nonpositive base, unsupported exponent, operand domain or resources.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::bounded::power"
    ),
    ret
)]
pub fn power(value: &Interval, exponent: &Rational, grid: u32, b: &mut Budget) -> Result<Interval, Error> {
    domain(value, 0, 2, b)?;
    if value.lower().is_zero() {
        return Err(refused(Refusal::OutsideDomain));
    }
    let negative = exponent.is_negative();
    let magnitude = if negative { exponent.negated(b)? } else { exponent.clone() };
    let (numerator, denominator) = magnitude
        .small_ratio(b)?
        .ok_or_else(|| refused(Refusal::TargetNotCertifiable))?;
    if !denominator.is_power_of_two() {
        return Err(refused(Refusal::NonDyadicExponent));
    }
    let mut base = value.clone();
    for _ in 0..denominator.trailing_zeros() {
        base = square_root(&base, grid, b)?;
    }
    let mut result = scalar(1, b)?;
    let mut count = numerator;
    while count > 0 {
        if count % 2 == 1 {
            result = result.mul(&base, grid, b)?;
        }
        count /= 2;
        if count != 0 {
            base = base.mul(&base, grid, b)?;
        }
    }
    if negative {
        if result.lower().is_zero() {
            return Err(refused(Refusal::TargetNotCertifiable));
        }
        Ok(result.reciprocal(grid, b)?)
    } else {
        Ok(result)
    }
}

/// Compose the original activation at one explicitly supplied working target.
/// Constants are independently admitted once by the enclosing solve context.
/// (´def:numerics:activation´)
/// # Errors
/// Refuses unsupported quantities, domains, unattained final width and resources.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::bounded::activation"
    ),
    ret
)]
pub fn activation(
    input: &super::Request,
    constants: &[Interval; 2],
    policy: &nrz_cas::enclosure::RefinementPolicy,
    operation_precision: u32,
    b: &mut Budget,
) -> Result<Interval, Error> {
    if !matches!(input.quantity, super::Quantity::Responsive | super::Quantity::Clamped) {
        return Err(refused(Refusal::OutsideDomain));
    }
    let grid = policy.grid_ceiling;
    if operation_precision > grid {
        return Err(refused(Refusal::TargetNotCertifiable));
    }
    let mut standing = Interval::new(
        Rational::parse(&input.standing.lower, b)?,
        Rational::parse(&input.standing.upper, b)?,
        b,
    )?;
    if standing.lower().is_negative() {
        return Err(refused(Refusal::OutsideDomain));
    }
    normal(&standing, b)?;
    for value in constants {
        normal(value, b)?;
    }
    let wall = match (&input.wall, &input.wall_enclosure) {
        (Some(value), None) => Some(Interval::singleton(&Rational::parse(value, b)?, b)?),
        (None, Some(value)) => Some(Interval::new(
            Rational::parse(&value.lower, b)?,
            Rational::parse(&value.upper, b)?,
            b,
        )?),
        (None, None) => None,
        _ => return Err(refused(Refusal::OutsideDomain)),
    };
    if matches!(input.quantity, super::Quantity::Clamped) != wall.is_some() {
        return Err(refused(Refusal::OutsideDomain));
    }
    if let Some(wall) = wall {
        if wall.lower().is_zero() || wall.lower().is_negative() {
            return Err(refused(Refusal::OutsideDomain));
        }
        normal(&wall, b)?;
        standing = standing.maximum(&wall, grid, b)?;
    }
    let one = scalar(1, b)?;
    let reduced = standing.mul(&one.add(&standing, grid, b)?.reciprocal(grid, b)?, grid, b)?;
    domain(&reduced, 0, 1, b)?;
    let temperature = constants[0].mul(&reduced, grid, b)?;
    let sigmoid = sigmoid(&temperature, operation_precision, grid, policy.term_ceiling, b)?;
    let hyperbolic = tanh(&reduced, operation_precision, grid, policy.term_ceiling, b)?;
    let bleed = Rational::parse(&input.bleed_squared, b)?;
    if bleed.is_negative() || !bleed.compare(&integer(1, b)?, b)?.is_lt() {
        return Err(refused(Refusal::OutsideDomain));
    }
    let bleed = Interval::singleton(&bleed, b)?;
    normal(&bleed, b)?;
    let leak = bleed.mul(&hyperbolic, grid, b)?;
    let radicand = hyperbolic.mul(&one.sub(&leak, grid, b)?, grid, b)?;
    let unnormalized = sigmoid.mul(&square_root(&radicand, grid, b)?, grid, b)?;
    if constants[1].lower().is_zero() || constants[1].lower().is_negative() {
        return Err(refused(Refusal::OutsideDomain));
    }
    let normalized = unnormalized.mul(&constants[1].reciprocal(grid, b)?, grid, b)?;
    domain(&normalized, 0, 2, b)?;
    let first = square_root(&normalized, grid, b)?;
    let result = square_root(&first, grid, b)?;
    if !attained(&result, policy.precision, false, b)? {
        return Err(refused(Refusal::TargetNotCertifiable));
    }
    Ok(result)
}
