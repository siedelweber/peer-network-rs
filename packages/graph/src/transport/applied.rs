//! Revision-two sparse vector transport with outward dyadic arithmetic.
//! (´[ROOT-alg:design:transport]´)
use nrz_cas::{Rational, enclosure::Interval, limits::Budget};
use pn_records::transport::Matrix;

/// Scope and unresolved denominators remain distinct from resource exhaustion.
/// (´[ROOT-alg:design:transport]´)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid sparse transport premises or capacity")]
    Scope,
    #[error("positive denominator not certified at the declared precision")]
    Indecisive,
    #[error("bounded arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

/// Two transported aggregates, never a source-target product matrix.
/// Counters count visited support entries and allocated scalar slots.
/// (´[ROOT-alg:design:transport]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub numerator: Vec<Interval>,
    pub denominator: Vec<Interval>,
    pub standing: Vec<Interval>,
    pub support_visits: usize,
    pub vector_slots: usize,
    pub row_slots: usize,
}

fn zero(b: &mut Budget) -> Result<Interval, Error> {
    Ok(Interval::singleton(&Rational::parse("0", b)?, b)?)
}
fn div(a: &Interval, d: &Interval, bits: u32, b: &mut Budget) -> Result<Interval, Error> {
    if d.lower().is_zero() || d.lower().is_negative() {
        return Err(Error::Indecisive);
    }
    Ok(a.mul(&d.reciprocal(bits, b)?, bits, b)?)
}

/// Apply each normalized sparse hop to two vectors, accumulating positive depths.
/// The callback supplies one recipient tilt vector at a time. It cannot supply
/// a composed matrix. Original exact counts, rates, emission and depth masses
/// are checked before rounding; every subsequent operation rounds outward.
/// (´[ROOT-alg:design:transport]´)
/// # Errors
/// Refuses invalid premises, capacity, unresolved divisors and exhausted resources.
#[tracing::instrument(
    name = "alg:design:transport",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:transport",
        source_item = "transport::applied::evaluate"
    ),
    ret
)]
pub fn evaluate(
    input: &Input<'_>,
    bits: u32,
    maximum_cells: usize,
    b: &mut Budget,
    tilt: &mut impl HopFactors,
) -> Result<Output, Error> {
    validate(input, maximum_cells, b)?;
    let Input {
        rows,
        depth_mass,
        emission,
        counts,
        rates,
    } = *input;
    let n = rows.len();
    let one = Rational::parse("1", b)?;
    let nil = zero(b)?;
    let mut amount = Vec::with_capacity(n);
    let mut count = Vec::with_capacity(n);
    let mut numerator = Vec::with_capacity(n);
    let mut denominator = Vec::with_capacity(n);
    for ((source_count, source_rate), fraction) in counts.iter().zip(rates).zip(emission) {
        let source_count = source_count.coarsen(bits, b)?;
        let source_rate = source_rate.coarsen(bits, b)?;
        let retained = Interval::singleton(&one.sub(fraction.lower(), b)?, b)?.coarsen(bits, b)?;
        let fraction = fraction.coarsen(bits, b)?;
        let moving = source_count.mul(&fraction, bits, b)?;
        amount.push(moving.mul(&source_rate, bits, b)?);
        count.push(moving);
        let held = source_count.mul(&retained, bits, b)?;
        numerator.push(held.mul(&source_rate, bits, b)?);
        denominator.push(held);
    }
    let mut visits = 0usize;
    let mut row_slots = 0usize;
    for (depth, mass) in depth_mass.iter().enumerate() {
        let factors = tilt.at(depth, b)?;
        if factors.len() != n || factors.iter().any(|v| v.lower().is_negative() || v.lower().is_zero()) {
            return Err(Error::Indecisive);
        }
        let mut next_amount = vec![nil.clone(); n];
        let mut next_count = vec![nil.clone(); n];
        for (source, row) in rows.iter().enumerate() {
            let mut weighted = Vec::with_capacity(row.len());
            let mut sum = nil.clone();
            for (target, base) in row {
                let base = base.coarsen(bits, b)?;
                let value = if source == *target {
                    base
                } else {
                    base.mul(&factors[*target].coarsen(bits, b)?, bits, b)?
                };
                sum = sum.add(&value, bits, b)?;
                weighted.push((*target, value));
            }
            row_slots = row_slots.max(weighted.len());
            for (target, value) in weighted {
                let probability = div(&value, &sum, bits, b)?;
                next_amount[target] = next_amount[target].add(&amount[source].mul(&probability, bits, b)?, bits, b)?;
                next_count[target] = next_count[target].add(&count[source].mul(&probability, bits, b)?, bits, b)?;
                visits = visits.checked_add(1).ok_or(Error::Scope)?;
            }
        }
        amount = next_amount;
        count = next_count;
        if !mass.lower().is_zero() {
            let mass = mass.coarsen(bits, b)?;
            for ((total, next), (den, next_den)) in numerator.iter_mut().zip(&amount).zip(denominator.iter_mut().zip(&count)) {
                *total = total.add(&next.mul(&mass, bits, b)?, bits, b)?;
                *den = den.add(&next_den.mul(&mass, bits, b)?, bits, b)?;
            }
        }
    }
    let standing = numerator
        .iter()
        .zip(&denominator)
        .map(|(a, d)| div(a, d, bits, b))
        .collect::<Result<_, _>>()?;
    Ok(Output {
        numerator,
        denominator,
        standing,
        support_visits: visits,
        vector_slots: n.checked_mul(10).ok_or(Error::Scope)?,
        row_slots,
    })
}

/// Borrowed immutable source vectors and sparse base, not hop products.
/// (´[ROOT-alg:design:transport]´)
#[derive(Clone, Copy, Debug)]
pub struct Input<'a> {
    pub rows: &'a Matrix<Interval>,
    pub depth_mass: &'a [Interval],
    pub emission: &'a [Interval],
    pub counts: &'a [Interval],
    pub rates: &'a [Interval],
}
fn validate(input: &Input<'_>, maximum_cells: usize, b: &mut Budget) -> Result<(), Error> {
    let Input {
        rows,
        depth_mass,
        emission,
        counts,
        rates,
    } = *input;
    let n = rows.len();
    let z = rows.iter().map(std::collections::BTreeMap::len).sum::<usize>();
    let slots = n.checked_mul(10).and_then(|v| v.checked_add(z)).ok_or(Error::Scope)?;
    if slots > maximum_cells || depth_mass.is_empty() || emission.len() != n || counts.len() != n || rates.len() != n {
        return Err(Error::Scope);
    }
    let one = Rational::parse("1", b)?;
    let mut mass = Rational::parse("0", b)?;
    for value in depth_mass.iter().chain(emission).chain(counts).chain(rates) {
        if value.lower() != value.upper() || value.lower().is_negative() {
            return Err(Error::Scope);
        }
    }
    for value in depth_mass {
        mass = mass.add(value.lower(), b)?;
    }
    if mass != one {
        return Err(Error::Scope);
    }
    for (source, row) in rows.iter().enumerate() {
        if row.keys().any(|target| *target >= n)
            || row.values().any(|v| v.lower().is_negative())
            || row
                .get(&source)
                .is_none_or(|v| v.lower().is_zero() || v.lower().is_negative())
            || counts[source].lower().is_zero()
            || emission[source].upper().compare(&one, b)?.is_gt()
        {
            return Err(Error::Scope);
        }
    }
    Ok(())
}

/// A fully observable provider supplies one checked recipient-factor vector.
/// (´[ROOT-alg:design:transport]´)
pub trait HopFactors: std::fmt::Debug {
    /// Compute one hop under the supplied remaining budget.
    /// (´[ROOT-alg:design:transport]´)
    /// # Errors
    /// Refuses changed premises, unresolved enclosures or exhausted arithmetic.
    fn at(&mut self, depth: usize, budget: &mut Budget) -> Result<Vec<Interval>, Error>;
}
