//! Positive rational-endpoint transport, with scalar premises supplied by the owning epoch.
//! (´[ROOT-alg:design:transport]´)

use nrz_cas::{Rational, enclosure::Interval, limits::Budget};
use pn_records::transport::{KernelError, Matrix, TransportInput, TransportOutput};
use std::collections::BTreeMap;

fn fault(e: nrz_cas::Fault) -> KernelError {
    KernelError::Arithmetic(e.to_string())
}
fn singleton(s: &str, b: &mut Budget) -> Result<Interval, KernelError> {
    let n = Rational::parse(s, b).map_err(fault)?;
    Interval::singleton(&n, b).map_err(fault)
}
fn add(a: &Interval, c: &Interval, b: &mut Budget) -> Result<Interval, KernelError> {
    let lo = a.lower().add(c.lower(), b).map_err(fault)?;
    let hi = a.upper().add(c.upper(), b).map_err(fault)?;
    Interval::new(lo, hi, b).map_err(fault)
}
fn mul(a: &Interval, c: &Interval, b: &mut Budget) -> Result<Interval, KernelError> {
    if a.lower().is_negative() || c.lower().is_negative() {
        return Err(KernelError::Input);
    }
    let lo = a.lower().mul(c.lower(), b).map_err(fault)?;
    let hi = a.upper().mul(c.upper(), b).map_err(fault)?;
    Interval::new(lo, hi, b).map_err(fault)
}
fn div(a: &Interval, c: &Interval, b: &mut Budget) -> Result<Interval, KernelError> {
    if a.lower().is_negative() || c.lower().is_negative() || c.lower().is_zero() {
        return Err(KernelError::Input);
    }
    let lo = a.lower().div(c.upper(), b).map_err(fault)?;
    let hi = a.upper().div(c.lower(), b).map_err(fault)?;
    Interval::new(lo, hi, b).map_err(fault)
}
fn accumulate(row: &mut BTreeMap<usize, Interval>, key: usize, value: Interval, b: &mut Budget) -> Result<(), KernelError> {
    let next = if let Some(old) = row.get(&key) {
        add(old, &value, b)?
    } else {
        value
    };
    row.insert(key, next);
    Ok(())
}
fn normalize(m: &Matrix<Interval>, b: &mut Budget) -> Result<Matrix<Interval>, KernelError> {
    let mut out = Vec::new();
    for (i, row) in m.iter().enumerate() {
        let mut sum = singleton("0", b)?;
        for (j, value) in row {
            if *j >= m.len() || value.lower().is_negative() {
                return Err(KernelError::Input);
            }
            sum = add(&sum, value, b)?;
        }
        let diagonal = row.get(&i).ok_or(KernelError::Input)?;
        if diagonal.lower().is_zero() || diagonal.lower().is_negative() {
            return Err(KernelError::Input);
        }
        out.push(
            row.iter()
                .map(|(j, v)| Ok((*j, div(v, &sum, b)?)))
                .collect::<Result<_, KernelError>>()?,
        );
    }
    Ok(out)
}
fn validate(input: &TransportInput<Interval>, maximum_cells: usize, b: &mut Budget) -> Result<(), KernelError> {
    let n = input.counts.len();
    if n.checked_mul(n)
        .and_then(|v| v.checked_mul(input.hops.len().saturating_add(3)))
        .is_none_or(|v| v > maximum_cells)
    {
        return Err(KernelError::Limit);
    }
    if input.hops.is_empty()
        || input.hops.len() != input.depth_mass.len()
        || input.emission.len() != n
        || input.rates.len() != n
        || input.hops.iter().any(|h| h.len() != n)
    {
        return Err(KernelError::Input);
    }
    let one = Rational::parse("1", b).map_err(fault)?;
    let mut mass = Rational::parse("0", b).map_err(fault)?;
    for value in input
        .depth_mass
        .iter()
        .chain(&input.counts)
        .chain(&input.rates)
        .chain(&input.emission)
    {
        if value.lower() != value.upper() || value.lower().is_negative() {
            return Err(KernelError::Input);
        }
    }
    for value in &input.depth_mass {
        mass = mass.add(value.lower(), b).map_err(fault)?;
    }
    if mass != one || input.counts.iter().any(|v| v.lower().is_zero()) {
        return Err(KernelError::Input);
    }
    for value in &input.emission {
        if value.upper().compare(&one, b).map_err(fault)?.is_gt() {
            return Err(KernelError::Input);
        }
    }
    Ok(())
}
fn products(input: &TransportInput<Interval>, b: &mut Budget) -> Result<(Vec<Matrix<Interval>>, Matrix<Interval>), KernelError> {
    let normalized = input.hops.iter().map(|h| normalize(h, b)).collect::<Result<Vec<_>, _>>()?;
    let n = input.counts.len();
    let one = singleton("1", b)?;
    let mut product: Matrix<_> = (0..n).map(|i| BTreeMap::from([(i, one.clone())])).collect();
    let mut raw = vec![BTreeMap::new(); n];
    for (hop, mass) in normalized.iter().zip(&input.depth_mass) {
        let mut next = vec![BTreeMap::new(); n];
        for (source, row) in product.iter().enumerate() {
            for (relay, left) in row {
                for (target, right) in &hop[*relay] {
                    accumulate(&mut next[source], *target, mul(left, right, b)?, b)?;
                }
            }
        }
        product = next;
        for (source, row) in product.iter().enumerate() {
            for (target, value) in row {
                accumulate(&mut raw[source], *target, mul(mass, value, b)?, b)?;
            }
        }
    }
    Ok((normalized, raw))
}
fn emission(raw: &Matrix<Interval>, fractions: &[Interval], b: &mut Budget) -> Result<Matrix<Interval>, KernelError> {
    let mut output = raw.clone();
    let one = Rational::parse("1", b).map_err(fault)?;
    for (source, row) in output.iter_mut().enumerate() {
        for value in row.values_mut() {
            *value = mul(&fractions[source], value, b)?;
        }
        let retained = one.sub(fractions[source].lower(), b).map_err(fault)?;
        accumulate(row, source, Interval::singleton(&retained, b).map_err(fault)?, b)?;
    }
    Ok(output)
}
fn pairs(
    input: &TransportInput<Interval>,
    emitted: &Matrix<Interval>,
    b: &mut Budget,
) -> Result<TransportOutput<Interval>, KernelError> {
    let n = input.counts.len();
    let zero = singleton("0", b)?;
    let mut numerator = vec![zero.clone(); n];
    let mut denominator = vec![zero; n];
    let mut ranges: Vec<Option<(Interval, Interval)>> = vec![None; n];
    for (source, row) in emitted.iter().enumerate() {
        for (target, weight) in row {
            if weight.upper().is_zero() {
                continue;
            }
            let count = mul(weight, &input.counts[source], b)?;
            numerator[*target] = add(&numerator[*target], &mul(&count, &input.rates[source], b)?, b)?;
            denominator[*target] = add(&denominator[*target], &count, b)?;
            match &mut ranges[*target] {
                None => ranges[*target] = Some((input.rates[source].clone(), input.rates[source].clone())),
                Some((lo, hi)) => {
                    if input.rates[source].lower().compare(lo.lower(), b).map_err(fault)?.is_lt() {
                        *lo = input.rates[source].clone();
                    }
                    if input.rates[source].upper().compare(hi.upper(), b).map_err(fault)?.is_gt() {
                        *hi = input.rates[source].clone();
                    }
                }
            }
        }
    }
    let mut standing = Vec::new();
    let mut hull = Vec::new();
    for ((num, den), range) in numerator.iter().zip(&denominator).zip(ranges) {
        let (lo, hi) = range.ok_or(KernelError::Input)?;
        let bounds = Interval::new(lo.lower().clone(), hi.upper().clone(), b).map_err(fault)?;
        standing.push(div(num, den, b)?.intersection(&bounds, b).map_err(fault)?);
        hull.push((lo, hi));
    }
    Ok(TransportOutput {
        normalized: Vec::new(),
        raw: Vec::new(),
        emitted: emitted.clone(),
        numerator,
        denominator,
        standing,
        hull,
    })
}

/// Compose positive endpoint transport using exact rational endpoint operations.
/// Conservation follows from normalization and emission identities, not interval row sums.
/// (´[ROOT-alg:design:transport]´)
/// # Errors
/// Refuses malformed domains, dimensions, denominator separation or exhausted arithmetic.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "transport::enclosed::evaluate"
    ),
    ret
)]
pub fn evaluate(
    input: &TransportInput<Interval>,
    budget: &mut Budget,
    maximum_cells: usize,
) -> Result<TransportOutput<Interval>, KernelError> {
    validate(input, maximum_cells, budget)?;
    let (normalized, raw) = products(input, budget)?;
    let emitted = emission(&raw, &input.emission, budget)?;
    let mut result = pairs(input, &emitted, budget)?;
    result.normalized = normalized;
    result.raw = raw;
    Ok(result)
}
