//! Reusable exact finite transport; no nonlinear evaluator or ledger mutation.
//! (´def:numerics:exact-transport´)
use pn_records::transport::{ExactArithmetic, KernelError, Matrix, TransportInput, TransportOutput};

fn normalize<A: ExactArithmetic>(matrix: &Matrix<A::Number>, a: &mut A) -> Result<Matrix<A::Number>, KernelError> {
    let zero = a.zero();
    let mut output = Vec::new();
    for (index, row) in matrix.iter().enumerate() {
        let mut sum = zero.clone();
        for (target, value) in row {
            if *target >= matrix.len() || a.compare(value, &zero)?.is_lt() {
                return Err(KernelError::Input);
            }
            sum = a.add(&sum, value)?;
        }
        if !a.compare(row.get(&index).ok_or(KernelError::Input)?, &zero)?.is_gt() {
            return Err(KernelError::Input);
        }
        let mut normalized = std::collections::BTreeMap::new();
        for (target, value) in row {
            normalized.insert(*target, a.div(value, &sum)?);
        }
        output.push(normalized);
    }
    Ok(output)
}

fn add_entry<A: ExactArithmetic>(
    row: &mut std::collections::BTreeMap<usize, A::Number>,
    target: usize,
    value: &A::Number,
    a: &mut A,
) -> Result<(), KernelError> {
    let prior = row.get(&target).cloned().unwrap_or_else(|| a.zero());
    row.insert(target, a.add(&prior, value)?);
    Ok(())
}

fn validate<A: ExactArithmetic>(input: &TransportInput<A::Number>, a: &mut A, maximum_cells: usize) -> Result<(), KernelError> {
    let n = input.counts.len();
    let cells = n
        .checked_mul(n)
        .and_then(|v| v.checked_mul(input.hops.len().saturating_add(3)))
        .ok_or(KernelError::Limit)?;
    if cells > maximum_cells {
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
    let zero = a.zero();
    let one = a.one();
    let mut mass = zero.clone();
    for weight in &input.depth_mass {
        if a.compare(weight, &zero)?.is_lt() {
            return Err(KernelError::Input);
        }
        mass = a.add(&mass, weight)?;
    }
    if a.compare(&mass, &one)?.is_ne() {
        return Err(KernelError::Input);
    }
    for ((count, rate), emission) in input.counts.iter().zip(&input.rates).zip(&input.emission) {
        if !a.compare(count, &zero)?.is_gt()
            || a.compare(rate, &zero)?.is_lt()
            || a.compare(emission, &zero)?.is_lt()
            || a.compare(emission, &one)?.is_gt()
        {
            return Err(KernelError::Input);
        }
    }
    Ok(())
}

/// Normalize each hop, multiply source-adjacent products, then apply emission once.
/// (´[ROOT-alg:design:transport]´)
/// # Errors
/// Refuses malformed indices, weights, counts, fractions or exhausted cell/arithmetic limits.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "transport::exact_transport"
    ),
    ret
)]
pub fn exact_transport<A: ExactArithmetic>(
    input: &TransportInput<A::Number>,
    a: &mut A,
    maximum_cells: usize,
) -> Result<TransportOutput<A::Number>, KernelError> {
    validate(input, a, maximum_cells)?;
    let n = input.counts.len();
    let zero = a.zero();
    let one = a.one();
    let mut normalized = Vec::new();
    for hop in &input.hops {
        normalized.push(normalize(hop, a)?);
    }
    let mut product: Matrix<_> = (0..n).map(|i| std::collections::BTreeMap::from([(i, one.clone())])).collect();
    let mut raw: Matrix<_> = vec![std::collections::BTreeMap::new(); n];
    for (hop, weight) in normalized.iter().zip(&input.depth_mass) {
        let mut next: Matrix<_> = vec![std::collections::BTreeMap::new(); n];
        for (source, row) in product.iter().enumerate() {
            for (relay, left) in row {
                for (target, right) in &hop[*relay] {
                    let value = a.mul(left, right)?;
                    add_entry(&mut next[source], *target, &value, a)?;
                }
            }
        }
        product = next;
        for (source, row) in product.iter().enumerate() {
            for (target, value) in row {
                let value = a.mul(weight, value)?;
                add_entry(&mut raw[source], *target, &value, a)?;
            }
        }
    }
    let mut emitted = raw.clone();
    for (source, row) in emitted.iter_mut().enumerate() {
        for value in row.values_mut() {
            *value = a.mul(&input.emission[source], value)?;
        }
        let retained = a.sub(&one, &input.emission[source])?;
        add_entry(row, source, &retained, a)?;
    }
    let mut numerator = vec![zero.clone(); n];
    let mut denominator = vec![zero.clone(); n];
    let mut ranges: Vec<Option<(A::Number, A::Number)>> = vec![None; n];
    for (source, row) in emitted.iter().enumerate() {
        for (target, weight) in row {
            if a.compare(weight, &zero)?.is_eq() {
                continue;
            }
            let count = a.mul(weight, &input.counts[source])?;
            let amount = a.mul(&count, &input.rates[source])?;
            denominator[*target] = a.add(&denominator[*target], &count)?;
            numerator[*target] = a.add(&numerator[*target], &amount)?;
            match &mut ranges[*target] {
                None => ranges[*target] = Some((input.rates[source].clone(), input.rates[source].clone())),
                Some((low, high)) => {
                    if a.compare(&input.rates[source], low)?.is_lt() {
                        *low = input.rates[source].clone();
                    }
                    if a.compare(&input.rates[source], high)?.is_gt() {
                        *high = input.rates[source].clone();
                    }
                }
            }
        }
    }
    let mut standing = Vec::new();
    let mut hull = Vec::new();
    for ((numerator, denominator), range) in numerator.iter().zip(&denominator).zip(ranges) {
        if !a.compare(denominator, &zero)?.is_gt() {
            return Err(KernelError::Input);
        }
        let value = a.div(numerator, denominator)?;
        let (low, high) = range.ok_or(KernelError::Input)?;
        if a.compare(&value, &low)?.is_lt() || a.compare(&value, &high)?.is_gt() {
            return Err(KernelError::Input);
        }
        standing.push(value);
        hull.push((low, high));
    }
    Ok(TransportOutput {
        normalized,
        raw,
        emitted,
        numerator,
        denominator,
        standing,
        hull,
    })
}
