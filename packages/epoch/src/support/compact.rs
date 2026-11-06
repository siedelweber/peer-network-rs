//! Exact contributing extrema with two propagation buffers.
//! (´def:compiler:emission-support´)
use super::{
    BTreeMap, BaseAllocation, Budget, ChargedPrice, CompilerInputs, ContributingRange, FinalLedger, Limits, NumericContext,
    Rational, SourceEmission, SupportError, positive, source_pairs,
};

/// Compact support retains extrema and source fractions, not reachable pairs.
/// (´def:compiler:emission-support´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingSupport {
    pub boundary: u64,
    pub sources: BTreeMap<String, SourceEmission>,
    pub ranges: BTreeMap<String, ContributingRange>,
    pub depth: usize,
    pub support_visits: u64,
    pub extrema_slots: usize,
}
fn merge(slot: &mut Option<(Rational, Rational)>, value: &(Rational, Rational), b: &mut Budget) -> Result<(), SupportError> {
    if let Some((lo, hi)) = slot {
        if value.0.compare(lo, b)?.is_lt() {
            *lo = value.0.clone();
        }
        if value.1.compare(hi, b)?.is_gt() {
            *hi = value.1.clone();
        }
    } else {
        *slot = Some(value.clone());
    }
    Ok(())
}
/// Derive extrema from the same exact ledger/base premises as the legacy compiler.
/// Each depth scans only positive base support, independently of composed density.
/// (´[ROOT-alg:design:emission-support]´)
/// # Errors
/// Refuses changed boundary, charges, source premises and resource exhaustion.
#[tracing::instrument(
    name = "alg:design:emission-support",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "alg:design:emission-support",
        source_item = "support::compact::compile_support"
    ),
    ret
)]
pub fn compile_support(
    inputs: &CompilerInputs,
    price: &ChargedPrice,
    ledger: &FinalLedger,
    base: &BaseAllocation,
    numeric: &mut NumericContext,
    limits: Limits,
    maximum_products: u64,
) -> Result<StandingSupport, SupportError> {
    let boundary = inputs.parameters().boundary;
    if base.boundary != boundary
        || base.edition != inputs.parameters().edition
        || ledger.snapshots.last().map(|s| s.boundary) != Some(boundary)
        || price.numeraire() != &inputs.parameters().numeraire
        || numeric.replay_charged_price(
            price,
            &inputs.parameters().numeraire,
            inputs.constants().content().floor,
            &pn_graph::numeric::ridge::ChargeReplay,
        )? != *price
        || ledger.debits.values().any(|d| d.boundary() == boundary && d.price() != price)
    {
        return Err(SupportError::Boundary);
    }
    let mut b = Budget::new(limits)?;
    let actors: Vec<_> = base.rows.keys().cloned().collect();
    let indices: BTreeMap<_, _> = actors.iter().enumerate().map(|(i, a)| (a.clone(), i)).collect();
    let mut adjacency = Vec::new();
    for (source, row) in &base.rows {
        let mut targets = Vec::new();
        for (target, entry) in row {
            let index = *indices.get(target).ok_or(SupportError::Base)?;
            if positive(&entry.score, &mut b)? {
                targets.push(index);
            }
        }
        if !targets.contains(&indices[source]) {
            return Err(SupportError::Base);
        }
        adjacency.push(targets);
    }
    let (sources, rates) = source_pairs(inputs, price, ledger, base, &mut b)?;
    let mut current = actors
        .iter()
        .map(|a| {
            if sources[a].emission == "0" {
                None
            } else {
                Some((rates[a].clone(), rates[a].clone()))
            }
        })
        .collect::<Vec<_>>();
    let mut extrema = actors
        .iter()
        .map(|a| {
            if sources[a].retained == "0" {
                None
            } else {
                Some((rates[a].clone(), rates[a].clone()))
            }
        })
        .collect::<Vec<_>>();
    let mut visits = 0u64;
    let mut depth = 0;
    for (index, mass) in inputs.parameters().depth_mass.iter().enumerate() {
        let mut next = vec![None; actors.len()];
        for (source, targets) in adjacency.iter().enumerate() {
            for target in targets {
                visits = visits
                    .checked_add(1)
                    .filter(|v| *v <= maximum_products)
                    .ok_or(SupportError::Products)?;
                if let Some(value) = &current[source] {
                    merge(&mut next[*target], value, &mut b)?;
                }
            }
        }
        current = next;
        if !crate::constant(inputs.constants(), mass, &mut b)?.is_zero() {
            depth = index + 1;
            for (slot, value) in extrema.iter_mut().zip(&current) {
                if let Some(value) = value {
                    merge(slot, value, &mut b)?;
                }
            }
        }
    }
    let mut ranges = BTreeMap::new();
    for (actor, value) in actors.iter().zip(extrema) {
        let (lo, hi) = value.ok_or(SupportError::Base)?;
        ranges.insert(
            actor.clone(),
            ContributingRange {
                minimum: lo.exact_string(&mut b)?,
                maximum: hi.exact_string(&mut b)?,
                width: hi.sub(&lo, &mut b)?.exact_string(&mut b)?,
            },
        );
    }
    Ok(StandingSupport {
        boundary,
        sources,
        ranges,
        depth,
        support_visits: visits,
        extrema_slots: actors.len().checked_mul(3).ok_or(SupportError::Products)?,
    })
}
