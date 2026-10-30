//! Source emission and pre-solve contributing support, without transport weights.
//! (´def:compiler:emission-support´)

use crate::{
    CompilerInputs, InputError,
    base::{BaseAllocation, BaseScore},
    ledger::FinalLedger,
};
use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use pn_records::{
    burn::Address,
    numerics::{ChargedPrice, NumericContext, NumericError},
};
use std::collections::{BTreeMap, BTreeSet};

/// Directed support on the same anchored-Actor index as the base.
/// (´def:compiler:emission-support´)
pub type SupportRows = BTreeMap<String, BTreeSet<String>>;

/// One source's reduced rate and its emission and identity-retention fractions.
/// (´def:compiler:emission-support´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceEmission {
    pub reduced_rate: String,
    pub emission: String,
    pub retained: String,
}

/// Exact extrema of source rates reaching a target, not a standing solution.
/// (´def:compiler:emission-support´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContributingRange {
    pub minimum: String,
    pub maximum: String,
    pub width: String,
}

/// Supported hop products before emission, and the emitted contributing relation.
/// (´def:compiler:emission-support´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingSupport {
    pub boundary: u64,
    pub sources: BTreeMap<String, SourceEmission>,
    pub by_depth: BTreeMap<usize, SupportRows>,
    pub emitted: SupportRows,
    pub contributors: SupportRows,
    pub ranges: BTreeMap<String, ContributingRange>,
    pub products: u64,
}

/// No partial support escapes invalid premises or bounded computation.
/// (´def:compiler:emission-support´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SupportError {
    #[error("base, ledger or price does not match the bound boundary")]
    Boundary,
    #[error("base is not a nonnegative square anchored matrix with positive diagonal")]
    Base,
    #[error("anchored ledger pair is missing, has zero count or differs in units")]
    Ledger,
    #[error("support product budget exhausted")]
    Products,
    #[error("bound parameter: {0}")]
    Input(#[from] InputError),
    #[error("numeric coordinate: {0}")]
    Numeric(#[from] NumericError),
    #[error("exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

/// Compile source fractions and Boolean reachability from the derived base and final ledger.
/// (´[ROOT-alg:design:emission-support]´)
/// The caller supplies outputs for the same completed history; this checks their structural
/// boundary, index, units and writing-price premises, not their canonical provenance.
/// # Errors
/// Refuses inconsistent carriers, missing anchored pairs or numeric/product-budget exhaustion.
#[tracing::instrument(
    name = "alg:design:emission-support",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "alg:design:emission-support",
        source_item = "support::compile_support"
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
        || ledger.snapshots.last().map(|snapshot| snapshot.boundary) != Some(boundary)
        || price.numeraire() != &inputs.parameters().numeraire
        || numeric.charged_price(
            price.wall(),
            &inputs.parameters().numeraire,
            inputs.constants().content().floor,
        )? != *price
        || ledger
            .debits
            .values()
            .any(|debit| debit.boundary() == boundary && debit.price() != price)
    {
        return Err(SupportError::Boundary);
    }
    let mut budget = Budget::new(limits)?;
    let mut adjacency = BTreeMap::new();
    for (source, row) in &base.rows {
        let mut targets = BTreeSet::new();
        for (target, entry) in row {
            if !base.rows.contains_key(target) {
                return Err(SupportError::Base);
            }
            if positive(&entry.score, &mut budget)? {
                targets.insert(target.clone());
            }
        }
        if !targets.contains(source) {
            return Err(SupportError::Base);
        }
        adjacency.insert(source.clone(), targets);
    }
    let (sources, rates) = source_pairs(inputs, price, ledger, base, &mut budget)?;
    let mut current: SupportRows = base
        .rows
        .keys()
        .map(|source| (source.clone(), BTreeSet::from([source.clone()])))
        .collect();
    let mut by_depth = BTreeMap::new();
    let mut products = 0_u64;
    for (index, mass_name) in inputs.parameters().depth_mass.iter().enumerate() {
        let mut next = BTreeMap::new();
        for (source, reached) in &current {
            let mut targets = BTreeSet::new();
            for relay in reached {
                for target in adjacency.get(relay).ok_or(SupportError::Base)? {
                    products = products
                        .checked_add(1)
                        .filter(|value| *value <= maximum_products)
                        .ok_or(SupportError::Products)?;
                    targets.insert(target.clone());
                }
            }
            next.insert(source.clone(), targets);
        }
        current = next;
        if !crate::constant(inputs.constants(), mass_name, &mut budget)?.is_zero() {
            by_depth.insert(index + 1, current.clone());
        }
    }
    let mut emitted = BTreeMap::new();
    let mut contributors: SupportRows = base.rows.keys().map(|actor| (actor.clone(), BTreeSet::new())).collect();
    for (source, evidence) in &sources {
        let mut targets = BTreeSet::new();
        if evidence.emission != "0" {
            for support in by_depth.values() {
                targets.extend(support[source].iter().cloned());
            }
        }
        if evidence.retained != "0" {
            targets.insert(source.clone());
        }
        for target in &targets {
            contributors.get_mut(target).ok_or(SupportError::Base)?.insert(source.clone());
        }
        emitted.insert(source.clone(), targets);
    }
    let ranges = contributing_ranges(&contributors, &rates, &mut budget)?;
    Ok(StandingSupport {
        boundary,
        sources,
        by_depth,
        emitted,
        contributors,
        ranges,
        products,
    })
}

fn positive(score: &BaseScore, budget: &mut Budget) -> Result<bool, SupportError> {
    let (exact, terms) = match score {
        BaseScore::Exact(value) => (value, &[][..]),
        BaseScore::Held { exact_part, terms } if !terms.is_empty() => (exact_part, terms.as_slice()),
        BaseScore::Held { .. } => return Err(SupportError::Base),
    };
    let value = Rational::parse(exact, budget)?;
    if value.is_negative() {
        return Err(SupportError::Base);
    }
    for term in terms {
        for spelling in [&term.radicand, &term.domain_factor] {
            let value = Rational::parse(spelling, budget)?;
            if value.is_negative() || value.is_zero() {
                return Err(SupportError::Base);
            }
        }
    }
    // Every retained irrational term has a provably positive coefficient and factor.
    Ok(!value.is_zero() || !terms.is_empty())
}

type Rates = BTreeMap<String, Rational>;

fn source_pairs(
    inputs: &CompilerInputs,
    price: &ChargedPrice,
    ledger: &FinalLedger,
    base: &BaseAllocation,
    budget: &mut Budget,
) -> Result<(BTreeMap<String, SourceEmission>, Rates), SupportError> {
    let nu = Rational::parse(inputs.parameters().numeraire.amount().exact(), budget)?;
    let threshold = Rational::parse(price.price().exact(), budget)?;
    let one = Rational::parse("1", budget)?;
    let mut sources = BTreeMap::new();
    let mut rates = BTreeMap::new();
    for source in base.rows.keys() {
        let address = Address(source.clone());
        let count = ledger
            .counts
            .get(&address)
            .filter(|count| count.0 > 0)
            .ok_or(SupportError::Ledger)?;
        let balance = ledger.balances.get(&address).ok_or(SupportError::Ledger)?;
        if balance.unit() != price.price().unit() {
            return Err(SupportError::Ledger);
        }
        let balance = Rational::parse(balance.exact(), budget)?;
        let count = Rational::parse(&count.0.to_string(), budget)?;
        let rate = balance.div(&nu.mul(&count, budget)?, budget)?;
        let fraction = balance.div(&threshold.mul(&count, budget)?, budget)?;
        let emission = if fraction.compare(&one, budget)?.is_gt() {
            one.clone()
        } else {
            fraction
        };
        sources.insert(
            source.clone(),
            SourceEmission {
                reduced_rate: rate.exact_string(budget)?,
                emission: emission.exact_string(budget)?,
                retained: one.sub(&emission, budget)?.exact_string(budget)?,
            },
        );
        rates.insert(source.clone(), rate);
    }
    Ok((sources, rates))
}

fn contributing_ranges(
    contributors: &SupportRows,
    rates: &Rates,
    budget: &mut Budget,
) -> Result<BTreeMap<String, ContributingRange>, SupportError> {
    let mut ranges = BTreeMap::new();
    for (target, contributing) in contributors {
        let mut minimum = None;
        let mut maximum = Rational::parse("0", budget)?;
        for source in contributing {
            let rate = rates.get(source).ok_or(SupportError::Ledger)?;
            if minimum
                .as_ref()
                .map(|old| rate.compare(old, budget))
                .transpose()?
                .is_none_or(std::cmp::Ordering::is_lt)
            {
                minimum = Some(rate.clone());
            }
            if rate.compare(&maximum, budget)?.is_gt() {
                maximum = rate.clone();
            }
        }
        let minimum = minimum.ok_or(SupportError::Base)?;
        ranges.insert(
            target.clone(),
            ContributingRange {
                minimum: minimum.exact_string(budget)?,
                maximum: maximum.exact_string(budget)?,
                width: maximum.sub(&minimum, budget)?.exact_string(budget)?,
            },
        );
    }
    Ok(ranges)
}
