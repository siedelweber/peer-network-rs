//! Exact zero-tilt anchor on the frozen compiler output, with irrational holds retained.
//! (´def:compiler:exact-anchor´)
use crate::{base::BaseScore, compiler::CompiledState};
use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use pn_graph::transport::exact_transport;
use pn_records::transport::{ExactArithmetic, KernelError, Matrix, TransportInput};
use pn_records::{DeclarationId, burn::Address, solve::Bounds};
use std::collections::BTreeMap;

/// Exact reduced transported amounts and action counts; the ledger is unchanged.
/// (´def:compiler:exact-anchor´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactAnchor {
    pub boundary: u64,
    pub edition: DeclarationId,
    pub normalized: BTreeMap<String, BTreeMap<String, String>>,
    pub raw: BTreeMap<String, BTreeMap<String, String>>,
    pub emitted: BTreeMap<String, BTreeMap<String, String>>,
    pub numerator: BTreeMap<String, String>,
    pub denominator: BTreeMap<String, String>,
    pub standing: BTreeMap<String, String>,
    pub hull: BTreeMap<String, Bounds>,
}

/// The exact subset never supplies a partial answer for an irrational base.
/// (´def:compiler:exact-anchor´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorOutcome {
    Exact(Box<ExactAnchor>),
    Held { entries: BTreeMap<(String, String), BaseScore> },
}

#[derive(Debug)]
struct Arithmetic {
    budget: Budget,
    zero: Rational,
    one: Rational,
}
impl ExactArithmetic for Arithmetic {
    type Number = Rational;
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "anchor::<Arithmetic as ExactArithmetic>::zero"
        ),
        ret
    )]
    fn zero(&self) -> Rational {
        self.zero.clone()
    }
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "anchor::<Arithmetic as ExactArithmetic>::one"
        ),
        ret
    )]
    fn one(&self) -> Rational {
        self.one.clone()
    }
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "anchor::<Arithmetic as ExactArithmetic>::add"
        ),
        ret
    )]
    fn add(&mut self, a: &Rational, b: &Rational) -> Result<Rational, KernelError> {
        a.add(b, &mut self.budget).map_err(arithmetic)
    }
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "anchor::<Arithmetic as ExactArithmetic>::sub"
        ),
        ret
    )]
    fn sub(&mut self, a: &Rational, b: &Rational) -> Result<Rational, KernelError> {
        a.sub(b, &mut self.budget).map_err(arithmetic)
    }
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "anchor::<Arithmetic as ExactArithmetic>::mul"
        ),
        ret
    )]
    fn mul(&mut self, a: &Rational, b: &Rational) -> Result<Rational, KernelError> {
        a.mul(b, &mut self.budget).map_err(arithmetic)
    }
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "anchor::<Arithmetic as ExactArithmetic>::div"
        ),
        ret
    )]
    fn div(&mut self, a: &Rational, b: &Rational) -> Result<Rational, KernelError> {
        a.div(b, &mut self.budget).map_err(arithmetic)
    }
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "anchor::<Arithmetic as ExactArithmetic>::compare"
        ),
        ret
    )]
    fn compare(&mut self, a: &Rational, b: &Rational) -> Result<std::cmp::Ordering, KernelError> {
        a.compare(b, &mut self.budget).map_err(arithmetic)
    }
}
fn arithmetic(error: nrz_cas::Fault) -> KernelError {
    KernelError::Arithmetic(error.to_string())
}
fn vector(values: &[Rational], actors: &[String], budget: &mut Budget) -> Result<BTreeMap<String, String>, KernelError> {
    actors
        .iter()
        .zip(values)
        .map(|(actor, value)| Ok((actor.clone(), value.exact_string(budget).map_err(arithmetic)?)))
        .collect()
}
fn matrix(
    values: &Matrix<Rational>,
    actors: &[String],
    budget: &mut Budget,
) -> Result<BTreeMap<String, BTreeMap<String, String>>, KernelError> {
    actors
        .iter()
        .zip(values)
        .map(|(actor, row)| {
            Ok((
                actor.clone(),
                row.iter()
                    .map(|(target, value)| Ok((actors[*target].clone(), value.exact_string(budget).map_err(arithmetic)?)))
                    .collect::<Result<_, KernelError>>()?,
            ))
        })
        .collect()
}

/// Construct the rational zero-tilt anchor from one frozen verified compilation.
/// (´[ROOT-alg:design:transport]´)
/// # Errors
/// Refuses resource exhaustion or inconsistent exact operator inputs; irrational entries return Held.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "anchor::exact_anchor"
    ),
    ret
)]
pub fn exact_anchor(state: &CompiledState, limits: Limits, maximum_cells: usize) -> Result<AnchorOutcome, KernelError> {
    let view = state.view();
    let inputs = state.package().input().inputs.last().ok_or(KernelError::Input)?;
    let actors: Vec<_> = view.base.rows.keys().cloned().collect();
    let mut held = BTreeMap::new();
    for (source, row) in &view.base.rows {
        for (target, entry) in row {
            if matches!(&entry.score, BaseScore::Held { .. }) {
                held.insert((source.clone(), target.clone()), entry.score.clone());
            }
        }
    }
    if !held.is_empty() {
        return Ok(AnchorOutcome::Held { entries: held });
    }
    let depth = inputs.parameters().depth_mass.len();
    if actors
        .len()
        .checked_mul(actors.len())
        .and_then(|n| n.checked_mul(depth.saturating_add(3)))
        .is_none_or(|n| n > maximum_cells)
    {
        return Err(KernelError::Limit);
    }
    let mut budget = Budget::new(limits).map_err(arithmetic)?;
    let zero = Rational::parse("0", &mut budget).map_err(arithmetic)?;
    let one = Rational::parse("1", &mut budget).map_err(arithmetic)?;
    let indices: BTreeMap<_, _> = actors.iter().enumerate().map(|(i, actor)| (actor, i)).collect();
    let mut base = Vec::new();
    for row in view.base.rows.values() {
        let mut values = BTreeMap::new();
        for (target, entry) in row {
            let BaseScore::Exact(value) = &entry.score else {
                return Err(KernelError::Input);
            };
            values.insert(
                *indices.get(target).ok_or(KernelError::Input)?,
                Rational::parse(value, &mut budget).map_err(arithmetic)?,
            );
        }
        base.push(values);
    }
    let mut depth_mass = Vec::new();
    for name in &inputs.parameters().depth_mass {
        depth_mass
            .push(crate::constant(inputs.constants(), name, &mut budget).map_err(|e| KernelError::Arithmetic(e.to_string()))?);
    }
    let mut counts = Vec::new();
    let mut rates = Vec::new();
    let mut emission = Vec::new();
    for actor in &actors {
        let address = Address(actor.clone());
        let count = view.ledger.counts.get(&address).ok_or(KernelError::Input)?.0;
        let source = view.support.sources.get(actor).ok_or(KernelError::Input)?;
        counts.push(Rational::parse(&count.to_string(), &mut budget).map_err(arithmetic)?);
        rates.push(Rational::parse(&source.reduced_rate, &mut budget).map_err(arithmetic)?);
        emission.push(Rational::parse(&source.emission, &mut budget).map_err(arithmetic)?);
    }
    let input = TransportInput {
        hops: vec![base; depth],
        depth_mass,
        counts,
        rates,
        emission,
    };
    let mut a = Arithmetic { budget, zero, one };
    let result = exact_transport(&input, &mut a, maximum_cells)?;
    let mut hull = BTreeMap::new();
    for (actor, (lower, upper)) in actors.iter().zip(&result.hull) {
        hull.insert(
            actor.clone(),
            Bounds {
                lower: lower.exact_string(&mut a.budget).map_err(arithmetic)?,
                upper: upper.exact_string(&mut a.budget).map_err(arithmetic)?,
            },
        );
    }
    Ok(AnchorOutcome::Exact(Box::new(ExactAnchor {
        boundary: view.base.boundary,
        edition: view.base.edition.clone(),
        normalized: matrix(result.normalized.first().ok_or(KernelError::Input)?, &actors, &mut a.budget)?,
        raw: matrix(&result.raw, &actors, &mut a.budget)?,
        emitted: matrix(&result.emitted, &actors, &mut a.budget)?,
        numerator: vector(&result.numerator, &actors, &mut a.budget)?,
        denominator: vector(&result.denominator, &actors, &mut a.budget)?,
        standing: vector(&result.standing, &actors, &mut a.budget)?,
        hull,
    })))
}
