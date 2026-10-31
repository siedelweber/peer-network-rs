//! Reference-profile endpoint envelopes retain their scalar premises.
//! (´def:numerics:activation-endpoints´)

use super::{Error, Quantity, Request};
use nrz_cas::{Location, Rational, limits::Budget};
use pn_records::{
    primitive::{Goal, Node, PrimitiveRecord, Query, Range},
    solve::Procedure,
};

/// Locally constructed endpoint evidence; no caller-supplied bound can construct this value.
/// (´def:numerics:activation-endpoints´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    input: Request,
    bounds: Option<Range>,
    records: Vec<PrimitiveRecord>,
    source: Option<Box<Envelope>>,
    work: u64,
}

impl Envelope {
    /// Borrow the derived enclosure, absent when a scalar request produced no bound.
    /// (´def:numerics:activation-endpoints´)
    /// Justified: Immutable access retains the checked endpoint construction boundary.
    #[must_use]
    pub const fn bounds(&self) -> Option<&Range> {
        self.bounds.as_ref()
    }

    /// Borrow every original scalar request and its checked or stopped evidence.
    /// (´def:numerics:activation-endpoints´)
    /// Justified: Immutable access retains the checked endpoint construction boundary.
    #[must_use]
    pub fn records(&self) -> &[PrimitiveRecord] {
        &self.records
    }

    /// Actual Work includes exact endpoint assembly and all enclosed requests.
    /// (´def:numerics:activation-endpoints´)
    /// Justified: Immutable access retains the checked endpoint construction boundary.
    #[must_use]
    pub const fn work(&self) -> u64 {
        self.work
    }

    /// Borrow the previously checked activation reused by an endpoint-power request.
    /// (´def:numerics:activation-endpoints´)
    /// Justified: Immutable access retains the explicit checked source rather than a private cache.
    #[must_use]
    pub fn source(&self) -> Option<&Self> {
        self.source.as_deref()
    }
}

fn allowance(procedure: &Procedure, budget: &Budget) -> Result<Procedure, Error> {
    let mut next = procedure.clone();
    let policy = next.enclosure.as_mut().ok_or(Error::Unsupported)?;
    policy.operation.work = policy
        .operation
        .work
        .checked_sub(budget.usage().work)
        .filter(|v| *v > 0)
        .ok_or(Error::Declaration)?;
    Ok(next)
}

fn point(
    procedure: &Procedure,
    input: &Request,
    at: &Rational,
    quantity: Quantity,
    budget: &mut Budget,
) -> Result<PrimitiveRecord, Error> {
    let at = at.exact_string(budget)?;
    let request = Request {
        standing: Range {
            lower: at.clone(),
            upper: at,
        },
        bleed_squared: input.bleed_squared.clone(),
        wall: None,
        quantity,
    };
    let result = super::evaluate(&allowance(procedure, budget)?, &request, None)?.primitive;
    budget.work(result.evidence.work, Location::new("activation endpoint request"))?;
    Ok(result)
}

fn endpoints(input: &Request, budget: &mut Budget) -> Result<(Rational, Rational, bool), Error> {
    super::validate(input, budget)?;
    if Rational::parse(&input.bleed_squared, budget)? != Rational::parse("1/400", budget)? {
        return Err(Error::Unsupported);
    }
    let mut lower = Rational::parse(&input.standing.lower, budget)?;
    let mut upper = Rational::parse(&input.standing.upper, budget)?;
    let mut includes_zero = false;
    if let Some(wall) = &input.wall {
        let wall = Rational::parse(wall, budget)?;
        includes_zero = !lower.compare(&wall, budget)?.is_gt();
        if lower.compare(&wall, budget)?.is_lt() {
            lower = wall.clone();
        }
        if upper.compare(&wall, budget)?.is_lt() {
            upper = wall;
        }
    }
    Ok((lower, upper, includes_zero))
}

/// Enclose reference-profile values or gains by their proved monotone endpoints.
/// (´def:numerics:activation-endpoints´)
/// # Errors
/// Refuses a different bleed profile, unsupported quantity, domain or finite resource failure.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::monotone::evaluate"
    ),
    ret
)]
pub fn evaluate(procedure: &Procedure, input: &Request) -> Result<Envelope, Error> {
    super::super::preflight(procedure)?;
    let policy = procedure.enclosure.as_ref().ok_or(Error::Unsupported)?;
    let mut budget = Budget::new(policy.operation.clone())?;
    let (lower, upper, includes_zero) = endpoints(input, &mut budget)?;
    let gain = matches!(input.quantity, Quantity::ResponsiveLogGain | Quantity::GeneralizedLogGain);
    if !matches!(
        input.quantity,
        Quantity::Responsive | Quantity::Clamped | Quantity::ResponsiveLogGain | Quantity::GeneralizedLogGain
    ) {
        return Err(Error::Unsupported);
    }
    let mut result = Envelope {
        input: input.clone(),
        bounds: None,
        records: Vec::new(),
        source: None,
        work: 0,
    };
    if gain
        && includes_zero
        && Rational::parse(&input.standing.upper, &mut budget)?
            .compare(&lower, &mut budget)?
            .is_lt()
    {
        result.bounds = Some(Range {
            lower: "0".into(),
            upper: "0".into(),
        });
        result.work = budget.usage().work;
        return Ok(result);
    }
    let quantity = if gain {
        Quantity::ResponsiveLogGain
    } else {
        Quantity::Responsive
    };
    let first = point(procedure, input, &lower, quantity.clone(), &mut budget)?;
    result.records.push(first);
    if lower != upper && !(gain && includes_zero) {
        result.records.push(point(procedure, input, &upper, quantity, &mut budget)?);
    }
    result.bounds = assemble(input, &result.records, includes_zero, gain, &mut budget)?;
    result.work = budget.usage().work;
    Ok(result)
}

fn assemble(
    input: &Request,
    records: &[PrimitiveRecord],
    includes_zero: bool,
    gain: bool,
    budget: &mut Budget,
) -> Result<Option<Range>, Error> {
    let Some(first) = records.first().and_then(|r| r.evidence.bounds.as_ref()) else {
        return Ok(None);
    };
    let Some(last) = records.last().and_then(|r| r.evidence.bounds.as_ref()) else {
        return Ok(None);
    };
    if gain && includes_zero {
        let below = Rational::parse(&input.standing.upper, budget)?
            .compare(
                &Rational::parse(input.wall.as_ref().ok_or(Error::Declaration)?, budget)?,
                budget,
            )?
            .is_lt();
        return Ok(Some(Range {
            lower: "0".into(),
            upper: if below {
                "0".into()
            } else {
                first.upper().exact_string(budget)?
            },
        }));
    }
    let (lower, upper) = if gain {
        (last.lower(), first.upper())
    } else {
        (first.lower(), last.upper())
    };
    Ok(Some(Range {
        lower: lower.exact_string(budget)?,
        upper: upper.exact_string(budget)?,
    }))
}

/// Raise one locally checked positive activation enclosure without recomputing its activation.
/// (´def:numerics:activation-endpoints´)
/// # Errors
/// Refuses a gain, missing bound, nonpositive base, negative exponent or resource failure.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::activation::monotone::power"
    ),
    ret
)]
pub fn power(procedure: &Procedure, base: &Envelope, exponent: &str) -> Result<Envelope, Error> {
    super::super::preflight(procedure)?;
    if !matches!(base.input.quantity, Quantity::Responsive | Quantity::Clamped) {
        return Err(Error::Declaration);
    }
    let bounds = base.bounds.as_ref().ok_or(Error::Declaration)?;
    let policy = procedure.enclosure.as_ref().ok_or(Error::Unsupported)?;
    let mut budget = Budget::new(policy.operation.clone())?;
    let exponent = super::nonnegative(exponent, &mut budget)?.exact_string(&mut budget)?;
    let lower = Rational::parse(&bounds.lower, &mut budget)?;
    if lower.is_negative() || lower.is_zero() {
        return Err(Error::Declaration);
    }
    let mut result = Envelope {
        input: base.input.clone(),
        bounds: None,
        records: Vec::new(),
        source: Some(Box::new(base.clone())),
        work: 0,
    };
    for text in [&bounds.lower, &bounds.upper] {
        let query = Query {
            coordinates: Vec::new(),
            nodes: vec![Node::Rational(text.clone()), Node::PositivePower(0, exponent.clone())],
            target: 1,
            goal: Goal::Width,
        };
        let evidence = super::super::evaluate(&allowance(procedure, &budget)?, &query, None)?;
        budget.work(evidence.work, Location::new("activation endpoint power"))?;
        result.records.push(PrimitiveRecord {
            query,
            precision: policy.refinement.precision,
            evidence,
        });
    }
    result.bounds = assemble(&base.input, &result.records, false, false, &mut budget)?;
    result.work = budget.usage().work;
    Ok(result)
}
