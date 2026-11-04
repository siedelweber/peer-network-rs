//! Strict-sign inversion of the deployed gain, with complete expected-query replay.
//! (´[ROOT-alg:design:reference-wall]´)

mod branches;

use super::activation::{Quantity, Request};
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    primitive::{Goal, Node, Outcome, PrimitiveRecord, Range},
    solve::{Precision, Procedure},
    wall::{Inputs, Record, Sign, Step, Verdict},
};

/// Refusals identify the first failed admission or evidence check.
/// (´[ROOT-alg:design:reference-wall]´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid reference wall declaration")]
    Declaration,
    #[error("lower bracket endpoint is outside the declared reduction range")]
    Binding,
    #[error("initial bracket has a certified wrong endpoint sign")]
    Bracket,
    #[error("supplied wall query or precision differs from the rebuilt query")]
    Query,
    #[error("supplied wall attachment is absent or invalid")]
    Attachment,
    #[error("supplied wall result differs from independently replayed evidence")]
    Record,
    #[error("wall scalar evaluation stopped: {outcome:?}; resource fault: {resource_fault:?}")]
    Operational {
        outcome: Outcome,
        resource_fault: Option<pn_records::primitive::FaultAssertion>,
    },
    #[error("wall iteration allowance exhausted")]
    Iterations,
    #[error("binding ridge floor requires its exact defining object")]
    Ridge,
    #[error("wall numeric request: {0}")]
    Numeric(#[from] super::Error),
    #[error("wall exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

fn positive(value: &str, b: &mut Budget) -> Result<Rational, Error> {
    let value = Rational::parse(value, b)?;
    if value.is_negative() || value.is_zero() {
        return Err(Error::Declaration);
    }
    Ok(value)
}

fn range(a: &Rational, z: &Rational, b: &mut Budget) -> Result<Range, Error> {
    Ok(Range {
        lower: a.exact_string(b)?,
        upper: z.exact_string(b)?,
    })
}

fn validate(procedure: &Procedure, input: &Inputs, b: &mut Budget) -> Result<(), Error> {
    super::preflight(procedure)?;
    let policy = procedure.enclosure.as_ref().ok_or(Error::Declaration)?;
    let k = policy.refinement.reduction_ceiling;
    let scale = 1_u64.checked_shl(k).filter(|v| *v > 2).ok_or(Error::Binding)?;
    let a = positive(&input.bracket.lower, b)?;
    let z = positive(&input.bracket.upper, b)?;
    let minimum = Rational::parse("1", b)?.div(&Rational::parse(&(scale - 2).to_string(), b)?, b)?;
    if a.compare(&minimum, b)?.is_lt() {
        return Err(Error::Binding);
    }
    if !a.compare(&z, b)?.is_lt()
        || Rational::parse(&input.width, b)?.is_negative()
        || !positive(&procedure.margin, b)?.compare(&Rational::parse("1", b)?, b)?.is_gt()
        || input.maximum_steps == 0
        || input.maximum_work == 0
        || input.maximum_replay_work == 0
    {
        return Err(Error::Declaration);
    }
    positive(&input.cumulative_tilt, b)?;
    positive(&input.stopping_width, b)?;
    branches::validate(input, b)
}

struct Run<'a> {
    procedure: &'a Procedure,
    bleed_squared: &'a str,
    supplied: Option<&'a Record>,
    reconstruct: bool,
    budget: Budget,
    result: Record,
}

impl Run<'_> {
    fn sign(&mut self, x: &Rational, target: &Rational) -> Result<Sign, Error> {
        let Precision::AbsoluteWidthBits(sequence) = &self.procedure.precision else {
            return Err(Error::Declaration);
        };
        for precision in sequence {
            let before = self.budget.usage().work;
            let mut query = super::activation::query(
                &Request {
                    standing: range(x, x, &mut self.budget)?,
                    bleed_squared: self.bleed_squared.into(),
                    wall: None,
                    wall_enclosure: None,
                    quantity: Quantity::ResponsiveLogGain,
                },
                &mut self.budget,
            )?;
            let index = query.nodes.len();
            query.nodes.push(Node::Rational(target.exact_string(&mut self.budget)?));
            query.nodes.push(Node::Subtract(query.target, index));
            query.target = index + 1;
            query.goal = Goal::Width;
            let supplied = self
                .supplied
                .map(|r| r.steps.get(self.result.steps.len()).ok_or(Error::Query))
                .transpose()?;
            if supplied.is_some_and(|s| s.primitive.query != query || s.primitive.precision != *precision) {
                return Err(Error::Query);
            }
            let attachment = supplied
                .map(|s| s.primitive.evidence.attachment.as_ref().ok_or(Error::Attachment))
                .transpose()?;
            if let Some(attachment) = attachment {
                super::schemas(&attachment.schemas).map_err(|_| Error::Attachment)?;
            }
            let mut policy = self.procedure.clone();
            policy.enclosure.as_mut().ok_or(Error::Declaration)?.refinement.precision = *precision;
            let evidence = super::run_budget(
                &policy,
                &query,
                attachment.filter(|_| !self.reconstruct),
                None,
                &mut self.budget,
            )
            .map_err(|e| match e {
                super::Error::InvalidCertificate(_) | super::Error::Schema if supplied.is_some() => Error::Attachment,
                other => Error::Numeric(other),
            })?;
            if self.reconstruct && supplied.is_some_and(|s| s.primitive.evidence.attachment != evidence.attachment) {
                return Err(Error::Attachment);
            }
            if !matches!(evidence.outcome, Outcome::Bound | Outcome::Indecisive(_)) {
                return Err(Error::Operational {
                    outcome: evidence.outcome,
                    resource_fault: evidence.resource_fault,
                });
            }
            let bounds = evidence.bounds.as_ref().ok_or(Error::Record)?;
            let zero = Rational::parse("0", &mut self.budget)?;
            let sign = if bounds.lower().compare(&zero, &mut self.budget)?.is_gt() {
                Sign::Positive
            } else if bounds.upper().compare(&zero, &mut self.budget)?.is_lt() {
                Sign::Negative
            } else {
                Sign::Indecisive
            };
            if supplied.is_some_and(|s| {
                s.sign != sign
                    || s.primitive.evidence.bounds != evidence.bounds
                    || s.primitive.evidence.outcome != evidence.outcome
                    || s.primitive.evidence.resource_fault != evidence.resource_fault
            }) {
                return Err(Error::Record);
            }
            self.result.steps.push(Step {
                primitive: PrimitiveRecord {
                    query,
                    precision: *precision,
                    evidence,
                },
                sign,
                work: self.budget.usage().work - before,
            });
            if sign != Sign::Indecisive {
                return Ok(sign);
            }
        }
        self.result.indecisive = true;
        Ok(Sign::Indecisive)
    }

    fn invert(&mut self, input: &Inputs) -> Result<Option<Range>, Error> {
        let b = &mut self.budget;
        let width = Rational::parse(&input.width, b)?;
        if width.is_zero() {
            return Ok(None);
        }
        let denominator = Rational::parse("2", b)?
            .mul(&Rational::parse(&self.procedure.margin, b)?, b)?
            .mul(&Rational::parse(&input.cumulative_tilt, b)?, b)?
            .mul(&width, b)?;
        let target = Rational::parse("1", b)?.div(&denominator, b)?;
        let mut a = Rational::parse(&input.bracket.lower, b)?;
        let mut z = Rational::parse(&input.bracket.upper, b)?;
        let stop = Rational::parse(&input.stopping_width, b)?;
        let two = Rational::parse("2", b)?;
        for (endpoint, required) in [(&a, Sign::Positive), (&z, Sign::Negative)] {
            let sign = self.sign(endpoint, &target)?;
            if sign == Sign::Indecisive {
                return Ok(None);
            }
            if sign != required {
                return Err(Error::Bracket);
            }
        }
        loop {
            let before = self.budget.usage().work;
            if !z.sub(&a, &mut self.budget)?.compare(&stop, &mut self.budget)?.is_gt() {
                break;
            }
            if self.result.bisections >= input.maximum_steps {
                return Err(Error::Iterations);
            }
            let middle = a.add(&z, &mut self.budget)?.div(&two, &mut self.budget)?;
            match self.sign(&middle, &target)? {
                Sign::Positive => a = middle,
                Sign::Negative => z = middle,
                Sign::Indecisive => return Ok(None),
            }
            self.result.bisections += 1;
            self.result.bisection_work.push(self.budget.usage().work - before);
        }
        Ok(Some(range(&a, &z, &mut self.budget)?))
    }
}

fn run(procedure: &Procedure, input: &Inputs, supplied: Option<&Record>) -> Result<Record, Error> {
    let policy = procedure.enclosure.as_ref().ok_or(Error::Declaration)?;
    let mut limits = policy.operation.clone();
    limits.work = limits.work.min(if supplied.is_some() {
        input.maximum_replay_work
    } else {
        input.maximum_work
    });
    let mut run = Run {
        procedure,
        bleed_squared: "1/400",
        supplied,
        reconstruct: false,
        budget: Budget::new(limits)?,
        result: Record {
            target: None,
            steps: Vec::new(),
            bisections: 0,
            bisection_work: Vec::new(),
            branches: None,
            indecisive: false,
            work: 0,
        },
    };
    validate(procedure, input, &mut run.budget)?;
    run.result.target = run.invert(input)?;
    if !run.result.indecisive {
        run.result.branches = branches::evaluate(input, run.result.target.as_ref(), &mut run.budget)?;
        run.result.indecisive =
            run.result.branches.as_ref().is_none_or(|branches| {
                branches.above_floor == Verdict::Indecisive || branches.policy_valid == Verdict::Indecisive
            });
    }
    run.result.work = run.budget.usage().work;
    if supplied.is_some_and(|r| {
        r.steps.len() != run.result.steps.len()
            || r.target != run.result.target
            || r.bisections != run.result.bisections
            || r.branches != run.result.branches
            || r.indecisive != run.result.indecisive
    }) {
        return Err(Error::Record);
    }
    Ok(run.result)
}

/// Check the lower endpoint and complete declaration before any scalar evaluation.
/// (´[ROOT-alg:design:reference-wall]´)
/// # Errors
/// Refuses malformed fields and an unsupported reduction range.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::wall::check_declaration"
    ),
    ret
)]
pub fn check_declaration(procedure: &Procedure, input: &Inputs) -> Result<(), Error> {
    let limits = procedure.enclosure.as_ref().ok_or(Error::Declaration)?.operation.clone();
    validate(procedure, input, &mut Budget::new(limits)?)
}

/// Enclose the defining target and certify the controller branches without changing a price.
/// (´[ROOT-alg:design:reference-wall]´)
/// # Errors
/// Refuses invalid declarations, wrong brackets, unavailable ridge objects and operational stops.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::wall::evaluate"
    ),
    ret
)]
pub fn evaluate(procedure: &Procedure, input: &Inputs) -> Result<Record, Error> {
    run(procedure, input, None)
}

/// Rebuild endpoint and midpoint queries from inputs and checked signs, then check attachments.
/// (´[ROOT-alg:design:reference-wall]´)
/// # Errors
/// Refuses changed queries at Query and missing or invalid certificates at Attachment.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::wall::replay"
    ),
    ret
)]
pub fn replay(procedure: &Procedure, input: &Inputs, record: &Record) -> Result<Record, Error> {
    run(procedure, input, Some(record))
}

// The production controller shares only the inverse algorithm, not reference branches.
pub(super) fn inverse(
    procedure: &Procedure,
    input: &Inputs,
    bleed_squared: &str,
    supplied: Option<&Record>,
) -> Result<Record, Error> {
    let policy = procedure.enclosure.as_ref().ok_or(Error::Declaration)?;
    let mut limits = policy.operation.clone();
    limits.work = limits.work.min(if supplied.is_some() {
        input.maximum_replay_work
    } else {
        input.maximum_work
    });
    let mut run = Run {
        procedure,
        bleed_squared,
        supplied,
        reconstruct: true,
        budget: Budget::new(limits)?,
        result: Record {
            target: None,
            steps: Vec::new(),
            bisections: 0,
            bisection_work: Vec::new(),
            branches: None,
            indecisive: false,
            work: 0,
        },
    };
    validate(procedure, input, &mut run.budget)?;
    positive(bleed_squared, &mut run.budget)?;
    run.result.target = run.invert(input)?;
    run.result.work = run.budget.usage().work;
    if let Some(record) = supplied {
        if record.steps.len() != run.result.steps.len() {
            return Err(Error::Query);
        }
        for (expected, actual) in record.steps.iter().zip(&run.result.steps) {
            if expected.primitive.query != actual.primitive.query || expected.primitive.precision != actual.primitive.precision {
                return Err(Error::Query);
            }
            if expected.primitive.evidence.attachment != actual.primitive.evidence.attachment {
                return Err(Error::Attachment);
            }
        }
        if record != &run.result {
            return Err(Error::Record);
        }
    }
    Ok(run.result)
}
