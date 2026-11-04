//! Independently replayed clean ridge evidence, separate from deployed gain inversion.
//! (´[ROOT-alg:design:binding-ridge]´)

mod formula;
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    numerics::{Floor, FloorComparison},
    primitive::{Outcome, PrimitiveRecord, Query, Range},
    ridge::{ComparisonRecord, Definition, Inputs, Record, Wall},
    solve::{Precision, Procedure},
    wall::Sign,
};

/// Refusals preserve the first failed defining, query, attachment or arithmetic check.
/// (´[ROOT-alg:design:binding-ridge]´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("unsupported clean ridge defining object")]
    Definition,
    #[error("invalid ridge declaration")]
    Declaration,
    #[error("certified wrong ridge endpoint sign")]
    Bracket,
    #[error("ridge query or precision differs from its reconstruction")]
    Query,
    #[error("ridge attachment absent or invalid")]
    Attachment,
    #[error("ridge record differs from independently checked evidence")]
    Record,
    #[error("ridge query {query} stopped without mathematical evidence: {outcome:?}, {fault:?}")]
    Operational {
        query: usize,
        outcome: Outcome,
        fault: Option<pn_records::primitive::FaultAssertion>,
    },
    #[error("ridge numerical kernel: {0}")]
    Numeric(#[from] super::Error),
    #[error("ridge exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

/// Only independent replay constructs this immutable authority for ridge comparisons.
/// (´[ROOT-alg:design:binding-ridge]´)
#[derive(Clone, Debug)]
pub struct CheckedRidge {
    procedure: Procedure,
    input: Inputs,
    image: Option<Range>,
}

impl CheckedRidge {
    /// Borrow the checked image; absence means the defining evidence stayed indecisive.
    /// (´[ROOT-alg:design:binding-ridge]´)
    /// Justified: Immutable access inherits the replay operation and supplies no new verdict.
    #[must_use]
    pub fn image(&self) -> Option<&Range> {
        self.image.as_ref()
    }
}

fn definition(d: &Definition) -> Result<(), Error> {
    if d.schema != "clean-elasticity-ridge-v1"
        || d.inverse_temperature != "2*ln(2)"
        || d.bleed_squared != "0"
        || d.core_power != "1"
    {
        return Err(Error::Definition);
    }
    Ok(())
}

fn interval(a: &Rational, b: &Rational, budget: &mut Budget) -> Result<Range, Error> {
    Ok(Range {
        lower: a.exact_string(budget)?,
        upper: b.exact_string(budget)?,
    })
}

fn validate(p: &Procedure, input: &Inputs, b: &mut Budget) -> Result<(), Error> {
    super::preflight(p)?;
    definition(&input.definition)?;
    let Precision::AbsoluteWidthBits(sequence) = &p.precision else {
        return Err(Error::Declaration);
    };
    let a = Rational::parse(&input.bracket.lower, b)?;
    let z = Rational::parse(&input.bracket.upper, b)?;
    if a.is_negative()
        || a.is_zero()
        || !a.compare(&z, b)?.is_lt()
        || !z.compare(&Rational::parse("3/40", b)?, b)?.is_lt()
        || sequence.is_empty()
        || sequence.contains(&0)
        || sequence.windows(2).any(|s| s[0] >= s[1])
        || input.maximum_work == 0
        || input.maximum_replay_work == 0
    {
        return Err(Error::Declaration);
    }
    Ok(())
}

struct Run<'a> {
    procedure: &'a Procedure,
    supplied: Option<&'a [PrimitiveRecord]>,
    budget: Budget,
    queries: Vec<PrimitiveRecord>,
}

impl<'a> Run<'a> {
    fn new(p: &'a Procedure, input: &Inputs, supplied: Option<&'a [PrimitiveRecord]>) -> Result<Self, Error> {
        let mut limits = p.enclosure.as_ref().ok_or(Error::Declaration)?.operation.clone();
        limits.work = limits.work.min(if supplied.is_some() {
            input.maximum_replay_work
        } else {
            input.maximum_work
        });
        let mut budget = Budget::new(limits)?;
        validate(p, input, &mut budget)?;
        Ok(Self {
            procedure: p,
            supplied,
            budget,
            queries: Vec::new(),
        })
    }
    fn request(&mut self, query: Query, precision: u32) -> Result<Option<nrz_cas::enclosure::Interval>, Error> {
        let supplied = self
            .supplied
            .map(|v| v.get(self.queries.len()).ok_or(Error::Query))
            .transpose()?;
        if supplied.is_some_and(|r| r.query != query || r.precision != precision) {
            return Err(Error::Query);
        }
        let attachment = supplied.and_then(|r| r.evidence.attachment.as_ref());
        if supplied.is_some_and(|r| r.evidence.bounds.is_some()) && attachment.is_none() {
            return Err(Error::Attachment);
        }
        if let Some(a) = attachment {
            super::schemas(&a.schemas).map_err(|_| Error::Attachment)?;
        }
        let mut policy = self.procedure.clone();
        policy.enclosure.as_mut().ok_or(Error::Declaration)?.refinement.precision = precision;
        let evidence = super::run_budget(&policy, &query, attachment, None, &mut self.budget).map_err(|e| match e {
            super::Error::InvalidCertificate(_) | super::Error::Schema if supplied.is_some() => Error::Attachment,
            other => Error::Numeric(other),
        })?;
        if !matches!(
            evidence.outcome,
            Outcome::Bound | Outcome::Indecisive(_) | Outcome::DomainBoundary
        ) {
            return Err(Error::Operational {
                query: self.queries.len(),
                outcome: evidence.outcome,
                fault: evidence.resource_fault,
            });
        }
        if supplied.is_some_and(|r| {
            r.evidence.bounds != evidence.bounds
                || r.evidence.outcome != evidence.outcome
                || r.evidence.resource_fault != evidence.resource_fault
        }) {
            return Err(Error::Record);
        }
        let bounds = if evidence.outcome == Outcome::DomainBoundary {
            None
        } else {
            evidence.bounds.clone()
        };
        self.queries.push(PrimitiveRecord {
            query,
            precision,
            evidence,
        });
        Ok(bounds)
    }
    fn sign(&mut self, query: &Query) -> Result<Sign, Error> {
        let Precision::AbsoluteWidthBits(sequence) = &self.procedure.precision else {
            return Err(Error::Declaration);
        };
        for precision in sequence {
            if let Some(bounds) = self.request(query.clone(), *precision)? {
                let zero = Rational::parse("0", &mut self.budget)?;
                if bounds.lower().compare(&zero, &mut self.budget)?.is_gt() {
                    return Ok(Sign::Positive);
                }
                if bounds.upper().compare(&zero, &mut self.budget)?.is_lt() {
                    return Ok(Sign::Negative);
                }
            }
        }
        Ok(Sign::Indecisive)
    }
    fn value(&mut self, query: Query) -> Result<Option<Range>, Error> {
        let Precision::AbsoluteWidthBits(sequence) = &self.procedure.precision else {
            return Err(Error::Declaration);
        };
        let precision = *sequence.last().ok_or(Error::Declaration)?;
        self.request(query, precision)?
            .map(|b| interval(b.lower(), b.upper(), &mut self.budget))
            .transpose()
    }
    fn derivative(&mut self, point: &str) -> Result<Sign, Error> {
        let Some(beta) = self.value(formula::beta())? else {
            return Ok(Sign::Indecisive);
        };
        let Some(sigma) = self.value(formula::sigmoid(point))? else {
            return Ok(Sign::Indecisive);
        };
        let Some(t) = self.value(formula::tanh(point))? else {
            return Ok(Sign::Indecisive);
        };
        self.sign(&formula::derivative(point, vec![beta, sigma, t]))
    }
    fn complete(&self) -> Result<(), Error> {
        if self.supplied.is_some_and(|s| s.len() != self.queries.len()) {
            return Err(Error::Query);
        }
        Ok(())
    }
    fn concavity(&mut self, maximum_depth: u32) -> Result<Option<Vec<Range>>, Error> {
        let mut pending = vec![(
            Rational::parse("0", &mut self.budget)?,
            Rational::parse("1/2", &mut self.budget)?,
            0,
        )];
        let mut cells = Vec::new();
        while let Some((a, b, depth)) = pending.pop() {
            let cell = interval(&a, &b, &mut self.budget)?;
            let Some(beta) = self.value(formula::beta())? else {
                return Ok(None);
            };
            let Some(sa) = self.value(formula::sinhc(&cell.lower, false))? else {
                return Ok(None);
            };
            let Some(sb) = self.value(formula::sinhc(&cell.upper, false))? else {
                return Ok(None);
            };
            let Some(sp) = self.value(formula::sinhc(&cell.upper, true))? else {
                return Ok(None);
            };
            if self.sign(&formula::concavity(&cell.lower, &cell.upper, vec![sa, sb, sp, beta]))? == Sign::Negative {
                cells.push(cell);
                continue;
            }
            if depth >= maximum_depth {
                return Ok(None);
            }
            let middle = a
                .add(&b, &mut self.budget)?
                .div(&Rational::parse("2", &mut self.budget)?, &mut self.budget)?;
            pending.push((middle.clone(), b, depth + 1));
            pending.push((a, middle, depth + 1));
        }
        Ok(Some(cells))
    }
}

fn run(p: &Procedure, input: &Inputs, supplied: Option<&Record>) -> Result<Record, Error> {
    if supplied.is_some_and(|r| r.input != *input) {
        return Err(Error::Definition);
    }
    let mut run = Run::new(p, input, supplied.map(|r| r.queries.as_slice()))?;
    let mut result = Record {
        input: input.clone(),
        queries: Vec::new(),
        cells: Vec::new(),
        image: None,
        work: 0,
    };
    let mut established =
        run.sign(&formula::beta_bound())? == Sign::Negative && run.sign(&formula::initial_slope())? == Sign::Positive;
    if established {
        if let Some(cells) = run.concavity(input.maximum_depth)? {
            result.cells = cells;
        } else {
            established = false;
        }
    }
    if established {
        for (point, required) in [(&input.bracket.lower, Sign::Positive), (&input.bracket.upper, Sign::Negative)] {
            let sign = run.derivative(point)?;
            if sign == Sign::Indecisive {
                established = false;
                break;
            }
            if sign != required {
                return Err(Error::Bracket);
            }
        }
    }
    if established {
        let b = &mut run.budget;
        let one = Rational::parse("1", b)?;
        let a = Rational::parse(&input.bracket.lower, b)?;
        let z = Rational::parse(&input.bracket.upper, b)?;
        result.image = Some(interval(&a.div(&one.sub(&a, b)?, b)?, &z.div(&one.sub(&z, b)?, b)?, b)?);
    }
    run.complete()?;
    result.work = run.budget.usage().work;
    result.queries = run.queries;
    if supplied.is_some_and(|r| r.image != result.image || r.cells != result.cells) {
        return Err(Error::Record);
    }
    Ok(result)
}

/// Certify the defining ridge with endpoint signs and a complete concavity majorant cover.
/// (´[ROOT-alg:design:binding-ridge]´)
/// # Errors
/// Refuses defining changes, malformed declarations, wrong endpoint signs and operational faults.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::ridge::evaluate"
    ),
    ret
)]
pub fn evaluate(p: &Procedure, input: &Inputs) -> Result<Record, Error> {
    run(p, input, None)
}

/// Rebuild every defining query and coverage decision in a fresh independent budget.
/// (´[ROOT-alg:design:binding-ridge]´)
/// # Errors
/// Refuses substituted inputs, queries, attachments, coverage and images.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::ridge::replay"
    ),
    ret
)]
pub fn replay(p: &Procedure, input: &Inputs, record: &Record) -> Result<CheckedRidge, Error> {
    let checked = run(p, input, Some(record))?;
    Ok(CheckedRidge {
        procedure: p.clone(),
        input: input.clone(),
        image: checked.image,
    })
}

fn comparison(
    checked: &CheckedRidge,
    wall: &Wall,
    floor: Floor,
    supplied: Option<&ComparisonRecord>,
) -> Result<ComparisonRecord, Error> {
    if supplied.is_some_and(|r| r.wall != *wall || r.floor != floor) {
        return Err(Error::Query);
    }
    let mut run = Run::new(&checked.procedure, &checked.input, supplied.map(|r| r.queries.as_slice()))?;
    let verdict = if checked.image.is_none() {
        FloorComparison::Indecisive
    } else {
        match wall {
            Wall::DefiningRidge(d) => {
                definition(d)?;
                if *d != checked.input.definition {
                    return Err(Error::Definition);
                }
                if floor == Floor::RidgeImage {
                    FloorComparison::Equal
                } else {
                    FloorComparison::Below
                }
            }
            Wall::Rational(s) => {
                let b = &mut run.budget;
                let x = Rational::parse(s, b)?;
                if x.is_negative() {
                    return Err(Error::Declaration);
                }
                if floor == Floor::RationalThreeThirtySevenths {
                    match x.compare(&Rational::parse("3/37", b)?, b)? {
                        std::cmp::Ordering::Less => FloorComparison::Below,
                        std::cmp::Ordering::Equal => FloorComparison::Equal,
                        std::cmp::Ordering::Greater => FloorComparison::Above,
                    }
                } else if x.is_zero() {
                    FloorComparison::Below
                } else if !x.compare(&Rational::parse("1", b)?, b)?.is_lt() {
                    FloorComparison::Above
                } else {
                    let one = Rational::parse("1", b)?;
                    let p = x.div(&one.add(&x, b)?, b)?.exact_string(b)?;
                    match run.derivative(&p)? {
                        Sign::Positive => FloorComparison::Below,
                        Sign::Negative => FloorComparison::Above,
                        Sign::Indecisive => FloorComparison::Indecisive,
                    }
                }
            }
        }
    };
    run.complete()?;
    if supplied.is_some_and(|r| r.verdict != verdict) {
        return Err(Error::Record);
    }
    Ok(ComparisonRecord {
        wall: wall.clone(),
        floor,
        queries: run.queries,
        verdict,
        work: run.budget.usage().work,
    })
}

/// Compare against a checked exact defining object, without constructing a charged price.
/// (´[ROOT-alg:design:binding-ridge]´)
/// # Errors
/// Refuses invalid walls or defining inputs and operational faults; unresolved bounds remain indecisive.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::ridge::compare"
    ),
    ret
)]
pub fn compare(checked: &CheckedRidge, wall: &Wall, floor: Floor) -> Result<ComparisonRecord, Error> {
    comparison(checked, wall, floor, None)
}

/// Reconstruct the expected comparison and independently check each attempted attachment.
/// (´[ROOT-alg:design:binding-ridge]´)
/// # Errors
/// Refuses changed walls, floors, queries, attachments or asserted verdicts.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::ridge::replay_comparison"
    ),
    ret
)]
pub fn replay_comparison(
    checked: &CheckedRidge,
    wall: &Wall,
    floor: Floor,
    record: &ComparisonRecord,
) -> Result<ComparisonRecord, Error> {
    comparison(checked, wall, floor, Some(record))
}

// A controller may narrow the comparison allowance without changing the checked definition.
pub(super) fn compare_limited(
    checked: &CheckedRidge,
    wall: &Wall,
    floor: Floor,
    remaining_work: u64,
) -> Result<ComparisonRecord, Error> {
    let mut limited = checked.clone();
    limited.input.maximum_work = limited.input.maximum_work.min(remaining_work);
    comparison(&limited, wall, floor, None)
}

/// Independent records-layer charge verifier for the admitted clean ridge transcript.
/// (´[ROOT-rule:design:ridge-charge-contract]´)
#[derive(Debug)]
pub struct ChargeReplay;

impl pn_records::ridge::ChargeVerifier for ChargeReplay {
    #[tracing::instrument(
        name = "sig:design:graph",
        fields(
            execution_owner = "GRAPH",
            claim_owner = "ROOT",
            claim_label = "sig:design:graph",
            source_item = "numeric::ridge::<ChargeReplay as pn_records :: ridge :: ChargeVerifier>::replay"
        ),
        ret
    )]
    fn replay(&self, evidence: &pn_records::ridge::ChargeEvidence) -> Result<(), pn_records::numerics::NumericError> {
        use pn_records::numerics::NumericError;
        if evidence.analytic_premises != "clean-ridge-analytic-v1" {
            return Err(NumericError::RidgeDefinition);
        }
        replay(&evidence.procedure, &evidence.input, &evidence.record)
            .map(|_| ())
            .map_err(|error| match error {
                Error::Definition => NumericError::RidgeDefinition,
                Error::Numeric(super::Error::Backend(fault)) | Error::Arithmetic(fault) => NumericError::Backend(fault),
                Error::Operational { fault: Some(fault), .. } => NumericError::RetainedFault(fault),
                _ => NumericError::RidgeEvidence,
            })
    }
}
