//! Certified canonical controller composition over the admitted scalar fragment.
//! (´[ROOT-alg:design:production-wall-controller]´)

use super::ridge::CheckedRidge;
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    controller::{Attempt, Branches, Delivery, Inputs, Record, Relation, Stage, Verdict},
    numerics::{Floor, FloorComparison},
    primitive::Range,
    ridge::Wall,
    solve::{Precision, Procedure},
};

/// Invalid declarations and evidence do not acquire mathematical verdicts.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid canonical controller declaration")]
    Declaration,
    #[error("controller Work allowance exhausted")]
    Work,
    #[error("controller replay input or evidence mismatch")]
    Evidence,
    #[error("controller exact arithmetic stopped: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
    #[error("inverse evidence: {0}")]
    Inverse(#[from] super::wall::Error),
    #[error("ridge evidence: {0}")]
    Ridge(#[from] super::ridge::Error),
    #[error("controller primitive declaration: {0}")]
    Numeric(#[from] super::Error),
}

type Pair = (Rational, Rational);
fn rat(x: &str, b: &mut Budget) -> Result<Rational, Error> {
    Ok(Rational::parse(x, b)?)
}
fn point(x: &Rational) -> Pair {
    (x.clone(), x.clone())
}
fn endpoints(x: &Range, b: &mut Budget) -> Result<Pair, Error> {
    Ok((rat(&x.lower, b)?, rat(&x.upper, b)?))
}
fn range(x: &Pair, b: &mut Budget) -> Result<Range, Error> {
    Ok(Range {
        lower: x.0.exact_string(b)?,
        upper: x.1.exact_string(b)?,
    })
}
fn relation(x: &Pair, y: &Rational, b: &mut Budget) -> Result<Relation, Error> {
    Ok(if x.1.compare(y, b)?.is_lt() {
        Relation::Below
    } else if x.0.compare(y, b)?.is_gt() {
        Relation::Above
    } else if x.0 == *y && x.1 == *y {
        Relation::Equal
    } else {
        Relation::Indecisive
    })
}
fn magnitude(x: &Pair, b: &mut Budget) -> Result<Pair, Error> {
    let zero = rat("0", b)?;
    if !x.0.is_negative() {
        return Ok(x.clone());
    }
    if !x.1.compare(&zero, b)?.is_gt() {
        return Ok((zero.sub(&x.1, b)?, zero.sub(&x.0, b)?));
    }
    let neg = zero.sub(&x.0, b)?;
    Ok((zero, if neg.compare(&x.1, b)?.is_gt() { neg } else { x.1.clone() }))
}
fn minimum(x: &Rational, y: &Rational, b: &mut Budget) -> Result<Rational, Error> {
    Ok(if x.compare(y, b)?.is_lt() { x.clone() } else { y.clone() })
}

struct Run<'a> {
    p: &'a Procedure,
    input: &'a Inputs,
    ridge: Option<&'a CheckedRidge>,
    b: Budget,
    spent: u64,
    ceiling: u64,
}
impl Run<'_> {
    fn floor_check(&mut self, x: &Rational, a: &mut Attempt) -> Result<Relation, Error> {
        if self.input.floor == Floor::RationalThreeThirtySevenths {
            return relation(&point(x), &rat("3/37", &mut self.b)?, &mut self.b);
        }
        let checked = self.ridge.ok_or(Error::Declaration)?;
        let remaining = self
            .ceiling
            .checked_sub(self.spent)
            .and_then(|n| n.checked_sub(self.b.usage().work))
            .filter(|n| *n > 0)
            .ok_or(Error::Work)?;
        let record = super::ridge::compare_limited(
            checked,
            &Wall::Rational(x.exact_string(&mut self.b)?),
            self.input.floor,
            remaining,
        )?;
        self.spent = self.spent.checked_add(record.work).ok_or(Error::Work)?;
        let result = match record.verdict {
            FloorComparison::Below => Relation::Below,
            FloorComparison::Equal => Relation::Equal,
            FloorComparison::Above => Relation::Above,
            FloorComparison::Indecisive => Relation::Indecisive,
        };
        a.floor_checks.push(record);
        Ok(result)
    }
    fn floor(&mut self) -> Result<Pair, Error> {
        match self.input.floor {
            Floor::RationalThreeThirtySevenths => Ok(point(&rat("3/37", &mut self.b)?)),
            Floor::RidgeImage => endpoints(
                self.ridge.and_then(CheckedRidge::image).ok_or(Error::Declaration)?,
                &mut self.b,
            ),
        }
    }
    fn validate(&mut self) -> Result<(), Error> {
        super::preflight(self.p)?;
        let budget = &mut self.b;
        let zero = rat("0", budget)?;
        let one = rat("1", budget)?;
        for x in [
            &self.input.previous,
            &self.input.cumulative_tilt,
            &self.input.bleed_squared,
            &self.input.absolute_cap,
        ] {
            if !rat(x, budget)?.compare(&zero, budget)?.is_gt() {
                return Err(Error::Declaration);
            }
        }
        let width = rat(&self.input.width, budget)?;
        let rung = rat(&self.input.accepted_rung, budget)?;
        let relative = rat(&self.input.relative_cap, budget)?;
        let deadband = rat(&self.input.deadband, budget)?;
        if width.is_negative()
            || (self.input.empty_live_domain && !width.is_zero())
            || rung.is_negative()
            || rung.compare(&one, budget)?.is_gt()
            || !relative.compare(&zero, budget)?.is_gt()
            || !relative.compare(&one, budget)?.is_lt()
            || deadband.is_negative()
            || !deadband.compare(&one, budget)?.is_lt()
            || self.input.maximum_steps == 0
            || self.input.maximum_work == 0
            || self.input.maximum_replay_work == 0
        {
            return Err(Error::Declaration);
        }
        if let Delivery::Grid { quantum, maximum_error } = &self.input.delivery {
            let quantum_value = rat(quantum, budget)?;
            let error_limit = rat(maximum_error, budget)?;
            if !quantum_value.compare(&zero, budget)?.is_gt()
                || error_limit.compare(&quantum_value, budget)?.is_lt()
                || !rat(&self.input.previous, budget)?.div(&quantum_value, budget)?.is_integer()
            {
                return Err(Error::Declaration);
            }
        }
        Ok(())
    }
    fn attempt(&mut self, bits: u32, index: usize, supplied: Option<&Attempt>) -> Result<Attempt, Error> {
        let mut a = Attempt {
            precision: bits,
            stopped_at: None,
            inverse: None,
            floor_checks: Vec::new(),
            branches: None,
            delivered: None,
            delivery_error: None,
        };
        let previous = rat(&self.input.previous, &mut self.b)?;
        match self.floor_check(&previous, &mut a)? {
            Relation::Below => return Err(Error::Declaration),
            Relation::Indecisive => {
                a.stopped_at = Some(Stage::Floor);
                return Ok(a);
            }
            _ => {}
        }
        let floor = self.floor()?;
        let zero_width = rat(&self.input.width, &mut self.b)?.is_zero();
        let (proposal, floor_relation) = if zero_width {
            (floor, Relation::Equal)
        } else {
            let mut p = self.p.clone();
            p.precision = Precision::AbsoluteWidthBits(vec![bits]);
            p.enclosure.as_mut().ok_or(Error::Declaration)?.refinement.precision = bits;
            let mut stopping = rat(&self.input.stopping_width, &mut self.b)?;
            let two = rat("2", &mut self.b)?;
            for _ in 0..index {
                stopping = stopping.div(&two, &mut self.b)?;
            }
            let remaining = self
                .ceiling
                .checked_sub(self.spent)
                .and_then(|n| n.checked_sub(self.b.usage().work))
                .filter(|n| *n > 0)
                .ok_or(Error::Work)?;
            let input = pn_records::wall::Inputs {
                width: self.input.width.clone(),
                cumulative_tilt: self.input.cumulative_tilt.clone(),
                bracket: self.input.bracket.clone(),
                stopping_width: stopping.exact_string(&mut self.b)?,
                maximum_steps: self.input.maximum_steps,
                maximum_work: remaining,
                maximum_replay_work: remaining,
                // Inversion does not consume these reference-only branch fields.
                floor: pn_records::wall::Floor::Rational,
                previous: pn_records::wall::Previous::Target,
                door: "1".into(),
                absolute_cap: self.input.absolute_cap.clone(),
                relative_cap: self.input.relative_cap.clone(),
                deadband: self.input.deadband.clone(),
            };
            let inverse = super::wall::inverse(
                &p,
                &input,
                &self.input.bleed_squared,
                supplied.and_then(|s| s.inverse.as_ref()),
            )?;
            self.spent = self.spent.checked_add(inverse.work).ok_or(Error::Work)?;
            let target = inverse.target.clone();
            a.inverse = Some(inverse);
            let Some(target) = target else {
                a.stopped_at = Some(Stage::InverseGain);
                return Ok(a);
            };
            let target = endpoints(&target, &mut self.b)?;
            let lo = self.floor_check(&target.0, &mut a)?;
            let hi = self.floor_check(&target.1, &mut a)?;
            if matches!(hi, Relation::Below | Relation::Equal) {
                // The certified inverse bracket is strict at both endpoints.
                (floor, Relation::Below)
            } else if matches!(lo, Relation::Above | Relation::Equal) {
                (target, Relation::Above)
            } else {
                a.stopped_at = Some(Stage::Floor);
                return Ok(a);
            }
        };
        let Some(branches) = self.branches(zero_width, floor_relation, &proposal, &previous, &mut a.stopped_at)? else {
            return Ok(a);
        };
        let ideal = endpoints(&branches.ideal, &mut self.b)?;
        a.branches = Some(branches);
        a.delivered = self.deliver(&ideal, &previous, &mut a)?;
        if a.delivered.is_none() && a.stopped_at.is_none() {
            a.stopped_at = Some(Stage::Delivery);
        }
        Ok(a)
    }
    fn branches(
        &mut self,
        zero_width: bool,
        floor: Relation,
        proposal: &Pair,
        previous: &Rational,
        stopped_at: &mut Option<Stage>,
    ) -> Result<Option<Branches>, Error> {
        let b = &mut self.b;
        let zero = rat("0", b)?;
        let e = (proposal.0.sub(previous, b)?, proposal.1.sub(previous, b)?);
        let distance = magnitude(&e, b)?;
        let deadband = relation(&distance, &rat(&self.input.deadband, b)?.mul(previous, b)?, b)?;
        let direction = relation(&e, &zero, b)?;
        let abs = rat(&self.input.absolute_cap, b)?;
        let rel = rat(&self.input.relative_cap, b)?.mul(previous, b)?;
        let absolute_cap = relation(&distance, &abs, b)?;
        let relative_cap = relation(&distance, &rel, b)?;
        let ideal = match deadband {
            Relation::Below | Relation::Equal => point(previous),
            Relation::Indecisive => {
                *stopped_at = Some(Stage::Deadband);
                return Ok(None);
            }
            Relation::Above => {
                if direction == Relation::Indecisive
                    || absolute_cap == Relation::Indecisive
                    || relative_cap == Relation::Indecisive
                {
                    *stopped_at = Some(Stage::StepCap);
                    return Ok(None);
                }
                let cap = minimum(&abs, &rel, b)?;
                if matches!(relation(&distance, &cap, b)?, Relation::Above | Relation::Equal) {
                    point(&if direction == Relation::Below {
                        previous.sub(&cap, b)?
                    } else {
                        previous.add(&cap, b)?
                    })
                } else {
                    proposal.clone()
                }
            }
        };
        Ok(Some(Branches {
            zero_width,
            floor,
            deadband,
            absolute_cap,
            relative_cap,
            direction,
            proposal: range(proposal, b)?,
            ideal: range(&ideal, b)?,
        }))
    }
}

fn grid_index(x: &Rational, q: &Rational, b: &mut Budget) -> Result<u64, Error> {
    let mut lo = 0_u64;
    let mut hi = 1_u64;
    while rat(&hi.to_string(), b)?.mul(q, b)?.compare(x, b)?.is_le() {
        lo = hi;
        hi = hi.checked_mul(2).ok_or(Error::Declaration)?;
    }
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if rat(&mid.to_string(), b)?.mul(q, b)?.compare(x, b)?.is_le() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}
fn grid_point(i: u64, q: &Rational, b: &mut Budget) -> Result<Rational, Error> {
    Ok(rat(&i.to_string(), b)?.mul(q, b)?)
}
fn ceil_grid(x: &Rational, q: &Rational, b: &mut Budget) -> Result<u64, Error> {
    let i = grid_index(x, q, b)?;
    Ok(if grid_point(i, q, b)? == *x {
        i
    } else {
        i.checked_add(1).ok_or(Error::Declaration)?
    })
}
fn nearest(
    target: &Rational,
    quantum: &Rational,
    first: u64,
    last: u64,
    previous: &Rational,
    budget: &mut Budget,
) -> Result<u64, Error> {
    let lower_index = grid_index(target, quantum, budget)?;
    let upper_index = lower_index.checked_add(1).ok_or(Error::Declaration)?;
    let lower_index = lower_index.clamp(first, last);
    let upper_index = upper_index.clamp(first, last);
    let lower = grid_point(lower_index, quantum, budget)?;
    let upper = grid_point(upper_index, quantum, budget)?;
    let lower_distance = magnitude(&point(&lower.sub(target, budget)?), budget)?.0;
    let upper_distance = magnitude(&point(&upper.sub(target, budget)?), budget)?.0;
    Ok(match lower_distance.compare(&upper_distance, budget)? {
        std::cmp::Ordering::Less => lower_index,
        std::cmp::Ordering::Greater => upper_index,
        std::cmp::Ordering::Equal => {
            let lower_step = magnitude(&point(&lower.sub(previous, budget)?), budget)?.0;
            let upper_step = magnitude(&point(&upper.sub(previous, budget)?), budget)?.0;
            if lower_step.compare(&upper_step, budget)?.is_le() {
                lower_index
            } else {
                upper_index
            }
        }
    })
}
impl Run<'_> {
    fn deliver(&mut self, ideal: &Pair, previous: &Rational, a: &mut Attempt) -> Result<Option<String>, Error> {
        let Delivery::Grid { quantum, maximum_error } = &self.input.delivery else {
            if ideal.0 != ideal.1 {
                return Ok(None);
            }
            if !matches!(self.floor_check(&ideal.0, a)?, Relation::Above | Relation::Equal) {
                a.stopped_at = Some(Stage::Floor);
                return Ok(None);
            }
            let zero = rat("0", &mut self.b)?;
            a.delivery_error = Some(range(&point(&zero), &mut self.b)?);
            return Ok(Some(ideal.0.exact_string(&mut self.b)?));
        };
        let quantum = quantum.clone();
        let maximum_error = maximum_error.clone();
        let b = &mut self.b;
        let q = rat(&quantum, b)?;
        let cap = minimum(
            &rat(&self.input.absolute_cap, b)?,
            &rat(&self.input.relative_cap, b)?.mul(previous, b)?,
            b,
        )?;
        let lower = previous.sub(&cap, b)?;
        let upper = previous.add(&cap, b)?;
        let cap_first = ceil_grid(&lower, &q, b)?;
        let last = grid_index(&upper, &q, b)?;
        let floor = self.floor()?;
        let mut first = cap_first.max(ceil_grid(&floor.1, &q, &mut self.b)?);
        while first > cap_first {
            let x = grid_point(first - 1, &q, &mut self.b)?;
            match self.floor_check(&x, a)? {
                Relation::Above | Relation::Equal => first -= 1,
                Relation::Below => break,
                Relation::Indecisive => {
                    a.stopped_at = Some(Stage::Floor);
                    return Ok(None);
                }
            }
        }
        if first > last {
            return Err(Error::Declaration);
        }
        let left = nearest(&ideal.0, &q, first, last, previous, &mut self.b)?;
        let right = nearest(&ideal.1, &q, first, last, previous, &mut self.b)?;
        if left != right {
            return Ok(None);
        }
        let selected = grid_point(left, &q, &mut self.b)?;
        if !matches!(self.floor_check(&selected, a)?, Relation::Above | Relation::Equal) {
            a.stopped_at = Some(Stage::Floor);
            return Ok(None);
        }
        let error = magnitude(
            &(ideal.0.sub(&selected, &mut self.b)?, ideal.1.sub(&selected, &mut self.b)?),
            &mut self.b,
        )?;
        let limit = rat(&maximum_error, &mut self.b)?;
        if error.1.compare(&limit, &mut self.b)?.is_gt() {
            return Ok(None);
        }
        a.delivery_error = Some(range(&error, &mut self.b)?);
        Ok(Some(selected.exact_string(&mut self.b)?))
    }
}

fn run(p: &Procedure, input: &Inputs, ridge: Option<&CheckedRidge>, supplied: Option<&Record>) -> Result<Record, Error> {
    if supplied.is_some_and(|r| r.inputs != *input || r.procedure != *p) {
        return Err(Error::Evidence);
    }
    let mut limits = p.enclosure.as_ref().ok_or(Error::Declaration)?.operation.clone();
    let ceiling = if supplied.is_some() {
        input.maximum_replay_work
    } else {
        input.maximum_work
    };
    limits.work = limits.work.min(ceiling);
    let mut run = Run {
        p,
        input,
        ridge,
        b: Budget::new(limits)?,
        spent: 0,
        ceiling,
    };
    run.validate()?;
    let Precision::AbsoluteWidthBits(sequence) = &p.precision else {
        return Err(Error::Declaration);
    };
    let mut result = Record {
        procedure: p.clone(),
        inputs: input.clone(),
        attempts: Vec::new(),
        verdict: Verdict::Indecisive,
    };
    for (index, bits) in sequence.iter().enumerate() {
        let expected = supplied.map(|r| r.attempts.get(index).ok_or(Error::Evidence)).transpose()?;
        let attempt = run.attempt(*bits, index, expected)?;
        if expected.is_some_and(|e| e != &attempt) {
            return Err(Error::Evidence);
        }
        let delivered = attempt.delivered.is_some();
        result.attempts.push(attempt);
        if delivered {
            result.verdict = Verdict::Delivered;
            break;
        }
    }
    if result.verdict == Verdict::Indecisive
        && matches!(input.delivery, Delivery::ExactRational)
        && result
            .attempts
            .last()
            .is_some_and(|a| a.branches.as_ref().is_some_and(|b| b.ideal.lower != b.ideal.upper))
    {
        result.verdict = Verdict::DeliveryRefused;
    }
    if run.spent.checked_add(run.b.usage().work).is_none_or(|n| n > ceiling) {
        return Err(Error::Work);
    }
    if supplied.is_some_and(|r| r != &result) {
        return Err(Error::Evidence);
    }
    Ok(result)
}

/// Retain the mathematical proposal and certify the independently deliverable rational wall.
/// (´[ROOT-alg:design:production-wall-controller]´)
/// # Errors
/// Refuses malformed declarations, altered defining evidence and bounded operational failures.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::controller::evaluate"
    ),
    ret
)]
pub fn evaluate(p: &Procedure, input: &Inputs, ridge: Option<&CheckedRidge>) -> Result<Record, Error> {
    run(p, input, ridge, None)
}

/// Independently reconstruct every inverse query, branch and grid selection from the inputs.
/// (´[ROOT-alg:design:production-wall-controller]´)
/// # Errors
/// Refuses changed inputs, primitive attachments and derived branch or delivery evidence.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::controller::replay"
    ),
    ret
)]
pub fn replay(p: &Procedure, input: &Inputs, ridge: Option<&CheckedRidge>, record: &Record) -> Result<Record, Error> {
    run(p, input, ridge, Some(record))
}
