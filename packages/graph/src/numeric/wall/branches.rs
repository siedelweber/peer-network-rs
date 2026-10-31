//! Outward decisions for the reference controller, without an exact-price substitution.
//! (´[ROOT-rule:design:reference-wall-branches]´)

use super::{Error, positive, range};
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    primitive::Range,
    wall::{Branches, Floor, Inputs, Participation, Previous, Verdict},
};

pub(super) fn validate(input: &Inputs, b: &mut Budget) -> Result<(), Error> {
    positive(&input.door, b)?;
    positive(&input.absolute_cap, b)?;
    let one = Rational::parse("1", b)?;
    let relative = positive(&input.relative_cap, b)?;
    let band = Rational::parse(&input.deadband, b)?;
    if !relative.compare(&one, b)?.is_lt() || band.is_negative() || !band.compare(&one, b)?.is_lt() {
        return Err(Error::Declaration);
    }
    if let Previous::Rational(previous) = &input.previous {
        let previous = positive(previous, b)?;
        if previous.compare(&Rational::parse("3/37", b)?, b)?.is_lt() {
            return Err(Error::Declaration);
        }
    }
    Ok(())
}

fn verdict(lower: &Rational, upper: &Rational, bound: &Rational, b: &mut Budget) -> Result<Verdict, Error> {
    Ok(if !lower.compare(bound, b)?.is_lt() {
        Verdict::Pass
    } else if upper.compare(bound, b)?.is_lt() {
        Verdict::Fail
    } else {
        Verdict::Indecisive
    })
}

fn magnitude(lower: &Rational, upper: &Rational, b: &mut Budget) -> Result<(Rational, Rational), Error> {
    let zero = Rational::parse("0", b)?;
    if !lower.is_negative() {
        return Ok((lower.clone(), upper.clone()));
    }
    let minus_lower = zero.sub(lower, b)?;
    if !upper.compare(&zero, b)?.is_gt() {
        return Ok((zero.sub(upper, b)?, minus_lower));
    }
    let maximum = if minus_lower.compare(upper, b)?.is_gt() {
        minus_lower
    } else {
        upper.clone()
    };
    Ok((zero, maximum))
}

fn delivered(input: &Inputs, proposal: &Range, identity: bool, b: &mut Budget) -> Result<Option<(Range, bool, bool)>, Error> {
    if identity {
        return Ok(Some((proposal.clone(), true, false)));
    }
    let Previous::Rational(previous) = &input.previous else {
        return Ok(None);
    };
    let previous = Rational::parse(previous, b)?;
    let lower = Rational::parse(&proposal.lower, b)?.sub(&previous, b)?;
    let upper = Rational::parse(&proposal.upper, b)?.sub(&previous, b)?;
    let (distance_lower, distance_upper) = magnitude(&lower, &upper, b)?;
    let band = Rational::parse(&input.deadband, b)?.mul(&previous, b)?;
    if !distance_upper.compare(&band, b)?.is_gt() {
        return Ok(Some((range(&previous, &previous, b)?, true, false)));
    }
    if !distance_lower.compare(&band, b)?.is_gt() {
        return Ok(None);
    }
    let absolute = Rational::parse(&input.absolute_cap, b)?;
    let relative = Rational::parse(&input.relative_cap, b)?.mul(&previous, b)?;
    let cap = if absolute.compare(&relative, b)?.is_lt() {
        absolute
    } else {
        relative
    };
    if !distance_upper.compare(&cap, b)?.is_gt() {
        return Ok(Some((proposal.clone(), false, false)));
    }
    if distance_lower.compare(&cap, b)?.is_lt() {
        return Ok(None);
    }
    let value = if upper.is_negative() {
        previous.sub(&cap, b)?
    } else {
        previous.add(&cap, b)?
    };
    Ok(Some((range(&value, &value, b)?, false, true)))
}

pub(super) fn evaluate(input: &Inputs, target: Option<&Range>, b: &mut Budget) -> Result<Option<Branches>, Error> {
    let floor = Rational::parse("3/37", b)?;
    let (proposal, floor_binding) = if let Some(target) = target {
        let lower = Rational::parse(&target.lower, b)?;
        let upper = Rational::parse(&target.upper, b)?;
        if lower.compare(&floor, b)?.is_gt() {
            (target.clone(), false)
        } else if input.floor == Floor::Ridge {
            return Err(Error::Ridge);
        } else if !upper.compare(&floor, b)?.is_gt() {
            (range(&floor, &floor, b)?, true)
        } else {
            return Ok(None);
        }
    } else {
        if input.floor == Floor::Ridge {
            return Err(Error::Ridge);
        }
        (range(&floor, &floor, b)?, true)
    };
    let identity = matches!(input.previous, Previous::Target) && target.is_some() && !floor_binding;
    let Some((delivered, deadband_hold, step_capped)) = delivered(input, &proposal, identity, b)? else {
        return Ok(None);
    };
    let lower = Rational::parse(&delivered.lower, b)?;
    let upper = Rational::parse(&delivered.upper, b)?;
    let above_floor = verdict(&lower, &upper, &floor, b)?;
    let door = Rational::parse(&input.door, b)?;
    let policy_valid = verdict(&door.sub(&upper, b)?, &door.sub(&lower, b)?, &Rational::parse("0", b)?, b)?;
    Ok(Some(Branches {
        floor_binding,
        deadband_hold,
        step_capped,
        above_floor,
        policy_valid,
        participation: match policy_valid {
            Verdict::Pass => Participation::Door,
            Verdict::Fail => Participation::Wall,
            Verdict::Indecisive => Participation::Indecisive,
        },
        proposal,
        delivered,
    }))
}
