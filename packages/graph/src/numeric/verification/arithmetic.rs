//! Charged signed interval arithmetic with a declared outward dyadic grid.
//! (´[ROOT-rule:design:refinement]´)
use super::Error;
use nrz_cas::{Rational, enclosure::Interval, limits::Budget};
use pn_records::primitive::Range;

pub(super) struct Arithmetic {
    pub budget: Budget,
    pub bits: u32,
}
impl Arithmetic {
    pub(super) fn scalar(&mut self, s: &str) -> Result<Interval, Error> {
        Ok(Interval::singleton(&Rational::parse(s, &mut self.budget)?, &mut self.budget)?)
    }
    pub(super) fn range(&mut self, r: &Range) -> Result<Interval, Error> {
        Ok(Interval::new(
            Rational::parse(&r.lower, &mut self.budget)?,
            Rational::parse(&r.upper, &mut self.budget)?,
            &mut self.budget,
        )?)
    }
    pub(super) fn encode(&mut self, r: &Interval) -> Result<Range, Error> {
        Ok(Range {
            lower: r.lower().exact_string(&mut self.budget)?,
            upper: r.upper().exact_string(&mut self.budget)?,
        })
    }
    fn result(&mut self, lo: Rational, hi: Rational) -> Result<Interval, Error> {
        Ok(Interval::new(lo, hi, &mut self.budget)?.coarsen(self.bits, &mut self.budget)?)
    }
    pub(super) fn add(&mut self, a: &Interval, b: &Interval) -> Result<Interval, Error> {
        let lo = a.lower().add(b.lower(), &mut self.budget)?;
        let hi = a.upper().add(b.upper(), &mut self.budget)?;
        self.result(lo, hi)
    }
    pub(super) fn sub(&mut self, a: &Interval, b: &Interval) -> Result<Interval, Error> {
        let lo = a.lower().sub(b.upper(), &mut self.budget)?;
        let hi = a.upper().sub(b.lower(), &mut self.budget)?;
        self.result(lo, hi)
    }
    pub(super) fn mul(&mut self, a: &Interval, b: &Interval) -> Result<Interval, Error> {
        let mut products = Vec::new();
        for x in [a.lower(), a.upper()] {
            for y in [b.lower(), b.upper()] {
                products.push(x.mul(y, &mut self.budget)?);
            }
        }
        let mut lo = products[0].clone();
        let mut hi = lo.clone();
        for value in products {
            if value.compare(&lo, &mut self.budget)?.is_lt() {
                lo = value.clone();
            }
            if value.compare(&hi, &mut self.budget)?.is_gt() {
                hi = value;
            }
        }
        self.result(lo, hi)
    }
    pub(super) fn div(&mut self, a: &Interval, b: &Interval) -> Result<Interval, Error> {
        if b.lower().is_negative() || b.lower().is_zero() {
            return Err(Error::Declaration);
        }
        let one = Rational::parse("1", &mut self.budget)?;
        let reciprocal = Interval::new(
            one.div(b.upper(), &mut self.budget)?,
            one.div(b.lower(), &mut self.budget)?,
            &mut self.budget,
        )?;
        self.mul(a, &reciprocal)
    }
}
pub(super) fn magnitude(a: &Interval, b: &mut Budget) -> Result<Rational, Error> {
    let lo = if a.lower().is_negative() {
        a.lower().negated(b)?
    } else {
        a.lower().clone()
    };
    let hi = if a.upper().is_negative() {
        a.upper().negated(b)?
    } else {
        a.upper().clone()
    };
    Ok(if lo.compare(&hi, b)?.is_gt() { lo } else { hi })
}
