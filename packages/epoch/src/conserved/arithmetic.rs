//! Exact endpoint compositions and deterministic rational rounding.
//! (´[ROOT-alg:design:transport]´)
use super::Error;
use nrz_cas::{Rational, enclosure::Interval, limits::Budget};

pub(super) fn singleton(value: &str, b: &mut Budget) -> Result<Interval, Error> {
    Ok(Interval::singleton(&Rational::parse(value, b)?, b)?)
}
pub(super) fn multiply(a: &Interval, c: &Interval, b: &mut Budget) -> Result<Interval, Error> {
    if a.lower().is_negative() || c.lower().is_negative() {
        return Err(Error::Map);
    }
    Ok(Interval::new(a.lower().mul(c.lower(), b)?, a.upper().mul(c.upper(), b)?, b)?)
}
