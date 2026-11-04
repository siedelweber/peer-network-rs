//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};
use pn_epoch::publication::disclosures as d;

structure!(d::enclosure::RefinementPolicy {
    version,
    precision,
    grid_ceiling,
    rounds,
    reduction_ceiling,
    term_ceiling,
    checking_work
});
impl Wire for d::enclosure::UndecidedReason {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Straddle => Ok(array([Value::Unsigned(0)])),
            Self::WidthLimit => Ok(array([Value::Unsigned(1)])),
            Self::WorkExhausted => Ok(array([Value::Unsigned(2)])),
            Self::DomainBoundary => Ok(array([Value::Unsigned(3)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Straddle,
            1 => Self::WidthLimit,
            2 => Self::WorkExhausted,
            3 => Self::DomainBoundary,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(d::enclosure::EnclosureCertificate {
    law,
    version,
    scope,
    grid,
    presentation,
    records,
    logarithms,
    exponentials,
    powers,
    derivatives
});
