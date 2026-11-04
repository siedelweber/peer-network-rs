//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};
use pn_epoch::publication::disclosures as d;

impl Wire for d::enclosure::PowerRoute {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Integer => Ok(array([Value::Unsigned(0)])),
            Self::Dyadic => Ok(array([Value::Unsigned(1)])),
            Self::LogExp => Ok(array([Value::Unsigned(2)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Integer,
            1 => Self::Dyadic,
            2 => Self::LogExp,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(d::enclosure::PowerEvidence {
    record,
    route,
    roots,
    logarithm
});
