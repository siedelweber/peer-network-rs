//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};
use pn_epoch::publication::disclosures as d;

structure!(d::TitleEvent {
    epoch,
    item,
    acts,
    buyer,
    seller,
    outcome
});
impl Wire for d::TitleOutcome {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Transferred => Ok(array([Value::Unsigned(0)])),
            Self::Conflict => Ok(array([Value::Unsigned(1)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Transferred,
            1 => Self::Conflict,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
