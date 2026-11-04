//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, newtype};

newtype!(pn_records::numerics::ActionCount);
impl Wire for pn_records::numerics::Floor {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::RationalThreeThirtySevenths => Ok(array([Value::Unsigned(0)])),
            Self::RidgeImage => Ok(array([Value::Unsigned(1)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::RationalThreeThirtySevenths,
            1 => Self::RidgeImage,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::numerics::FloorComparison {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Below => Ok(array([Value::Unsigned(0)])),
            Self::Equal => Ok(array([Value::Unsigned(1)])),
            Self::Above => Ok(array([Value::Unsigned(2)])),
            Self::Indecisive => Ok(array([Value::Unsigned(3)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Below,
            1 => Self::Equal,
            2 => Self::Above,
            3 => Self::Indecisive,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
