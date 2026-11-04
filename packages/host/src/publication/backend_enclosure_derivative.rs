//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};
use pn_epoch::publication::disclosures as d;

impl Wire for d::enclosure::DerivativeRule {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Constant => Ok(array([Value::Unsigned(0)])),
            Self::Coordinate => Ok(array([Value::Unsigned(1)])),
            Self::Parameter => Ok(array([Value::Unsigned(2)])),
            Self::Negate => Ok(array([Value::Unsigned(3)])),
            Self::Sum => Ok(array([Value::Unsigned(4)])),
            Self::Difference => Ok(array([Value::Unsigned(5)])),
            Self::Product => Ok(array([Value::Unsigned(6)])),
            Self::Quotient => Ok(array([Value::Unsigned(7)])),
            Self::Exponential => Ok(array([Value::Unsigned(8)])),
            Self::Logarithm => Ok(array([Value::Unsigned(9)])),
            Self::Sigmoid => Ok(array([Value::Unsigned(10)])),
            Self::Tanh => Ok(array([Value::Unsigned(11)])),
            Self::Power => Ok(array([Value::Unsigned(12)])),
            Self::Root => Ok(array([Value::Unsigned(13)])),
            Self::ClampConstant => Ok(array([Value::Unsigned(14)])),
            Self::ClampResponsive => Ok(array([Value::Unsigned(15)])),
            Self::ClampJoin => Ok(array([Value::Unsigned(16)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Constant,
            1 => Self::Coordinate,
            2 => Self::Parameter,
            3 => Self::Negate,
            4 => Self::Sum,
            5 => Self::Difference,
            6 => Self::Product,
            7 => Self::Quotient,
            8 => Self::Exponential,
            9 => Self::Logarithm,
            10 => Self::Sigmoid,
            11 => Self::Tanh,
            12 => Self::Power,
            13 => Self::Root,
            14 => Self::ClampConstant,
            15 => Self::ClampResponsive,
            16 => Self::ClampJoin,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(d::enclosure::DerivativeStep { rule, bound });
structure!(d::enclosure::DerivativeEvidence {
    record,
    first,
    coordinate,
    steps
});
