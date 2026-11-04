//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish};
use pn_epoch::publication::disclosures as d;

impl Wire for d::enclosure::EnclosureLaw {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::RationalInclusion => Ok(array([Value::Unsigned(0)])),
            Self::RootGrid => Ok(array([Value::Unsigned(1)])),
            Self::LogAtanh => Ok(array([Value::Unsigned(2)])),
            Self::ExpTaylor => Ok(array([Value::Unsigned(3)])),
            Self::SigmoidCompose => Ok(array([Value::Unsigned(4)])),
            Self::TanhCompose => Ok(array([Value::Unsigned(5)])),
            Self::PositivePower => Ok(array([Value::Unsigned(6)])),
            Self::SmoothDerivative => Ok(array([Value::Unsigned(7)])),
            Self::ClampGeneralized => Ok(array([Value::Unsigned(8)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::RationalInclusion,
            1 => Self::RootGrid,
            2 => Self::LogAtanh,
            3 => Self::ExpTaylor,
            4 => Self::SigmoidCompose,
            5 => Self::TanhCompose,
            6 => Self::PositivePower,
            7 => Self::SmoothDerivative,
            8 => Self::ClampGeneralized,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
