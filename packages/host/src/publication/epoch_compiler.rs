//! Explicit field and variant mapping for the test publication theory.
use super::scalars::ExactText;
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish};

impl Wire for pn_epoch::compiler::CoefficientEvidence {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Exact(v0) => Ok(array([Value::Unsigned(0), v0.write_exact(c)?])),
            Self::Irrational { radicand } => Ok(array([Value::Unsigned(1), radicand.write_exact(c)?])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Exact(String::read_exact(fields.next().ok_or(Error::Shape)?, c)?),
            1 => Self::Irrational {
                radicand: String::read_exact(fields.next().ok_or(Error::Shape)?, c)?,
            },
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
