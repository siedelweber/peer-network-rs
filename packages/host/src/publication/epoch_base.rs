//! Explicit field and variant mapping for the test publication theory.
use super::scalars::ExactText;
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::base::HeldCoefficient {
    cell,
    radicand: exact,
    domain_factor: exact
});
impl Wire for pn_epoch::base::BaseScore {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Exact(v0) => Ok(array([Value::Unsigned(0), v0.write_exact(c)?])),
            Self::Held { exact_part, terms } => Ok(array([Value::Unsigned(1), exact_part.write_exact(c)?, terms.write(c)?])),
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
            1 => Self::Held {
                exact_part: String::read_exact(fields.next().ok_or(Error::Shape)?, c)?,
                terms: take(&mut fields, c)?,
            },
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_epoch::base::BaseEntry { score, cells });
structure!(pn_epoch::base::BaseAllocation { boundary, edition, rows });
