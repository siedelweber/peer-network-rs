//! Explicit field and variant mapping for the test publication theory.
use super::scalars::ExactText;
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_records::ridge::Definition {
    schema,
    inverse_temperature,
    bleed_squared: exact,
    core_power: exact
});
structure!(pn_records::ridge::Inputs {
    definition,
    bracket,
    maximum_depth,
    maximum_work,
    maximum_replay_work
});
structure!(pn_records::ridge::Record {
    input,
    queries,
    cells,
    image,
    work
});
impl Wire for pn_records::ridge::Wall {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Rational(v0) => Ok(array([Value::Unsigned(0), v0.write_exact(c)?])),
            Self::DefiningRidge(v0) => Ok(array([Value::Unsigned(1), v0.write(c)?])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Rational(String::read_exact(fields.next().ok_or(Error::Shape)?, c)?),
            1 => Self::DefiningRidge(take(&mut fields, c)?),
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::ridge::ComparisonRecord {
    wall,
    floor,
    queries,
    verdict,
    work
});
structure!(pn_records::ridge::ChargeEvidence {
    analytic_premises,
    procedure,
    input,
    record
});
