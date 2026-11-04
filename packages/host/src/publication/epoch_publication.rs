//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::publication::Causes {
    acts,
    names,
    declarations,
    editions
});
structure!(pn_epoch::publication::RealizationEvidence {
    edition,
    provenance,
    capacity_bound,
    dimensioned_unit_cost,
    recording_event_costs,
    settlement_and_finality,
    operator
});
impl Wire for pn_epoch::publication::OperatorEvidence {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Bound { bound, proof } => Ok(array([Value::Unsigned(0), bound.write(c)?, proof.write(c)?])),
            Self::Absent { statement, explanation } => {
                Ok(array([Value::Unsigned(1), statement.write(c)?, explanation.write(c)?]))
            }
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Bound {
                bound: take(&mut fields, c)?,
                proof: take(&mut fields, c)?,
            },
            1 => Self::Absent {
                statement: take(&mut fields, c)?,
                explanation: take(&mut fields, c)?,
            },
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_epoch::publication::NumericPolicy {
    arithmetic,
    comparison_attempts,
    comparison_work
});
