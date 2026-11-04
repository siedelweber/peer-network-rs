//! Explicit field and variant mapping for the test publication theory.
use super::scalars::ExactText;
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::admission::ScheduleInput {
    controller,
    announced_at,
    initialization,
    numeraire,
    delivery,
    refinement
});
structure!(pn_epoch::admission::InitializationInput {
    floor,
    wall: exact,
    parameters,
    policy_floor: exact,
    effective_boundary
});
structure!(pn_epoch::admission::ControllerParameters {
    absolute_cap: exact,
    relative_cap: exact,
    deadband: exact,
    margin: exact
});
impl Wire for pn_epoch::admission::Delivery {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::ExactRational => Ok(array([Value::Unsigned(0)])),
            Self::Grid { quantum, maximum_error } => Ok(array([
                Value::Unsigned(1),
                quantum.write_exact(c)?,
                maximum_error.write_exact(c)?,
            ])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::ExactRational,
            1 => Self::Grid {
                quantum: String::read_exact(fields.next().ok_or(Error::Shape)?, c)?,
                maximum_error: String::read_exact(fields.next().ok_or(Error::Shape)?, c)?,
            },
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_epoch::admission::Refinement {
    precision_bits,
    maximum_work,
    maximum_replay_work
});
