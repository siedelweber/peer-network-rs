//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

impl Wire for pn_records::wall::Sign {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Positive => Ok(array([Value::Unsigned(0)])),
            Self::Negative => Ok(array([Value::Unsigned(1)])),
            Self::Indecisive => Ok(array([Value::Unsigned(2)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Positive,
            1 => Self::Negative,
            2 => Self::Indecisive,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::wall::Step { primitive, sign, work });
impl Wire for pn_records::wall::Verdict {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Pass => Ok(array([Value::Unsigned(0)])),
            Self::Fail => Ok(array([Value::Unsigned(1)])),
            Self::Indecisive => Ok(array([Value::Unsigned(2)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Pass,
            1 => Self::Fail,
            2 => Self::Indecisive,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::wall::Participation {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Door => Ok(array([Value::Unsigned(0)])),
            Self::Wall => Ok(array([Value::Unsigned(1)])),
            Self::Indecisive => Ok(array([Value::Unsigned(2)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Door,
            1 => Self::Wall,
            2 => Self::Indecisive,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::wall::Branches {
    floor_binding,
    deadband_hold,
    step_capped,
    above_floor,
    policy_valid,
    participation,
    proposal,
    delivered
});
structure!(pn_records::wall::Record {
    target,
    steps,
    bisections,
    bisection_work,
    branches,
    indecisive,
    work
});
