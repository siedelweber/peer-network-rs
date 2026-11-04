//! Explicit field and variant mapping for the test publication theory.
use super::scalars::ExactText;
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

impl Wire for pn_records::controller::Delivery {
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
structure!(pn_records::controller::Inputs {
    width: exact,
    empty_live_domain,
    accepted_rung: exact,
    cumulative_tilt: exact,
    bleed_squared: exact,
    previous: exact,
    floor,
    absolute_cap: exact,
    relative_cap: exact,
    deadband: exact,
    bracket,
    stopping_width: exact,
    maximum_steps,
    maximum_work,
    maximum_replay_work,
    delivery
});
impl Wire for pn_records::controller::Relation {
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
structure!(pn_records::controller::Branches {
    zero_width,
    floor,
    deadband,
    absolute_cap,
    relative_cap,
    direction,
    proposal,
    ideal
});
impl Wire for pn_records::controller::Stage {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Floor => Ok(array([Value::Unsigned(0)])),
            Self::InverseGain => Ok(array([Value::Unsigned(1)])),
            Self::Deadband => Ok(array([Value::Unsigned(2)])),
            Self::StepCap => Ok(array([Value::Unsigned(3)])),
            Self::Delivery => Ok(array([Value::Unsigned(4)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Floor,
            1 => Self::InverseGain,
            2 => Self::Deadband,
            3 => Self::StepCap,
            4 => Self::Delivery,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::controller::Attempt {
    precision,
    stopped_at,
    inverse,
    floor_checks,
    branches,
    delivered: exact,
    delivery_error
});
impl Wire for pn_records::controller::Verdict {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Delivered => Ok(array([Value::Unsigned(0)])),
            Self::Indecisive => Ok(array([Value::Unsigned(1)])),
            Self::DeliveryRefused => Ok(array([Value::Unsigned(2)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Delivered,
            1 => Self::Indecisive,
            2 => Self::DeliveryRefused,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::controller::Record {
    procedure,
    inputs,
    attempts,
    verdict
});
