//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

impl Wire for pn_records::solve::Primitive {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Rational => Ok(array([Value::Unsigned(0)])),
            Self::Root => Ok(array([Value::Unsigned(1)])),
            Self::Exponential => Ok(array([Value::Unsigned(2)])),
            Self::Logarithm => Ok(array([Value::Unsigned(3)])),
            Self::Power => Ok(array([Value::Unsigned(4)])),
            Self::Sigmoid => Ok(array([Value::Unsigned(5)])),
            Self::Tanh => Ok(array([Value::Unsigned(6)])),
            Self::SmoothDerivative => Ok(array([Value::Unsigned(7)])),
            Self::ClampGeneralized => Ok(array([Value::Unsigned(8)])),
            Self::Matrix => Ok(array([Value::Unsigned(9)])),
            Self::Krawczyk => Ok(array([Value::Unsigned(10)])),
            Self::InverseGain => Ok(array([Value::Unsigned(11)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Rational,
            1 => Self::Root,
            2 => Self::Exponential,
            3 => Self::Logarithm,
            4 => Self::Power,
            5 => Self::Sigmoid,
            6 => Self::Tanh,
            7 => Self::SmoothDerivative,
            8 => Self::ClampGeneralized,
            9 => Self::Matrix,
            10 => Self::Krawczyk,
            11 => Self::InverseGain,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::solve::Precision {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::ExactRational => Ok(array([Value::Unsigned(0)])),
            Self::BinaryBits(v0) => Ok(array([Value::Unsigned(1), v0.write(c)?])),
            Self::AbsoluteWidthBits(v0) => Ok(array([Value::Unsigned(2), v0.write(c)?])),
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
            1 => Self::BinaryBits(take(&mut fields, c)?),
            2 => Self::AbsoluteWidthBits(take(&mut fields, c)?),
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::solve::Equality {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::ExactRationalOnly => Ok(array([Value::Unsigned(0)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::ExactRationalOnly,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::solve::FenceProfile {
    bleed_squared,
    shape,
    inverse_wall
});
structure!(pn_records::solve::Procedure {
    edition,
    boundary,
    name,
    backend,
    primitives,
    precision,
    equality,
    grid: exact,
    margin: exact,
    maximum_work,
    maximum_solve_work,
    maximum_replay_work,
    maximum_iterations,
    endpoint_grid: exact,
    enclosure,
    fence
});
structure!(pn_records::solve::Bounds {
    lower: exact,
    upper: exact
});
impl Wire for pn_records::solve::Completion {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Pass => Ok(array([Value::Unsigned(0)])),
            Self::Fail => Ok(array([Value::Unsigned(1)])),
            Self::Indecisive => Ok(array([Value::Unsigned(2)])),
            Self::Interrupted => Ok(array([Value::Unsigned(3)])),
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
            3 => Self::Interrupted,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::solve::AttemptStop {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::ComparisonSeparated => Ok(array([Value::Unsigned(0)])),
            Self::PrecisionSequenceExhausted => Ok(array([Value::Unsigned(1)])),
            Self::WorkLimit => Ok(array([Value::Unsigned(2)])),
            Self::Interrupted => Ok(array([Value::Unsigned(3)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::ComparisonSeparated,
            1 => Self::PrecisionSequenceExhausted,
            2 => Self::WorkLimit,
            3 => Self::Interrupted,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::solve::Attempt {
    rung: exact,
    margined_fence,
    work,
    completion,
    stop,
    primitives
});
structure!(pn_records::solve::Residual {
    candidate: exact,
    residual_upper: exact,
    contraction_upper: exact,
    radius: exact
});
structure!(pn_records::solve::Evidence {
    hull,
    attempts,
    residual,
    primitives
});
