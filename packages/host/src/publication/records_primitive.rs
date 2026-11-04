//! Explicit field and variant mapping for the test publication theory.
use super::scalars::ExactText;
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_records::primitive::EnclosurePolicy {
    store,
    operation,
    refinement
});
impl Wire for pn_records::primitive::Node {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Rational(v0) => Ok(array([Value::Unsigned(0), v0.write_exact(c)?])),
            Self::Coordinate(v0) => Ok(array([Value::Unsigned(1), v0.write(c)?])),
            Self::Negate(v0) => Ok(array([Value::Unsigned(2), v0.write(c)?])),
            Self::Add(v0, v1) => Ok(array([Value::Unsigned(3), v0.write(c)?, v1.write(c)?])),
            Self::Subtract(v0, v1) => Ok(array([Value::Unsigned(4), v0.write(c)?, v1.write(c)?])),
            Self::Multiply(v0, v1) => Ok(array([Value::Unsigned(5), v0.write(c)?, v1.write(c)?])),
            Self::Divide(v0, v1) => Ok(array([Value::Unsigned(6), v0.write(c)?, v1.write(c)?])),
            Self::SquareRoot(v0) => Ok(array([Value::Unsigned(7), v0.write(c)?])),
            Self::Logarithm(v0) => Ok(array([Value::Unsigned(8), v0.write(c)?])),
            Self::Exponential(v0) => Ok(array([Value::Unsigned(9), v0.write(c)?])),
            Self::Sigmoid(v0) => Ok(array([Value::Unsigned(10), v0.write(c)?])),
            Self::Tanh(v0) => Ok(array([Value::Unsigned(11), v0.write(c)?])),
            Self::PositivePower(v0, v1) => Ok(array([Value::Unsigned(12), v0.write(c)?, v1.write_exact(c)?])),
            Self::Derivative(v0, v1) => Ok(array([Value::Unsigned(13), v0.write(c)?, v1.write(c)?])),
            Self::Clamp(v0, v1) => Ok(array([Value::Unsigned(14), v0.write(c)?, v1.write(c)?])),
            Self::GeneralizedDerivative(v0, v1) => Ok(array([Value::Unsigned(15), v0.write(c)?, v1.write(c)?])),
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
            1 => Self::Coordinate(take(&mut fields, c)?),
            2 => Self::Negate(take(&mut fields, c)?),
            3 => Self::Add(take(&mut fields, c)?, take(&mut fields, c)?),
            4 => Self::Subtract(take(&mut fields, c)?, take(&mut fields, c)?),
            5 => Self::Multiply(take(&mut fields, c)?, take(&mut fields, c)?),
            6 => Self::Divide(take(&mut fields, c)?, take(&mut fields, c)?),
            7 => Self::SquareRoot(take(&mut fields, c)?),
            8 => Self::Logarithm(take(&mut fields, c)?),
            9 => Self::Exponential(take(&mut fields, c)?),
            10 => Self::Sigmoid(take(&mut fields, c)?),
            11 => Self::Tanh(take(&mut fields, c)?),
            12 => Self::PositivePower(
                take(&mut fields, c)?,
                String::read_exact(fields.next().ok_or(Error::Shape)?, c)?,
            ),
            13 => Self::Derivative(take(&mut fields, c)?, take(&mut fields, c)?),
            14 => Self::Clamp(take(&mut fields, c)?, take(&mut fields, c)?),
            15 => Self::GeneralizedDerivative(take(&mut fields, c)?, take(&mut fields, c)?),
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::primitive::Goal {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Width => Ok(array([Value::Unsigned(0)])),
            Self::AtMost(v0) => Ok(array([Value::Unsigned(1), v0.write_exact(c)?])),
            Self::LessThan(v0) => Ok(array([Value::Unsigned(2), v0.write_exact(c)?])),
            Self::Equal(v0) => Ok(array([Value::Unsigned(3), v0.write_exact(c)?])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Width,
            1 => Self::AtMost(String::read_exact(fields.next().ok_or(Error::Shape)?, c)?),
            2 => Self::LessThan(String::read_exact(fields.next().ok_or(Error::Shape)?, c)?),
            3 => Self::Equal(String::read_exact(fields.next().ok_or(Error::Shape)?, c)?),
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::primitive::Range {
    lower: exact,
    upper: exact
});
structure!(pn_records::primitive::Query {
    coordinates,
    nodes,
    target,
    goal
});
structure!(pn_records::primitive::Schema { name, version });
structure!(pn_records::primitive::Attachment { schemas, certificate });
impl Wire for pn_records::primitive::Outcome {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Pass => Ok(array([Value::Unsigned(0)])),
            Self::Fail => Ok(array([Value::Unsigned(1)])),
            Self::Bound => Ok(array([Value::Unsigned(2)])),
            Self::Indecisive(v0) => Ok(array([Value::Unsigned(3), v0.write(c)?])),
            Self::Exhausted => Ok(array([Value::Unsigned(4)])),
            Self::Interrupted => Ok(array([Value::Unsigned(5)])),
            Self::Unsupported => Ok(array([Value::Unsigned(6)])),
            Self::DomainBoundary => Ok(array([Value::Unsigned(7)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Pass,
            1 => Self::Fail,
            2 => Self::Bound,
            3 => Self::Indecisive(take(&mut fields, c)?),
            4 => Self::Exhausted,
            5 => Self::Interrupted,
            6 => Self::Unsupported,
            7 => Self::DomainBoundary,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::primitive::PrimitiveEvidence {
    outcome,
    bounds,
    attachment,
    work,
    usage,
    evaluation_work,
    precision_met,
    completed_rounds,
    resource_fault
});
structure!(pn_records::primitive::PrimitiveRecord {
    query,
    precision,
    evidence
});
structure!(pn_records::primitive::FaultAssertion {
    kind,
    operation,
    logical_id
});
