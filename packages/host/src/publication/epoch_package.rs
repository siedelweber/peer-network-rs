//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::package::ClosureStatement {
    policy,
    opened_at,
    determined_at,
    cause,
    attestation
});
structure!(pn_epoch::package::ClosurePolicy {
    target,
    minimum_ticks,
    maximum_ticks,
    clock
});
impl Wire for pn_epoch::package::ClosureCause {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::TargetAfterMinimum => Ok(array([Value::Unsigned(0)])),
            Self::MaximumDuration => Ok(array([Value::Unsigned(1)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::TargetAfterMinimum,
            1 => Self::MaximumDuration,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
