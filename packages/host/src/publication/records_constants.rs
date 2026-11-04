//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_records::constants::EditionInput {
    id,
    floor,
    numeraire,
    formula_edition,
    controller_edition,
    constants,
    permitted_overrides,
    domain_profiles,
    numerical_procedure,
    authentication_realization,
    publication_profile
});
impl Wire for pn_records::constants::ConstantDefinition {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Literal { name, value } => Ok(array([Value::Unsigned(0), name.write(c)?, value.write(c)?])),
            Self::Expression {
                name,
                expression,
                source_label,
            } => Ok(array([
                Value::Unsigned(1),
                name.write(c)?,
                expression.write(c)?,
                source_label.write(c)?,
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
            0 => Self::Literal {
                name: take(&mut fields, c)?,
                value: take(&mut fields, c)?,
            },
            1 => Self::Expression {
                name: take(&mut fields, c)?,
                expression: take(&mut fields, c)?,
                source_label: take(&mut fields, c)?,
            },
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
