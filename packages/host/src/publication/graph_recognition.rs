//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};
use pn_epoch::publication::disclosures as d;

structure!(d::RecognitionContext {
    epoch,
    prior_epoch,
    owners,
    consumed
});
impl Wire for d::RecognitionClause {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Completeness => Ok(array([Value::Unsigned(0)])),
            Self::ReferenceBinding => Ok(array([Value::Unsigned(1)])),
            Self::Authorization => Ok(array([Value::Unsigned(2)])),
            Self::BuyerConsent => Ok(array([Value::Unsigned(3)])),
            Self::SellerConsent => Ok(array([Value::Unsigned(4)])),
            Self::WellFormedness => Ok(array([Value::Unsigned(5)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Completeness,
            1 => Self::ReferenceBinding,
            2 => Self::Authorization,
            3 => Self::BuyerConsent,
            4 => Self::SellerConsent,
            5 => Self::WellFormedness,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(d::PartnerEvidence {
    ratify_author_is_buyer,
    accept_target_is_buyer,
    ratify_target_is_seller
});
