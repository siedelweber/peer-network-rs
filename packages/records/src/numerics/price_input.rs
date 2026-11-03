//! Untrusted exact charge disclosure, separate from a checked writing vintage.
//! (´rule:numerics:restored-charge´)

use super::{ChargedPrice, Floor, Numeraire, NumericContext, NumericError};

/// Complete rational charge assertion and defining evidence; no stored trust bit.
/// (´rule:numerics:restored-charge´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriceInput {
    pub wall: String,
    pub numeraire: Numeraire,
    pub price: String,
    pub floor: Floor,
    pub ridge: Option<Box<crate::ridge::ChargeEvidence>>,
}

impl ChargedPrice {
    /// Disclose the exact wall and its full proof rather than an enclosure endpoint.
    /// (´rule:numerics:restored-charge´)
    /// Justified: Immutable disclosure carries no new charge authority.
    #[must_use]
    pub fn disclosure(&self) -> PriceInput {
        PriceInput {
            wall: self.wall().exact().into(),
            numeraire: self.numeraire().clone(),
            price: self.price().exact().into(),
            floor: self.floor,
            ridge: self.ridge.clone(),
        }
    }
}

impl NumericContext {
    /// Rebuild charge authority from an untrusted semantic disclosure.
    /// The consuming layer selects its admitted verifier; parsing grants no authority.
    /// (´rule:numerics:restored-charge´)
    /// # Errors
    /// Refuses a changed defining proof, unresolved comparison, extraneous ridge proof,
    /// wrong rational product or bounded arithmetic failure.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-replay-charged-price",
            source_item = "numerics::price_input::NumericContext::restore_charged_price"
        ),
        ret
    )]
    pub fn restore_charged_price(
        &mut self,
        input: &PriceInput,
        verifier: &impl crate::ridge::ChargeVerifier,
    ) -> Result<ChargedPrice, NumericError> {
        let literal = self.literal(&input.wall)?;
        let wall = self.computed(&literal)?;
        let price = match (input.floor, input.ridge.as_deref()) {
            (Floor::RidgeImage, Some(evidence)) => self.charged_price_with_ridge(&wall, &input.numeraire, evidence, verifier)?,
            (Floor::RationalThreeThirtySevenths, None) => self.charged_price(&wall, &input.numeraire, input.floor)?,
            _ => return Err(NumericError::RidgeEvidence),
        };
        if price.price().exact() != input.price {
            return Err(NumericError::RidgeEvidence);
        }
        Ok(price)
    }
}
