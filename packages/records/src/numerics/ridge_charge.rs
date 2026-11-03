//! Records checks the exact defining envelope; a declared kernel verifier checks its proof.
//! (´[ROOT-rule:design:ridge-charge-contract]´)

use super::{ChargedPrice, Computed, Floor, Numeraire, NumericContext, NumericError};
use crate::ridge::{ChargeEvidence, ChargeVerifier};
use nrz_cas::Rational;

impl NumericContext {
    fn ridge_envelope(&mut self, evidence: &ChargeEvidence) -> Result<Option<(Rational, Rational)>, NumericError> {
        let input = &evidence.input;
        let definition = &input.definition;
        if evidence.analytic_premises != "clean-ridge-analytic-v1"
            || definition.schema != "clean-elasticity-ridge-v1"
            || definition.inverse_temperature != "2*ln(2)"
            || definition.bleed_squared != "0"
            || definition.core_power != "1"
        {
            return Err(NumericError::RidgeDefinition);
        }
        if evidence.record.input != *input {
            return Err(NumericError::RidgeEvidence);
        }
        let b = &mut self.budget;
        let a = Rational::parse(&input.bracket.lower, b)?;
        let z = Rational::parse(&input.bracket.upper, b)?;
        if a.is_negative() || a.is_zero() || !a.compare(&z, b)?.is_lt() || !z.compare(&Rational::parse("3/40", b)?, b)?.is_lt() {
            return Err(NumericError::RidgeEvidence);
        }
        let Some(image) = &evidence.record.image else {
            return Ok(None);
        };
        let mut next = Rational::parse("0", b)?;
        for cell in &evidence.record.cells {
            let lower = Rational::parse(&cell.lower, b)?;
            let upper = Rational::parse(&cell.upper, b)?;
            if lower != next || !lower.compare(&upper, b)?.is_lt() {
                return Err(NumericError::RidgeEvidence);
            }
            next = upper;
        }
        if next != Rational::parse("1/2", b)? {
            return Err(NumericError::RidgeEvidence);
        }
        let one = Rational::parse("1", b)?;
        let lower = a.div(&one.sub(&a, b)?, b)?;
        let upper = z.div(&one.sub(&z, b)?, b)?;
        if Rational::parse(&image.lower, b)? != lower || Rational::parse(&image.upper, b)? != upper {
            return Err(NumericError::RidgeEvidence);
        }
        Ok(Some((lower, upper)))
    }

    /// Independently validate defining evidence, decide the exact rational wall's side
    /// from its checked envelope, and derive only that wall's rational burn image.
    /// (´[ROOT-rule:design:ridge-charge-contract]´)
    /// # Errors
    /// Refuses changed definitions, invalid proof structure or replay, walls below the
    /// floor, unresolved envelope comparisons and exhausted explicit budgets.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-ridge-charged-price",
            source_item = "numerics::ridge_charge::NumericContext::charged_price_with_ridge"
        ),
        ret
    )]
    pub fn charged_price_with_ridge(
        &mut self,
        wall: &Computed,
        numeraire: &Numeraire,
        evidence: &ChargeEvidence,
        verifier: &impl ChargeVerifier,
    ) -> Result<ChargedPrice, NumericError> {
        let result = (|| {
            if self.comparisons.reserve_attempt(1).is_err() {
                return Err(NumericError::Indecisive);
            }
            let envelope = self.ridge_envelope(evidence)?;
            verifier.replay(evidence)?;
            let (lower, upper) = envelope.ok_or(NumericError::Indecisive)?;
            if wall.exact.value.compare(&lower, &mut self.budget)?.is_lt() {
                return Err(NumericError::BelowFloor);
            }
            if wall.exact.value.compare(&upper, &mut self.budget)?.is_lt() {
                return Err(NumericError::Indecisive);
            }
            Ok(ChargedPrice {
                wall: wall.clone(),
                numeraire: numeraire.clone(),
                price: self.per_action(wall, numeraire)?,
                floor: Floor::RidgeImage,
                ridge: Some(Box::new(evidence.clone())),
            })
        })();
        if result.is_err() {
            crate::refused();
        }
        result
    }

    /// Reconstruct a retained charge under the expected floor and numeraire.
    /// Ridge evidence is replayed afresh; rational floors use the original exact path.
    /// (´[ROOT-rule:design:ridge-charge-contract]´)
    /// # Errors
    /// Refuses missing or invalid ridge evidence, unresolved comparisons and arithmetic limits.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-replay-charged-price",
            source_item = "numerics::ridge_charge::NumericContext::replay_charged_price"
        ),
        ret
    )]
    pub fn replay_charged_price(
        &mut self,
        price: &ChargedPrice,
        numeraire: &Numeraire,
        floor: Floor,
        verifier: &impl ChargeVerifier,
    ) -> Result<ChargedPrice, NumericError> {
        if floor == Floor::RidgeImage {
            self.charged_price_with_ridge(
                price.wall(),
                numeraire,
                price.ridge.as_deref().ok_or(NumericError::RidgeEvidence)?,
                verifier,
            )
        } else {
            self.charged_price(price.wall(), numeraire, floor)
        }
    }
}
