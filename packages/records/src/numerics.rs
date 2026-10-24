//! Exact unit carriers and bounded rational arithmetic; no byte encoding.
//! (´def:numerics:exact-carriers´)
use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use std::cmp::Ordering;

/// Explicit cumulative comparison attempt/work limits.
/// (´def:numerics:exact-carriers´)
pub use nrz_accuracy::Limits as ComparisonLimits;
/// Explicit CAS representation and work limits, re-exported for records callers.
/// (´def:numerics:exact-carriers´)
pub use nrz_cas::limits::Limits as ExactLimits;

/// A typed refusal; the unpublished surface is exhaustive.
/// (´def:numerics:exact-carriers´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NumericError {
    /// Backend syntax or finite resource refusal.
    #[error("exact backend: {0}")]
    Backend(#[from] nrz_cas::Fault),
    /// Scalar spelling or display refusal; never an approximate binding answer.
    #[error("literal or display: {0}")]
    Scalar(#[from] nrz_scalar::ArithmeticFailure),
    /// Quantities cannot be negative; costs, factors and numeraires must be positive.
    #[error("invalid quantity sign")]
    Sign,
    /// A required public identifier or terms string is empty.
    #[error("empty unit, identity or terms")]
    Empty,
    /// Only matching unit names and named numeraires compose.
    #[error("unit or numeraire mismatch")]
    Units,
    /// An exact comparison proves the wall below the floor.
    #[error("wall below declared floor")]
    BelowFloor,
    /// Unsupported or exhausted comparison cannot authorize publication.
    #[error("indecisive comparison")]
    Indecisive,
    /// A display request exceeds its representation bound.
    #[error("display exceeds eighteen fractional digits")]
    DisplayBound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Exact {
    canonical: String,
    value: Rational,
}
impl Exact {
    fn new(value: Rational, budget: &mut Budget) -> Result<Self, NumericError> {
        let canonical = value.exact_string(budget)?;
        Ok(Self { canonical, value })
    }
}

/// Original exact literal and its reduced rational value, never a rounded display.
/// (´def:numerics:exact-carriers´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Literal {
    source: String,
    exact: Exact,
}

/// An exact computed rational, with no implicit conversion from display text.
/// (´def:numerics:exact-carriers´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Computed {
    exact: Exact,
}

/// Nonbinding rounded text and the explicit arithmetic revision used to obtain it.
/// (´def:numerics:exact-carriers´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundedDisplay {
    text: String,
    fractional_digits: u8,
    arithmetic_revision: u32,
}

/// Count in actions, not in burn units; no multiplication by a unit cost exists.
/// (´def:numerics:dimensioned-values´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionCount(pub u64);

/// An explicit positive burn quantity defining a named reduced coordinate system.
/// (´def:numerics:dimensioned-values´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Numeraire {
    identity: String,
    amount: BurnAmount,
}

/// Full standing divided by the retained, explicitly named numeraire.
/// (´def:numerics:dimensioned-values´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReducedStanding {
    exact: Exact,
    numeraire: Numeraire,
}

/// Positive external denomination per burn unit, with applicable public terms.
/// (´def:numerics:dimensioned-values´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitCost {
    exact: Exact,
    denomination: String,
    burn_unit: String,
    terms: String,
}

/// External cost of a burn quantity under the retained terms.
/// (´def:numerics:dimensioned-values´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalCost {
    exact: Exact,
    denomination: String,
    terms: String,
}

/// Separate recording-event audit evidence, never the destruction price projection.
/// (´def:numerics:dimensioned-values´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordingEventCost {
    exact: Exact,
    denomination: String,
    terms: String,
}

/// Explicit floor alternatives; neither implements Default.
/// (´def:declarations:constants-edition´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Floor {
    /// Exactly three divided by thirty-seven.
    RationalThreeThirtySevenths,
    /// The defining ridge real mapped by p/(1-p), never an enclosure endpoint.
    RidgeImage,
}

/// Exact wall-minus-floor evidence, or an honest lack of a decision.
/// (´def:declarations:constants-edition´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloorComparison {
    Below,
    Equal,
    Above,
    Indecisive,
}

/// One coupled wall and numeraire; its burn-per-action image cannot be set separately.
/// (´def:ledger:charged-coordinate´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChargedPrice {
    wall: Computed,
    numeraire: Numeraire,
    price: BurnPerAction,
    floor: Floor,
}

/// Immutable consummated charge with its own price, action count and boundary.
/// (´def:ledger:charged-coordinate´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChargedVintage {
    price: ChargedPrice,
    actions: ActionCount,
    charged: BurnAmount,
    boundary: u64,
}

/// Caller-supplied exact arithmetic limits and cumulative comparison attempts.
/// (´def:numerics:exact-carriers´)
#[derive(Debug)]
pub struct NumericContext {
    budget: Budget,
    comparisons: nrz_accuracy::WorkBudget,
}

fn nonempty(text: &str) -> Result<(), NumericError> {
    if text.is_empty() { Err(NumericError::Empty) } else { Ok(()) }
}
fn sign(value: &Exact, positive: bool) -> Result<(), NumericError> {
    if value.value.is_negative() || (positive && value.value.is_zero()) {
        Err(NumericError::Sign)
    } else {
        Ok(())
    }
}
fn units(left: &str, right: &str) -> Result<(), NumericError> {
    if left == right { Ok(()) } else { Err(NumericError::Units) }
}

/// A nonnegative amount in the named burn unit.
/// (´def:numerics:dimensioned-values´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnAmount {
    exact: Exact,
    unit: String,
}

/// A nonnegative burn-unit quantity per action, distinct from amounts and counts.
/// (´def:numerics:dimensioned-values´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnPerAction {
    exact: Exact,
    unit: String,
}

/// Nonnegative full standing in the named burn unit.
/// (´def:numerics:dimensioned-values´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullStanding {
    exact: Exact,
    unit: String,
}

impl NumericContext {
    /// Start explicit exact-work and comparison-attempt ledgers; zero allowances remain refusing.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-new",
            source_item = "numerics::NumericContext::new"
        ),
        ret
    )]
    pub fn new(limits: Limits, comparisons: nrz_accuracy::Limits) -> Result<Self, NumericError> {
        let result = (|| {
            Ok(Self {
                budget: Budget::new(limits)?,
                comparisons: comparisons.start(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Parse the original exact rational spelling without evaluating a floating candidate.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-literal",
            source_item = "numerics::NumericContext::literal"
        ),
        ret
    )]
    pub fn literal(&mut self, source: &str) -> Result<Literal, NumericError> {
        let result = (|| {
            let value = Rational::parse(source, &mut self.budget)?;
            Ok(Literal {
                source: source.into(),
                exact: Exact::new(value, &mut self.budget)?,
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Admit an exact literal as a computed rational under the receiving limits.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-computed",
            source_item = "numerics::NumericContext::computed"
        ),
        ret
    )]
    pub fn computed(&mut self, literal: &Literal) -> Result<Computed, NumericError> {
        let result = (|| {
            literal
                .exact
                .value
                .check(&self.budget, nrz_cas::Location::new("records computed admission"))?;
            Ok(Computed {
                exact: literal.exact.clone(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Admit a nonnegative quantity with an explicit nonempty burn-unit name.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-burn",
            source_item = "numerics::NumericContext::burn"
        ),
        ret
    )]
    pub fn burn(&mut self, literal: &Literal, unit: &str) -> Result<BurnAmount, NumericError> {
        let result = (|| {
            nonempty(unit)?;
            sign(&literal.exact, false)?;
            Ok(BurnAmount {
                exact: literal.exact.clone(),
                unit: unit.into(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Admit a nonnegative quantity with an explicit nonempty burn-unit name.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-burn-per-action",
            source_item = "numerics::NumericContext::burn_per_action"
        ),
        ret
    )]
    pub fn burn_per_action(&mut self, literal: &Literal, unit: &str) -> Result<BurnPerAction, NumericError> {
        let result = (|| {
            nonempty(unit)?;
            sign(&literal.exact, false)?;
            Ok(BurnPerAction {
                exact: literal.exact.clone(),
                unit: unit.into(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Admit a nonnegative quantity with an explicit nonempty burn-unit name.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-standing",
            source_item = "numerics::NumericContext::standing"
        ),
        ret
    )]
    pub fn standing(&mut self, literal: &Literal, unit: &str) -> Result<FullStanding, NumericError> {
        let result = (|| {
            nonempty(unit)?;
            sign(&literal.exact, false)?;
            Ok(FullStanding {
                exact: literal.exact.clone(),
                unit: unit.into(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Declare a strictly positive named numeraire, without an external market price.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-numeraire",
            source_item = "numerics::NumericContext::numeraire"
        ),
        ret
    )]
    pub fn numeraire(&mut self, identity: &str, amount: &BurnAmount) -> Result<Numeraire, NumericError> {
        let result = (|| {
            nonempty(identity)?;
            sign(&amount.exact, true)?;
            Ok(Numeraire {
                identity: identity.into(),
                amount: amount.clone(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Divide full standing by the explicitly retained numeraire in the same burn unit.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-reduce",
            source_item = "numerics::NumericContext::reduce"
        ),
        ret
    )]
    pub fn reduce(&mut self, standing: &FullStanding, numeraire: &Numeraire) -> Result<ReducedStanding, NumericError> {
        let result = (|| {
            units(&standing.unit, &numeraire.amount.unit)?;
            let value = standing.exact.value.div(&numeraire.amount.exact.value, &mut self.budget)?;
            Ok(ReducedStanding {
                exact: Exact::new(value, &mut self.budget)?,
                numeraire: numeraire.clone(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Declare a positive external denomination per burn unit; no universal lower bound is imposed.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-unit-cost",
            source_item = "numerics::NumericContext::unit_cost"
        ),
        ret
    )]
    pub fn unit_cost(
        &mut self,
        literal: &Literal,
        denomination: &str,
        burn_unit: &str,
        terms: &str,
    ) -> Result<UnitCost, NumericError> {
        let result = (|| {
            sign(&literal.exact, true)?;
            nonempty(denomination)?;
            nonempty(burn_unit)?;
            nonempty(terms)?;
            Ok(UnitCost {
                exact: literal.exact.clone(),
                denomination: denomination.into(),
                burn_unit: burn_unit.into(),
                terms: terms.into(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Multiply a cost only by a burn amount; action counts cannot inhabit this argument.
    /// (´def:numerics:exact-carriers´)
    ///
    /// ```compile_fail,E0308
    /// use pn_records::numerics::{ActionCount, NumericContext, UnitCost};
    /// fn wrong(c: &mut NumericContext, cost: &UnitCost) {
    ///     let _ = c.apply_cost(cost, &ActionCount(2));
    /// }
    /// ```
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-apply-cost",
            source_item = "numerics::NumericContext::apply_cost"
        ),
        ret
    )]
    pub fn apply_cost(&mut self, cost: &UnitCost, amount: &BurnAmount) -> Result<ExternalCost, NumericError> {
        let result = (|| {
            units(&cost.burn_unit, &amount.unit)?;
            let value = cost.exact.value.mul(&amount.exact.value, &mut self.budget)?;
            Ok(ExternalCost {
                exact: Exact::new(value, &mut self.budget)?,
                denomination: cost.denomination.clone(),
                terms: cost.terms.clone(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Project the burn-denominated sum theta plus numeraire times reduced standing into external cost.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-combined-cost",
            source_item = "numerics::NumericContext::combined_cost"
        ),
        ret
    )]
    pub fn combined_cost(
        &mut self,
        cost: &UnitCost,
        theta: &BurnAmount,
        rho: &ReducedStanding,
    ) -> Result<ExternalCost, NumericError> {
        let result = (|| {
            units(&theta.unit, &rho.numeraire.amount.unit)?;
            let full = rho.exact.value.mul(&rho.numeraire.amount.exact.value, &mut self.budget)?;
            let value = theta.exact.value.add(&full, &mut self.budget)?;
            let amount = BurnAmount {
                exact: Exact::new(value, &mut self.budget)?,
                unit: theta.unit.clone(),
            };
            self.apply_cost(cost, &amount)
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Retain recording-event cost as separate audit evidence, with no unit-cost conversion.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-recording-cost",
            source_item = "numerics::NumericContext::recording_cost"
        ),
        ret
    )]
    pub fn recording_cost(
        &mut self,
        literal: &Literal,
        denomination: &str,
        terms: &str,
    ) -> Result<RecordingEventCost, NumericError> {
        let result = (|| {
            sign(&literal.exact, false)?;
            nonempty(denomination)?;
            nonempty(terms)?;
            Ok(RecordingEventCost {
                exact: literal.exact.clone(),
                denomination: denomination.into(),
                terms: terms.into(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Co-scale amount and numeraire into the new unit; reduced coordinates then agree.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-recoin",
            source_item = "numerics::NumericContext::recoin"
        ),
        ret
    )]
    pub fn recoin(
        &mut self,
        amount: &BurnAmount,
        numeraire: &Numeraire,
        factor: &Literal,
        new_unit: &str,
    ) -> Result<(BurnAmount, Numeraire), NumericError> {
        let result = (|| {
            sign(&factor.exact, true)?;
            nonempty(new_unit)?;
            units(&amount.unit, &numeraire.amount.unit)?;
            let a = amount.exact.value.mul(&factor.exact.value, &mut self.budget)?;
            let n = numeraire.amount.exact.value.mul(&factor.exact.value, &mut self.budget)?;
            Ok((
                BurnAmount {
                    exact: Exact::new(a, &mut self.budget)?,
                    unit: new_unit.into(),
                },
                Numeraire {
                    identity: numeraire.identity.clone(),
                    amount: BurnAmount {
                        exact: Exact::new(n, &mut self.budget)?,
                        unit: new_unit.into(),
                    },
                },
            ))
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// At fixed purchasing power divide the numeric amount by the market factor; the unit and numeraire do not change.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-reprice",
            source_item = "numerics::NumericContext::reprice"
        ),
        ret
    )]
    pub fn reprice(&mut self, amount: &BurnAmount, market_factor: &Literal) -> Result<BurnAmount, NumericError> {
        let result = (|| {
            sign(&market_factor.exact, true)?;
            let value = amount.exact.value.div(&market_factor.exact.value, &mut self.budget)?;
            Ok(BurnAmount {
                exact: Exact::new(value, &mut self.budget)?,
                unit: amount.unit.clone(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Compare with the exact rational floor; unresolved ridge or exhausted work remains indecisive.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-compare-floor",
            source_item = "numerics::NumericContext::compare_floor"
        ),
        ret
    )]
    pub fn compare_floor(&mut self, wall: &Computed, floor: Floor) -> Result<FloorComparison, NumericError> {
        let result = (|| {
            if self.comparisons.reserve_attempt(1).is_err() {
                return Ok(FloorComparison::Indecisive);
            }
            if floor == Floor::RidgeImage {
                return Ok(FloorComparison::Indecisive);
            }
            let compared = (|| {
                let rational = Rational::parse("3/37", &mut self.budget)?;
                wall.exact.value.compare(&rational, &mut self.budget)
            })();
            Ok(match compared {
                Ok(Ordering::Less) => FloorComparison::Below,
                Ok(Ordering::Equal) => FloorComparison::Equal,
                Ok(Ordering::Greater) => FloorComparison::Above,
                Err(_) => FloorComparison::Indecisive,
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Certify the rational wall and derive its sole charged price as wall times numeraire.
    /// (´def:numerics:exact-carriers´)
    ///
    /// ```compile_fail,E0308
    /// use pn_records::numerics::{Floor, NumericContext, Numeraire, RoundedDisplay};
    /// fn wrong(c: &mut NumericContext, display: &RoundedDisplay, nu: &Numeraire) {
    ///     let _ = c.charged_price(display, nu, Floor::RationalThreeThirtySevenths);
    /// }
    /// ```
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-charged-price",
            source_item = "numerics::NumericContext::charged_price"
        ),
        ret
    )]
    pub fn charged_price(&mut self, wall: &Computed, numeraire: &Numeraire, floor: Floor) -> Result<ChargedPrice, NumericError> {
        let result = (|| {
            match self.compare_floor(wall, floor)? {
                FloorComparison::Below => return Err(NumericError::BelowFloor),
                FloorComparison::Indecisive => return Err(NumericError::Indecisive),
                FloorComparison::Equal | FloorComparison::Above => {}
            }
            let value = wall.exact.value.mul(&numeraire.amount.exact.value, &mut self.budget)?;
            Ok(ChargedPrice {
                wall: wall.clone(),
                numeraire: numeraire.clone(),
                floor,
                price: BurnPerAction {
                    exact: Exact::new(value, &mut self.budget)?,
                    unit: numeraire.amount.unit.clone(),
                },
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Retain this consummated action count and charged pair independently of later prices.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-consummate",
            source_item = "numerics::NumericContext::consummate"
        ),
        ret
    )]
    pub fn consummate(
        &mut self,
        price: &ChargedPrice,
        actions: ActionCount,
        boundary: u64,
    ) -> Result<ChargedVintage, NumericError> {
        let result = (|| {
            let count = Rational::parse(&actions.0.to_string(), &mut self.budget)?;
            let value = price.price.exact.value.mul(&count, &mut self.budget)?;
            Ok(ChargedVintage {
                price: price.clone(),
                actions,
                boundary,
                charged: BurnAmount {
                    exact: Exact::new(value, &mut self.budget)?,
                    unit: price.price.unit.clone(),
                },
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl NumericContext {
    /// Create nonbinding rounded candidate text; it is not accepted by a numeric comparison.
    /// (´def:numerics:exact-carriers´)
    ///
    /// # Errors
    /// Refuses invalid signs, units, syntax or exhausted explicit resource limits as applicable.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "numeric-display",
            source_item = "numerics::NumericContext::display"
        ),
        ret
    )]
    pub fn display(&mut self, value: &Computed, fractional_digits: u8) -> Result<RoundedDisplay, NumericError> {
        let result = (|| {
            if fractional_digits > 18 {
                return Err(NumericError::DisplayBound);
            }
            let arithmetic = nrz_scalar::ArithmeticContext::new()?;
            let literal = nrz_scalar::NumericLiteral::new(&value.exact.canonical, nrz_scalar::LiteralLimits::default())?;
            let decoded = literal.decode::<f64>(&arithmetic)?;
            Ok(RoundedDisplay {
                text: format!("{:.*}", usize::from(fractional_digits), decoded.center().get()),
                fractional_digits,
                arithmetic_revision: arithmetic.revision(),
            })
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl Literal {
    /// Borrow the exact reduced rational spelling, never display rounding.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn exact(&self) -> &str {
        &self.exact.canonical
    }
}

impl Computed {
    /// Borrow the exact reduced rational spelling, never display rounding.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn exact(&self) -> &str {
        &self.exact.canonical
    }
}

impl BurnAmount {
    /// Borrow the exact reduced rational spelling, never display rounding.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn exact(&self) -> &str {
        &self.exact.canonical
    }
}

impl BurnPerAction {
    /// Borrow the exact reduced rational spelling, never display rounding.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn exact(&self) -> &str {
        &self.exact.canonical
    }
}

impl FullStanding {
    /// Borrow the exact reduced rational spelling, never display rounding.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn exact(&self) -> &str {
        &self.exact.canonical
    }
}

impl ReducedStanding {
    /// Borrow the exact reduced rational spelling, never display rounding.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn exact(&self) -> &str {
        &self.exact.canonical
    }
}

impl UnitCost {
    /// Borrow the exact reduced rational spelling, never display rounding.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn exact(&self) -> &str {
        &self.exact.canonical
    }
}

impl ExternalCost {
    /// Borrow the exact reduced rational spelling, never display rounding.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn exact(&self) -> &str {
        &self.exact.canonical
    }
}

impl RecordingEventCost {
    /// Borrow the exact reduced rational spelling, never display rounding.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn exact(&self) -> &str {
        &self.exact.canonical
    }
}

impl BurnAmount {
    /// Borrow the explicit burn-unit name.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn unit(&self) -> &str {
        &self.unit
    }
}

impl BurnPerAction {
    /// Borrow the explicit burn-unit name.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn unit(&self) -> &str {
        &self.unit
    }
}

impl FullStanding {
    /// Borrow the explicit burn-unit name.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn unit(&self) -> &str {
        &self.unit
    }
}

impl Literal {
    /// Borrow the original declaration spelling.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

impl Numeraire {
    /// Borrow the coordinate-system identity.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

impl Numeraire {
    /// Borrow the positive burn amount defining this numeraire.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn amount(&self) -> &BurnAmount {
        &self.amount
    }
}

impl ReducedStanding {
    /// Borrow the coordinate system retained by this reduction.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn numeraire(&self) -> &Numeraire {
        &self.numeraire
    }
}

impl RoundedDisplay {
    /// Borrow illustrative text; no exact-value conversion is provided.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl ChargedPrice {
    /// Borrow the derived price, which cannot be independently set.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn price(&self) -> &BurnPerAction {
        &self.price
    }
}

impl ChargedPrice {
    /// Borrow the exact wall used for this charge.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn wall(&self) -> &Computed {
        &self.wall
    }
}

impl ChargedPrice {
    /// Borrow this price coordinate system.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn numeraire(&self) -> &Numeraire {
        &self.numeraire
    }
}

impl ChargedVintage {
    /// Borrow the retained historical charge.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn charged(&self) -> &BurnAmount {
        &self.charged
    }
}

impl ChargedVintage {
    /// Borrow the consummated price, not a current-price lookup.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn price(&self) -> &ChargedPrice {
        &self.price
    }
}

impl ChargedVintage {
    /// Read the consummation boundary.
    /// (´def:numerics:exact-carriers´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn boundary(&self) -> u64 {
        self.boundary
    }
}

#[cfg(test)]
mod tests {
    use super::{ComparisonLimits, ExactLimits, NumericContext, NumericError};

    /// Claim: Exact decimal import retains its source and canonical rational, negative quantities and zero costs refuse, and an exhausted arithmetic budget returns a typed backend refusal instead of an approximate value.
    /// ´claim:numerics:literal-signs-and-resources-refuse-explicitly´
    /// ´test:unit:literal-admission´
    #[test]
    fn literal_admission() {
        let mut c = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(10, 10)).unwrap();
        let literal = c.literal("1.25").unwrap();
        assert_eq!((literal.source(), literal.exact()), ("1.25", "5/4"));
        let negative = c.literal("-1").unwrap();
        let zero = c.literal("0").unwrap();
        assert_eq!(c.burn(&negative, "burn"), Err(NumericError::Sign));
        assert_eq!(c.unit_cost(&zero, "USD", "burn", "terms"), Err(NumericError::Sign));
        let tiny = c.literal("1/1000000000000").unwrap();
        assert!(c.unit_cost(&tiny, "USD", "burn", "terms").is_ok());
        assert!(c.literal("NaN").is_err());
        let mut exhausted = NumericContext::new(
            ExactLimits {
                arithmetic_steps: 0,
                ..ExactLimits::default()
            },
            ComparisonLimits::new(0, 0),
        )
        .unwrap();
        assert!(matches!(exhausted.literal("1/3"), Err(NumericError::Backend(_))));
    }
}
