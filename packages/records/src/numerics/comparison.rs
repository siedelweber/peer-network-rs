//! Explicit comparison editions; endpoint consistency is not soundness.
//! (´[ROOT-dec:design:comparison-verdict-record]´)

use super::{Floor, NumericContext, NumericError};
use crate::{
    binary64::Fraction,
    primitive::PrimitiveRecord,
    ridge::{ChargeEvidence, ChargeVerifier, Definition, Wall},
};
use nrz_cas::Rational;
use std::cmp::Ordering;

/// Structural refusals, separate from carried operational outcomes.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The retained left operand differs from the independent question.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    QuestionLeft,
    /// The retained right operand or its defining identity differs.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    QuestionRight,
    /// The reduction code is outside the closed list.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Reduction,
    /// The predicate code is outside the five comparisons.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Predicate,
    /// The declared reduction differs from the expected quantity.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ExpectedReduction,
    /// The declared predicate differs from the expected predicate.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ExpectedPredicate,
    /// The derivative reduction needs a rational left operand.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    DerivativeLeft,
    /// The derivative reduction needs a defining-ridge right operand.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    DerivativeRight,
    /// The derivative wall is not strictly above zero.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    WallLower,
    /// The derivative wall is not strictly below one.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    WallUpper,
    /// The defining object is not the admitted clean ridge.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Definition,
    /// No defining proof is supplied.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    MissingProof,
    /// The defining proof belongs to a different defining object.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ProofIdentity,
    /// The defining proof is invalid or incomplete.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Proof,
    /// An evaluated result has two exact rational contextual operands.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ExactEvaluated,
    /// An exact result has a symbolic contextual operand.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ExactContext,
    /// The exact left operand differs from its original contextual value.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ExactLeft,
    /// The exact right operand differs from its original contextual value.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ExactRight,
    /// The enclosure endpoints are reversed.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    EnclosureOrder,
    /// An equal-endpoint enclosure excludes its lower endpoint.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    LowerInclusion,
    /// An equal-endpoint enclosure excludes its upper endpoint.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    UpperInclusion,
    /// The reduction threshold is not exact zero.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Threshold,
    /// The threshold differs from the independently expected threshold.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ExpectedThreshold,
    /// The relation code is unknown.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Relation,
    /// An exact comparison carries an unresolved relation.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ExactUnresolved,
    /// The retained relation differs from the endpoint relation.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    RelationAgreement,
    /// The verdict code is unknown.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Verdict,
    /// An exact comparison carries INDECISIVE.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ExactIndecisive,
    /// The retained verdict differs from the endpoint implication.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    VerdictAgreement,
    /// The operational cause is outside the closed seven.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Cause,
    /// The retained ridge wall differs from the independent wall.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    WallBinding,
    /// The retained ridge floor differs from the independent floor.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    FloorBinding,
    /// The supplied cumulative arithmetic ceiling is exhausted.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Resource,
    /// An original operand is not an exact rational.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Number,
}

/// The original operands supplied by the containing question, never by an interval.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub left: Wall,
    pub right: Wall,
}

/// Independently supplied binding; its interval is deliberately not a member.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    pub question: Question,
    pub reduction: u64,
    pub predicate: u64,
    pub threshold: Fraction,
}

/// Exact rational enclosure with explicit endpoint inclusion.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enclosure {
    pub lower: Fraction,
    pub lower_included: bool,
    pub upper: Fraction,
    pub upper_included: bool,
}

/// Disjoint evaluated, exact and operational constructors of the second edition.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResultKind {
    /// A claim about the reduction's quantity, with its endpoint-derived verdict.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Evaluated {
        reduction: u64,
        predicate: u64,
        enclosure: Enclosure,
        threshold: Fraction,
        relation: u64,
        verdict: u64,
    },
    /// Original exact operands; no enclosure or mathematical indecision is invented.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Exact {
        left: Fraction,
        predicate: u64,
        right: Fraction,
        relation: u64,
        verdict: u64,
    },
    /// An operational outcome has a cause and has no verdict.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Operational { cause: u64 },
}

/// Explicitly selected `FloorComparison` edition two, not an admission carrier.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloorComparisonV2 {
    pub result: ResultKind,
}

/// Explicitly selected ridge comparison edition two with unchanged context projections.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComparisonRecordV2 {
    pub wall: Wall,
    pub floor: Floor,
    pub queries: Vec<PrimitiveRecord>,
    pub comparison: FloorComparisonV2,
    pub work: u64,
}

/// External defining evidence and the existing admitted replay boundary.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Debug)]
pub struct DefiningProof<'a> {
    pub evidence: &'a ChargeEvidence,
    pub verifier: &'a dyn ChargeVerifier,
}

fn predicate(code: u64) -> Result<(), Error> {
    if (1..=5).contains(&code) {
        Ok(())
    } else {
        Err(Error::Predicate)
    }
}

fn clean(definition: &Definition) -> bool {
    definition.schema == "clean-elasticity-ridge-v1"
        && definition.inverse_temperature == "2*ln(2)"
        && definition.bleed_squared == "0"
        && definition.core_power == "1"
}

fn proof_error(error: NumericError) -> Error {
    match error {
        NumericError::Backend(fault) if matches!(fault.kind, nrz_cas::FaultKind::Exhausted { .. }) => Error::Resource,
        NumericError::RetainedFault(fault) if matches!(fault.kind, nrz_cas::FaultKind::Exhausted { .. }) => Error::Resource,
        _ => Error::Proof,
    }
}

fn endpoint_verdict(
    code: u64,
    enclosure: &Enclosure,
    lower: Ordering,
    upper: Ordering,
    relation: u64,
    verdict: u64,
) -> Result<(), Error> {
    let below = upper.is_lt() || (upper.is_eq() && !enclosure.upper_included);
    let above = lower.is_gt() || (lower.is_eq() && !enclosure.lower_included);
    let equal = lower.is_eq() && upper.is_eq();
    let actual_relation = if below {
        0
    } else if equal {
        1
    } else if above {
        2
    } else {
        3
    };
    if relation > 3 {
        return Err(Error::Relation);
    }
    if relation != actual_relation {
        return Err(Error::RelationAgreement);
    }
    if verdict > 2 {
        return Err(Error::Verdict);
    }
    let (pass, fail) = match code {
        1 => (!upper.is_gt(), above),
        2 => (below, !lower.is_lt()),
        3 => (equal, below || above),
        4 => (!lower.is_lt(), below),
        5 => (above, !upper.is_gt()),
        _ => return Err(Error::Predicate),
    };
    let actual_verdict = if pass {
        0
    } else if fail {
        1
    } else {
        2
    };
    if verdict != actual_verdict {
        return Err(Error::VerdictAgreement);
    }
    Ok(())
}

impl NumericContext {
    fn comparison_q(&mut self, fraction: &Fraction) -> Result<Rational, Error> {
        let (numerator, denominator) = fraction.parts();
        let text = if denominator == "1" {
            numerator.to_owned()
        } else {
            format!("{numerator}/{denominator}")
        };
        Rational::parse(&text, &mut self.budget).map_err(|_| Error::Resource)
    }

    fn comparison_rational(&mut self, operand: &Wall) -> Result<Rational, Error> {
        let Wall::Rational(text) = operand else {
            return Err(Error::ExactContext);
        };
        Rational::parse(text, &mut self.budget).map_err(|fault| match fault.kind {
            nrz_cas::FaultKind::Exhausted { .. } => Error::Resource,
            nrz_cas::FaultKind::Invalid(_) => Error::Number,
        })
    }

    fn comparison_proof(&mut self, definition: &Definition, proof: Option<&DefiningProof<'_>>) -> Result<(), Error> {
        if !clean(definition) {
            return Err(Error::Definition);
        }
        let proof = proof.ok_or(Error::MissingProof)?;
        if proof.evidence.input.definition != *definition {
            return Err(Error::ProofIdentity);
        }
        if self.ridge_envelope(proof.evidence).map_err(proof_error)?.is_none() {
            return Err(Error::Proof);
        }
        proof.verifier.replay(proof.evidence).map_err(proof_error)
    }

    fn comparison_domain(&mut self, reduction: u64, question: &Question, proof: Option<&DefiningProof<'_>>) -> Result<(), Error> {
        if reduction == 0 {
            for operand in [&question.left, &question.right] {
                match operand {
                    Wall::Rational(_) => {
                        self.comparison_rational(operand)?;
                    }
                    Wall::DefiningRidge(definition) => self.comparison_proof(definition, proof)?,
                }
            }
        } else {
            if !matches!(question.left, Wall::Rational(_)) {
                return Err(Error::DerivativeLeft);
            }
            let Wall::DefiningRidge(definition) = &question.right else {
                return Err(Error::DerivativeRight);
            };
            let wall = self.comparison_rational(&question.left)?;
            if wall.is_negative() || wall.is_zero() {
                return Err(Error::WallLower);
            }
            let one = Rational::parse("1", &mut self.budget).map_err(|_| Error::Resource)?;
            if !wall.compare(&one, &mut self.budget).map_err(|_| Error::Resource)?.is_lt() {
                return Err(Error::WallUpper);
            }
            self.comparison_proof(definition, proof)?;
        }
        Ok(())
    }

    fn comparison_evaluated(
        &mut self,
        enclosure: &Enclosure,
        threshold: &Fraction,
        expected: &Fraction,
    ) -> Result<(Ordering, Ordering), Error> {
        let lower = self.comparison_q(&enclosure.lower)?;
        let upper = self.comparison_q(&enclosure.upper)?;
        let order = lower.compare(&upper, &mut self.budget).map_err(|_| Error::Resource)?;
        if order.is_gt() {
            return Err(Error::EnclosureOrder);
        }
        if order.is_eq() && !enclosure.lower_included {
            return Err(Error::LowerInclusion);
        }
        if order.is_eq() && !enclosure.upper_included {
            return Err(Error::UpperInclusion);
        }
        let threshold_value = self.comparison_q(threshold)?;
        if !threshold_value.is_zero() {
            return Err(Error::Threshold);
        }
        if threshold != expected {
            return Err(Error::ExpectedThreshold);
        }
        Ok((
            lower
                .compare(&threshold_value, &mut self.budget)
                .map_err(|_| Error::Resource)?,
            upper
                .compare(&threshold_value, &mut self.budget)
                .map_err(|_| Error::Resource)?,
        ))
    }

    fn comparison_inner(
        &mut self,
        comparison: &FloorComparisonV2,
        question: &Question,
        expected: &Expected,
        proof: Option<&DefiningProof<'_>>,
    ) -> Result<(), Error> {
        if question.left != expected.question.left {
            return Err(Error::QuestionLeft);
        }
        if question.right != expected.question.right {
            return Err(Error::QuestionRight);
        }
        match &comparison.result {
            ResultKind::Operational { cause } => {
                if !(1..=7).contains(cause) {
                    return Err(Error::Cause);
                }
            }
            ResultKind::Evaluated {
                reduction,
                predicate: code,
                enclosure,
                threshold,
                relation,
                verdict,
            } => {
                if *reduction > 1 {
                    return Err(Error::Reduction);
                }
                predicate(*code)?;
                if *reduction != expected.reduction {
                    return Err(Error::ExpectedReduction);
                }
                if *code != expected.predicate {
                    return Err(Error::ExpectedPredicate);
                }
                self.comparison_domain(*reduction, question, proof)?;
                if matches!((&question.left, &question.right), (Wall::Rational(_), Wall::Rational(_))) {
                    return Err(Error::ExactEvaluated);
                }
                let (lower, upper) = self.comparison_evaluated(enclosure, threshold, &expected.threshold)?;
                endpoint_verdict(*code, enclosure, lower, upper, *relation, *verdict)?;
            }
            ResultKind::Exact {
                left,
                predicate: code,
                right,
                relation,
                verdict,
            } => {
                if !matches!((&question.left, &question.right), (Wall::Rational(_), Wall::Rational(_))) {
                    return Err(Error::ExactContext);
                }
                let original_left = self.comparison_rational(&question.left)?;
                let original_right = self.comparison_rational(&question.right)?;
                let left = self.comparison_q(left)?;
                if left != original_left {
                    return Err(Error::ExactLeft);
                }
                let right = self.comparison_q(right)?;
                if right != original_right {
                    return Err(Error::ExactRight);
                }
                predicate(*code)?;
                if *code != expected.predicate {
                    return Err(Error::ExpectedPredicate);
                }
                if *relation > 3 {
                    return Err(Error::Relation);
                }
                if *relation == 3 {
                    return Err(Error::ExactUnresolved);
                }
                let order = left.compare(&right, &mut self.budget).map_err(|_| Error::Resource)?;
                let actual_relation = match order {
                    Ordering::Less => 0,
                    Ordering::Equal => 1,
                    Ordering::Greater => 2,
                };
                if *relation != actual_relation {
                    return Err(Error::RelationAgreement);
                }
                if *verdict > 2 {
                    return Err(Error::Verdict);
                }
                if *verdict == 2 {
                    return Err(Error::ExactIndecisive);
                }
                let pass = match code {
                    1 => !order.is_gt(),
                    2 => order.is_lt(),
                    3 => order.is_eq(),
                    4 => !order.is_lt(),
                    5 => order.is_gt(),
                    _ => return Err(Error::Predicate),
                };
                if *verdict != u64::from(!pass) {
                    return Err(Error::VerdictAgreement);
                }
            }
        }
        Ok(())
    }
}

fn with_numeric<T>(
    budget: &mut nrz_cas::limits::Budget,
    check: impl FnOnce(&mut NumericContext) -> Result<T, Error>,
) -> Result<T, Error> {
    let placeholder = nrz_cas::limits::Budget::new(budget.limits().clone()).map_err(|_| Error::Resource)?;
    let mut numeric = NumericContext {
        budget: std::mem::replace(budget, placeholder),
        comparisons: nrz_accuracy::Limits::new(1, 1).start(),
    };
    let result = check(&mut numeric);
    *budget = numeric.budget;
    result
}

impl FloorComparisonV2 {
    /// Check the explicit second edition against an independent original question.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    /// # Errors
    /// Returns the first structural refusal in the recorded order, never a verdict.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "comparison-floor-validate",
            source_item = "numerics::comparison::FloorComparisonV2::validate"
        ),
        ret
    )]
    pub fn validate(
        &self,
        question: &Question,
        expected: &Expected,
        proof: Option<&DefiningProof<'_>>,
        budget: &mut nrz_cas::limits::Budget,
    ) -> Result<(), Error> {
        with_numeric(budget, |numeric| numeric.comparison_inner(self, question, expected, proof))
    }
}

impl ComparisonRecordV2 {
    /// Check retained ridge projections before the nested explicit comparison.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    /// # Errors
    /// Refuses outer binding or the first nested structural violation.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "comparison-ridge-validate",
            source_item = "numerics::comparison::ComparisonRecordV2::validate"
        ),
        ret
    )]
    pub fn validate(
        &self,
        expected_wall: &Wall,
        expected_floor: Floor,
        expected: &Expected,
        proof: Option<&DefiningProof<'_>>,
        budget: &mut nrz_cas::limits::Budget,
    ) -> Result<(), Error> {
        if self.wall != *expected_wall {
            return Err(Error::WallBinding);
        }
        if self.floor != expected_floor {
            return Err(Error::FloorBinding);
        }
        let right = match self.floor {
            Floor::RationalThreeThirtySevenths => Wall::Rational("3/37".into()),
            Floor::RidgeImage => Wall::DefiningRidge(Definition {
                schema: "clean-elasticity-ridge-v1".into(),
                inverse_temperature: "2*ln(2)".into(),
                bleed_squared: "0".into(),
                core_power: "1".into(),
            }),
        };
        let question = Question {
            left: self.wall.clone(),
            right,
        };
        with_numeric(budget, |numeric| {
            numeric.comparison_inner(&self.comparison, &question, expected, proof)
        })
    }
}
