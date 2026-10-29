//! Exact rational coefficients; irrational results remain explicit evidence holds.
//! (´def:compiler:cell-coefficients´)

use crate::cells::StandingCell;
use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};

/// Mandatory authored coordinates from the nineteen-family census.
/// Invitation is enumerated but its cell compilation remains held.
/// (´def:compiler:cell-coefficients´)
pub const MANDATORY_COORDINATES: [(&str, &[&str]); 19] = [
    ("Registration", &[]),
    ("Publish", &["attachment"]),
    ("Owner", &["attachment"]),
    ("Affinity", &["association", "attraction"]),
    ("Opinion", &["polarity", "reaction"]),
    ("Tag", &["relevance", "confidence"]),
    ("Review", &["enthusiasm", "effort"]),
    ("Reference", &["enthusiasm", "effort"]),
    ("Send", &["importance"]),
    ("Bid", &["generosity", "urgency"]),
    ("Join Request", &["urgency", "formality"]),
    ("Participant", &["interactivity", "responsibility"]),
    ("Invitation", &["urgency", "formality"]),
    ("Accept", &["comfort", "equity"]),
    ("Ratify", &["comfort", "equity"]),
    ("Withdraw", &[]),
    ("Rescind", &[]),
    ("Leave", &[]),
    ("De-invite", &[]),
];

/// Exact-only evidence boundary; no approximate coefficient can escape a hold.
/// (´def:compiler:cell-coefficients´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CoefficientError {
    #[error("exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
    #[error("Invitation withdrawal awaits the next minor edition")]
    InvitationEdition,
    #[error("unknown family, wrong mandatory coordinates or out-of-range value")]
    Representation,
    #[error("irrational coefficient needs numeric evidence: square root of {radicand}")]
    Irrational { radicand: String },
}

/// Price mandatory folded magnitudes, independently of recipient resolution.
/// The returned spelling is an exact rational, not a canonical byte encoding.
/// (´def:compiler:cell-coefficients´)
/// # Errors
/// Returns a typed edition or irrational-evidence hold, malformed cell refusal,
/// or exact arithmetic resource failure; it never substitutes an approximation.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "coefficients::coefficient"
    ),
    ret
)]
pub fn coefficient(cell: &StandingCell, limits: Limits) -> Result<String, CoefficientError> {
    if cell.identity.family == "Invitation" {
        return Err(CoefficientError::InvitationEdition);
    }
    let names = MANDATORY_COORDINATES
        .iter()
        .find(|(family, _)| *family == cell.identity.family)
        .map(|(_, names)| *names)
        .ok_or(CoefficientError::Representation)?;
    if cell.coordinates.len() != names.len() {
        return Err(CoefficientError::Representation);
    }
    let mut budget = Budget::new(limits)?;
    let one = Rational::parse("1", &mut budget)?;
    let mut product = one.clone();
    for name in names {
        let mut value = Rational::parse(
            cell.coordinates.get(*name).ok_or(CoefficientError::Representation)?,
            &mut budget,
        )?;
        if value.is_negative() {
            value = value.negated(&mut budget)?;
        }
        if value.compare(&one, &mut budget)?.is_gt() {
            return Err(CoefficientError::Representation);
        }
        product = product.mul(&value, &mut budget)?;
    }
    let spelling = product.exact_string(&mut budget)?;
    if names.len() < 2 || product.is_zero() {
        return Ok(spelling);
    }
    let (numerator, denominator) = spelling.split_once('/').unwrap_or((&spelling, "1"));
    let n = integer_root(numerator, &mut budget)?;
    let d = integer_root(denominator, &mut budget)?;
    match (n, d) {
        (Some(n), Some(d)) => Ok(n.div(&d, &mut budget)?.exact_string(&mut budget)?),
        _ => Err(CoefficientError::Irrational { radicand: spelling }),
    }
}

// Decimal digit extraction uses only the existing prepaid exact arithmetic.
// At each step root is floor(sqrt(prefix)); the next digit lies in 0..=9.
// No floating-point estimate or new numeric dependency enters this boundary.
fn integer_root(spelling: &str, budget: &mut Budget) -> Result<Option<Rational>, CoefficientError> {
    let padded = if spelling.len() % 2 == 0 {
        spelling.to_owned()
    } else {
        format!("0{spelling}")
    };
    let ten = Rational::parse("10", budget)?;
    let hundred = Rational::parse("100", budget)?;
    let mut prefix = Rational::parse("0", budget)?;
    let mut root = prefix.clone();
    for digits in padded.as_bytes().as_chunks::<2>().0 {
        let pair = u16::from(digits[0] - b'0') * 10 + u16::from(digits[1] - b'0');
        prefix = prefix
            .mul(&hundred, budget)?
            .add(&Rational::parse(&pair.to_string(), budget)?, budget)?;
        let base = root.mul(&ten, budget)?;
        for digit in (0..=9).rev() {
            let candidate = base.add(&Rational::parse(&digit.to_string(), budget)?, budget)?;
            if !candidate.mul(&candidate, budget)?.compare(&prefix, budget)?.is_gt() {
                root = candidate;
                break;
            }
        }
    }
    Ok((root.mul(&root, budget)? == prefix).then_some(root))
}
