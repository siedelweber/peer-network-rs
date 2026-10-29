//! Exact structural compiler inputs; no publication encoding or standing solve.
//! (´def:compiler:boundary-inputs´)

use std::collections::{BTreeMap, BTreeSet};

use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use pn_records::{
    DeclarationId,
    constants::{ConstantDefinition, ConstantsEdition, ConstantsError, ConstantsHistory},
    numerics::Numeraire,
};

/// One family's explicitly published domain weights, bound to a constants edition.
/// (´def:compiler:boundary-inputs´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyProfile {
    /// Exact family name from the authored census.
    pub family: String,
    /// Declared profile name; no inferred equal split.
    pub name: String,
    /// Edition publishing this interpretation.
    pub edition: DeclarationId,
    /// Literal constant names by domain; omitted domains have weight zero.
    pub weights: BTreeMap<String, String>,
}

/// Untrusted structural parameter interpretation, not a canonical document.
/// (´def:compiler:boundary-inputs´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterInput {
    pub boundary: u64,
    pub edition: DeclarationId,
    pub numeraire: Numeraire,
    pub profiles: Vec<FamilyProfile>,
    /// Name of the positive self-retention literal in the effective edition.
    pub self_base: String,
    /// Literal constant names for depths one through the vector length.
    pub depth_mass: Vec<String>,
}

/// Immutable checked parameters; callers cannot replace an edition or profile after validation.
/// (´def:compiler:boundary-inputs´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompilerInputs {
    parameters: ParameterInput,
    constants: ConstantsEdition,
}

/// Distinct structural and bounded-arithmetic refusals.
/// (´def:compiler:boundary-inputs´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    #[error("constants selection: {0}")]
    Constants(#[from] ConstantsError),
    #[error("exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
    #[error("boundary zero is not a compiling epoch")]
    Boundary,
    #[error("input edition differs from the effective edition")]
    Edition,
    #[error("profile mixes constants editions")]
    MixedEdition,
    #[error("unit or numeraire differs from the effective edition")]
    Units,
    #[error("missing or unsupported literal constant")]
    Constant,
    #[error("family profile missing")]
    MissingProfile,
    #[error("duplicate or unknown family or undeclared profile")]
    ProfileIdentity,
    #[error("negative profile weight")]
    NegativeProfile,
    #[error("profile does not sum to one")]
    ProfileSum,
    #[error("profile supported outside the family's projection domains")]
    ProfileSupport,
    #[error("self retention must be positive")]
    SelfBase,
    #[error("depth mass must be nonempty, nonnegative and sum to one")]
    DepthMass,
}

/// Bind one boundary's interpreted parameters to its effective constants edition.
/// (´[ROOT-sig:design:epoch]´)
///
/// Authentication and canonical encoding remain at their existing boundaries.
/// # Errors
/// Returns the specific structural refusal or exact resource failure; never a partial input.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "bind_inputs"
    ),
    ret
)]
pub fn bind_inputs(history: &ConstantsHistory<'_>, input: ParameterInput, limits: Limits) -> Result<CompilerInputs, InputError> {
    if input.boundary == 0 {
        return Err(InputError::Boundary);
    }
    let constants = history.resolve("numeric", "constants", input.boundary)?;
    let edition = constants.content();
    if input.edition != edition.id {
        return Err(InputError::Edition);
    }
    if input.numeraire != edition.numeraire {
        return Err(InputError::Units);
    }
    let mut budget = Budget::new(limits)?;
    let mut families = BTreeSet::new();
    for profile in &input.profiles {
        if profile.edition != input.edition {
            return Err(InputError::MixedEdition);
        }
        let domains = projection_domains(&profile.family).ok_or(InputError::ProfileIdentity)?;
        if !families.insert(profile.family.as_str()) || !edition.domain_profiles.contains(&profile.name) {
            return Err(InputError::ProfileIdentity);
        }
        let mut sum = Rational::parse("0", &mut budget)?;
        for (domain, spelling) in &profile.weights {
            let weight = constant(constants, spelling, &mut budget)?;
            if weight.is_negative() {
                return Err(InputError::NegativeProfile);
            }
            if !weight.is_zero() && !domains.contains(&domain.as_str()) {
                return Err(InputError::ProfileSupport);
            }
            sum = sum.add(&weight, &mut budget)?;
        }
        if sum.exact_string(&mut budget)? != "1" {
            return Err(InputError::ProfileSum);
        }
    }
    if families.len() != 19 {
        return Err(InputError::MissingProfile);
    }
    let base = constant(constants, &input.self_base, &mut budget)?;
    if base.is_negative() || base.is_zero() {
        return Err(InputError::SelfBase);
    }
    let mut sum = Rational::parse("0", &mut budget)?;
    for spelling in &input.depth_mass {
        let mass = constant(constants, spelling, &mut budget)?;
        if mass.is_negative() {
            return Err(InputError::DepthMass);
        }
        sum = sum.add(&mass, &mut budget)?;
    }
    if sum.exact_string(&mut budget)? != "1" {
        return Err(InputError::DepthMass);
    }
    Ok(CompilerInputs {
        parameters: input,
        constants: constants.clone(),
    })
}

fn constant(edition: &ConstantsEdition, name: &str, budget: &mut Budget) -> Result<Rational, InputError> {
    let value = edition
        .content()
        .constants
        .iter()
        .find_map(|definition| match definition {
            ConstantDefinition::Literal { name: candidate, value } if candidate == name => Some(value),
            _ => None,
        })
        .ok_or(InputError::Constant)?;
    Ok(Rational::parse(value.exact(), budget)?)
}

impl CompilerInputs {
    /// Borrow the checked structural interpretation without changing it.
    /// (´def:compiler:boundary-inputs´)
    /// Justified: Immutable carrier access inherits the enclosing validation operation.
    #[must_use]
    pub fn parameters(&self) -> &ParameterInput {
        &self.parameters
    }

    /// Borrow the entire effective edition retained at validation.
    /// (´def:compiler:boundary-inputs´)
    /// Justified: Immutable carrier access inherits the enclosing validation operation.
    #[must_use]
    pub fn constants(&self) -> &ConstantsEdition {
        &self.constants
    }
}

fn projection_domains(family: &str) -> Option<&'static [&'static str]> {
    match family {
        "Registration" => Some(&["Identity"]),
        "Publish" | "Owner" | "Bid" => Some(&["Economic"]),
        "Opinion" => Some(&["Tribal"]),
        "Affinity" | "Tag" => Some(&["Epistemic"]),
        "Participant" | "Invitation" => Some(&["Relational", "Epistemic"]),
        "Review" | "Reference" => Some(&["Tribal", "Epistemic"]),
        "Join Request" | "Accept" | "Ratify" => Some(&["Relational"]),
        "Send" => Some(&["Relational", "Minimal"]),
        "De-invite" | "Leave" | "Withdraw" | "Rescind" => Some(&["Minimal"]),
        _ => None,
    }
}
