//! Declaration payloads joined to the already validated opaque edition history.
//! (´def:declarations:constants-edition´)
use crate::numerics::{Floor, Literal, Numeraire};
use crate::{DeclarationId, ValidatedRecords, ValidationError, select_effective_declaration};
use std::collections::BTreeSet;

/// A retained source definition, distinct from computed values and rounded displays.
/// (´def:declarations:constants-edition´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstantDefinition {
    /// Original exact literal; the source spelling is retained.
    Literal { name: String, value: Literal },
    /// Exact symbolic definition and its public source label; no approximate evaluation is asserted.
    Expression {
        name: String,
        expression: String,
        source_label: String,
    },
}

/// Proposed public content for one opaque edition; binding validates its complete key set.
/// (´def:declarations:constants-edition´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditionInput {
    /// The previously validated announcement/effective edition identity.
    pub id: DeclarationId,
    /// Explicit floor selection; no default or epoch override.
    pub floor: Floor,
    /// Explicit structural coordinate system.
    pub numeraire: Numeraire,
    /// Public formula edition identifier.
    pub formula_edition: String,
    /// Public controller edition identifier; evaluation belongs to the schedules bite.
    pub controller_edition: String,
    /// Original constant definitions; names are unique within this edition.
    pub constants: Vec<ConstantDefinition>,
    /// Names of explicitly permitted future overrides; the structural floor is excluded.
    pub permitted_overrides: Vec<String>,
    /// Public domain profiles.
    pub domain_profiles: Vec<String>,
    /// Declared exact comparison/refinement procedure identity.
    pub numerical_procedure: String,
    /// Public authentication realization, not secret credentials.
    pub authentication_realization: String,
    /// Public publication profile identity.
    pub publication_profile: String,
}

/// Checked payload, retaining the declaration's definitions rather than a current-price lookup.
/// (´def:declarations:constants-edition´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstantsEdition {
    input: EditionInput,
    floor_source: ConstantDefinition,
}

/// Payload history attached to one immutable validated declaration snapshot.
/// (´def:declarations:constants-edition´)
#[derive(Debug)]
pub struct ConstantsHistory<'a> {
    records: &'a ValidatedRecords,
    editions: Vec<ConstantsEdition>,
}

/// Exhaustive unpublished declaration-content refusals.
/// (´def:declarations:constants-edition´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConstantsError {
    /// Selection still follows the original validated announcement/effective contract.
    #[error("declaration selection: {0}")]
    Selection(#[from] ValidationError),
    /// Every validated identity has exactly one payload and no foreign payload.
    #[error("missing, duplicate or foreign edition payload")]
    EditionSet,
    /// Required public identities and source definitions cannot be empty or duplicated.
    #[error("empty or duplicate constant definition or profile")]
    Definition,
    /// The floor is a structural change, never a permitted epoch override.
    #[error("invalid override permission")]
    Override,
}

/// Bind each payload exactly once to the immutable validated edition set.
/// (´def:declarations:constants-edition´)
///
/// # Errors
/// Refuses foreign, missing or duplicate editions, malformed definitions and floor overrides.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "bind-constants",
        source_item = "constants::bind_constants"
    ),
    ret
)]
pub fn bind_constants(records: &ValidatedRecords, inputs: Vec<EditionInput>) -> Result<ConstantsHistory<'_>, ConstantsError> {
    let result = bind(records, inputs);
    if result.is_err() {
        super::refused();
    }
    result
}

fn bind(records: &ValidatedRecords, inputs: Vec<EditionInput>) -> Result<ConstantsHistory<'_>, ConstantsError> {
    let expected: BTreeSet<_> = records.declarations.iter().map(|d| &d.id).collect();
    let actual: BTreeSet<_> = inputs.iter().map(|d| &d.id).collect();
    if expected != actual || inputs.len() != actual.len() {
        return Err(ConstantsError::EditionSet);
    }
    let mut editions = Vec::with_capacity(inputs.len());
    for input in inputs {
        if [
            &input.formula_edition,
            &input.controller_edition,
            &input.numerical_procedure,
            &input.authentication_realization,
            &input.publication_profile,
        ]
        .iter()
        .any(|s| s.is_empty())
            || input.domain_profiles.is_empty()
            || input.domain_profiles.iter().any(String::is_empty)
            || input.domain_profiles.iter().collect::<BTreeSet<_>>().len() != input.domain_profiles.len()
        {
            return Err(ConstantsError::Definition);
        }
        let mut names = BTreeSet::new();
        for constant in &input.constants {
            let name = match constant {
                ConstantDefinition::Literal { name, .. } => name,
                ConstantDefinition::Expression {
                    name,
                    expression,
                    source_label,
                } => {
                    if expression.is_empty() || source_label.is_empty() {
                        return Err(ConstantsError::Definition);
                    }
                    name
                }
            };
            if name.is_empty() || name == "structural-floor" || !names.insert(name.as_str()) {
                return Err(ConstantsError::Definition);
            }
        }
        let overrides: BTreeSet<_> = input.permitted_overrides.iter().map(String::as_str).collect();
        if overrides.len() != input.permitted_overrides.len() || !overrides.is_subset(&names) {
            return Err(ConstantsError::Override);
        }
        let floor_source = match input.floor {
            Floor::RationalThreeThirtySevenths => ConstantDefinition::Expression {
                name: "structural-floor".into(),
                expression: "3/37".into(),
                source_label: "case:epoch:safety-wall-floor-rational-floor".into(),
            },
            Floor::RidgeImage => ConstantDefinition::Expression {
                name: "structural-floor".into(),
                expression: "p_ridge/(1-p_ridge); p_ridge is the defining ridge real".into(),
                source_label: "case:epoch:safety-wall-floor-ridge-floor".into(),
            },
        };
        editions.push(ConstantsEdition { input, floor_source });
    }
    Ok(ConstantsHistory { records, editions })
}

impl ConstantsHistory<'_> {
    /// Resolve old boundaries through bite 1's selection, then return that edition's own constants.
    /// (´def:declarations:constants-edition´)
    ///
    /// # Errors
    /// Refuses a missing effective edition or a malformed selection key through the original typed cause.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "resolve-constants",
            source_item = "constants::ConstantsHistory < '_ >::resolve"
        ),
        ret
    )]
    pub fn resolve(&self, namespace: &str, name: &str, boundary: u64) -> Result<&ConstantsEdition, ConstantsError> {
        let result = (|| {
            let declaration = select_effective_declaration(self.records, namespace, name, boundary)?;
            self.editions
                .iter()
                .find(|e| e.input.id == declaration.id)
                .ok_or(ConstantsError::EditionSet)
        })();
        if result.is_err() {
            super::refused();
        }
        result
    }
}

impl ConstantsEdition {
    /// Borrow all retained public declaration content; no mutable access is exposed.
    /// (´def:declarations:constants-edition´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn content(&self) -> &EditionInput {
        &self.input
    }

    /// Borrow the exact chosen floor definition and source, never a rounded evaluation.
    /// (´def:declarations:constants-edition´)
    /// Justified: Pure immutable field access inherits the labelled numeric operation that produced this carrier; it performs no numeric computation.
    #[must_use]
    pub fn floor_source(&self) -> &ConstantDefinition {
        &self.floor_source
    }
}
