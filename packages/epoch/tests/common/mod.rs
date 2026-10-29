use std::collections::BTreeMap;

use pn_epoch::{FamilyProfile, ParameterInput};
use pn_records::constants::{ConstantDefinition, EditionInput};
use pn_records::numerics::{ComparisonLimits, ExactLimits, Floor, NumericContext};
use pn_records::{Declaration, DeclarationContent, DeclarationId};

pub(crate) fn fixture() -> (Declaration, EditionInput, ParameterInput) {
    let mut c = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
    let one = c.literal("1").unwrap();
    let unit = c.burn_per_action(&one, "burn").unwrap();
    let numeraire = c.numeraire("nu", &unit).unwrap();
    let id = DeclarationId {
        namespace: "numeric".into(),
        name: "constants".into(),
        edition: 1,
    };
    let declaration = Declaration {
        id: id.clone(),
        announced_at: 0,
        effective_at: 1,
        content: DeclarationContent::Opaque,
    };
    let definitions = [
        ("one", "1"),
        ("zero", "0"),
        ("negative", "-1/3"),
        ("third", "1/3"),
        ("rest", "2/3"),
    ]
    .into_iter()
    .map(|(name, value)| ConstantDefinition::Literal {
        name: name.into(),
        value: c.literal(value).unwrap(),
    })
    .collect();
    let edition = EditionInput {
        id: id.clone(),
        floor: Floor::RationalThreeThirtySevenths,
        numeraire: numeraire.clone(),
        formula_edition: "formula".into(),
        controller_edition: "controller".into(),
        constants: definitions,
        permitted_overrides: vec![],
        domain_profiles: vec!["declared".into()],
        numerical_procedure: "exact-rational".into(),
        authentication_realization: "declared".into(),
        publication_profile: "internal".into(),
    };
    let mut profiles: Vec<_> = [
        ("Registration", "Identity"),
        ("Publish", "Economic"),
        ("Owner", "Economic"),
        ("Bid", "Economic"),
        ("Opinion", "Tribal"),
        ("Affinity", "Epistemic"),
        ("Tag", "Epistemic"),
        ("Participant", "Relational"),
        ("Invitation", "Relational"),
        ("Review", "Tribal"),
        ("Reference", "Epistemic"),
        ("Join Request", "Relational"),
        ("Accept", "Relational"),
        ("Ratify", "Relational"),
        ("Send", "Minimal"),
        ("De-invite", "Minimal"),
        ("Leave", "Minimal"),
        ("Withdraw", "Minimal"),
        ("Rescind", "Minimal"),
    ]
    .into_iter()
    .map(|(family, domain)| FamilyProfile {
        family: family.into(),
        name: "declared".into(),
        edition: id.clone(),
        weights: BTreeMap::from([(domain.into(), "one".into())]),
    })
    .collect();
    profiles[7].weights = BTreeMap::from([("Relational".into(), "third".into()), ("Epistemic".into(), "rest".into())]);
    let input = ParameterInput {
        boundary: 1,
        edition: id,
        numeraire,
        profiles,
        self_base: "one".into(),
        depth_mass: vec!["third".into(), "rest".into()],
    };
    (declaration, edition, input)
}
