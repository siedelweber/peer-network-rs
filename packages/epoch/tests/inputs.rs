mod common;

use common::fixture;
use pn_epoch::{InputError, bind_inputs};
use pn_records::constants::bind_constants;
use pn_records::numerics::{ComparisonLimits, ExactLimits, NumericContext};
use pn_records::{validate_history, validate_record};
use std::collections::BTreeMap;

/// Claim: A compiler input retains its effective constants and exact declared unequal profile, refuses foreign and mixed editions, unit mismatch, missing or invalid family profiles, nonpositive self-base and invalid depth mass distinctly, and never substitutes equal weights or rounded literals.
/// ´claim:compiler:boundary-inputs-bind-complete-declared-parameters´
/// ´test:integration:parameter-binding´
#[test]
fn parameter_binding() {
    let (declaration, edition, input) = fixture();
    let empty = validate_history(&[], &[]).unwrap();
    let records = validate_record(&[], &empty, &[declaration]).unwrap();
    let history = bind_constants(&records, vec![edition.clone()]).unwrap();
    let checked = bind_inputs(&history, input.clone(), ExactLimits::default()).unwrap();
    assert_eq!(checked.parameters(), &input);
    assert_eq!(checked.constants().content(), &edition);
    let refuse = |value, cause| assert_eq!(bind_inputs(&history, value, ExactLimits::default()), Err(cause));
    let mut bad = input.clone();
    bad.boundary = 0;
    refuse(bad, InputError::Boundary);
    let mut bad = input.clone();
    bad.edition.edition = 2;
    refuse(bad, InputError::Edition);
    let mut bad = input.clone();
    bad.profiles[0].edition.edition = 2;
    refuse(bad, InputError::MixedEdition);
    let mut bad = input.clone();
    bad.profiles.pop();
    refuse(bad, InputError::MissingProfile);
    let mut bad = input.clone();
    bad.profiles[0].weights.insert("Identity".into(), "negative".into());
    refuse(bad, InputError::NegativeProfile);
    let mut bad = input.clone();
    bad.profiles[0].weights.insert("Identity".into(), "third".into());
    refuse(bad, InputError::ProfileSum);
    let mut bad = input.clone();
    bad.profiles[0].weights = BTreeMap::from([("Economic".into(), "one".into())]);
    refuse(bad, InputError::ProfileSupport);
    let mut bad = input.clone();
    bad.profiles[0].name = "undeclared".into();
    refuse(bad, InputError::ProfileIdentity);
    let mut bad = input.clone();
    bad.profiles[0].family = "unknown".into();
    refuse(bad, InputError::ProfileIdentity);
    let mut bad = input.clone();
    bad.profiles.push(bad.profiles[0].clone());
    refuse(bad, InputError::ProfileIdentity);
    for base in ["zero", "negative"] {
        let mut bad = input.clone();
        bad.self_base = base.into();
        refuse(bad, InputError::SelfBase);
    }
    let mut bad = input.clone();
    bad.self_base = "absent".into();
    refuse(bad, InputError::Constant);
    for depth in [vec![], vec!["third".into()], vec!["negative".into()]] {
        let mut bad = input.clone();
        bad.depth_mass = depth;
        refuse(bad, InputError::DepthMass);
    }
    let mut c = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
    let one = c.literal("1").unwrap();
    let amount = c.burn_per_action(&one, "other").unwrap();
    let mut bad = input;
    bad.numeraire = c.numeraire("nu", &amount).unwrap();
    refuse(bad, InputError::Units);
}
