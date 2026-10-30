use nrz_cas::limits::Limits;
use pn_epoch::{
    cells::{CellIdentity, StandingCell},
    coefficients::{CoefficientError, MANDATORY_COORDINATES, coefficient},
};
use std::collections::{BTreeMap, BTreeSet};

fn cell(family: &str, entries: &[(&str, &str)]) -> StandingCell {
    StandingCell {
        identity: CellIdentity {
            author: "author".into(),
            family: family.into(),
            incidence: vec![],
            singleton: None,
        },
        members: BTreeSet::new(),
        coordinates: entries
            .iter()
            .map(|(name, value)| ((*name).into(), (*value).into()))
            .collect(),
    }
}

/// Claim: The mandatory-coordinate census names all nineteen families and agrees with an independent literal table; empty sets weigh one, single coordinates use their magnitude, and Invitation uses its mandatory A-leg pair.
/// ´claim:compiler:mandatory-coordinate-census-covers-nineteen-families´
/// ´test:integration:coefficient-census´
#[test]
fn coefficient_census() {
    let expected: BTreeMap<_, Vec<_>> = [
        ("Opinion", vec!["polarity", "reaction"]),
        ("Reference", vec!["effort", "enthusiasm"]),
        ("Invitation", vec!["formality", "urgency"]),
        ("Accept", vec!["comfort", "equity"]),
        ("Ratify", vec!["comfort", "equity"]),
        ("Publish", vec!["attachment"]),
        ("Owner", vec!["attachment"]),
        ("Affinity", vec!["association", "attraction"]),
        ("Tag", vec!["confidence", "relevance"]),
        ("Review", vec!["effort", "enthusiasm"]),
        ("Send", vec!["importance"]),
        ("Bid", vec!["generosity", "urgency"]),
        ("Join Request", vec!["formality", "urgency"]),
        ("Participant", vec!["interactivity", "responsibility"]),
        ("Registration", vec![]),
        ("Withdraw", vec![]),
        ("Rescind", vec![]),
        ("Leave", vec![]),
        ("De-invite", vec![]),
    ]
    .into_iter()
    .collect();
    let actual: BTreeMap<_, _> = MANDATORY_COORDINATES
        .into_iter()
        .map(|(family, names)| {
            let mut names = names.to_vec();
            names.sort_unstable();
            (family, names)
        })
        .collect();
    assert_eq!(actual.len(), 19);
    assert_eq!(actual, expected);
    for (family, names) in &expected {
        let entries: Vec<_> = names.iter().map(|name| (*name, "-1/2")).collect();
        let result = coefficient(&cell(family, &entries), Limits::default());
        assert_eq!(result.unwrap(), if names.is_empty() { "1" } else { "1/2" });
    }
}

/// Claim: Exact rational geometric means use mandatory magnitudes, including zero and hostile coordinates; nonsquare products return a typed irrational-evidence hold and never an approximation. Independent integer-square tables and rational probe bounds distinguish the held cases.
/// ´claim:compiler:coefficients-are-exact-or-held-with-numeric-evidence´
/// ´test:integration:coefficient-evidence´
#[test]
fn coefficient_evidence() {
    for (left, right, expected) in [
        ("1/4", "1", "1/2"),
        ("-1/4", "1", "1/2"),
        ("-1/4", "-1", "1/2"),
        ("0", "-1/3", "0"),
        ("4/9", "1/4", "1/3"),
        ("1", "1", "1"),
    ] {
        assert_eq!(
            coefficient(
                &cell("Opinion", &[("polarity", left), ("reaction", right)]),
                Limits::default()
            )
            .unwrap(),
            expected
        );
    }
    // Independent finite oracle: the complete integer square table in 0..=16.
    let squares: BTreeMap<u64, &str> = [(0, "0"), (1, "1/4"), (4, "1/2"), (9, "3/4"), (16, "1")]
        .into_iter()
        .collect();
    for numerator in 0..=16 {
        let value = format!("{numerator}/16");
        let result = coefficient(
            &cell("Opinion", &[("polarity", &value), ("reaction", "1")]),
            Limits::default(),
        );
        if let Some(expected) = squares.get(&numerator) {
            assert_eq!(result.unwrap(), *expected);
        } else {
            assert!(matches!(result, Err(CoefficientError::Irrational { .. })));
        }
    }
    // sqrt(1/2) lies strictly inside (70/100, 71/100), by integer products.
    assert!(70_u64.pow(2) * 2 < 100_u64.pow(2));
    assert!(71_u64.pow(2) * 2 > 100_u64.pow(2));
    assert_eq!(
        coefficient(&cell("Opinion", &[("polarity", "1/2"), ("reaction", "1")]), Limits::default()),
        Err(CoefficientError::Irrational { radicand: "1/2".into() })
    );
    // Large perfect-square components exercise more than a machine-word radicand.
    let value = "10000000000000000000200000000000000000001/1000000000000000000000000000000000000000000";
    assert_eq!(
        coefficient(&cell("Opinion", &[("polarity", value), ("reaction", "1")]), Limits::default()).unwrap(),
        "100000000000000000001/1000000000000000000000"
    );
}

/// Claim: The coefficient boundary refuses unknown families, missing or extra mandatory coordinates and out-of-range inputs, without interpreting them as an irrational hold or returning partial evidence.
/// ´claim:compiler:coefficient-inputs-are-bounded-and-complete´
/// ´test:integration:coefficient-refusals´
#[test]
fn coefficient_refusals() {
    for value in [
        cell("unknown", &[]),
        cell("Opinion", &[("polarity", "1")]),
        cell("Registration", &[("extra", "0")]),
        cell("Send", &[("importance", "2")]),
        cell("Send", &[("importance", "-2")]),
    ] {
        assert_eq!(coefficient(&value, Limits::default()), Err(CoefficientError::Representation));
    }
    assert!(matches!(
        coefficient(&cell("Send", &[("importance", "1/0")]), Limits::default()),
        Err(CoefficientError::Arithmetic(_))
    ));
}
