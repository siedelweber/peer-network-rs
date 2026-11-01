use crate::joined::{act, package_at_numeraires};
use pn_records::CandidateAct;

pub(crate) const BOUNDARY_CASES: &[&str] = &["vintage", "degradation", "repricing", "base", "recoinage"];

pub(crate) struct BoundaryFixture {
    pub acts: Vec<CandidateAct>,
    pub burns: Vec<(&'static str, String)>,
    pub numeraires: [&'static str; 2],
}

pub(crate) fn boundary_fixture(case: &str) -> BoundaryFixture {
    use crate::common::pins::NumberId as N;
    let acts = vec![
        act("Opinion", "seller", 3, 2),
        act("Registration", "buyer", 2, 1),
        act("Registration", "seller", 1, 1),
    ];
    let factor = if matches!(case, "recoinage" | "degradation") {
        N::NumbersScalingFactor.integer()
    } else {
        1
    };
    let burns = [("seller", N::NumbersScalingSellerBurn), ("buyer", N::NumbersScalingBuyerBurn)]
        .into_iter()
        .map(|(actor, pin)| (actor, (pin.integer() * factor).to_string()))
        .collect();
    let base = N::NumbersScalingBaseNumeraire.value();
    let changed = N::NumbersScalingRepricedNumeraire.value();
    let numeraires = match case {
        "recoinage" | "repricing" => [changed, changed],
        "vintage" => [base, changed],
        "base" | "degradation" => [base, base],
        _ => panic!("undeclared boundary case"),
    };
    BoundaryFixture { acts, burns, numeraires }
}

pub(crate) fn boundary_package(input: &BoundaryFixture) -> pn_epoch::package::VerifiedPackage {
    let burns: Vec<_> = input.burns.iter().map(|(actor, value)| (*actor, value.as_str())).collect();
    package_at_numeraires(
        &input.acts,
        2,
        &burns,
        crate::common::pins::NumberId::NumbersScalingWall.value(),
        &input.numeraires,
    )
}
