use pn_records::burn::{AcceptedSet, BurnError, Disclosure, Encoding, OperatorEvidence, validate_burn};
use pn_records::test_support::burn as fixtures;
use std::collections::BTreeSet;

/// Claim: Removing each required disclosure prevents readiness even when arithmetic does not read it; explicit empty event costs and explained operator absence remain valid publications.
/// ´claim:burn:missing-required-burn-disclosures-prevent-readiness´
/// ´test:integration:required-disclosures´
#[test]
fn required_disclosures() {
    let base = fixtures::generate(&[3]).burn;
    assert_eq!(validate_burn(base.clone()).unwrap().publication(), &base);
    for field in [
        Disclosure::AddressSpace,
        Disclosure::Edition,
        Disclosure::SampleConvention,
        Disclosure::Bootstrap,
        Disclosure::UnitCost,
        Disclosure::SettlementDepth,
        Disclosure::Finality,
        Disclosure::Provenance,
        Disclosure::RecordingCosts,
        Disclosure::Operator,
    ] {
        let mut input = base.clone();
        match field {
            Disclosure::AddressSpace => input.address_space.clear(),
            Disclosure::Edition => input.edition.clear(),
            Disclosure::SampleConvention => input.sample_convention.clear(),
            Disclosure::Bootstrap => input.bootstrap = None,
            Disclosure::UnitCost => input.unit_cost = None,
            Disclosure::SettlementDepth => input.evidence.settlement_depth = None,
            Disclosure::Finality => input.evidence.finality_assumptions = None,
            Disclosure::Provenance => input.evidence.provenance = None,
            Disclosure::RecordingCosts => input.evidence.recording_costs = None,
            Disclosure::Operator => input.evidence.operator = None,
        }
        assert_eq!(validate_burn(input), Err(BurnError::Publication(field)));
    }
    let mut mismatched = base.clone();
    mismatched.evidence.edition = "other-edition".into();
    assert_eq!(validate_burn(mismatched), Err(BurnError::EvidenceBinding));
    let mut mismatched = base.clone();
    mismatched.evidence.sample_convention = "other-convention".into();
    assert_eq!(validate_burn(mismatched), Err(BurnError::EvidenceBinding));
    let mut unexplained = base.clone();
    unexplained.bootstrap.as_mut().unwrap().explanation.clear();
    assert_eq!(validate_burn(unexplained), Err(BurnError::Publication(Disclosure::Bootstrap)));
    let mut bounded = base;
    let bound = bounded.bootstrap.as_ref().unwrap().bound.clone();
    bounded.evidence.operator = Some(OperatorEvidence::Bound {
        amount: bound.clone(),
        proof: "public fixture derivation".into(),
    });
    assert!(validate_burn(bounded.clone()).is_ok());
    bounded.evidence.operator = Some(OperatorEvidence::Bound {
        amount: bound,
        proof: String::new(),
    });
    assert_eq!(validate_burn(bounded), Err(BurnError::Publication(Disclosure::Operator)));
}

/// Claim: Zero-index recognition requires the policy's initial name, no predecessor and empty acceptance and snapshot; immediate unique successors retain fixed policy and interpretation content rather than treating the name alone as identity.
/// ´claim:burn:markers-fix-initial-state-and-succession´
/// ´test:integration:initial-and-identity´
#[test]
fn initial_and_identity() {
    let base = fixtures::generate(&[]);
    for variant in 0..4 {
        let mut case = base.clone();
        let first = &mut case.history.markers[0];
        match variant {
            0 => first.predecessor = Some("foreign".into()),
            1 => first.accepted = AcceptedSet::CompleteList(BTreeSet::from(["r0".into()])),
            2 => first.initial_snapshot = Some(case.burn.amounts.clone()),
            _ => first.name = "other".into(),
        }
        assert_eq!(fixtures::recognize(case), Err(BurnError::Initial));
    }
    let original = fixtures::recognize(base.clone()).unwrap();
    let mut changed = base;
    changed.history.markers[1].accepted = AcceptedSet::CompleteList(BTreeSet::new());
    let altered = fixtures::recognize(changed).unwrap();
    assert_ne!(original.markers()[1].identity(), altered.markers()[1].identity());
    assert_eq!(original.markers()[1].identity().name, altered.markers()[1].identity().name);
}

/// Claim: Complete lists and unique binding public openings recover the same finite sets under their declared policies; whole-prefix acceptance uses all lineage only when explicitly selected, and invalid unaccepted records need not become burns.
/// ´claim:burn:public-openings-recover-complete-policy-sets´
/// ´test:integration:policy-encodings´
#[test]
fn policy_encodings() {
    let base = fixtures::generate(&[]);
    let listed = fixtures::recognize(base.clone()).unwrap();
    let mut commitment = base.clone();
    fixtures::committed(&mut commitment);
    let opened = fixtures::recognize(commitment).unwrap();
    for (left, right) in listed.markers().iter().zip(opened.markers()) {
        assert_eq!(left.accepted(), right.accepted());
        assert_eq!(left.destructions(), right.destructions());
    }
    let mut prefix = base.clone();
    prefix.policy.encoding = Encoding::WholePrefixAcceptAll;
    for marker in &mut prefix.history.markers {
        marker.accepted = AcceptedSet::WholePrefix;
    }
    let whole = fixtures::recognize(prefix).unwrap();
    assert_eq!(whole.markers()[1].accepted(), &BTreeSet::from(["r0".into(), "r1".into()]));
    let mut pending = base;
    pending.history.markers.truncate(2);
    pending.history.records[1].evidence.clear();
    assert!(fixtures::recognize(pending).is_ok());
}

/// Claim: Copied marker contents lose recognition when this history omits a lineage member or predecessor; a separately identified alternative history is checked against its own predecessors without cross-history acceptance bounds.
/// ´claim:burn:recognition-requires-one-complete-history´
/// ´test:integration:history-dependence´
#[test]
fn history_dependence() {
    for (name, cause) in [
        ("lost-lineage", BurnError::MissingLineage),
        ("lost-predecessor", BurnError::Succession),
    ] {
        let mut case = fixtures::generate(&[]);
        fixtures::corrupt(&mut case, name);
        assert_eq!(fixtures::recognize(case), Err(cause));
    }
    let base = fixtures::generate(&[]);
    let first = fixtures::recognize(base.clone()).unwrap();
    let mut alternative = base;
    alternative.history.identity = "alternative".into();
    for marker in &mut alternative.history.markers {
        marker.history = "alternative".into();
        marker.accepted = AcceptedSet::CompleteList(BTreeSet::new());
    }
    let second = fixtures::recognize(alternative).unwrap();
    assert_ne!(first.history(), second.history());
    assert!(second.markers().last().unwrap().accepted().is_empty());
}

/// Claim: Consistent aliases accepted together or later retain one destruction representative with its original amount and address; changed alias attribution or amount refuses rather than contributing twice, without deriving an increment or snapshot.
/// ´claim:burn:destruction-aliases-retain-one-contribution-identity´
/// ´test:integration:alias-deduplication´
#[test]
fn alias_deduplication() {
    let case = fixtures::generate(&[9]);
    let result = fixtures::recognize(case.clone()).unwrap();
    assert_eq!(result.markers()[1].destructions().len(), 1);
    assert_eq!(result.markers()[2].accepted().len(), 3);
    assert_eq!(result.markers()[2].destructions().len(), 2);
    assert_eq!(
        result.markers()[1].destructions()["d0"].amount,
        result.markers()[2].destructions()["d0"].amount
    );
    for name in ["alias-address", "alias-amount"] {
        let mut bad = case.clone();
        fixtures::corrupt(&mut bad, name);
        assert_eq!(fixtures::recognize(bad), Err(BurnError::InconsistentAlias));
    }
    let mut same = case;
    same.history.markers[1].lineage.insert("alias".into());
    same.history.markers[1].accepted = AcceptedSet::CompleteList(BTreeSet::from(["r0".into(), "alias".into()]));
    assert_eq!(fixtures::recognize(same).unwrap().markers()[1].destructions().len(), 1);
}
