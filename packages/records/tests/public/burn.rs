use pn_records::burn::{AcceptedSet, BurnError, Disclosure, Encoding, OperatorEvidence, validate_burn};
use pn_records::test_support::burn as fixtures;
use std::collections::BTreeSet;

/// Claim: Only the marker/policy edition effective at genesis binds; a later announcement,
/// absent family, wrong identity, edition or publication cannot authorize recognition.
/// ´claim:burn:genesis-policy-requires-effective-declaration´
/// ´test:integration:policy-declaration-binding´
#[test]
fn policy_declaration_binding() {
    use pn_records::constants::bind_marker_policy;
    use pn_records::{Declaration, DeclarationId, ValidationError, validate_history, validate_record};
    let fixture = fixtures::generate(&[3]);
    let burn = validate_burn(fixture.burn).unwrap();
    let history = validate_history(&[], &[]).unwrap();
    let declaration = Declaration {
        id: DeclarationId {
            namespace: "marker".into(),
            name: "policy".into(),
            edition: 1,
        },
        announced_at: 0,
        effective_at: 0,
    };
    let records = validate_record(&[], &history, std::slice::from_ref(&declaration)).unwrap();
    assert!(bind_marker_policy(&records, fixture.policy.clone(), &burn).is_ok());
    for field in ["identity", "edition", "publication"] {
        let mut policy = fixture.policy.clone();
        match field {
            "identity" => policy.identity = "other".into(),
            "edition" => policy.edition = "2".into(),
            _ => {
                policy.published_at = 1;
                policy.genesis_at = 2;
            }
        }
        assert_eq!(bind_marker_policy(&records, policy, &burn), Err(BurnError::PolicyBinding));
    }
    let mut late = declaration;
    late.announced_at = fixture.policy.genesis_at + 1;
    late.effective_at = late.announced_at;
    for declarations in [vec![], vec![late]] {
        let records = validate_record(&[], &history, &declarations).unwrap();
        assert_eq!(
            bind_marker_policy(&records, fixture.policy.clone(), &burn),
            Err(BurnError::PolicySelection(ValidationError::MissingDeclaration {
                namespace: "marker".into(),
                name: "policy".into(),
                boundary: fixture.policy.genesis_at,
            }))
        );
    }
}

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

/// Claim: For an index-zero candidate, changing the initial name, predecessor, empty acceptance or empty snapshot refuses it; changing a valid successor's acceptance changes structural identity while its lookup name remains the same.
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
        assert_eq!(
            fixtures::recognize(case).unwrap().first_refusal().map(|f| &f.cause),
            Some(&BurnError::Initial)
        );
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
    assert!(fixtures::recognize(pending).unwrap().first_refusal().is_none());
}

/// Claim: A missing lineage member or predecessor stops recognition at the affected candidate, retaining earlier markers; a separately identified alternative history is checked against its own predecessors without cross-history acceptance bounds.
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
        let result = fixtures::recognize(case).unwrap();
        assert_eq!(result.first_refusal().map(|f| &f.cause), Some(&cause));
        assert_eq!(result.markers().len(), 1);
        assert_eq!(result.markers()[0].identity().name, "m0");
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
        assert_eq!(
            fixtures::recognize(bad).unwrap().first_refusal().map(|f| &f.cause),
            Some(&BurnError::InconsistentAlias)
        );
    }
    let mut same = case;
    same.history.markers[1].lineage.insert("alias".into());
    same.history.markers[1].accepted = AcceptedSet::CompleteList(BTreeSet::from(["r0".into(), "alias".into()]));
    assert_eq!(fixtures::recognize(same).unwrap().markers()[1].destructions().len(), 1);
}

/// Claim: Under either declared selection rule, an invalid last candidate preserves the two valid predecessors and reports its exact refusal; no dependent successor crosses the gap.
/// ´claim:burn:invalid-candidates-preserve-recognized-predecessors´
/// ´test:integration:invalid-candidate-prefix´
#[test]
fn invalid_candidate_prefix() {
    use pn_records::burn::CandidateRule;
    for rule in [CandidateRule::UniquePerIndex, CandidateRule::FirstValidInHistoryOrder] {
        let mut case = fixtures::generate(&[]);
        case.policy.candidate_rule = rule;
        let prefix = fixtures::recognize(case.clone()).unwrap().markers()[..2].to_vec();
        case.history.records[2].evidence.clear();
        let mut successor = case.history.markers[2].clone();
        successor.name = "m3".into();
        successor.index = 3;
        successor.predecessor = Some("m2".into());
        case.history.markers.push(successor);
        let result = fixtures::recognize(case).unwrap();
        assert_eq!(result.markers(), prefix);
        let refusal = result.first_refusal().unwrap();
        assert_eq!(refusal.candidate.as_ref().unwrap().name, "m2");
        assert_eq!(refusal.cause, BurnError::InvalidMember);
    }
}

/// Claim: Competing candidates preserve earlier markers; the unique-index assumption stops before that index, while first-valid selection chooses in history order and retains the first rejection when a later competitor passes.
/// ´claim:burn:declared-policy-selects-competing-candidates´
/// ´test:integration:competing-candidates´
#[test]
fn competing_candidates() {
    use pn_records::burn::CandidateRule;
    let base = fixtures::generate(&[]);
    let prefix = fixtures::recognize(base.clone()).unwrap().markers()[..2].to_vec();
    let mut competing = base.clone();
    let mut other = competing.history.markers[2].clone();
    other.name = "other-m2".into();
    competing.history.markers.insert(2, other);
    let unique = fixtures::recognize(competing.clone()).unwrap();
    assert_eq!(unique.markers(), prefix);
    assert_eq!(unique.first_refusal().unwrap().cause, BurnError::Succession);
    competing.policy.candidate_rule = CandidateRule::FirstValidInHistoryOrder;
    let first = fixtures::recognize(competing.clone()).unwrap();
    assert_eq!(&first.markers()[..2], prefix);
    assert_eq!(first.markers()[2].identity().name, "other-m2");
    assert!(first.first_refusal().is_none());
    competing.history.markers.swap(2, 3);
    assert_eq!(
        fixtures::recognize(competing.clone()).unwrap().markers()[2].identity().name,
        "m2"
    );
    competing.history.markers[2].accepted = AcceptedSet::CompleteList(BTreeSet::from(["r1".into()]));
    let fallback = fixtures::recognize(competing).unwrap();
    assert_eq!(&fallback.markers()[..2], prefix);
    assert_eq!(fallback.markers()[2].identity().name, "other-m2");
    assert_eq!(fallback.first_refusal().unwrap().cause, BurnError::RegressedAcceptance);
}

/// Claim: Each newly isolated premise refuses with its own cause from an otherwise valid fixture: index origin, predecessor name, successor snapshot, policy identity and sequence, burn unit, and explained operator absence.
/// ´claim:burn:isolated-premises-have-exact-refusals´
/// ´test:integration:isolated-recognition-premises´
#[test]
fn isolated_recognition_premises() {
    for (name, expected) in [
        ("initial-index", BurnError::Initial),
        ("predecessor-name", BurnError::Succession),
        ("successor-snapshot", BurnError::Succession),
        ("policy-identity", BurnError::HistoryPolicy),
        ("policy-sequence", BurnError::HistoryPolicy),
        ("burn-unit", BurnError::Units),
        ("unexplained-operator", BurnError::Publication(Disclosure::Operator)),
    ] {
        let mut input = fixtures::generate(&[5]);
        assert!(fixtures::recognize(input.clone()).unwrap().first_refusal().is_none());
        fixtures::corrupt(&mut input, name);
        let cause = fixtures::recognize(input).map_or_else(Some, |r| r.first_refusal().map(|f| f.cause.clone()));
        assert_eq!(cause, Some(expected), "{name}");
    }
}
