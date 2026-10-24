use pn_records::burn::{AcceptedSet, BurnError, Disclosure, Encoding, OperatorEvidence, validate_burn};
use pn_records::test_support::burn as fixtures;
use std::collections::BTreeSet;

/// Claim: Only the marker/policy edition effective at genesis binds; a later announcement,
/// absent family, wrong identity, edition or publication cannot authorize recognition.
/// ´claim:burn:genesis-policy-requires-effective-declaration´
/// ´test:integration:policy-declaration-binding´
#[test]
fn policy_declaration_binding() {
    use pn_records::constants::{bind_marker_policy, marker_policy_digest};
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
        content: pn_records::DeclarationContent::MarkerPolicy {
            recipe: "pn-records/marker-policy/v1".into(),
            digest: marker_policy_digest(&fixture.policy),
        },
    };
    let deployment = Declaration {
        id: DeclarationId {
            namespace: "deployment".into(),
            name: "genesis".into(),
            edition: 1,
        },
        announced_at: 0,
        effective_at: 0,
        content: pn_records::DeclarationContent::Deployment { genesis_at: 1 },
    };
    let records = validate_record(&[], &history, &[declaration.clone(), deployment.clone()]).unwrap();
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
        let expected = if field == "publication" {
            BurnError::DeploymentBinding
        } else {
            BurnError::PolicyBinding
        };
        assert_eq!(bind_marker_policy(&records, policy, &burn), Err(expected));
    }
    let mut late = declaration;
    late.announced_at = fixture.policy.genesis_at + 1;
    late.effective_at = late.announced_at;
    for declarations in [vec![deployment.clone()], vec![late, deployment]] {
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

/// Claim: A policy cannot move the deployment genesis or substitute any complete payload at an unchanged edition and publication; only the structural declaration and its fixed digest authorize binding.
/// ´claim:burn:policy-binding-fixes-genesis-and-content´
/// ´test:integration:policy-content-binding´
#[test]
fn policy_content_binding() {
    use pn_records::constants::{bind_marker_policy, marker_policy_digest};
    use pn_records::{Declaration, DeclarationContent, DeclarationId, validate_history, validate_record};
    let fixture = fixtures::generate(&[3]);
    let burn = validate_burn(fixture.burn).unwrap();
    let history = validate_history(&[], &[]).unwrap();
    let policy = fixture.policy;
    let declarations = [
        Declaration {
            id: DeclarationId {
                namespace: "deployment".into(),
                name: "genesis".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: DeclarationContent::Deployment { genesis_at: 1 },
        },
        Declaration {
            id: DeclarationId {
                namespace: "marker".into(),
                name: "policy".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: DeclarationContent::MarkerPolicy {
                recipe: "pn-records/marker-policy/v1".into(),
                digest: marker_policy_digest(&policy),
            },
        },
    ];
    let records = validate_record(&[], &history, &declarations).unwrap();
    assert!(bind_marker_policy(&records, policy.clone(), &burn).is_ok());
    let mut moved = policy.clone();
    moved.genesis_at = 2;
    assert_eq!(bind_marker_policy(&records, moved, &burn), Err(BurnError::DeploymentBinding));
    for field in [
        "sequence",
        "initial",
        "placement",
        "cadence",
        "encoding",
        "rule",
        "profile",
        "buffer",
    ] {
        let mut changed = policy.clone();
        match field {
            "sequence" => changed.sequence.push('x'),
            "initial" => changed.initial_marker.push('x'),
            "placement" => changed.placement_procedure.push('x'),
            "cadence" => changed.cadence.push('x'),
            "encoding" => changed.encoding = Encoding::PublicCommitment,
            "rule" => changed.candidate_rule = pn_records::burn::CandidateRule::FirstValidInHistoryOrder,
            "profile" => changed.verification_profile.push('x'),
            _ => changed.stability_buffer += 1,
        }
        assert_ne!(marker_policy_digest(&changed), marker_policy_digest(&policy), "{field}");
        assert_eq!(
            bind_marker_policy(&records, changed, &burn),
            Err(BurnError::PolicyDigest),
            "{field}"
        );
    }
    let mut unknown = declarations.clone();
    unknown[1].content = DeclarationContent::MarkerPolicy {
        recipe: "unsupported-policy-recipe".into(),
        digest: marker_policy_digest(&policy),
    };
    assert_eq!(
        bind_marker_policy(&validate_record(&[], &history, &unknown).unwrap(), policy.clone(), &burn),
        Err(BurnError::UnsupportedPolicyRecipe)
    );
    let mut missing = declarations.clone();
    missing[1].content = DeclarationContent::Opaque;
    assert_eq!(
        bind_marker_policy(&validate_record(&[], &history, &missing).unwrap(), policy.clone(), &burn),
        Err(BurnError::PolicyDigest)
    );
    missing[0].content = DeclarationContent::Opaque;
    assert_eq!(
        bind_marker_policy(&validate_record(&[], &history, &missing).unwrap(), policy, &burn),
        Err(BurnError::DeploymentBinding)
    );
}

fn binding_fixture() -> (
    pn_records::burn::PolicyInput,
    pn_records::burn::ValidatedBurn,
    Vec<pn_records::Declaration>,
) {
    use pn_records::{Declaration, DeclarationContent, DeclarationId};
    let case = fixtures::generate(&[3]);
    let mut policy = case.policy;
    policy.genesis_at = 10;
    let burn = validate_burn(case.burn).unwrap();
    let declarations = vec![
        Declaration {
            id: DeclarationId {
                namespace: "deployment".into(),
                name: "genesis".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: DeclarationContent::Deployment { genesis_at: 10 },
        },
        Declaration {
            id: DeclarationId {
                namespace: "marker".into(),
                name: "policy".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: DeclarationContent::MarkerPolicy {
                recipe: "pn-records/marker-policy/v1".into(),
                digest: pn_records::constants::marker_policy_digest(&policy),
            },
        },
    ];
    assert!(bind_fixture(&policy, &burn, &declarations).is_ok());
    (policy, burn, declarations)
}
fn bind_fixture(
    policy: &pn_records::burn::PolicyInput,
    burn: &pn_records::burn::ValidatedBurn,
    declarations: &[pn_records::Declaration],
) -> Result<pn_records::burn::ValidatedPolicy, BurnError> {
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let records = pn_records::validate_record(&[], &history, declarations).unwrap();
    pn_records::constants::bind_marker_policy(&records, policy.clone(), burn)
}

/// Claim: A second structurally valid deployment edition makes genesis ambiguous even when both payloads agree, preventing a policy binder from silently selecting one.
/// ´claim:burn:deployment-genesis-is-unambiguous´
/// ´test:integration:duplicate-deployment´
#[test]
fn duplicate_deployment() {
    let (policy, burn, mut declarations) = binding_fixture();
    let mut second = declarations[0].clone();
    second.id.edition = 2;
    second.effective_at = 1;
    declarations.push(second);
    assert_eq!(bind_fixture(&policy, &burn, &declarations), Err(BurnError::DeploymentBinding));
}

/// Claim: A deployment whose announcement and effect follow its declared genesis cannot bind a policy, even though its declaration ordering is internally valid.
/// ´claim:burn:deployment-must-be-announced-by-genesis´
/// ´test:integration:late-deployment-announcement´
#[test]
fn late_deployment_announcement() {
    let (policy, burn, mut declarations) = binding_fixture();
    declarations[0].announced_at = 11;
    declarations[0].effective_at = 11;
    assert_eq!(bind_fixture(&policy, &burn, &declarations), Err(BurnError::DeploymentBinding));
}

/// Claim: An already announced deployment that becomes effective only after genesis refuses policy binding; publication alone cannot establish the genesis boundary.
/// ´claim:burn:deployment-must-be-effective-by-genesis´
/// ´test:integration:late-deployment-effect´
#[test]
fn late_deployment_effect() {
    let (policy, burn, mut declarations) = binding_fixture();
    declarations[0].effective_at = 11;
    assert_eq!(bind_fixture(&policy, &burn, &declarations), Err(BurnError::DeploymentBinding));
}

/// Claim: A publication mismatch before the unchanged genesis refuses even with a matching content commitment, so content equality cannot replace announcement binding.
/// ´claim:burn:policy-publication-matches-announcement´
/// ´test:integration:policy-publication-binding´
#[test]
fn policy_publication_binding() {
    let (mut policy, burn, mut declarations) = binding_fixture();
    policy.published_at = 1;
    declarations[1].content = pn_records::DeclarationContent::MarkerPolicy {
        recipe: "pn-records/marker-policy/v1".into(),
        digest: pn_records::constants::marker_policy_digest(&policy),
    };
    assert_eq!(bind_fixture(&policy, &burn, &declarations), Err(BurnError::PolicyBinding));
}

/// Claim: Changing only open placement changes the commitment and refuses policy validity; even an unpublished invalid candidate cannot alias the open policy's recipe input.
/// ´claim:burn:policy-commitment-includes-open-placement´
/// ´test:integration:policy-open-placement-binding´
#[test]
fn policy_open_placement_binding() {
    let (mut policy, burn, declarations) = binding_fixture();
    let original = pn_records::constants::marker_policy_digest(&policy);
    policy.open_placement = false;
    assert_ne!(pn_records::constants::marker_policy_digest(&policy), original);
    assert_eq!(bind_fixture(&policy, &burn, &declarations), Err(BurnError::Policy));
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
            0 => first.predecessor = Some(999),
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
        successor.history_position = 30;
        successor.predecessor = Some(20);
        case.history.markers.push(successor);
        let result = fixtures::recognize(case).unwrap();
        assert_eq!(result.markers(), prefix);
        let refusal = result.first_refusal().unwrap();
        assert_eq!(refusal.candidate.as_ref().unwrap().name, "m2");
        assert_eq!(refusal.cause, BurnError::InvalidMember);
    }
}

/// Claim: Disclosed positions select the same competing marker and refusal after reversal or shuffle; duplicate positions refuse validation, while lookup names do not choose a predecessor.
/// ´claim:burn:declared-policy-selects-competing-candidates´
/// ´test:integration:competing-candidates´
#[test]
fn competing_candidates() {
    use pn_records::burn::CandidateRule;
    let base = fixtures::generate(&[]);
    let prefix = fixtures::recognize(base.clone()).unwrap().markers()[..2].to_vec();
    let mut competing = base;
    let mut other = competing.history.markers[2].clone();
    other.name = "other-m2".into();
    other.history_position = 19;
    competing.history.markers.push(other);
    for rule in [CandidateRule::UniquePerIndex, CandidateRule::FirstValidInHistoryOrder] {
        competing.policy.candidate_rule = rule;
        let expected = fixtures::recognize(competing.clone()).unwrap();
        assert_eq!(&expected.markers()[..2], prefix);
        if rule == CandidateRule::UniquePerIndex {
            assert_eq!(expected.markers(), prefix);
            let refusal = expected.first_refusal().unwrap();
            assert_eq!(refusal.cause, BurnError::Succession);
            assert_eq!(
                refusal.competitors.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
                ["other-m2", "m2"]
            );
        } else {
            assert_eq!(expected.markers()[2].identity().name, "other-m2");
            assert!(expected.first_refusal().is_none());
        }
        for order in [[3, 2, 1, 0], [2, 0, 3, 1], [1, 3, 0, 2]] {
            let mut shuffled = competing.clone();
            shuffled.history.markers = order.iter().map(|&i| competing.history.markers[i].clone()).collect();
            assert_eq!(fixtures::recognize(shuffled).unwrap(), expected);
        }
    }
    let mut duplicate = competing.clone();
    duplicate.history.markers[3].history_position = duplicate.history.markers[2].history_position;
    assert_eq!(fixtures::recognize(duplicate), Err(BurnError::HistoryPosition));
    competing.policy.candidate_rule = CandidateRule::FirstValidInHistoryOrder;
    competing.history.markers[3].accepted = AcceptedSet::CompleteList(BTreeSet::from(["r1".into()]));
    let fallback = fixtures::recognize(competing.clone()).unwrap();
    assert_eq!(fallback.markers()[2].identity().name, "m2");
    assert_eq!(fallback.first_refusal().unwrap().cause, BurnError::RegressedAcceptance);
    competing.history.markers.reverse();
    assert_eq!(fixtures::recognize(competing).unwrap(), fallback);
}

/// Claim: Each newly isolated premise refuses with its own cause from an otherwise valid fixture: index origin, predecessor position, successor snapshot, policy identity and sequence, sample and cost units, operator-bound units, explained operator absence, and an empty marker name or self-predecessor.
/// ´claim:burn:isolated-premises-have-exact-refusals´
/// ´test:integration:isolated-recognition-premises´
#[test]
fn isolated_recognition_premises() {
    for (name, expected) in [
        ("initial-index", BurnError::Initial),
        ("predecessor-position", BurnError::Succession),
        ("successor-snapshot", BurnError::Succession),
        ("policy-identity", BurnError::HistoryPolicy),
        ("policy-sequence", BurnError::HistoryPolicy),
        ("burn-unit", BurnError::Units),
        ("cost-unit", BurnError::Units),
        ("operator-unit", BurnError::Units),
        ("empty-name", BurnError::Succession),
        ("self-predecessor", BurnError::Succession),
        ("unexplained-operator", BurnError::Publication(Disclosure::Operator)),
    ] {
        let mut input = fixtures::generate(&[5]);
        assert!(fixtures::recognize(input.clone()).unwrap().first_refusal().is_none());
        fixtures::corrupt(&mut input, name);
        let cause = fixtures::recognize(input).map_or_else(Some, |r| r.first_refusal().map(|f| f.cause.clone()));
        assert_eq!(cause, Some(expected), "{name}");
    }
}

/// Claim: Recognition retains history, policy, verifier and publication keys without certifying finality; a new publication edition changes those keys even when its recognized marker prefix is identical.
/// ´claim:burn:recognition-retains-unsettled-computation-keys´
/// ´test:integration:recognition-basis´
#[test]
fn recognition_basis() {
    use pn_records::burn::RecognitionBasis;
    let mut input = fixtures::generate(&[]);
    let recognized = fixtures::recognize(input.clone()).unwrap();
    assert_eq!(
        recognized.basis(),
        &RecognitionBasis {
            history: input.history.identity.clone(),
            policy_identity: input.policy.identity.clone(),
            policy_edition: input.policy.edition.clone(),
            verifier_profile: input.policy.verification_profile.clone(),
            burn_publication_edition: input.burn.edition.clone(),
            sample_convention: input.burn.sample_convention.clone(),
        }
    );
    input.burn.edition = "edition-2".into();
    input.burn.evidence.edition = input.burn.edition.clone();
    let changed = fixtures::recognize(input).unwrap();
    assert_eq!(recognized.markers(), changed.markers());
    assert_ne!(recognized.basis(), changed.basis());
    assert_eq!(changed.basis().burn_publication_edition, "edition-2");
}

/// Claim: A later copied lookup name cannot stall first-valid recognition or redirect a position-bound successor; unique-index still refuses competitors by index, and repeated names across indices are valid under either rule in either presentation.
/// ´claim:burn:copied-names-do-not-control-succession´
/// ´test:integration:copied-marker-names´
#[test]
fn copied_marker_names() {
    use pn_records::burn::CandidateRule;
    for rule in [CandidateRule::FirstValidInHistoryOrder, CandidateRule::UniquePerIndex] {
        let mut base = fixtures::generate(&[]);
        base.policy.candidate_rule = rule;
        // Reusing a selected lookup label does not change the position reference.
        base.history.markers[2].name = base.history.markers[1].name.clone();
        let expected = fixtures::recognize(base.clone()).unwrap();
        assert_eq!(expected.markers().len(), 3);
        assert!(expected.first_refusal().is_none());
        let mut copy = base.history.markers[2].clone();
        copy.history_position = 21;
        let mut successor = base.history.markers[2].clone();
        successor.index = 3;
        successor.history_position = 30;
        successor.predecessor = Some(20);
        base.history.markers.push(copy);
        base.history.markers.push(successor);
        let recognized = fixtures::recognize(base.clone()).unwrap();
        if rule == CandidateRule::FirstValidInHistoryOrder {
            assert_eq!(recognized.markers().len(), 4);
            assert_eq!(&recognized.markers()[..3], expected.markers());
            assert!(recognized.first_refusal().is_none());
            let mut redirected = base.clone();
            redirected.history.markers[4].predecessor = Some(21);
            let refused = fixtures::recognize(redirected).unwrap();
            assert_eq!(refused.markers(), expected.markers());
            assert_eq!(refused.first_refusal().unwrap().cause, BurnError::Succession);
        } else {
            assert_eq!(recognized.markers(), &expected.markers()[..2]);
            let refusal = recognized.first_refusal().unwrap();
            assert_eq!(refusal.cause, BurnError::Succession);
            assert_eq!(
                refusal.competitors.iter().map(|m| m.history_position).collect::<Vec<_>>(),
                [20, 21]
            );
        }
        for order in [[4, 3, 2, 1, 0], [2, 0, 4, 1, 3]] {
            let mut shuffled = base.clone();
            shuffled.history.markers = order.iter().map(|&i| base.history.markers[i].clone()).collect();
            assert_eq!(fixtures::recognize(shuffled).unwrap(), recognized);
        }
    }
}

/// Claim: With an otherwise valid disclosure under either candidate rule, a successor placed before its named predecessor refuses Succession and retains exactly the preceding prefix; presentation order cannot repair it.
/// ´claim:burn:successors-follow-predecessor-positions´
/// ´test:integration:successor-position´
#[test]
fn successor_position() {
    use pn_records::burn::CandidateRule;
    for rule in [CandidateRule::UniquePerIndex, CandidateRule::FirstValidInHistoryOrder] {
        let mut case = fixtures::generate(&[]);
        case.policy.candidate_rule = rule;
        let valid = fixtures::recognize(case.clone()).unwrap();
        assert!(valid.first_refusal().is_none());
        let prefix = valid.markers()[..2].to_vec();
        case.history.markers[2].history_position = 5;
        let refused = fixtures::recognize(case.clone()).unwrap();
        assert_eq!(refused.markers(), prefix);
        assert_eq!(refused.first_refusal().unwrap().cause, BurnError::Succession);
        case.history.markers.reverse();
        assert_eq!(fixtures::recognize(case).unwrap(), refused);
    }
}

/// Claim: Publication validates the complete policy first and returns its recipe with the digest; an invalid policy produces no declaration, and an unknown recipe has its own binding cause.
/// ´claim:burn:policy-publication-validates-and-names-recipe´
/// ´test:integration:policy-publication-recipe´
#[test]
fn policy_publication_recipe() {
    use pn_records::constants::{MARKER_POLICY_RECIPE, marker_policy_declaration, marker_policy_digest};
    let (policy, burn, mut declarations) = binding_fixture();
    let content = marker_policy_declaration(&policy, &burn).unwrap();
    assert_eq!(
        content,
        pn_records::DeclarationContent::MarkerPolicy {
            recipe: MARKER_POLICY_RECIPE.into(),
            digest: marker_policy_digest(&policy),
        }
    );
    declarations[1].content = content;
    assert!(bind_fixture(&policy, &burn, &declarations).is_ok());
    let mut invalid = policy.clone();
    invalid.identity.clear();
    assert_eq!(marker_policy_declaration(&invalid, &burn), Err(BurnError::Policy));
    if let pn_records::DeclarationContent::MarkerPolicy { recipe, .. } = &mut declarations[1].content {
        *recipe = "unsupported-policy-recipe".into();
    }
    assert_eq!(
        bind_fixture(&policy, &burn, &declarations),
        Err(BurnError::UnsupportedPolicyRecipe)
    );
}

/// Claim: The permanent marker-policy recipe preserves its exact SHA-256 bytes for all encoding and candidate-rule discriminants across a cryptographic-library change; the expected bytes come from independently framed public inputs.
/// ´claim:burn:policy-digest-recipe-preserves-known-bytes´
/// ´test:integration:policy-digest-vectors´
#[test]
fn policy_digest_vectors() {
    use pn_records::burn::{CandidateRule, PolicyInput};
    let rows: Vec<(usize, usize, [u8; 32])> = serde_json::from_str(include_str!("policy-digest-v1.json")).unwrap();
    for (encoding, candidate_rule, expected) in rows {
        let policy = PolicyInput {
            identity: "marker/policy".into(),
            edition: "edition-7".into(),
            sequence: "sequence-public".into(),
            initial_marker: "genesis".into(),
            placement_procedure: "open placement".into(),
            cadence: "cadence-public".into(),
            verification_profile: "verifier-v1".into(),
            published_at: 3,
            genesis_at: 11,
            stability_buffer: 5,
            open_placement: true,
            encoding: [
                Encoding::CompleteList,
                Encoding::PublicCommitment,
                Encoding::WholePrefixAcceptAll,
            ][encoding],
            candidate_rule: [CandidateRule::FirstValidInHistoryOrder, CandidateRule::UniquePerIndex][candidate_rule],
        };
        assert_eq!(
            pn_records::constants::marker_policy_digest(&policy),
            expected,
            "{encoding}/{candidate_rule}"
        );
    }
}
