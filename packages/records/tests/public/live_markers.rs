use pn_records::{
    burn::*,
    live_markers::{self, Error, LiveVerifier, Status},
    test_support::burn as fixtures,
};
use std::collections::BTreeSet;

#[derive(Debug)]
struct Service(fixtures::BurnCase);
impl PublicVerifier for Service {
    fn profile(&self) -> &str {
        FixtureVerifier.profile()
    }
    fn destruction(&self, r: &BurnRecord) -> bool {
        FixtureVerifier.destruction(r)
    }
    fn opening(&self, c: &[u8], o: &Opening) -> bool {
        FixtureVerifier.opening(c, o)
    }
}
use fixtures::FixtureVerifier;
impl LiveVerifier for Service {
    fn settlement(&self, history: &HistoryInput, policy: &PolicyInput, burn: &BurnInput, evidence: &[u8]) -> Status {
        let mut actual = history.clone();
        let mut expected = self.0.history.clone();
        actual.markers.sort_by_key(|m| m.index);
        expected.markers.sort_by_key(|m| m.index);
        actual.records.sort_by(|a, b| a.identity.cmp(&b.identity));
        expected.records.sort_by(|a, b| a.identity.cmp(&b.identity));
        if evidence == b"lost" {
            Status::Lost
        } else if actual == expected && policy == &self.0.policy && burn == &self.0.burn && evidence == b"operator-settled" {
            Status::Final
        } else {
            Status::Pending
        }
    }
}
fn case() -> fixtures::BurnCase {
    let mut c = fixtures::generate(&[]);
    c.policy.open_placement = false;
    c.policy.placement_procedure = "fixture operator places markers; anyone extends accumulators".into();
    c
}
fn bound(c: &fixtures::BurnCase) -> ValidatedPolicy {
    use pn_records::{Declaration, DeclarationContent, DeclarationId};
    let burn = validate_burn(c.burn.clone()).unwrap();
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let declarations = [
        Declaration {
            id: DeclarationId {
                namespace: "marker".into(),
                name: "policy".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: DeclarationContent::MarkerPolicy {
                recipe: pn_records::constants::HOST_MARKER_POLICY_RECIPE.into(),
                digest: pn_records::constants::marker_policy_digest(&c.policy),
            },
        },
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
    ];
    let records = pn_records::validate_record(&[], &history, &declarations).unwrap();
    pn_records::constants::bind_marker_policy(&records, c.policy.clone(), &burn).unwrap()
}
fn verify(c: &fixtures::BurnCase, service: &Service) -> Result<live_markers::LiveMarkers, Error> {
    let mut h = c.history.clone();
    h.markers.reverse();
    h.records.reverse();
    live_markers::verify(h, &bound(c), b"operator-settled", service)
}

/// Claim: Under a declared live fixture verifier, complete reversed disclosures retain immediate marker succession and refuse skipped, competing, lost-lineage and copied-name candidates. A name or a depth assumption alone supplies no live settlement authority.
/// ´claim:burn:live-markers-require-complete-lineage´
/// ´test:integration:live-marker-rules´
#[test]
fn live_marker_rules() {
    let c = case();
    let service = Service(c.clone());
    assert!(verify(&c, &service).is_ok());
    let mut bad = c.clone();
    bad.history.markers.remove(1);
    assert_eq!(verify(&bad, &service), Err(Error::Recognition(BurnError::Succession)));
    bad = c.clone();
    let mut duplicate = bad.history.markers[1].clone();
    duplicate.history_position += 1;
    bad.history.markers.push(duplicate);
    assert_eq!(verify(&bad, &service), Err(Error::Recognition(BurnError::Succession)));
    bad = c.clone();
    bad.history.records.remove(0);
    assert_eq!(verify(&bad, &service), Err(Error::Recognition(BurnError::MissingLineage)));
    bad = c.clone();
    bad.history.markers[2].lineage.remove("r0");
    assert_eq!(verify(&bad, &service), Err(Error::Recognition(BurnError::RegressedLineage)));
    bad = c.clone();
    bad.history.markers[0].initial_snapshot = None;
    assert_eq!(verify(&bad, &service), Err(Error::Recognition(BurnError::Initial)));
    bad = c.clone();
    bad.history.markers[2].policy_edition.push_str("-foreign");
    assert_eq!(verify(&bad, &service), Err(Error::Recognition(BurnError::HistoryPolicy)));
    bad = c.clone();
    bad.history.markers[1].name = "copied-marker".into();
    assert_eq!(verify(&bad, &service), Err(Error::Pending));
    assert_eq!(
        live_markers::verify(c.history.clone(), &bound(&c), b"", &service),
        Err(Error::MissingEvidence)
    );
    assert_eq!(
        live_markers::verify(c.history.clone(), &bound(&c), b"lost", &service),
        Err(Error::Lost)
    );
}

fn committed(mut c: fixtures::BurnCase) -> fixtures::BurnCase {
    c.policy.encoding = Encoding::PublicCommitment;
    for marker in &mut c.history.markers {
        let AcceptedSet::CompleteList(members) = &marker.accepted else {
            unreachable!()
        };
        let bytes = format!("set:{}", members.iter().cloned().collect::<Vec<_>>().join("|")).into_bytes();
        marker.accepted = AcceptedSet::Commitment {
            commitment: bytes.clone(),
            openings: vec![Opening {
                members: members.clone(),
                proof: bytes,
            }],
        };
    }
    c
}

/// Claim: Complete lists and uniquely opened commitments yield the same accepted sets under declared fixture verifiers; missing member proof, missing or ambiguous opening, out-of-lineage acceptance and dropped predecessor acceptance refuse without substituting a smaller set.
/// ´claim:burn:live-acceptance-requires-complete-proof´
/// ´test:integration:live-marker-openings´
#[test]
fn live_marker_openings() {
    let c = case();
    let listed = verify(&c, &Service(c.clone())).unwrap();
    let commit = committed(c.clone());
    let opened = verify(&commit, &Service(commit.clone())).unwrap();
    for (a, b) in listed.markers().markers().iter().zip(opened.markers().markers()) {
        assert_eq!(a.accepted(), b.accepted());
    }
    let mut bad = commit.clone();
    if let AcceptedSet::Commitment { openings, .. } = &mut bad.history.markers[1].accepted {
        openings.clear();
    }
    assert_eq!(
        verify(&bad, &Service(commit.clone())),
        Err(Error::Recognition(BurnError::MissingOpening))
    );
    bad = commit.clone();
    if let AcceptedSet::Commitment { openings, .. } = &mut bad.history.markers[1].accepted {
        openings.push(openings[0].clone());
    }
    assert_eq!(
        verify(&bad, &Service(commit)),
        Err(Error::Recognition(BurnError::AmbiguousOpening))
    );
    for mut bad in [c.clone(), committed(c.clone())] {
        bad.history.records[0].evidence.clear();
        assert_eq!(
            verify(&bad, &Service(bad.clone())),
            Err(Error::Recognition(BurnError::InvalidMember))
        );
    }
    bad = c.clone();
    bad.history.markers[1].accepted = AcceptedSet::CompleteList(BTreeSet::from(["alias".into()]));
    assert_eq!(
        verify(&bad, &Service(c.clone())),
        Err(Error::Recognition(BurnError::OutOfLineage))
    );
    bad = c.clone();
    bad.history.markers[2].accepted = AcceptedSet::CompleteList(BTreeSet::new());
    assert_eq!(
        verify(&bad, &Service(c)),
        Err(Error::Recognition(BurnError::RegressedAcceptance))
    );
}

/// Claim: Declared live fixture recognition retains delayed acceptance and deduplicates consistent aliases by destruction identity; an alias with changed attribution refuses. No observed lineage total substitutes for acceptance.
/// ´claim:burn:live-aliases-retain-first-acceptance´
/// ´test:integration:live-marker-aliases´
#[test]
fn live_marker_aliases() {
    let c = case();
    let checked = verify(&c, &Service(c.clone())).unwrap();
    let markers = checked.markers().markers();
    assert!(markers[1].identity().lineage.contains("r1"));
    assert!(!markers[1].accepted().contains("r1"));
    assert!(markers[2].accepted().contains("r1"));
    assert_eq!(markers[2].destructions().len(), c.history.records.len() - 1);
    let mut bad = c;
    bad.history.records[2].address = Address("changed".into());
    let r = &mut bad.history.records[2];
    r.evidence = format!("{}:{}:{}:{}", r.destruction, r.address.0, r.amount.exact(), r.amount.unit()).into_bytes();
    assert_eq!(
        verify(&bad, &Service(bad.clone())),
        Err(Error::Recognition(BurnError::InconsistentAlias))
    );
}
