use super::*;
use pn_records::{EdgeId, Quantity};

fn id(sequence: u64, family: &str) -> ActId {
    ActId {
        author: format!("pn-devnet-v1/{}/{}", "12".repeat(32), "34".repeat(32)),
        sequence,
        family: family.into(),
    }
}
fn secret(bytes: &[u8]) -> SecretSlice<u8> {
    SecretSlice::from(bytes.to_vec())
}
fn list(ids: Vec<ActId>) -> SecretBox<DependencyIds> {
    SecretBox::new(Box::new(DependencyIds(ids)))
}
fn nonce(sequence: u64) -> SecretSlice<u8> {
    let mut bytes = sequence.to_be_bytes().to_vec();
    bytes.extend(0..32);
    secret(&bytes)
}
fn salt(counter: u128, start: u8) -> SecretSlice<u8> {
    let mut bytes = counter.to_be_bytes().to_vec();
    bytes.extend(start..start + 32);
    secret(&bytes)
}
fn named(namespace: &str, name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: name.into(),
    }
}
fn body(family: &str) -> ProposalBody {
    let id = id(2, family);
    let (layout, coordinates) = schema(family).unwrap();
    let roles: &[Role] = match layout {
        Layout::Binary => &[Role::Binary],
        Layout::Paired => &[Role::A, Role::T],
    };
    let mut quantities = Vec::new();
    for (name, _) in coordinates {
        for (part, value) in [("denominator", 2), ("numerator", 1)] {
            quantities.push((
                format!("{name}.{part}"),
                Quantity {
                    value,
                    unit: "one".into(),
                    vintage: 0,
                },
            ));
        }
    }
    quantities.sort_by(|a, b| a.0.cmp(&b.0));
    let settlement = match family {
        "Accept" => Some(pn_records::SettlementReferences::Accept {
            settles: super::tests::id(1, "Bid"),
        }),
        "Ratify" => Some(pn_records::SettlementReferences::Ratify {
            settles: super::tests::id(1, "Bid"),
            accepts: super::tests::id(1, "Accept"),
        }),
        _ => None,
    };
    ProposalBody {
        legs: roles
            .iter()
            .map(|role| CandidateLeg {
                id: EdgeId {
                    act: id.clone(),
                    role: *role,
                },
                source: named(if *role == Role::T { "prof" } else { "addr" }, &id.author),
                target: named("prof", &id.author),
                removal: None,
            })
            .collect(),
        id,
        body: StructuralBody {
            settlement,
            license: None,
            asserted_parents: Vec::new(),
            layout,
            quantities,
        },
        protocol_references: Vec::new(),
        content: ContentRequest::Full,
        dependency: DependencyRequest::Full,
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::new();
    for byte in bytes {
        write!(&mut result, "{byte:02x}").unwrap();
    }
    result
}

// Fixture-only secret boundary: The caller owns these fixed values and only comparison results leave the accessor.
// Caveat: Fixed test pre-digests are borrowed solely for hexadecimal equality with independently authored fixture vectors; the borrow ends at this comparison and the helper never receives production material.
// (´[ROOT-cav:observe:secret-profile-fixture-digest]´)
// Justified: The fixture must compare the hash's protected intermediate with a public expected vector without adding a production export API.
#[allow(clippy::disallowed_methods)]
fn fixture_digest(value: &SecretSlice<u8>, expected: &str) -> bool {
    hex(value.expose_secret(/* (´[ROOT-cav:observe:secret-profile-fixture-digest]´) */)) == expected
}

/// Claim: Independently authored fixed preimages bind both private intermediates and all three public residues; typed controls preserve the profile's boundaries.
/// ´claim:profile:fixed-recipes-bind-exact-authored-inputs´
/// ´test:unit:fixed-recipes-and-controls´
#[test]
fn fixed_recipes_and_controls() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/commitments.json")).unwrap();
    let expected = |name: &str| {
        vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap()["digest"]
            .as_str()
            .unwrap()
    };
    let proposal_body = body("Registration");
    let proposal_nonce = nonce(2);
    let payload = secret(b"fixture private aggregate");
    let dependency_ids = list(vec![id(1, "Registration")]);
    let hy = hash(
        PROPOSAL_RECIPE,
        "PN-content-pre-v1",
        vec![
            public(identifier(&proposal_body.id)),
            SecretValue::Bytes(proposal_nonce.clone()),
            SecretValue::Bytes(payload.clone()),
        ],
    )
    .unwrap();
    let hd = hash(
        PROPOSAL_RECIPE,
        "PN-dependency-pre-v1",
        vec![
            public(identifier(&proposal_body.id)),
            SecretValue::Bytes(proposal_nonce.clone()),
            dependencies(&dependency_ids, None).unwrap().0,
        ],
    )
    .unwrap();
    assert!(fixture_digest(&hy, expected("content-pre")));
    assert!(fixture_digest(&hd, expected("dependency-pre")));
    let proposal = proposal_commitment(&proposal_body, &proposal_nonce, &payload, &dependency_ids).unwrap();
    assert_eq!(hex(&proposal.bytes), expected("proposal"));
    let sy = salt(1, 32);
    let sd = salt(2, 64);
    let cy = content_commitment(&proposal_body.id, &proposal, &sy, &payload).unwrap();
    assert_eq!(hex(&cy.bytes), expected("content"));
    let cd = dependency_commitment(&proposal_body.id, &proposal, &sd, &dependency_ids).unwrap();
    assert_eq!(hex(&cd.bytes), expected("dependency"));
    assert!(proposal_matches_supplied_commitment(&proposal_body, &proposal, &proposal_nonce, &payload, &dependency_ids).is_ok());
    assert!(content_matches_supplied_commitment(&proposal_body.id, &proposal, &cy, &sy, &payload).is_ok());
    assert!(dependencies_match_supplied_commitment(&proposal_body.id, &proposal, &cd, &sd, &dependency_ids).is_ok());
    assert!(content_matches_supplied_commitment(&proposal_body.id, &proposal, &cy, &sd, &payload).is_err());
    assert!(content_matches_supplied_commitment(&proposal_body.id, &proposal, &cy, &sy, &secret(b"other")).is_err());
    assert!(dependencies_match_supplied_commitment(&id(3, "Registration"), &proposal, &cd, &sd, &dependency_ids).is_err());
    assert!(dependencies_match_supplied_commitment(&proposal_body.id, &proposal, &cd, &sy, &dependency_ids).is_err());
    assert!(dependencies_match_supplied_commitment(&proposal_body.id, &proposal, &cd, &sd, &list(Vec::new())).is_err());
    let fabricated = ProposalCommitment {
        recipe: PROPOSAL_RECIPE.into(),
        bytes: [19; 32],
    };
    assert!(dependencies_match_supplied_commitment(&proposal_body.id, &fabricated, &cd, &sd, &dependency_ids).is_err());
    let replacement = dependency_commitment(&proposal_body.id, &fabricated, &sd, &dependency_ids).unwrap();
    assert!(dependencies_match_supplied_commitment(&proposal_body.id, &fabricated, &replacement, &sd, &dependency_ids).is_ok());
    representation_controls();
    retained_field_controls();
}

fn representation_controls() {
    let proposal_body = body("Registration");
    let proposal_nonce = nonce(2);
    let payload = secret(b"fixture private aggregate");
    let dependency_ids = list(vec![id(1, "Registration")]);
    let proposal = proposal_commitment(&proposal_body, &proposal_nonce, &payload, &dependency_ids).unwrap();
    let sd = salt(2, 64);
    let sy = salt(1, 32);
    let mut wrong = proposal.clone();
    wrong.recipe.push_str("-other");
    assert!(dependency_commitment(&proposal_body.id, &wrong, &sd, &dependency_ids).is_err());
    assert!(proposal_commitment(&proposal_body, &nonce(3), &payload, &dependency_ids).is_err());
    assert!(proposal_commitment(&proposal_body, &secret(&[0; 39]), &payload, &dependency_ids).is_err());
    assert!(content_commitment(&proposal_body.id, &proposal, &secret(&[0; 47]), &payload).is_err());
    assert!(content_commitment(&proposal_body.id, &proposal, &secret(&[0; 49]), &payload).is_err());
    assert!(
        proposal_commitment(
            &proposal_body,
            &proposal_nonce,
            &payload,
            &list(vec![proposal_body.id.clone()])
        )
        .is_err()
    );
    assert!(dependency_commitment(&proposal_body.id, &proposal, &sd, &list(vec![proposal_body.id.clone()])).is_ok());
    assert!(
        dependency_commitment(
            &proposal_body.id,
            &proposal,
            &sd,
            &list(vec![id(1, "Registration"), id(1, "Registration")])
        )
        .is_err()
    );
    assert!(
        dependency_commitment(
            &proposal_body.id,
            &proposal,
            &sd,
            &list(vec![id(3, "Registration"), id(1, "Registration")])
        )
        .is_err()
    );
    // Records' family order is lexical, unlike CBOR's encoded text-length order.
    let affinity = id(1, "Affinity");
    let bid = id(1, "Bid");
    assert!(affinity < bid);
    assert!(identifier(&affinity).to_canonical_bytes() > identifier(&bid).to_canonical_bytes());
    assert!(dependency_commitment(&proposal_body.id, &proposal, &sd, &list(vec![affinity.clone(), bid.clone()])).is_ok());
    assert!(dependency_commitment(&proposal_body.id, &proposal, &sd, &list(vec![bid, affinity])).is_err());
    assert!(content_commitment(&proposal_body.id, &proposal, &sy, &secret(&vec![42; 65_536])).is_ok());
    assert!(content_commitment(&proposal_body.id, &proposal, &sy, &secret(&vec![42; 65_537])).is_err());
    assert!(
        dependency_commitment(
            &proposal_body.id,
            &proposal,
            &sd,
            &list((0..1024).map(|i| id(i, "Registration")).collect())
        )
        .is_ok()
    );
    assert!(
        dependency_commitment(
            &proposal_body.id,
            &proposal,
            &sd,
            &list((0..1025).map(|i| id(i, "Registration")).collect())
        )
        .is_err()
    );
    let mut empty = proposal_body.clone();
    empty.content = ContentRequest::FullEmpty;
    empty.dependency = DependencyRequest::FullEmpty;
    assert!(proposal_commitment(&empty, &proposal_nonce, &secret(b""), &list(Vec::new())).is_ok());
    assert!(proposal_commitment(&empty, &proposal_nonce, &payload, &dependency_ids).is_err());
    family_controls();
}

fn family_controls() {
    let proposal_nonce = nonce(2);
    let payload = secret(b"fixture private aggregate");
    let dependency_ids = list(vec![id(1, "Registration")]);
    for family in [
        "Registration",
        "Publish",
        "Opinion",
        "Affinity",
        "Participant",
        "Owner",
        "Join Request",
        "Invitation",
        "De-invite",
        "Tag",
        "Review",
        "Reference",
        "Bid",
        "Send",
        "Accept",
        "Ratify",
        "Withdraw",
        "Rescind",
        "Leave",
    ] {
        let candidate = body(family);
        assert!(
            proposal_commitment(&candidate, &proposal_nonce, &payload, &dependency_ids).is_ok(),
            "{family}"
        );
        let mut changed = candidate.clone();
        changed.legs[0].id.role = Role::T;
        assert!(proposal_commitment(&changed, &proposal_nonce, &payload, &dependency_ids).is_err());
        let t = (candidate.body.layout == Layout::Paired).then(|| secret(b""));
        assert!(render_payload(family, &payload, t.as_ref()).is_ok());
        if !candidate.body.quantities.is_empty() {
            let original = proposal_commitment(&candidate, &proposal_nonce, &payload, &dependency_ids).unwrap();
            let mut equivalent = candidate.clone();
            for (_, q) in &mut equivalent.body.quantities {
                q.value *= 2;
            }
            assert_ne!(
                original,
                proposal_commitment(&equivalent, &proposal_nonce, &payload, &dependency_ids).unwrap()
            );
        }
    }
    for family in ["Invitation", "De-invite", "Tag", "Reference"] {
        assert!(render_payload(family, &payload, Some(&payload)).is_err());
    }
    assert!(render_payload("Review", &secret(b""), Some(&secret(b""))).is_ok());
    assert!(render_payload("Review", &secret(&vec![7; 65_531]), Some(&secret(b""))).is_ok());
    assert!(render_payload("Review", &secret(&vec![7; 65_532]), Some(&secret(b""))).is_err());
}

fn retained_field_controls() {
    let proposal_body = body("Registration");
    let proposal_nonce = nonce(2);
    let payload = secret(b"fixture private aggregate");
    let dependency_ids = list(vec![id(1, "Registration")]);
    let proposal = proposal_commitment(&proposal_body, &proposal_nonce, &payload, &dependency_ids).unwrap();
    let sy = salt(1, 32);
    let sd = salt(2, 64);
    let mut typed = proposal_body.clone();
    typed.legs[0].target = named("name", &"a".repeat(1024));
    assert!(proposal_commitment(&typed, &proposal_nonce, &payload, &dependency_ids).is_ok());
    typed.legs[0].target = named("name", &"a".repeat(1025));
    assert!(proposal_commitment(&typed, &proposal_nonce, &payload, &dependency_ids).is_err());
    let mut parents = proposal_body.clone();
    parents.body.asserted_parents = (100..1124).map(|proposal_nonce| id(proposal_nonce, "Registration")).collect();
    assert!(proposal_commitment(&parents, &proposal_nonce, &payload, &dependency_ids).is_ok());
    parents.body.asserted_parents.push(id(1124, "Registration"));
    assert!(proposal_commitment(&parents, &proposal_nonce, &payload, &dependency_ids).is_err());
    let mut changed = proposal_body.clone();
    changed.content = ContentRequest::Reduced;
    assert_ne!(
        proposal,
        proposal_commitment(&changed, &proposal_nonce, &payload, &dependency_ids).unwrap()
    );
    changed = proposal_body.clone();
    changed.dependency = DependencyRequest::Tombstoned;
    assert_ne!(
        proposal,
        proposal_commitment(&changed, &proposal_nonce, &payload, &dependency_ids).unwrap()
    );
    changed = proposal_body.clone();
    changed.body.asserted_parents = vec![id(1, "Registration")];
    assert_ne!(
        proposal,
        proposal_commitment(&changed, &proposal_nonce, &payload, &dependency_ids).unwrap()
    );
    changed = proposal_body.clone();
    changed.legs[0].target = named("name", "different typed endpoint");
    assert_ne!(
        proposal,
        proposal_commitment(&changed, &proposal_nonce, &payload, &dependency_ids).unwrap()
    );
    changed = proposal_body.clone();
    changed.protocol_references.push(named("name", "unsupported"));
    assert!(proposal_commitment(&changed, &proposal_nonce, &payload, &dependency_ids).is_err());
    changed = proposal_body.clone();
    changed.body.layout = Layout::Paired;
    assert!(proposal_commitment(&changed, &proposal_nonce, &payload, &dependency_ids).is_err());
    let mut accept = body("Accept");
    let prior = proposal_commitment(&accept, &proposal_nonce, &payload, &dependency_ids).unwrap();
    accept.body.settlement = Some(pn_records::SettlementReferences::Accept { settles: id(9, "Bid") });
    assert_ne!(
        prior,
        proposal_commitment(&accept, &proposal_nonce, &payload, &dependency_ids).unwrap()
    );
    let mut publish = body("Publish");
    publish.legs[0].target = PublicReference::Minted(publish.id.clone());
    assert!(proposal_commitment(&publish, &proposal_nonce, &payload, &dependency_ids).is_err());
    let degree = pn_records::LicenseDegree {
        numerator: 1,
        denominator: 2,
    };
    publish.body.license = Some(pn_records::LicenseQualifiers {
        attribution: degree,
        provenance: degree,
    });
    let licensed = proposal_commitment(&publish, &proposal_nonce, &payload, &dependency_ids).unwrap();
    publish.body.license.as_mut().unwrap().attribution = pn_records::LicenseDegree {
        numerator: 2,
        denominator: 4,
    };
    assert_ne!(
        licensed,
        proposal_commitment(&publish, &proposal_nonce, &payload, &dependency_ids).unwrap()
    );
    publish.body.license.as_mut().unwrap().provenance.denominator = 0;
    assert!(proposal_commitment(&publish, &proposal_nonce, &payload, &dependency_ids).is_err());
    let mut bad_content = content_commitment(&proposal_body.id, &proposal, &sy, &payload).unwrap();
    bad_content.recipe.push('x');
    assert!(content_matches_supplied_commitment(&proposal_body.id, &proposal, &bad_content, &sy, &payload).is_err());
    let mut wrong_dependencies = dependency_commitment(&proposal_body.id, &proposal, &sd, &dependency_ids).unwrap();
    wrong_dependencies.recipe.push('x');
    assert!(
        dependencies_match_supplied_commitment(&proposal_body.id, &proposal, &wrong_dependencies, &sd, &dependency_ids).is_err()
    );
    // Public substrate controls: no external profile envelope decoder is admitted.
    // A hostile claimed length is refused from a short slice before collections
    // can be sized by it; alternate preferred heads cannot change recipe bytes.
    for raw in [
        &[24, 0][..],
        &[159, 255],
        &[155, 255, 255, 255, 255, 255, 255, 255, 255],
        &[91, 255, 255, 255, 255, 255, 255, 255, 255],
    ] {
        assert!(Value::from_canonical_bytes(raw).is_err());
    }
}

fn expand_artifacts(value: &mut serde_json::Value) {
    if value["encoding"] == "json" && value.get("artifact").is_some() {
        let artifact = &value["artifact"];
        let bytes = std::fs::read(artifact["path"].as_str().unwrap()).unwrap();
        assert_eq!(
            u64::try_from(bytes.len()).unwrap(),
            artifact["length_bytes"].as_u64().unwrap()
        );
        assert_eq!(hex(&Sha256::digest(&bytes)), artifact["digest"].as_str().unwrap());
        *value = serde_json::from_slice(&bytes).unwrap();
    }
    match value {
        serde_json::Value::Object(fields) => fields.values_mut().for_each(expand_artifacts),
        serde_json::Value::Array(elements) => elements.iter_mut().for_each(expand_artifacts),
        _ => {}
    }
}

/// Claim: Complete traced commitment computations retain the three fixed residues without emitting the nonce, salts, payload, dependency list or private pre-digests.
/// ´claim:profile:commitment-traces-retain-only-public-projection´
/// ´test:unit:commitment-trace-privacy´
#[test]
fn commitment_trace_privacy() {
    let proposal_body = body("Registration");
    let proposal_nonce = nonce(2);
    let payload = secret(b"fixture private aggregate");
    let dependency_ids = list(vec![id(1, "Registration")]);
    let sy = salt(1, 32);
    let sd = salt(2, 64);
    if std::env::var_os("PN_PROFILE_TRACE_CHILD").is_some() {
        let _guard = cli_common::init_json_tracing(tracing::Level::TRACE).unwrap();
        let proposal = proposal_commitment(&proposal_body, &proposal_nonce, &payload, &dependency_ids).unwrap();
        let cy = content_commitment(&proposal_body.id, &proposal, &sy, &payload).unwrap();
        let cd = dependency_commitment(&proposal_body.id, &proposal, &sd, &dependency_ids).unwrap();
        let vectors: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/commitments.json")).unwrap();
        for (name, bytes) in [("proposal", proposal.bytes), ("content", cy.bytes), ("dependency", cd.bytes)] {
            let row = vectors["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["name"] == name)
                .unwrap();
            assert_eq!(hex(&bytes), row["digest"].as_str().unwrap());
        }
        return;
    }
    for level in ["default", "trace"] {
        let artifacts = std::env::temp_dir().join(format!("pn-act-profile-trace-{}-{level}", std::process::id()));
        std::fs::create_dir(&artifacts).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::commitment_trace_privacy", "--nocapture"])
            .env("PN_PROFILE_TRACE_CHILD", "1")
            .env("PN_OBSERVE_LEVEL", level)
            .env("PN_OBSERVE_ARTIFACT_DIR", &artifacts)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let mut records: Vec<serde_json::Value> = String::from_utf8(output.stderr)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        records.iter_mut().for_each(expand_artifacts);
        std::fs::remove_dir_all(&artifacts).unwrap();
        let status: Vec<_> = records.iter().filter(|row| row["kind"] == "observation_status").collect();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0]["lost_records"], 0);
        assert_eq!(status[0]["undelivered_records"], 0);
        assert!(status[0]["delivered_records"].as_u64().unwrap() > 0);
        let metrics = records.iter().find(|row| row["kind"] == "metric_summary").unwrap();
        let started = metrics["metrics"]["instruments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "actprofile__root__amend__decomposition__act_profile__started_operations")
            .unwrap();
        assert_eq!(started["counter"], 3);
        let trace = serde_json::to_string(&records).unwrap();
        assert!(!trace.contains("fixture private aggregate"));
        assert!(!trace.contains("sequence: 1,"));
        let mut private = vec![b"fixture private aggregate".to_vec()];
        for (prefix, width, start) in [(2_u128, 8, 0_u8), (1, 16, 32), (2, 16, 64)] {
            let mut bytes = prefix.to_be_bytes()[16 - width..].to_vec();
            bytes.extend(start..start + 32);
            private.push(bytes);
        }
        let vectors: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/commitments.json")).unwrap();
        for row in vectors["vectors"].as_array().unwrap() {
            let digest = row["digest"].as_str().unwrap();
            if row["name"].as_str().unwrap().ends_with("-pre") {
                assert!(!trace.contains(digest));
                private.push(
                    (0..digest.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&digest[i..i + 2], 16).unwrap())
                        .collect(),
                );
            }
        }
        for bytes in private {
            assert!(!trace.contains(&hex(&bytes)));
            assert!(!trace.contains(&serde_json::to_string(&bytes).unwrap()));
            assert!(!trace.contains(&format!("{bytes:?}")));
        }
    }
}

#[derive(Debug)]
struct FixtureApproval;
impl pn_graph::registration::RegistrationVerifier for FixtureApproval {
    fn approval(&self, _: &pn_records::ValidatedAct) -> bool {
        true
    }
    fn removal(&self, _: &pn_records::ValidatedAct, _: pn_graph::registration::OpeningKind, _: pn_records::Position) -> bool {
        true
    }
}

fn history_act(mut body: ProposalBody, author: &str, sequence: u64, position: u64) -> pn_records::CandidateAct {
    body.id.author = author.into();
    body.id.sequence = sequence;
    for leg in &mut body.legs {
        leg.id.act = body.id.clone();
    }
    body.legs[0].source = named("addr", author);
    pn_records::CandidateAct {
        id: body.id,
        body: body.body,
        legs: body.legs,
        protocol_references: Vec::new(),
        projections: pn_records::RemovableProjections {
            content: pn_records::Removal::Live,
            dependency: pn_records::DependencyProjection::FullEmpty,
        },
        commitments: None,
        authentication_evidence: vec![1],
        finalization_epoch: 1,
        authoritative_position: position,
        logical_time: 0,
    }
}

fn settlement_history() -> Vec<pn_records::CandidateAct> {
    let seller = id(1, "Owner").author;
    let buyer = seller.replace(&"34".repeat(32), &"56".repeat(32));
    let mut owner = history_act(body("Owner"), &seller, 1, 1);
    let item = PublicReference::Minted(owner.id.clone());
    owner.legs[0].target = item.clone();
    let mut bid = history_act(body("Bid"), &buyer, 1, 2);
    bid.legs[0].target = item.clone();
    bid.legs[1].source = item;
    bid.legs[1].target = PublicReference::Minted(bid.id.clone());
    bid.projections.dependency = pn_records::DependencyProjection::Full(vec![owner.id.clone()]);
    let mut accept = history_act(body("Accept"), &seller, 2, 3);
    accept.legs[0].target = named("addr", &buyer);
    accept.body.settlement = Some(pn_records::SettlementReferences::Accept { settles: bid.id.clone() });
    let mut ratify = history_act(body("Ratify"), &buyer, 2, 4);
    ratify.legs[0].target = named("addr", &seller);
    ratify.body.settlement = Some(pn_records::SettlementReferences::Ratify {
        settles: bid.id.clone(),
        accepts: accept.id.clone(),
    });
    vec![owner, bid, accept, ratify]
}

fn attach_anchor(act: &mut pn_records::CandidateAct, ids: Vec<ActId>) {
    let proposal = ProposalCommitment {
        recipe: PROPOSAL_RECIPE.into(),
        bytes: [29; 32],
    };
    let content = content_commitment(&act.id, &proposal, &salt(1, 32), &secret(b"")).unwrap();
    let dependency = dependency_commitment(&act.id, &proposal, &salt(2, 64), &list(ids)).unwrap();
    act.commitments = Some(pn_records::commitments::ActCommitments {
        proposal,
        content,
        dependency,
    });
}

fn opened(
    history: &pn_records::ValidatedHistory,
    act: &ActId,
    ids: Vec<ActId>,
) -> Result<pn_records::ValidatedHistory, pn_records::commitments::OpeningError> {
    pn_records::replay_openings(
        history,
        &DependencyOpenings(vec![DependencyOpening {
            act: act.clone(),
            salt: salt(2, 64),
            dependencies: list(ids),
        }]),
    )
}

/// Claim: Matching tombstone openings restore exact recurrence and retain placement faults without changing settlement verdicts or title; missing or refused evidence never authenticates anchors or replaces retained carriage.
/// ´claim:profile:opened-replay-preserves-structure-and-title´
/// ´test:unit:opened-replay´
#[test]
fn opened_replay() {
    use pn_records::{DependencyProjection, replay_openings, validate_history};
    let mut acts = settlement_history();
    let dependency = acts[0].id.clone();
    let target = acts[1].id.clone();
    attach_anchor(&mut acts[1], vec![dependency.clone()]);
    let full = validate_history(&acts, &[]).unwrap();
    acts[1].projections.dependency = DependencyProjection::Tombstoned((1, 9));
    let retained = validate_history(&acts, &[]).unwrap();
    assert!(retained.unavailable_dependencies().contains(&target));
    let restored = opened(&retained, &target, vec![dependency.clone()]).unwrap();
    assert_eq!(full.time_evidence(), restored.time_evidence());
    assert_eq!(retained.acts(), restored.acts());
    assert!(restored.unavailable_dependencies().is_empty());
    let missing = replay_openings(&retained, &DependencyOpenings(Vec::new())).unwrap();
    assert_eq!(missing.time_evidence(), retained.time_evidence());
    assert!(opened(&full, &target, vec![dependency.clone()]).is_err());
    assert!(opened(&retained, &target, Vec::new()).is_err());
    assert!(opened(&retained, &target, vec![dependency.clone(), dependency.clone()]).is_err());
    assert!(
        replay_openings(
            &retained,
            &DependencyOpenings(vec![DependencyOpening {
                act: target.clone(),
                salt: secret(&[0; 47]),
                dependencies: list(vec![dependency.clone()])
            }])
        )
        .is_err()
    );
    let baseline_graph = pn_graph::formation::reconstruct_replay(&full, &FixtureApproval).unwrap();
    let baseline = pn_graph::title::replay_title(&baseline_graph, &full, &FixtureApproval, 1).unwrap();
    assert_eq!(baseline.events.len(), 1);
    assert!(baseline.boundaries[0].candidates[0].recognized);
    for history in [&retained, &restored] {
        let graph = pn_graph::formation::reconstruct_replay(history, &FixtureApproval).unwrap();
        let title = pn_graph::title::replay_title(&graph, history, &FixtureApproval, 1).unwrap();
        assert_eq!(baseline.certificate, title.certificate);
        assert_eq!(baseline.events, title.events);
        assert_eq!(baseline.consumed, title.consumed);
        assert_eq!(
            baseline.boundaries[0].candidates[0].clauses,
            title.boundaries[0].candidates[0].clauses
        );
        assert_eq!(
            baseline.boundaries[0].candidates[0].recognized,
            title.boundaries[0].candidates[0].recognized
        );
    }
    for fault in [id(999, "Registration"), acts[3].id.clone(), target.clone()] {
        let mut faulty = acts.clone();
        attach_anchor(&mut faulty[1], vec![fault.clone()]);
        let retained = validate_history(&faulty, &[]).unwrap();
        let result = opened(&retained, &target, vec![fault]).unwrap();
        assert_ne!(result.non_compliance(), []);
        assert_eq!(retained.acts(), result.acts());
        let graph = pn_graph::formation::reconstruct_replay(&result, &FixtureApproval).unwrap();
        let title = pn_graph::title::replay_title(&graph, &result, &FixtureApproval, 1).unwrap();
        assert_eq!(baseline.certificate, title.certificate);
        assert_eq!(baseline.events, title.events);
        assert_eq!(
            baseline.boundaries[0].candidates[0].clauses,
            title.boundaries[0].candidates[0].clauses
        );
    }
}
