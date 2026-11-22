use super::*;
use serde_json::Value as Json;

fn corpus() -> Json {
    serde_json::from_str(include_str!("../../../act-authentication/tests/v3-golden.json")).unwrap()
}

fn hex(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn field(row: &Json, name: &str) -> Vec<u8> {
    hex(row[name].as_str().unwrap())
}
fn body(row: &Json) -> ProposalBody {
    decode_body(&field(row, "body")).unwrap()
}
fn pair(row: &Json) -> ContentPair {
    ContentPair {
        payload: field(row, "payload").into(),
        author_content_blinding_value: field(row, "ny").into(),
    }
}
fn list(row: &Json) -> SecretBox<DependencyIds> {
    let ids = row["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| ActId {
            author: item[1].as_str().unwrap().into(),
            sequence: item[2].as_u64().unwrap(),
            family: item[3].as_str().unwrap().into(),
        })
        .collect();
    SecretBox::new(Box::new(DependencyIds(ids)))
}
fn received(row: &Json, body: &ProposalBody) -> ContentPreDigest {
    ContentPreDigest {
        act: body.id.clone(),
        bytes: field(row, "hy").into(),
    }
}
fn proposal(row: &Json) -> ProposalCommitment {
    ProposalCommitment {
        recipe: PROPOSAL_RECIPE.into(),
        bytes: field(row, "p").try_into().unwrap(),
    }
}
fn content(row: &Json) -> ContentCommitment {
    ContentCommitment {
        recipe: CONTENT_RECIPE.into(),
        bytes: field(row, "cy").try_into().unwrap(),
    }
}
fn dependency(row: &Json) -> DependencyCommitment {
    DependencyCommitment {
        recipe: DEPENDENCY_RECIPE.into(),
        bytes: field(row, "cd").try_into().unwrap(),
    }
}

fn boundary_value(source: &Json) -> Value {
    if source.is_null() {
        return Value::Null;
    }
    if let Some(number) = source.as_u64() {
        return Value::Unsigned(number);
    }
    if let Some(string) = source.as_str() {
        return Value::Text(string.to_owned().into());
    }
    if let Some(bytes) = source.get("bytes") {
        return Value::Bytes(Bytes::from(hex(bytes.as_str().unwrap())));
    }
    let entries = source.as_array().expect("boundary value is an array");
    array(entries.iter().map(boundary_value))
}

/// A complete frame of synthetic fill at the admitted ceiling passes;
/// one additional byte reaches the private bound before any digest is exposed.
/// ´claim:profile:dependency-proof-preimage-guard´
/// ´test:unit:dependency-preimage-guard´
#[test]
fn dependency_preimage_guard() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../act-authentication/tests/carrier-refusals.json")).unwrap();
    let cases: Vec<_> = corpus["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["site"] == "profile-guard")
        .collect();
    assert_eq!(cases.len(), 2);
    for row in cases {
        let fill = usize::try_from(row["construction"]["zero_bytes"].as_u64().unwrap()).unwrap();
        let bytes = usize::try_from(row["construction"]["preimage_bytes"].as_u64().unwrap()).unwrap();
        // Array(2), text head plus tag, Array(1), and five-byte bytes head.
        assert_eq!(
            DEPENDENCY_RECIPE.len() + 1 + 1 + 1 + "PN-dependency-v3".len() + 1 + 5 + fill,
            bytes
        );
        let fields = vec![SecretValue::Bytes(vec![0_u8; fill].into())];
        let result = frame_hash(DEPENDENCY_RECIPE, "PN-dependency-v3", fields);
        match row["expected"].as_str().unwrap() {
            "Valid" => assert!(result.is_ok(), "{}", row["id"]),
            "Bound" => assert!(matches!(result, Err(ProfileError::Bound)), "{}", row["id"]),
            other => panic!("unrecognized guard result: {other}"),
        }
    }
}

/// Independent B3 bytes round-trip through both selected paths and bind the independent residues.
/// ´claim:profile:version-three-body-values´
/// ´test:unit:body-values´
#[test]
fn body_values() {
    let corpus = corpus();
    for row in corpus["rows"].as_array().unwrap() {
        let expected = field(row, "body");
        let body = decode_body(&expected).unwrap();
        assert_eq!(encode_body(&body).unwrap(), expected);
        assert_eq!(body_from_projection(&body_projection(&body).unwrap()).unwrap(), body);
        assert_eq!(compare_body(&body, &body), Ok(()));
    }
}

/// B3 rejects malformed bytes and field substitutions in its admitted order.
/// ´claim:profile:version-three-body-refusal-order´
/// ´test:unit:body-order´
#[test]
fn body_order() {
    let corpus = corpus();
    let row = &corpus["rows"][0];
    let body = body(row);
    // The admitted B1 and B2 bodies are distinct selected inputs, not B3 aliases.
    for old_fixture in [
        include_str!("../../../act-authentication/tests/encoding-golden.json"),
        include_str!("../../../act-authentication/tests/v2-golden.json"),
    ] {
        let old: Json = serde_json::from_str(old_fixture).unwrap();
        let Value::Map(header) = Value::from_canonical_bytes(&field(&old["rows"][0], "header")).unwrap() else {
            panic!("admitted old header map");
        };
        let old_body = header.iter().find(|(key, _)| **key == Value::Unsigned(2)).unwrap().1;
        assert_eq!(body_from_projection(old_body), Err(ProfileError::BodyShape));
        assert_eq!(decode_body(&old_body.to_canonical_bytes()), Err(ProfileError::BodyShape));
    }
    let mut oversized = body.clone();
    oversized.signed_extension.resize(1_048_577, 0);
    oversized.id.family = "unknown".into();
    assert_eq!(body_projection(&oversized), Err(ProfileError::Bound));
    let mut changed = body.clone();
    changed.signed_extension.push(7);
    assert_eq!(compare_body(&changed, &body), Err(ProfileError::Body));
    let mut invalid = body.clone();
    invalid.id.family = "unknown".into();
    assert_eq!(body_projection(&invalid), Err(ProfileError::BodyShape));
    let mut invalid = body.clone();
    invalid.legs.clear();
    assert_eq!(body_projection(&invalid), Err(ProfileError::BodyShape));
    let mut invalid = body.clone();
    invalid.body.asserted_parents = vec![body.id.clone(), body.id.clone()];
    assert_eq!(body_projection(&invalid), Err(ProfileError::BodyShape));
    let mut invalid = body.clone();
    invalid.protocol_references.push(body.legs[0].source.clone());
    assert_eq!(body_projection(&invalid), Err(ProfileError::BodyShape));
    let mut bytes = field(row, "body");
    bytes.push(0);
    assert_eq!(decode_body(&bytes), Err(ProfileError::Canonical));
    assert_eq!(decode_body(&[u8::MAX]), Err(ProfileError::Canonical));
    assert_eq!(decode_body(&vec![u8::MAX; 1_048_577]), Err(ProfileError::Bound));
    let value = Value::from_canonical_bytes(&field(row, "body")).unwrap();
    let Value::Array(fields) = value else {
        panic!("fixture body array");
    };
    let mut fields = fields.as_slice().to_vec();
    fields[9] = Value::Text("not bytes".to_owned().into());
    assert_eq!(body_from_projection(&array(fields.clone())), Err(ProfileError::BodyShape));
    fields.pop();
    assert_eq!(body_from_projection(&array(fields)), Err(ProfileError::BodyShape));
    let boundary = &corpus["boundaries"];
    let Value::Array(prefix) = boundary_value(&boundary["body_without_extension"]) else {
        panic!("boundary body prefix");
    };
    let mut prefix = prefix.as_slice().to_vec();
    prefix.push(Value::Bytes(Bytes::from(Vec::new())));
    let base = body_from_projection(&array(prefix)).unwrap();
    for row in boundary["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["name"].as_str().unwrap().starts_with("extension"))
    {
        let mut selected = base.clone();
        selected.signed_extension = vec![0; usize::try_from(row["count"].as_u64().unwrap()).unwrap()];
        if row["result"] == "valid" {
            assert_eq!(
                encode_body(&selected).unwrap().len(),
                usize::try_from(row["encoded_bytes"].as_u64().unwrap()).unwrap()
            );
        } else {
            assert_eq!(encode_body(&selected), Err(ProfileError::Bound));
        }
    }
}

/// Full and host proposal routes reproduce all three independent residues.
/// ´claim:profile:version-three-proposal-values´
/// ´test:unit:proposal-values´
#[test]
fn proposal_values() {
    let corpus = corpus();
    for row in corpus["rows"].as_array().unwrap() {
        let body = body(row);
        let computed = computed_proposal_commitment(&body, &pair(row), &field(row, "nd").into(), &list(row)).unwrap();
        assert_eq!(computed.as_recorded(), &proposal(row));
        let host = proposal_commitment(&body, &received(row, &body), &field(row, "nd").into(), &list(row)).unwrap();
        assert_eq!(host, proposal(row));
        assert_eq!(
            proposal_matches_supplied_commitment(
                &body,
                &proposal(row),
                &received(row, &body),
                &field(row, "nd").into(),
                &list(row)
            ),
            Ok(())
        );
        assert_eq!(
            computed_proposal_matches_supplied_commitment(
                &body,
                &proposal(row),
                &pair(row),
                &field(row, "nd").into(),
                &list(row)
            ),
            Ok(())
        );
    }
}

/// Proposal recipe and supplied opening defects precede reduction and equality.
/// ´claim:profile:version-three-proposal-refusal-order´
/// ´test:unit:proposal-order´
#[test]
fn proposal_order() {
    let corpus = corpus();
    let row = &corpus["rows"][0];
    let body = body(row);
    let mut wrong = proposal(row);
    wrong.recipe = super::super::v2::PROPOSAL_RECIPE.into();
    assert_eq!(
        computed_proposal_matches_supplied_commitment(&body, &wrong, &pair(row), &field(row, "nd").into(), &list(row)),
        Err(ProfileError::Recipe)
    );
    let mut bad_hy = received(row, &body);
    bad_hy.act.sequence ^= 1;
    assert_eq!(
        proposal_commitment(&body, &bad_hy, &field(row, "nd").into(), &list(row)),
        Err(ProfileError::ContentPreDigest)
    );
    let mut bad_nd = field(row, "nd");
    bad_nd.pop();
    assert_eq!(
        computed_proposal_commitment(&body, &pair(row), &bad_nd.clone().into(), &list(row)).unwrap_err(),
        ProfileError::Blinding
    );
    let mut short_content_blinding = pair(row);
    short_content_blinding.author_content_blinding_value = vec![0; 39].into();
    assert_eq!(
        computed_proposal_commitment(&body, &short_content_blinding, &field(row, "nd").into(), &list(row)).unwrap_err(),
        ProfileError::Blinding
    );
    let mut long_content_blinding = pair(row);
    long_content_blinding.author_content_blinding_value = vec![0; 41].into();
    assert_eq!(
        computed_proposal_commitment(&body, &long_content_blinding, &bad_nd.into(), &list(row)).unwrap_err(),
        ProfileError::Blinding
    );
    let mut short_hy = received(row, &body);
    short_hy.bytes = vec![0; 31].into();
    assert_eq!(
        proposal_commitment(&body, &short_hy, &field(row, "nd").into(), &list(row)).unwrap_err(),
        ProfileError::ContentPreDigest
    );
    let mut changed = proposal(row);
    changed.bytes[0] ^= 1;
    assert_eq!(
        computed_proposal_matches_supplied_commitment(&body, &changed, &pair(row), &field(row, "nd").into(), &list(row)),
        Err(ProfileError::Proposal)
    );
    let too_many = SecretBox::new(Box::new(DependencyIds(vec![body.id.clone(); 1025])));
    assert_eq!(
        computed_proposal_commitment(&body, &pair(row), &field(row, "nd").into(), &too_many).unwrap_err(),
        ProfileError::Dependencies
    );
    let repeated = SecretBox::new(Box::new(DependencyIds(vec![body.id.clone(); 2])));
    assert_eq!(
        computed_proposal_commitment(&body, &pair(row), &field(row, "nd").into(), &repeated).unwrap_err(),
        ProfileError::Dependencies
    );
    let boundary = &corpus["boundaries"];
    let identity = &boundary["identity"];
    let id = ActId {
        author: identity[1].as_str().unwrap().into(),
        sequence: identity[2].as_u64().unwrap(),
        family: identity[3].as_str().unwrap().into(),
    };
    for row in boundary["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["name"].as_str().unwrap().starts_with("payload"))
    {
        let pair = ContentPair {
            payload: vec![0; usize::try_from(row["count"].as_u64().unwrap()).unwrap()].into(),
            author_content_blinding_value: hex(boundary["nonce"].as_str().unwrap()).into(),
        };
        let outcome = content_pre_digest(&id, &pair);
        if row["result"] == "valid" {
            assert!(outcome.is_ok());
        } else {
            assert_eq!(outcome.unwrap_err(), ProfileError::Bound);
        }
    }
}

/// Content residue agrees with independent values and absence is explicit.
/// ´claim:profile:version-three-content-values´
/// ´test:unit:content-values´
#[test]
fn content_values() {
    let corpus = corpus();
    for row in corpus["rows"].as_array().unwrap() {
        let body = body(row);
        let p = proposal(row);
        let computed = content_commitment(&body.id, &p, &field(row, "sy").into(), &received(row, &body)).unwrap();
        assert_eq!(computed, content(row));
        assert_eq!(
            content_matches_supplied_commitment(&body.id, &p, &content(row), &field(row, "sy").into(), Some(&pair(row))),
            Ok(OpeningComparison::Matches)
        );
        assert_eq!(
            content_matches_supplied_commitment(&body.id, &p, &content(row), &field(row, "sy").into(), None),
            Ok(OpeningComparison::Unavailable)
        );
    }
}

/// Content checks recipes and present formats before the absence branch.
/// ´claim:profile:version-three-content-refusal-order´
/// ´test:unit:content-order´
#[test]
fn content_order() {
    let corpus = corpus();
    let row = &corpus["rows"][0];
    let body = body(row);
    let mut wrong = proposal(row);
    wrong.recipe = super::super::v2::PROPOSAL_RECIPE.into();
    assert_eq!(
        content_matches_supplied_commitment(&body.id, &wrong, &content(row), &field(row, "sy").into(), None),
        Err(ProfileError::Recipe)
    );
    let mut wrong_content = content(row);
    wrong_content.recipe = super::super::v2::CONTENT_RECIPE.into();
    assert_eq!(
        content_matches_supplied_commitment(&body.id, &proposal(row), &wrong_content, &field(row, "sy").into(), None),
        Err(ProfileError::Recipe)
    );
    let mut invalid_id = body.id.clone();
    invalid_id.family = "unknown".into();
    assert_eq!(
        content_matches_supplied_commitment(&invalid_id, &proposal(row), &content(row), &field(row, "sy").into(), None),
        Err(ProfileError::Representation)
    );
    let mut short = field(row, "sy");
    short.pop();
    assert_eq!(
        content_matches_supplied_commitment(&body.id, &proposal(row), &content(row), &short.into(), None),
        Err(ProfileError::Blinding)
    );
    let mut changed = content(row);
    changed.bytes[0] ^= 1;
    assert_eq!(
        content_matches_supplied_commitment(&body.id, &proposal(row), &changed, &field(row, "sy").into(), Some(&pair(row))),
        Err(ProfileError::Content)
    );
    let mut bad_pair = pair(row);
    bad_pair.author_content_blinding_value = vec![0; 39].into();
    assert_eq!(
        content_matches_supplied_commitment(
            &body.id,
            &proposal(row),
            &content(row),
            &field(row, "sy").into(),
            Some(&bad_pair)
        ),
        Err(ProfileError::Blinding)
    );
    let mut bad_host = field(row, "sy");
    bad_host.push(0);
    assert_eq!(
        content_matches_supplied_commitment(&body.id, &proposal(row), &content(row), &bad_host.into(), Some(&bad_pair)),
        Err(ProfileError::Blinding)
    );
    let mut large_pair = pair(row);
    large_pair.payload = vec![0; 65_537].into();
    assert_eq!(
        content_matches_supplied_commitment(
            &body.id,
            &proposal(row),
            &content(row),
            &field(row, "sy").into(),
            Some(&large_pair)
        ),
        Err(ProfileError::Content)
    );
}

/// Complete D and `C_D` agree with independent empty and nonempty anchors.
/// ´claim:profile:version-three-dependency-values´
/// ´test:unit:dependency-values´
#[test]
fn dependency_values() {
    let corpus = corpus();
    for row in corpus["rows"].as_array().unwrap() {
        let body = body(row);
        let p = proposal(row);
        assert_eq!(
            dependency_commitment(&body.id, &p, &field(row, "sd").into(), &list(row)).unwrap(),
            dependency(row)
        );
        let opening = super::super::DependencyOpening {
            act: body.id.clone(),
            dependencies: list(row),
            host_dependency_blinding_value: field(row, "sd").into(),
        };
        assert_eq!(
            dependencies_match_supplied_commitment(&p, &dependency(row), Some(&opening)),
            Ok(OpeningComparison::Matches)
        );
        assert_eq!(
            dependencies_match_supplied_commitment(&p, &dependency(row), None),
            Ok(OpeningComparison::Unavailable)
        );
    }
}

/// Dependency recipes precede absence, then malformed D precedes equality.
/// ´claim:profile:version-three-dependency-refusal-order´
/// ´test:unit:dependency-order´
#[test]
fn dependency_order() {
    let corpus = corpus();
    let row = &corpus["rows"][0];
    let body = body(row);
    let mut wrong = dependency(row);
    wrong.recipe = super::super::v2::DEPENDENCY_RECIPE.into();
    assert_eq!(
        dependencies_match_supplied_commitment(&proposal(row), &wrong, None),
        Err(ProfileError::Recipe)
    );
    let mut changed = dependency(row);
    changed.bytes[0] ^= 1;
    let opening = super::super::DependencyOpening {
        act: body.id.clone(),
        dependencies: list(row),
        host_dependency_blinding_value: field(row, "sd").into(),
    };
    assert_eq!(
        dependencies_match_supplied_commitment(&proposal(row), &changed, Some(&opening)),
        Err(ProfileError::Dependency)
    );
    assert_eq!(check_dependency_bounds(1024, 262_144), Ok(()));
    assert_eq!(check_dependency_bounds(1024, 262_145), Err(ProfileError::Dependencies));
}
