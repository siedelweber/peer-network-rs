use super::{change_header, field, hex};
use pn_act_authentication::v3 as auth;
use pn_act_profile::v3 as profile;
use pn_interchange::{Array, Bytes, Map, Value};

fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!("../v3-golden.json")).unwrap()
}

fn context(row: &serde_json::Value, body: &profile::ProposalBody) -> auth::MaterialContext {
    auth::MaterialContext {
        selected_run: field(row, "run").try_into().unwrap(),
        act: body.id.clone(),
        expected_host: row["host"].as_str().unwrap().into(),
        header_version: [3, 0, 0],
    }
}

fn opening(row: &serde_json::Value, act: &pn_records::ActId) -> pn_act_profile::DependencyOpening {
    let ids = row["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| pn_records::ActId {
            author: id[1].as_str().unwrap().into(),
            sequence: id[2].as_u64().unwrap(),
            family: id[3].as_str().unwrap().into(),
        })
        .collect();
    pn_act_profile::DependencyOpening {
        act: act.clone(),
        dependencies: Box::new(pn_act_profile::DependencyIds(ids)).into(),
        host_dependency_blinding_value: field(row, "sd").into(),
    }
}

fn computed(row: &serde_json::Value, body: &profile::ProposalBody) -> profile::ComputedProposalCommitment {
    let opening = opening(row, &body.id);
    profile::computed_proposal_commitment(
        body,
        &profile::ContentPair {
            payload: field(row, "payload").into(),
            author_content_blinding_value: field(row, "ny").into(),
        },
        &field(row, "nd").into(),
        &opening.dependencies,
    )
    .unwrap()
}

fn changed_recipe(bytes: &[u8], key: u64, recipe: &str) -> Vec<u8> {
    let Value::Map(map) = Value::from_canonical_bytes(bytes).unwrap() else {
        panic!("fixture header map");
    };
    let (_, Value::Array(pair)) = map.iter().find(|(field, _)| **field == Value::Unsigned(key)).unwrap() else {
        panic!("fixture recipe pair");
    };
    change_header(
        bytes,
        key,
        &Value::Array(Array::new([
            Value::Text(recipe.to_owned().into()),
            pair.as_slice()[1].clone(),
        ])),
    )
}

/// Three independent canonical headers agree with the selected pure producer and comparator.
/// ´claim:authentication:version-three-header-values´
/// ´test:integration:header-values´
#[test]
fn header_values() {
    let corpus = corpus();
    for row in corpus["rows"].as_array().unwrap() {
        let bytes = field(row, "header");
        let decoded = auth::decode_header(&bytes).unwrap();
        assert_eq!(auth::encode_header(decoded.parts()).unwrap().bytes(), bytes);
        assert_eq!(auth::compare_header(&bytes, decoded.parts()), Ok(()));
        assert_eq!(profile::encode_body(&decoded.parts().body).unwrap(), field(row, "body"));
    }
}

/// Header byte, field and adjacent-overlap refusals preserve the admitted order.
/// ´claim:authentication:version-three-header-refusal-order´
/// ´test:integration:header-order´
#[test]
fn header_order() {
    let corpus = corpus();
    let row = &corpus["rows"][0];
    let bytes = field(row, "header");
    let header = auth::decode_header(&bytes).unwrap();
    let mut wrong = header.parts().clone();
    wrong.body.signed_extension.push(1);
    wrong.commitments.proposal.bytes[0] ^= 1;
    assert_eq!(auth::compare_header(&bytes, &wrong), Err(auth::EncodingError::Body));
    let mut wrong = header.parts().clone();
    wrong.commitments.proposal.bytes[0] ^= 1;
    wrong.commitments.content.bytes[0] ^= 1;
    assert_eq!(auth::compare_header(&bytes, &wrong), Err(auth::EncodingError::Proposal));
    let mut wrong = header.parts().clone();
    wrong.commitments.content.bytes[0] ^= 1;
    assert_eq!(auth::compare_header(&bytes, &wrong), Err(auth::EncodingError::Content));
    let mut wrong = header.parts().clone();
    wrong.commitments.dependency.bytes[0] ^= 1;
    assert_eq!(auth::compare_header(&bytes, &wrong), Err(auth::EncodingError::Dependency));
    let mut wrong = header.parts().clone();
    wrong.actor_signature[0] ^= 1;
    assert_eq!(auth::compare_header(&bytes, &wrong), Err(auth::EncodingError::ActorSignature));
    for (key, recipe) in [
        (3, pn_act_profile::v2::PROPOSAL_RECIPE),
        (5, pn_act_profile::v2::CONTENT_RECIPE),
        (6, pn_act_profile::v2::DEPENDENCY_RECIPE),
    ] {
        assert_eq!(
            auth::decode_header(&changed_recipe(&bytes, key, recipe)),
            Err(auth::EncodingError::Recipe)
        );
    }
    assert_eq!(
        auth::decode_header(&change_header(&bytes, 7, &Value::Text("2".to_owned().into()))),
        Err(auth::EncodingError::ContentEdition)
    );
    assert_eq!(
        auth::decode_header(&change_header(&bytes, 8, &Value::Text("2".to_owned().into()))),
        Err(auth::EncodingError::DependencyEdition)
    );
    let changed = change_header(&bytes, 1, &Value::Array(Array::new([3, 0, 1].map(Value::Unsigned))));
    assert_eq!(auth::decode_header(&changed), Err(auth::EncodingError::Edition));
    let changed = change_header(&bytes, 0, &Value::Text("foreign".to_owned().into()));
    assert_eq!(auth::decode_header(&changed), Err(auth::EncodingError::Edition));
    let changed = change_header(&bytes, 0, &Value::Unsigned(7));
    assert_eq!(auth::decode_header(&changed), Err(auth::EncodingError::Edition));
    // A selected legacy consumer never upgrades a major-three header by reading its bytes.
    assert_eq!(
        pn_act_authentication::decode_header(&bytes),
        Err(pn_act_authentication::EncodingError::Edition)
    );
    assert_eq!(
        pn_act_authentication::v2::decode_header(&bytes),
        Err(pn_act_authentication::v2::EncodingError::Edition)
    );
    let Value::Map(map) = Value::from_canonical_bytes(&bytes).unwrap() else {
        panic!("fixture map");
    };
    let missing = Value::Map(
        Map::new(
            map.iter()
                .filter(|(key, _)| **key != Value::Unsigned(4))
                .map(|(key, value)| (key.clone(), value.clone())),
        )
        .unwrap(),
    );
    assert_eq!(
        auth::decode_header(&missing.to_canonical_bytes()),
        Err(auth::EncodingError::Shape)
    );
    let mut malformed = bytes.clone();
    malformed.push(0);
    assert_eq!(auth::decode_header(&malformed), Err(auth::EncodingError::Canonical));
    assert_eq!(auth::decode_header(&vec![0xff; 2_097_153]), Err(auth::EncodingError::Bound));
}

/// Three material values agree under independently selected run and host contexts.
/// ´claim:authentication:version-three-material-values´
/// ´test:integration:material-values´
#[test]
fn material_values() {
    let corpus = corpus();
    for row in corpus["rows"].as_array().unwrap() {
        let body = profile::decode_body(&field(row, "body")).unwrap();
        let context = context(row, &body);
        let bytes = field(row, "material");
        let material = auth::decode_material(&bytes, &context).unwrap();
        assert_eq!(auth::encode_material(&material, &context).unwrap(), bytes);
    }
}

/// Material refuses first on shape, edition, run, host and header version.
/// ´claim:authentication:version-three-material-refusal-order´
/// ´test:integration:material-order´
#[test]
fn material_order() {
    let corpus = corpus();
    let row = &corpus["rows"][0];
    let body = profile::decode_body(&field(row, "body")).unwrap();
    let context = context(row, &body);
    let bytes = field(row, "material");
    // The same selection boundary holds for public material.
    assert_eq!(
        pn_act_authentication::decode_material(&bytes, pn_act_authentication::AUTHENTICATION_EDITION),
        Err(pn_act_authentication::EncodingError::Edition)
    );
    assert_eq!(
        pn_act_authentication::v2::decode_material(&bytes, pn_act_authentication::v2::AUTHENTICATION_EDITION),
        Err(pn_act_authentication::v2::EncodingError::Edition)
    );
    let mut changed = context.clone();
    changed.selected_run[0] ^= 1;
    assert_eq!(auth::decode_material(&bytes, &changed), Err(auth::EncodingError::Run));
    let mut changed = context.clone();
    changed.expected_host.push('x');
    changed.header_version = [2, 0, 0];
    assert_eq!(auth::decode_material(&bytes, &changed), Err(auth::EncodingError::Host));
    let mut changed = context.clone();
    changed.header_version = [2, 0, 0];
    assert_eq!(auth::decode_material(&bytes, &changed), Err(auth::EncodingError::Edition));
    let Value::Array(material) = Value::from_canonical_bytes(&bytes).unwrap() else {
        panic!("fixture material");
    };
    let mut fields = material.as_slice().to_vec();
    fields[0] = Value::Text("pn-act-authentication/author-token-bip340/v2".to_owned().into());
    assert_eq!(
        auth::decode_material(&Value::Array(Array::new(fields)).to_canonical_bytes(), &context),
        Err(auth::EncodingError::Edition)
    );
    for index in 1..5 {
        let mut malformed = material.as_slice().to_vec();
        malformed[index] = Value::Unsigned(7);
        assert_eq!(
            auth::decode_material(&Value::Array(Array::new(malformed)).to_canonical_bytes(), &context),
            Err(auth::EncodingError::Shape)
        );
    }
    let mut malformed = material.as_slice().to_vec();
    malformed.pop();
    assert_eq!(
        auth::decode_material(&Value::Array(Array::new(malformed)).to_canonical_bytes(), &context),
        Err(auth::EncodingError::Shape)
    );
    let mut wrong_key = material.as_slice().to_vec();
    wrong_key[4] = Value::Bytes(Bytes::from(vec![0; 32]));
    assert_eq!(
        auth::decode_material(&Value::Array(Array::new(wrong_key)).to_canonical_bytes(), &context),
        Err(auth::EncodingError::Host)
    );
    assert_eq!(
        auth::decode_material(&vec![0xff; 513], &context),
        Err(auth::EncodingError::Bound)
    );
    assert_eq!(auth::decode_material(&[0xff], &context), Err(auth::EncodingError::Canonical));
}

/// Three independently framed role messages agree without asserting signatures.
/// ´claim:authentication:version-three-roles-values´
/// ´test:integration:roles-values´
#[test]
fn roles_values() {
    let corpus = corpus();
    for row in corpus["rows"].as_array().unwrap() {
        let header = auth::decode_header(&field(row, "header")).unwrap();
        let context = context(row, &header.parts().body);
        let material = auth::decode_material(&field(row, "material"), &context).unwrap();
        let proposal = auth::proposal_message(&computed(row, &header.parts().body));
        let seal = auth::seal_message(&material, &context, &header).unwrap();
        let approval = auth::approval_message(&material, &context, &header, &field(row, "seal").try_into().unwrap()).unwrap();
        assert!(proposal.matches_bytes(&hex(row["messages"][0].as_str().unwrap())));
        assert!(seal.matches_bytes(&hex(row["messages"][1].as_str().unwrap())));
        assert!(approval.matches_bytes(&hex(row["messages"][2].as_str().unwrap())));
        assert!(!proposal.matches_bytes(seal.bytes()));
        assert!(!seal.matches_bytes(approval.bytes()));
        assert!(!approval.matches_bytes(proposal.bytes()));
    }
}

/// Role framing refuses invalid material and major-version context first.
/// ´claim:authentication:version-three-roles-refusal-order´
/// ´test:integration:roles-order´
#[test]
fn roles_order() {
    let corpus = corpus();
    let row = &corpus["rows"][0];
    let header = auth::decode_header(&field(row, "header")).unwrap();
    let context = context(row, &header.parts().body);
    let material = auth::decode_material(&field(row, "material"), &context).unwrap();
    let mut changed = context.clone();
    changed.expected_host.push('x');
    changed.header_version = [2, 0, 0];
    assert_eq!(
        auth::seal_message(&material, &changed, &header),
        Err(auth::EncodingError::Host)
    );
    assert_eq!(
        auth::approval_message(&material, &changed, &header, &field(row, "seal").try_into().unwrap()),
        Err(auth::EncodingError::Host)
    );
    let mut changed = context.clone();
    changed.header_version = [2, 0, 0];
    assert_eq!(
        auth::seal_message(&material, &changed, &header),
        Err(auth::EncodingError::Edition)
    );
    let foreign = auth::decode_header(&field(&corpus["rows"][1], "header")).unwrap();
    assert_ne!(foreign.parts().body.id.author, header.parts().body.id.author);
    assert_eq!(
        auth::seal_message(&material, &context, &foreign),
        Err(auth::EncodingError::Run)
    );
    assert_eq!(
        auth::approval_message(&material, &context, &foreign, &field(row, "seal").try_into().unwrap()),
        Err(auth::EncodingError::Run)
    );
}
