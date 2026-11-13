use super::{change_header, field, hex};
use pn_act_authentication::v2 as auth;
use pn_act_profile::v2 as profile;
use pn_interchange::{Array, Map, Value};
use pn_records::authentication::AuthenticationFields;

fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!("../v2-golden.json")).unwrap()
}

fn dependencies(row: &serde_json::Value) -> pn_act_profile::DependencyIds {
    pn_act_profile::DependencyIds(
        row["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| pn_records::ActId {
                author: id[1].as_str().unwrap().into(),
                sequence: id[2].as_u64().unwrap(),
                family: id[3].as_str().unwrap().into(),
            })
            .collect(),
    )
}

fn pair(row: &serde_json::Value) -> profile::ContentPair {
    profile::ContentPair {
        payload: field(row, "payload").into(),
        nonce: field(row, "ny").into(),
    }
}

fn disclosure(row: &serde_json::Value, header: &auth::VerifiedHeader) -> AuthenticationFields {
    AuthenticationFields {
        proposal_precommitment: header.parts().commitments.proposal.bytes.to_vec(),
        actor_proposal_signature: header.parts().actor_signature.to_vec(),
        content_edition: "2".into(),
        dependency_edition: "2".into(),
        verified_header: header.bytes().to_vec(),
        host_seal: field(row, "seal"),
        approval_binding: vec![16; 64],
        authentication_edition: auth::AUTHENTICATION_EDITION.into(),
        public_verification_material: field(row, "material"),
    }
}

/// Conformance: three distinct unsorted fixtures match independent recipe,
/// header, material and role-message bytes; no signature or entropy is tested.
/// ´claim:authentication:version-two-golden-values´
/// ´test:integration:golden-values´
#[test]
fn golden_values() {
    let values = corpus();
    let rows = values["rows"].as_array().unwrap();
    assert_eq!(
        rows.iter().map(|r| r["case"].as_u64().unwrap()).collect::<Vec<_>>(),
        [3, 0, 7]
    );
    for row in rows {
        let header = auth::decode_header(&field(row, "header")).unwrap();
        let body = &header.parts().body;
        let projected = profile::body_projection(body).unwrap();
        assert_eq!(projected.to_canonical_bytes(), field(row, "body"));
        assert_eq!(profile::body_from_projection(&projected).unwrap(), *body);
        assert_eq!(auth::encode_header(header.parts()).unwrap(), header);
        let material = auth::decode_material(&field(row, "material"), auth::AUTHENTICATION_EDITION).unwrap();
        assert_eq!(auth::encode_material(&material).unwrap(), field(row, "material"));
        assert_eq!(
            auth::compare_header(&header, header.parts(), &disclosure(row, &header)),
            Ok(())
        );
        let computed = profile::computed_proposal_commitment(
            body,
            &pair(row),
            &field(row, "nd").into(),
            &Box::new(dependencies(row)).into(),
        )
        .unwrap();
        assert_eq!(computed.as_recorded(), &header.parts().commitments.proposal);
        let opaque = profile::ContentPreDigest {
            act: body.structural.id.clone(),
            bytes: field(row, "hy").into(),
        };
        assert_eq!(profile::content_pair_matches(body, &opaque, None), Ok(false));
        assert_eq!(profile::content_pair_matches(body, &opaque, Some(&pair(row))), Ok(true));
        let mut bad_pair = pair(row);
        let mut nonce = field(row, "ny");
        nonce[39] ^= 1;
        bad_pair.nonce = nonce.into();
        assert_eq!(
            profile::content_pair_matches(body, &opaque, Some(&bad_pair)),
            Err(pn_act_profile::ProfileError::Mismatch)
        );
        assert_eq!(
            profile::proposal_commitment(body, &opaque, &field(row, "nd").into(), &Box::new(dependencies(row)).into()).unwrap(),
            *computed.as_recorded()
        );
        assert_eq!(
            profile::content_commitment(&body.structural.id, computed.as_recorded(), &field(row, "sy").into(), &opaque).unwrap(),
            header.parts().commitments.content
        );
        assert_eq!(
            profile::content_matches_supplied_commitment(
                &body.structural.id,
                computed.as_recorded(),
                &header.parts().commitments.content,
                &field(row, "sy").into(),
                &pair(row)
            ),
            Ok(())
        );
        let run = field(row, "run").try_into().unwrap();
        let host = row["host"].as_str().unwrap();
        let seal = field(row, "seal").try_into().unwrap();
        assert_eq!(
            auth::proposal_message(&computed).bytes().as_slice(),
            hex(row["messages"][0].as_str().unwrap())
        );
        assert_eq!(
            auth::seal_message(&run, host, &header).unwrap().bytes().as_slice(),
            hex(row["messages"][1].as_str().unwrap())
        );
        assert_eq!(
            auth::approval_message(&run, host, &header, &seal).unwrap().bytes().as_slice(),
            hex(row["messages"][2].as_str().unwrap())
        );
    }
}

/// Robustness: missing retirement data, wrong editions and independently
/// supplied conflicting identity or retirement fields refuse, without upgrade.
/// ´claim:authentication:version-two-refusals´
/// ´test:integration:refusals´
#[test]
fn refusals() {
    let values = corpus();
    let row = &values["rows"][0];
    let bytes = field(row, "header");
    let header = auth::decode_header(&bytes).unwrap();
    let Value::Array(body) = profile::body_projection(&header.parts().body).unwrap() else {
        panic!("fixture body")
    };
    let mut missing = body.as_slice().to_vec();
    missing.remove(1);
    let missing = Value::Array(Array::new(missing));
    assert_eq!(
        profile::body_from_projection(&missing),
        Err(pn_act_profile::ProfileError::Representation),
        "missing retirement field must refuse"
    );
    assert_eq!(
        auth::decode_header(&change_header(&bytes, 2, &missing)),
        Err(auth::EncodingError::Body)
    );
    for version in [[2, 1, 0], [1, 0, 0], [2, 0, 1]] {
        let bad = change_header(&bytes, 1, &Value::Array(Array::new(version.map(Value::Unsigned))));
        assert_eq!(
            auth::decode_header(&bad),
            Err(auth::EncodingError::Edition),
            "wrong edition must refuse"
        );
    }
    assert!(pn_act_authentication::decode_header(&bytes).is_err());
    assert_eq!(
        auth::decode_header(&field(&super::corpus()["rows"][0], "header")),
        Err(auth::EncodingError::Edition)
    );
    assert_eq!(
        auth::decode_material(&field(row, "material"), pn_act_authentication::AUTHENTICATION_EDITION),
        Err(auth::EncodingError::Edition)
    );
    let disclosure = disclosure(row, &header);
    let mut expected = header.parts().clone();
    expected.body.structural.id.sequence ^= 1;
    for leg in &mut expected.body.structural.legs {
        leg.id.act = expected.body.structural.id.clone();
    }
    assert!(
        profile::body_projection(&expected.body).is_ok(),
        "conflicting identity stays well formed"
    );
    assert_eq!(
        auth::compare_header(&header, &expected, &disclosure),
        Err(auth::EncodingError::Body),
        "identity confusion must refuse"
    );
    expected = header.parts().clone();
    expected.body.retirement_point[0] ^= 1;
    assert_eq!(expected.body.structural.id, header.parts().body.structural.id);
    assert_eq!(
        auth::compare_header(&header, &expected, &disclosure),
        Err(auth::EncodingError::Body)
    );
    let Value::Map(map) = Value::from_canonical_bytes(&bytes).unwrap() else {
        panic!("fixture map")
    };
    for key in 0..9 {
        let missing = Value::Map(
            Map::new(
                map.iter()
                    .filter(|(k, _)| **k != Value::Unsigned(key))
                    .map(|(k, v)| (k.clone(), v.clone())),
            )
            .unwrap(),
        );
        assert_eq!(
            auth::decode_header(&missing.to_canonical_bytes()),
            Err(auth::EncodingError::Shape)
        );
    }
}

/// Conformance and robustness: three-part dependency openings match supplied
/// anchors for zero, two and 1024 dependencies; changed parts do not match.
/// Neither private nonce is an opening input or an authenticity conclusion.
/// ´claim:authentication:version-two-dependency-proof´
/// ´test:integration:dependency-proof´
#[test]
fn dependency_proof() {
    let values = corpus();
    for row in values["rows"].as_array().unwrap() {
        let header = auth::decode_header(&field(row, "header")).unwrap();
        let parts = header.parts();
        let mut opening = pn_act_profile::DependencyOpening {
            act: parts.body.structural.id.clone(),
            dependencies: Box::new(dependencies(row)).into(),
            salt: field(row, "sd").into(),
        };
        let check = |o: &pn_act_profile::DependencyOpening| {
            profile::dependencies_match_supplied_commitment(o, &parts.commitments.proposal, &parts.commitments.dependency)
        };
        assert_eq!(check(&opening), Ok(()));
        opening.act.sequence ^= 1;
        assert_eq!(check(&opening), Err(pn_act_profile::ProfileError::Mismatch));
        opening.act = parts.body.structural.id.clone();
        let mut salt = field(row, "sd");
        salt[0] ^= 1;
        opening.salt = salt.into();
        assert_eq!(check(&opening), Err(pn_act_profile::ProfileError::Mismatch));
        opening.salt = field(row, "sd").into();
        let mut ids = dependencies(row);
        if ids.0.is_empty() {
            ids.0.push(parts.body.structural.id.clone());
        } else {
            ids.0.remove(0);
        }
        opening.dependencies = Box::new(ids).into();
        assert_eq!(check(&opening), Err(pn_act_profile::ProfileError::Mismatch));
        let mut wrong = parts.commitments.proposal.clone();
        wrong.recipe = pn_act_profile::PROPOSAL_RECIPE.into();
        assert_eq!(
            profile::dependencies_match_supplied_commitment(&opening, &wrong, &parts.commitments.dependency),
            Err(pn_act_profile::ProfileError::Recipe)
        );
    }
}

/// Robustness: each original field and each duplicated disclosure field has
/// its distinct refusal; malformed material and its edition also refuse.
/// Each negative changes one field after an equal positive control.
/// ´claim:authentication:version-two-header-comparison-refuses-each-field´
/// ´test:integration:header-field-refusals´
#[test]
fn header_field_refusals() {
    let values = corpus();
    let row = &values["rows"][0];
    let header = auth::decode_header(&field(row, "header")).unwrap();
    let original = header.parts();
    let disclosure = disclosure(row, &header);
    assert_eq!(auth::compare_header(&header, original, &disclosure), Ok(()));
    for (field, error) in [
        ("body", auth::EncodingError::Body),
        ("proposal", auth::EncodingError::Proposal),
        ("content", auth::EncodingError::Content),
        ("dependency", auth::EncodingError::Dependency),
        ("signature", auth::EncodingError::ActorSignature),
        ("content-edition", auth::EncodingError::ContentEdition),
        ("dependency-edition", auth::EncodingError::DependencyEdition),
    ] {
        let mut changed = original.clone();
        match field {
            "body" => changed.body.retirement_point[0] ^= 1,
            "proposal" => changed.commitments.proposal.bytes[0] ^= 1,
            "content" => changed.commitments.content.bytes[0] ^= 1,
            "dependency" => changed.commitments.dependency.bytes[0] ^= 1,
            "signature" => changed.actor_signature[0] ^= 1,
            "content-edition" => changed.content_edition.push('x'),
            "dependency-edition" => changed.dependency_edition.push('x'),
            _ => unreachable!(),
        }
        assert_eq!(
            auth::compare_header(&header, &changed, &disclosure),
            Err(error),
            "expected {field}"
        );
    }
    for (field, error) in [
        ("proposal", auth::EncodingError::Proposal),
        ("signature", auth::EncodingError::ActorSignature),
        ("content-edition", auth::EncodingError::ContentEdition),
        ("dependency-edition", auth::EncodingError::DependencyEdition),
        ("header-bytes", auth::EncodingError::HeaderBytes),
        ("material-edition", auth::EncodingError::Edition),
        ("material", auth::EncodingError::Shape),
    ] {
        let mut changed = disclosure.clone();
        match field {
            "proposal" => changed.proposal_precommitment[0] ^= 1,
            "signature" => changed.actor_proposal_signature[0] ^= 1,
            "content-edition" => changed.content_edition.push('x'),
            "dependency-edition" => changed.dependency_edition.push('x'),
            "header-bytes" => changed.verified_header.push(0),
            "material-edition" => changed.authentication_edition.push('x'),
            "material" => changed.public_verification_material = vec![0],
            _ => unreachable!(),
        }
        assert_eq!(
            auth::compare_header(&header, original, &changed),
            Err(error),
            "disclosure {field}"
        );
    }
}

/// Robustness: a foreign namespace and a changed recipe in each of the
/// three commitment keys refuse with the specific representation error.
/// Each negative preserves every other field of the admitted header.
/// ´claim:authentication:version-two-header-domain-refusals´
/// ´test:integration:header-domain-refusals´
#[test]
fn header_domain_refusals() {
    let values = corpus();
    let bytes = field(&values["rows"][0], "header");
    assert!(auth::decode_header(&bytes).is_ok());
    let foreign = change_header(&bytes, 0, &Value::Text("foreign".to_owned().into()));
    assert_eq!(auth::decode_header(&foreign), Err(auth::EncodingError::Shape), "namespace");
    let Value::Map(map) = Value::from_canonical_bytes(&bytes).unwrap() else {
        panic!("fixture map")
    };
    for key in [3, 5, 6] {
        let (_, Value::Array(pair)) = map.iter().find(|(k, _)| **k == Value::Unsigned(key)).unwrap() else {
            panic!("fixture pair")
        };
        let changed = Value::Array(Array::new([
            Value::Text("unknown".to_owned().into()),
            pair.as_slice()[1].clone(),
        ]));
        assert_eq!(
            auth::decode_header(&change_header(&bytes, key, &changed)),
            Err(auth::EncodingError::Recipe),
            "recipe key {key}"
        );
    }
}
