use pn_act_authentication::*;
use pn_interchange::{Array, Map, Value};
use std::collections::BTreeSet;

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!("encoding-golden.json")).unwrap()
}
fn field(row: &serde_json::Value, name: &str) -> Vec<u8> {
    hex(row[name].as_str().unwrap())
}
fn computed(row: &serde_json::Value, body: &pn_act_profile::ProposalBody) -> pn_act_profile::ComputedProposalCommitment {
    let dependencies = row["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| pn_records::ActId {
            author: id[1].as_str().unwrap().into(),
            sequence: id[2].as_u64().unwrap(),
            family: id[3].as_str().unwrap().into(),
        })
        .collect();
    pn_act_profile::computed_proposal_commitment(
        body,
        &field(row, "nonce").into(),
        &field(row, "payload").into(),
        &Box::new(pn_act_profile::DependencyIds(dependencies)).into(),
    )
    .unwrap()
}
fn role_type<T: 'static>(_: &T) -> std::any::TypeId {
    std::any::TypeId::of::<T>()
}
fn change_header(input: &[u8], key: u64, value: &Value) -> Vec<u8> {
    let Value::Map(m) = Value::from_canonical_bytes(input).unwrap() else {
        panic!("fixture map")
    };
    Value::Map(
        Map::new(m.iter().map(|(k, v)| {
            (
                k.clone(),
                if *k == Value::Unsigned(key) {
                    value.clone()
                } else {
                    v.clone()
                },
            )
        }))
        .unwrap(),
    )
    .to_canonical_bytes()
}

/// Independent canonical bytes round trip through typed parts without repair.
/// Five distinct fixtures reach the operations in deliberately unsorted order.
/// Their decoded bodies and retained openings recompute P through the profile encoder.
/// ´claim:authentication:canonical-header-material´
/// ´test:integration:canonical-header-material´
#[test]
fn canonical_header_material() {
    let values = corpus();
    for row in values["rows"].as_array().unwrap() {
        let bytes = field(row, "header");
        let header = decode_header(&bytes).unwrap();
        assert_eq!(encode_header(header.parts()).unwrap(), header);
        assert_eq!(header.bytes(), bytes);
        let dependencies = row["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| pn_records::ActId {
                author: id[1].as_str().unwrap().into(),
                sequence: id[2].as_u64().unwrap(),
                family: id[3].as_str().unwrap().into(),
            })
            .collect();
        let proposal = pn_act_profile::proposal_commitment(
            &header.parts().body,
            &field(row, "nonce").into(),
            &field(row, "payload").into(),
            &Box::new(pn_act_profile::DependencyIds(dependencies)).into(),
        )
        .unwrap();
        assert_eq!(
            proposal,
            header.parts().commitments.proposal,
            "profile commitment binds golden body"
        );
        let projected = pn_act_profile::body_projection(&header.parts().body).unwrap();
        assert_eq!(pn_act_profile::body_from_projection(&projected).unwrap(), header.parts().body);
        let material_bytes = field(row, "material");
        let material = decode_material(&material_bytes, AUTHENTICATION_EDITION).unwrap();
        assert_eq!(encode_material(&material).unwrap(), material_bytes);
        let Value::Array(a) = Value::from_canonical_bytes(&material_bytes).unwrap() else {
            panic!("material")
        };
        for index in [4, 1, 2] {
            for length in [33, 0, 31] {
                let mut fields = a.as_slice().to_vec();
                fields[index] = Value::Bytes(vec![0; length].into());
                assert_eq!(
                    decode_material(&Value::Array(Array::new(fields)).to_canonical_bytes(), AUTHENTICATION_EDITION),
                    Err(EncodingError::Shape)
                );
            }
        }
        let mut fields = a.into_vec();
        fields[0] = Value::Text("unknown".to_owned().into());
        assert_eq!(
            decode_material(&Value::Array(Array::new(fields)).to_canonical_bytes(), AUTHENTICATION_EDITION),
            Err(EncodingError::Edition)
        );

        assert_eq!(decode_material(&material_bytes, "unknown"), Err(EncodingError::Edition));
        for version in [[1, 0, 1], [0, 0, 0], [1, 1, 0], [2, 0, 0], [1, 0, u64::MAX]] {
            let bad = change_header(&bytes, 1, &Value::Array(Array::new(version.map(Value::Unsigned))));
            assert_eq!(decode_header(&bad), Err(EncodingError::Edition));
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_header(&trailing), Err(EncodingError::Canonical));
        let mut long = bytes.clone();
        long.splice(1..2, [0x18, 0]);
        assert_eq!(decode_header(&long), Err(EncodingError::Canonical));
        let mut indefinite = bytes.clone();
        indefinite[0] = 0xbf;
        indefinite.push(0xff);
        assert_eq!(decode_header(&indefinite), Err(EncodingError::Canonical));
        let Value::Map(m) = Value::from_canonical_bytes(&bytes).unwrap() else {
            panic!("map")
        };
        let entries: Vec<_> = m
            .iter()
            .map(|(k, v)| [k.to_canonical_bytes(), v.to_canonical_bytes()].concat())
            .collect();
        let mut reordered = vec![0xa9];
        for i in [1, 0, 2, 3, 4, 5, 6, 7, 8] {
            reordered.extend(&entries[i]);
        }
        assert_eq!(decode_header(&reordered), Err(EncodingError::Canonical));
        let mut duplicate = vec![0xaa];
        duplicate.extend(&entries[0]);
        duplicate.extend_from_slice(&bytes[1..]);
        assert_eq!(decode_header(&duplicate), Err(EncodingError::Canonical));
        let missing = Value::Map(
            Map::new(
                m.iter()
                    .filter(|(k, _)| **k != Value::Unsigned(8))
                    .map(|(k, v)| (k.clone(), v.clone())),
            )
            .unwrap(),
        )
        .to_canonical_bytes();
        assert_eq!(decode_header(&missing), Err(EncodingError::Shape));
    }
}

/// Three recipe outputs agree with independent framing and SHA-256; only a
/// profile-computed commitment produces a proposal role. An unopened seal digest
/// remains a different type and establishes no proposal relation.
/// ´claim:authentication:role-messages-match-golden-values´
/// ´test:integration:role-messages´
#[test]
fn role_messages() {
    let values = corpus();
    let mut seen = BTreeSet::new();
    for row in values["rows"].as_array().unwrap() {
        let header = decode_header(&field(row, "header")).unwrap();
        let run: [u8; 32] = field(row, "run").try_into().unwrap();
        let host = row["host"].as_str().unwrap();
        let seal: [u8; 64] = field(row, "seal").try_into().unwrap();
        assert_eq!(seal_message(&run, "wrong-host", &header), Err(EncodingError::Shape));
        assert_eq!(
            approval_message(&run, "wrong-host", &header, &seal),
            Err(EncodingError::Shape)
        );
        let computed_message = proposal_message(&computed(row, &header.parts().body));
        let actual = [
            *computed_message.bytes(),
            *seal_message(&run, host, &header).unwrap().bytes(),
            *approval_message(&run, host, &header, &seal).unwrap().bytes(),
        ];
        for (message, expected) in actual.iter().zip(row["messages"].as_array().unwrap()) {
            assert_eq!(message.as_slice(), hex(expected.as_str().unwrap()));
            assert!(seen.insert(*message));
        }
        let supplied_seal = pn_records::commitments::ProposalCommitment {
            recipe: pn_act_profile::PROPOSAL_RECIPE.into(),
            bytes: *seal_message(&run, host, &header).unwrap().bytes(),
        };
        let unopened = unopened_proposal_digest(&supplied_seal).unwrap();
        assert_eq!(unopened.bytes(), &supplied_seal.bytes);
        assert_ne!(
            role_type(&unopened),
            role_type(&computed_message),
            "unopened seal digest is not a proposal message"
        );
        let host2 = host.replace("0a", "0b");
        let mut parts2 = header.parts().clone();
        parts2.actor_signature[0] ^= 1;
        let header2 = encode_header(&parts2).unwrap();
        let mut run2 = run;
        run2[0] ^= 1;
        for (r, h, v) in [
            (&run2, host, &header),
            (&run, host2.as_str(), &header),
            (&run, host, &header2),
        ] {
            assert_ne!(seal_message(&run, host, &header), seal_message(r, h, v));
            assert_ne!(approval_message(&run, host, &header, &seal), approval_message(r, h, v, &seal));
        }
        let mut seal2 = seal;
        seal2[0] ^= 1;
        assert_ne!(
            approval_message(&run, host, &header, &seal),
            approval_message(&run, host, &header, &seal2)
        );
    }
    assert_eq!(seen.len(), 15);
}

/// Every independently compared field has a distinct refusal; no residue is
/// omitted when the original parts and retained disclosure are compared.
/// ´claim:authentication:header-comparison-refuses-each-field´
/// ´test:integration:header-comparison´
#[test]
fn header_comparison() {
    use pn_records::authentication::AuthenticationFields;
    let values = corpus();
    let row = &values["rows"][1];
    let header = decode_header(&field(row, "header")).unwrap();
    let original = header.parts();
    let disclosure = AuthenticationFields {
        proposal_precommitment: original.commitments.proposal.bytes.to_vec(),
        actor_proposal_signature: original.actor_signature.to_vec(),
        content_edition: "1".into(),
        dependency_edition: "1".into(),
        verified_header: header.bytes().to_vec(),
        host_seal: vec![15; 64],
        approval_binding: vec![16; 64],
        authentication_edition: AUTHENTICATION_EDITION.into(),
        public_verification_material: field(row, "material"),
    };
    assert_eq!(compare_header(&header, original, &disclosure), Ok(()));
    let mut act = pn_records::CandidateAct {
        commitments: Some(original.commitments.clone()),
        id: original.body.id.clone(),
        body: original.body.body.clone(),
        legs: original.body.legs.clone(),
        projections: pn_records::RemovableProjections {
            content: pn_records::Removal::Live,
            dependency: pn_records::DependencyProjection::FullEmpty,
        },
        protocol_references: original.body.protocol_references.clone(),
        authentication_evidence: disclosure.clone(),
        finalization_epoch: 1,
        authoritative_position: 1,
        logical_time: 1,
    };
    assert_eq!(compare_act(&header, &act), Ok(()));
    act.id.sequence += 1;
    assert_eq!(compare_act(&header, &act), Err(EncodingError::Body));

    for (field, expected) in [
        (3, EncodingError::Dependency),
        (0, EncodingError::Body),
        (5, EncodingError::ContentEdition),
        (2, EncodingError::Content),
        (1, EncodingError::Proposal),
        (6, EncodingError::DependencyEdition),
        (4, EncodingError::ActorSignature),
    ] {
        let mut changed = original.clone();
        match field {
            0 => changed.body.id.sequence += 1,
            1 => changed.commitments.proposal.bytes[0] ^= 1,
            2 => changed.commitments.content.bytes[0] ^= 1,
            3 => changed.commitments.dependency.bytes[0] ^= 1,
            4 => changed.actor_signature[0] ^= 1,
            5 => changed.content_edition.push('x'),
            6 => changed.dependency_edition.push('x'),
            _ => unreachable!(),
        }
        assert_eq!(compare_header(&header, &changed, &disclosure), Err(expected));
    }
    for (field, expected) in [
        (4, EncodingError::HeaderBytes),
        (0, EncodingError::Proposal),
        (6, EncodingError::Shape),
        (2, EncodingError::ContentEdition),
        (5, EncodingError::Edition),
        (1, EncodingError::ActorSignature),
        (3, EncodingError::DependencyEdition),
    ] {
        let mut changed = disclosure.clone();
        match field {
            0 => changed.proposal_precommitment[0] ^= 1,
            1 => changed.actor_proposal_signature[0] ^= 1,
            2 => changed.content_edition.push('x'),
            3 => changed.dependency_edition.push('x'),
            4 => changed.verified_header.push(0),
            5 => changed.authentication_edition.push('x'),
            6 => changed.public_verification_material = vec![0],
            _ => unreachable!(),
        }
        assert_eq!(compare_header(&header, original, &changed), Err(expected));
    }
}
