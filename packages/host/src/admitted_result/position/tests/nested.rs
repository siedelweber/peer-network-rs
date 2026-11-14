use super::*;

fn fields(value: &Value) -> &[Value] {
    let Value::Array(array) = value else {
        panic!("publication array")
    };
    array.as_slice()
}

fn canonical(value: &Value) -> Vec<u8> {
    value
        .to_canonical_bytes_budgeted(usize::MAX, &mut EncodingUsage::default(), |_| Ok(()))
        .unwrap()
}

fn compare(name: &str, kind: &str, actual: Value, expected: &Value) {
    let actual_bytes = canonical(&actual);
    actual.dispose();
    let expected_bytes = expected.to_canonical_bytes();
    assert_eq!(
        hex(&actual_bytes),
        hex(&expected_bytes),
        "pinned publication projection: {name}/{kind}"
    );
}

fn vary(disclosure: &mut d::Disclosure, declaration: &mut Declaration) {
    declaration.id.namespace = "other-deployment".into();
    declaration.id.name = "other-genesis".into();
    declaration.id.edition += 7;
    declaration.announced_at += 11;
    declaration.effective_at += 13;
    declaration.content = DeclarationContent::Deployment { genesis_at: 17 };
    let policy = &mut disclosure.frames[0].marker_policy;
    policy.identity.push_str("-other");
    policy.edition.push_str("-other");
    policy.sequence.push_str("-other");
    policy.published_at += 19;
    policy.genesis_at += 23;
    policy.initial_marker.push_str("-other");
    policy.open_placement = !policy.open_placement;
    policy.placement_procedure.push_str("-other");
    policy.cadence.push_str("-other");
    policy.encoding = burn::Encoding::PublicCommitment;
    policy.candidate_rule = match policy.candidate_rule {
        burn::CandidateRule::FirstValidInHistoryOrder => burn::CandidateRule::UniquePerIndex,
        burn::CandidateRule::UniquePerIndex => burn::CandidateRule::FirstValidInHistoryOrder,
    };
    policy.verification_profile.push_str("-other");
    policy.stability_buffer += 29;
    let record = &mut disclosure.frames[0].marker_history.records[0];
    record.address.0.push_str("-other");
    let mut numeric = base::numeric();
    let literal = numeric.literal("31/37").unwrap();
    record.amount = numeric.burn(&literal, "other-unit").unwrap();
}

/// Claim: Nested declaration, policy, address and amount bytes are compared with the public publication writer at edition 1.0.0 over the seven vector fixtures and an independently varied component fixture; no admission is asserted for the varied disclosure.
/// ´claim:history:position-nested-publication´
/// ´test:unit:position-nested-publication´
#[test]
fn position_nested_publication() {
    let root = Input::admitted(&packages().0).unwrap();
    let mut distinct = BTreeSet::new();
    let mut nested: [BTreeSet<Vec<u8>>; 4] = std::array::from_fn(|_| BTreeSet::new());
    for name in [
        "set-order",
        "root",
        "commitment",
        "ordinary",
        "utf8",
        "whole-prefix",
        "initial-lineage",
        "varied",
    ] {
        let mut disclosure = packages().0.disclosures();
        let frame = if name == "ordinary" {
            Input::admitted(&packages().1).unwrap().frame.clone()
        } else if name == "varied" {
            root.frame.clone()
        } else {
            vector_frame(name, root.frame.clone())
        };
        disclosure.frames[0].marker_policy = frame.marker_policy;
        disclosure.frames[0].marker_history = frame.marker_history;
        let mut declaration = root.genesis.clone();
        if name == "varied" {
            vary(&mut disclosure, &mut declaration);
        }
        disclosure.causes.declarations = vec![declaration.clone()];
        let encoded = crate::publication::encode(&disclosure, &mut base::numeric(), d::Limits::default()).unwrap();
        assert!(distinct.insert(encoded.clone()), "distinct disclosure input: {name}");
        let published = pn_interchange::Document::from_canonical_bytes(&encoded).unwrap();
        let edition = published.envelope().version();
        assert_eq!(
            (edition.major(), edition.minor(), edition.patch()),
            (1, 0, 0),
            "pinned publication edition"
        );
        let reproduction = fields(published.content().get(8).unwrap());
        let published_declaration = &fields(&reproduction[0])[0];
        let published_frame = fields(&fields(&reproduction[3])[0]);
        nested[0].insert(published_declaration.to_canonical_bytes());
        nested[1].insert(published_frame[5].to_canonical_bytes());
        let mut usage = EncodingUsage::default();
        let mut callback = |_| Ok(());
        let mut builder = Builder {
            ceiling: usize::MAX,
            usage: &mut usage,
            reservation: &mut callback,
        };
        compare(
            name,
            "declaration",
            builder.declaration(&declaration).unwrap(),
            published_declaration,
        );
        compare(
            name,
            "policy",
            builder.policy(&disclosure.frames[0].marker_policy).unwrap(),
            &published_frame[5],
        );
        let records = fields(&fields(&published_frame[6])[1]);
        for (record, published_record) in disclosure.frames[0].marker_history.records.iter().zip(records) {
            let projected = builder.record(record).unwrap();
            for (index, kind) in [(2, "address"), (3, "amount")] {
                nested[index].insert(fields(published_record)[index].to_canonical_bytes());
                assert_eq!(
                    hex(&canonical(&fields(&projected)[index])),
                    hex(&fields(published_record)[index].to_canonical_bytes()),
                    "pinned publication projection: {name}/{kind}/{}",
                    record.identity
                );
            }
            projected.dispose();
        }
    }
    assert_eq!(distinct.len(), 8, "eight distinct unsorted disclosure inputs");
    assert_eq!(
        nested.map(|values| values.len()),
        [2, 4, 2, 2],
        "distinct nested values by kind"
    );
}
