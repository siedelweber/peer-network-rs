use super::{base, fixture, wire_limits};
use pn_interchange::{Array, Content, ContentKey, Document, Envelope, NamespaceLabel, Value, Version};

fn refuse(bytes: &[u8]) {
    assert!(pn_host::publication::decode(bytes, &mut base::numeric(), wire_limits()).is_err());
}

/// Claim: The publication codec refuses unsupported coordinates, missing and extra sections, duplicate keys and noncanonical CBOR before restoration; declared decoding work is an input, not a default grant.
/// ´claim:publication:malformed-documents-never-become-disclosures´
/// ´test:integration:publication-malformed-documents´
#[test]
fn publication_malformed_documents() {
    let (admitted, _) = fixture::complete();
    let bytes = pn_host::publication::encode(&admitted.disclosures(), &mut base::numeric(), wire_limits()).unwrap();
    let document = Document::from_canonical_bytes(&bytes).unwrap();
    for (label, version) in [
        ("org.peer-network.other", Version::new(1, 0, 0)),
        ("org.peer-network.test.publication", Version::new(2, 0, 0)),
    ] {
        refuse(
            &Document::new(
                Envelope::new(NamespaceLabel::parse(label).unwrap(), version),
                document.content().clone(),
            )
            .to_canonical_bytes(),
        );
    }
    let patch = Document::new(
        Envelope::new(document.envelope().label().clone(), Version::new(1, 0, 1)),
        document.content().clone(),
    )
    .to_canonical_bytes();
    assert_eq!(
        pn_host::publication::decode(&patch, &mut base::numeric(), wire_limits()).unwrap(),
        admitted.disclosures()
    );
    let mut missing = Content::new();
    for key in 3..=8 {
        missing.insert(ContentKey::new(key).unwrap(), document.content().get(key).unwrap().clone());
    }
    refuse(&Document::new(document.envelope().clone(), missing).to_canonical_bytes());
    let mut extra = document.content().clone();
    extra.insert(ContentKey::new(9).unwrap(), pn_interchange::Value::Null);
    refuse(&Document::new(document.envelope().clone(), extra).to_canonical_bytes());
    assert_eq!(bytes[0], 0xa9);
    let mut noncanonical = vec![0xb8, 9];
    noncanonical.extend_from_slice(&bytes[1..]);
    refuse(&noncanonical);
    let mut duplicate = bytes.clone();
    duplicate[0] = 0xaa;
    duplicate.extend_from_slice(&[8, 0xf6]);
    refuse(&duplicate);
    for (numerator, denominator) in [("2", "8"), ("1", "0"), ("-1", "-4"), ("01", "4")] {
        refuse(&changed(
            &document,
            8,
            &[3, 0, 3, 0, 1],
            &Value::Array(Array::new([
                Value::Text(numerator.to_owned().into()),
                Value::Text(denominator.to_owned().into()),
            ])),
        ));
    }
    refuse(&changed(
        &document,
        2,
        &[2, 0, 1, 3],
        &Value::Array(Array::new([Value::Unsigned(99)])),
    ));
    refuse(&changed(
        &document,
        8,
        &[2, 0, 0],
        &Value::Text((u128::from(u64::MAX) + 1).to_string().into()),
    ));
    let zero = base::Limits {
        work: 0,
        ..wire_limits()
    };
    assert!(pn_host::publication::decode(&bytes, &mut base::numeric(), zero).is_err());
}

fn replace(value: &Value, path: &[usize], replacement: &Value) -> Value {
    if let Some((first, rest)) = path.split_first() {
        let Value::Array(values) = value else {
            panic!("fixture path must be an array")
        };
        let mut items = values.as_slice().to_vec();
        items[*first] = replace(&items[*first], rest, replacement);
        Value::Array(Array::new(items))
    } else {
        replacement.clone()
    }
}

fn changed(document: &Document, key: u64, path: &[usize], replacement: &Value) -> Vec<u8> {
    let mut content = document.content().clone();
    content.insert(
        ContentKey::new(key).unwrap(),
        replace(document.content().get(key).unwrap(), path, replacement),
    );
    Document::new(document.envelope().clone(), content).to_canonical_bytes()
}
