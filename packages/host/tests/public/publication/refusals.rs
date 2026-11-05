use super::{base, fixture, wire_limits};
use pn_host::publication::Error;
use pn_interchange::{Array, Content, ContentKey, Document, Envelope, Map, NamespaceLabel, Value, Version};

macro_rules! refuse {
    ($count:expr, $positive:expr, $negative:expr, $error:pat) => {{
        super::decode_exact(&$positive);
        *$count += 1;
        let result = pn_host::publication::decode(&$negative, &mut base::numeric(), wire_limits());
        assert!(matches!(result, Err($error)), "unexpected refusal: {result:?}");
    }};
}

/// Claim: The publication codec refuses unsupported coordinates, missing and extra sections, duplicate keys and noncanonical CBOR before restoration; declared decoding work is an input, not a default grant.
/// ´claim:publication:malformed-documents-never-become-disclosures´
/// ´test:integration:publication-malformed-documents´
#[test]
fn publication_malformed_documents() {
    let (admitted, _) = fixture::complete();
    let bytes = pn_host::publication::encode(&admitted.disclosures(), &mut base::numeric(), wire_limits()).unwrap();
    let document = Document::from_canonical_bytes(&bytes).unwrap();
    let mut controls = 0;
    coordinates(&document, &mut controls);
    shapes(&document, &mut controls);
    numbers(&document, &mut controls);
    order(&document, &mut controls);
    ranges(&document, &mut controls);
    let zero = base::Limits {
        work: 0,
        ..wire_limits()
    };
    super::decode_exact(&bytes);
    controls += 1;
    let result = pn_host::publication::decode(&bytes, &mut base::numeric(), zero);
    assert!(
        matches!(result, Err(Error::CanonicalNumber)),
        "unexpected zero-work refusal: {result:?}"
    );
    assert_eq!(controls, 26);
}

fn coordinates(document: &Document, count: &mut usize) {
    let bytes = document.to_canonical_bytes();
    for (label, version) in [
        ("org.peer-network.other", Version::new(1, 0, 0)),
        ("org.peer-network.test.publication", Version::new(2, 0, 0)),
        ("org.peer-network.test.publication", Version::new(1, 1, 0)),
    ] {
        let changed = Document::new(
            Envelope::new(NamespaceLabel::parse(label).unwrap(), version),
            document.content().clone(),
        );
        refuse!(count, bytes, changed.to_canonical_bytes(), Error::Edition);
    }
    let patch = Document::new(
        Envelope::new(document.envelope().label().clone(), Version::new(1, 0, 1)),
        document.content().clone(),
    );
    refuse!(count, bytes, patch.to_canonical_bytes(), Error::Patch);
}

fn shapes(document: &Document, count: &mut usize) {
    let bytes = document.to_canonical_bytes();
    let mut missing = Content::new();
    for key in 3..=8 {
        missing.insert(ContentKey::new(key).unwrap(), document.content().get(key).unwrap().clone());
    }
    refuse!(
        count,
        bytes,
        Document::new(document.envelope().clone(), missing).to_canonical_bytes(),
        Error::Shape
    );
    let mut extra = document.content().clone();
    extra.insert(ContentKey::new(9).unwrap(), Value::Null);
    refuse!(
        count,
        bytes,
        Document::new(document.envelope().clone(), extra).to_canonical_bytes(),
        Error::Shape
    );
    assert_eq!(bytes[0], 0xa9);
    let mut noncanonical = vec![0xb8, 9];
    noncanonical.extend_from_slice(&bytes[1..]);
    refuse!(count, bytes, noncanonical, Error::Encoding);
    let mut duplicate = bytes.clone();
    duplicate[0] = 0xaa;
    duplicate.extend_from_slice(&[8, 0xf6]);
    refuse!(count, bytes, duplicate, Error::Encoding);
    let path = &[2, 0, 1, 3];
    refuse!(
        count,
        changed(document, 2, path, at(document, 2, path)),
        changed(document, 2, path, &array([Value::Unsigned(99)])),
        Error::Shape
    );
}

fn numbers(document: &Document, count: &mut usize) {
    let path = &[3, 0, 3, 0, 1];
    for (n, d) in [("2", "8"), ("1", "0"), ("-1", "-4"), ("01", "4")] {
        refuse!(
            count,
            changed(document, 8, path, at(document, 8, path)),
            changed(document, 8, path, &array([text(n), text(d)])),
            Error::CanonicalNumber
        );
    }
    for spelling in ["01", "+1"] {
        refuse!(
            count,
            changed(document, 8, &[2, 1], &text("1")),
            changed(document, 8, &[2, 1], &text(spelling)),
            Error::CanonicalNumber
        );
    }
}

fn order(document: &Document, count: &mut usize) {
    let Value::Array(acts) = at(document, 2, &[0]) else {
        panic!("cause set")
    };
    assert!(acts.as_slice().len() > 1);
    let mut reversed = acts.as_slice().to_vec();
    reversed.reverse();
    refuse!(
        count,
        changed(document, 2, &[0], &Value::Array(acts.clone())),
        changed(document, 2, &[0], &array(reversed)),
        Error::Order
    );
    let mut repeated = acts.as_slice().to_vec();
    repeated.insert(1, repeated[0].clone());
    refuse!(
        count,
        changed(document, 2, &[0], &Value::Array(acts.clone())),
        changed(document, 2, &[0], &array(repeated)),
        Error::Order
    );
    // Alternate integer keys refuse before semantic map insertion. Do not
    // weaken canonical numbers just to reach the defensive Order branch.
    let empty = Value::Map(Map::new([]).unwrap());
    let positive = Value::Map(Map::new([(text("1"), empty.clone())]).unwrap());
    let repeated = Value::Map(Map::new([(text("1"), empty.clone()), (text("01"), empty)]).unwrap());
    refuse!(
        count,
        changed(document, 5, &[0, 2], &positive),
        changed(document, 5, &[0, 2], &repeated),
        Error::CanonicalNumber
    );
}

fn ranges(document: &Document, count: &mut usize) {
    for (path, bound, over) in [
        (vec![2, 1], u32::MAX.to_string(), (u64::from(u32::MAX) + 1).to_string()),
        (vec![2, 2], u64::MAX.to_string(), (u128::from(u64::MAX) + 1).to_string()),
        (vec![2, 0, 0], usize::MAX.to_string(), (usize::MAX as u128 + 1).to_string()),
    ] {
        refuse!(
            count,
            changed(document, 8, &path, &text(&bound)),
            changed(document, 8, &path, &text(&over)),
            Error::Range
        );
    }
    let Value::Array(acts) = at(document, 2, &[0]) else {
        panic!("cause set")
    };
    let index = acts
        .as_slice()
        .iter()
        .position(|act| {
            let Value::Array(fields) = act else { return false };
            let Value::Array(body) = &fields.as_slice()[2] else {
                return false;
            };
            matches!(&body.as_slice()[4], Value::Array(values) if !values.as_slice().is_empty())
        })
        .unwrap();
    let path = &[0, index, 2, 4, 0, 1, 0];
    for (bound, over) in [(i64::MAX, i128::from(i64::MAX) + 1), (i64::MIN, i128::from(i64::MIN) - 1)] {
        refuse!(
            count,
            changed(document, 2, path, &text(&bound.to_string())),
            changed(document, 2, path, &text(&over.to_string())),
            Error::Range
        );
    }
    // Byte strings intrinsically bound u8; this theory has no scalar decimal-u8
    // field. Replacing authentication bytes with integer items is Shape.
    refuse!(
        count,
        changed(document, 2, &[0, 0, 6, 0], &Value::Bytes(vec![u8::MAX].into())),
        changed(document, 2, &[0, 0, 6, 0], &array([Value::Unsigned(256)])),
        Error::Shape
    );
    wide_range(document, count);
}

fn wide_range(document: &Document, count: &mut usize) {
    let id = array([text("actor"), text("0"), text("family")]);
    let time = array([
        id.clone(),
        array([Value::Unsigned(0)]),
        array([Value::Unsigned(0), text(&u128::MAX.to_string())]),
    ]);
    let empty = Value::Map(Map::new([]).unwrap());
    let settlement = array([
        array([id.clone(), id.clone(), id]),
        array([Value::Null, Value::Null]),
        Value::Bool(false),
        array([Value::Bool(false), Value::Bool(false), Value::Bool(false)]),
        array([Value::Null, Value::Null, Value::Null]),
        array([time, Value::Null, Value::Null]),
        Value::Null,
        Value::Null,
        empty.clone(),
        array([]),
        array([]),
        array([]),
        Value::Bool(false),
    ]);
    let boundary = array([
        array([text("0"), text("1"), empty.clone(), array([])]),
        array([settlement]),
        empty,
        array([]),
    ]);
    let positive = changed(document, 7, &[0, 0, 3], &array([boundary]));
    let control = Document::from_canonical_bytes(&positive).unwrap();
    refuse!(
        count,
        positive,
        changed(
            &control,
            7,
            &[0, 0, 3, 0, 1, 0, 5, 0, 2, 1],
            &text("340282366920938463463374607431768211456")
        ),
        Error::Range
    );
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned().into())
}
fn array(items: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(items))
}

fn at<'a>(document: &'a Document, key: u64, path: &[usize]) -> &'a Value {
    let mut value = document.content().get(key).unwrap();
    for index in path {
        let Value::Array(items) = value else {
            panic!("fixture path must be an array")
        };
        value = &items.as_slice()[*index];
    }
    value
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
