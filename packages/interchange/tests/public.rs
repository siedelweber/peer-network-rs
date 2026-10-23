use pn_interchange::Value;

/// Claim: Prefix decoding exposes exactly the first value's extent while strict decoding refuses trailing bytes.
/// ´claim:vectors:public-prefix-extent´
/// ´test:integration:prefix-extent´
#[test]
fn prefix_extent() {
    let bytes = [24, 42, 255];
    let (value, consumed) = Value::from_canonical_prefix(&bytes).expect("one canonical integer prefix");
    assert_eq!(value, Value::Unsigned(42));
    assert_eq!(consumed, 2);
    assert_eq!(value.to_canonical_bytes(), bytes[..consumed]);
    assert!(Value::from_canonical_bytes(&bytes).is_err());
}

/// Claim: Debug retains every nested tag and the terminal value across ten thousand levels without the call stack, so enabling observation cannot introduce recursive formatting failure for a valid deep value.
/// ´claim:vectors:deep-debug-retains-public-structure´
/// ´test:integration:deep-debug´
#[test]
fn deep_debug() {
    let mut value = Value::Unsigned(42);
    for _ in 0..10_000 {
        value = Value::Tag(pn_interchange::Tag::new(24, value));
    }
    let text = format!("{value:?}");
    assert_eq!(text.matches("Tag(Tag { number: 24, item: ").count(), 10_000);
    assert_eq!(text.matches("Unsigned(42)").count(), 1);
    assert_eq!(text.matches(" })").count(), 10_000);
    let map = pn_interchange::Map::new([(
        Value::Unsigned(1),
        Value::Array(pn_interchange::Array::new([Value::Bool(true), Value::Null])),
    )])
    .unwrap();
    assert_eq!(
        format!("{:?}", Value::Map(map)),
        "Map(Map([(Unsigned(1), Array(Array([Bool(true), Null])))]))"
    );
}
