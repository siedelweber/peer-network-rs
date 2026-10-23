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
