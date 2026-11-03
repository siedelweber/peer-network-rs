//! Bounded transient messages and unchanged canonical membership.

use pn_interchange::{DecodeError, TransportLimits, TransportUsage, Value};

// Fixture declarations, not deployment defaults. Each refusal overrides one
// ceiling; the accepted control uses this same finite declaration.
const LIMITS: TransportLimits = TransportLimits {
    input_bytes: 256,
    allocation_bytes: 8192,
    items: 64,
    depth: 16,
    nesting: 16,
    work: 2048,
};

fn read(bytes: &[u8]) -> Result<Value, DecodeError> {
    Value::from_transport_bytes(bytes, LIMITS, &mut TransportUsage::default())
}

/// Claim: Allowed transport heads, map order, indefinite containers and empty or nonempty chunks yield the canonical reader's typed value without changing embedded document bytes.
/// ´claim:encoding:transport-variants-preserve-values´
/// ´test:integration:transport-variants-preserve-values´
#[test]
fn transport_variants_preserve_values() {
    for major in 0_u8..=5 {
        let canonical = [major << 5];
        let expected = Value::from_canonical_bytes(&canonical).expect("immediate zero argument");
        for (additional, width) in [(24, 1), (25, 2), (26, 4), (27, 8)] {
            let mut bytes = vec![(major << 5) | additional];
            bytes.extend(std::iter::repeat_n(0, width));
            assert_eq!(read(&bytes).expect("legal wider argument"), expected);
            assert!(matches!(
                Value::from_canonical_bytes(&bytes),
                Err(DecodeError::NonPreferredHead { offset: 0 })
            ));
        }
    }
    let cases: &[(&[u8], &[u8])] = &[
        (&[0], &[0x18, 0]),
        (&[0x20], &[0x39, 0, 0]),
        (&[0x41, 1], &[0x58, 1, 1]),
        (&[0x61, b'a'], &[0x79, 0, 1, b'a']),
        (&[0x82, 0, 1], &[0x98, 2, 0, 1]),
        (&[0x82, 0, 1], &[0x9f, 0, 1, 0xff]),
        (&[0x80], &[0x9f, 0xff]),
        (&[0xa0], &[0xbf, 0xff]),
        (&[0xa1, 0x61, b'a', 0], &[0xb8, 1, 0x61, b'a', 0]),
        (
            &[0xa2, 0x61, b'a', 0, 0x61, b'b', 1],
            &[0xbf, 0x61, b'b', 1, 0x61, b'a', 0, 0xff],
        ),
        (&[0x42, 0x18, 0], &[0x5f, 0x40, 0x41, 0x18, 0x40, 0x41, 0, 0xff]),
        (&[0x62, b'a', b'b'], &[0x7f, 0x60, 0x61, b'a', 0x78, 1, b'b', 0x60, 0xff]),
        (&[0x40], &[0x5f, 0x40, 0xff]),
        (&[0x60], &[0x7f, 0xff]),
        (&[0xf9, 0x3c, 0], &[0xfa, 0x3f, 0x80, 0, 0]),
        (&[0xf9, 0x80, 0], &[0xfb, 0x80, 0, 0, 0, 0, 0, 0, 0]),
    ];
    for (canonical, transport) in cases {
        let expected = Value::from_canonical_bytes(canonical).expect("canonical oracle");
        assert_eq!(read(transport).expect("allowed outer variant"), expected);
        assert!(
            Value::from_canonical_bytes(transport).is_err(),
            "strict spelling: {transport:?}"
        );
    }
    let Value::Bytes(inner) = read(&[0x5f, 0x41, 0x18, 0x41, 0, 0xff]).expect("outer chunks") else {
        panic!("byte string remains a byte string");
    };
    assert_eq!(inner.as_slice(), &[0x18, 0]);
    assert!(matches!(
        Value::from_canonical_bytes(inner.as_slice()),
        Err(DecodeError::NonPreferredHead { offset: 0 })
    ));
}

/// Claim: Transport refuses duplicate decoded keys, malformed chunks, breaks, UTF-8, reserved heads, unsupported values, truncation and trailing data while accepting each class's valid control.
/// ´claim:encoding:transport-refusals-retain-valid-controls´
/// ´test:integration:transport-refusals-retain-valid-controls´
#[test]
fn transport_refusals_retain_valid_controls() {
    assert!(
        matches!(
            read(&[0xa1, 0x9f, 0, 0xff, 0]),
            Err(DecodeError::TransportValue { offset: 1 })
        ),
        "an indefinite non-text key is located at its head"
    );
    let cases: &[(&[u8], &[u8])] = &[
        (
            &[0xbf, 0x61, b'a', 0, 0x7f, 0x61, b'a', 0xff, 1, 0xff],
            &[0xa1, 0x61, b'a', 0],
        ),
        (&[0x81, 0xa2, 0x61, b'a', 0, 0x61, b'a', 1], &[0x81, 0xa1, 0x61, b'a', 0]),
        (&[0x5f, 0x5f, 0xff, 0xff], &[0x5f, 0x40, 0xff]),
        (&[0x7f, 0x7f, 0xff, 0xff], &[0x7f, 0x60, 0xff]),
        (&[0x5f, 0x60, 0xff], &[0x5f, 0x40, 0xff]),
        (&[0x7f, 0x40, 0xff], &[0x7f, 0x60, 0xff]),
        (&[0xff], &[0xf6]),
        (&[0x81, 0xff], &[0x81, 0]),
        (&[0xbf, 0x61, b'a', 0xff], &[0xbf, 0x61, b'a', 0, 0xff]),
        (&[0x61, 0xff], &[0x61, b'a']),
        (&[0x7f, 0x61, 0xc2, 0x61, 0xa2, 0xff], &[0x7f, 0x62, 0xc2, 0xa2, 0xff]),
        (&[0x1c], &[0]),
        (&[0xc0, 0], &[0]),
        (&[0xf7], &[0xf6]),
        (&[0xf8, 0], &[0xf4]),
        (&[0xf9, 0x7c, 0], &[0xf9, 0x3c, 0]),
        (&[0xf9, 0x7e, 0], &[0xf9, 0, 0]),
        (&[0xa1, 0, 0], &[0xa1, 0x60, 0]),
        (&[0x42, 0], &[0x41, 0]),
        (&[0x9f, 0], &[0x9f, 0, 0xff]),
        (&[0, 1], &[0]),
    ];
    let expected = [
        "duplicate",
        "duplicate",
        "malformed",
        "malformed",
        "malformed",
        "malformed",
        "malformed",
        "malformed",
        "malformed",
        "utf8",
        "utf8",
        "malformed",
        "vocabulary",
        "vocabulary",
        "malformed",
        "vocabulary",
        "vocabulary",
        "vocabulary",
        "truncated",
        "truncated",
        "trailing",
    ];
    assert_eq!(cases.len(), expected.len());
    for ((refused, control), class) in cases.iter().zip(expected) {
        let error = read(refused).expect_err("refusal fixture");
        let actual = match error {
            DecodeError::DuplicateMapKey { .. } => "duplicate",
            DecodeError::IllFormed { .. } => "malformed",
            DecodeError::InvalidUtf8 { .. } => "utf8",
            DecodeError::TransportValue { .. } => "vocabulary",
            DecodeError::Truncated { .. } => "truncated",
            DecodeError::TrailingBytes { .. } => "trailing",
            other => panic!("wrong refusal class: {other:?}"),
        };
        assert_eq!(actual, class, "refused: {refused:?}");
        assert!(read(control).is_ok(), "control: {control:?}");
    }
}

/// Claim: Each transport ceiling refuses at its reservation boundary, with zero reservation calls for a refused first allocation and unchanged prior calls at a nested refusal; empty chunks consume work and items.
/// ´claim:encoding:transport-limits-precede-reservations´
/// ´test:integration:transport-limits-precede-reservations´
#[test]
fn transport_limits_precede_reservations() {
    geometric_reservations();
    let bytes = [0x41, 0];
    let mut control = TransportUsage::default();
    assert!(Value::from_transport_bytes(&bytes, LIMITS, &mut control).is_ok());
    let exact = TransportLimits {
        input_bytes: bytes.len(),
        allocation_bytes: control.allocation_bytes,
        items: control.items,
        depth: 1,
        nesting: 0,
        work: control.work,
    };
    assert!(Value::from_transport_bytes(&bytes, exact, &mut TransportUsage::default()).is_ok());
    for (bytes, limits, resource) in [
        (
            &[0x41, 0][..],
            TransportLimits {
                input_bytes: 1,
                ..LIMITS
            },
            "input bytes",
        ),
        (
            &[0x41, 0][..],
            TransportLimits {
                allocation_bytes: 0,
                ..LIMITS
            },
            "allocation bytes",
        ),
        (&[0x81, 0][..], TransportLimits { items: 1, ..LIMITS }, "items"),
        (&[0x41, 0][..], TransportLimits { depth: 0, ..LIMITS }, "depth"),
        (&[0x81, 0][..], TransportLimits { nesting: 0, ..LIMITS }, "nesting"),
        (&[0x41, 0][..], TransportLimits { work: 2, ..LIMITS }, "work"),
    ] {
        let mut usage = TransportUsage::default();
        assert!(matches!(Value::from_transport_bytes(bytes, limits, &mut usage),
            Err(DecodeError::TransportLimit { resource: actual, .. }) if actual == resource));
        assert_eq!(usage.allocation_calls, 0, "{resource}");
        assert_eq!(usage.allocation_bytes, 0, "{resource}");
        let mut control = TransportUsage::default();
        assert!(Value::from_transport_bytes(bytes, LIMITS, &mut control).is_ok());
        assert!(control.allocation_calls > 0);
    }
    let mut usage = TransportUsage::default();
    assert!(matches!(
        Value::from_transport_bytes(&[0x81, 0x41, 0], TransportLimits { depth: 1, ..LIMITS }, &mut usage),
        Err(DecodeError::TransportLimit { resource: "depth", .. })
    ));
    assert_eq!(usage.allocation_calls, 1, "only the outer frame was reserved");
    let mut usage = TransportUsage::default();
    assert!(matches!(
        Value::from_transport_bytes(&[0x5f, 0x40, 0x40, 0xff], TransportLimits { items: 2, ..LIMITS }, &mut usage),
        Err(DecodeError::TransportLimit { resource: "items", .. })
    ));
    assert_eq!(usage.allocation_calls, 0, "empty chunks allocate no payload");
    let mut usage = TransportUsage::default();
    assert!(matches!(
        Value::from_transport_bytes(&[0x5f, 0x40, 0x40, 0xff], TransportLimits { work: 4, ..LIMITS }, &mut usage),
        Err(DecodeError::TransportLimit { resource: "work", .. })
    ));
    assert_eq!(usage.allocation_calls, 0);
    let mut usage = TransportUsage::default();
    let chunked = [0x5f, 0x41, b'a', 0x41, b'b', 0xff];
    assert!(matches!(
        Value::from_transport_bytes(
            &chunked,
            TransportLimits {
                allocation_bytes: 1,
                ..LIMITS
            },
            &mut usage
        ),
        Err(DecodeError::TransportLimit {
            resource: "allocation bytes",
            ..
        })
    ));
    assert_eq!(
        (usage.allocation_calls, usage.allocation_bytes),
        (1, 1),
        "the replacement buffer was never requested"
    );
    assert!(read(&chunked).is_ok());
    for head in [0x9b, 0xbb] {
        let mut bytes = [0xff; 9];
        bytes[0] = head;
        let mut usage = TransportUsage::default();
        assert!(matches!(
            Value::from_transport_bytes(&bytes, LIMITS, &mut usage),
            Err(DecodeError::TransportLimit { resource: "items", .. })
        ));
        assert_eq!(usage.allocation_calls, 0, "oversized declared count");
    }
}

/// Claim: The canonical entry selects the Strict policy independently of transport declarations, retaining its refusal classes for nonpreferred heads, indefinite items, unsorted keys and wide floats.
/// ´claim:encoding:strict-entry-selects-strict-policy´
/// ´test:integration:strict-entry-selects-strict-policy´
#[test]
fn strict_entry_selects_strict_policy() {
    assert!(matches!(
        Value::from_canonical_bytes(&[0x18, 0]),
        Err(DecodeError::NonPreferredHead { offset: 0 })
    ));
    assert!(matches!(
        Value::from_canonical_bytes(&[0x9f, 0xff]),
        Err(DecodeError::IndefiniteLength { offset: 0 })
    ));
    assert!(matches!(
        Value::from_canonical_bytes(&[0xa2, 0x61, b'b', 0, 0x61, b'a', 1]),
        Err(DecodeError::UnsortedMapKeys { .. })
    ));
    assert!(matches!(
        Value::from_canonical_bytes(&[0xfa, 0x3f, 0x80, 0, 0]),
        Err(DecodeError::NonShortestFloat { offset: 0 })
    ));
    let (value, used) = Value::from_canonical_prefix(&[0, 1]).expect("strict prefix");
    assert_eq!((value, used), (Value::Unsigned(0), 1));
    assert!(matches!(
        Value::from_canonical_bytes(&[0, 1]),
        Err(DecodeError::TrailingBytes { offset: 1, count: 1 })
    ));
}

// Additional controls for transport_limits_precede_reservations.
fn geometric_reservations() {
    // Cumulative replacement buffers form a geometric sum, not the sum of
    // every prefix. Include the frame reservation separately from the values.
    let element_bytes = std::mem::size_of::<Value>();
    let mut singleton = TransportUsage::default();
    assert!(Value::from_transport_bytes(&[0x9f, 0, 0xff], LIMITS, &mut singleton).is_ok());
    let frame_bytes = singleton.allocation_bytes - element_bytes;
    for count in [1usize, 2, 4, 8, 16, 32] {
        let mut input = vec![0x9f];
        input.extend(std::iter::repeat_n(0, count));
        input.push(0xff);
        let allocation_bytes = frame_bytes + (2 * count - 1) * element_bytes;
        let limits = TransportLimits {
            allocation_bytes,
            ..LIMITS
        };
        let mut usage = TransportUsage::default();
        assert!(Value::from_transport_bytes(&input, limits, &mut usage).is_ok());
        assert_eq!(usage.allocation_bytes, allocation_bytes);
        assert_eq!(usage.allocation_calls, 2 + count.ilog2() as usize);
        let mut refused = TransportUsage::default();
        assert!(matches!(
            Value::from_transport_bytes(
                &input,
                TransportLimits {
                    allocation_bytes: allocation_bytes - 1,
                    ..limits
                },
                &mut refused
            ),
            Err(DecodeError::TransportLimit {
                resource: "allocation bytes",
                ..
            })
        ));
        assert_eq!(refused.allocation_calls + 1, usage.allocation_calls);
        assert_eq!(refused.allocation_bytes, allocation_bytes - count * element_bytes);
    }
    // The last growth of a definite three-element array stops at three.
    let mut definite = TransportUsage::default();
    assert!(Value::from_transport_bytes(&[0x83, 0, 0, 0], LIMITS, &mut definite).is_ok());
    assert_eq!(definite.allocation_bytes, frame_bytes + 6 * element_bytes);
    // The same growth boundary serves joined chunks and the active frame stack.
    let mut chunks = vec![0x5f];
    for _ in 0..16 {
        chunks.extend([0x41, 0]);
    }
    chunks.push(0xff);
    let mut joined = TransportUsage::default();
    assert!(Value::from_transport_bytes(&chunks, LIMITS, &mut joined).is_ok());
    assert_eq!((joined.allocation_calls, joined.allocation_bytes), (5, 31));
    let mut nested = vec![0x81; 8];
    nested.push(0);
    let mut frames = TransportUsage::default();
    assert!(Value::from_transport_bytes(&nested, LIMITS, &mut frames).is_ok());
    assert_eq!(frames.allocation_calls, 4 + 8);
    assert_eq!(frames.allocation_bytes, 15 * frame_bytes + 8 * element_bytes);
    let mut map = TransportUsage::default();
    assert!(Value::from_transport_bytes(&[0xa3, 0x61, b'a', 0, 0x61, b'b', 0, 0x61, b'c', 0], LIMITS, &mut map).is_ok());
    assert_eq!(
        map.allocation_bytes,
        frame_bytes + 6 * std::mem::size_of::<(Value, Value)>() + 3
    );
}
