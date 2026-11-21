//! Isolated annotation-map controls under (´[ROOT-amend:design:implementation-annotations]´).

use pn_host::publication::annotations::{
    AnnotationError, AnnotationLimits, AnnotationUsage, read_annotation_map, skip_annotation_map,
};

const MAP: &[u8] = &[0xa1, 0x63, b'a', b'.', b'b', 0xa1, 0x61, b'x', 0x41, 0xff];

fn limits(map_bytes: usize) -> AnnotationLimits {
    AnnotationLimits {
        map_bytes,
        caller_bytes: 64,
        allocation_bytes: 4096,
        visitor_bytes: 255,
    }
}

/// Claim: The exact trial map ceiling admits the map and a one-byte-larger canonical map refuses before traversal.
/// ´claim:host:annotation-map-size-boundary´
/// ´test:integration:annotation-map-size-boundary´
#[test]
fn annotation_map_size_boundary() {
    let one_over = &[0xa1, 0x63, b'a', b'.', b'b', 0xa1, 0x61, b'x', 0x42, 0xff, 0x00];
    size_boundary(MAP.len(), MAP, one_over);
}

fn size_boundary(limit: usize, exact: &[u8], one_over: &[u8]) {
    assert_eq!(exact.len(), limit);
    assert_eq!(one_over.len(), limit + 1);
    let mut usage = AnnotationUsage::default();
    assert_eq!(
        read_annotation_map(exact, limits(limit), &mut usage).unwrap().as_bytes(),
        exact
    );
    assert!(usage.visited_items > 0);
    assert!(matches!(
        read_annotation_map(one_over, limits(limit), &mut usage),
        Err(AnnotationError::AnnotationSize)
    ));
    assert_eq!(usage.visited_items, 0);
    assert_eq!(usage.canonical.allocation_calls, 0);
}

/// Claim: A caller budget below the map's length returns operational unavailability before traversal.
/// ´claim:host:annotation-caller-budget´
/// ´test:integration:annotation-caller-budget´
#[test]
fn annotation_caller_budget() {
    let mut usage = AnnotationUsage::default();
    let constrained = AnnotationLimits {
        caller_bytes: MAP.len() - 1,
        ..limits(MAP.len())
    };
    assert!(matches!(
        read_annotation_map(MAP, constrained, &mut usage),
        Err(AnnotationError::Unavailable)
    ));
    assert_eq!(usage.visited_items, 0);
    assert_eq!(usage.canonical.allocation_calls, 0);
}

/// Claim: Canonical outer maps accept opaque byte payloads without decoding them and refuse malformed framing.
/// ´claim:host:annotation-opaque-skip´
/// ´test:integration:annotation-opaque-skip´
#[test]
fn annotation_opaque_skip() {
    let mut usage = AnnotationUsage::default();
    skip_annotation_map(MAP, limits(MAP.len()), &mut usage).unwrap();
    assert!(usage.visited_items > 0);
    let truncated = &MAP[..MAP.len() - 1];
    assert!(matches!(
        skip_annotation_map(truncated, limits(MAP.len()), &mut usage),
        Err(AnnotationError::Framing)
    ));
    let wrong_value = &[0xa1, 0x63, b'a', b'.', b'b', 0xa1, 0x61, b'x', 0x00];
    assert!(matches!(
        skip_annotation_map(wrong_value, limits(MAP.len()), &mut usage),
        Err(AnnotationError::Framing)
    ));
    for malformed in [
        &[0xa1, 0x63, b'a', b'b', b'c', 0xa1, 0x61, b'x', 0x40][..],
        &[0xa1, 0x63, b'a', b'.', b'b', 0xa1, 0x61, b'A', 0x40][..],
        &[0xa1, 0x63, b'a', b'.', b'b', 0xa2, 0x61, b'x', 0x40, 0x61, b'x', 0x40][..],
        &[0xa1, 0x63, b'a', b'.', b'b', 0xa2, 0x61, b'y', 0x40, 0x61, b'x', 0x40][..],
    ] {
        assert!(matches!(
            skip_annotation_map(malformed, limits(malformed.len()), &mut usage),
            Err(AnnotationError::Framing)
        ));
    }
}
