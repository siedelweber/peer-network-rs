use super::*;
use std::cell::RefCell;

type Requests = Vec<(usize, usize, usize)>;
type Read = (Result<(), DecodeError>, CanonicalUsage, Requests);

thread_local! {
    static REQUESTS: RefCell<Vec<(usize, usize, usize)>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn requested(bytes: usize, usage: &CanonicalUsage) {
    REQUESTS.with_borrow_mut(|calls| calls.push((bytes, usage.allocation_calls, usage.allocation_bytes)));
}

fn read(bytes: &[u8], limit: usize) -> Read {
    REQUESTS.with_borrow_mut(Vec::clear);
    let mut usage = CanonicalUsage::default();
    let mut reservations = Vec::new();
    let result = Value::validate_canonical_bytes(
        bytes,
        limit,
        &mut usage,
        |bytes| {
            reservations.push(bytes);
            Ok(())
        },
        |_| {},
    );
    let calls = REQUESTS.with_borrow(Clone::clone);
    assert_eq!(
        reservations,
        calls.iter().map(|call| call.0).collect::<Vec<_>>(),
        "shared meter sees every exact request"
    );
    (result, usage, calls)
}

fn accounted(usage: &CanonicalUsage, calls: &[(usize, usize, usize)]) {
    let mut total = 0;
    for (index, &(bytes, charged_calls, charged_bytes)) in calls.iter().enumerate() {
        total += bytes;
        assert_eq!(
            charged_calls,
            index + 1,
            "reservation was charged before reservation-site execution"
        );
        assert_eq!(charged_bytes, total, "bytes were charged before reservation-site execution");
    }
    assert_eq!(
        usage.allocation_calls,
        calls.len(),
        "usage reports actual requests even on refusal"
    );
    assert_eq!(usage.allocation_bytes, total, "usage retains requested bytes on refusal");
}

/// Claim: Every request observed at the strict validation reservation site is charged before execution and reported exactly, including on refusal; zero-ceiling scalar and empty-container controls observe no request at that site.
/// ´claim:encoding:canonical-validation-reserves-before-allocation´
/// ´test:unit:canonical-validation-reserves-before-allocation´
#[test]
fn canonical_validation_reserves_before_allocation() {
    for bytes in [&[0x43, 1, 2, 3][..], &[0x63, b'a', b'b', b'c'], &[0x80], &[0xa0]] {
        let (result, usage, calls) = read(bytes, 0);
        assert!(result.is_ok(), "borrowed scalar or empty container needs no buffer");
        assert_eq!(calls, []);
        accounted(&usage, &calls);
    }
    let frame = std::mem::size_of::<Frame>();
    // Tags, arrays and maps share the frame stack. Their completed contents
    // require no boxes, element buffers, growth or finalization allocations.
    for (unit, tail) in [
        (&[0xc1][..], &[0][..]),
        (&[0x81][..], &[0x61, b'x'][..]),
        (&[0xa1, 0][..], &[0x41, 7][..]),
    ] {
        for depth in [1usize, 2, 3, 4, 5, 8, 9, 16] {
            let mut bytes = unit.repeat(depth);
            bytes.extend_from_slice(tail);
            let capacity = depth.next_power_of_two();
            let need = (2 * capacity - 1) * frame;
            let (result, usage, calls) = read(&bytes, need);
            assert!(result.is_ok(), "exact stack budget, depth {depth}");
            assert_eq!(usage.allocation_bytes, need);
            accounted(&usage, &calls);
            let (result, refused, calls) = read(&bytes, need - 1);
            assert!(
                matches!(result, Err(DecodeError::CanonicalLimit { .. })),
                "one below reservation need"
            );
            assert_eq!(
                refused.allocation_bytes,
                need - capacity * frame,
                "refused request never reaches reservation-site execution"
            );
            accounted(&refused, &calls);
        }
    }
    // Completed children followed by malformed/trailing bytes must not erase
    // counters, and cleanup must not build a heap-owned value worklist.
    for bytes in [&[0x82, 0x81, 0, 0x1c][..], &[0x81, 0, 1], &[0xa2, 0, 0, 0, 0]] {
        let (result, usage, calls) = read(bytes, 16 * frame);
        assert!(result.is_err());
        assert_ne!(calls, []);
        accounted(&usage, &calls);
    }
}

/// Claim: The caller can refuse each successive reservation of a nested strict input before its reservation-site execution, with exact prior usage retained; visitor charges can exhaust the same meter before a later reservation.
/// ´claim:encoding:canonical-validation-shared-meter´
/// ´test:unit:canonical-validation-obeys-shared-meter´
#[test]
fn canonical_validation_obeys_shared_meter() {
    let mut bytes = vec![0xc1; 16];
    bytes.push(0);
    let (result, _, baseline) = read(&bytes, usize::MAX);
    assert!(result.is_ok());
    assert_eq!(baseline.len(), 5);
    for refused in 1..=baseline.len() {
        REQUESTS.with_borrow_mut(Vec::clear);
        let mut usage = CanonicalUsage::default();
        let mut attempts = 0;
        let result = Value::validate_canonical_bytes(
            &bytes,
            usize::MAX,
            &mut usage,
            |_| {
                attempts += 1;
                if attempts == refused { Err(()) } else { Ok(()) }
            },
            |_| {},
        );
        assert!(
            matches!(result, Err(DecodeError::CanonicalReservation { .. })),
            "shared meter refusal stops before reservation"
        );
        assert_eq!(attempts, refused);
        let calls = REQUESTS.with_borrow(Clone::clone);
        assert_eq!(calls, baseline[..refused - 1]);
        accounted(&usage, &calls);
    }
    REQUESTS.with_borrow_mut(Vec::clear);
    let remaining = std::cell::Cell::new(2 * std::mem::size_of::<Frame>());
    let mut usage = CanonicalUsage::default();
    let mut events = 0;
    let result = Value::validate_canonical_bytes(
        &[0x82, 0, 0x81, 0],
        usize::MAX,
        &mut usage,
        |amount| {
            let next = remaining.get().checked_sub(amount).ok_or(())?;
            remaining.set(next);
            Ok(())
        },
        |_| {
            events += 1;
            remaining.set(0);
        },
    );
    assert!(
        matches!(result, Err(DecodeError::CanonicalReservation { .. })),
        "visitor's charge governs later reservations"
    );
    assert_eq!(events, 1);
    let calls = REQUESTS.with_borrow(Clone::clone);
    assert_eq!(calls.len(), 1);
    accounted(&usage, &calls);
}
