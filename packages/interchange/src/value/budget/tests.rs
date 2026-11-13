use super::*;
use crate::{EncodingError, EncodingUsage, Tag};
use std::cell::Cell;

thread_local! { static GROWTH: Cell<usize> = const { Cell::new(0) }; }
pub(super) fn allocation_site() {
    GROWTH.with(|value| value.set(value.get() + 1));
}
fn clear() {
    GROWTH.with(|value| value.set(0));
}
fn dispose(value: Value) {
    clear();
    value.dispose();
    assert_eq!(GROWTH.with(Cell::get), 0, "disposal never enters a legacy allocation site");
}

/// Claim: Reserved transfers retain buffer addresses and capacities, and capacity, UTF-8 and empty-map refusals leave the original buffers unchanged; these are transfer controls, not an allocator census.
/// ´claim:encoding:reserved-value-transfers´
/// ´test:unit:reserved-value-transfers´
#[test]
fn reserved_value_transfers() {
    let mut bytes = vec![1, 2, 3];
    assert_eq!(bytes.capacity(), bytes.len());
    let pointer = bytes.as_ptr();
    let capacity = bytes.capacity();
    let value = Bytes::take_reserved(&mut bytes).unwrap();
    assert_eq!(bytes, [] as [u8; 0]);
    assert_eq!(value.as_slice().as_ptr(), pointer, "byte transfer retains address");
    assert_eq!(value.into_vec().capacity(), capacity, "byte transfer retains capacity");

    let mut text = b"valid text".to_vec();
    let pointer = text.as_ptr();
    let capacity = text.capacity();
    let value = Text::take_reserved(&mut text).unwrap();
    assert_eq!(text, [] as [u8; 0]);
    assert_eq!(value.as_str().as_ptr(), pointer, "text transfer retains address");
    assert_eq!(value.into_string().capacity(), capacity, "text transfer retains capacity");

    let mut invalid = vec![0xff];
    let pointer = invalid.as_ptr();
    let capacity = invalid.capacity();
    assert_eq!(
        Text::take_reserved(&mut invalid),
        Err(TransferError::InvalidUtf8 { offset: 0 })
    );
    assert_eq!(
        (invalid.as_ptr(), invalid.capacity(), invalid.as_slice()),
        (pointer, capacity, &[0xff][..])
    );

    {
        let mut spare = Vec::with_capacity(16);
        spare.push(1);
        let pointer = spare.as_ptr();
        let capacity = spare.capacity();
        assert_eq!(
            Bytes::take_reserved(&mut spare),
            Err(TransferError::SpareCapacity),
            "transfer never shrinks spare capacity"
        );
        assert_eq!(
            (spare.as_ptr(), spare.capacity(), spare.as_slice()),
            (pointer, capacity, &[1][..])
        );
    }
    let mut spare = Vec::with_capacity(16);
    spare.push(b'a');
    let pointer = spare.as_ptr();
    let capacity = spare.capacity();
    assert_eq!(Text::take_reserved(&mut spare), Err(TransferError::SpareCapacity));
    assert_eq!((spare.as_ptr(), spare.capacity()), (pointer, capacity));

    let mut children = Vec::with_capacity(16);
    children.push(Value::Null);
    let pointer = children.as_ptr();
    let capacity = children.capacity();
    let array = Array::take_reserved(&mut children);
    assert_eq!(children, [] as [Value; 0]);
    assert_eq!(array.as_slice().as_ptr(), pointer, "array transfer does not recollect");
    assert_eq!(array.into_vec().capacity(), capacity, "array transfer does not shrink");

    let mut entries = Vec::with_capacity(16);
    let pointer = entries.as_ptr();
    let capacity = entries.capacity();
    let map = Map::take_empty_reserved(&mut entries).unwrap();
    let result = map.into_entries();
    assert_eq!((result.as_ptr(), result.capacity()), (pointer, capacity));
    for mut entries in [
        vec![(Value::Unsigned(1), Value::Null)],
        vec![(Value::Unsigned(2), Value::Null), (Value::Unsigned(1), Value::Null)],
        vec![(Value::Null, Value::Null), (Value::Null, Value::Null)],
    ] {
        let pointer = entries.as_ptr();
        let capacity = entries.capacity();
        let length = entries.len();
        assert_eq!(
            Map::take_empty_reserved(&mut entries),
            Err(TransferError::NonemptyMap),
            "empty-map invariant is checked"
        );
        assert_eq!(
            (entries.as_ptr(), entries.capacity(), entries.len()),
            (pointer, capacity, length)
        );
    }
}

fn nested(depth: usize, refuse: usize) -> (Value, EncodingUsage, usize, Result<(), EncodingError>) {
    let mut value = Value::Null;
    let mut usage = EncodingUsage::default();
    let mut calls = 0;
    for _ in 0..depth {
        let mut items = Vec::new();
        let result = usage.reserve_value_buffer(&mut items, 2, usize::MAX, |_| {
            calls += 1;
            if calls == refuse { Err(()) } else { Ok(()) }
        });
        if result.is_err() {
            return (value, usage, calls, result);
        }
        items.push(value);
        items.push(Value::Null);
        value = Value::Array(Array::take_reserved(&mut items));
    }
    (value, usage, calls, Ok(()))
}

fn leaf(usage: &mut EncodingUsage, remaining: &mut usize) -> Value {
    let mut items = Vec::new();
    usage
        .reserve_value_buffer(&mut items, 4, usize::MAX, |amount| {
            *remaining = remaining.checked_sub(amount).ok_or(())?;
            Ok(())
        })
        .unwrap();
    let mut bytes = Vec::new();
    usage
        .reserve_value_buffer(&mut bytes, 3, usize::MAX, |amount| {
            *remaining = remaining.checked_sub(amount).ok_or(())?;
            Ok(())
        })
        .unwrap();
    bytes.extend_from_slice(&[1, 2, 3]);
    items.push(Value::Bytes(Bytes::take_reserved(&mut bytes).unwrap()));
    let mut text = Vec::new();
    usage
        .reserve_value_buffer(&mut text, 2, usize::MAX, |amount| {
            *remaining = remaining.checked_sub(amount).ok_or(())?;
            Ok(())
        })
        .unwrap();
    text.extend_from_slice(b"ok");
    items.push(Value::Text(Text::take_reserved(&mut text).unwrap()));
    items.push(Value::Map(Map::take_empty_reserved(&mut Vec::new()).unwrap()));
    items.push(Value::Bool(true));
    Value::Array(Array::take_reserved(&mut items))
}

/// Claim: Explicit disposal reaches no marked legacy allocation site for 4096 nested arrays, mixed containers, or the partial value after each of twelve construction reservation refusals; no allocator outside those sites is observed.
/// ´claim:encoding:reserved-value-disposal´
/// ´test:unit:reserved-value-disposal´
#[test]
fn reserved_value_disposal() {
    let (value, _, _, result) = nested(4096, 0);
    assert!(result.is_ok());
    dispose(value);
    dispose(Value::Map(
        Map::new([
            (Value::Null, Value::Array(Array::new([Value::Null]))),
            (Value::Unsigned(1), Value::Tag(Tag::new(42, Value::Array(Array::new([]))))),
        ])
        .unwrap(),
    ));
    for refuse in 1..=12 {
        let (value, usage, calls, result) = nested(12, refuse);
        assert_eq!(result, Err(EncodingError::Reservation));
        assert_eq!(calls, refuse);
        assert_eq!(usage.allocation_calls, refuse - 1);
        assert_eq!(usage.allocation_bytes, (refuse - 1) * 2 * mem::size_of::<Value>());
        dispose(value);
        assert_eq!(calls, refuse, "disposal invokes no reservation callback");
    }
}

/// Claim: Public construction and canonical encoding share a caller meter, with exact admitted requests on success and refusal; explicit disposal adds none, and exact versus one-below construction limits decide before reservation.
/// ´claim:encoding:reserved-value-shared-meter´
/// ´test:unit:reserved-value-shared-meter´
#[test]
fn reserved_value_shared_meter() {
    let mut construction = EncodingUsage::default();
    let mut allowance = usize::MAX;
    let value = leaf(&mut construction, &mut allowance);
    let mut encoded = EncodingUsage::default();
    let mut encoded_requests = 0;
    let bytes = value
        .to_canonical_bytes_budgeted(usize::MAX, &mut encoded, |amount| {
            encoded_requests += amount;
            Ok(())
        })
        .unwrap();
    assert_eq!(bytes, [0x84, 0x43, 1, 2, 3, 0x62, b'o', b'k', 0xa0, 0xf5]);
    assert_eq!(encoded.allocation_bytes, encoded_requests);
    let total = construction.allocation_bytes + encoded_requests;
    dispose(value);
    let mut remaining = total;
    let mut usage = EncodingUsage::default();
    let value = leaf(&mut usage, &mut remaining);
    let construction_bytes = usage.allocation_bytes;
    let mut output_usage = EncodingUsage::default();
    let output = value
        .to_canonical_bytes_budgeted(total, &mut output_usage, |amount| {
            remaining = remaining.checked_sub(amount).ok_or(())?;
            Ok(())
        })
        .unwrap();
    assert_eq!(output, bytes);
    assert_eq!(remaining, 0, "one shared meter accounts for construction and encoding");
    assert_eq!(construction_bytes + output_usage.allocation_bytes, total);
    dispose(value);
    let mut remaining = total - 1;
    let mut construction = EncodingUsage::default();
    let value = leaf(&mut construction, &mut remaining);
    let mut refused_usage = EncodingUsage::default();
    assert_eq!(
        value.to_canonical_bytes_budgeted(total, &mut refused_usage, |amount| {
            remaining = remaining.checked_sub(amount).ok_or(())?;
            Ok(())
        }),
        Err(EncodingError::Reservation),
        "shared meter refuses encoding after admitted construction"
    );
    assert_eq!(
        construction.allocation_bytes + refused_usage.allocation_bytes,
        total - 1 - remaining
    );
    dispose(value);
    let mut bytes = Vec::<u8>::new();
    let mut usage = EncodingUsage::default();
    let mut callback = false;
    assert_eq!(
        usage.reserve_value_buffer(&mut bytes, 8, 7, |_| {
            callback = true;
            Ok(())
        }),
        Err(EncodingError::Limit)
    );
    assert!(!callback);
    assert_eq!(usage.allocation_bytes, 0);
    usage.reserve_value_buffer(&mut bytes, 8, 8, |_| Ok(())).unwrap();
    assert_eq!(usage.allocation_bytes, 8);
    let before = (usage.allocation_bytes, usage.allocation_calls, bytes.capacity());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        usage.reserve_value_buffer(&mut bytes, 16, usize::MAX, |_| panic!("caller panic"))
    }));
    assert!(panic.is_err());
    assert_eq!((usage.allocation_bytes, usage.allocation_calls, bytes.capacity()), before);
    let mut usage = EncodingUsage::default();
    assert_eq!(
        usage.reserve_value_buffer(&mut Vec::<u8>::new(), usize::MAX, usize::MAX, |_| Ok(())),
        Err(EncodingError::Allocation)
    );
    assert_eq!((usage.allocation_bytes, usage.allocation_calls), (usize::MAX, 1));
}
