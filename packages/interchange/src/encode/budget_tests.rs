use super::*;
use crate::{Array, Map, Tag};
use std::cell::RefCell;

type Requests = Vec<(usize, usize, usize)>;
thread_local! {
    static REQUESTS: RefCell<Requests> = const { RefCell::new(Vec::new()) };
}
pub(super) fn requested(amount: usize, usage: &EncodingUsage) {
    REQUESTS.with_borrow_mut(|calls| calls.push((amount, usage.allocation_calls, usage.allocation_bytes)));
}
fn clear() {
    REQUESTS.with_borrow_mut(Vec::clear);
}
fn calls() -> Requests {
    REQUESTS.with_borrow(Clone::clone)
}
fn accounted(usage: &EncodingUsage) {
    let mut total = 0;
    for (index, (amount, count, bytes)) in calls().into_iter().enumerate() {
        total += amount;
        assert_eq!(count, index + 1, "charge precedes reservation-site execution");
        assert_eq!(bytes, total, "bytes charged before site execution");
    }
    assert_eq!(usage.allocation_bytes, total, "usage retains exact requests on every outcome");
    assert_eq!(usage.allocation_calls, calls().len());
}
fn nested() -> Value {
    let mut value = Value::Unsigned(24);
    for width in [16, 8, 4, 2] {
        let mut children = vec![Value::Null; width];
        children.push(value);
        value = Value::Array(Array::new(children));
    }
    value
}

/// Claim: Encoding reservation-site observations show prior charging and exact usage on success and refusal, including each workspace growth and output reservation; no allocator outside the site is observed.
/// ´claim:encoding:canonical-encoding-reservations´
/// ´test:unit:canonical-encoding-reservations´
#[test]
fn canonical_encoding_reservations() {
    for value in [Value::Null, Value::Array(Array::new([])), nested()] {
        clear();
        let mut usage = EncodingUsage::default();
        let bytes = value.to_canonical_bytes_budgeted(usize::MAX, &mut usage, |_| Ok(())).unwrap();
        assert_eq!(bytes, value.to_canonical_bytes());
        accounted(&usage);
        let need = usage.allocation_bytes;
        assert!(
            need >= std::mem::size_of::<Node<'_>>() + bytes.len(),
            "workspace and output are charged"
        );
        let requests = calls();
        let mut prefix = 0;
        for (index, request) in requests.iter().enumerate() {
            prefix += request.0;
            clear();
            assert_eq!(
                value.to_canonical_bytes_budgeted(prefix - 1, &mut usage, |_| Ok(())),
                Err(EncodingError::Limit),
                "one below each reservation prefix"
            );
            assert_eq!(calls(), requests[..index], "one below refuses the next site");
            accounted(&usage);
            clear();
            let result = value.to_canonical_bytes_budgeted(prefix, &mut usage, |_| Ok(()));
            assert_eq!(
                result.is_ok(),
                index + 1 == requests.len(),
                "exact prefix admits its reservation"
            );
            assert_eq!(calls(), requests[..=index]);
            accounted(&usage);
        }
        clear();
        assert!(
            value.to_canonical_bytes_budgeted(need, &mut usage, |_| Ok(())).is_ok(),
            "exact budget succeeds"
        );
        assert_eq!(usage.allocation_bytes, need);
        accounted(&usage);
        clear();
        assert_eq!(
            value.to_canonical_bytes_budgeted(need - 1, &mut usage, |_| Ok(())),
            Err(EncodingError::Limit),
            "one below refuses before output reservation"
        );
        accounted(&usage);
    }
    clear();
    let mut usage = EncodingUsage::default();
    let mut invoked = false;
    assert_eq!(
        nested().to_canonical_bytes_budgeted(0, &mut usage, |_| {
            invoked = true;
            Ok(())
        }),
        Err(EncodingError::Limit)
    );
    assert!(!invoked, "ceiling precedes callback");
    assert_eq!(calls(), []);
    accounted(&usage);
    clear();
    let mut usage = EncodingUsage::default();
    let mut callback = |_| Ok(());
    let mut policy = WritePolicy::Budget {
        limit: usize::MAX,
        usage: &mut usage,
        reservation: &mut callback,
    };
    assert_eq!(
        policy.reserve(&mut Vec::<u8>::new(), usize::MAX),
        Err(EncodingError::Allocation),
        "admitted impossible allocation reports refusal"
    );
    accounted(&usage);
}

/// Claim: Each reservation position of one nested encoding can be refused by the caller before execution, with prior usage retained; a shared meter and a panicking callback preserve that boundary.
/// ´claim:encoding:canonical-encoding-callback´
/// ´test:unit:canonical-encoding-callback´
#[test]
fn canonical_encoding_callback() {
    let value = nested();
    clear();
    let mut usage = EncodingUsage::default();
    value.to_canonical_bytes_budgeted(usize::MAX, &mut usage, |_| Ok(())).unwrap();
    let requests = calls();
    assert_eq!(requests.len(), 6, "six reservation positions of this nested input");
    for refused in 0..requests.len() {
        clear();
        let mut position = 0;
        let result = value.to_canonical_bytes_budgeted(usize::MAX, &mut usage, |_| {
            position += 1;
            if position == refused + 1 { Err(()) } else { Ok(()) }
        });
        assert_eq!(result, Err(EncodingError::Reservation), "caller refusal stops encoding");
        assert_eq!(calls(), requests[..refused], "refused request never executes");
        accounted(&usage);
    }
    let bytes = value.to_canonical_bytes();
    let mut validation = crate::CanonicalUsage::default();
    Value::validate_canonical_bytes(&bytes, usize::MAX, &mut validation, |_| Ok(()), |_| {}).unwrap();
    let mut remaining = validation.allocation_bytes + requests.iter().map(|request| request.0).sum::<usize>() - 1;
    Value::validate_canonical_bytes(
        &bytes,
        usize::MAX,
        &mut validation,
        |amount| {
            remaining = remaining.checked_sub(amount).ok_or(())?;
            Ok(())
        },
        |_| {},
    )
    .unwrap();
    clear();
    assert_eq!(
        value.to_canonical_bytes_budgeted(usize::MAX, &mut usage, |amount| {
            remaining = remaining.checked_sub(amount).ok_or(())?;
            Ok(())
        }),
        Err(EncodingError::Reservation),
        "shared meter refuses midway"
    );
    accounted(&usage);
    clear();
    let mut position = 0;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(value.to_canonical_bytes_budgeted(usize::MAX, &mut usage, |_| {
            position += 1;
            assert_ne!(position, 2, "callback fixture panic");
            Ok(())
        }));
    }));
    assert!(result.is_err(), "callback panic propagates");
    assert_eq!(calls(), requests[..1]);
    accounted(&usage);
}

/// Claim: The counting sink refuses an over-ceiling or overflowing length before output allocation, while adjacent admitted lengths remain exact.
/// ´claim:encoding:canonical-encoding-length´
/// ´test:unit:canonical-encoding-length´
#[test]
fn canonical_encoding_length() {
    let mut sink = PublicOutput::Count { length: 3, ceiling: 4 };
    assert_eq!(sink.count(1), Ok(()));
    assert_eq!(sink.count(1), Err(EncodingError::Length), "length pass refuses above ceiling");
    let mut sink = PublicOutput::Count {
        length: usize::MAX,
        ceiling: usize::MAX,
    };
    assert_eq!(
        sink.count(1),
        Err(EncodingError::Length),
        "length arithmetic refuses overflow"
    );
    clear();
    let value = Value::Bytes(vec![0; 1024].into());
    let mut usage = EncodingUsage::default();
    assert_eq!(
        value.to_canonical_bytes_budgeted(128, &mut usage, |_| Ok(())),
        Err(EncodingError::Length)
    );
    assert_eq!(calls().len(), 1, "length refusal allocates workspace only");
    accounted(&usage);
}

fn head_controls() {
    // Head-only controls cover lengths whose complete payload would require gigabytes.
    // They are not counted as additional complete-value inputs.
    for argument in [u64::MAX, 0, 24, 23, 256, 255, 65_536, 65_535, 4_294_967_296, 4_294_967_295] {
        for major in 0..=6 {
            let mut expected = Vec::new();
            write_head(&mut expected, major, argument);
            let mut actual = Vec::new();
            PublicOutput::Bytes(&mut actual).head(major, argument).unwrap();
            assert_eq!(actual, expected);
            let mut count = PublicOutput::Count {
                length: 0,
                ceiling: expected.len(),
            };
            count.head(major, argument).unwrap();
            assert!(matches!(count, PublicOutput::Count { length, .. } if length == expected.len()));
        }
    }
}

fn corpus() -> Vec<Value> {
    let mut corpus = vec![Value::Null, Value::Bool(true), Value::Bool(false)];
    for n in [u64::MAX, 0, 24, 23, 256, 255, 65_536, 65_535, 4_294_967_296, 4_294_967_295] {
        corpus.push(Value::Unsigned(n));
        corpus.push(Value::Negative(crate::Negative::from_argument(n)));
        corpus.push(Value::Tag(Tag::new(n, Value::Null)));
    }
    for n in [255, 0, 254, 19, 32] {
        corpus.push(Value::Simple(crate::Simple::new(n).unwrap()));
    }
    for f in [0.0, -0.0, 1.5, 100_000.0, 1.1, f64::INFINITY, f64::NEG_INFINITY] {
        corpus.push(Value::Float(crate::Float::from_f64(f).unwrap()));
    }
    corpus.push(Value::Float(crate::Float::CANONICAL_NAN));
    for length in [256, 0, 1, 24, 23, 255, 65_536, 65_535] {
        corpus.push(Value::Bytes(vec![0x41; length].into()));
        corpus.push(Value::Text("a".repeat(length).into()));
    }
    for width in [24, 0, 1, 23, 256, 255] {
        corpus.push(Value::Array(Array::new((0..width).map(Value::Unsigned))));
        corpus.push(Value::Map(
            Map::new((0..width).rev().map(|n| (Value::Unsigned(n), Value::Null))).unwrap(),
        ));
    }
    let mut nested = Value::Null;
    for depth in 1..=64 {
        nested = match depth % 3 {
            0 => Value::Array(Array::new([nested])),
            1 => Value::Tag(Tag::new(24, nested)),
            _ => Value::Map(Map::new([(Value::Unsigned(0), nested)]).unwrap()),
        };
        corpus.push(nested.clone());
    }
    corpus
}

/// Claim: A finite unsorted corpus spanning all item kinds, head-width boundaries, container shapes and nesting encodes to the unchanged canonical bytes and passes budgeted strict validation.
/// ´claim:encoding:canonical-encoding-differential´
/// ´test:unit:canonical-encoding-differential´
#[test]
fn canonical_encoding_differential() {
    head_controls();
    let corpus = corpus();
    let mut seen = std::collections::BTreeSet::new();
    for value in corpus {
        let expected = value.to_canonical_bytes();
        let mut usage = EncodingUsage::default();
        let mut requests = Vec::new();
        let bytes = value
            .to_canonical_bytes_budgeted(usize::MAX, &mut usage, |n| {
                requests.push(n);
                Ok(())
            })
            .unwrap();
        assert_eq!(bytes, expected, "budgeted and legacy bytes agree");
        assert_eq!(usage.allocation_bytes, requests.iter().sum::<usize>());
        let mut validation = crate::CanonicalUsage::default();
        let mut validated_requests = Vec::new();
        assert!(
            Value::validate_canonical_bytes(
                &bytes,
                usize::MAX,
                &mut validation,
                |n| {
                    validated_requests.push(n);
                    Ok(())
                },
                |_| {}
            )
            .is_ok()
        );
        assert_eq!(validation.allocation_bytes, validated_requests.iter().sum::<usize>());
        seen.insert(expected); // Deduplication occurs only after both routes and validation.
    }
    assert_eq!(seen.len(), 137, "distinct inputs reached code unsorted");
}
