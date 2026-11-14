use super::*;

fn array(value: &Value) -> &[Value] {
    match value {
        Value::Array(a) => a.as_slice(),
        _ => panic!("array"),
    }
}

std::thread_local! {
    static RELEASES: std::cell::RefCell<Vec<(&'static str, usize)>> = const { std::cell::RefCell::new(Vec::new()) };
}

pub(in crate::admitted_result::position) fn release_site(kind: &'static str, values: &[Value]) {
    // This observes the host's disposal invocation, not the dependency's allocator or destructor.
    RELEASES.with(|events| events.borrow_mut().push((kind, values.len())));
}

/// Claim: Host cleanup sites release partial children on refusal and panic and the complete preimage on encoding refusal and panic; this observes disposal invocations, not allocator activity. A real spare-capacity buffer refuses transfer and retains its address and capacity.
/// ´claim:history:position-release-sites´
/// ´test:unit:position-release-sites´
#[test]
fn position_release_sites() {
    partial_cleanup();
    complete_cleanup();
    spare_capacity();
}

fn partial_cleanup() {
    for panic in [false, true] {
        RELEASES.with(|events| events.borrow_mut().clear());
        let result = std::panic::catch_unwind(|| {
            let mut usage = EncodingUsage::default();
            let mut callback = |_| Ok(());
            let mut builder = Builder {
                ceiling: usize::MAX,
                usage: &mut usage,
                reservation: &mut callback,
            };
            builder.array(3, |builder, children| {
                children.push(builder.text("first")?);
                children.push(builder.text("second")?);
                assert!(!panic, "partial construction panic");
                Err(Error::InvalidPosition)
            })
        });
        if panic {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().unwrap_err(), Error::InvalidPosition);
        }
        assert_eq!(
            RELEASES.with(|events| events.borrow().clone()),
            [("children", 2)],
            "partial children reach disposal once"
        );
    }
}

fn complete_cleanup() {
    let input = Input::admitted(&packages().0).unwrap();
    let mut construction = EncodingUsage::default();
    let mut callback = |_| Ok(());
    let mut builder = Builder {
        ceiling: usize::MAX,
        usage: &mut construction,
        reservation: &mut callback,
    };
    drop(builder.projection(&input, None, None).unwrap());
    let construction_calls = construction.allocation_calls;
    for panic in [false, true] {
        RELEASES.with(|events| events.borrow_mut().clear());
        let mut calls = 0;
        let mut usage = EncodingUsage::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Position::from_package(&packages().0, None, RECIPE, usize::MAX, &mut usage, |_| {
                if calls == construction_calls {
                    assert!(!panic, "encoding callback panic");
                    return Err(());
                }
                calls += 1;
                Ok(())
            })
            .map(|_| ())
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap(),
                Err(Error::Representation(Representation::Encoding(EncodingError::Reservation)))
            );
        }
        assert_eq!(
            RELEASES.with(|events| events
                .borrow()
                .iter()
                .filter(|(kind, _)| *kind == "owned")
                .copied()
                .collect::<Vec<_>>()),
            [("owned", 1)],
            "complete preimage reaches disposal once"
        );
    }
}

fn spare_capacity() {
    let mut buffer = Vec::new();
    EncodingUsage::default()
        .reserve_value_buffer(&mut buffer, 8, usize::MAX, |_| Ok(()))
        .unwrap();
    buffer.extend_from_slice(b"text");
    let address = buffer.as_ptr();
    let capacity = buffer.capacity();
    assert!(capacity > buffer.len());
    let refused = Text::take_reserved(&mut buffer).map_err(Error::from);
    assert_eq!(
        refused.unwrap_err(),
        Error::Representation(Representation::Transfer(TransferError::SpareCapacity)),
        "spare capacity remains a representation refusal"
    );
    assert_eq!(buffer.as_ptr(), address);
    assert_eq!(buffer.capacity(), capacity);
    assert_eq!(buffer, b"text");
}

/// Claim: A marker projection emits a nonempty lineage, accepted and complete-list difference over a nonempty base, excluding inherited members without changing the seven vectors.
/// ´claim:history:position-nonempty-difference´
/// ´test:unit:position-nonempty-difference´
#[test]
fn position_nonempty_difference() {
    let root = Input::admitted(&packages().0).unwrap();
    let child = Input::admitted(&packages().1).unwrap();
    assert!(!root.terminal.accepted().is_empty());
    let mut frame = child.frame.clone();
    let mut added = frame.marker_history.records[0].clone();
    added.identity = "new-record".into();
    frame.marker_history.records.push(added);
    let marker = frame.marker_history.markers.last_mut().unwrap();
    marker.lineage.insert("new-record".into());
    let burn::AcceptedSet::CompleteList(members) = &mut marker.accepted else {
        unreachable!()
    };
    members.insert("new-record".into());
    recognize(&mut frame);
    let child = input(&frame, child.genesis);
    child.validate(Some(&root)).unwrap();
    let value = Value::from_canonical_bytes(&bytes(&child, Some(&root), Some(&[1; 32]))).unwrap();
    let projected = &array(&array(&value)[1])[2];
    let lineage = array(&array(projected)[7]);
    assert_eq!(lineage.len(), 1, "inherited lineage omitted");
    assert_eq!(array(&lineage[0])[0], Value::Text("new-record".to_owned().into()));
    assert_eq!(
        array(&array(projected)[8])[1],
        Value::Array(Array::new([Value::Text("new-record".to_owned().into())]))
    );
    assert_eq!(
        array(projected)[9],
        Value::Array(Array::new([Value::Text("new-record".to_owned().into())]))
    );
    value.dispose();
}
