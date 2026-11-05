use pn_interchange::{Bytes, TransportLimits, TransportUsage, Value};

pub fn input(size: usize, chunked: bool) -> (Value, Vec<u8>, TransportLimits) {
    let payload: Vec<_> = (0..size).map(|index| u8::try_from(index % 251).unwrap()).collect();
    let value = Value::Bytes(Bytes::from(payload.clone()));
    let bytes = if chunked {
        let mut bytes = vec![0x5f, 0x40];
        for part in payload.chunks(64) {
            bytes.extend(Value::Bytes(Bytes::from(part.to_vec())).to_canonical_bytes());
            bytes.push(0x40);
        }
        bytes.push(0xff);
        bytes
    } else {
        value.to_canonical_bytes()
    };
    let limits = TransportLimits {
        input_bytes: bytes.len(),
        allocation_bytes: size * 4,
        items: size + 4,
        depth: 2,
        nesting: 1,
        work: size * 16,
    };
    let decoded = if chunked {
        Value::from_transport_bytes(&bytes, limits, &mut TransportUsage::default()).unwrap()
    } else {
        Value::from_canonical_bytes(&bytes).unwrap()
    };
    assert_eq!(decoded, value);
    (value, bytes, limits)
}
