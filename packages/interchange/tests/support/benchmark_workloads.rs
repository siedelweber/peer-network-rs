use pn_interchange::{Array, Value};

pub fn value() -> Value {
    Value::Array(Array::new(vec![
        Value::Unsigned(0),
        Value::Unsigned(24),
        Value::Bool(true),
        Value::Null,
    ]))
}

pub const BYTES: &[u8] = &[132, 0, 24, 24, 245, 246];
