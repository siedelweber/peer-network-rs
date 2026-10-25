//! Bounded JSON construction, rejecting duplicate keys and inexact numbers.
use crate::rpc::RpcRefusal;
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;

struct Seed<'a> {
    depth: usize,
    remaining: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    /// Justified: Bounded JSON visitor plumbing inherits the RPC read operation; per-token observation would duplicate public content and defeat item bounds.
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.depth == 0 || *self.remaining == 0 {
            return Err(D::Error::custom("JSON resource limit"));
        }
        *self.remaining -= 1;
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    /// Justified: Bounded JSON visitor plumbing inherits the RPC read operation; per-token observation would duplicate public content and defeat item bounds.
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded exact JSON")
    }
    /// Justified: Bounded JSON visitor plumbing inherits the RPC read operation; per-token observation would duplicate public content and defeat item bounds.
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    /// Justified: Bounded JSON visitor plumbing inherits the RPC read operation; per-token observation would duplicate public content and defeat item bounds.
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    /// Justified: Bounded JSON visitor plumbing inherits the RPC read operation; per-token observation would duplicate public content and defeat item bounds.
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }
    /// Justified: Bounded JSON visitor plumbing inherits the RPC read operation; per-token observation would duplicate public content and defeat item bounds.
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }
    // No float visitor: typed chain reads have only exact integers and hex bytes.
    /// Justified: Bounded JSON visitor plumbing inherits the RPC read operation; per-token observation would duplicate public content and defeat item bounds.
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(value.into())
    }
    /// Justified: Bounded JSON visitor plumbing inherits the RPC read operation; per-token observation would duplicate public content and defeat item bounds.
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        Ok(value.into())
    }
    /// Justified: Bounded JSON visitor plumbing inherits the RPC read operation; per-token observation would duplicate public content and defeat item bounds.
    fn visit_seq<A: SeqAccess<'de>>(self, mut source: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = source.next_element_seed(Seed {
            depth: self.depth - 1,
            remaining: self.remaining,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    /// Justified: Bounded JSON visitor plumbing inherits the RPC read operation; per-token observation would duplicate public content and defeat item bounds.
    fn visit_map<A: MapAccess<'de>>(self, mut source: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = source.next_key_seed(Seed {
            depth: self.depth - 1,
            remaining: self.remaining,
        })? {
            let Value::String(key) = key else {
                return Err(A::Error::custom("JSON object key"));
            };
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON key"));
            }
            let value = source.next_value_seed(Seed {
                depth: self.depth - 1,
                remaining: self.remaining,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

pub(crate) fn parse(bytes: &[u8], depth: usize, mut items: usize) -> Result<Value, RpcRefusal> {
    let text = std::str::from_utf8(bytes).map_err(|_| RpcRefusal::Json)?;
    if text.starts_with('\u{feff}') {
        return Err(RpcRefusal::Json);
    }
    let mut decoder = serde_json::Deserializer::from_str(text);
    let value = Seed {
        depth,
        remaining: &mut items,
    }
    .deserialize(&mut decoder)
    .map_err(|_| RpcRefusal::Json)?;
    decoder.end().map_err(|_| RpcRefusal::Json)?;
    Ok(value)
}

pub(crate) fn envelope(value: Value, status: u16, id: u64) -> Result<Value, RpcRefusal> {
    let Value::Object(mut object) = value else {
        return Err(RpcRefusal::Json);
    };
    if object.remove("jsonrpc") != Some(Value::String("2.0".into()))
        || object.remove("id") != Some(id.into())
        || object.len() != 1
    {
        return Err(RpcRefusal::Correlation);
    }
    if let Some(result) = object.remove("result") {
        return if status == 200 {
            Ok(result)
        } else {
            Err(RpcRefusal::Status(status))
        };
    }
    let Some(Value::Object(mut error)) = object.remove("error") else {
        return Err(RpcRefusal::Json);
    };
    let code = error
        .remove("code")
        .and_then(|value| value.as_i64())
        .ok_or(RpcRefusal::Json)?;
    let Some(Value::String(message)) = error.remove("message") else {
        return Err(RpcRefusal::Json);
    };
    let data = error.remove("data");
    if !error.is_empty() {
        return Err(RpcRefusal::Json);
    }
    Err(RpcRefusal::Remote { code, message, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Claim: JSON parsing rejects invalid UTF-8, BOM, duplicate escaped keys, depth and item excesses and inexact numbers before constructing an admitted message.
    /// ´claim:wallet:rpc-json-parser-is-exact-and-bounded´
    /// ´test:unit:parser-cases´
    #[test]
    fn parser_cases() {
        for bytes in [
            b"\xff".as_slice(),
            b"\xef\xbb\xbfnull",
            br#"{"a":1,"\u0061":2}"#,
            b"1.0",
            b"1e2",
            b"18446744073709551616",
            b"-9223372036854775809",
            b"true false",
        ] {
            assert_eq!(parse(bytes, 16, 4096), Err(RpcRefusal::Json));
        }
        assert_eq!(parse(b"[[0]]", 3, 3), Ok(json!([[0]])));
        assert_eq!(parse(b"[[0]]", 2, 3), Err(RpcRefusal::Json));
        assert_eq!(parse(b"[[0]]", 3, 2), Err(RpcRefusal::Json));
        assert_eq!(parse(br#"{"a":0}"#, 2, 3), Ok(json!({"a":0})));
        assert_eq!(parse(br#"{"a":0}"#, 2, 2), Err(RpcRefusal::Json));
        assert_eq!(parse(b"18446744073709551615", 1, 1), Ok(json!(u64::MAX)));
        assert_eq!(parse(b"-9223372036854775808", 1, 1), Ok(json!(i64::MIN)));
    }

    /// Claim: JSON-RPC envelopes require version 2.0, an exact identifier, exclusive result or error and exact error fields; only status 200 admits a result and method schemas decide nullability.
    /// ´claim:wallet:rpc-json-envelope-is-correlated´
    /// ´test:unit:envelope-cases´
    #[test]
    fn envelope_cases() {
        assert_eq!(
            envelope(json!({"jsonrpc":"2.0","id":7,"result":null}), 200, 7),
            Ok(Value::Null)
        );
        for value in [
            json!({"jsonrpc":"1.0","id":7,"result":0}),
            json!({"jsonrpc":"2.0","id":"7","result":0}),
            json!({"jsonrpc":"2.0","id":8,"result":0}),
            json!({"jsonrpc":"2.0","id":7}),
            json!({"jsonrpc":"2.0","id":7,"result":null,"error":null}),
            json!({"jsonrpc":"2.0","result":0}),
        ] {
            assert_eq!(envelope(value, 200, 7), Err(RpcRefusal::Correlation));
        }
        for status in [200, 400, 404, 500] {
            assert_eq!(
                envelope(
                    json!({"jsonrpc":"2.0","id":7,"error":{"code":-1,"message":"public","data":{"x":1}}}),
                    status,
                    7
                ),
                Err(RpcRefusal::Remote {
                    code: -1,
                    message: "public".into(),
                    data: Some(json!({"x":1}))
                })
            );
            if status != 200 {
                assert_eq!(
                    envelope(json!({"jsonrpc":"2.0","id":7,"result":null}), status, 7),
                    Err(RpcRefusal::Status(status))
                );
            }
        }
        for error in [
            Value::Null,
            json!({"code":1.5,"message":"x"}),
            json!({"code":1,"message":false}),
            json!({"code":1,"message":"x","extra":0}),
        ] {
            assert_eq!(
                envelope(json!({"jsonrpc":"2.0","id":7,"error":error}), 200, 7),
                Err(RpcRefusal::Json)
            );
        }
        assert_eq!(envelope(json!([]), 200, 7), Err(RpcRefusal::Json));
    }
}
