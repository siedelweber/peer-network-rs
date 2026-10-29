//! mod:module:encode
//!
//! The canonical encoder — total, with no failure mode.
//!
//! Every `Value` is already a member of the data language, so the encoder
//! has no canonicity decision left to make: it writes heads in preferred
//! serialization, definite lengths throughout, map entries in the order
//! the map already stands in, and floats in the width their construction
//! fixed.
//!
//! The walk is iterative. A value nested deeply enough to overflow a
//! recursive encoder is a value the decoder will accept, since the data
//! language bounds nesting nowhere.

use crate::value::{Bytes, Float, Simple, Text, Value};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretSlice, SecretString};

/// The initial byte of a head: the major type, and the additional
/// information the argument's magnitude selects.
// Justified: the narrowing branch requires the argument to be below twenty-four.
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn initial_byte(major: u8, argument: u64) -> u8 {
    let additional = if argument < 24 {
        argument as u8
    } else if argument <= u8::MAX as u64 {
        24
    } else if argument <= u16::MAX as u64 {
        25
    } else if argument <= u32::MAX as u64 {
        26
    } else {
        27
    };
    (major << 5) | additional
}

/// How many bytes a head of this argument occupies, initial byte included.
pub(crate) const fn head_len(argument: u64) -> usize {
    match initial_byte(0, argument) {
        24 => 2,
        25 => 3,
        26 => 5,
        27 => 9,
        _ => 1,
    }
}

// Justified: initial_byte selects each argument width only after checking its numeric bound.
#[allow(clippy::cast_possible_truncation)]
fn write_head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let initial = initial_byte(major, argument);
    out.push(initial);
    match initial & 0x1f {
        24 => out.push(argument as u8),
        25 => out.extend_from_slice(&(argument as u16).to_be_bytes()),
        26 => out.extend_from_slice(&(argument as u32).to_be_bytes()),
        27 => out.extend_from_slice(&argument.to_be_bytes()),
        _ => {}
    }
}

fn write_simple(out: &mut Vec<u8>, simple: Simple) {
    if simple.get() < 24 {
        out.push(0xe0 | simple.get());
    } else {
        out.push(0xf8);
        out.push(simple.get());
    }
}

fn write_float(out: &mut Vec<u8>, float: Float) {
    out.push(float.width().initial_byte());
    let argument_len = float.width().argument_len();
    out.extend_from_slice(&float.bits().to_be_bytes()[8 - argument_len..]);
}

impl Value {
    /// The value's canonical name. Total.
    ///
    /// ```
    /// use pn_interchange::{Text, Value};
    ///
    /// let v = Value::Text(Text::from("IETF".to_owned()));
    /// assert_eq!(v.to_canonical_bytes(), [0x64, 0x49, 0x45, 0x54, 0x46]);
    /// ```
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "INTERCHANGE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "encode::Value::to_canonical_bytes"
        ),
        ret
    )]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.canonical_len());
        self.write_canonical(&mut out);
        out
    }

    /// Append the canonical name to `out`. Total.
    ///
    /// ```
    /// use pn_interchange::Value;
    ///
    /// let mut out = vec![0xff];
    /// Value::Unsigned(1).write_canonical(&mut out);
    /// assert_eq!(out, [0xff, 0x01]);
    /// ```
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "INTERCHANGE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "encode::Value::write_canonical"
        ),
        ret
    )]
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        write_nodes(Node::Public(self), out);
    }

    /// The length of the canonical name, without producing it.
    ///
    /// ```
    /// use pn_interchange::{Array, Value};
    ///
    /// let v = Value::Array(Array::new([Value::Unsigned(1), Value::Unsigned(1000)]));
    /// assert_eq!(v.canonical_len(), v.to_canonical_bytes().len());
    /// ```
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "INTERCHANGE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "encode::Value::canonical_len"
        ),
        ret
    )]
    pub fn canonical_len(&self) -> usize {
        let mut total = 0usize;
        let mut work: Vec<&Value> = vec![self];
        while let Some(value) = work.pop() {
            total += match value {
                Value::Unsigned(n) => head_len(*n),
                Value::Negative(n) => head_len(n.argument()),
                Value::Bytes(b) => {
                    let len = b.as_slice().len();
                    head_len(len as u64) + len
                }
                Value::Text(t) => {
                    let len = t.as_str().len();
                    head_len(len as u64) + len
                }
                Value::Array(a) => {
                    work.extend(a.as_slice());
                    head_len(a.len() as u64)
                }
                Value::Map(m) => {
                    for (key, item) in m.iter() {
                        work.push(key);
                        work.push(item);
                    }
                    head_len(m.len() as u64)
                }
                Value::Tag(t) => {
                    work.push(t.item());
                    head_len(t.number())
                }
                Value::Bool(_) | Value::Null => 1,
                Value::Simple(s) => {
                    if s.get() < 24 {
                        1
                    } else {
                        2
                    }
                }
                Value::Float(f) => 1 + f.width().argument_len(),
            };
        }
        total
    }
}

fn write_bytes(out: &mut Vec<u8>, bytes: &Bytes) {
    write_head(out, 2, bytes.as_slice().len() as u64);
    out.extend_from_slice(bytes.as_slice());
}

fn write_text(out: &mut Vec<u8>, text: &Text) {
    write_head(out, 3, text.as_str().len() as u64);
    out.extend_from_slice(text.as_str().as_bytes());
}

/// Work items borrow either public values or protected leaves.
enum Node<'a> {
    Public(&'a Value),
    Private(&'a SecretValue),
}

fn write_nodes(root: Node<'_>, out: &mut Vec<u8>) {
    let mut work = vec![root];
    while let Some(value) = work.pop() {
        match value {
            Node::Private(private) => {
                write_private(private, out, &mut work);
            }
            Node::Public(value) => match value {
                Value::Unsigned(n) => write_head(out, 0, *n),
                Value::Negative(n) => write_head(out, 1, n.argument()),
                Value::Bytes(b) => write_bytes(out, b),
                Value::Text(t) => write_text(out, t),
                Value::Array(a) => {
                    write_head(out, 4, a.len() as u64);
                    work.extend(a.as_slice().iter().rev().map(Node::Public));
                }
                Value::Map(m) => {
                    write_head(out, 5, m.len() as u64);
                    for (key, item) in m.entries().iter().rev() {
                        work.push(Node::Public(item));
                        work.push(Node::Public(key));
                    }
                }
                Value::Tag(t) => {
                    write_head(out, 6, t.number());
                    work.push(Node::Public(t.item()));
                }
                Value::Bool(false) => out.push(0xf4),
                Value::Bool(true) => out.push(0xf5),
                Value::Null => out.push(0xf6),
                Value::Simple(s) => write_simple(out, *s),
                Value::Float(f) => write_float(out, *f),
            },
        }
    }
}

/// A commitment input with protected leaves and public structure.
/// Public values remain fully observed; private leaves never enter `Value`.
/// (´[ROOT-amend:observe:secret-canonical-encoding]´)
#[derive(Debug)]
pub enum SecretValue {
    /// Deliberately public structure, observed by the ordinary encoder.
    Public(Value),
    /// Private byte field; its length is permitted metadata.
    Bytes(SecretSlice<u8>),
    /// Private UTF-8 field; its length is permitted metadata.
    Text(SecretString),
    /// Private unsigned integer.
    Unsigned(SecretBox<u64>),
    /// Private signed integer.
    Signed(SecretBox<i64>),
    /// Ordered tuple or list; the number and structure of fields are public.
    Array(Vec<SecretValue>),
}

impl Drop for SecretValue {
    /// Justified: Iterative destruction preserves the container's erasure without recursive tracing or a nesting-dependent stack limit.
    fn drop(&mut self) {
        let Self::Array(items) = self else {
            return;
        };
        let mut work = std::mem::take(items);
        while let Some(mut value) = work.pop() {
            if let Self::Array(items) = &mut value {
                work.append(items);
            }
        }
    }
}

impl SecretValue {
    /// Encode through the same canonical traversal as public values.
    /// The result remains protected until an explicitly labelled consumer borrow.
    ///
    /// # Errors
    /// Refuses if the conservative allocation bound exceeds `maximum` or usize.
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "INTERCHANGE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "encode::SecretValue::to_secret_canonical_bytes"
        ),
        ret
    )]
    pub fn to_secret_canonical_bytes(&self, maximum: usize) -> Result<SecretBox<Vec<u8>>, SecretEncodingLimit> {
        let capacity = private_capacity(self, maximum)?;
        let mut output = SecretBox::new(Box::new(Vec::with_capacity(capacity)));
        encode_protected(self, &mut output);
        Ok(output)
    }
}

/// The caller's allocation envelope cannot hold this input's conservative bound.
/// No input content is carried in the refusal.
/// (´[ROOT-amend:observe:secret-canonical-encoding]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretEncodingLimit;

// Caveat: Protected output storage is lent to the canonical traversal only until that traversal returns; its existing writer requires a mutable vector and the preallocated capacity prevents relocation of private bytes.
// (´[ROOT-cav:observe:secret-interchange-encode-output]´)
// Justified: The canonical writer borrows protected output for one traversal without exposing it to an observed ordinary argument.
#[allow(clippy::disallowed_methods)]
fn encode_protected(value: &SecretValue, output: &mut SecretBox<Vec<u8>>) {
    write_nodes(
        Node::Private(value),
        output.expose_secret_mut(/* (´[ROOT-cav:observe:secret-interchange-encode-output]´) */),
    );
}

// Caveat: Private bytes are borrowed only to measure their length for the protected output allocation; the borrow ends at len and no byte is read as a public value.
// (´[ROOT-cav:observe:secret-interchange-capacity-bytes]´)
// Caveat: Private text is borrowed only to measure its UTF-8 length for protected output allocation; the borrow ends at len and the text is never formatted.
// (´[ROOT-cav:observe:secret-interchange-capacity-text]´)
// Justified: Container length access requires these two minimal borrows; only permitted size metadata leaves the calculation.
#[allow(clippy::disallowed_methods)]
fn private_capacity(value: &SecretValue, maximum: usize) -> Result<usize, SecretEncodingLimit> {
    let mut work = vec![value];
    let mut total = 0_usize;
    while let Some(value) = work.pop() {
        let size = match value {
            SecretValue::Public(value) => value.canonical_len(),
            SecretValue::Bytes(bytes) => {
                bytes.expose_secret(/* (´[ROOT-cav:observe:secret-interchange-capacity-bytes]´) */).len().checked_add(9).ok_or(SecretEncodingLimit)?
            }
            SecretValue::Text(text) => {
                text.expose_secret(/* (´[ROOT-cav:observe:secret-interchange-capacity-text]´) */).len().checked_add(9).ok_or(SecretEncodingLimit)?
            }
            SecretValue::Unsigned(_) | SecretValue::Signed(_) => 9,
            SecretValue::Array(items) => {
                work.extend(items);
                9
            }
        };
        total = total.checked_add(size).ok_or(SecretEncodingLimit)?;
        if total > maximum {
            return Err(SecretEncodingLimit);
        }
    }
    Ok(total)
}

// Caveat: The private byte field is borrowed by canonical byte-string framing and copying into protected output; the borrow ends at extend_from_slice and no public Value is constructed.
// (´[ROOT-cav:observe:secret-interchange-write-bytes]´)
// Caveat: The private text field is borrowed by canonical UTF-8 framing and copying into protected output; the borrow ends at extend_from_slice without invoking the public Text accessor.
// (´[ROOT-cav:observe:secret-interchange-write-text]´)
// Caveat: The private unsigned integer is borrowed only for canonical head emission into protected output; the borrow ends with write_head and no instrumented integer constructor runs.
// (´[ROOT-cav:observe:secret-interchange-write-unsigned]´)
// Caveat: The private signed integer is borrowed for sign and magnitude selection and canonical head emission into protected output; the borrow ends at the signed arm and neither branch observes its numeric value.
// (´[ROOT-cav:observe:secret-interchange-write-signed]´)
// Justified: These field-specific borrows feed the existing canonical framing primitives directly and end within their match arms.
#[allow(clippy::disallowed_methods)]
fn write_private<'a>(value: &'a SecretValue, out: &mut Vec<u8>, work: &mut Vec<Node<'a>>) {
    match value {
        SecretValue::Public(value) => work.push(Node::Public(value)),
        SecretValue::Array(items) => {
            write_head(out, 4, items.len() as u64);
            work.extend(items.iter().rev().map(Node::Private));
        }
        SecretValue::Bytes(value) => {
            let bytes = value.expose_secret(/* (´[ROOT-cav:observe:secret-interchange-write-bytes]´) */);
            write_head(out, 2, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        SecretValue::Text(value) => {
            let text = value.expose_secret(/* (´[ROOT-cav:observe:secret-interchange-write-text]´) */);
            write_head(out, 3, text.len() as u64);
            out.extend_from_slice(text.as_bytes());
        }
        SecretValue::Unsigned(value) => write_head(
            out,
            0,
            *value.expose_secret(/* (´[ROOT-cav:observe:secret-interchange-write-unsigned]´) */),
        ),
        SecretValue::Signed(value) => {
            let number = value.expose_secret(/* (´[ROOT-cav:observe:secret-interchange-write-signed]´) */);
            if *number < 0 {
                write_head(out, 1, number.unsigned_abs() - 1);
            } else {
                write_head(out, 0, number.unsigned_abs());
            }
        }
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;
    use crate::{Array, Bytes, Text};
    // Fixture-only secret boundary: The caller owns these fixed test values; only equality with expected public vector bytes is returned.
    // Caveat: The fixed-vector encoded result is borrowed solely for equality with the fixture's public expected encoding; the borrow ends at the comparison and no borrowed bytes enter tracing.
    // (´[ROOT-cav:observe:secret-interchange-fixture-equality]´)
    // Justified: The fixture must compare the protected output with its independently specified expected bytes without logging the borrow.
    #[allow(clippy::disallowed_methods)]
    fn fixture_equal(value: &SecretBox<Vec<u8>>, expected: &[u8]) -> bool {
        value.expose_secret(/* (´[ROOT-cav:observe:secret-interchange-fixture-equality]´) */).as_slice() == expected
    }

    fn fixture() -> (SecretValue, Value) {
        let words = [
            "nonce-private-000",
            "salt-private-111",
            "payload-private-222",
            "dependency-private-333",
            "predigest-private-444",
        ];
        let mut values: Vec<_> = words
            .iter()
            .map(|word| SecretValue::Bytes(SecretSlice::from(word.as_bytes().to_vec())))
            .collect();
        values.push(SecretValue::Text(SecretString::from("private-author-name".to_owned())));
        values.push(SecretValue::Unsigned(SecretBox::new(Box::new(u64::MAX))));
        values.push(SecretValue::Signed(SecretBox::new(Box::new(i64::MIN))));
        let mut public: Vec<_> = words
            .iter()
            .map(|word| Value::Bytes(Bytes::from(word.as_bytes().to_vec())))
            .collect();
        public.push(Value::Text(Text::from("private-author-name".to_owned())));
        public.push(Value::Unsigned(u64::MAX));
        public.push(Value::integer(i128::from(i64::MIN)).unwrap());
        (SecretValue::Array(values), Value::Array(Array::new(public)))
    }

    /// Claim: Protected canonical tuples match public canonical bytes while complete full-trace child captures record no protected field or encoded result; the public route still records its content and the private allocation bound refuses excess.
    /// ´claim:encoding:protected-canonical-bytes-preserve-privacy´
    /// ´test:unit:protected-canonical-bytes´
    #[test]
    fn protected_canonical_bytes() {
        if let Ok(mode) = std::env::var("PN_ENCODING_FIXTURE_CHILD") {
            let (value, public) = fixture();
            let expected = public.to_canonical_bytes();
            let _guard = cli_common::init_json_tracing(tracing::Level::TRACE).unwrap();
            if mode == "private" {
                let encoded = value.to_secret_canonical_bytes(4096).unwrap();
                assert!(fixture_equal(&encoded, &expected));
                assert!(value.to_secret_canonical_bytes(1).is_err());
            } else {
                assert_eq!(public.to_canonical_bytes(), expected);
            }
            return;
        }
        for mode in ["private", "public"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "encode::secret_tests::protected_canonical_bytes", "--nocapture"])
                .env("PN_ENCODING_FIXTURE_CHILD", mode)
                .env("PN_OBSERVE_LEVEL", "trace")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let records: Vec<serde_json::Value> = String::from_utf8(output.stderr)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let status: Vec<_> = records.iter().filter(|row| row["kind"] == "observation_status").collect();
            assert_eq!(status.len(), 1);
            assert_eq!(status[0]["lost_records"], 0);
            assert_eq!(status[0]["undelivered_records"], 0);
            assert!(status[0]["delivered_records"].as_u64().unwrap() > 0);
            let delivered = serde_json::to_string(&records).unwrap();
            if mode == "private" {
                for word in [
                    "nonce-private-000",
                    "salt-private-111",
                    "payload-private-222",
                    "dependency-private-333",
                    "predigest-private-444",
                    "private-author-name",
                ] {
                    assert!(!delivered.contains(word));
                    assert!(!delivered.contains(&serde_json::to_string(word.as_bytes()).unwrap()));
                }
                assert!(!delivered.contains(&u64::MAX.to_string()));
                assert!(!delivered.contains(&i64::MIN.to_string()));
            } else {
                assert!(delivered.contains("private-author-name"));
            }
        }
    }
}
