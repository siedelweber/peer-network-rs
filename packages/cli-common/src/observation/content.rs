//! Lossless public payload representations and delivery-owned artifacts.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const INLINE_BYTES: usize = 65_536;
// Leave envelope and reference headroom below serde_json's default 128 levels.
pub(super) const INLINE_NESTING: usize = 96;

/// Convert the available Debug value grammar into tagged JSON structure.
/// Justified: Representation runs inside the labelled observation delivery operation and must not recursively observe itself.
pub(super) fn structured(text: &str) -> Value {
    let mut parser = Parser { text, position: 0 };
    if let Some(value) = parser.value(0) {
        parser.space();
        if parser.position == text.len() {
            return value;
        }
    }
    // Debug is an open formatting interface, not a serialization trait. An
    // arbitrary implementation need not use Rust's structural grammar. Preserve
    // that representation explicitly instead of guessing its data model.
    json!({"representation":"custom-debug","content":bytes(text.as_bytes())})
}

struct Parser<'a> {
    text: &'a str,
    position: usize,
}
impl Parser<'_> {
    fn space(&mut self) {
        while self.text.as_bytes().get(self.position).is_some_and(u8::is_ascii_whitespace) {
            self.position += 1;
        }
    }
    fn consume(&mut self, byte: u8) -> bool {
        self.space();
        if self.text.as_bytes().get(self.position) == Some(&byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }
    fn quoted(&mut self, quote: u8) -> Option<String> {
        self.space();
        if quote == b'"' {
            let mut strings = serde_json::Deserializer::from_str(self.text.get(self.position..)?).into_iter::<String>();
            if let Some(Ok(value)) = strings.next() {
                self.position += strings.byte_offset();
                return Some(value);
            }
        }
        if !self.consume(quote) {
            return None;
        }
        let mut result = String::new();
        loop {
            let next = self.text.get(self.position..)?.chars().next()?;
            self.position += next.len_utf8();
            if next == char::from(quote) {
                return Some(result);
            }
            if next != '\\' {
                result.push(next);
                continue;
            }
            let escape = *self.text.as_bytes().get(self.position)?;
            self.position += 1;
            result.push(match escape {
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'0' => '\0',
                b'\\' => '\\',
                b'"' => '"',
                b'\'' => '\'',
                b'u' => {
                    if !self.consume(b'{') {
                        return None;
                    }
                    let end = self.text.get(self.position..)?.find('}')? + self.position;
                    let scalar = u32::from_str_radix(self.text.get(self.position..end)?, 16).ok()?;
                    self.position = end + 1;
                    char::from_u32(scalar)?
                }
                b'x' => {
                    let end = self.position.checked_add(2)?;
                    let scalar = u8::from_str_radix(self.text.get(self.position..end)?, 16).ok()?;
                    self.position = end;
                    char::from(scalar)
                }
                _ => return None,
            });
        }
    }
    fn sequence(&mut self, end: u8, depth: usize) -> Option<Vec<Value>> {
        let mut values = Vec::new();
        if self.consume(end) {
            return Some(values);
        }
        loop {
            values.push(self.value(depth + 1)?);
            if self.consume(end) {
                return Some(values);
            }
            if !self.consume(b',') {
                return None;
            }
            if self.consume(end) {
                return Some(values);
            }
        }
    }
    fn object(&mut self, depth: usize) -> Option<Value> {
        let mut entries = Vec::new();
        if self.consume(b'}') {
            return Some(json!({"entries":entries}));
        }
        loop {
            let key = self.value(depth + 1)?;
            if !self.consume(b':') {
                return None;
            }
            let value = self.value(depth + 1)?;
            entries.push(json!([key, value]));
            if self.consume(b'}') {
                return Some(json!({"entries":entries}));
            }
            if !self.consume(b',') {
                return None;
            }
        }
    }
    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > 48 {
            return None;
        }
        self.space();
        if self.text.get(self.position..)?.starts_with("[REDACTED]") {
            self.position += "[REDACTED]".len();
            return Some(json!({"representation":"secret-marker","marker":"[REDACTED]"}));
        }
        match *self.text.as_bytes().get(self.position)? {
            b'"' => return self.quoted(b'"').map(Value::String),
            b'\'' => return self.quoted(b'\'').map(|v| json!({"character":v})),
            b'[' => {
                self.position += 1;
                if let Some(end) = self.text.get(self.position..)?.find(']') {
                    let body = self.text.get(self.position..self.position + end)?;
                    if !body.is_empty() {
                        let packed: Result<Vec<u8>, _> = body.split(',').map(|s| s.trim().parse()).collect();
                        if let Ok(packed) = packed {
                            self.position += end + 1;
                            return Some(json!({"sequence_u8":bytes(&packed)}));
                        }
                    }
                }
                let values = self.sequence(b']', depth)?;
                let packed: Option<Vec<u8>> = values.iter().map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok())).collect();
                return Some(
                    packed
                        .filter(|_| !values.is_empty())
                        .map_or_else(|| json!({"sequence":values}), |v| json!({"sequence_u8":bytes(&v)})),
                );
            }
            b'(' => {
                self.position += 1;
                return self.sequence(b')', depth).map(|v| json!({"tuple":v}));
            }
            b'{' => {
                self.position += 1;
                return self.object(depth);
            }
            _ => {}
        }
        let start = self.position;
        while self
            .text
            .as_bytes()
            .get(self.position)
            .is_some_and(|b| !b.is_ascii_whitespace() && !b"(){}[],:".contains(b))
        {
            self.position += 1;
        }
        let atom = self.text.get(start..self.position)?;
        if atom.is_empty() {
            return None;
        }
        if self.consume(b'(') {
            return self.sequence(b')', depth).map(|v| json!({"constructor":atom,"arguments":v}));
        }
        if self.consume(b'{') {
            return self.object(depth).map(|v| json!({"type":atom,"fields":v}));
        }
        if let Ok(value) = serde_json::from_str::<Value>(atom) {
            // This round-trip comparison is deliberate: JSON may otherwise
            // approximate an integer wider than u64 as a floating-point value.
            let spelling = value.to_string();
            if !value.is_number() || spelling == atom {
                return Some(value);
            }
        }
        Some(json!({"atom":atom}))
    }
}

/// Encode arbitrary public bytes without decimal-array expansion.
/// Justified: Representation runs inside the labelled observation delivery operation and must not recursively observe itself.
pub(super) fn bytes(value: &[u8]) -> Value {
    match std::str::from_utf8(value) {
        Ok(text) => json!({"encoding":"utf-8","data":text,"length_bytes":value.len()}),
        Err(_) => json!({"encoding":"base64","data":base64(value),"length_bytes":value.len()}),
    }
}

fn base64(value: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::with_capacity(value.len().div_ceil(3) * 4);
    for part in value.chunks(3) {
        let a = part[0];
        let b = part.get(1).copied().unwrap_or(0);
        let c = part.get(2).copied().unwrap_or(0);
        for index in [a >> 2, ((a & 3) << 4) | (b >> 4)] {
            text.push(char::from(ALPHABET[usize::from(index)]));
        }
        text.push(if part.len() > 1 {
            char::from(ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        text.push(if part.len() > 2 {
            char::from(ALPHABET[usize::from(c & 63)])
        } else {
            '='
        });
    }
    text
}

/// Store large values on the delivery worker, replacing only their representation.
/// Justified: Artifact publication is part of the labelled observation delivery operation and must not recursively observe itself.
pub(super) fn compact(record: &mut Value, root: &Path) -> io::Result<()> {
    // Address payloads before their changing timestamp/operation envelopes.
    if let Value::Object(fields) = record {
        for value in fields.values_mut() {
            compact_value(value, root)?;
        }
    }
    let encoded = serde_json::to_vec(record)?;
    if encoded.len() >= super::RECORD_LIMIT {
        *record = json!({"kind":"observation_artifact","payload":artifact(&encoded, root)?});
    }
    Ok(())
}

fn nesting(value: &Value) -> usize {
    match value {
        Value::Object(fields) => 1 + fields.values().map(nesting).max().unwrap_or(0),
        Value::Array(values) => 1 + values.iter().map(nesting).max().unwrap_or(0),
        _ => 0,
    }
}

fn compact_value(value: &mut Value, root: &Path) -> io::Result<()> {
    let encoded = serde_json::to_vec(value)?;
    if encoded.len() <= INLINE_BYTES && nesting(value) < INLINE_NESTING {
        return Ok(());
    }
    compact_tree(value, root)?;
    Ok(())
}

// Derive exact JSON sizes and remaining nesting once, bottom-up. Children are
// addressed before envelopes, so payload identity is independent of its parent.
fn compact_tree(value: &mut Value, root: &Path) -> io::Result<(usize, usize)> {
    let (size, depth) = match value {
        Value::Object(fields) => {
            let mut size = 2 + fields.len().saturating_sub(1);
            let mut depth = 1;
            for (key, child) in fields {
                let (child_size, child_depth) = compact_tree(child, root)?;
                size += serde_json::to_vec(key)?.len() + 1 + child_size;
                depth = depth.max(1 + child_depth);
            }
            (size, depth)
        }
        Value::Array(values) => {
            let mut size = 2 + values.len().saturating_sub(1);
            let mut depth = 1;
            for child in values {
                let (child_size, child_depth) = compact_tree(child, root)?;
                size += child_size;
                depth = depth.max(1 + child_depth);
            }
            (size, depth)
        }
        _ => (serde_json::to_vec(value)?.len(), 0),
    };
    if size > INLINE_BYTES || depth >= INLINE_NESTING {
        *value = artifact(&serde_json::to_vec(value)?, root)?;
        return Ok((serde_json::to_vec(value)?.len(), nesting(value)));
    }
    Ok((size, depth))
}

fn artifact(encoded: &[u8], root: &Path) -> io::Result<Value> {
    use std::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(encoded) {
        write!(&mut digest, "{byte:02x}").map_err(io::Error::other)?;
    }
    let directory = root.join("objects").join("sha256");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(&digest);
    // A fresh, written object atomically replaces corrupt content. Concurrent
    // publishers of the same digest write identical verified bytes.
    if std::fs::read(&path).ok().as_deref() != Some(encoded) {
        let temporary = tempfile::NamedTempFile::new_in(&directory)?;
        let mut file = temporary.as_file();
        file.write_all(encoded)?;
        temporary.persist(&path).map_err(|error| error.error)?;
    }
    // An existing object must be complete; never silently reuse corrupt bytes.
    if std::fs::read(&path)? != encoded {
        return Err(io::Error::other("observation artifact content mismatch"));
    }
    Ok(json!({"encoding":"json","artifact":{"algorithm":"sha256","digest":digest,"length_bytes":encoded.len(),"path":path}}))
}

/// Resolve the caller-owned artifact root without creating it before work.
/// Justified: Artifact configuration belongs to the executable-owned observation bootstrap and must not recursively observe itself.
pub(super) fn root() -> io::Result<PathBuf> {
    let path = std::env::var_os("PN_OBSERVE_ARTIFACT_DIR").map_or_else(|| PathBuf::from(".lane/observations"), PathBuf::from);
    std::path::absolute(path)
}
