//! Connection-only JSON is decoded directly into secret-owned fields.
use crate::{
    Refusal,
    secret::{Buffer, LIMIT},
};
use secrecy::ExposeSecretMut;
use std::{fmt, io::Read, ops::Range};

/// A store configuration acquired under the public host-secured link case.
/// (´def:host:connection-configuration´)
/// The private fields have neither Display nor serialization. Parsing failures
/// contain only bounded causes, never a parser's copy of the input.
///
/// ```compile_fail
/// fn display(config: pn_host::Configuration) { let _ = format!("{config}"); }
/// ```
///
/// ```compile_fail
/// fn serialize(config: pn_host::Configuration) { let _ = serde_json::to_vec(&config); }
/// ```
pub struct Configuration {
    data: Buffer,
    fields: [Range<usize>; 6],
}

impl Configuration {
    /// Acquire connection-only JSON without an intermediate public allocation.
    /// (´rule:host:secret-acquisition´)
    /// # Errors
    /// Refuses an absent, unknown or held case before reading; malformed JSON,
    /// duplicate/unknown fields, unsupported endpoint forms and excessive input.
    pub fn acquire(case: Option<&str>, reader: &mut impl Read) -> Result<Self, Refusal> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "config::Configuration::acquire",
            &"secret connection input",
        );
        let result = Self::read(case, reader);
        if let Err(cause) = &result {
            tracing::warn!(outcome = "refusal", cause = ?cause, "store configuration refused");
        } else {
            tracing::info!(store_link_case = "host-secured");
        }
        operation.finish(&result);
        result
    }
    fn read(case: Option<&str>, reader: &mut impl Read) -> Result<Self, Refusal> {
        match case {
            Some("host-secured") => (),
            None => return Err(Refusal::MissingCase),
            Some("guarded") => return Err(Refusal::HeldCase),
            Some(_) => return Err(Refusal::UnknownCase),
        }
        let mut input = Buffer::new();
        let mut length = 0;
        loop {
            if length == LIMIT {
                return Err(Refusal::RepresentationLimit);
            }
            let count = reader
                .read(&mut input.storage()[length..])
                .map_err(|_| Refusal::ConfigurationIo)?;
            if count == 0 {
                break;
            }
            length += count;
        }
        input.set_length(length)?;
        let mut cursor = Json {
            bytes: input.bytes(),
            at: 0,
        };
        let mut data = Buffer::new();
        let mut fields: [Option<Range<usize>>; 6] = std::array::from_fn(|_| None);
        cursor.token(b'{')?;
        loop {
            let key = cursor.string()?;
            let index = match key.bytes() {
                b"transport" => 0,
                b"endpoint" => 1,
                b"port" => 2,
                b"user" => 3,
                b"password" => 4,
                b"database" => 5,
                _ => return Err(Refusal::ConfigurationSyntax),
            };
            if fields[index].is_some() {
                return Err(Refusal::ConfigurationSyntax);
            }
            cursor.token(b':')?;
            let value = cursor.string()?;
            if value.bytes().contains(&0) {
                return Err(Refusal::ConfigurationSyntax);
            }
            let start = data.bytes().len();
            data.append(value.bytes())?;
            fields[index] = Some(start..data.bytes().len());
            cursor.space();
            if cursor.bytes.get(cursor.at) == Some(&b'}') {
                cursor.at += 1;
                break;
            }
            cursor.token(b',')?;
        }
        cursor.space();
        if cursor.at != cursor.bytes.len() || fields.iter().any(Option::is_none) {
            return Err(Refusal::ConfigurationSyntax);
        }
        let fields = fields.map(Option::unwrap);
        let result = Self { data, fields };
        if !matches!(result.field(0), b"unix" | b"tcp")
            || result.field(1).is_empty()
            || result.field(3).is_empty()
            || result.field(5).is_empty()
            || !result.field(4).iter().all(|value| (0x20..=0x7e).contains(value))
        {
            return Err(Refusal::ConfigurationSyntax);
        }
        result.port()?;
        Ok(result)
    }
    pub(crate) fn field(&self, index: usize) -> &[u8] {
        &self.data.bytes()[self.fields[index].clone()]
    }
    pub(crate) fn text(&self, index: usize) -> Result<&str, Refusal> {
        std::str::from_utf8(self.field(index)).map_err(|_| Refusal::ConfigurationSyntax)
    }
    pub(crate) fn port(&self) -> Result<u16, Refusal> {
        self.text(2)?
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(Refusal::ConfigurationSyntax)
    }
}
impl fmt::Debug for Configuration {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Configuration { role: store-connection, value: [REDACTED] }")
    }
}

struct Json<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Json<'_> {
    fn space(&mut self) {
        while self.bytes.get(self.at).is_some_and(|v| b" \t\r\n".contains(v)) {
            self.at += 1;
        }
    }
    fn token(&mut self, byte: u8) -> Result<(), Refusal> {
        self.space();
        if self.bytes.get(self.at) != Some(&byte) {
            return Err(Refusal::ConfigurationSyntax);
        }
        self.at += 1;
        Ok(())
    }
    fn hex(&mut self) -> Result<u32, Refusal> {
        let mut value = 0;
        for _ in 0..4 {
            let digit = *self.bytes.get(self.at).ok_or(Refusal::ConfigurationSyntax)?;
            self.at += 1;
            value = value * 16 + char::from(digit).to_digit(16).ok_or(Refusal::ConfigurationSyntax)?;
        }
        Ok(value)
    }
    fn string(&mut self) -> Result<Buffer, Refusal> {
        self.token(b'"')?;
        let mut value = Buffer::new();
        loop {
            let byte = *self.bytes.get(self.at).ok_or(Refusal::ConfigurationSyntax)?;
            self.at += 1;
            match byte {
                b'"' => {
                    std::str::from_utf8(value.bytes()).map_err(|_| Refusal::ConfigurationSyntax)?;
                    return Ok(value);
                }
                b'\\' => {
                    let escaped = *self.bytes.get(self.at).ok_or(Refusal::ConfigurationSyntax)?;
                    self.at += 1;
                    let decoded = match escaped {
                        b'"' | b'\\' | b'/' => escaped,
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => 10,
                        b'r' => 13,
                        b't' => 9,
                        b'u' => {
                            let mut code = self.hex()?;
                            if (0xd800..=0xdbff).contains(&code) {
                                if self.bytes.get(self.at..self.at + 2) != Some(b"\\u") {
                                    return Err(Refusal::ConfigurationSyntax);
                                }
                                self.at += 2;
                                let low = self.hex()?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Err(Refusal::ConfigurationSyntax);
                                }
                                code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
                            }
                            let scalar = char::from_u32(code).ok_or(Refusal::ConfigurationSyntax)?;
                            let mut encoded = secrecy::SecretBox::new(Box::new([0_u8; 4]));
                            value.append(scalar.encode_utf8(encoded.expose_secret_mut()).as_bytes())?;
                            continue;
                        }
                        _ => return Err(Refusal::ConfigurationSyntax),
                    };
                    value.append(&[decoded])?;
                }
                0..=31 => return Err(Refusal::ConfigurationSyntax),
                _ => value.append(&[byte])?,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Configuration, Refusal};

    /// Claim: Direct secret parsing gives JSON escapes their Unicode scalar meaning while refusing isolated surrogates, repeated fields and trailing input, so malformed private configuration cannot acquire a different interpretation.
    /// ´claim:host:secret-json-has-one-field-interpretation´
    /// ´test:unit:secret-json-grammar´
    #[test]
    fn secret_json_grammar() {
        let input = br#"{"transport":"unix","endpoint":"/socket","port":"42100","user":"a\u0062\uD83D\uDE00","password":"safe","database":"db"}"#;
        let config = Configuration::acquire(Some("host-secured"), &mut input.as_slice()).unwrap();
        assert_eq!(config.field(3), "ab😀".as_bytes());
        for invalid in [
            br#"{"transport":"unix","endpoint":"/socket","port":"42100","user":"\uD800","password":"safe","database":"db"}"#.as_slice(),
            br#"{"transport":"unix","endpoint":"/socket","port":"42100","user":"a","user":"b","password":"safe","database":"db"}"#,
            br#"{"transport":"unix","endpoint":"/socket","port":"42100","user":"a","password":"safe","database":"db"} true"#,
        ] {
            assert_eq!(Configuration::acquire(Some("host-secured"), &mut &*invalid).unwrap_err(), Refusal::ConfigurationSyntax);
        }
    }
}
