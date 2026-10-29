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
    // Caveat: The connection input storage is lent to Read::read for the current bounded acquisition call; the mutable borrow ends when that call returns because Read requires a byte slice.
    // (´[ROOT-cav:observe:secret-host-config-read-buffer-1]´)
    // Caveat: The acquired connection JSON is lent to the Json cursor for field parsing; the borrow ends after the final cursor check before input is dropped because the parser requires a byte slice.
    // (´[ROOT-cav:observe:secret-host-config-read-buffer-2]´)
    // Caveat: The parsed configuration key is lent to the field-name match for this iteration; the borrow ends with that match because byte-pattern selection cannot inspect a carrier.
    // (´[ROOT-cav:observe:secret-host-config-read-buffer-3]´)
    // Caveat: The parsed configuration value is lent to the NUL-byte predicate; the borrow ends when contains returns because slice validation cannot inspect a carrier.
    // (´[ROOT-cav:observe:secret-host-config-read-buffer-4]´)
    // Caveat: The parsed field value is lent to data.append for copying into protected configuration storage; the borrow ends when append returns because bounded append accepts a byte slice.
    // (´[ROOT-cav:observe:secret-host-config-read-buffer-6]´)
    // Caveat: The configured transport discriminant is lent to its acquisition validity predicate; the borrow ends when that predicate completes because byte validation requires a slice.
    // (´[ROOT-cav:observe:secret-host-config-read-field-0]´)
    // Caveat: The configured endpoint is lent to its acquisition validity predicate; the borrow ends when that predicate completes because byte validation requires a slice.
    // (´[ROOT-cav:observe:secret-host-config-read-field-1]´)
    // Caveat: The configured user is lent to its acquisition validity predicate; the borrow ends when that predicate completes because byte validation requires a slice.
    // (´[ROOT-cav:observe:secret-host-config-read-field-3]´)
    // Caveat: The configured database is lent to its acquisition validity predicate; the borrow ends when that predicate completes because byte validation requires a slice.
    // (´[ROOT-cav:observe:secret-host-config-read-field-5]´)
    // Caveat: The configured password is lent to its acquisition validity predicate; the borrow ends when that predicate completes because byte validation requires a slice.
    // (´[ROOT-cav:observe:secret-host-config-read-field-4]´)
    // Caveat: The parsed private port scalar is returned only for acquisition validation and immediately discarded; a nonzero u16 check requires an ordinary integer.
    // (´[ROOT-cav:observe:secret-host-config-read-port-1]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
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
                .read(&mut input.expose_storage(/* (´[ROOT-cav:observe:secret-host-config-read-buffer-1]´) */)[length..])
                .map_err(|_| Refusal::ConfigurationIo)?;
            if count == 0 {
                break;
            }
            length += count;
        }
        input.set_length(length)?;
        let mut cursor = Json {
            bytes: input.expose_bytes(/* (´[ROOT-cav:observe:secret-host-config-read-buffer-2]´) */),
            at: 0,
        };
        let mut data = Buffer::new();
        let mut fields: [Option<Range<usize>>; 6] = std::array::from_fn(|_| None);
        cursor.token(b'{')?;
        loop {
            let key = cursor.string()?;
            let index = match key.expose_bytes(/* (´[ROOT-cav:observe:secret-host-config-read-buffer-3]´) */) {
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
            if value.expose_bytes(/* (´[ROOT-cav:observe:secret-host-config-read-buffer-4]´) */).contains(&0) {
                return Err(Refusal::ConfigurationSyntax);
            }
            let start = data.len();
            data.append(value.expose_bytes(/* (´[ROOT-cav:observe:secret-host-config-read-buffer-6]´) */))?;
            fields[index] = Some(start..data.len());
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
        if !matches!(
            result.expose_field(/* (´[ROOT-cav:observe:secret-host-config-read-field-0]´) */ 0),
            b"unix" | b"tcp"
        ) || result
            .expose_field(/* (´[ROOT-cav:observe:secret-host-config-read-field-1]´) */ 1)
            .is_empty()
            || result
                .expose_field(/* (´[ROOT-cav:observe:secret-host-config-read-field-3]´) */ 3)
                .is_empty()
            || result
                .expose_field(/* (´[ROOT-cav:observe:secret-host-config-read-field-5]´) */ 5)
                .is_empty()
            || !result
                .expose_field(/* (´[ROOT-cav:observe:secret-host-config-read-field-4]´) */ 4)
                .iter()
                .all(|value| (0x20..=0x7e).contains(value))
        {
            return Err(Refusal::ConfigurationSyntax);
        }
        result.expose_port(/* (´[ROOT-cav:observe:secret-host-config-read-port-1]´) */)?;
        Ok(result)
    }
    // Caveat: The selected private configuration range is borrowed from its protected backing buffer and returned only through the denied expose_field accessor; the borrow ends with its separately labelled caller use because indexed selection requires a slice.
    // (´[ROOT-cav:observe:secret-host-config-field-buffer-1]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn expose_field(&self, index: usize) -> &[u8] {
        &self.data.expose_bytes(/* (´[ROOT-cav:observe:secret-host-config-field-buffer-1]´) */)[self.fields[index].clone()]
    }
    // Caveat: The selected configuration bytes are lent to UTF-8 validation and returned through denied expose_text; the borrow ends with its separately labelled caller use because from_utf8 requires a slice.
    // (´[ROOT-cav:observe:secret-host-config-text-field-1]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn expose_text(&self, index: usize) -> Result<&str, Refusal> {
        std::str::from_utf8(self.expose_field(/* (´[ROOT-cav:observe:secret-host-config-text-field-1]´) */ index))
            .map_err(|_| Refusal::ConfigurationSyntax)
    }
    // Caveat: The configured port text is lent to u16 parsing; its borrow ends at parse return and the ordinary scalar leaves only through denied expose_port because numeric parsing requires text.
    // (´[ROOT-cav:observe:secret-host-config-port-text-1]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn expose_port(&self) -> Result<u16, Refusal> {
        self.expose_text(/* (´[ROOT-cav:observe:secret-host-config-port-text-1]´) */ 2)?
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
    // Caveat: Private configuration text is borrowed only for UTF-8 validation before returning its carrier; the validator requires a slice.
    // (´[ROOT-cav:observe:secret-host-config-string-buffer-1]´)
    // Caveat: The Unicode encoder writes private configuration text into protected storage; its API requires a mutable byte array.
    // (´[ROOT-cav:observe:secret-host-config-string-1]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    fn string(&mut self) -> Result<Buffer, Refusal> {
        self.token(b'"')?;
        let mut value = Buffer::new();
        loop {
            let byte = *self.bytes.get(self.at).ok_or(Refusal::ConfigurationSyntax)?;
            self.at += 1;
            match byte {
                b'"' => {
                    std::str::from_utf8(value.expose_bytes(/* (´[ROOT-cav:observe:secret-host-config-string-buffer-1]´) */))
                        .map_err(|_| Refusal::ConfigurationSyntax)?;
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
                            value.append(
                                scalar
                                    .encode_utf8(
                                        encoded.expose_secret_mut(/* (´[ROOT-cav:observe:secret-host-config-string-1]´) */),
                                    )
                                    .as_bytes(),
                            )?;
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
    // Fixture-only secret boundary: This test creates its own isolated configuration.
    // Caveat: The fixture user bytes go only to the Unicode-decoding equality assertion until that comparison ends; the assertion requires a byte slice and accepts no deployment configuration.
    // (´[ROOT-cav:observe:secret-host-config-grammar-field-1]´)
    // Justified: The fixture assertion requires a borrowed byte slice for its exact decoding comparison.
    #[allow(clippy::disallowed_methods)]
    fn secret_json_grammar() {
        let input = br#"{"transport":"unix","endpoint":"/socket","port":"42100","user":"a\u0062\uD83D\uDE00","password":"safe","database":"db"}"#;
        let config = Configuration::acquire(Some("host-secured"), &mut input.as_slice()).unwrap();
        assert_eq!(
            config.expose_field(/* (´[ROOT-cav:observe:secret-host-config-grammar-field-1]´) */ 3),
            "ab😀".as_bytes()
        );
        for invalid in [
            br#"{"transport":"unix","endpoint":"/socket","port":"42100","user":"\uD800","password":"safe","database":"db"}"#.as_slice(),
            br#"{"transport":"unix","endpoint":"/socket","port":"42100","user":"a","user":"b","password":"safe","database":"db"}"#,
            br#"{"transport":"unix","endpoint":"/socket","port":"42100","user":"a","password":"safe","database":"db"} true"#,
        ] {
            assert_eq!(Configuration::acquire(Some("host-secured"), &mut &*invalid).unwrap_err(), Refusal::ConfigurationSyntax);
        }
    }
}
