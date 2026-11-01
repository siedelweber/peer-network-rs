//! Exact decimal arithmetic at the dataset projection boundary.

use std::collections::BTreeSet;
use std::fmt::Write;

use serde::Deserialize;
use serde_json::json;

use crate::Result;
use crate::envelope::Dataset;

pub(crate) const NAMESPACE: &str = "org.peer-network.numbers.registry";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    value: String,
    unit: String,
    display: String,
    magnitude: Option<i32>,
    exact_digits: usize,
    paper_key: Option<String>,
    paper_tag: Option<String>,
}

fn natural(text: &str) -> Result<String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("number: expected decimal digits".into());
    }
    let value = text.trim_start_matches('0');
    Ok(if value.is_empty() { "0" } else { value }.to_owned())
}

fn ratio(text: &str) -> Result<(bool, String, String)> {
    let negative = text.starts_with('-');
    let unsigned = text.strip_prefix(['-', '+']).unwrap_or(text);
    let (numerator, denominator) = if let Some((left, right)) = unsigned.split_once('/') {
        (natural(left)?, natural(right)?)
    } else if let Some((left, right)) = unsigned.split_once('.') {
        natural(left)?;
        natural(right)?;
        (natural(&format!("{left}{right}"))?, format!("1{}", "0".repeat(right.len())))
    } else {
        (natural(unsigned)?, "1".to_owned())
    };
    if denominator == "0" {
        return Err("number: denominator must be positive".into());
    }
    Ok((negative && numerator != "0", numerator, denominator))
}

fn compare(left: &str, right: &str) -> std::cmp::Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

// Inputs are normalized natural numbers, and left is at least right.
fn subtract(left: &str, right: &str) -> String {
    let mut borrow = 0_i16;
    let mut other = right.bytes().rev();
    let mut digits = Vec::with_capacity(left.len());
    for byte in left.bytes().rev() {
        let difference = i16::from(byte - b'0') - i16::from(other.next().unwrap_or(b'0') - b'0') - borrow;
        borrow = i16::from(difference < 0);
        digits.push(char::from(b'0' + u8::try_from(difference.rem_euclid(10)).unwrap_or_default()));
    }
    let result: String = digits.into_iter().rev().collect();
    let trimmed = result.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn increment(value: &str) -> String {
    let mut carry = true;
    let mut digits = Vec::with_capacity(value.len() + 1);
    for byte in value.bytes().rev() {
        let digit = byte - b'0' + u8::from(carry);
        carry = digit == 10;
        digits.push(char::from(b'0' + digit % 10));
    }
    if carry {
        digits.push('1');
    }
    digits.into_iter().rev().collect()
}

fn divide(numerator: &str, denominator: &str) -> (String, String) {
    let mut remainder = String::new();
    let mut quotient = String::new();
    for digit in numerator.chars() {
        if remainder == "0" {
            remainder.clear();
        }
        remainder.push(digit);
        let mut count = 0;
        while !compare(&remainder, denominator).is_lt() {
            remainder = subtract(&remainder, denominator);
            count += 1;
        }
        quotient.push(char::from(b'0' + count));
    }
    let trimmed = quotient.trim_start_matches('0');
    (
        if trimmed.is_empty() {
            "0".to_owned()
        } else {
            trimmed.to_owned()
        },
        remainder,
    )
}

fn group(text: &str) -> String {
    let mut result = String::new();
    let mut fractional = false;
    let mut remaining = text.bytes().take_while(u8::is_ascii_digit).count();
    let mut position = 0;
    for (index, character) in text.char_indices() {
        if character.is_ascii_digit() {
            if position > 0 && (if fractional { position % 3 == 0 } else { remaining % 3 == 0 }) {
                result.push('\u{202f}');
            }
            result.push(character);
            position += 1;
            remaining = remaining.saturating_sub(1);
        } else {
            result.push(character);
            fractional = character == '.';
            position = 0;
            remaining = text[index + character.len_utf8()..]
                .bytes()
                .take_while(u8::is_ascii_digit)
                .count();
        }
    }
    result
}

fn rounded(value: &str, magnitude: i32, rule: &str) -> Result<(String, bool)> {
    let (negative, mut numerator, mut denominator) = ratio(value)?;
    let places = usize::try_from(magnitude.unsigned_abs())?;
    if magnitude < 0 {
        numerator.push_str(&"0".repeat(places));
        numerator = natural(&numerator)?;
    } else {
        denominator.push_str(&"0".repeat(places));
    }
    let (mut quotient, remainder) = divide(&numerator, &denominator);
    let exact = remainder == "0";
    // r >= d-r is exactly the half comparison, without machine-size arithmetic.
    let increase = match rule {
        "floor" => negative && !exact,
        "ceiling" => !negative && !exact,
        _ => !compare(&remainder, &subtract(&denominator, &remainder)).is_lt(),
    };
    if increase {
        quotient = increment(&quotient);
    }
    let nonzero = quotient != "0";
    if magnitude < 0 {
        if quotient.len() <= places {
            quotient = format!("{}{}", "0".repeat(places + 1 - quotient.len()), quotient);
        }
        quotient.insert(quotient.len() - places, '.');
    } else if nonzero {
        quotient.push_str(&"0".repeat(places));
    }
    if negative && nonzero {
        quotient.insert(0, '-');
    }
    Ok((group(&quotient), exact))
}

fn validate(entry: &Entry) -> Result<()> {
    let atoms: Vec<_> = entry.id.split(':').collect();
    if atoms.len() != 3
        || atoms.iter().enumerate().any(|(index, atom)| {
            (index < 2 && atom.contains('-'))
                || atom
                    .split('-')
                    .any(|word| word.is_empty() || !word.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
        })
    {
        return Err(format!("number: invalid id {}", entry.id).into());
    }
    if !["Work", "bytes", "seconds", "dimensionless"].contains(&entry.unit.as_str()) {
        return Err(format!("number: invalid unit for {}", entry.id).into());
    }
    if entry.value.len() > 16384 || entry.exact_digits > 32768 || entry.magnitude.is_some_and(|value| value.unsigned_abs() > 1024)
    {
        return Err(format!("number: display bound exceeded for {}", entry.id).into());
    }
    ratio(&entry.value)?;
    match (&entry.paper_key, &entry.paper_tag) {
        (None, None) => {}
        (Some(key), Some(tag)) if !key.is_empty() && !tag.is_empty() => {}
        _ => return Err(format!("number: incomplete published authority for {}", entry.id).into()),
    }
    Ok(())
}

#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "numbers::project"
    ),
    ret
)]
pub(super) fn project(dataset: &mut Dataset) -> Result<()> {
    if dataset.namespace != NAMESPACE {
        return Ok(());
    }
    let mut ids = BTreeSet::new();
    for row in &mut dataset.rows {
        let entry: Entry = serde_json::from_value(serde_json::to_value(&row)?)?;
        validate(&entry)?;
        if !ids.insert(entry.id.clone()) {
            return Err(format!("number: duplicate id {}", entry.id).into());
        }
        let exact = group(&entry.value);
        let (display, is_exact) = match (entry.display.as_str(), entry.magnitude) {
            ("exact", None) => (exact.clone(), true),
            ("rounded" | "floor" | "ceiling", Some(magnitude)) => rounded(&entry.value, magnitude, &entry.display)?,
            _ => return Err(format!("number: invalid display rule for {}", entry.id).into()),
        };
        let digits = entry.value.bytes().filter(u8::is_ascii_digit).count();
        if entry.display == "exact" && digits > entry.exact_digits {
            return Err(format!("number: exact display exceeds budget for {}", entry.id).into());
        }
        row.insert("num".to_owned(), json!(display));
        row.insert("num_exact".to_owned(), json!(is_exact));
        let relation = if is_exact {
            "="
        } else {
            match entry.display.as_str() {
                "floor" => "≥",
                "ceiling" => "≤",
                _ => "≈",
            }
        };
        row.insert("num_relation".to_owned(), json!(relation));
        if digits <= entry.exact_digits {
            row.insert("exact".to_owned(), json!(exact));
            row.insert("exact_exact".to_owned(), json!(true));
            row.insert("exact_relation".to_owned(), json!("="));
        }
    }
    Ok(())
}

fn rust_integer_literal(value: usize) -> String {
    let digits = value.to_string();
    let mut literal = String::new();
    for (index, digit) in digits.char_indices() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            literal.push('_');
        }
        literal.push(digit);
    }
    literal
}

#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "numbers::pins"
    ),
    ret
)]
pub(super) fn pins(dataset: &Dataset, input: &str) -> Result<String> {
    let mut variants = BTreeSet::new();
    let mut declarations = String::new();
    let mut arms = String::new();
    for row in &dataset.rows {
        let id = row.get("id").and_then(serde_json::Value::as_str).ok_or("number: absent id")?;
        let variant: String = id
            .strip_prefix("num:")
            .unwrap_or(id)
            .split([':', '-'])
            .map(|word| {
                let mut letters = word.chars();
                letters
                    .next()
                    .map_or_else(String::new, |first| first.to_ascii_uppercase().to_string() + letters.as_str())
            })
            .collect();
        if !variants.insert(variant.clone()) {
            return Err(format!("number: ambiguous Rust id {id}").into());
        }
        let declaration = format!("id = \"{id}\"");
        let start = input
            .find(&declaration)
            .ok_or("number: typed ids require canonical input fields")?;
        let rest = &input[start + declaration.len()..];
        let prefix = "value = \"";
        let offset = rest.find(prefix).ok_or("number: absent canonical value field")?;
        let begin = start + declaration.len() + offset + prefix.len();
        let value = row
            .get("value")
            .and_then(serde_json::Value::as_str)
            .ok_or("number: absent value")?;
        let end = begin + value.len();
        if input.get(begin..end) != Some(value) || !input[end..].starts_with('"') {
            return Err(format!("number: noncanonical value field for {id}").into());
        }
        writeln!(declarations, "    /// Registry id: {id}.\n    {variant},")?;
        writeln!(arms, "    ({}, {}),", rust_integer_literal(begin), rust_integer_literal(end))?;
    }
    let count = dataset.rows.len();
    Ok(format!(
        "// Generated by the documents input projection. Values remain in the registry.\n\n/// A declared numeric pin; removing an id removes its variant.\n#[derive(Clone, Copy, Debug)]\npub enum NumberId {{\n{declarations}}}\n\nconst OFFSETS: [(usize, usize); {count}] = [\n{arms}];\n\nimpl NumberId {{\n    /// Read the full-precision value from the committed registry.\n    ///\n    /// # Panics\n    /// Panics only if generated offsets differ from the registry, which the fixed-point gate refuses.\n    #[must_use]\n    pub fn value(self) -> &'static str {{\n        let (start, end) = OFFSETS[self as usize];\n        include_str!(\"../../../docs/inputs/numbers.toml\")\n            .get(start..end)\n            .expect(\"registry offsets must be regenerated\")\n    }}\n\n    /// Read an unsigned integer pin without a second literal.\n    ///\n    /// # Panics\n    /// Panics only if the selected pin is not an unsigned machine integer, which a correctly typed consumer selection cannot arrange.\n    #[must_use]\n    pub fn integer(self) -> u64 {{\n        self.value().parse().expect(\"registry pin must be an unsigned integer\")\n    }}\n}}\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::rust_integer_literal;

    /// Rust pin offsets retain their integer value with underscore groups across digit boundaries.
    /// (´claim:render:number-forms-are-exactly-projected´)
    /// ´test:unit:rust-integer-boundaries´
    #[test]
    fn rust_integer_boundaries() {
        for (value, expected) in [
            (0, "0"),
            (999, "999"),
            (1_000, "1_000"),
            (9_999, "9_999"),
            (10_000, "10_000"),
            (99_999, "99_999"),
            (100_000, "100_000"),
            (1_234_567, "1_234_567"),
        ] {
            assert_eq!(rust_integer_literal(value), expected);
        }
    }
}
