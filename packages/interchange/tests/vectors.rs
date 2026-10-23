//! The RFC 8949 vector corpus, driven row by row.
//!
//! The corpus was assembled from RFC 8949's own text during the design
//! phase and mechanically re-verified; each row carries the sentence of
//! the standard it stands for. A canonical row must decode, re-encode
//! byte-identically, and round-trip; a refusal row must be refused with a
//! located error, and with the named variant wherever the row's reason
//! fixes one.

mod support;

use pn_interchange::{DecodeError, Value};
use support::{hex_to_bytes, offset_of, variant_name};

const CORPUS: &str = include_str!("corpus/rfc8949-vectors.json");

/// The seeded set of the design's test plan: 67 canonical rows and 26
/// refusals. The counts are asserted so that a corpus silently losing rows
/// is a failure rather than a smaller test run.
const CANONICAL_ROWS: usize = 67;
const REFUSAL_ROWS: usize = 26;

struct Row {
    hex: String,
    diagnostic: String,
    valid_canonical: bool,
    reason: String,
}

fn corpus() -> Vec<Row> {
    let parsed: serde_json::Value = serde_json::from_str(CORPUS).expect("the corpus is JSON");
    let rows = parsed.as_array().expect("the corpus is an array");
    rows.iter()
        .map(|row| {
            let field = |name: &str| {
                row.get(name)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_else(|| panic!("row {row} has no string field {name}"))
                    .to_owned()
            };
            Row {
                hex: field("hex"),
                diagnostic: field("diagnostic"),
                valid_canonical: row
                    .get("valid_canonical")
                    .and_then(serde_json::Value::as_bool)
                    .expect("every row states whether it is canonical"),
                reason: field("reason"),
            }
        })
        .collect()
}

/// Claim: The vector corpus still holds the 67 canonical rows and 26 refusals it was seeded with.
/// ´claim:vectors:the-corpus-keeps-its-seeded-counts´
/// ´test:integration:corpus-has-the-seeded-shape´
#[test]
fn corpus_has_the_seeded_shape() {
    let rows = corpus();
    let canonical = rows.iter().filter(|row| row.valid_canonical).count();
    assert_eq!(canonical, CANONICAL_ROWS);
    assert_eq!(rows.len() - canonical, REFUSAL_ROWS);
}

/// Claim: Every canonical vector of the standard decodes, re-encodes to the same bytes, and round-trips.
/// ´claim:vectors:a-canonical-vector-re-encodes-to-its-own-bytes´
/// ´test:integration:canonical-rows-decode-reencode-identically-and-roundtrip´
#[test]
fn canonical_rows_decode_reencode_identically_and_roundtrip() {
    drive("canonical", true, CANONICAL_ROWS, |row| {
        let bytes = hex_to_bytes(&row.hex);
        let context = &row.diagnostic;

        let value = Value::from_canonical_bytes(&bytes).unwrap_or_else(|e| panic!("{context} ({}) was refused: {e}", row.hex));

        let reencoded = value.to_canonical_bytes();
        assert_eq!(reencoded, bytes, "{context} did not re-encode identically");
        assert_eq!(value.canonical_len(), bytes.len(), "{context} mismeasured its own name");

        let again = Value::from_canonical_bytes(&reencoded).unwrap_or_else(|e| panic!("{context} did not round-trip: {e}"));
        assert_eq!(again, value, "{context} decoded to a different structure");

        let (prefix_value, consumed) =
            Value::from_canonical_prefix(&bytes).unwrap_or_else(|e| panic!("{context} was refused as a prefix: {e}"));
        assert_eq!((prefix_value, consumed), (value, bytes.len()));
    });
}

/// Claim: Every refusal vector is refused inside its own bytes and as the variant its reason names.
/// ´claim:vectors:a-refusal-vector-is-refused-where-it-stands´
/// ´test:integration:refusal-rows-are-refused-with-a-located-error´
#[test]
fn refusal_rows_are_refused_with_a_located_error() {
    drive("refusal", false, REFUSAL_ROWS, |row| {
        let bytes = hex_to_bytes(&row.hex);
        let context = &row.diagnostic;

        let error = match Value::from_canonical_bytes(&bytes) {
            Ok(value) => panic!("{context} ({}) was accepted as {value:?}", row.hex),
            Err(error) => error,
        };

        assert!(
            offset_of(&error) <= bytes.len(),
            "{context} was refused at an offset outside the input: {error}"
        );

        match expected_refusal(&bytes, &row.reason) {
            Expected::Exactly(variant) => assert_eq!(
                variant_name(&error),
                variant,
                "{context} was refused as {error}, not as {variant}"
            ),
            Expected::WellFormedness => assert!(
                matches!(error, DecodeError::IllFormed { .. } | DecodeError::Truncated { .. }),
                "{context} claims to be ill-formed but was refused as {error}"
            ),
        }
    });
}

enum Expected {
    /// The row's reason fixes one variant.
    Exactly(&'static str),
    /// The row's reason says only that the bytes are not well-formed,
    /// which the crate reports as an ill-formed head or as truncation
    /// depending on which the input ran into first.
    WellFormedness,
}

/// Which refusal a row's own reason calls for.
///
/// The reasons are prose written against the standard, so the clauses are
/// ordered: a reason may name more than one property, and the most
/// specific naming wins.
///
/// An indefinite-length head is refused where it stands, so such a row is
/// classified by the byte the decoder meets rather than by the deeper defect
/// its reason goes on to describe.
fn expected_refusal(bytes: &[u8], reason: &str) -> Expected {
    if reason.contains("map keys not in bytewise-lexicographic order") {
        return Expected::Exactly("UnsortedMapKeys");
    }
    if reason.contains("duplicate map key") {
        return Expected::Exactly("DuplicateMapKey");
    }
    if reason.contains("not the shortest form") {
        return Expected::Exactly("NonShortestFloat");
    }
    if reason.contains("but not canonical") {
        return Expected::Exactly("NonPreferredHead");
    }
    if matches!(bytes.first(), Some(0x5f | 0x7f | 0x9f | 0xbf)) {
        return Expected::Exactly("IndefiniteLength");
    }
    assert!(
        reason.contains("well-formed"),
        "a refusal reason naming no property this test knows: {reason}"
    );
    Expected::WellFormedness
}

fn drive(suite: &str, valid: bool, expected: usize, predicate: impl Fn(&Row) + std::panic::RefUnwindSafe) {
    let rows = corpus();
    let cases: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.valid_canonical == valid)
        .map(|(index, row)| pn_testkit::Case {
            id: format!("row-{index}"),
            input: row,
        })
        .collect();
    assert_eq!(cases.len(), expected);
    let results = pn_testkit::run(suite, "rfc8949", &cases, &["pn-interchange-rust"], |_, row| {
        std::panic::catch_unwind(|| predicate(row)).map_err(|_| "vector predicate failed")
    })
    .expect("the committed corpus has distinct row identifiers");
    if let Ok(directory) = std::env::var("PN_CONTRACT_RESULTS") {
        let source = std::env::var("PN_HARNESS_SOURCE").expect("runner source");
        let configuration = std::env::var("PN_HARNESS_CONFIGURATION").expect("runner configuration");
        let utc = std::env::var("PN_HARNESS_UTC").expect("runner UTC instant");
        let records: Vec<_> = results
            .iter()
            .map(|result| {
                serde_json::json!({
                    "operation": format!("contract::rfc8949::{suite}::{}", result.case),
                    "implementation": result.implementation, "contract_edition": result.edition,
                    "outcome": if result.outcome.is_ok() { "passed" } else { "failed" },
                    "duration_ms": result.elapsed.as_secs_f64() * 1000.0,
                    "source": source, "configuration": configuration, "utc": utc,
                    "owner": "interchange conformance implementer"
                })
            })
            .collect();
        let path = std::path::Path::new(&directory).join(format!("rfc8949-{suite}.json"));
        std::fs::write(path, serde_json::to_vec(&records).expect("result records serialize")).expect("case results persist");
    }
    assert_eq!(results.len(), expected);
    assert!(
        results.iter().all(|result| result.outcome.is_ok()),
        "a corpus predicate failed"
    );
}
