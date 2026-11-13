//! Closed control schema envelope and exact text carriage.
//! (´[ROOT-dec:api:schema]´)

use pn_interchange::{Document, Theory, control_schema, satisfies};

#[path = "../examples/control_schema.rs"]
mod generator;

fn hex_to_bytes(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "whole hexadecimal bytes");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hexadecimal corpus byte"))
        .collect()
}

const SOURCE: &str = include_str!("../schema/control.graphql");
const ARTIFACT: &[u8] = include_bytes!("../schema/control.cbor");

fn corpus() -> Vec<serde_json::Value> {
    serde_json::from_str(include_str!("corpus/control-schema.json")).expect("committed independent corpus")
}

/// Claim: Conformance compares the input and rendered record with the authored fenced source byte for byte, including its final newline.
/// ´claim:documents:control-source-record-agreement´
/// ´test:integration:source-record-agreement´
#[test]
fn source_record_agreement() {
    for record in [
        include_str!("../../../docs/templates/adr/018-public-api.md.j2"),
        include_str!("../../../adr/018-public-api.md"),
    ] {
        let source = record
            .split_once("```graphql\n")
            .expect("one schema block")
            .1
            .split_once("```")
            .expect("closed fence")
            .0;
        assert_eq!(
            SOURCE.as_bytes(),
            source.as_bytes(),
            "schema input must equal the record's exact payload"
        );
    }
}

/// Claim: Conformance exercises the registered generator logic for argument refusals, publication and comparison in a fresh runtime directory, matching the committed artifact and independent bytes while retaining the complete source.
/// ´claim:documents:control-artifact-fixed-point´
/// ´test:integration:artifact-fixed-point´
#[test]
fn artifact_fixed_point() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("pn-control-schema-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&root).expect("fresh runtime directory");
    let directory = root.join("packages/interchange/schema");
    std::fs::create_dir_all(&directory).expect("schema directory");
    std::fs::write(directory.join("control.graphql"), SOURCE).expect("source fixture");
    let artifact = directory.join("control.cbor");
    for args in [
        vec![],
        vec![root.clone().into_os_string()],
        vec![root.clone().into_os_string(), "unknown".into()],
        vec![root.clone().into_os_string(), "write".into(), "extra".into()],
    ] {
        assert!(
            generator::run(args.into_iter()).is_err(),
            "generator refuses invalid arguments"
        );
        assert!(!artifact.exists(), "argument refusal publishes nothing");
    }
    let invoke = |mode: &str| generator::run([root.clone().into_os_string(), mode.into()].into_iter());
    assert!(invoke("check").is_err(), "comparison refuses an absent artifact");
    invoke("write").expect("registered publication logic");
    assert_eq!(
        std::fs::read(&artifact).expect("published artifact"),
        ARTIFACT,
        "registered generator publishes exact bytes"
    );
    invoke("check").expect("registered comparison logic");
    std::fs::write(&artifact, b"changed").expect("changed fixture");
    assert!(invoke("check").is_err(), "comparison refuses a changed artifact");
    assert_eq!(
        std::fs::read(&artifact).expect("refused artifact"),
        b"changed",
        "comparison does not repair bytes"
    );
    invoke("write").expect("restore publication");
    invoke("check").expect("restored comparison");
    std::fs::remove_dir_all(&root).expect("remove temporary publication");
    let expected = hex_to_bytes(corpus()[0]["bytes"].as_str().expect("first golden bytes"));
    assert_eq!(ARTIFACT, expected, "artifact equals independent route");
    assert_eq!(
        control_schema::encode(SOURCE).expect("admitted fixed role"),
        ARTIFACT,
        "artifact is a generator fixed point"
    );
    assert_eq!(
        control_schema::decode(ARTIFACT).expect("accepted artifact").as_bytes(),
        SOURCE.as_bytes(),
        "carriage retains source"
    );
}

/// Claim: Robustness compares each original corpus input with its named refusal and the closed theory, including other roles, editions, content shapes and malformed document bytes.
/// ´claim:documents:control-envelope-refusals´
/// ´test:integration:envelope-refusals´
#[test]
fn envelope_refusals() {
    let theory = Theory::parse(r#"e = {0 => "org.peer-network.test.api-control-schema", 1 => [1, 0, uint], 2 => tstr}"#)
        .expect("admitted theory");
    for row in corpus() {
        let bytes = hex_to_bytes(row["bytes"].as_str().expect("golden bytes"));
        let result = control_schema::decode(&bytes);
        let class = match &result {
            Ok(_) => "accepted",
            Err(control_schema::Refusal::Role) => "role",
            Err(control_schema::Refusal::Edition) => "edition",
            Err(control_schema::Refusal::Content) => "content",
            Err(control_schema::Refusal::Document(error)) => match error {
                pn_interchange::EnvelopeError::MissingKey { key: 0 } => "missing-role",
                pn_interchange::EnvelopeError::MissingKey { key: 1 } => "missing-edition",
                pn_interchange::EnvelopeError::NotAMap => "not-a-map",
                pn_interchange::EnvelopeError::NonIntegerKey { .. } => "non-integer-key",
                pn_interchange::EnvelopeError::NotCanonical(pn_interchange::DecodeError::DuplicateMapKey { .. }) => {
                    "duplicate-key"
                }
                pn_interchange::EnvelopeError::NotCanonical(pn_interchange::DecodeError::UnsortedMapKeys { .. }) => {
                    "unsorted-keys"
                }
                pn_interchange::EnvelopeError::NotCanonical(pn_interchange::DecodeError::IndefiniteLength { .. }) => {
                    "indefinite-length"
                }
                pn_interchange::EnvelopeError::BadLabelType => "label-type",
                pn_interchange::EnvelopeError::BadLabel(_) => "label",
                pn_interchange::EnvelopeError::BadVersion => "version",
                pn_interchange::EnvelopeError::NotCanonical(pn_interchange::DecodeError::TrailingBytes { .. }) => "trailing",
                pn_interchange::EnvelopeError::NotCanonical(pn_interchange::DecodeError::Truncated { .. }) => "truncated",
                pn_interchange::EnvelopeError::NotCanonical(pn_interchange::DecodeError::NonPreferredHead { .. }) => {
                    "nonpreferred"
                }
                pn_interchange::EnvelopeError::NotCanonical(pn_interchange::DecodeError::InvalidUtf8 { .. }) => "utf8",
                _ => "other-document",
            },
            Err(other) => panic!("unlisted control schema refusal: {other:?}"),
        };
        assert_eq!(
            class,
            row["expected"].as_str().expect("expected class"),
            "named refusal for {}",
            row["name"]
        );
        let closed = Document::from_canonical_bytes(&bytes).is_ok_and(|document| satisfies(&document, &theory).holds());
        assert_eq!(result.is_ok(), closed, "closed theory agrees for {}", row["name"]);
    }
}

/// Claim: Conformance retains every accepted corpus text byte, including control characters, distinct Unicode spellings, LF, CR, CRLF and absent or present terminal newlines.
/// ´claim:documents:control-source-retention´
/// ´test:integration:source-retention´
#[test]
fn source_retention() {
    for row in corpus().into_iter().filter(|row| row["expected"] == "accepted") {
        let bytes = hex_to_bytes(row["bytes"].as_str().expect("golden bytes"));
        let source = row["source"].as_str().expect("accepted source");
        assert_eq!(
            control_schema::decode(&bytes).expect("accepted test input").as_bytes(),
            source.as_bytes(),
            "exact retention for {}",
            row["name"]
        );
        if row["name"] != "patch" {
            assert_eq!(
                control_schema::encode(source).expect("fixed initial envelope"),
                bytes,
                "independent text framing for {}",
                row["name"]
            );
        }
    }
}
