//! Consistency checks for public, supplied installation evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use serde::de::value::MapAccessDeserializer;
use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

/// A conditional verdict over supplied public facts, not an installation claim.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Verdict {
    /// The selected evidence predicate.
    pub check: String,
    /// The candidate commit named by the evidence.
    pub commit: String,
    /// Whether the supplied facts satisfy that predicate.
    pub facts_consistent: bool,
}

/// A closed refusal class for evidence admission or a selected predicate.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The evidence file could not be admitted as the selected closed shape.
    EvidenceInvalid(String),
    /// A supplied tag fact failed its consistency predicate.
    TagRefused(String),
    /// A supplied source or build fact failed its consistency predicate.
    SourcesRefused(String),
    /// A supplied placement fact failed its consistency predicate.
    PlacementRefused(String),
}

impl fmt::Display for Refusal {
    /// Justified: this trait adapter consumes only the public evidence boundary and adds no independent effect or private payload.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EvidenceInvalid(field) => write!(formatter, "EvidenceInvalid: {field}"),
            Self::TagRefused(field) => write!(formatter, "TagRefused: {field}"),
            Self::SourcesRefused(field) => write!(formatter, "SourcesRefused: {field}"),
            Self::PlacementRefused(field) => write!(formatter, "PlacementRefused: {field}"),
        }
    }
}

impl std::error::Error for Refusal {}

#[derive(Debug)]
struct RequiredNullable<T>(Option<T>);

impl<'de, T: DeserializeOwned> Deserialize<'de> for RequiredNullable<T> {
    /// Justified: this trait adapter consumes only the public evidence boundary and adds no independent effect or private payload.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.is_null() {
            Ok(Self(None))
        } else {
            T::deserialize(value).map(Some).map(Self).map_err(serde::de::Error::custom)
        }
    }
}

impl RequiredNullable<bool> {
    fn established(&self) -> bool {
        self.0 == Some(true)
    }
}

struct MapOnly<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    /// Justified: the closed evidence shape admits objects, never positional struct sequences.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        map_only(deserializer).map(Self)
    }
}

fn map_only<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JSON object")
        }

        fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
}

fn map_only_rows<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<SourceRow>, D::Error> {
    Vec::<MapOnly<SourceRow>>::deserialize(deserializer).map(|rows| rows.into_iter().map(|row| row.0).collect())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(bound(deserialize = "F: Deserialize<'de>"))]
struct Envelope<F> {
    schema: u64,
    check: String,
    commit: String,
    #[serde(deserialize_with = "map_only")]
    facts: F,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TagFacts {
    tag: String,
    annotated: RequiredNullable<bool>,
    publisher_key: String,
    verified_key: RequiredNullable<String>,
    signature_valid: RequiredNullable<bool>,
    resolved_commit: String,
    public_main: String,
    ancestor: RequiredNullable<bool>,
}

enum SourceKind {
    Registry,
    Git,
    Path,
    Patch,
    Notice,
    Compiler,
    Component,
    Selection,
}

impl<'de> Deserialize<'de> for SourceKind {
    /// Justified: a source kind is one of the closed string names, never an enum-shaped object.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "registry" => Ok(Self::Registry),
            "git" => Ok(Self::Git),
            "path" => Ok(Self::Path),
            "patch" => Ok(Self::Patch),
            "notice" => Ok(Self::Notice),
            "compiler" => Ok(Self::Compiler),
            "component" => Ok(Self::Component),
            "selection" => Ok(Self::Selection),
            _ => Err(serde::de::Error::unknown_variant(
                &value,
                &[
                    "registry",
                    "git",
                    "path",
                    "patch",
                    "notice",
                    "compiler",
                    "component",
                    "selection",
                ],
            )),
        }
    }
}

impl SourceKind {
    fn text(&self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Git => "git",
            Self::Path => "path",
            Self::Patch => "patch",
            Self::Notice => "notice",
            Self::Compiler => "compiler",
            Self::Component => "component",
            Self::Selection => "selection",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRow {
    kind: SourceKind,
    identity: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcesFacts {
    #[serde(deserialize_with = "map_only_rows")]
    expected: Vec<SourceRow>,
    #[serde(deserialize_with = "map_only_rows")]
    captured: Vec<SourceRow>,
    fetch_checksums_verified: RequiredNullable<bool>,
    fetch_without_dependency_execution: RequiredNullable<bool>,
    build_network_denied: RequiredNullable<bool>,
    no_build_acquisition: RequiredNullable<bool>,
    source_bytes_unchanged: RequiredNullable<bool>,
    release_build_succeeded: RequiredNullable<bool>,
    package_scoped: RequiredNullable<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlacementFacts {
    binary_sha256: String,
    provenance_binary_sha256: String,
    directory_binary_sha256: String,
    administrator_owned: RequiredNullable<bool>,
    binary_read_only: RequiredNullable<bool>,
    provenance_read_only: RequiredNullable<bool>,
    directory_not_replaceable: RequiredNullable<bool>,
    full_path_selected: RequiredNullable<bool>,
    provenance_same_build: RequiredNullable<bool>,
    never_rewritten: RequiredNullable<bool>,
    identities_separate: RequiredNullable<bool>,
}

fn identity(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn commit_id(value: &str) -> bool {
    lowercase_hex(value, 40) || lowercase_hex(value, 64)
}

fn admitted<F>(bytes: &[u8], selected: &str) -> Result<Envelope<F>, Refusal>
where
    F: for<'de> Deserialize<'de>,
{
    let envelope: MapOnly<Envelope<F>> =
        serde_json::from_slice(bytes).map_err(|error| Refusal::EvidenceInvalid(error.to_string()))?;
    let envelope = envelope.0;
    if envelope.schema != 1 {
        return Err(Refusal::EvidenceInvalid("schema".into()));
    }
    if envelope.check != selected {
        return Err(Refusal::EvidenceInvalid("check".into()));
    }
    if !commit_id(&envelope.commit) {
        return Err(Refusal::EvidenceInvalid("commit".into()));
    }
    Ok(envelope)
}

fn tag_shape(commit: &str, facts: &TagFacts) -> Result<(), Refusal> {
    if !identity(&facts.publisher_key) {
        return Err(Refusal::EvidenceInvalid("publisher_key".into()));
    }
    if facts.verified_key.0.as_deref().is_some_and(|value| !identity(value)) {
        return Err(Refusal::EvidenceInvalid("verified_key".into()));
    }
    if !commit_id(&facts.resolved_commit) || facts.resolved_commit.len() != commit.len() {
        return Err(Refusal::EvidenceInvalid("resolved_commit".into()));
    }
    if !commit_id(&facts.public_main) || facts.public_main.len() != commit.len() {
        return Err(Refusal::EvidenceInvalid("public_main".into()));
    }
    Ok(())
}

fn tag_form(tag: &str) -> bool {
    let Some(number) = tag.strip_prefix("deploy/test-") else {
        return false;
    };
    let Some((&first, rest)) = number.as_bytes().split_first() else {
        return false;
    };
    (b'1'..=b'9').contains(&first) && rest.iter().all(u8::is_ascii_digit)
}

fn tag(commit: &str, facts: &TagFacts) -> Result<(), Refusal> {
    if !tag_form(&facts.tag) {
        return Err(Refusal::TagRefused("tag".into()));
    }
    if !facts.annotated.established() {
        return Err(Refusal::TagRefused("annotated".into()));
    }
    if facts.verified_key.0.as_deref() != Some(facts.publisher_key.as_str()) {
        return Err(Refusal::TagRefused("verified_key".into()));
    }
    if !facts.signature_valid.established() {
        return Err(Refusal::TagRefused("signature_valid".into()));
    }
    if facts.resolved_commit != commit {
        return Err(Refusal::TagRefused("resolved_commit".into()));
    }
    if !facts.ancestor.established() {
        return Err(Refusal::TagRefused("ancestor".into()));
    }
    Ok(())
}

fn source_shape(rows: &[SourceRow], side: &str) -> Result<(), Refusal> {
    for row in rows {
        if !identity(&row.identity) || row.identity.starts_with('/') {
            return Err(Refusal::EvidenceInvalid(format!("{side}.identity")));
        }
        if !lowercase_hex(&row.sha256, 64) {
            return Err(Refusal::EvidenceInvalid(format!("{side}.sha256")));
        }
    }
    Ok(())
}

fn source_map(rows: &[SourceRow], side: &str) -> Result<BTreeMap<(String, String), String>, Refusal> {
    let mut found = BTreeMap::new();
    for row in rows {
        let key = (row.kind.text().to_owned(), row.identity.clone());
        if found.insert(key.clone(), row.sha256.clone()).is_some() {
            return Err(Refusal::SourcesRefused(format!("{side}.{}:{}", key.0, key.1)));
        }
    }
    Ok(found)
}

fn sources(facts: &SourcesFacts) -> Result<(), Refusal> {
    if facts.expected.is_empty() {
        return Err(Refusal::SourcesRefused("expected".into()));
    }
    if facts.captured.is_empty() {
        return Err(Refusal::SourcesRefused("captured".into()));
    }
    let expected = source_map(&facts.expected, "expected")?;
    let captured = source_map(&facts.captured, "captured")?;
    let keys: BTreeSet<_> = expected.keys().chain(captured.keys()).collect();
    for key in keys {
        if expected.get(key) != captured.get(key) {
            return Err(Refusal::SourcesRefused(format!("{}:{}", key.0, key.1)));
        }
    }
    for (name, assertion) in [
        ("fetch_checksums_verified", &facts.fetch_checksums_verified),
        (
            "fetch_without_dependency_execution",
            &facts.fetch_without_dependency_execution,
        ),
        ("build_network_denied", &facts.build_network_denied),
        ("no_build_acquisition", &facts.no_build_acquisition),
        ("source_bytes_unchanged", &facts.source_bytes_unchanged),
        ("release_build_succeeded", &facts.release_build_succeeded),
        ("package_scoped", &facts.package_scoped),
    ] {
        if !assertion.established() {
            return Err(Refusal::SourcesRefused(name.into()));
        }
    }
    Ok(())
}

fn placement_shape(facts: &PlacementFacts) -> Result<(), Refusal> {
    for (name, digest) in [
        ("binary_sha256", &facts.binary_sha256),
        ("provenance_binary_sha256", &facts.provenance_binary_sha256),
        ("directory_binary_sha256", &facts.directory_binary_sha256),
    ] {
        if !lowercase_hex(digest, 64) {
            return Err(Refusal::EvidenceInvalid(name.into()));
        }
    }
    Ok(())
}

fn placement(facts: &PlacementFacts) -> Result<(), Refusal> {
    if facts.binary_sha256 != facts.provenance_binary_sha256 {
        return Err(Refusal::PlacementRefused("provenance_binary_sha256".into()));
    }
    if facts.binary_sha256 != facts.directory_binary_sha256 {
        return Err(Refusal::PlacementRefused("directory_binary_sha256".into()));
    }
    for (name, assertion) in [
        ("administrator_owned", &facts.administrator_owned),
        ("binary_read_only", &facts.binary_read_only),
        ("provenance_read_only", &facts.provenance_read_only),
        ("directory_not_replaceable", &facts.directory_not_replaceable),
        ("full_path_selected", &facts.full_path_selected),
        ("provenance_same_build", &facts.provenance_same_build),
        ("never_rewritten", &facts.never_rewritten),
        ("identities_separate", &facts.identities_separate),
    ] {
        if !assertion.established() {
            return Err(Refusal::PlacementRefused(name.into()));
        }
    }
    Ok(())
}

/// Evaluate one selected predicate from one closed public evidence object.
///
/// # Errors
/// Refuses an invalid evidence shape or the first negative fact of the selected predicate.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "installation::evaluate"
    ),
    ret
)]
pub fn evaluate(selected: &str, bytes: &[u8]) -> Result<Verdict, Refusal> {
    let commit = match selected {
        "tag" => {
            let envelope: Envelope<TagFacts> = admitted(bytes, selected)?;
            tag_shape(&envelope.commit, &envelope.facts)?;
            tag(&envelope.commit, &envelope.facts)?;
            envelope.commit
        }
        "sources" => {
            let envelope: Envelope<SourcesFacts> = admitted(bytes, selected)?;
            source_shape(&envelope.facts.expected, "expected")?;
            source_shape(&envelope.facts.captured, "captured")?;
            sources(&envelope.facts)?;
            envelope.commit
        }
        "placement" => {
            let envelope: Envelope<PlacementFacts> = admitted(bytes, selected)?;
            placement_shape(&envelope.facts)?;
            placement(&envelope.facts)?;
            envelope.commit
        }
        _ => return Err(Refusal::EvidenceInvalid("check".into())),
    };
    Ok(Verdict {
        check: selected.into(),
        commit,
        facts_consistent: true,
    })
}

/// Read one public evidence file and evaluate the selected predicate.
///
/// A relative file is resolved against the repository root; no installation is inspected.
///
/// # Errors
/// Refuses unreadable evidence, an invalid shape, or the first negative selected fact.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "installation::check_file"
    ),
    ret
)]
pub fn check_file(root: &Path, selected: &str, facts: &Path) -> Result<Verdict, Refusal> {
    let path = root.join(facts);
    let bytes = fs::read(path).map_err(|error| Refusal::EvidenceInvalid(format!("facts: {}", error.kind())))?;
    evaluate(selected, &bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};

    use super::{Refusal, check_file, evaluate};

    fn commit() -> String {
        "a".repeat(40)
    }

    fn digest() -> String {
        "b".repeat(64)
    }

    fn encoded(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    fn tag_facts() -> Value {
        json!({
            "schema": 1,
            "check": "tag",
            "commit": commit(),
            "facts": {
                "tag": "deploy/test-12",
                "annotated": true,
                "publisher_key": "publisher-A",
                "verified_key": "publisher-A",
                "signature_valid": true,
                "resolved_commit": commit(),
                "public_main": commit(),
                "ancestor": true
            }
        })
    }

    fn source_row(kind: &str, identity: &str) -> Value {
        json!({"kind": kind, "identity": identity, "sha256": digest()})
    }

    fn source_facts() -> Value {
        let rows = vec![source_row("registry", "crate/a"), source_row("notice", "NOTICE")];
        json!({
            "schema": 1,
            "check": "sources",
            "commit": commit(),
            "facts": {
                "expected": rows,
                "captured": rows,
                "fetch_checksums_verified": true,
                "fetch_without_dependency_execution": true,
                "build_network_denied": true,
                "no_build_acquisition": true,
                "source_bytes_unchanged": true,
                "release_build_succeeded": true,
                "package_scoped": true
            }
        })
    }

    fn placement_facts() -> Value {
        json!({
            "schema": 1,
            "check": "placement",
            "commit": commit(),
            "facts": {
                "binary_sha256": digest(),
                "provenance_binary_sha256": digest(),
                "directory_binary_sha256": digest(),
                "administrator_owned": true,
                "binary_read_only": true,
                "provenance_read_only": true,
                "directory_not_replaceable": true,
                "full_path_selected": true,
                "provenance_same_build": true,
                "never_rewritten": true,
                "identities_separate": true
            }
        })
    }

    fn refusal(check: &str, value: &Value) -> Refusal {
        evaluate(check, &encoded(value)).unwrap_err()
    }

    /// Claim: Supplied tag facts admit only the selected key, resolved commit and established ancestry with exact tag form.
    /// ´claim:installation:bad-tag´
    /// ´test:unit:installation-bad-tag´
    #[test]
    fn installation_bad_tag() {
        let admitted = tag_facts();
        assert!(evaluate("tag", &encoded(&admitted)).is_ok());
        for bad in [
            "release/test-12",
            "deploy/test-0",
            "deploy/test-012",
            "deploy/test-12x",
            "deploy/test-",
            "deploy/test-１２",
        ] {
            let mut evidence = admitted.clone();
            evidence["facts"]["tag"] = bad.into();
            assert_eq!(refusal("tag", &evidence), Refusal::TagRefused("tag".into()));
        }
        for (field, value, named) in [
            ("annotated", json!(false), "annotated"),
            ("annotated", Value::Null, "annotated"),
            ("verified_key", json!("publisher-B"), "verified_key"),
            ("verified_key", Value::Null, "verified_key"),
            ("signature_valid", json!(false), "signature_valid"),
            ("signature_valid", Value::Null, "signature_valid"),
            ("resolved_commit", json!("c".repeat(40)), "resolved_commit"),
            ("ancestor", json!(false), "ancestor"),
            ("ancestor", Value::Null, "ancestor"),
        ] {
            let mut evidence = admitted.clone();
            evidence["facts"][field] = value;
            assert_eq!(refusal("tag", &evidence), Refusal::TagRefused(named.into()));
        }
        let mut first = admitted;
        first["facts"]["tag"] = "deploy/test-0".into();
        first["facts"]["annotated"] = false.into();
        assert_eq!(refusal("tag", &first), Refusal::TagRefused("tag".into()));
    }

    /// Claim: Supplied source evidence requires nonempty unique exact membership and digest agreement before every execution assertion.
    /// ´claim:installation:missing-source´
    /// ´test:unit:installation-missing-source´
    #[test]
    fn installation_missing_source() {
        let admitted = source_facts();
        assert!(evaluate("sources", &encoded(&admitted)).is_ok());
        for (side, named) in [("expected", "expected"), ("captured", "captured")] {
            let mut evidence = admitted.clone();
            evidence["facts"][side] = json!([]);
            assert_eq!(refusal("sources", &evidence), Refusal::SourcesRefused(named.into()));
        }
        let mut both = admitted.clone();
        both["facts"]["expected"] = json!([]);
        both["facts"]["captured"] = json!([]);
        both["facts"]["build_network_denied"] = false.into();
        assert_eq!(refusal("sources", &both), Refusal::SourcesRefused("expected".into()));
        for (side, named) in [("expected", "expected.notice:NOTICE"), ("captured", "captured.notice:NOTICE")] {
            let mut evidence = admitted.clone();
            evidence["facts"][side]
                .as_array_mut()
                .unwrap()
                .push(source_row("notice", "NOTICE"));
            assert_eq!(refusal("sources", &evidence), Refusal::SourcesRefused(named.into()));
        }
        let mut missing = admitted.clone();
        missing["facts"]["captured"].as_array_mut().unwrap().pop();
        assert_eq!(refusal("sources", &missing), Refusal::SourcesRefused("notice:NOTICE".into()));
        let mut substituted = admitted.clone();
        substituted["facts"]["captured"][1]["identity"] = "OTHER".into();
        assert_eq!(
            refusal("sources", &substituted),
            Refusal::SourcesRefused("notice:NOTICE".into())
        );
        let mut changed = admitted.clone();
        changed["facts"]["captured"][1]["sha256"] = "c".repeat(64).into();
        assert_eq!(refusal("sources", &changed), Refusal::SourcesRefused("notice:NOTICE".into()));
        for field in [
            "fetch_checksums_verified",
            "fetch_without_dependency_execution",
            "build_network_denied",
            "no_build_acquisition",
            "source_bytes_unchanged",
            "release_build_succeeded",
            "package_scoped",
        ] {
            for value in [json!(false), Value::Null] {
                let mut evidence = admitted.clone();
                evidence["facts"][field] = value;
                assert_eq!(refusal("sources", &evidence), Refusal::SourcesRefused(field.into()));
            }
        }
    }

    /// Claim: Supplied effective placement facts require digest equality, established rights, immutable ancestry and separate identities.
    /// ´claim:installation:writable-install´
    /// ´test:unit:installation-writable-install´
    #[test]
    fn installation_writable_install() {
        let admitted = placement_facts();
        assert!(evaluate("placement", &encoded(&admitted)).is_ok());
        for field in ["provenance_binary_sha256", "directory_binary_sha256"] {
            let mut evidence = admitted.clone();
            evidence["facts"][field] = "c".repeat(64).into();
            assert_eq!(refusal("placement", &evidence), Refusal::PlacementRefused(field.into()));
        }
        for field in [
            "administrator_owned",
            "binary_read_only",
            "provenance_read_only",
            "directory_not_replaceable",
            "full_path_selected",
            "provenance_same_build",
            "never_rewritten",
            "identities_separate",
        ] {
            for value in [json!(false), Value::Null] {
                let mut evidence = admitted.clone();
                evidence["facts"][field] = value;
                assert_eq!(refusal("placement", &evidence), Refusal::PlacementRefused(field.into()));
            }
        }
    }

    fn positional_evidence_shapes_refuse(admitted: &Value) {
        let envelope_as_array = json!([admitted["schema"], admitted["check"], admitted["commit"], admitted["facts"]]);
        let mut tag_as_array = admitted.clone();
        let facts = &admitted["facts"];
        tag_as_array["facts"] = json!([
            facts["tag"],
            facts["annotated"],
            facts["publisher_key"],
            facts["verified_key"],
            facts["signature_valid"],
            facts["resolved_commit"],
            facts["public_main"],
            facts["ancestor"]
        ]);
        for value in [envelope_as_array, tag_as_array] {
            assert!(matches!(evaluate("tag", &encoded(&value)), Err(Refusal::EvidenceInvalid(_))));
        }
        let mut sources_as_array = source_facts();
        let source_fields = &sources_as_array["facts"];
        sources_as_array["facts"] = json!([
            source_fields["expected"],
            source_fields["captured"],
            source_fields["fetch_checksums_verified"],
            source_fields["fetch_without_dependency_execution"],
            source_fields["build_network_denied"],
            source_fields["no_build_acquisition"],
            source_fields["source_bytes_unchanged"],
            source_fields["release_build_succeeded"],
            source_fields["package_scoped"]
        ]);
        assert!(matches!(
            evaluate("sources", &encoded(&sources_as_array)),
            Err(Refusal::EvidenceInvalid(_))
        ));
        let mut row_as_array = source_facts();
        let row = &row_as_array["facts"]["expected"][0];
        row_as_array["facts"]["expected"][0] = json!([row["kind"], row["identity"], row["sha256"]]);
        assert!(matches!(
            evaluate("sources", &encoded(&row_as_array)),
            Err(Refusal::EvidenceInvalid(_))
        ));
        let mut enum_as_object = source_facts();
        enum_as_object["facts"]["expected"][0]["kind"] = json!({"registry": null});
        assert!(matches!(
            evaluate("sources", &encoded(&enum_as_object)),
            Err(Refusal::EvidenceInvalid(_))
        ));
        let mut placement_as_array = placement_facts();
        let placement_fields = &placement_as_array["facts"];
        placement_as_array["facts"] = json!([
            placement_fields["binary_sha256"],
            placement_fields["provenance_binary_sha256"],
            placement_fields["directory_binary_sha256"],
            placement_fields["administrator_owned"],
            placement_fields["binary_read_only"],
            placement_fields["provenance_read_only"],
            placement_fields["directory_not_replaceable"],
            placement_fields["full_path_selected"],
            placement_fields["provenance_same_build"],
            placement_fields["never_rewritten"],
            placement_fields["identities_separate"]
        ]);
        assert!(matches!(
            evaluate("placement", &encoded(&placement_as_array)),
            Err(Refusal::EvidenceInvalid(_))
        ));
    }

    /// Claim: Closed evidence decoding rejects malformed, duplicate, unknown, missing and mismatched shapes before predicate checks.
    /// ´claim:installation:evidence-shape´
    /// ´test:unit:installation-evidence-shape´
    #[test]
    fn installation_evidence_shape() {
        let admitted = tag_facts();
        assert!(evaluate("tag", &encoded(&admitted)).is_ok());
        for raw in [b"{".as_slice(), b"{}".as_slice(), b"[]".as_slice()] {
            assert!(matches!(evaluate("tag", raw), Err(Refusal::EvidenceInvalid(_))));
        }
        positional_evidence_shapes_refuse(&admitted);
        let mut cases = Vec::new();
        let mut unknown = admitted.clone();
        unknown["extra"] = true.into();
        cases.push(unknown);
        let mut nested = admitted.clone();
        nested["facts"]["extra"] = true.into();
        cases.push(nested);
        let mut schema = admitted.clone();
        schema["schema"] = 2.into();
        cases.push(schema);
        let mut selector = admitted.clone();
        selector["check"] = "sources".into();
        cases.push(selector);
        let mut wrong_type = admitted.clone();
        wrong_type["facts"]["annotated"] = "true".into();
        cases.push(wrong_type);
        let mut absent = admitted.clone();
        absent["facts"].as_object_mut().unwrap().remove("signature_valid");
        cases.push(absent);
        let mut bad_commit = admitted.clone();
        bad_commit["commit"] = "ABC".into();
        cases.push(bad_commit);
        let mut bad_identity = admitted.clone();
        bad_identity["facts"]["publisher_key"] = "".into();
        cases.push(bad_identity);
        for (index, value) in cases.into_iter().enumerate() {
            let result = evaluate("tag", &encoded(&value));
            assert!(matches!(result, Err(Refusal::EvidenceInvalid(_))), "case {index}: {result:?}");
        }
        let duplicated = format!(
            "{{\"schema\":1,\"schema\":1,\"check\":\"tag\",\"commit\":\"{}\",\"facts\":{}}}",
            commit(),
            admitted["facts"]
        );
        assert!(matches!(
            evaluate("tag", duplicated.as_bytes()),
            Err(Refusal::EvidenceInvalid(_))
        ));
        let trailing = format!("{} {{}}", String::from_utf8(encoded(&admitted)).unwrap());
        assert!(matches!(
            evaluate("tag", trailing.as_bytes()),
            Err(Refusal::EvidenceInvalid(_))
        ));
        let mut source = source_facts();
        source["facts"]["expected"][0]["identity"] = "/private/path".into();
        assert_eq!(
            refusal("sources", &source),
            Refusal::EvidenceInvalid("expected.identity".into())
        );
        let mut digest = source_facts();
        digest["facts"]["captured"][0]["sha256"] = "ABC".into();
        assert_eq!(
            refusal("sources", &digest),
            Refusal::EvidenceInvalid("captured.sha256".into())
        );
    }

    /// Claim: The command seam emits one conditional JSON success and distinguishes runtime evidence refusal from usage selection.
    /// ´claim:installation:verdict-route´
    /// ´test:unit:installation-verdict-route´
    #[test]
    fn installation_verdict_route() {
        let directory = tempfile::tempdir().unwrap();
        let facts = directory.path().join("facts.json");
        fs::write(&facts, encoded(&tag_facts())).unwrap();
        let verdict = check_file(directory.path(), "tag", std::path::Path::new("facts.json")).unwrap();
        assert_eq!(
            serde_json::to_string(&verdict).unwrap(),
            format!("{{\"check\":\"tag\",\"commit\":\"{}\",\"facts_consistent\":true}}", commit())
        );
        let mut bad = tag_facts();
        bad["facts"]["tag"] = "deploy/test-0".into();
        fs::write(&facts, encoded(&bad)).unwrap();
        assert_eq!(
            check_file(directory.path(), "tag", std::path::Path::new("facts.json")).unwrap_err(),
            Refusal::TagRefused("tag".into())
        );
        assert_eq!(cli_common::CommandExit::Failure.code(), 1);
        assert_eq!(cli_common::CommandExit::Usage.code(), 2);
        assert!(matches!(
            evaluate("unknown", &encoded(&tag_facts())),
            Err(Refusal::EvidenceInvalid(_))
        ));
        fs::remove_file(&facts).unwrap();
        assert!(matches!(
            check_file(directory.path(), "tag", std::path::Path::new("facts.json")),
            Err(Refusal::EvidenceInvalid(_))
        ));
    }
}
