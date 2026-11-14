//! Test-only reader admission; no execution configuration is exported.
//! (´verif:node:admission´)

use async_graphql_parser::{
    parse_schema,
    types::{TypeKind, TypeSystemDefinition},
};
use std::collections::{BTreeMap, BTreeSet};
use toml::Value;

const ARTIFACT: &[u8] = include_bytes!("../../interchange/schema/control.cbor");
const SOURCE: &str = include_str!("../../interchange/schema/control.graphql");
const DRAFT: &str = include_str!("../schema/control-register-draft.toml");

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Envelope,
    Embedding,
    SchemaSyntax,
    SchemaShape,
    RegisterSyntax,
    UnknownKey,
    RegisterShape,
    Agreement,
    Pending,
    Unserved,
}

#[derive(Debug, PartialEq, Eq)]
struct Shape {
    query: String,
    mutation: String,
    objects: BTreeMap<String, Vec<String>>,
}

fn schema(source: &str) -> Result<Shape, Refusal> {
    let parsed = parse_schema(source).map_err(|_| Refusal::SchemaSyntax)?;
    let mut roots = None;
    let mut objects = BTreeMap::new();
    for definition in parsed.definitions {
        match definition {
            TypeSystemDefinition::Schema(definition) => {
                let d = definition.node;
                if roots.is_some() || d.extend || !d.directives.is_empty() || d.subscription.is_some() {
                    return Err(Refusal::SchemaShape);
                }
                roots = Some((
                    d.query.ok_or(Refusal::SchemaShape)?.node.to_string(),
                    d.mutation.ok_or(Refusal::SchemaShape)?.node.to_string(),
                ));
            }
            TypeSystemDefinition::Type(definition) => {
                let d = definition.node;
                if d.extend || !d.directives.is_empty() {
                    return Err(Refusal::SchemaShape);
                }
                let TypeKind::Object(object) = d.kind else {
                    return Err(Refusal::SchemaShape);
                };
                if !object.implements.is_empty() {
                    return Err(Refusal::SchemaShape);
                }
                let mut names = BTreeSet::new();
                let mut fields = Vec::new();
                for f in object.fields {
                    let f = f.node;
                    if !names.insert(f.name.node.to_string()) || !f.arguments.is_empty() || !f.directives.is_empty() {
                        return Err(Refusal::SchemaShape);
                    }
                    fields.push(format!("{}:{}", f.name.node, f.ty.node));
                }
                if objects.insert(d.name.node.to_string(), fields).is_some() {
                    return Err(Refusal::SchemaShape);
                }
            }
            TypeSystemDefinition::Directive(_) => return Err(Refusal::SchemaShape),
        }
    }
    let (query, mutation) = roots.ok_or(Refusal::SchemaShape)?;
    Ok(Shape {
        query,
        mutation,
        objects,
    })
}

fn keys(table: &toml::Table, expected: &[&str]) -> Result<(), Refusal> {
    if table.keys().any(|key| !expected.contains(&key.as_str())) {
        return Err(Refusal::UnknownKey);
    }
    if expected.iter().any(|key| !table.contains_key(*key)) {
        return Err(Refusal::RegisterShape);
    }
    Ok(())
}

fn text<'a>(table: &'a toml::Table, name: &str) -> Result<&'a str, Refusal> {
    table.get(name).and_then(Value::as_str).ok_or(Refusal::RegisterShape)
}

fn strings(table: &toml::Table, name: &str) -> Result<Vec<String>, Refusal> {
    table
        .get(name)
        .and_then(Value::as_array)
        .ok_or(Refusal::RegisterShape)?
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or(Refusal::RegisterShape))
        .collect()
}

fn fixed(table: &toml::Table, name: &str, value: &str) -> Result<(), Refusal> {
    if text(table, name)? != value {
        return Err(Refusal::RegisterShape);
    }
    Ok(())
}

fn limit(value: &Value, unit: &str) -> Result<bool, Refusal> {
    let table = value.as_table().ok_or(Refusal::RegisterShape)?;
    fixed(table, "unit", unit)?;
    match text(table, "status")? {
        "not-yet-admitted" => {
            if table.contains_key("value") {
                return Err(Refusal::RegisterShape);
            }
            keys(table, &["status", "unit"])?;
            Ok(true)
        }
        "admitted" => {
            keys(table, &["status", "value", "unit"])?;
            if table.get("value").and_then(Value::as_integer).is_none_or(|v| v <= 0) {
                return Err(Refusal::RegisterShape);
            }
            Ok(false)
        }
        _ => Err(Refusal::RegisterShape),
    }
}

fn operation_metadata(operation: &toml::Table) -> Result<(), Refusal> {
    keys(
        operation,
        &[
            "name",
            "kind",
            "arguments",
            "defaults",
            "result",
            "fields",
            "success",
            "refusal",
            "failures",
            "authorization",
            "bootstrap",
            "pagination",
            "cancellation",
            "argument_nullability",
            "work_weights",
        ],
    )?;
    for (name, value) in [
        ("name", "start"),
        ("kind", "mutation"),
        ("success", "ready=true; failure=null"),
        ("refusal", "ready=false; failure=one-closed-name"),
        ("authorization", "in-process-entry; no-channel; no-control-credential"),
        ("bootstrap", "embedding-public-context; no-message-arguments"),
        ("pagination", "not-applicable:no-list-result"),
        ("cancellation", "before-ready; first-terminal-cause; absolute-deadline"),
        ("argument_nullability", "not-applicable:no-arguments"),
    ] {
        fixed(operation, name, value)?;
    }
    if !strings(operation, "arguments")?.is_empty() || !strings(operation, "defaults")?.is_empty() {
        return Err(Refusal::RegisterShape);
    }
    Ok(())
}

fn failure_metadata(operation: &toml::Table, conditions: &toml::Table) -> Result<(), Refusal> {
    let failures = [
        ("BootstrapInvalid", "public-bootstrap-validation"),
        ("EditionUnsupported", "unsupported-lifecycle-edition"),
        ("ResourceLimit", "resource-or-execution-deadline-exhausted"),
        ("Cancelled", "cancellation-before-readiness"),
        ("StartFailed", "remaining-checked-shell-startup-failure"),
    ];
    if strings(operation, "failures")? != failures.iter().map(|(name, _)| (*name).to_owned()).collect::<Vec<_>>() {
        return Err(Refusal::RegisterShape);
    }
    keys(conditions, &failures.iter().map(|(name, _)| *name).collect::<Vec<_>>())?;
    for (name, value) in failures {
        fixed(conditions, name, value)?;
    }
    Ok(())
}

fn ceiling_metadata(ceilings: &toml::Table) -> Result<bool, Refusal> {
    let units = [
        ("schema_source", "utf8-bytes"),
        ("register_source", "utf8-bytes"),
        ("graphql_source", "utf8-bytes"),
        ("transport", "bytes"),
        ("decoded_bytes", "bytes"),
        ("decoded_items", "items"),
        ("cbor_nesting", "levels"),
        ("input_nesting", "levels"),
        ("lexical_tokens", "tokens"),
        ("source_nesting", "levels"),
        ("selection_depth", "levels"),
        ("root_selections", "selections"),
        ("fields", "selections"),
        ("aliases", "aliases"),
        ("fragment_work", "occurrences"),
        ("resolver_work", "work"),
        ("response", "bytes"),
        ("concurrency", "executions"),
        ("execution", "nanoseconds"),
        ("cancellation_drain", "nanoseconds"),
        ("shell_start", "nanoseconds"),
        ("shell_stop", "nanoseconds"),
    ];
    let mut ceiling_keys = units.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    ceiling_keys.extend(["list_size", "page_size", "http_body"]);
    keys(ceilings, &ceiling_keys)?;
    for (name, value) in [
        ("list_size", "not-applicable:no-list-type"),
        ("page_size", "not-applicable:no-pagination"),
        ("http_body", "not-applicable:no-http-listener"),
    ] {
        fixed(ceilings, name, value)?;
    }
    let mut pending = false;
    for (name, unit) in units {
        pending |= limit(&ceilings[name], unit)?;
    }
    Ok(pending)
}

fn register(source: &str) -> Result<(Shape, bool), Refusal> {
    let table = source.parse::<toml::Table>().map_err(|_| Refusal::RegisterSyntax)?;
    keys(
        &table,
        &[
            "role",
            "schema_namespace",
            "schema_version",
            "query_root",
            "query_fields",
            "mutation_root",
            "query_admission",
            "introspection",
            "operations",
            "failure_conditions",
            "ceilings",
        ],
    )?;
    for (name, value) in [
        ("role", "control"),
        ("schema_namespace", "org.peer-network.test.api-control-schema"),
        ("schema_version", "1.0.0"),
        ("query_admission", "refuse-before-resolver"),
        ("introspection", "isolated-conformance-only"),
    ] {
        fixed(&table, name, value)?;
    }
    let operations = table["operations"].as_array().ok_or(Refusal::RegisterShape)?;
    if operations.len() != 1 {
        return Err(Refusal::RegisterShape);
    }
    let operation = operations[0].as_table().ok_or(Refusal::RegisterShape)?;
    operation_metadata(operation)?;
    failure_metadata(
        operation,
        table["failure_conditions"].as_table().ok_or(Refusal::RegisterShape)?,
    )?;
    let pending = limit(&operation["work_weights"], "work-per-start")?
        | ceiling_metadata(table["ceilings"].as_table().ok_or(Refusal::RegisterShape)?)?;
    let query = text(&table, "query_root")?.to_owned();
    let mutation = text(&table, "mutation_root")?.to_owned();
    let result = text(operation, "result")?;
    let result_name = result.strip_suffix('!').ok_or(Refusal::RegisterShape)?;
    let mut objects = BTreeMap::new();
    for (name, fields) in [
        (query.clone(), strings(&table, "query_fields")?),
        (mutation.clone(), vec![format!("start:{result}")]),
        (result_name.to_owned(), strings(operation, "fields")?),
    ] {
        if objects.insert(name, fields).is_some() {
            return Err(Refusal::RegisterShape);
        }
    }
    Ok((
        Shape {
            query,
            mutation,
            objects,
        },
        pending,
    ))
}

fn agree(source: &str, draft: &str) -> Result<bool, Refusal> {
    let schema = schema(source)?;
    let (register, pending) = register(draft)?;
    if schema != register {
        return Err(Refusal::Agreement);
    }
    Ok(pending)
}

fn embedding(bytes: &[u8], draft: &str) -> Result<bool, Refusal> {
    let source = pn_interchange::control_schema::decode(bytes).map_err(|_| Refusal::Envelope)?;
    if bytes != ARTIFACT || draft.as_bytes() != DRAFT.as_bytes() {
        return Err(Refusal::Embedding);
    }
    agree(&source, draft)
}

fn served(pending: bool) -> Result<(), Refusal> {
    if pending {
        Err(Refusal::Pending)
    } else {
        Err(Refusal::Unserved)
    }
}

/// Claim: Conformance parses the exact carried schema and independent draft into agreeing roots, fields and nullability, with closed metadata and pending ceilings; no execution occurs.
/// ´claim:admission:control-schema-register-agree´
/// ´test:unit:agreement´
#[test]
fn agreement() {
    assert_eq!(agree(SOURCE, DRAFT), Ok(true), "independent register comparison");
    assert_eq!(embedding(ARTIFACT, DRAFT), Ok(true), "reviewed embedding agrees");
    assert_eq!(
        agree(&SOURCE.replace("ready: Boolean!", "ready: Boolean"), DRAFT),
        Err(Refusal::Agreement),
        "nullability disagreement"
    );
    assert_eq!(
        agree(SOURCE, &DRAFT.replace("ready:Boolean!", "ready:String!")),
        Err(Refusal::Agreement),
        "register type disagreement"
    );
    assert_eq!(
        agree(
            &SOURCE.replace(
                "  ready: Boolean!\n  edition: String!",
                "  edition: String!\n  ready: Boolean!"
            ),
            DRAFT
        ),
        Err(Refusal::Agreement),
        "semantic row order disagreement"
    );
}

/// Claim: Robustness refuses malformed schema source at parsing and duplicate or additional definitions, directives and arguments at the closed shape check before agreement.
/// ´claim:admission:schema-reader-refuses-invalid-shapes´
/// ´test:unit:schema-refusals´
#[test]
fn schema_refusals() {
    assert_eq!(
        schema("schema {"),
        Err(Refusal::SchemaSyntax),
        "malformed SDL reaches parser refusal"
    );
    for bad in [
        format!("{SOURCE}\ntype ControlQuery {{ other: Boolean }}\n"),
        SOURCE.replace("unavailable: Boolean", "unavailable: Boolean\n  unavailable: Boolean"),
        SOURCE.replace("start:", "start(input: String):"),
        format!("{SOURCE}\ndirective @extra on FIELD\n"),
        format!("{SOURCE}\nscalar Extra\n"),
    ] {
        assert_eq!(schema(&bad), Err(Refusal::SchemaShape), "closed schema shape refusal");
    }
}

/// Claim: Robustness refuses malformed TOML and duplicate keys through the admitted reader, with only a constant first-party refusal class retained.
/// ´claim:admission:register-syntax-refuses´
/// ´test:unit:register-syntax´
#[test]
fn register_syntax() {
    for bad in ["role = [".to_owned(), format!("role = \"private-diagnostic-probe\"\n{DRAFT}")] {
        assert_eq!(
            register(&bad),
            Err(Refusal::RegisterSyntax),
            "malformed or duplicate register input refuses"
        );
        assert!(
            !format!("{:?}", register(&bad)).contains("private-diagnostic-probe"),
            "no dependency input diagnostic escapes"
        );
    }
}

/// Claim: Robustness refuses unknown keys at the root, operation, failure, ceiling and bound levels, before structural agreement.
/// ´claim:admission:register-unknown-keys-refuse´
/// ´test:unit:register-unknown-keys´
#[test]
fn register_unknown_keys() {
    for bad in [
        format!("extra = true\n{DRAFT}"),
        DRAFT.replace("name = \"start\"", "extra = true\nname = \"start\""),
        DRAFT.replace("[failure_conditions]", "[failure_conditions]\nextra = \"value\""),
        DRAFT.replace("[ceilings]", "[ceilings]\nextra = 1"),
        DRAFT.replacen("unit = \"work-per-start\"", "unit = \"work-per-start\", extra = 1", 1),
    ] {
        assert_eq!(
            register(&bad),
            Err(Refusal::UnknownKey),
            "unknown register key reaches its own refusal"
        );
    }
}

/// Claim: Robustness refuses missing members, wrong types, reordered failure rows and invalid status, unit, applicability or value combinations without treating pending as unlimited.
/// ´claim:admission:register-metadata-is-closed´
/// ´test:unit:register-metadata´
#[test]
fn register_metadata() {
    for bad in [
        DRAFT.replace("role = \"control\"\n", ""),
        DRAFT.replace("role = \"control\"", "role = true"),
        DRAFT.replace(
            "\"BootstrapInvalid\", \"EditionUnsupported\"",
            "\"EditionUnsupported\", \"BootstrapInvalid\"",
        ),
        DRAFT.replace("not-yet-admitted", "unbounded"),
        DRAFT.replace("work-per-start", "seconds"),
        DRAFT.replace("not-applicable:no-list-type", "not-yet-admitted"),
        DRAFT.replacen("status = \"not-yet-admitted\"", "status = \"not-yet-admitted\", value = 1", 1),
        DRAFT.replacen("status = \"not-yet-admitted\"", "status = \"admitted\", value = 0", 1),
        DRAFT.replace("arguments = []", "arguments = [\"input:String\"]"),
        DRAFT.replace("remaining-checked-shell-startup-failure", "private-error-text"),
    ] {
        assert_eq!(
            register(&bad),
            Err(Refusal::RegisterShape),
            "closed register metadata refusal"
        );
    }
}

/// Claim: Conformance refuses served construction while any register value is pending; even a fully admitted synthetic fixture cannot construct a served operation in this test-only harness.
/// ´claim:admission:pending-register-cannot-serve´
/// ´test:unit:pending-refusal´
#[test]
fn pending_refusal() {
    let pending = agree(SOURCE, DRAFT).expect("unserved draft agreement");
    assert_eq!(
        served(pending),
        Err(Refusal::Pending),
        "pending measurement refuses served construction"
    );
    let complete = DRAFT.replace("status = \"not-yet-admitted\"", "status = \"admitted\", value = 1");
    assert!(!register(&complete).expect("synthetic positive units only").1);
    assert_eq!(served(false), Err(Refusal::Unserved), "admission harness never serves");
}

/// Claim: Conformance compares embedded bytes with the committed inputs and the record's exact draft, refuses a decodable alternate patch or changed draft, and observes no disk-policy read after substituting runtime files.
/// ´claim:admission:embedding-is-build-owned´
/// ´test:unit:embedding-owned´
#[test]
fn embedding_owned() {
    assert_eq!(
        pn_interchange::control_schema::encode(SOURCE).expect("source encode"),
        ARTIFACT,
        "embedded source bytes"
    );
    for record in [
        include_str!("../../../docs/templates/adr/018-public-api.md.j2"),
        include_str!("../../../adr/018-public-api.md"),
    ] {
        let draft = record
            .split_once("```toml\n")
            .expect("draft fence")
            .1
            .split_once("```")
            .expect("closed draft")
            .0;
        assert_eq!(
            draft.as_bytes(),
            DRAFT.as_bytes(),
            "draft record and embedded input agree byte for byte"
        );
    }
    let mut alternate = ARTIFACT.to_vec();
    let offset = alternate
        .windows(4)
        .position(|w| w == [0x83, 1, 0, 0])
        .expect("version tuple");
    alternate[offset + 3] = 1;
    assert!(
        pn_interchange::control_schema::decode(&alternate).is_ok(),
        "alternate patch reaches embedding check"
    );
    assert_eq!(
        embedding(&alternate, DRAFT),
        Err(Refusal::Embedding),
        "alternate patch is not the embedded artifact"
    );
    assert_eq!(
        embedding(ARTIFACT, &(DRAFT.to_owned() + "\n")),
        Err(Refusal::Embedding),
        "changed draft bytes refuse"
    );
    assert_eq!(
        embedding(b"invalid envelope", DRAFT),
        Err(Refusal::Envelope),
        "carriage validation precedes use"
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("pn-admission-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).expect("runtime fixture directory");
    std::fs::write(directory.join("control.cbor"), b"substituted").expect("substitute artifact");
    std::fs::write(directory.join("control-register-draft.toml"), b"substituted").expect("substitute register");
    let child = std::process::Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", "admission::embedded_child", "--nocapture"])
        .current_dir(&directory)
        .output()
        .expect("embedded reader child");
    assert!(
        child.status.success(),
        "disk substitutions cannot change the embedded result: {}",
        String::from_utf8_lossy(&child.stdout)
    );
    std::fs::remove_dir_all(directory).expect("remove fixtures");
}

/// Claim: Conformance uses the build-owned artifact and draft without a runtime path, including when invoked from a directory containing substituted files.
/// ´claim:admission:embedded-child-has-no-policy-path´
/// ´test:unit:embedded-child´
#[test]
fn embedded_child() {
    assert_eq!(
        embedding(ARTIFACT, DRAFT),
        Ok(true),
        "disk substitutes are never inputs to embedded readers"
    );
}
