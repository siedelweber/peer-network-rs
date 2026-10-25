use std::fs;
use std::path::Path;
use std::process::Command;

use documents::{Finding, FindingKind, Operation, Result};

fn write_dataset(path: &Path, data: &serde_json::Value) -> Result<()> {
    fs::write(
        path,
        format!(
            "{{\"namespace\":{},\"version\":{},\"rows\":{}}}\n",
            data["namespace"], data["version"], data["rows"]
        ),
    )?;
    Ok(())
}

fn fixture() -> Result<tempfile::TempDir> {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("Cargo.toml"), "[workspace]\nmembers = []\n")?;
    git(directory.path(), &["init", "--quiet"])?;
    fs::create_dir_all(directory.path().join("docs/inputs"))?;
    fs::create_dir_all(directory.path().join("docs/templates/docs"))?;
    fs::write(
        directory.path().join("docs/inputs/items.toml"),
        "namespace = \"org.peer-network.test.items\"\nversion = [1, 0, 0]\n[[rows]]\nname = \"alpha\"\ncount = 2\n",
    )?;
    fs::write(
        directory.path().join("docs/templates/docs/result.md.j2"),
        "{{ row('org.peer-network.test.items', name='alpha').count | number }}\n",
    )?;
    documents::run(directory.path(), Operation::Generate { check: false })?;
    documents::run(directory.path(), Operation::Write)?;
    git(directory.path(), &["add", "-A"])?;
    Ok(directory)
}

/// Claim: Two consecutive generate-check and document-check passes report no findings on the repository, checking that committed inputs and outputs form a fixed point.
/// ´claim:render:repository-fixed-point´
/// ´test:integration:repository-fixed-point´
#[test]
fn repository_fixed_point() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for _ in 0..2 {
        assert_eq!(
            documents::run(&root, Operation::Generate { check: true })?.findings,
            Vec::<Finding>::new()
        );
        assert_eq!(documents::run(&root, Operation::Check)?.findings, Vec::<Finding>::new());
    }
    Ok(())
}

/// Claim: Changing the fixture dataset count produces exactly stale-dataset and stale-document findings without repairing the changed bytes, preserving read-only diagnosis.
/// ´claim:render:dataset-mutation´
/// ´test:integration:dataset-mutation´
#[test]
fn dataset_mutation() -> Result<()> {
    let directory = fixture()?;
    let path = directory.path().join("docs/datasets/org.peer-network.test.items.json");
    let mutated = fs::read_to_string(&path)?.replace("\"count\": 2", "\"count\": 3");
    fs::write(&path, &mutated)?;
    let report = documents::run(directory.path(), Operation::Check)?;
    assert_eq!(
        report.findings,
        [
            Finding {
                kind: FindingKind::StaleDataset,
                path: "docs/datasets/org.peer-network.test.items.json".into()
            },
            Finding {
                kind: FindingKind::StaleDocument,
                path: "docs/result.md".into()
            },
        ]
    );
    assert_eq!(fs::read_to_string(&path)?, mutated);
    Ok(())
}

/// Claim: A stale fixture document remains untouched by checking, is repaired to the exact rendered bytes by writing with a finding, and then checks clean.
/// ´claim:render:stale-rendering´
/// ´test:integration:stale-rendering´
#[test]
fn stale_rendering() -> Result<()> {
    let directory = fixture()?;
    let path = directory.path().join("docs/result.md");
    fs::write(&path, "stale\n")?;
    assert_eq!(
        documents::run(directory.path(), Operation::Check)?.findings,
        [Finding {
            kind: FindingKind::StaleDocument,
            path: "docs/result.md".into()
        }]
    );
    assert_eq!(fs::read_to_string(&path)?, "stale\n");
    assert_eq!(
        documents::run(directory.path(), Operation::Write)?.findings,
        [Finding {
            kind: FindingKind::StaleDocument,
            path: "docs/result.md".into()
        }]
    );
    assert_eq!(fs::read_to_string(path)?, "2\n");
    assert_eq!(
        documents::run(directory.path(), Operation::Check)?.findings,
        Vec::<Finding>::new()
    );
    Ok(())
}

/// Claim: non-Markdown text outputs render from datasets and participate in fixed-point checking.
/// ´claim:render:text-output´
/// ´test:integration:text-output´
#[test]
fn text_output() -> Result<()> {
    let directory = fixture()?;
    let root = directory.path();
    fs::create_dir_all(root.join("docs/templates/.linter/imports"))?;
    fs::write(
        root.join("docs/templates/.linter/imports/paper.toml.j2"),
        "{{ require(rows('org.peer-network.test.items') | length == 1, 'one input row') }}count = {{ row('org.peer-network.test.items', name='alpha').count | number }}\n",
    )?;
    let output = root.join(".linter/imports/paper.toml");
    let report = documents::run(root, Operation::Write)?;
    assert_eq!(
        report.findings,
        [Finding {
            kind: FindingKind::StaleDocument,
            path: ".linter/imports/paper.toml".into(),
        }]
    );
    assert_eq!(fs::read_to_string(&output)?, "count = 2\n");
    assert_eq!(documents::run(root, Operation::Check)?.findings, Vec::<Finding>::new());
    fs::write(&output, "count = 3\n")?;
    assert_eq!(documents::run(root, Operation::Check)?.findings, report.findings);
    assert_eq!(fs::read_to_string(output)?, "count = 3\n");
    Ok(())
}

/// Claim: both release documents refuse mismatched refresh tags, and the register refuses a changed status-absence set.
/// ´claim:render:release-premises´
/// ´test:integration:release-premises´
#[test]
fn release_premises() -> Result<()> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for document in ["inventory", "questions"] {
        let directory = fixture()?;
        let root = directory.path();
        for input in [
            "design-inventory",
            "design-constants",
            "design-summary",
            "design-publication",
            "design-questions",
            "render-premises",
        ] {
            fs::copy(
                repository.join(format!("docs/inputs/{input}.toml")),
                root.join(format!("docs/inputs/{input}.toml")),
            )?;
        }
        fs::create_dir_all(root.join("docs/templates/docs/design"))?;
        let template = format!("docs/templates/docs/design/{document}.md.j2");
        fs::copy(repository.join(&template), root.join(&template))?;
        documents::run(root, Operation::Generate { check: false })?;
        documents::run(root, Operation::Write)?;
        for (dataset, field, message) in [
            ("inventory", "current_at", "inventory current_at must match publication tag"),
            (
                "constants",
                "refreshed_at",
                "constants refreshed_at must match publication tag",
            ),
            ("questions", "status", "questions without status must match the declared ids"),
        ] {
            if document == "inventory" && field == "status" {
                continue;
            }
            let path = root.join(format!("docs/datasets/org.peer-network.design.{dataset}.json"));
            let original = fs::read_to_string(&path)?;
            let mut data: serde_json::Value = serde_json::from_str(&original)?;
            let row = data["rows"]
                .as_array_mut()
                .ok_or("rows")?
                .iter_mut()
                .find(|row| row.get(field).is_some())
                .ok_or("marked row")?;
            if field == "status" {
                row.as_object_mut().ok_or("row object")?.remove(field);
            } else {
                row[field] = "network-v0.25.2".into();
            }
            write_dataset(&path, &data)?;
            let result = documents::run(root, Operation::Write);
            assert!(result.is_err());
            assert!(result.err().ok_or("expected refusal")?.to_string().contains(message));
            fs::write(path, original)?;
        }
    }
    Ok(())
}

/// Claim: reserved kinds, owners and profile policies propagate from one dataset to both declarations and record 001.
/// ´claim:render:declaration-authority´
/// ´test:integration:declaration-authority´
#[test]
fn declaration_authority() -> Result<()> {
    let directory = fixture()?;
    let root = directory.path();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for input in [
        "records",
        "kinds-registry",
        "linter-reserved",
        "linter-owners",
        "linter-policies",
    ] {
        fs::copy(
            repository.join(format!("docs/inputs/{input}.toml")),
            root.join(format!("docs/inputs/{input}.toml")),
        )?;
    }
    fs::create_dir_all(root.join("docs/templates/.linter"))?;
    fs::create_dir_all(root.join("docs/templates/adr"))?;
    fs::create_dir_all(root.join("docs/fragments"))?;
    for path in [
        "docs/templates/.linter/environments.toml.j2",
        "docs/templates/.linter/owners.toml.j2",
        "docs/templates/.linter/policies.toml.j2",
        "docs/templates/.linter/lists.toml.j2",
        "docs/templates/adr/001-label-calculus.md.j2",
        "docs/fragments/record-front-matter.j2",
    ] {
        fs::copy(repository.join(path), root.join(path))?;
    }
    documents::run(root, Operation::Generate { check: false })?;
    documents::run(root, Operation::Write)?;
    for (dataset, declaration, needle) in [
        ("reserved", "environments", "newreserved"),
        ("owners", "owners", "EXAMPLE"),
        ("policies", "policies", "EXAMPLE"),
        ("policies", "lists", "EXAMPLE"),
    ] {
        let path = root.join(format!("docs/datasets/org.peer-network.linter.{dataset}.json"));
        let original = fs::read_to_string(&path)?;
        let mut data: serde_json::Value = serde_json::from_str(&original)?;
        match dataset {
            "reserved" => data["rows"][0]["kinds"][0] = needle.into(),
            "owners" => data["rows"][0]["owners"][0] = needle.into(),
            _ => {
                let row = data["rows"]
                    .as_array_mut()
                    .ok_or("rows")?
                    .iter_mut()
                    .find(|row| row["policy"] == "profile.tests-conform")
                    .ok_or("test policy")?;
                row["owner"] = needle.into();
            }
        }
        write_dataset(&path, &data)?;
        documents::run(root, Operation::Write)?;
        assert!(fs::read_to_string(root.join(format!(".linter/{declaration}.toml")))?.contains(needle));
        assert!(fs::read_to_string(root.join("adr/001-label-calculus.md"))?.contains(needle));
        fs::write(path, original)?;
    }
    Ok(())
}

/// Claim: only declared document roots and registry outputs can be rendered; repository machinery and vendor members are protected.
/// ´claim:render:protected-outputs´
/// ´test:integration:protected-outputs´
#[test]
fn protected_outputs() -> Result<()> {
    for document in [
        "docs/inputs/records.toml",
        "docs/datasets/result.json",
        "docs/templates/docs/result.md.j2",
        "vendor/new-member/README.md",
        ".git/config",
        "ci/gate.sh",
        "Cargo.toml",
        "packages/documents/Cargo.toml",
        "packages/graph/Cargo.toml",
        "Cargo.lock",
    ] {
        let directory = fixture()?;
        let root = directory.path();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = ['vendor/new-member']\n")?;
        let template = root.join("docs/templates").join(format!("{document}.j2"));
        fs::create_dir_all(template.parent().ok_or("template parent")?)?;
        fs::write(template, "overwrite\n")?;
        for operation in [
            Operation::Check,
            Operation::Write,
            Operation::Census,
            Operation::Generate { check: true },
            Operation::Generate { check: false },
        ] {
            let error = documents::run(root, operation).expect_err("protected output");
            assert!(error.to_string().contains("protected rendering output path"), "{error}");
            assert!(error.to_string().contains(document), "{error}");
        }
        assert_eq!(fs::read_to_string(root.join("docs/result.md"))?, "2\n");
    }
    let directory = fixture()?;
    let root = directory.path();
    fs::create_dir_all(root.join("docs/templates/packages/graph"))?;
    fs::write(root.join("docs/templates/packages/graph/README.md.j2"), "graph guide\n")?;
    documents::run(root, Operation::Write)?;
    assert_eq!(fs::read_to_string(root.join("packages/graph/README.md"))?, "graph guide\n");
    Ok(())
}

/// Claim: exhibiting supplied labels changes only their delimiters and leaves source prose intact.
/// ´claim:render:exhibited-labels´
/// ´test:integration:exhibited-labels´
#[test]
fn exhibited_labels() -> Result<()> {
    for labels in [
        "['def:graph:authored-act', 'def:graph:authored-act-bundle']",
        "['def:graph:authored-act-bundle', 'def:graph:authored-act']",
    ] {
        let directory = fixture()?;
        let root = directory.path();
        fs::write(
            root.join("docs/templates/docs/result.md.j2"),
            format!(
                "{{{{ 'Study judgment: preserve (def:graph:authored-act) and (def:graph:authored-act-bundle).' | exhibit({labels}) }}}}\n"
            ),
        )?;
        documents::run(root, Operation::Write)?;
        assert_eq!(
            fs::read_to_string(root.join("docs/result.md"))?,
            "Study judgment: preserve (``def:graph:authored-act``) and (``def:graph:authored-act-bundle``).\n"
        );
    }
    Ok(())
}

/// Claim: included and imported fragments share dataset tracking, emit no separate output, and preserve raw delimiters.
/// ´claim:render:template-fragments´
/// ´test:integration:template-fragments´
#[test]
fn template_fragments() -> Result<()> {
    let directory = fixture()?;
    let root = directory.path();
    fs::create_dir_all(root.join("docs/fragments"))?;
    fs::write(
        root.join("docs/fragments/value.j2"),
        "{{ row('org.peer-network.test.items', name='alpha').count | number }}",
    )?;
    fs::write(
        root.join("docs/fragments/macros.j2"),
        "{% macro literal() %}{% raw %}{{ literal }}{% endraw %}{% endmacro %}",
    )?;
    fs::write(
        root.join("docs/templates/docs/result.md.j2"),
        "{% import 'fragments/macros.j2' as macros %}{% include 'fragments/value.j2' %} {{ macros.literal() }} <markup>\n",
    )?;
    let report = documents::run(root, Operation::Write)?;
    assert_eq!(fs::read_to_string(root.join("docs/result.md"))?, "2 {{ literal }} <markup>\n");
    assert_eq!(report.templates.len(), 1);
    assert_eq!(report.templates[0].datasets, ["org.peer-network.test.items"]);
    assert!(!root.join("fragments").exists());
    assert_eq!(documents::run(root, Operation::Check)?.findings, Vec::<Finding>::new());
    fs::write(root.join("docs/fragments/value.j2"), "{{ absent }}")?;
    assert!(documents::run(root, Operation::Check).is_err());
    Ok(())
}

/// Claim: registry counts and homonyms derive from classified rows, exclude devices, and reject duplicate or candidate pairs.
/// ´claim:render:registry-relation´
/// ´test:integration:registry-relation´
#[test]
fn registry_relation() -> Result<()> {
    let directory = fixture()?;
    let root = directory.path();
    let input = root.join("docs/inputs/kinds.toml");
    let source = "namespace = 'org.peer-network.kinds.registry'\nversion = [1,0,0]\nrows = [\n{section='example',environment='Example',kind='ex',category='ordinary',status='firm'},\n{section='example',environment='Example',kind='demo',category='extension',status='firm'},\n{section='example',environment='Starred',kind='',category='device',status='device'},\n]\n";
    fs::write(&input, source)?;
    fs::write(
        root.join("docs/templates/docs/result.md.j2"),
        "{% set registry = kinds_registry() %}{% for item in registry.counts %}{{ item.measure }}={{ item.count }};{% endfor %}homonyms={{ registry.homonyms | length }}\n",
    )?;
    documents::run(root, Operation::Generate { check: false })?;
    let report = documents::run(root, Operation::Write)?;
    assert_eq!(report.templates[0].datasets, ["org.peer-network.kinds.registry"]);
    assert_eq!(
        fs::read_to_string(root.join("docs/result.md"))?,
        "Names=1;Rows=1;Kinds=1;Declared hybrids=0;Device classes=1;homonyms=2\n"
    );
    for (source, message) in [
        (source.replace("kind='demo'", "kind='ex'"), "duplicate pair"),
        (source.replace("status='firm'", "status='candidate'"), "firm or borderline"),
    ] {
        fs::write(&input, source)?;
        documents::run(root, Operation::Generate { check: false })?;
        let error = documents::run(root, Operation::Write).expect_err("invalid registry relation");
        assert!(error.to_string().contains(message), "{error}");
    }
    Ok(())
}

/// Claim: missing, misordered, misspelled and malformed envelopes identify their rejected field before reading payloads.
/// ´claim:envelope:named-refusals´
/// ´test:integration:named-refusals´
#[test]
fn named_refusals() -> Result<()> {
    let directory = fixture()?;
    let input = directory.path().join("docs/inputs/items.toml");
    for (text, field) in [
        ("rows = broken", "namespace"),
        ("version = [1, 0, 0]\nnamespace = 'org.peer-network.test.items'", "namespace"),
        ("namespce = 'org.peer-network.test.items'", "namespace"),
        ("namespace = 'wrong'\nversion = [1,0,0]", "namespace"),
        ("namespace = 'org.peer-network.test.items'", "version"),
        ("namespace = 'org.peer-network.test.items'\nrows = broken", "version"),
        ("namespace = 'org.peer-network.test.items'\nversoin = [1,0,0]", "version"),
        (
            "namespace = 'org.peer-network.test.items'\nversion = [01,0,0]\nrows = broken",
            "version",
        ),
        (
            "namespace = 'org.peer-network.test.items'\nversion = [2,0,0]\nrows = broken",
            "version",
        ),
    ] {
        fs::write(&input, text)?;
        let error = documents::run(directory.path(), Operation::Generate { check: true }).expect_err("invalid envelope");
        assert!(error.to_string().contains(field), "{error}");
    }
    let dataset = directory.path().join("docs/datasets/org.peer-network.test.items.json");
    for (text, field) in [
        ("{\"rows\": broken}", "namespace"),
        ("{\"version\":[1,0,0],\"namespace\": broken}", "namespace"),
        ("{\"namespce\": broken}", "namespace"),
        ("{\"namespace\":\"wrong\",\"rows\":broken}", "namespace"),
        ("{\"namespace\":\"org.peer-network.test.items\"}", "version"),
        (
            "{\"namespace\":\"org.peer-network.test.items\",\"versoin\":broken}",
            "version",
        ),
        ("{\"namespace\":\"org.peer-network.test.items\",\"rows\":broken}", "version"),
        (
            "{\"namespace\":\"org.peer-network.test.items\",\"version\":[1e0,0,0],\"rows\":broken}",
            "version",
        ),
    ] {
        fs::write(&dataset, text)?;
        let error = documents::run(directory.path(), Operation::Write).expect_err("invalid envelope");
        assert!(error.to_string().contains(field), "{error}");
    }
    Ok(())
}

/// Claim: absent datasets and rows fail by name, and failed requirements retain their message.
/// ´claim:render:premise-refusals´
/// ´test:integration:premise-refusals´
#[test]
fn premise_refusals() -> Result<()> {
    let directory = fixture()?;
    let template = directory.path().join("docs/templates/docs/result.md.j2");
    for (source, expected) in [
        ("{{ rows('org.peer-network.test.absent') }}", "org.peer-network.test.absent"),
        ("{{ row('org.peer-network.test.items', name='missing') }}", "absent row"),
        ("{{ require(false, 'premise does not hold') }}", "premise does not hold"),
        ("{{ row('org.peer-network.test.items', name='alpha').missing }}", "undefined"),
    ] {
        fs::write(&template, source)?;
        let error = documents::run(directory.path(), Operation::Check).expect_err("render must refuse");
        assert!(error.to_string().contains(expected), "{error}");
    }
    fs::write(&template, "literal {braces} and <markup>\n")?;
    documents::run(directory.path(), Operation::Write)?;
    assert_eq!(
        fs::read_to_string(directory.path().join("docs/result.md"))?,
        "literal {braces} and <markup>\n"
    );
    Ok(())
}

/// Claim: help, version and usage errors are JSON control records with no stdout result.
/// ´claim:cli:control-records´
/// ´test:integration:control-records´
#[test]
fn control_records() -> Result<()> {
    for (argument, status, kind) in [
        ("--help", 0, "help"),
        ("--version", 0, "version"),
        ("--unknown", 2, "usage_error"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_documents")).arg(argument).output()?;
        assert_eq!(output.status.code(), Some(status));
        assert_eq!(output.stdout, b"");
        let record: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(record["kind"], kind);
    }
    Ok(())
}

/// Claim: a terminal on stdout is refused before a write can change the repository.
/// ´claim:cli:terminal-refusal´
/// ´test:integration:terminal-refusal´
#[test]
fn terminal_refusal() -> Result<()> {
    let directory = fixture()?;
    fs::write(directory.path().join("docs/result.md"), "stale")?;
    let script = "import os,pty,subprocess,sys,json\nm,s=pty.openpty()\np=subprocess.run([sys.argv[1],'--root',sys.argv[2],'write'],stdout=s,stderr=subprocess.PIPE)\nos.close(s)\nassert p.returncode==2\nrecords=[json.loads(line) for line in p.stderr.splitlines()]\nassert sum(r.get('kind')=='tty_refusal' for r in records)==1\ntry:\n data=os.read(m,4096)\nexcept OSError:\n data=b''\nassert data==b''\nos.close(m)\n";
    assert!(
        Command::new("python3")
            .args(["-c", script, env!("CARGO_BIN_EXE_documents")])
            .arg(directory.path())
            .status()?
            .success()
    );
    assert_eq!(fs::read_to_string(directory.path().join("docs/result.md"))?, "stale");
    Ok(())
}

fn invoke(root: &Path, operation: &str) -> Result<std::process::Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_documents"))
        .arg("--root")
        .arg(root)
        .arg(operation)
        .output()?)
}

/// Claim: a clean binary check emits exactly one JSON result line and status zero.
/// ´claim:cli:clean-result´
/// ´test:integration:clean-result´
#[test]
fn clean_result() -> Result<()> {
    let directory = fixture()?;
    let output = invoke(directory.path(), "check")?;
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.strip_suffix(b"\n").is_some_and(|line| !line.contains(&b'\n')));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert!(report.is_object());
    assert_eq!(report["findings"], serde_json::json!([]));
    let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stderr)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    assert!(records.iter().any(|record| record["kind"] == "metric_summary"));
    assert!(
        records
            .iter()
            .all(|record| record["level"] != "ERROR" && record["level"] != "WARN")
    );
    Ok(())
}

/// Claim: stale checking and refreshing both exit three, and refreshing changes the document.
/// ´claim:cli:finding-status´
/// ´test:integration:finding-status´
#[test]
fn finding_status() -> Result<()> {
    let directory = fixture()?;
    let path = directory.path().join("docs/result.md");
    fs::write(&path, "stale\n")?;
    for operation in ["check", "write"] {
        let output = invoke(directory.path(), operation)?;
        assert_eq!(output.status.code(), Some(3));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            report["findings"],
            serde_json::json!([{"kind": "stale_document", "path": "docs/result.md"}])
        );
        assert_eq!(
            fs::read_to_string(&path)?,
            if operation == "check" { "stale\n" } else { "2\n" }
        );
    }
    Ok(())
}

/// Claim: a malformed input makes the binary exit one with no result and a JSON tracing error naming its path.
/// ´claim:cli:runtime-error´
/// ´test:integration:runtime-error´
#[test]
fn runtime_error() -> Result<()> {
    let directory = fixture()?;
    fs::write(directory.path().join("docs/inputs/items.toml"), "namespace = 'wrong'\n")?;
    let output = invoke(directory.path(), "check")?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"");
    let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stderr)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let errors: Vec<_> = records.iter().filter(|record| record["level"] == "ERROR").collect();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].to_string().contains("docs/inputs/items.toml"));
    Ok(())
}

/// Claim: absent or empty template roots refuse through the binary with status one.
/// ´claim:render:empty-root´
/// ´test:integration:empty-root´
#[test]
fn empty_root() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for create in [false, true] {
        if create {
            fs::create_dir_all(directory.path().join("docs/templates"))?;
        }
        let output = invoke(directory.path(), "check")?;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stdout, b"");
        assert!(String::from_utf8(output.stderr)?.contains("docs/templates"));
    }
    Ok(())
}

/// Claim: datetime and non-finite input values refuse by field name, including nested values.
/// ´claim:envelope:json-model´
/// ´test:integration:json-model´
#[test]
fn json_model() -> Result<()> {
    let directory = fixture()?;
    let path = directory.path().join("docs/inputs/items.toml");
    for (value, reason) in [
        ("1979-05-27T07:32:00Z", "datetime"),
        ("nan", "non-finite"),
        ("{ nested = [inf] }", "non-finite"),
    ] {
        fs::write(
            &path,
            format!("namespace = 'org.peer-network.test.items'\nversion = [1,0,0]\n[[rows]]\nvalue = {value}\n"),
        )?;
        let error = documents::run(directory.path(), Operation::Generate { check: false }).expect_err("unsupported value");
        let message = error.to_string();
        assert!(
            message.contains("items.toml") && message.contains("value") && message.contains(reason),
            "{message}"
        );
    }
    Ok(())
}

/// Claim: a record without an index row, an index row without a record and Markdown without a template each refuse.
/// ´claim:render:paired-census´
/// ´test:integration:paired-census´
#[test]
fn paired_census() -> Result<()> {
    let directory = fixture()?;
    let root = directory.path();
    let stray = root.join("orphan.md");
    fs::write(&stray, "unpaired\n")?;
    git(root, &["add", "-A"])?;
    let error = documents::run(root, Operation::Check).expect_err("unpaired Markdown");
    assert!(error.to_string().contains("orphan.md: first-party Markdown has no template"));
    fs::remove_file(stray)?;
    git(root, &["add", "-A"])?;
    fs::create_dir_all(root.join("docs/templates/adr"))?;
    let template = root.join("docs/templates/adr/007-example.md.j2");
    fs::write(&template, "example\n")?;
    let error = documents::run(root, Operation::Check).expect_err("unindexed record");
    assert!(
        error
            .to_string()
            .contains("adr/007-example.md: record template has no index row")
    );
    fs::remove_file(template)?;
    fs::write(
        root.join("docs/inputs/records.toml"),
        "namespace = 'org.peer-network.records.index'\nversion = [1,0,0]\n[[rows]]\npath = 'adr/007-example.md'\n",
    )?;
    documents::run(root, Operation::Generate { check: false })?;
    let error = documents::run(root, Operation::Check).expect_err("missing record");
    assert!(
        error
            .to_string()
            .contains("adr/007-example.md: index row has no record template")
    );
    let report = documents::run(root, Operation::Census)?;
    assert_eq!(report.unread_datasets, ["docs/datasets/org.peer-network.records.index.json"]);
    Ok(())
}

/// Claim: refreshing replaces a document atomically rather than truncating its existing inode.
/// ´claim:render:atomic-refresh´
/// ´test:integration:atomic-refresh´
#[test]
fn atomic_refresh() -> Result<()> {
    let directory = fixture()?;
    let path = directory.path().join("docs/result.md");
    let previous = directory.path().join("previous.txt");
    fs::write(&path, "previous\n")?;
    fs::hard_link(&path, &previous)?;
    documents::run(directory.path(), Operation::Write)?;
    assert_eq!(fs::read_to_string(&path)?, "2\n");
    assert_eq!(fs::read_to_string(previous)?, "previous\n");
    Ok(())
}

/// Claim: record title and shared front matter follow one dataset row, and the accepted index refuses a superseded row.
/// ´claim:render:record-authority´
/// ´test:integration:record-authority´
#[test]
fn record_authority() -> Result<()> {
    let directory = fixture()?;
    let root = directory.path();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::create_dir_all(root.join("docs/templates/adr"))?;
    fs::create_dir_all(root.join("docs/fragments"))?;
    fs::copy(
        repository.join("docs/fragments/record-front-matter.j2"),
        root.join("docs/fragments/record-front-matter.j2"),
    )?;
    fs::copy(
        repository.join("docs/templates/adr/003-templated-documentation.md.j2"),
        root.join("docs/templates/adr/003-templated-documentation.md.j2"),
    )?;
    fs::write(
        root.join("docs/inputs/records.toml"),
        "namespace = 'org.peer-network.records.index'\nversion = [1,0,0]\n[[rows]]\npath = 'adr/003-templated-documentation.md'\ntitle = 'Revised rendering'\nstatus = 'superseded'\nlabel = 'rec:render:replacement'\nscope = 'Changed scope.'\ndepends_on = ['rec:render:other']\ndoes_not_establish = 'No extra claim.'\n",
    )?;
    documents::run(root, Operation::Generate { check: false })?;
    documents::run(root, Operation::Write)?;
    let rendered = fs::read_to_string(root.join("adr/003-templated-documentation.md"))?;
    assert!(rendered.starts_with("## Revised rendering"));
    assert!(rendered.contains("**Record (Revised rendering)**"));
    assert!(rendered.contains("`rec:render:replacement` Status: superseded."));
    assert!(rendered.contains("Scope: Changed scope. Depends on: (`rec:render:other`). Does not establish: No extra claim."));
    assert_eq!(documents::run(root, Operation::Check)?.findings, Vec::<Finding>::new());
    fs::copy(
        repository.join("docs/templates/adr/README.md.j2"),
        root.join("docs/templates/adr/README.md.j2"),
    )?;
    let error = documents::run(root, Operation::Check).expect_err("false accepted premise");
    assert!(error.to_string().contains("records index requires accepted decisions"));
    Ok(())
}

/// Claim: input, dataset and template read failures retain the offending path.
/// ´claim:render:io-paths´
/// ´test:integration:io-paths´
#[test]
fn io_paths() -> Result<()> {
    for (path, operation) in [
        ("docs/inputs/items.toml", Operation::Check),
        ("docs/datasets/org.peer-network.test.items.json", Operation::Write),
        ("docs/templates/docs/result.md.j2", Operation::Write),
    ] {
        let directory = fixture()?;
        fs::write(directory.path().join(path), [0xff])?;
        let error = documents::run(directory.path(), operation).expect_err("invalid UTF-8 input");
        assert!(error.to_string().contains(path));
    }
    Ok(())
}

fn git(root: &Path, arguments: &[&str]) -> Result<()> {
    let output = Command::new("git").current_dir(root).args(arguments).output()?;
    if !output.status.success() {
        return Err(String::from_utf8(output.stderr)?.into());
    }
    Ok(())
}

/// Claim: untracked Markdown is outside the census, while tracked Markdown under a nested target directory still needs a template.
/// ´claim:render:tracked-census´
/// ´test:integration:tracked-census´
#[test]
fn tracked_census() -> Result<()> {
    let directory = fixture()?;
    let root = directory.path();
    fs::write(root.join("draft.md"), "untracked\n")?;
    assert_eq!(documents::run(root, Operation::Check)?.findings, Vec::<Finding>::new());
    fs::create_dir_all(root.join("docs/notes/target"))?;
    fs::write(root.join("docs/notes/target/stray.md"), "tracked\n")?;
    git(root, &["add", "docs/notes/target/stray.md"])?;
    let error = documents::run(root, Operation::Check).expect_err("tracked Markdown without template");
    assert!(error.to_string().contains("docs/notes/target/stray.md"));
    Ok(())
}

/// Claim: the census excludes vendor members declared by the workspace, not a fixed crate list.
/// ´claim:render:vendor-census´
/// ´test:integration:vendor-census´
#[test]
fn vendor_census() -> Result<()> {
    let directory = fixture()?;
    let root = directory.path();
    fs::create_dir_all(root.join("vendor/new-member"))?;
    fs::write(root.join("vendor/new-member/README.md"), "third-party\n")?;
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = ['vendor/new-member']\n")?;
    git(root, &["add", "-A"])?;
    assert_eq!(documents::run(root, Operation::Check)?.findings, Vec::<Finding>::new());
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = []\n")?;
    let error = documents::run(root, Operation::Check).expect_err("no longer a vendor member");
    assert!(error.to_string().contains("vendor/new-member/README.md"));
    Ok(())
}

/// Claim: a record cannot select another record's row even when both paths occur in the index.
/// ´claim:render:record-row-key´
/// ´test:integration:record-row-key´
#[test]
fn record_row_key() -> Result<()> {
    let directory = fixture()?;
    let root = directory.path();
    fs::create_dir_all(root.join("docs/templates/adr"))?;
    fs::write(
        root.join("docs/inputs/records.toml"),
        "namespace = 'org.peer-network.records.index'\nversion = [1,0,0]\n[[rows]]\npath = 'adr/001-first.md'\ntitle = 'First'\n[[rows]]\npath = 'adr/002-second.md'\ntitle = 'Second'\n",
    )?;
    fs::write(
        root.join("docs/templates/adr/001-first.md.j2"),
        "{{ row('org.peer-network.records.index', path='adr/002-second.md').title }}\n",
    )?;
    fs::write(
        root.join("docs/templates/adr/002-second.md.j2"),
        "{{ row('org.peer-network.records.index', path='adr/001-first.md').title }}\n",
    )?;
    documents::run(root, Operation::Generate { check: false })?;
    let error = documents::run(root, Operation::Check).expect_err("swapped record rows");
    assert!(
        error
            .to_string()
            .contains("record row key differs from document path: adr/001-first.md")
    );
    Ok(())
}

/// Claim: records must execute their own index lookup and cannot substitute a collection read or an unexecuted lookup.
/// ´claim:render:record-observed-row´
/// ´test:integration:record-observed-row´
#[test]
fn record_observed_row() -> Result<()> {
    let directory = fixture()?;
    let root = directory.path();
    fs::create_dir_all(root.join("docs/templates/adr"))?;
    fs::write(
        root.join("docs/inputs/records.toml"),
        "namespace = 'org.peer-network.records.index'\nversion = [1,0,0]\n[[rows]]\npath = 'adr/007-example.md'\n",
    )?;
    documents::run(root, Operation::Generate { check: false })?;
    let template = root.join("docs/templates/adr/007-example.md.j2");
    for (source, message) in [
        ("literal record\n", "record rendering did not read its own index row"),
        (
            "{% if false %}{{ row('org.peer-network.records.index', path='adr/007-example.md') }}{% endif %}",
            "record rendering did not read its own index row",
        ),
        ("{{ rows('org.peer-network.records.index') }}", "not records-index rows"),
    ] {
        fs::write(&template, source)?;
        let error = documents::run(root, Operation::Check).expect_err("record lookup required");
        assert!(error.to_string().contains(message), "{error}");
    }
    fs::write(
        &template,
        "{{ row('org.peer-network.records.index', path='adr/007-example.md').path }}\n",
    )?;
    documents::run(root, Operation::Write)?;
    assert_eq!(documents::run(root, Operation::Check)?.findings, Vec::<Finding>::new());
    Ok(())
}

/// Claim: an unavailable Git executable makes the binary's tracked census refuse by name.
/// ´claim:render:git-required´
/// ´test:integration:git-required´
#[test]
fn git_required() -> Result<()> {
    let directory = fixture()?;
    let output = Command::new(env!("CARGO_BIN_EXE_documents"))
        .env("PATH", "")
        .arg("--root")
        .arg(directory.path())
        .arg("check")
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8(output.stderr)?.contains("git ls-files unavailable"));
    Ok(())
}
