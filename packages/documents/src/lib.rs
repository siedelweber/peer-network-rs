//! Deterministic document generation over validated, committed datasets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

mod census;
mod envelope;
mod registry;
mod rendering;
mod workspace;

/// Install the panic hook shared by the command and its subprocess probe.
/// Justified: This executable bootstrap or termination adapter surrounds installation and handoff to the labelled command boundary; pre-installation control records remain direct and process termination fabricates no completion.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
pub fn install_panic_hook() {
    cli_common::install_json_panic_hook("documents");
}

/// Failure before a complete verdict can be produced.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
/// A document operation or a named refusal.
pub type Result<T> = std::result::Result<T, Error>;

/// The requested operation.
#[derive(Clone, Copy, Debug)]
pub enum Operation {
    /// Generate datasets, optionally comparing without writes.
    Generate { check: bool },
    /// Compare dataset projections and rendered documents without writing.
    Check,
    /// Refresh differing documents and report them as findings.
    Write,
    /// Describe template and dataset dependencies.
    Census,
}

/// One template's rendered output and observed dataset dependencies.
#[derive(Debug, Serialize)]
pub struct Rendering {
    /// Repository-relative template path.
    pub template: String,
    /// Repository-relative document path.
    pub document: String,
    /// Namespaces read during rendering, in sorted order.
    pub datasets: Vec<String>,
}

/// A stable category of document drift.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// A generated dataset differs from its input projection.
    StaleDataset,
    /// A rendered document differs from its template result.
    StaleDocument,
    /// A committed dataset has no input projection.
    OrphanDataset,
    /// A template has no supported output path.
    UnrenderedTemplate,
}

/// One machine-readable finding with a repository-relative path.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable diagnostic category.
    pub kind: FindingKind,
    /// Repository-relative affected path.
    pub path: String,
}

fn at<T>(path: &Path, result: std::io::Result<T>) -> Result<T> {
    result.map_err(|error| format!("{}: {error}", path.display()).into())
}

#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "read"
    ),
    ret
)]
fn read(path: &Path) -> Result<String> {
    at(path, fs::read_to_string(path))
}

/// A complete machine-readable verdict.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// Files that differed, including files refreshed by this operation.
    pub findings: Vec<Finding>,
    /// Templates with the documents and datasets they render.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<Rendering>,
    /// Dataset namespaces and their repository-relative paths.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub datasets: BTreeMap<String, String>,
    /// Templates that cannot map to a text output.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unrendered_templates: Vec<String>,
    /// Dataset paths not read by any executed template.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unread_datasets: Vec<String>,
}

fn files(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    if !directory.exists() {
        return Ok(found);
    }
    for entry in at(directory, fs::read_dir(directory))? {
        let entry = at(directory, entry)?;
        let kind = at(&entry.path(), entry.file_type())?;
        if kind.is_symlink() {
            return Err(format!("symlink is not a document input: {}", entry.path().display()).into());
        }
        if kind.is_dir() {
            found.extend(files(&entry.path())?);
        } else if kind.is_file() {
            found.push(entry.path());
        }
    }
    found.sort();
    Ok(found)
}

fn relative(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)?
        .to_str()
        .ok_or("non-UTF-8 document path")?
        .replace('\\', "/"))
}

#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "compare"
    ),
    ret
)]
fn compare(path: &Path, bytes: &[u8], write: bool) -> Result<bool> {
    match fs::read(path) {
        Ok(current) if current == bytes => return Ok(false),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", path.display()).into()),
    }
    if write {
        cli_common::publish_batch(&[cli_common::PublicationAsset {
            role: "document output",
            path,
            bytes,
        }])
        .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(true)
}

#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "generate"
    ),
    ret
)]
fn generate(root: &Path, write: bool) -> Result<Vec<Finding>> {
    let mut projections = Vec::new();
    let mut namespaces = BTreeSet::new();
    for path in files(&root.join("docs/inputs"))? {
        if path.extension().is_none_or(|ext| ext != "toml") {
            return Err(format!("input carrier: expected TOML: {}", path.display()).into());
        }
        let dataset = envelope::input(&read(&path)?).map_err(|error| format!("{}: {error}", path.display()))?;
        if !namespaces.insert(dataset.namespace.clone()) {
            return Err(format!("duplicate dataset: {}", dataset.namespace).into());
        }
        let destination = root.join("docs/datasets").join(format!("{}.json", dataset.namespace));
        projections.push((destination, envelope::bytes(&dataset)?));
    }
    let expected: BTreeSet<_> = projections.iter().map(|(path, _)| path.clone()).collect();
    let mut findings = Vec::new();
    for path in files(&root.join("docs/datasets"))? {
        if !expected.contains(&path) {
            findings.push(Finding {
                kind: FindingKind::OrphanDataset,
                path: relative(root, &path)?,
            });
        }
    }
    for (path, bytes) in projections {
        if compare(&path, &bytes, write)? {
            findings.push(Finding {
                kind: FindingKind::StaleDataset,
                path: relative(root, &path)?,
            });
        }
    }
    Ok(findings)
}

fn validate_output(document: &str, vendors: &[PathBuf]) -> Result<()> {
    let path = Path::new(document);
    let allowed = (path.starts_with("docs") && path.extension().is_some_and(|extension| extension == "md"))
        || (path.starts_with("adr") && path.extension().is_some_and(|extension| extension == "md"))
        || matches!(
            document,
            "README.md"
                | "packages/documents/README.md"
                | "packages/interchange/README.md"
                | "packages/cli-common/README.md"
                | "packages/execwrap/README.md"
                | "packages/testkit/README.md"
                | "packages/records/README.md"
                | "packages/verification/README.md"
                | "packages/host/README.md"
                | ".linter/environments.toml"
                | ".linter/owners.toml"
                | ".linter/policies.toml"
                | ".linter/lists.toml"
                | ".linter/imports/paper.toml"
        );
    if !allowed
        || ["docs/inputs", "docs/datasets", "docs/templates", "docs/fragments"]
            .iter()
            .any(|directory| path.starts_with(directory))
        || vendors.iter().any(|vendor| path.starts_with(vendor))
    {
        return Err(format!("{document}: protected rendering output path").into());
    }
    Ok(())
}

fn validate_templates(root: &Path, template_root: &Path, paths: &[PathBuf]) -> Result<()> {
    let vendors = workspace::vendors(root)?;
    for path in paths {
        let name = relative(template_root, path)?;
        if let Some(document) = name.strip_suffix(".j2") {
            validate_output(document, &vendors)?;
        }
    }
    Ok(())
}

/// Execute one operation against an explicit repository root.
///
/// # Errors
/// Refuses malformed envelopes, invalid payloads, unreadable files, protected output paths and failed template premises.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "run"
    ),
    ret
)]
pub fn run(root: &Path, operation: Operation) -> Result<Report> {
    let template_root = root.join("docs/templates");
    let template_paths = files(&template_root)?;
    if !template_paths
        .iter()
        .any(|path| path.extension().is_some_and(|extension| extension == "j2"))
    {
        return Err(format!("{}: no text template", template_root.display()).into());
    }
    validate_templates(root, &template_root, &template_paths)?;
    let mut report = Report::default();
    if let Operation::Generate { check } = operation {
        report.findings = generate(root, !check)?;
        return Ok(report);
    }
    if matches!(operation, Operation::Check) {
        report.findings = generate(root, false)?;
    }
    let mut datasets = BTreeMap::new();
    for path in files(&root.join("docs/datasets"))? {
        let dataset = envelope::json(&read(&path)?).map_err(|error| format!("{}: {error}", path.display()))?;
        let namespace = dataset.namespace.clone();
        if datasets.insert(namespace.clone(), dataset).is_some() {
            return Err(format!("duplicate dataset: {namespace}").into());
        }
        report.datasets.insert(namespace, relative(root, &path)?);
    }
    let fragment_root = root.join("docs/fragments");
    let mut fragments = BTreeMap::new();
    for path in files(&fragment_root)? {
        let name = format!("fragments/{}", relative(&fragment_root, &path)?);
        fragments.insert(name, read(&path)?);
    }
    let mut prepared = Vec::new();
    for path in template_paths {
        let name = relative(&template_root, &path)?;
        let Some(document) = name.strip_suffix(".j2").filter(|stem| !stem.is_empty()).map(str::to_owned) else {
            report.unrendered_templates.push(relative(root, &path)?);
            continue;
        };
        let source = read(&path)?;
        let (bytes, used) = rendering::render(&source, &fragments, &datasets, &document)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        report.templates.push(Rendering {
            template: relative(root, &path)?,
            document: document.clone(),
            datasets: used,
        });
        prepared.push((root.join(document), bytes));
    }
    let used: BTreeSet<_> = report.templates.iter().flat_map(|item| item.datasets.iter()).collect();
    report.unread_datasets = report
        .datasets
        .iter()
        .filter(|(name, _)| !used.contains(name))
        .map(|(_, path)| path.clone())
        .collect();
    if matches!(operation, Operation::Check) {
        census::validate(root, &report.templates, &datasets)?;
    }
    if !matches!(operation, Operation::Census) {
        for (path, bytes) in prepared {
            if compare(&path, bytes.as_bytes(), matches!(operation, Operation::Write))? {
                report.findings.push(Finding {
                    kind: FindingKind::StaleDocument,
                    path: relative(root, &path)?,
                });
            }
        }
        report.findings.extend(report.unrendered_templates.iter().map(|path| Finding {
            kind: FindingKind::UnrenderedTemplate,
            path: path.clone(),
        }));
    }
    Ok(report)
}
