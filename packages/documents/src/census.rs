use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::envelope::Dataset;
use crate::{Rendering, Result};

fn markdown(root: &Path) -> Result<BTreeSet<String>> {
    let vendors = crate::workspace::vendors(root)?;
    let output = std::process::Command::new("git")
        .args(["ls-files", "-z", "--full-name"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("{}: git ls-files unavailable: {error}", root.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{}: git ls-files failed: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let mut found = BTreeSet::new();
    for bytes in output.stdout.split(|byte| *byte == 0).filter(|bytes| !bytes.is_empty()) {
        let name = std::str::from_utf8(bytes).map_err(|error| format!("git ls-files: non-UTF-8 path: {error}"))?;
        let path = Path::new(name);
        if path.extension().is_some_and(|extension| extension == "md") && !vendors.iter().any(|vendor| path.starts_with(vendor)) {
            found.insert(name.to_owned());
        }
    }
    Ok(found)
}

pub fn record(path: &str) -> bool {
    path.strip_prefix("adr/").is_some_and(|name| {
        name.as_bytes()
            .get(..3)
            .is_some_and(|digits| digits.iter().all(u8::is_ascii_digit))
            && name.as_bytes().get(3) == Some(&b'-')
            && Path::new(name).extension().is_some_and(|extension| extension == "md")
    })
}

pub fn validate(root: &Path, templates: &[Rendering], datasets: &BTreeMap<String, Dataset>) -> Result<()> {
    let documents: BTreeSet<_> = templates.iter().map(|item| item.document.clone()).collect();
    let authored = markdown(root)?;
    if let Some(path) = authored.difference(&documents).next() {
        return Err(format!("{path}: first-party Markdown has no template").into());
    }
    let records: BTreeSet<_> = documents.iter().filter(|path| record(path)).cloned().collect();
    let mut indexed = BTreeSet::new();
    if let Some(dataset) = datasets.get("org.peer-network.records.index") {
        for row in &dataset.rows {
            let path = row
                .get("path")
                .and_then(serde_json::Value::as_str)
                .ok_or("records index: missing path")?;
            if !indexed.insert(path.to_owned()) {
                return Err(format!("{path}: duplicate record index row").into());
            }
        }
    }
    if let Some(path) = records.difference(&indexed).next() {
        return Err(format!("{path}: record template has no index row").into());
    }
    if let Some(path) = indexed.difference(&records).next() {
        return Err(format!("{path}: index row has no record template").into());
    }
    for template in templates.iter().filter(|template| record(&template.document)) {
        if !template.datasets.iter().any(|name| name == "org.peer-network.records.index") {
            return Err(format!("{}: record rendering did not read its own index row", template.document).into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::record;

    /// Claim: Only a three-digit ADR filename with the Markdown extension enters the record index.
    /// ´claim:render:record-name-boundary´
    /// ´test:unit:record-name-boundary´
    #[test]
    fn record_name_boundary() {
        assert!(record("adr/020-testing-harness.md"));
        for path in [
            "adr/20-short.md",
            "adr/0200-long.md",
            "adr/020-title.txt",
            "docs/020-title.md",
            "adr/abc-title.md",
        ] {
            assert!(!record(path), "unexpected record: {path}");
        }
    }
}
