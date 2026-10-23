use std::path::{Path, PathBuf};

use crate::{Result, read};

#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "workspace::vendors"
    ),
    ret
)]
pub fn vendors(root: &Path) -> Result<Vec<PathBuf>> {
    let manifest_path = root.join("Cargo.toml");
    let manifest: toml::Value =
        toml::from_str(&read(&manifest_path)?).map_err(|error| format!("{}: {error}", manifest_path.display()))?;
    let members = manifest
        .get("workspace")
        .and_then(|table| table.get("members"))
        .and_then(toml::Value::as_array)
        .ok_or("Cargo.toml: workspace.members must be explicit member paths")?;
    let mut vendors = Vec::new();
    for member in members {
        let name = member.as_str().ok_or("Cargo.toml: member path must be a string")?;
        if name.split('/').any(|part| part.is_empty() || part == "." || part == "..") || name.contains(['*', '?', '[', '\\']) {
            return Err(format!("Cargo.toml: member path must be explicit and normalized: {name}").into());
        }
        if name.starts_with("vendor/") {
            vendors.push(PathBuf::from(name));
        }
    }
    Ok(vendors)
}
