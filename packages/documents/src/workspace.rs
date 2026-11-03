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
    let manifest_path = root.join("ci/vendor-packages.toml");
    let manifest: toml::Value =
        toml::from_str(&read(&manifest_path)?).map_err(|error| format!("{}: {error}", manifest_path.display()))?;
    let packages = manifest
        .get("packages")
        .and_then(toml::Value::as_array)
        .ok_or("ci/vendor-packages.toml: packages must be an explicit list")?;
    let mut vendors = Vec::new();
    for package in packages {
        let name = package
            .get("path")
            .and_then(toml::Value::as_str)
            .ok_or("ci/vendor-packages.toml: package path must be a string")?;
        if !name.starts_with("vendor/")
            || name.split('/').any(|part| part.is_empty() || part == "." || part == "..")
            || name.contains(['*', '?', '[', '\\'])
        {
            return Err(format!("ci/vendor-packages.toml: package path must be explicit and normalized: {name}").into());
        }
        vendors.push(PathBuf::from(name));
    }
    Ok(vendors)
}
