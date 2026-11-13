use std::io;
use std::path::{Component, Path, PathBuf};

/// A path selected from the running test's package and runner environment.
/// (´def:testkit:runtime-path´)
#[derive(Clone, Copy)]
pub enum RuntimePath<'a> {
    /// A relative path within the validated workspace.
    Workspace(&'a str),
    /// A relative path within the running test's package.
    Package(&'a str),
    /// A binary target supplied by the runner, outside the workspace if needed.
    Executable(&'a str),
}

/// Resolve a test path from runtime Cargo variables without a compiled fallback.
/// (´def:testkit:runtime-path´)
///
/// # Errors
/// Refuses absent or foreign package/workspace identity, escaping relative paths,
/// and absent or non-file executable targets, naming the input and remedy.
pub fn runtime_path(request: RuntimePath<'_>) -> io::Result<PathBuf> {
    let refuse = |found: String| {
        io::Error::other(format!(
            "expected a runner-provided Peer Network workspace and package; found {found}; run through cargo test or nextest with this checkout's metadata (use workspace remapping for an archive)"
        ))
    };
    let supplied = std::env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| refuse("CARGO_MANIFEST_DIR absent".into()))?;
    let supplied = PathBuf::from(supplied);
    if !supplied.is_absolute() {
        return Err(refuse(format!("CARGO_MANIFEST_DIR={}, not absolute", supplied.display())));
    }
    let package = supplied
        .canonicalize()
        .map_err(|error| refuse(format!("CARGO_MANIFEST_DIR={}: {error}", supplied.display())))?;
    let packages = package
        .parent()
        .ok_or_else(|| refuse(format!("package={}, no parent", package.display())))?;
    let root = packages
        .parent()
        .ok_or_else(|| refuse(format!("package={}, no workspace parent", package.display())))?;
    let name = std::env::var("CARGO_PKG_NAME").map_err(|error| refuse(format!("CARGO_PKG_NAME: {error}")))?;
    let read = |path: &Path| std::fs::read_to_string(path).map_err(|error| refuse(format!("{}: {error}", path.display())));
    let workspace = read(&root.join("Cargo.toml"))?;
    let manifest = read(&package.join("Cargo.toml"))?;
    let support = read(&root.join("packages/testkit/Cargo.toml"))?;
    let member = format!("\"packages/{}\"", package.file_name().unwrap_or_default().to_string_lossy());
    if packages.file_name().is_none_or(|value| value != "packages")
        || !workspace.lines().any(|line| line == "[workspace]")
        || !workspace.contains("\"Peer Network contributors\"")
        || !workspace
            .lines()
            .any(|line| line.starts_with("members = ") && line.contains(&member) && line.contains("\"packages/testkit\""))
        || !manifest.lines().any(|line| line == format!("name = \"{name}\""))
        || !support.lines().any(|line| line == "name = \"pn-testkit\"")
    {
        return Err(refuse(format!(
            "CARGO_MANIFEST_DIR={}, CARGO_PKG_NAME={name:?}, foreign workspace/package declaration",
            supplied.display()
        )));
    }
    let (base, relative) = match request {
        RuntimePath::Workspace(relative) => (root, relative),
        RuntimePath::Package(relative) => (package.as_path(), relative),
        RuntimePath::Executable(name) => {
            if name.is_empty()
                || !Path::new(name).components().all(|part| matches!(part, Component::Normal(_)))
                || Path::new(name).components().count() != 1
            {
                return Err(refuse(format!("invalid binary target name {name:?}")));
            }
            let variable = format!("CARGO_BIN_EXE_{name}");
            let value = std::env::var_os(&variable)
                .ok_or_else(|| refuse(format!("{variable} absent; select the binary's integration tests")))?;
            let path = PathBuf::from(value);
            if !path.is_absolute() || !path.is_file() {
                return Err(refuse(format!(
                    "{variable}={}, expected an absolute existing executable file",
                    path.display()
                )));
            }
            return Ok(path);
        }
    };
    if !Path::new(relative)
        .components()
        .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return Err(refuse(format!("relative path {relative:?} escapes its selected root")));
    }
    let result = base.join(relative);
    let existing = result
        .ancestors()
        .find(|path| path.symlink_metadata().is_ok())
        .ok_or_else(|| refuse(format!("{}, no existing ancestor", result.display())))?;
    let actual = existing
        .canonicalize()
        .map_err(|error| refuse(format!("{}: {error}", existing.display())))?;
    if !actual.starts_with(base) {
        return Err(refuse(format!(
            "{} resolves outside {} through {}",
            result.display(),
            base.display(),
            actual.display()
        )));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Claim: A subprocess of the already built helper reads a distinct runtime workspace's marker, selects its runtime binary path, and refuses an absent source or foreign workspace without reading the build tree.
    /// ´claim:testkit:runtime-workspace-controls-paths´
    /// ´test:unit:workspace-relocation´
    #[test]
    fn workspace_relocation() -> io::Result<()> {
        if let Ok(mode) = std::env::var("PN_TEST_WORKSPACE_MODE") {
            match mode.as_str() {
                "moved" => {
                    let marker = runtime_path(RuntimePath::Workspace("runtime-marker")).and_then(std::fs::read_to_string);
                    assert_eq!(
                        marker.as_deref().ok(),
                        Some("runtime workspace marker"),
                        "runtime marker: {marker:?}"
                    );
                    assert_eq!(
                        runtime_path(RuntimePath::Package(""))?,
                        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
                    );
                    assert_eq!(
                        runtime_path(RuntimePath::Executable("fixture"))?,
                        PathBuf::from(std::env::var_os("CARGO_BIN_EXE_fixture").unwrap())
                    );
                    assert!(runtime_path(RuntimePath::Workspace("../foreign")).is_err());
                    assert!(
                        runtime_path(RuntimePath::Executable("absent-fixture"))
                            .unwrap_err()
                            .to_string()
                            .contains("CARGO_BIN_EXE_absent-fixture absent")
                    );
                }
                "absent" => assert!(
                    runtime_path(RuntimePath::Workspace(""))
                        .unwrap_err()
                        .to_string()
                        .contains("CARGO_MANIFEST_DIR absent")
                ),
                "foreign" => assert!(
                    runtime_path(RuntimePath::Workspace(""))
                        .unwrap_err()
                        .to_string()
                        .contains("foreign workspace/package declaration")
                ),
                _ => return Err(io::Error::other(format!("unknown runtime workspace control {mode}"))),
            }
            return Ok(());
        }
        let source = runtime_path(RuntimePath::Workspace(""))?;
        let temporary = std::env::temp_dir().join(format!("runtime-workspace-{}", std::process::id()));
        std::fs::create_dir(&temporary)?;
        let result = (|| {
            let package = temporary.join("packages/testkit");
            std::fs::create_dir_all(&package)?;
            std::fs::copy(source.join("Cargo.toml"), temporary.join("Cargo.toml"))?;
            std::fs::copy(source.join("packages/testkit/Cargo.toml"), package.join("Cargo.toml"))?;
            std::fs::write(temporary.join("runtime-marker"), "runtime workspace marker")?;
            let binary = temporary.join("fixture");
            std::fs::write(&binary, "runtime executable marker")?;
            for mode in ["moved", "absent", "foreign"] {
                if mode == "foreign" {
                    std::fs::write(
                        temporary.join("Cargo.toml"),
                        "[workspace]\nmembers = [\"packages/testkit\"]\n",
                    )?;
                }
                let mut command = std::process::Command::new(std::env::current_exe()?);
                command
                    .args(["--exact", "paths::tests::workspace_relocation", "--nocapture"])
                    .env("PN_TEST_WORKSPACE_MODE", mode)
                    .env("CARGO_MANIFEST_DIR", &package)
                    .env("CARGO_PKG_NAME", "pn-testkit")
                    .env("CARGO_BIN_EXE_fixture", &binary)
                    .env_remove("CARGO_BIN_EXE_absent-fixture");
                if mode == "absent" {
                    command.env_remove("CARGO_MANIFEST_DIR");
                }
                let output = command.output()?;
                assert!(
                    output.status.success(),
                    "runtime workspace control {mode}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Ok(())
        })();
        std::fs::remove_dir_all(temporary)?;
        result
    }
}
