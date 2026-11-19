//! Regenerate or compare the admitted control register artifact.
//! (´[ROOT-dec:api:schema]´)

use std::path::PathBuf;

/// Publish or compare the artifact using an explicit workspace root and mode.
///
/// # Errors
/// Refuses missing arguments, unreadable source, failed publication, or a different artifact.
pub(crate) fn run(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let root = PathBuf::from(args.next().ok_or("expected explicit workspace root")?);
    let mode = args.next().ok_or("expected write or check")?;
    if args.next().is_some() || (mode != "write" && mode != "check") {
        return Err("expected workspace root and write or check".into());
    }
    let source = std::fs::read_to_string(root.join("packages/node/schema/control-register.toml"))?;
    let bytes = pn_interchange::control_register::encode(&source)?;
    let path = root.join("packages/interchange/schema/control-register.cbor");
    if mode == "write" {
        cli_common::publish_batch(&[cli_common::PublicationAsset {
            role: "control register",
            path: &path,
            bytes: &bytes,
        }])?;
    } else if std::fs::read(&path)? != bytes {
        return Err("control register artifact differs from its source projection".into());
    }
    Ok(serde_json::json!({"artifact":"control register","bytes":bytes.len(),"mode":mode.to_string_lossy()}))
}

#[cfg(not(test))]
fn main() -> std::process::ExitCode {
    cli_common::run_stdout_json_command("control-register", false, tracing::Level::INFO, || {
        run(std::env::args_os().skip(1))
    })
}
