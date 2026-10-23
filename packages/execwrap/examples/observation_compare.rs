//! Process witness for (´[ROOT-inv:observe:noninterference]´).

use cli_common::observation_export::{ExportConfig, ExportFailure, ExportTransport};
use cli_common::secrets::{PrivateString, SecretRole, SecretString};
use pn_interchange::{Content, ContentKey, Coordinate, Document, Envelope, NamespaceLabel, Registry, Theory, Value, Version};
use serde_json::json;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Debug)]
struct Unavailable;
impl ExportTransport for Unavailable {
    fn send(
        &self,
        _request: http::Request<bytes::Bytes>,
        _credential: &PrivateString,
    ) -> Result<http::Response<bytes::Bytes>, ExportFailure> {
        Err(ExportFailure::Unavailable)
    }
}

fn workload() -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let value = Value::from_canonical_bytes(&[130, 24, 42, 97, b'x'])?;
    let label = NamespaceLabel::parse("org.example")?;
    let theory = Theory::parse(r#"e = {0 => "org.example", 1 => [1, 0, uint], 2 => tstr}"#)?;
    let mut registry = Registry::new();
    registry.acquire(Coordinate::new(label.clone(), 1, 0), theory)?;
    let mut content = Content::new();
    content.insert(ContentKey::new(2)?, Value::Text("public-payload".to_owned().into()));
    let document = Document::new(Envelope::new(label, Version::new(1, 0, 0)), content);
    let verdict = pn_interchange::accept(&registry, &document);
    let fixture = std::env::args().nth(2).ok_or("document fixture path required")?;
    let docs = documents::run(Path::new(&fixture), documents::Operation::Check)?;
    let root = tempfile::tempdir()?;
    let output = root.path().join("stdout");
    let error = root.path().join("stderr");
    let config = execwrap::RoutingConfig {
        redirect_output: Some(output.clone()),
        redirect_error: Some(error.clone()),
        ..Default::default()
    };
    let child = execwrap::run(
        &[
            "sh".into(),
            "-c".into(),
            "printf 'public\\000\\377'; printf 'diagnostic' >&2; exit 7".into(),
        ],
        &config,
        |_| {},
    )?;
    Ok(
        json!({"canonical":value.to_canonical_bytes(),"verdict":format!("{verdict:?}"),"documents":docs,"child_exit":child.exit_code,"child_loss":child.data_loss,"child_stdout":std::fs::read(output)?,"child_stderr":std::fs::read(error)?}),
    )
}

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "enabled".into());
    let guard = if mode == "failing-export" {
        cli_common::observation::bootstrap_with_export(
            true,
            false,
            tracing::Level::INFO,
            ExportConfig {
                transport: Arc::new(Unavailable),
                credential: PrivateString::new(SecretRole::Authentication, SecretString::from("fixture-private-token")),
            },
        )
        .map_err(|error| error.to_string())
    } else {
        cli_common::observation::bootstrap(
            mode != "disabled",
            false,
            if mode == "sampled" {
                tracing::Level::ERROR
            } else {
                tracing::Level::INFO
            },
        )
        .map_err(str::to_owned)
    };
    match guard {
        Ok(_guard) => cli_common::run_stdout_json_command("observation-compare", false, tracing::Level::INFO, workload),
        Err(error) => cli_common::run_stdout_json_command("observation-compare", false, tracing::Level::INFO, || {
            Err::<serde_json::Value, _>(error)
        }),
    }
}
