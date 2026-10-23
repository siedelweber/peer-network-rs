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
    let mode = std::env::args().nth(1).unwrap_or_else(|| "default".into());
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
    } else {
        cli_common::observation::bootstrap(mode != "disabled", false, tracing::Level::INFO)
    };
    let observation_guard = match guard {
        Ok(guard) => Some(guard),
        Err(cli_common::observation::BootstrapError::Unavailable(_)) => None,
        Err(error @ cli_common::observation::BootstrapError::Configuration(_)) => {
            let mut record = cli_common::ControlPlaneRecord::usage_error("observation-compare", "observation_configuration");
            record.message = error.to_string();
            let _ignored = cli_common::emit_control_plane_record(&record);
            return cli_common::CommandExit::Usage.exit_code();
        }
    };
    // This executable already owns bootstrap. The convenience command runner
    // would bootstrap again and turn the disabled comparison back on.
    let exit = match workload() {
        Ok(output) => match cli_common::emit(&output) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        Err(_) => ExitCode::FAILURE,
    };
    if std::env::var_os("PN_TEST_OBSERVATION_RENDEZVOUS").is_some() {
        drop(observation_guard);
        // The process fixture releases this read after receiving its final status.
        // This is test ordering, not a longer production drain deadline.
        let mut released = [0];
        let _ignored = std::io::Read::read_exact(&mut std::io::stdin(), &mut released);
    }
    exit
}
