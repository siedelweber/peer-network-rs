#![doc = include_str!("../README.md")]

use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

use clap::{CommandFactory, Parser};
use serde::{Deserialize, Serialize};

pub mod observation;
pub mod observation_export;
mod observation_metrics;
mod publication;
pub mod secrets;

pub use publication::{
    BatchPublicationError, PublicationAsset, PublicationChange, PublicationMode, PublicationResult, publish_batch,
    set_publication_mode,
};

#[cfg(test)]
mod tests;

/// Schema version for shared JSON control-plane records.
pub const CONTROL_PLANE_SCHEMA: u32 = 1;

static PANIC_REPORTED: AtomicBool = AtomicBool::new(false);
static STDERR_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Baseline exit-code classes for command-line tools.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandExit {
    /// Successful completion.
    Success,
    /// Runtime, startup, internal, or command execution failure.
    Failure,
    /// Command-line usage failure, including clap errors and TTY refusal.
    Usage,
}

impl CommandExit {
    /// Return the numeric process status for this exit class.
    #[must_use]
    /// Justified: Const evaluation cannot emit runtime events; the caller operation accounts its execution without changing this compile-time contract.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Usage => 2,
        }
    }

    /// Return this class as a standard library [`ExitCode`].
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "CommandExit::exit_code"
        ),
        ret
    )]
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(self.code())
    }

    /// Map a numeric status back to a shared exit class.
    #[must_use]
    /// Justified: Const evaluation cannot emit runtime events; the caller operation accounts its execution without changing this compile-time contract.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Success),
            1 => Some(Self::Failure),
            2 => Some(Self::Usage),
            _ => None,
        }
    }
}

/// JSON control-plane record kinds emitted on stderr.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneRecordKind {
    /// Help text requested by the caller.
    Help,
    /// Version information requested by the caller.
    Version,
    /// Command-line usage or argv parsing failure.
    UsageError,
    /// Refusal to write stdout result data directly to a terminal.
    TtyRefusal,
    /// Panic diagnostic emitted by the shared panic hook.
    Panic,
    /// Non-error status update.
    Status,
    /// Runtime diagnostic or error.
    Diagnostic,
}

/// Standard streams referenced by control-plane records.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StandardStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Structured fields attached to a control-plane record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlPlaneFields {
    /// Help text returned by clap or a command-specific renderer.
    Help { text: String },
    /// Version string returned by clap or the command.
    Version { version: String },
    /// Details for an argv parsing or usage error.
    UsageError { exit_code: u8, clap_error_kind: String },
    /// Details for stdout TTY refusal.
    TtyRefusal { exit_code: u8, stream: StandardStream },
    /// Details for a panic diagnostic, including every available public string payload.
    Panic {
        exit_code: u8,
        thread: Option<String>,
        location: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        payload: Option<String>,
    },
}

/// Shared JSON control-plane record written to stderr.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneRecord {
    /// Record schema version.
    pub schema: u32,
    /// Binary or entrypoint name.
    pub command: String,
    /// Machine-readable record kind.
    pub kind: ControlPlaneRecordKind,
    /// Short human-readable message, still carried inside JSON.
    pub message: String,
    /// Complete public argv bytes on usage failure, including values clap may abbreviate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<Vec<u8>>>,
    /// Kind-specific structured fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<ControlPlaneFields>,
}

impl ControlPlaneRecord {
    /// Build a generic control-plane record.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "ControlPlaneRecord::new"
        ),
        ret
    )]
    pub fn new(command: &str, kind: ControlPlaneRecordKind, message: &str, fields: Option<ControlPlaneFields>) -> Self {
        Self {
            schema: CONTROL_PLANE_SCHEMA,
            command: command.to_string(),
            kind,
            message: message.to_string(),
            arguments: None,
            fields,
        }
    }

    /// Build a help record.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "ControlPlaneRecord::help"
        ),
        ret
    )]
    pub fn help(command: &str, text: &str) -> Self {
        Self::new(
            command,
            ControlPlaneRecordKind::Help,
            "help requested",
            Some(ControlPlaneFields::Help { text: text.to_string() }),
        )
    }

    /// Build a version record.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "ControlPlaneRecord::version"
        ),
        ret
    )]
    pub fn version(command: &str, version: &str) -> Self {
        Self::new(
            command,
            ControlPlaneRecordKind::Version,
            "version requested",
            Some(ControlPlaneFields::Version {
                version: version.to_string(),
            }),
        )
    }

    /// Build an argv usage-error record.
    ///
    /// The constructor supplies a generic message; parser callers replace it
    /// with the complete public diagnostic under (´[ROOT-rule:observe:privacy]´).
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "ControlPlaneRecord::usage_error"
        ),
        ret
    )]
    pub fn usage_error(command: &str, clap_error_kind: &str) -> Self {
        Self::new(
            command,
            ControlPlaneRecordKind::UsageError,
            "invalid command-line arguments",
            Some(ControlPlaneFields::UsageError {
                exit_code: CommandExit::Usage.code(),
                clap_error_kind: clap_error_kind.to_string(),
            }),
        )
    }

    /// Build a stdout TTY-refusal record.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "ControlPlaneRecord::tty_refusal"
        ),
        ret
    )]
    pub fn tty_refusal(command: &str) -> Self {
        Self::new(
            command,
            ControlPlaneRecordKind::TtyRefusal,
            "stdout is a terminal; pipe to a file or another process",
            Some(ControlPlaneFields::TtyRefusal {
                exit_code: CommandExit::Usage.code(),
                stream: StandardStream::Stdout,
            }),
        )
    }

    /// Build a panic diagnostic record.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "ControlPlaneRecord::panic"
        ),
        ret
    )]
    pub fn panic(command: &str, thread: Option<&str>, location: Option<&str>, payload: Option<&str>) -> Self {
        Self::new(
            command,
            ControlPlaneRecordKind::Panic,
            "unexpected panic",
            Some(ControlPlaneFields::Panic {
                exit_code: CommandExit::Failure.code(),
                thread: thread.map(str::to_string),
                location: location.map(str::to_string),
                payload: payload.map(str::to_string),
            }),
        )
    }

    /// Build a non-error status record.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "ControlPlaneRecord::status"
        ),
        ret
    )]
    pub fn status(command: &str, message: &str) -> Self {
        Self::new(command, ControlPlaneRecordKind::Status, message, None)
    }

    /// Build a runtime diagnostic record.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "ControlPlaneRecord::diagnostic"
        ),
        ret
    )]
    pub fn diagnostic(command: &str, message: &str) -> Self {
        Self::new(command, ControlPlaneRecordKind::Diagnostic, message, None)
    }
}

/// Control-plane record and exit class produced while parsing argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliExit {
    /// Record to write to stderr.
    pub record: ControlPlaneRecord,
    /// Process exit class to use after writing the record.
    pub exit: CommandExit,
}

impl CliExit {
    /// Build a new parse-control exit value.
    #[must_use]
    /// Justified: Const evaluation cannot emit runtime events; the caller operation accounts its execution without changing this compile-time contract.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub const fn new(record: ControlPlaneRecord, exit: CommandExit) -> Self {
        Self { record, exit }
    }

    /// Return this exit class as a standard library [`ExitCode`].
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "CLICOMMON",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "CliExit::exit_code"
        ),
        ret
    )]
    pub fn exit_code(&self) -> ExitCode {
        self.exit.exit_code()
    }
}

/// Source used to choose the JSON tracing filter directive.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TracingFilterSource {
    /// The `RUST_LOG` environment variable supplied the directive.
    RustLog,
    /// The shared `--debug` flag selected debug logging.
    DebugFlag,
    /// The caller-supplied default level was used.
    DefaultLevel,
}

/// Resolved JSON tracing filter directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracingFilter {
    /// Directive passed to `tracing-subscriber`'s environment filter.
    pub directive: String,
    /// Input source that selected the directive.
    pub source: TracingFilterSource,
}

impl TracingFilter {
    /// Build a resolved tracing filter directive.
    #[must_use]
    pub fn new(directive: impl Into<String>, source: TracingFilterSource) -> Self {
        let scope = crate::observation::scope(
            "CLICOMMON",
            "rule:observe:spans",
            "TracingFilter::new",
            &("Into<String> capability", source),
        );
        let result = {
            Self {
                directive: directive.into(),
                source,
            }
        };
        scope.finish(&result);
        result
    }
}

/// Resolve the JSON tracing filter using the precedence in (´[ROOT-rec:output:decision]´).
///
/// `RUST_LOG` wins when set and non-empty. Otherwise `--debug` selects `debug`,
/// and the caller-supplied default level is used last.
#[must_use]
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "CLICOMMON",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "tracing_filter"
    ),
    ret
)]
pub fn tracing_filter(debug_enabled: bool, default_level: tracing::Level) -> TracingFilter {
    tracing_filter_from_rust_log(std::env::var_os("RUST_LOG").as_deref(), debug_enabled, default_level)
}

fn tracing_filter_from_rust_log(rust_log: Option<&OsStr>, debug: bool, default_level: tracing::Level) -> TracingFilter {
    if let Some(value) = rust_log {
        let directive = value.to_string_lossy();
        let trimmed = directive.trim();
        if !trimmed.is_empty() {
            return TracingFilter::new(trimmed, TracingFilterSource::RustLog);
        }
    }

    if debug {
        TracingFilter::new("debug", TracingFilterSource::DebugFlag)
    } else {
        TracingFilter::new(level_directive(default_level), TracingFilterSource::DefaultLevel)
    }
}

fn level_directive(level: tracing::Level) -> String {
    level.as_str().to_ascii_lowercase()
}

/// Read a sole `--version` argument without adopting or changing a parser.
///
/// `args` excludes the executable name. Metadata belongs to the caller: pass
/// its manifest package and version, and its compiled source commit if present.
/// Other argument shapes return `None` without emitting output.
#[must_use]
pub fn version_exit_from<I, A>(args: I, command: &str, package: &str, version: &str, commit: Option<&str>) -> Option<CliExit>
where
    I: IntoIterator<Item = A>,
    A: AsRef<OsStr>,
{
    let scope = crate::observation::scope(
        "CLICOMMON",
        "rule:observe:spans",
        "version_exit_from",
        &(
            command,
            package,
            version,
            commit,
            "lazy argument iterator; only consumed arguments are observed",
        ),
    );
    let result = (|| {
        let mut args = args
            .into_iter()
            .inspect(|argument| tracing::info!(argument=?argument.as_ref()));
        if args.next()?.as_ref() != OsStr::new("--version") || args.next().is_some() {
            return None;
        }
        let version = commit.map_or_else(
            || format!("{package} {version}"),
            |commit| format!("{package} {version} (commit {commit})"),
        );
        Some(CliExit::new(
            ControlPlaneRecord::version(command, &version),
            CommandExit::Success,
        ))
    })();
    scope.finish(&result);
    result
}

/// Answer a sole process `--version` argument on stderr and exit successfully.
///
/// Call before startup work or other argv reading. Callers with argv0-based
/// forwarding must classify that mode first and leave forwarded argv alone.
/// Nonmatching argv returns normally; failure to emit the record exits 1.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "CLICOMMON",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "version_or_exit"
    ),
    ret
)]
pub fn version_or_exit(command: &str, package: &str, version: &str, commit: Option<&str>) {
    if let Some(exit) = version_exit_from(std::env::args_os().skip(1), command, package, version, commit) {
        let status = if emit_control_plane_record(&exit.record).is_ok() {
            exit.exit
        } else {
            CommandExit::Failure
        };
        exit_with(status);
    }
}

/// Parse argv with `clap`, converting help, version, and usage errors into
/// JSON control-plane records as required by (´[ROOT-rec:output:decision]´).
///
/// # Errors
///
/// Returns [`CliExit`] when parsing should stop and the caller should write the
/// enclosed record to stderr before exiting with the enclosed exit class.
/// The error value is intentionally returned by value because this path is only
/// used when parsing stops, and boxing it would complicate the public helper API.
// Justified: Parsing stops on this error path and returning the record by value preserves the public API.
#[allow(clippy::result_large_err)]
pub fn parse_args_from<T, I, A>(args: I) -> Result<T, CliExit>
where
    T: Parser,
    I: IntoIterator<Item = A>,
    A: Into<OsString> + Clone,
{
    let scope = crate::observation::scope(
        "CLICOMMON",
        "rule:observe:spans",
        "parse_args_from",
        &("argument iterator", std::any::type_name::<T>()),
    );
    let result = {
        let arguments: Vec<OsString> = args.into_iter().map(Into::into).collect();
        tracing::info!(arguments=?arguments);
        T::try_parse_from(&arguments).map_err(|clap_error| {
            let mut exit = cli_exit_from_clap_error::<T>(&clap_error);
            if exit.exit == CommandExit::Usage {
                exit.record.arguments = Some(
                    arguments
                        .iter()
                        .map(|argument| argument.as_encoded_bytes().to_vec())
                        .collect(),
                );
            }
            exit
        })
    };
    scope.finish(
        &result
            .as_ref()
            .map(|_| "parsed value has a Parser-only representation contract"),
    );
    result
}

/// Parse process argv with `clap`, emitting JSON control-plane records and
/// exiting for help, version, or usage errors (´[ROOT-rec:output:decision]´).
#[must_use]
pub fn parse_args_or_exit<T>() -> T
where
    T: Parser,
{
    let scope = crate::observation::scope(
        "CLICOMMON",
        "rule:observe:spans",
        "parse_args_or_exit",
        &std::any::type_name::<T>(),
    );
    let result = {
        match parse_args_from::<T, _, _>(std::env::args_os()) {
            Ok(args) => args,
            Err(exit) => {
                let _ignored = emit_control_plane_record(&exit.record);
                exit_with(exit.exit);
            }
        }
    };
    scope.finish(&"parsed value has a Parser-only representation contract");
    result
}

fn cli_exit_from_clap_error<T>(clap_error: &clap::Error) -> CliExit
where
    T: CommandFactory,
{
    let command_name = T::command().get_name().to_string();
    let text = clap_error.to_string().trim_end().to_string();

    match clap_error.kind() {
        clap::error::ErrorKind::DisplayHelp => CliExit::new(ControlPlaneRecord::help(&command_name, &text), CommandExit::Success),
        clap::error::ErrorKind::DisplayVersion => {
            CliExit::new(ControlPlaneRecord::version(&command_name, &text), CommandExit::Success)
        }
        _ => {
            let mut record = ControlPlaneRecord::usage_error(&command_name, &clap_error_kind_name(clap_error.kind()));
            record.message = text;
            CliExit::new(record, CommandExit::Usage)
        }
    }
}

fn clap_error_kind_name(kind: clap::error::ErrorKind) -> String {
    debug_name_to_snake_case(&format!("{kind:?}"))
}

fn debug_name_to_snake_case(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut previous_was_lower_or_digit = false;

    for character in name.chars() {
        if character.is_ascii_uppercase() {
            if !normalized.is_empty() && previous_was_lower_or_digit {
                normalized.push('_');
            }
            normalized.push(character.to_ascii_lowercase());
            previous_was_lower_or_digit = false;
        } else {
            normalized.push(character);
            previous_was_lower_or_digit = character.is_ascii_lowercase() || character.is_ascii_digit();
        }
    }

    normalized
}

/// Write one control-plane JSON record to stderr.
///
/// This helper does not depend on `tracing`, so it is safe for clap help,
/// clap parse errors, early startup failures, TTY refusal, and panic hooks.
///
/// # Errors
///
/// Returns an error if serialisation or writing to stderr fails.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "CLICOMMON",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "emit_control_plane_record"
    ),
    ret
)]
pub fn emit_control_plane_record(record: &ControlPlaneRecord) -> io::Result<()> {
    let mut writer = LockedStderrWriter::locked_stderr();
    write_json_line(&mut writer, record)
}

fn try_emit_control_plane_record(record: &ControlPlaneRecord) -> io::Result<bool> {
    let Some(mut writer) = LockedStderrWriter::try_locked_stderr() else {
        return Ok(false);
    };

    write_json_line(&mut writer, record)?;
    Ok(true)
}

fn write_json_line<W: Write, T: serde::Serialize>(writer: &mut W, value: &T) -> io::Result<()> {
    let json = serde_json::to_string(value)?;
    tracing::info!(public_json = %json);
    writer.write_all(json.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Install a JSON-only panic hook for command-line entrypoints.
///
/// The hook emits one best-effort control-plane record on stderr and terminates
/// the process with exit code 1 without invoking Rust's default text panic hook.
/// Justified: This executable bootstrap or termination adapter surrounds installation and handoff to the labelled command boundary; pre-installation control records remain direct and process termination fabricates no completion.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
pub fn install_json_panic_hook(command_name: &str) {
    let command_name = command_name.to_string();
    std::panic::set_hook(Box::new(move |panic_info| {
        if !PANIC_REPORTED.swap(true, Ordering::SeqCst) {
            let current_thread = std::thread::current();
            let thread_name = current_thread.name();
            let location = panic_info
                .location()
                .map(|location| format!("{}:{}:{}", location.file(), location.line(), location.column()));
            let payload = panic_payload_message(panic_info);
            let record = ControlPlaneRecord::panic(&command_name, thread_name, location.as_deref(), payload);
            let _ignored = try_emit_control_plane_record(&record);
        }

        exit_with(CommandExit::Failure);
    }));
}

fn panic_payload_message<'a>(info: &'a std::panic::PanicHookInfo<'_>) -> Option<&'a str> {
    panic_payload_message_from_payload(info.payload())
}

fn panic_payload_message_from_payload(payload: &(dyn std::any::Any + Send)) -> Option<&str> {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
}

/// Exit the current process with a command-line exit class.
// Justified: This single termination boundary implements the command-line contract after controlled JSON emission.
#[allow(clippy::exit)]
/// Justified: This executable bootstrap or termination adapter surrounds installation and handoff to the labelled command boundary; pre-installation control records remain direct and process termination fabricates no completion.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
pub fn exit_with(exit: CommandExit) -> ! {
    std::process::exit(i32::from(exit.code()));
}

/// Return a TTY-refusal record when stdout is attached to a terminal.
#[must_use]
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "CLICOMMON",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "stdout_tty_refusal_record"
    ),
    ret
)]
pub fn stdout_tty_refusal_record(command_name: &str) -> Option<ControlPlaneRecord> {
    if io::stdout().is_terminal() {
        Some(ControlPlaneRecord::tty_refusal(command_name))
    } else {
        None
    }
}

/// Refuse to run if stdout is a terminal (´[ROOT-rec:output:decision]´).
///
/// Emits a JSON control-plane record on stderr and exits with code 2.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "CLICOMMON",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "refuse_if_stdout_is_tty"
    ),
    ret
)]
pub fn refuse_if_stdout_is_tty(binary_name: &str) {
    if let Some(record) = stdout_tty_refusal_record(binary_name) {
        let _ignored = emit_control_plane_record(&record);
        exit_with(CommandExit::Usage);
    }
}

/// Initialise `tracing-subscriber` with JSON output on stderr.
/// Justified: This executable bootstrap or termination adapter surrounds installation and handoff to the labelled command boundary; pre-installation control records remain direct and process termination fabricates no completion.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
pub fn init_json_tracing(level: tracing::Level) {
    let _installed = try_init_json_tracing(level);
}

/// Try to initialise `tracing-subscriber` with JSON output on stderr.
///
/// Returns `false` if another subscriber is already installed.
#[must_use]
/// Justified: This executable bootstrap or termination adapter surrounds installation and handoff to the labelled command boundary; pre-installation control records remain direct and process termination fabricates no completion.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
pub fn try_init_json_tracing(level: tracing::Level) -> bool {
    observation::bootstrap(true, false, level).is_ok()
}

/// Initialise JSON stderr tracing with `RUST_LOG` / `--debug` precedence.
/// Justified: This executable bootstrap or termination adapter surrounds installation and handoff to the labelled command boundary; pre-installation control records remain direct and process termination fabricates no completion.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
pub fn init_json_tracing_with_debug(debug: bool, default_level: tracing::Level) {
    let _installed = try_init_json_tracing_with_debug(debug, default_level);
}

/// Try to initialise JSON stderr tracing with `RUST_LOG` / `--debug` precedence.
///
/// Returns `false` if another subscriber is already installed.
#[must_use]
/// Justified: This executable bootstrap or termination adapter surrounds installation and handoff to the labelled command boundary; pre-installation control records remain direct and process termination fabricates no completion.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
pub fn try_init_json_tracing_with_debug(debug: bool, default_level: tracing::Level) -> bool {
    observation::bootstrap(true, debug, default_level).is_ok()
}

/// Serialise `value` as one JSON object + trailing newline to stdout.
///
/// # Errors
///
/// Returns an error if serialisation or writing to stdout fails.
pub fn emit<T: serde::Serialize>(value: &T) -> io::Result<()> {
    let scope = crate::observation::scope("CLICOMMON", "rule:observe:spans", "emit", &std::any::type_name::<T>());
    let result = {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        write_json_line(&mut out, value)
    };
    scope.finish(&result);
    result
}

/// Run a stdout-producing single-JSON-object command.
///
/// The runner installs the JSON panic hook, initialises JSON stderr tracing,
/// refuses terminal stdout, writes successful result data to stdout, and maps
/// failures to the baseline exit classes in (´[ROOT-rec:output:decision]´).
pub fn run_stdout_json_command<Output, CommandError, Run>(
    command_name: &str,
    debug: bool,
    default_level: tracing::Level,
    run: Run,
) -> ExitCode
where
    Output: serde::Serialize,
    CommandError: std::fmt::Display,
    Run: FnOnce() -> Result<Output, CommandError>,
{
    install_json_panic_hook(command_name);
    let _observation_guard = observation::bootstrap(true, debug, default_level).ok();
    let scope = crate::observation::scope(
        "CLICOMMON",
        "rule:observe:spans",
        "run_stdout_json_command",
        &(command_name, debug, default_level, std::any::type_name::<Run>()),
    );
    let result = (|| {
        if let Some(record) = stdout_tty_refusal_record(command_name) {
            let _ignored = emit_control_plane_record(&record);
            return CommandExit::Usage.exit_code();
        }

        match run() {
            Ok(output) => match emit(&output) {
                Ok(()) => CommandExit::Success.exit_code(),
                Err(error) => {
                    tracing::error!(error = %error, "failed to write JSON to stdout");
                    CommandExit::Failure.exit_code()
                }
            },
            Err(error) => {
                // Public error text is recorded without rewriting (´[ROOT-rule:observe:privacy]´).
                tracing::error!(error = %error, "command failed");
                CommandExit::Failure.exit_code()
            }
        }
    })();
    scope.finish_with(
        if result == ExitCode::SUCCESS {
            observation::Outcome::Success
        } else if result == ExitCode::from(2) || result == ExitCode::from(3) {
            observation::Outcome::Refusal
        } else {
            observation::Outcome::Error
        },
        &result,
    );
    result
}

/// Run a side-effect command that does not emit stdout result data.
///
/// The runner installs the JSON panic hook, initialises JSON stderr tracing, and
/// maps failures to the baseline exit classes in (´[ROOT-rec:output:decision]´). It deliberately does not
/// perform stdout TTY refusal because the command has no stdout result data.
pub fn run_no_stdout_command<CommandError, Run>(
    command_name: &str,
    debug: bool,
    default_level: tracing::Level,
    run: Run,
) -> ExitCode
where
    CommandError: std::fmt::Display,
    Run: FnOnce() -> Result<(), CommandError>,
{
    install_json_panic_hook(command_name);
    let _observation_guard = observation::bootstrap(true, debug, default_level).ok();
    let scope = crate::observation::scope(
        "CLICOMMON",
        "rule:observe:spans",
        "run_no_stdout_command",
        &(command_name, debug, default_level, std::any::type_name::<Run>()),
    );
    let result = match run() {
        Ok(()) => CommandExit::Success.exit_code(),
        Err(error) => {
            // Public error text is recorded without rewriting (´[ROOT-rule:observe:privacy]´).
            tracing::error!(error = %error, "command failed");
            CommandExit::Failure.exit_code()
        }
    };
    scope.finish_with(
        if result == ExitCode::SUCCESS {
            observation::Outcome::Success
        } else if result == ExitCode::from(2) || result == ExitCode::from(3) {
            observation::Outcome::Refusal
        } else {
            observation::Outcome::Error
        },
        &result,
    );
    result
}

/// Run an async side-effect command that does not emit stdout result data.
///
/// The runner installs the JSON panic hook, initialises JSON stderr tracing, and
/// maps failures to the baseline exit classes in (´[ROOT-rec:output:decision]´). It deliberately does not
/// perform stdout TTY refusal because the command has no stdout result data.
pub async fn run_no_stdout_command_async<CommandError, Run, RunFuture>(
    command_name: &str,
    debug: bool,
    default_level: tracing::Level,
    run: Run,
) -> ExitCode
where
    CommandError: std::fmt::Display,
    Run: FnOnce() -> RunFuture,
    RunFuture: Future<Output = Result<(), CommandError>>,
{
    install_json_panic_hook(command_name);
    let _observation_guard = observation::bootstrap(true, debug, default_level).ok();
    let debug_requested = debug;
    let span = tracing::info_span!("rule:observe:spans", execution_owner="CLICOMMON", claim_owner="ROOT", claim_label="rule:observe:spans", source_item="run_no_stdout_command_async", asynchronous=true, command_name, debug_requested, default_level=?default_level, callback=std::any::type_name::<Run>());
    tracing::Instrument::instrument(
        async {
            let result = match run().await {
                Ok(()) => CommandExit::Success.exit_code(),
                Err(error) => {
                    // Public error text is recorded without rewriting (´[ROOT-rule:observe:privacy]´).
                    tracing::error!(error = %error, "command failed");
                    CommandExit::Failure.exit_code()
                }
            };
            tracing::info!(outcome=if result==ExitCode::SUCCESS {"success"} else {"error"}, "return"=?result);
            result
        },
        span,
    )
    .await
}

/// A completed checker verdict and its report.
pub struct CheckOutcome<Report> {
    pub report: Report,
    pub clean: bool,
}

/// Run a checker that produces a JSON report and a verdict.
/// See (´sec:clicommon:output-roles-and-stamps´) for the checker modes.
///
/// Installs the JSON panic hook and stderr tracing, runs the check, and
/// publishes the result through [`finish_check_command`] under the
/// active output mode: direct-mode stdout (refused on a terminal, exit
/// class 2) or a build-mode report asset plus success stamp. The `run`
/// closure returns a completed verdict even when it found defects. A dirty
/// verdict publishes its report but leaves the stamp untouched and exits 3.
/// `Err` is reserved for an incomplete command and exits 1.
pub fn run_check_command<Report, CommandError, Run>(
    command_name: &str,
    debug: bool,
    default_level: tracing::Level,
    output: &CheckOutputArgs,
    run: Run,
) -> ExitCode
where
    Report: serde::Serialize,
    CommandError: std::fmt::Display,
    Run: FnOnce() -> Result<CheckOutcome<Report>, CommandError>,
{
    install_json_panic_hook(command_name);
    let _observation_guard = observation::bootstrap(true, debug, default_level).ok();
    let scope = crate::observation::scope(
        "CLICOMMON",
        "rule:observe:spans",
        "run_check_command",
        &(command_name, debug, default_level, output, std::any::type_name::<Run>()),
    );
    let result = (|| {
        // Direct mode (no --report/--stamp) refuses terminal stdout *before*
        // any semantic work: the JSON result would have nowhere safe to go,
        // so running the check first would be wasted work and could touch
        // the filesystem on the way. Build mode has an explicit report/stamp
        // destination and is exempt. `finish_check_command` still performs
        // its own refusal for direct callers.
        if output.report.is_none()
            && output.stamp.is_none()
            && let Some(record) = stdout_tty_refusal_record(command_name)
        {
            let _ignored = emit_control_plane_record(&record);
            return CommandExit::Usage.exit_code();
        }

        let outcome = match run() {
            Ok(outcome) => outcome,
            Err(error) => {
                // Public error text is recorded without rewriting (´[ROOT-rule:observe:privacy]´).
                tracing::error!(error = %error, "command failed");
                return CommandExit::Failure.exit_code();
            }
        };

        let published = if outcome.clean {
            finish_check_command(command_name, output, &outcome.report)
        } else {
            match (&output.report, &output.stamp) {
                (None, None) => finish_check_command(command_name, output, &outcome.report),
                (Some(report_path), Some(stamp_path)) => {
                    ensure_distinct_outputs(&[("report", report_path), ("stamp", stamp_path)])
                        .map_err(CheckResultError::from)
                        .and_then(|()| {
                            write_json_report_if_changed(report_path, &outcome.report)
                                .map(|_change| ())
                                .map_err(CheckResultError::from)
                        })
                }
                _ => Err(CheckResultError::InvalidMode),
            }
        };

        match published {
            Ok(()) if outcome.clean => CommandExit::Success.exit_code(),
            Ok(()) => ExitCode::from(3),
            Err(CheckResultError::TtyRefusal) => CommandExit::Usage.exit_code(),
            Err(error) => {
                tracing::error!(error = %error, "failed to publish the check result");
                CommandExit::Failure.exit_code()
            }
        }
    })();
    scope.finish_with(
        if result == ExitCode::SUCCESS {
            observation::Outcome::Success
        } else if result == ExitCode::from(2) || result == ExitCode::from(3) {
            observation::Outcome::Refusal
        } else {
            observation::Outcome::Error
        },
        &result,
    );
    result
}

struct LockedStderrWriter {
    _guard: MutexGuard<'static, ()>,
    stderr: io::Stderr,
}

impl LockedStderrWriter {
    fn locked_stderr() -> Self {
        Self {
            _guard: STDERR_WRITE_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            stderr: io::stderr(),
        }
    }

    fn try_locked_stderr() -> Option<Self> {
        match STDERR_WRITE_LOCK.try_lock() {
            Ok(guard) => Some(Self {
                _guard: guard,
                stderr: io::stderr(),
            }),
            Err(TryLockError::Poisoned(poisoned)) => Some(Self {
                _guard: poisoned.into_inner(),
                stderr: io::stderr(),
            }),
            Err(TryLockError::WouldBlock) => None,
        }
    }
}

impl Write for LockedStderrWriter {
    /// Justified: The stderr sink is the observation delivery boundary and must write bytes without recursively observing its own output.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stderr.write(buf)
    }

    /// Justified: The stderr sink is the observation delivery boundary and must write bytes without recursively observing its own output.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn flush(&mut self) -> io::Result<()> {
        self.stderr.flush()
    }
}

/// Common `--debug` flag for all helpers. Flatten into each
/// binary's `Args` struct via `#[command(flatten)]`.
#[derive(clap::Args)]
pub struct BaseArgs {
    /// Enable debug-level logging on stderr.
    #[arg(long)]
    pub debug: bool,
}

/// Touch a checker stamp file (see (´sec:clicommon:output-roles-and-stamps´)): create it empty when absent, update
/// the modification time of an existing empty stamp, and refuse a
/// nonempty one.
///
/// A stamp is empty by contract — the JSON report is a separate asset
/// — so bytes in an existing stamp mean something other than this
/// command wrote it. Refusing (rather than truncating) is
/// non-destructive: the foreign bytes survive for inspection, no
/// fresh success stamp appears, and the build graph keeps the target
/// dirty. A failing command must not call this at all.
///
/// # Errors
///
/// Returns the underlying I/O error, or an `InvalidData` error for an
/// existing nonempty stamp.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "CLICOMMON",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "touch_stamp"
    ),
    ret
)]
pub fn touch_stamp(path: &std::path::Path) -> io::Result<()> {
    match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_created) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let file = std::fs::File::options().write(true).open(path)?;
            let length = file.metadata()?.len();
            if length > 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "stamp {} holds {length} byte(s); a stamp is empty by contract, \
                         refusing to re-date foreign bytes",
                        path.display(),
                    ),
                ));
            }
            let now = std::time::SystemTime::now();
            file.set_times(std::fs::FileTimes::new().set_accessed(now).set_modified(now))
        }
        Err(error) => Err(error),
    }
}

/// Output arguments for the checker modes in (´sec:clicommon:output-roles-and-stamps´).
///
/// A checker runs in one of two modes:
///
/// - **direct** — no `--report`/`--stamp`: the JSON result goes to
///   stdout (refused on a terminal) and no stamp is touched;
/// - **build** — both `--report` and `--stamp`: the result is published
///   as an explicit report asset (compare-if-changed), the stamp is
///   touched only after a successful report write, and stdout stays
///   empty.
///
/// `clap` enforces the reciprocal requirement, so a lone `--report` or
/// `--stamp` is a usage error before the command runs.
#[derive(clap::Args, Debug)]
pub struct CheckOutputArgs {
    /// Build mode: write the JSON result to this explicit report file.
    #[arg(long, value_name = "FILE", requires = "stamp")]
    pub report: Option<std::path::PathBuf>,

    /// Build mode: touch this success stamp after publishing the report.
    #[arg(long, value_name = "FILE", requires = "report")]
    pub stamp: Option<std::path::PathBuf>,
}

/// Identity of one output destination for role-uniqueness validation.
///
/// One lexically normalized absolute path
/// `(´guide:clicommon:cli-common´)`. Deliberately *not* filesystem
/// canonicalization, symlink resolution, device/inode comparison,
/// hard-link detection, or mount identity: those establish no boundary
/// the repository can hold, because the host may replace or remount a
/// path at any time.
///
/// This is a correctness guard against configuration mistakes — two
/// roles spelled differently for one destination. Callers must not
/// alias distinct output roles through symlinks, hard links, mounts,
/// or namespaces; a hard link is not semantic identity, and
/// first-party outputs are identified by role, path, schema, and
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationIdentity(std::path::PathBuf);

/// Compute the destination identity of a possibly not-yet-existing path.
///
/// A relative path is resolved against the process working directory,
/// its documented base. Normalization then removes `.` components and
/// resolves `..` components without consulting the filesystem, so the
/// result is defined for a destination that does not exist yet and is
/// unaffected by what the host has mounted beneath it.
#[must_use]
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "CLICOMMON",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "destination_identity"
    ),
    ret
)]
pub fn destination_identity(path: &std::path::Path) -> DestinationIdentity {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };

    let mut normalized = std::path::PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            // `pop` on a root leaves the root in place, so a `..`
            // chain cannot escape above it.
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other),
        }
    }
    DestinationIdentity(normalized)
}

/// Two output roles named one destination.
#[derive(Debug, thiserror::Error)]
#[error("output roles --{first} and --{second} name the same destination")]
pub struct AliasedOutputs {
    pub first: String,
    pub second: String,
}

/// Reject duplicated destinations among a command's output roles
/// before any semantic work or file mutation: a multi-output command
/// must never exit success with one role's bytes overwriting
/// another's.
///
/// The comparison is lexical. It catches two roles naming one
/// destination — including through `.` and `..` spellings — and makes
/// no claim about host-level aliasing or about the destination staying
/// put afterwards.
///
/// # Errors
///
/// Returns [`AliasedOutputs`] naming the first offending role pair.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "CLICOMMON",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "ensure_distinct_outputs"
    ),
    ret
)]
pub fn ensure_distinct_outputs(roles: &[(&str, &std::path::Path)]) -> Result<(), AliasedOutputs> {
    let identities = roles.iter().map(|(_, path)| destination_identity(path)).collect::<Vec<_>>();

    for (index, (first, _)) in roles.iter().enumerate() {
        for (offset, (second, _)) in roles.iter().enumerate().skip(index + 1) {
            if identities[index] == identities[offset] {
                return Err(AliasedOutputs {
                    first: (*first).to_owned(),
                    second: (*second).to_owned(),
                });
            }
        }
    }

    Ok(())
}

/// Failure publishing a check result through [`finish_check_command`].
#[derive(Debug, thiserror::Error)]
pub enum CheckResultError {
    /// Direct mode refused because stdout is a terminal (exit class 2).
    #[error("stdout is a terminal; refusing to write result data")]
    TtyRefusal,

    /// Exactly one of `--report`/`--stamp` was supplied. `clap` normally
    /// prevents this; the variant keeps the finalizer total.
    #[error("invalid checker output mode: --report and --stamp are all-or-nothing")]
    InvalidMode,

    /// The report could not be published or the stamp could not be
    /// touched.
    #[error("failed to publish the check result")]
    Io(#[from] io::Error),

    /// Build mode named one destination for both the report and the
    /// stamp; a stamp holding JSON bytes would contradict its
    /// empty-stamp role.
    #[error("aliased checker outputs: {0}")]
    AliasedOutputs(#[from] AliasedOutputs),
}

/// Publish a successful check result under the active output mode.
///
/// In direct mode the report is written to stdout (refused on a
/// terminal). In build mode the report is written compare-if-changed to
/// its explicit path and only then is the success stamp touched, so a
/// failed report publication never leaves a fresh stamp behind. Callers
/// must invoke this only when the semantic check succeeded; a failed
/// check leaves stdout empty and emits diagnostics on stderr.
///
/// # Errors
///
/// Returns [`CheckResultError::TtyRefusal`] in direct mode when stdout is
/// a terminal, [`CheckResultError::InvalidMode`] if only one build-mode
/// path is set, or [`CheckResultError::Io`] on a write failure.
/// Justified: This publication adapter inherits the checker command context and delegates all serialized output and file work to their separately observed boundaries without serializing a report twice.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
pub fn finish_check_command<T: serde::Serialize>(
    command_name: &str,
    output: &CheckOutputArgs,
    report: &T,
) -> Result<(), CheckResultError> {
    match (&output.report, &output.stamp) {
        (None, None) => {
            if let Some(record) = stdout_tty_refusal_record(command_name) {
                let _ignored = emit_control_plane_record(&record);
                return Err(CheckResultError::TtyRefusal);
            }
            emit(report)?;
            Ok(())
        }

        (Some(report_path), Some(stamp_path)) => {
            ensure_distinct_outputs(&[("report", report_path), ("stamp", stamp_path)])?;
            // The checker CLI contract reports the check result, not
            // the publication's freshness components; a mode-repaired
            // report is still a current report.
            let _change = write_json_report_if_changed(report_path, report)?;
            touch_stamp(stamp_path)?;
            Ok(())
        }

        _ => Err(CheckResultError::InvalidMode),
    }
}

/// Write `value` as one JSON object plus trailing newline to `path`,
/// skipping the write when the current contents already match.
///
/// The report is staged in a sibling temp file and atomically renamed,
/// so a partial write never leaves a truncated report. The staged file
/// carries the public publication mode before the rename, so a report
/// does not inherit the owner-only mode of the temporary. The
/// compare-if-changed skip keeps ninja `restat` from cascading rebuilds
/// on unchanged results.
///
/// Freshness is bytes **and** mode: a report whose bytes are
/// current but whose mode is not `0o644` is repaired in place, leaving
/// its bytes and their modification time alone. The typed
/// [`PublicationChange`] says which of the two happened.
fn write_json_report_if_changed<T: serde::Serialize>(path: &std::path::Path, value: &T) -> io::Result<PublicationChange> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');

    match publication::inspect_destination(path, &bytes, publication::PublicationMode::Public) {
        publication::DestinationState::Current => return Ok(PublicationChange::default()),
        publication::DestinationState::ModeOnly => {
            publication::repair_publication_mode(path, publication::PublicationMode::Public)?;
            return Ok(PublicationChange {
                bytes_changed: false,
                mode_changed: true,
            });
        }
        publication::DestinationState::StaleBytes => {}
    }

    let directory = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(directory)?;

    let mut staged = tempfile::Builder::new()
        .prefix(".check-report-staged-")
        .tempfile_in(directory)?;
    staged.write_all(&bytes)?;
    staged.as_file().sync_all()?;
    publication::set_publication_mode(staged.as_file(), publication::PublicationMode::Public)?;
    staged.persist(path).map_err(|error| error.error)?;
    Ok(PublicationChange {
        bytes_changed: true,
        mode_changed: false,
    })
}
