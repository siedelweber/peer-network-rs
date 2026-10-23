#![doc = include_str!("../README.md")]

use std::ffi::OsString;
use std::fs::{File, create_dir_all};
use std::io::{self, Read, Write};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Sender, channel};
use std::thread;

use thiserror::Error;

pub mod writer;

#[cfg(test)]
mod tests;

pub use writer::{StreamProps, Writer};

/// One of the two captured streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stream {
    /// Standard output of the wrapped child process.
    Stdout,
    /// Standard error of the wrapped child process.
    Stderr,
}

impl Stream {
    /// Uppercase label, e.g. `"STDOUT"`.
    #[must_use]
    /// Justified: Const evaluation cannot emit runtime events; the caller operation accounts its execution without changing this compile-time contract.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stdout => "STDOUT",
            Self::Stderr => "STDERR",
        }
    }
}

/// Errors returned from [`run`].
#[derive(Debug, Error)]
pub enum ExecError {
    /// An I/O error happened while preparing pipes, writers, or files.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// The child process could not be spawned.
    ///
    /// The failing program path remains in the enclosing operation's full public
    /// arguments under (´[ROOT-rec:output:decision]´); this variant carries the
    /// underlying error, without duplicating those arguments.
    #[error("failed to spawn child process: {source}")]
    Spawn {
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The command vector was empty (no program to run).
    #[error("empty command")]
    EmptyCommand,

    /// The user requested ambiguous routing for the same file.
    #[error("ambiguous redirection for {path}: configured for multiple routing kinds")]
    AmbiguousRedirection {
        /// Conflicting output path.
        path: PathBuf,
    },
}

/// User-provided routing configuration.
#[derive(Debug, Default, Clone)]
pub struct RoutingConfig {
    /// `--redirect` target: capture stdout and stderr merged in raw form.
    pub redirect: Option<PathBuf>,
    /// `--redirect-output` target: capture stdout only.
    pub redirect_output: Option<PathBuf>,
    /// `--redirect-error` target: capture stderr only.
    pub redirect_error: Option<PathBuf>,
    /// `--redirect-prefixed` target: capture both streams with prefixes.
    pub redirect_prefixed: Option<PathBuf>,
    /// Emit notifications when log files are written.
    pub notify_on_write: bool,
    /// Retained output-contract control; never selects observation emission.
    pub debug: bool,
}

impl RoutingConfig {
    /// True when the stream is being written to a log file.
    #[must_use]
    /// Justified: Const evaluation cannot emit runtime events; the caller operation accounts its execution without changing this compile-time contract.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub const fn is_stream_redirected(&self, stream: Stream) -> bool {
        if self.redirect.is_some() || self.redirect_prefixed.is_some() {
            return true;
        }
        match stream {
            Stream::Stdout => self.redirect_output.is_some(),
            Stream::Stderr => self.redirect_error.is_some(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteKind {
    CombinedRaw,
    CombinedPrefixed,
    StdoutOnly,
    StderrOnly,
}

#[derive(Debug)]
struct FileSpec {
    path: PathBuf,
    kind: RouteKind,
    identity: FileIdentity,
}

/// Filesystem identity of a redirection target.
///
/// This is the **sole** package-local exception to lexical output-role
/// comparison `(´guide:execwrap:execwrap´)`, which requires the
/// exception to state four things:
///
/// **The exact hazard.** Two redirection routes resolving to one file
/// are opened independently, each with truncation, and then written
/// concurrently by the wrapper as the child produces output. The
/// result is one log with interleaved and partially overwritten
/// bytes, and no I/O call fails at any point. The damage is done to
/// the operation's own output, not to repository state.
///
/// **The additional check.** Each target is resolved to a filesystem
/// identity before anything is opened: device and inode for an
/// existing file (so symlinks and hard links collapse), and resolved
/// parent directory plus file name for one that does not exist yet.
/// A dangling symlink resolves to its ultimate target, because
/// creating the file would follow the link.
///
/// **Why lexical uniqueness is insufficient here.** Lexical
/// comparison catches `a.log` against `./a.log`, but not two names
/// hard-linked to one file, nor two paths beneath a symlinked
/// directory, nor a dangling link and the name it points at. Those
/// all produce the interleaving above, and unlike an ordinary output
/// role — which the caller controls end to end — these paths are
/// routinely assembled by build glue where such aliases arise by
/// accident.
///
/// **The remaining host race.** None of this closes a
/// time-of-check/time-of-use window: the host may replace or remount
/// any of these paths between the check and the open. This is a
/// preflight guard against configuration mistakes and nothing more.
/// It is a package-local correctness measure, never a
/// repository-wide filesystem security claim.
#[derive(Debug, PartialEq, Eq)]
enum FileIdentity {
    /// The target exists: device and inode numbers (symlinks
    /// followed, hard links share the pair).
    Existing(u64, u64),
    /// The target does not exist yet: resolved parent directory plus
    /// final file name.
    Pending(PathBuf, OsString),
}

/// Bound on manual resolution of dangling symlink chains, matching
/// the kernel's nested-link limit behind `ELOOP`.
const SYMLINK_FOLLOW_LIMIT: usize = 40;

fn file_identity(path: &Path) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let mut current = path.to_path_buf();
    let mut hops = 0_usize;
    loop {
        match std::fs::metadata(&current) {
            Ok(metadata) => return Ok(FileIdentity::Existing(metadata.dev(), metadata.ino())),

            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // NotFound covers a dangling final symlink, and
                // `File::create` on that link would follow it: the
                // identity must be that of the link's ultimate
                // target, never the link's own name.
                let is_dangling_link = std::fs::symlink_metadata(&current).is_ok_and(|link| link.file_type().is_symlink());
                if !is_dangling_link {
                    return pending_identity(&current);
                }
                if hops == SYMLINK_FOLLOW_LIMIT {
                    // `ErrorKind::FilesystemLoop` is not stable yet.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "too many levels of symbolic links in redirection target",
                    ));
                }
                hops += 1;

                let target = std::fs::read_link(&current)?;
                current = if target.is_absolute() {
                    target
                } else {
                    // A relative link target resolves against the
                    // link's own directory, not the process cwd.
                    match current.parent() {
                        Some(parent) if !parent.as_os_str().is_empty() => parent.join(target),
                        _ => target,
                    }
                };
            }

            Err(error) => return Err(error),
        }
    }
}

/// Identity of a target that does not exist and is not a symlink.
fn pending_identity(path: &Path) -> io::Result<FileIdentity> {
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "redirection path has no file name"))?
        .to_os_string();

    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };

    let parent = resolve_pending_directory(parent)?;

    Ok(FileIdentity::Pending(parent, file_name))
}

/// Absolute identity of a directory whose trailing components may not
/// exist yet: every existing prefix component is resolved through the
/// filesystem (following symlinks), and only the missing suffix is
/// resolved lexically. Canonicalizing the whole parent — falling back
/// to a purely lexical form when any component is missing — would let
/// two routes through a symlinked existing ancestor with directories
/// still to be created below it register as distinct identities.
fn resolve_pending_directory(path: &Path) -> io::Result<PathBuf> {
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let mut resolved = PathBuf::new();
    // Number of trailing components that could not be resolved through
    // the filesystem. While zero, `resolved` is canonical and every
    // new component is re-resolved — so a `..` that pops back out of
    // the missing suffix returns to filesystem-backed resolution
    // instead of leaving later symlinked components lexical.
    let mut missing = 0_usize;
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            // Exact in both modes: a canonical prefix is symlink-free,
            // and a missing suffix directory is created literally.
            Component::ParentDir => {
                resolved.pop();
                missing = missing.saturating_sub(1);
            }
            other => {
                if missing > 0 {
                    resolved.push(other);
                    missing += 1;
                    continue;
                }
                resolved.push(other);
                match resolved.canonicalize() {
                    Ok(canonical) => resolved = canonical,
                    // Missing (or unreadable) component: lexical until
                    // a `..` climbs back into existing space.
                    Err(_) => missing = 1,
                }
            }
        }
    }

    Ok(resolved)
}

fn collect_file_specs(cfg: &RoutingConfig) -> Result<Vec<FileSpec>, ExecError> {
    let candidates = [
        (cfg.redirect.as_ref(), RouteKind::CombinedRaw),
        (cfg.redirect_prefixed.as_ref(), RouteKind::CombinedPrefixed),
        (cfg.redirect_output.as_ref(), RouteKind::StdoutOnly),
        (cfg.redirect_error.as_ref(), RouteKind::StderrOnly),
    ];

    let mut specs: Vec<FileSpec> = Vec::new();
    for (maybe_path, kind) in candidates {
        let Some(path) = maybe_path else { continue };
        let identity = file_identity(path)?;
        if let Some(existing) = specs.iter().find(|s| s.identity == identity) {
            if existing.kind != kind {
                return Err(ExecError::AmbiguousRedirection { path: path.clone() });
            }
        } else {
            specs.push(FileSpec {
                path: path.clone(),
                kind,
                identity,
            });
        }
    }
    Ok(specs)
}

/// Validate a routing configuration before any side effect.
///
/// Targets are only stat'ed — nothing is opened, created, or
/// truncated — so the binary can report an invalid argument
/// combination as a usage failure before touching any file.
///
/// # Errors
///
/// Returns [`ExecError::AmbiguousRedirection`] when one file — by
/// filesystem identity, not merely lexical path equality — is
/// configured for multiple routing kinds.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "EXECWRAP",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "preflight_routing"
    ),
    ret
)]
pub fn preflight_routing(cfg: &RoutingConfig) -> Result<(), ExecError> {
    collect_file_specs(cfg).map(|_specs| ())
}

/// Open `path` for writing in binary mode, creating parent directories as needed.
///
/// # Errors
///
/// Returns the underlying I/O error from directory creation or file open.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "EXECWRAP",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "safe_open"
    ),
    ret
)]
pub fn safe_open(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        create_dir_all(parent)?;
    }
    File::create(path)
}

/// Notification emitted by the wrapper while running.
#[derive(Debug, Clone)]
pub enum Notification {
    /// `--notify-on-write` informational record: writing to a log file.
    WritingToLog { path: PathBuf, stream: Stream },
    /// `--notify-on-write` deferred record: wrote to a log file by end of run.
    WroteToLog { path: PathBuf },
}

/// Outcome of running the wrapped command.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    /// Numeric exit code. Signal terminations are reported as `128 + signal`.
    pub exit_code: i32,
    /// True when captured output may be incomplete: a log-file write,
    /// a child-stream read, or a writer finalization failed. Callers
    /// must treat a run with data loss as failed even when the child
    /// exited 0 — silently succeeding after losing logs is data loss,
    /// not success.
    pub data_loss: bool,
}

/// Run the wrapped command using the provided routing configuration.
///
/// `notify` is called for each notification record (only when `notify_on_write`
/// is enabled).
///
/// # Errors
///
/// Returns [`ExecError`] for setup failures (pipes, writers, spawn). A non-zero
/// exit code from the child is *not* an error: it is returned through
/// [`ExecOutcome::exit_code`].
///
/// # Panics
///
/// Panics if the child's stdout/stderr pipes cannot be taken after being
/// configured as piped, which should never happen.
pub fn run(command: &[OsString], cfg: &RoutingConfig, mut notify: impl FnMut(&Notification)) -> Result<ExecOutcome, ExecError> {
    let scope = cli_common::observation::scope(
        "EXECWRAP",
        "rule:observe:spans",
        "run",
        &(command, cfg, "notification callback: opaque capability"),
    );
    let observation = cli_common::observation::Observation::current();
    let mut operation = observation.as_ref().map(|o| {
        o.operation(cli_common::observation::OperationKind::Child, o.capture(|| serde_json::json!({
        "command": command.iter().map(|arg| cli_common::observation::public_bytes(arg.as_encoded_bytes())).collect::<Vec<_>>(),
        "configuration": {"redirect":cfg.redirect.as_ref().map(|p|cli_common::observation::public_bytes(p.as_os_str().as_encoded_bytes())),
            "redirect_output":cfg.redirect_output.as_ref().map(|p|cli_common::observation::public_bytes(p.as_os_str().as_encoded_bytes())),
            "redirect_error":cfg.redirect_error.as_ref().map(|p|cli_common::observation::public_bytes(p.as_os_str().as_encoded_bytes())),
            "redirect_prefixed":cfg.redirect_prefixed.as_ref().map(|p|cli_common::observation::public_bytes(p.as_os_str().as_encoded_bytes())),
            "notify_on_write":cfg.notify_on_write,"debug":cfg.debug}
    })))
    });
    let result = run_observed(command, cfg, &mut notify, &mut operation);
    if let Some(operation) = operation {
        let content = observation.as_ref().map_or(serde_json::Value::Null, |o| {
            o.capture(|| match &result {
                Ok(outcome) => serde_json::json!({"exit_code":outcome.exit_code,"data_loss":outcome.data_loss}),
                Err(error) => serde_json::json!({"error":error.to_string(),"structured_result":"enclosing run span return"}),
            })
        });
        operation.finish(
            if result.is_ok() {
                cli_common::observation::Outcome::Success
            } else {
                cli_common::observation::Outcome::Error
            },
            content,
        );
    }
    scope.finish(&result);
    result
}

// Justified: The child-byte relay preserves setup, stream routing and finalisation as one operation with explicit status precedence.
#[allow(clippy::cognitive_complexity, clippy::too_many_lines, clippy::option_if_let_else)]
fn run_observed(
    command: &[OsString],
    cfg: &RoutingConfig,
    notify: &mut impl FnMut(&Notification),
    operation: &mut Option<cli_common::observation::Operation>,
) -> Result<ExecOutcome, ExecError> {
    let program = command.first().ok_or(ExecError::EmptyCommand)?;
    let args = &command[1..];

    let specs = collect_file_specs(cfg)?;

    // Build writers per file path, then index them per stream.
    let mut file_writers: Vec<FileWriter> = Vec::new();
    let mut stdout_subscribers: Vec<usize> = Vec::new();
    let mut stderr_subscribers: Vec<usize> = Vec::new();

    for spec in &specs {
        let file = safe_open(&spec.path).map_err(ExecError::Io)?;
        let is_prefixed = matches!(spec.kind, RouteKind::CombinedPrefixed);
        let props = if is_prefixed {
            StreamProps {
                line1_prefix_stdout: ">>> ".to_string(),
                wrap_prefix_stdout: "    ".to_string(),
                line1_prefix_stderr: "*** ".to_string(),
                wrap_prefix_stderr: "    ".to_string(),
            }
        } else {
            StreamProps::default()
        };
        let writer = Writer::new(file, is_prefixed, 80, props, cfg.debug);
        let idx = file_writers.len();
        file_writers.push(FileWriter {
            path: spec.path.clone(),
            writer,
        });

        match spec.kind {
            RouteKind::StdoutOnly => stdout_subscribers.push(idx),
            RouteKind::StderrOnly => stderr_subscribers.push(idx),
            RouteKind::CombinedRaw | RouteKind::CombinedPrefixed => {
                stdout_subscribers.push(idx);
                stderr_subscribers.push(idx);
            }
        }
    }

    // A stream with no file subscriber passes through to the parent's
    // corresponding stream unconditionally — pipe, file, or terminal.
    // Silently discarding a child stream is data loss, never a default.
    let stdout_passthrough = stdout_subscribers.is_empty();
    let stderr_passthrough = stderr_subscribers.is_empty();

    // Track first-write notifications.
    let mut first_write_stdout = !stdout_subscribers.is_empty();
    let mut first_write_stderr = !stderr_subscribers.is_empty();

    // Defer-or-immediate notification decision.
    let defer_notifications = cfg.notify_on_write
        && cfg.redirect_output.is_some()
        && cfg.redirect_error.is_none()
        && cfg.redirect.is_none()
        && cfg.redirect_prefixed.is_none()
        && !cfg.is_stream_redirected(Stream::Stderr);

    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ExecError::Spawn { source })?;

    tracing::info!(command = ?command, configuration = ?cfg, pid = child.id(), "executing child process");

    let stdout = child.stdout.take().expect("stdout pipe configured above");
    let stderr = child.stderr.take().expect("stderr pipe configured above");

    let (tx, rx) = channel::<ChannelMessage>();

    let stdout_handle = spawn_reader(Stream::Stdout, stdout, tx.clone());
    let stderr_handle = spawn_reader(Stream::Stderr, stderr, tx);

    // Buffered passthrough to the parent's standard streams when no subscriber.
    let mut parent_stdout = io::stdout();
    let mut parent_stderr = io::stderr();

    let mut pending_paths: Vec<PathBuf> = Vec::new();
    let mut data_loss = false;

    for message in rx {
        match message {
            ChannelMessage::Data { stream, data } => {
                if let Some(operation) = operation {
                    operation.work_bytes(u64::try_from(data.len()).unwrap_or(u64::MAX));
                    operation.progress(
                        || serde_json::json!({"stream":stream.label(),"bytes":cli_common::observation::public_bytes(&data)}),
                    );
                }
                let subscribers = match stream {
                    Stream::Stdout => &stdout_subscribers,
                    Stream::Stderr => &stderr_subscribers,
                };
                if subscribers.is_empty() {
                    let relay = match stream {
                        Stream::Stdout if stdout_passthrough => parent_stdout.write_all(&data),
                        Stream::Stderr if stderr_passthrough => parent_stderr.write_all(&data),
                        // Unreachable: passthrough is exactly
                        // "no subscriber" per stream.
                        _ => Ok(()),
                    };
                    if let Err(error) = relay {
                        data_loss = true;
                        tracing::error!(
                            error = %error,
                            stream = stream.label(),
                            "parent passthrough write failed",
                        );
                    }
                } else {
                    let first = match stream {
                        Stream::Stdout => {
                            let f = first_write_stdout;
                            first_write_stdout = false;
                            f
                        }
                        Stream::Stderr => {
                            let f = first_write_stderr;
                            first_write_stderr = false;
                            f
                        }
                    };
                    for &idx in subscribers {
                        let entry = &mut file_writers[idx];
                        if first && cfg.notify_on_write {
                            if defer_notifications {
                                if !pending_paths.contains(&entry.path) {
                                    pending_paths.push(entry.path.clone());
                                }
                            } else {
                                notify(&Notification::WritingToLog {
                                    path: entry.path.clone(),
                                    stream,
                                });
                            }
                        }
                        if let Err(error) = entry.writer.write(stream, &data) {
                            data_loss = true;
                            tracing::error!(error = %error, path = ?entry.path, "writer error");
                        }
                    }
                }
            }
            ChannelMessage::Eof { stream } => {
                tracing::debug!(stream = stream.label(), "child stream closed");
            }
            ChannelMessage::Error { stream, error } => {
                data_loss = true;
                tracing::error!(error = %error, stream = stream.label(), "read error on child stream");
            }
        }
    }

    // A panicked reader thread may have dropped bytes on the floor.
    for (handle, label) in [(stdout_handle, "stdout"), (stderr_handle, "stderr")] {
        if handle.join().is_err() {
            data_loss = true;
            tracing::error!(stream = label, "child stream reader thread panicked");
        }
    }

    for (parent, label) in [
        (&mut parent_stdout as &mut dyn Write, "stdout"),
        (&mut parent_stderr as &mut dyn Write, "stderr"),
    ] {
        if let Err(error) = parent.flush() {
            data_loss = true;
            tracing::error!(error = %error, stream = label, "parent stream flush failed");
        }
    }

    for entry in &mut file_writers {
        if let Err(error) = entry.writer.finalize() {
            data_loss = true;
            tracing::error!(error = %error, path = ?entry.path, "writer finalize error");
        }
    }

    for path in pending_paths {
        notify(&Notification::WroteToLog { path });
    }

    let status = child.wait().map_err(ExecError::Io)?;

    let exit_code = if let Some(code) = status.code() {
        code
    } else if let Some(signal) = status.signal() {
        128 + signal
    } else {
        1
    };

    tracing::debug!(exit_code, data_loss, "child exited");
    Ok(ExecOutcome { exit_code, data_loss })
}

struct FileWriter {
    path: PathBuf,
    writer: Writer,
}

enum ChannelMessage {
    Data { stream: Stream, data: Vec<u8> },
    Eof { stream: Stream },
    Error { stream: Stream, error: io::Error },
}

fn spawn_reader<R: Read + Send + 'static>(stream: Stream, source: R, tx: Sender<ChannelMessage>) -> thread::JoinHandle<()> {
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let parent = tracing::Span::current();
    thread::spawn(move || {
        let _dispatch = tracing::dispatcher::set_default(&dispatch);
        let _parent = parent.enter();
        read_stream(stream, source, &tx);
    })
}

fn read_stream<R: Read>(stream: Stream, mut source: R, tx: &Sender<ChannelMessage>) {
    let scope = cli_common::observation::scope(
        "EXECWRAP",
        "rule:observe:spans",
        "read_stream",
        &(stream, std::any::type_name::<R>(), "channel capability"),
    );
    let mut outcome = cli_common::observation::Outcome::Success;
    let mut buffer = [0_u8; 8192];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => {
                let _ignored = tx.send(ChannelMessage::Eof { stream });
                break;
            }
            Ok(read) => {
                if cli_common::observation::trace_enabled() {
                    tracing::info!(public_child_bytes=?cli_common::observation::public_bytes(&buffer[..read]), work_bytes=read as u64);
                } else {
                    tracing::info!(work_bytes = read as u64);
                }
                let data = buffer[..read].to_vec();
                if tx.send(ChannelMessage::Data { stream, data }).is_err() {
                    outcome = cli_common::observation::Outcome::Cancelled;
                    break;
                }
            }
            Err(ref error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                tracing::info!(public_read_error=?error);
                outcome = cli_common::observation::Outcome::Error;
                let _ignored = tx.send(ChannelMessage::Error { stream, error });
                break;
            }
        }
    }
    scope.finish_with(outcome, &());
}
