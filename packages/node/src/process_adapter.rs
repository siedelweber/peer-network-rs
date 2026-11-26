//! Private operating-system acquisition and lifecycle driving for the `pn` binary.
//! (´[ROOT-amend:api:health-lifecycle]´)

use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File},
    future::{Future, poll_fn},
    io::{self, Read},
    os::unix::{ffi::OsStrExt, fs::FileTypeExt, net::UnixDatagram},
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};

use cli_common::{CliExit, CommandExit, ControlPlaneRecord, OriginPreparation};
use pn::lifecycle::{
    Action, Cause, CheckedBootstrap, Controller, EditionInspection, EditionSource, Event, PreparationFacts, PreparationRefusal,
    PublicOutput, State,
};
use secrecy::{ExposeSecret, SecretBox};
use serde_json::{Value, json};

use crate::{Command, FixtureRequest};

const MAX_EDITION_BYTES: usize = "schema=org.peer-network.test.api-control-schema@".len()
    + ";register=org.peer-network.test.api-control-register@".len()
    + 6 * 20
    + 4;

struct NotificationAddress {
    bytes: SecretBox<[u8]>,
}

impl fmt::Debug for NotificationAddress {
    /// Justified: This formatter emits a fixed role marker and no protected bytes; the binary entry remains the observed command root.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NotificationAddress { role: notification, value: [REDACTED] }")
    }
}

// Justified: The four Booleans mirror the four independently checked notification validity facts in the controller contract.
#[expect(clippy::struct_excessive_bools)]
struct NotificationValidity {
    present: bool,
    form_valid: bool,
    final_symlink: bool,
    is_socket: bool,
    reason: &'static str,
    error_kind: Option<io::ErrorKind>,
    os_code: Option<i32>,
}

impl NotificationValidity {
    fn public_detail(&self) -> Value {
        json!({
            "reason": self.reason,
            "kind": self.error_kind.map(|kind| format!("{kind:?}")),
            "os_code": self.os_code,
        })
    }
}

impl NotificationAddress {
    fn acquire() -> Option<Self> {
        std::env::var_os("NOTIFY_SOCKET").map(|owned| Self {
            bytes: SecretBox::new(owned.into_encoded_bytes().into_boxed_slice()),
        })
    }

    // Caveat: Notification address bytes are borrowed only for slash, NUL and length checks until form validation returns; byte-slice operations cannot accept the protected carrier, and the original environment copy remains process-owned until exit.
    // (´[ROOT-cav:observe:secret-node-notify-form-1]´)
    // Justified: The protected notification address is borrowed only for form validation; the standard path parser cannot accept its carrier.
    #[allow(clippy::disallowed_methods)]
    fn form_valid(&self) -> bool {
        let bytes = self.bytes.expose_secret(/* (´[ROOT-cav:observe:secret-node-notify-form-1]´) */);
        (1..=107).contains(&bytes.len()) && bytes.first() == Some(&b'/') && !bytes.contains(&0)
    }

    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "process_adapter::NotificationAddress::metadata_validity"
        )
    )]
    // Caveat: Notification pathname bytes are borrowed for one symlink_metadata call until it returns; the filesystem API cannot accept protected storage and may retain a kernel pathname copy.
    // (´[ROOT-cav:observe:secret-node-notify-metadata-1]´)
    // Justified: The protected notification address is borrowed only across one metadata call; the filesystem API cannot accept its carrier.
    #[allow(clippy::disallowed_methods)]
    fn metadata_validity(&self) -> Result<(bool, bool), (io::ErrorKind, Option<i32>)> {
        let bytes = self.bytes.expose_secret(/* (´[ROOT-cav:observe:secret-node-notify-metadata-1]´) */);
        let path = Path::new(OsStr::from_bytes(bytes));
        match fs::symlink_metadata(path) {
            Ok(metadata) => Ok((metadata.file_type().is_symlink(), metadata.file_type().is_socket())),
            Err(error) => Err((error.kind(), error.raw_os_error())),
        }
    }

    fn validity(&self) -> NotificationValidity {
        let form_valid = self.form_valid();
        let (final_symlink, is_socket, reason, error_kind, os_code) = if form_valid {
            match self.metadata_validity() {
                Ok((true, _)) => (true, false, "final_symlink", None, None),
                Ok((false, true)) => (false, true, "valid_socket", None, None),
                Ok((false, false)) => (false, false, "not_socket", None, None),
                Err((kind, code)) => (false, false, "metadata_failed", Some(kind), code),
            }
        } else {
            (false, false, "form_refused", None, None)
        };
        NotificationValidity {
            present: true,
            form_valid,
            final_symlink,
            is_socket,
            reason,
            error_kind,
            os_code,
        }
    }

    // Caveat: Notification pathname bytes are borrowed for one send_to call until it returns; the socket API cannot accept protected storage and may retain a kernel address copy.
    // (´[ROOT-cav:observe:secret-node-notify-send-1]´)
    // Justified: The protected notification address is borrowed only for the one send call; the socket API cannot accept its carrier.
    #[allow(clippy::disallowed_methods)]
    fn send_once_with(
        &self,
        bytes: &[u8],
        send: impl FnOnce(&Path, &[u8]) -> io::Result<usize>,
    ) -> Result<usize, (io::ErrorKind, Option<i32>)> {
        let address = self.bytes.expose_secret(/* (´[ROOT-cav:observe:secret-node-notify-send-1]´) */);
        let path = Path::new(OsStr::from_bytes(address));
        send(path, bytes).map_err(|error| (error.kind(), error.raw_os_error()))
    }

    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "process_adapter::NotificationAddress::send_once"
        )
    )]
    fn send_once(&self, endpoint: &UnixDatagram, bytes: &[u8]) -> Result<usize, (io::ErrorKind, Option<i32>)> {
        self.send_once_with(bytes, |path, payload| endpoint.send_to(payload, path))
    }
}

pub(super) struct Prepared {
    controller: Controller,
    clock: Instant,
    stop: Option<Arc<AtomicBool>>,
    address: Option<NotificationAddress>,
}

impl fmt::Debug for Prepared {
    /// Justified: This formatter reports only lifecycle state and capability presence, suppressing the monotonic origin and private address.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Prepared")
            .field("controller", &self.controller.state())
            .field("clock", &"[monotonic origin]")
            .field("stop", &self.stop.is_some())
            .field("address", &self.address.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum AdapterFailure {
    Configuration,
    Selected(Cause),
}

impl fmt::Display for AdapterFailure {
    /// Justified: This formatter emits a closed public cause name after the controller selects an exit; the binary entry remains the observed command root.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => formatter.write_str("Configuration"),
            Self::Selected(Cause::PreDispatchFailure { class, ceiling }) => match ceiling {
                Some(key) => write!(formatter, "{class} ceiling={key}"),
                None => write!(formatter, "{class} ceiling=null"),
            },
            Self::Selected(cause) => write!(formatter, "{}", cause_name(*cause)),
        }
    }
}

fn cause_name(cause: Cause) -> &'static str {
    match cause {
        Cause::BeforeReadyStop => "BeforeReadyStop",
        Cause::AfterReadyStop => "AfterReadyStop",
        Cause::StartupTimeout => "StartupTimeout",
        Cause::StoppingTimeout => "StoppingTimeout",
        Cause::PresentationUnknown => "PresentationUnknown",
        Cause::StartFailure(name) | Cause::EntryFailure(name) => name,
        Cause::PreDispatchFailure { class, .. } => class,
        Cause::NotificationFailed => "NotificationFailed",
        Cause::CleanupFailed => "CleanupFailed",
        Cause::TransitionRefused => "TransitionRefused",
    }
}

fn elapsed_ns(clock: Instant) -> u64 {
    u64::try_from(clock.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn usage(reason: PreparationRefusal) -> CliExit {
    let kind = match reason {
        PreparationRefusal::Arguments => "arguments",
        PreparationRefusal::EditionSources => "edition_sources",
        PreparationRefusal::EditionForm => "edition_form",
        PreparationRefusal::ReservedInput => "reserved_input",
        PreparationRefusal::Notification => "notification",
    };
    CliExit::new(ControlPlaneRecord::usage_error("pn", kind), CommandExit::Usage)
}

fn runtime_terminal(reason: &'static str) -> CliExit {
    CliExit::new(ControlPlaneRecord::diagnostic("pn", reason), CommandExit::Failure)
}

fn terminal(exit: CliExit, arguments: Value) -> OriginPreparation<Prepared> {
    OriginPreparation::Terminal { exit, arguments }
}

fn no_notification() -> NotificationValidity {
    NotificationValidity {
        present: false,
        form_valid: false,
        final_symlink: false,
        is_socket: false,
        reason: "absent",
        error_kind: None,
        os_code: None,
    }
}

/// Acquire only the selected public inputs before handing a checked decision to the runner.
/// (´[ROOT-amend:api:health-lifecycle]´)
pub(super) fn prepare(
    command: &Command,
    arguments: &[OsString],
    shared: &[OsString],
    clock: Instant,
    fixture: &FixtureRequest,
) -> OriginPreparation<Prepared> {
    prepare_with(
        command,
        (arguments, shared),
        clock,
        fixture,
        acquire_actual_public_inputs,
        || {
            let address = NotificationAddress::acquire();
            let validity = address.as_ref().map_or_else(no_notification, NotificationAddress::validity);
            (address, validity)
        },
        |flag| signal_hook::flag::register(signal_hook::consts::SIGTERM, flag).map(|_| ()),
    )
}

fn prepare_with(
    command: &Command,
    argument_views: (&[OsString], &[OsString]),
    clock: Instant,
    fixture: &FixtureRequest,
    acquire_public: impl FnOnce() -> PublicInputs,
    notification: impl FnOnce() -> (Option<NotificationAddress>, NotificationValidity),
    register_stop: impl FnOnce(Arc<AtomicBool>) -> io::Result<()>,
) -> OriginPreparation<Prepared> {
    let (arguments, shared) = argument_views;
    let mut initial_arguments = json!({
        "arguments": arguments.iter().map(|value| value.as_encoded_bytes().to_vec()).collect::<Vec<_>>()
    });
    let mut controller = Controller::new();
    if controller.advance(Event::Prepare { at: 0 }).is_err() {
        return terminal(runtime_terminal("Configuration"), initial_arguments);
    }
    let fixture_selected = match fixture.accepted(command) {
        super::FixtureAdmission::Unselected => false,
        #[cfg(feature = "fixture")]
        super::FixtureAdmission::Selected => true,
        #[cfg(feature = "fixture")]
        super::FixtureAdmission::Refused(exit) => return terminal(*exit, initial_arguments),
    };
    let stop = if matches!(command, Command::Start) {
        let flag = Arc::new(AtomicBool::new(false));
        if let Err(error) = register_stop(Arc::clone(&flag)) {
            initial_arguments["failure"] = json!({
                "reason": "signal_registration_failed",
                "kind": format!("{:?}", error.kind()),
                "os_code": error.raw_os_error(),
            });
            return terminal(runtime_terminal("Configuration"), initial_arguments);
        }
        Some(flag)
    } else {
        None
    };
    let public = acquire_public();
    let mut observed = public.observed(arguments);
    let Some(argument_text) = shared.iter().map(|argument| argument.to_str()).collect::<Option<Vec<_>>>() else {
        return terminal(usage(PreparationRefusal::Arguments), observed);
    };
    match command {
        Command::Edition => {
            let facts = match public.facts(&argument_text, &no_notification()) {
                Ok(facts) => facts,
                Err(reason) => return terminal(usage(reason), observed),
            };
            let inspection = match EditionInspection::new(&facts) {
                Ok(inspection) => inspection,
                Err(reason) => return terminal(usage(reason), observed),
            };
            if controller.advance(Event::PreparedInspection(inspection)).is_err() {
                return terminal(runtime_terminal("Configuration"), observed);
            }
            OriginPreparation::Continue {
                context: Prepared {
                    controller,
                    clock,
                    stop: None,
                    address: None,
                },
                arguments: observed,
            }
        }
        Command::Start => {
            let preliminary = match public.facts(&argument_text, &no_notification()) {
                Ok(facts) => CheckedBootstrap::new(&facts),
                Err(reason) => Err(reason),
            };
            if let Err(reason) = preliminary {
                if reason != PreparationRefusal::Notification {
                    return terminal(usage(reason), observed);
                }
            } else {
                return terminal(runtime_terminal("Configuration"), observed);
            }
            let (address, validity) = notification();
            observed["notification"] = validity.public_detail();
            let facts = match public.facts(&argument_text, &validity) {
                Ok(facts) => facts,
                Err(reason) => return terminal(usage(reason), observed),
            };
            let bootstrap = match CheckedBootstrap::new(&facts) {
                Ok(bootstrap) => bootstrap,
                Err(reason) => return terminal(usage(reason), observed),
            };
            if fixture_selected {
                return terminal(runtime_terminal("Configuration"), observed);
            }
            if controller.advance(Event::PreparedStart(bootstrap)).is_err() {
                return terminal(runtime_terminal("Configuration"), observed);
            }
            if stop.as_ref().is_some_and(|flag| flag.load(Ordering::SeqCst)) {
                let _actions = controller.advance(Event::Stop { at: elapsed_ns(clock) });
                return terminal(runtime_terminal("BeforeReadyStop"), observed);
            }
            OriginPreparation::Continue {
                context: Prepared {
                    controller,
                    clock,
                    stop,
                    address,
                },
                arguments: observed,
            }
        }
    }
}

#[derive(Debug)]
struct PublicInputs {
    edition: Option<OsString>,
    edition_file: Option<OsString>,
    file_bytes: Option<Vec<u8>>,
    file_refused: bool,
    listen_pid: Option<OsString>,
    listen_fds: Option<OsString>,
    listen_fdnames: Option<OsString>,
    listen_pidfdid: bool,
    connection_input: bool,
}

impl PublicInputs {
    fn observed(&self, arguments: &[OsString]) -> Value {
        json!({
            "arguments": arguments.iter().map(|value| value.as_encoded_bytes().to_vec()).collect::<Vec<_>>(),
            "PN_EDITION": self.edition.as_ref().map(|value| value.as_encoded_bytes()),
            "PN_EDITION_FILE": self.edition_file.as_ref().map(|value| value.as_encoded_bytes()),
            "LISTEN_PID": self.listen_pid.as_ref().map(|value| value.as_encoded_bytes()),
            "LISTEN_FDS": self.listen_fds.as_ref().map(|value| value.as_encoded_bytes()),
            "LISTEN_FDNAMES": self.listen_fdnames.as_ref().map(|value| value.as_encoded_bytes()),
            "LISTEN_PIDFDID": self.listen_pidfdid,
            "PN_CONNECTION_INPUT": self.connection_input,
        })
    }

    fn facts<'a>(
        &'a self,
        arguments: &'a [&'a str],
        notification: &NotificationValidity,
    ) -> Result<PreparationFacts<'a>, PreparationRefusal> {
        if self.file_refused {
            return Err(PreparationRefusal::EditionForm);
        }
        let edition = self
            .edition
            .as_deref()
            .map(OsStr::to_str)
            .transpose_option(PreparationRefusal::EditionForm)?;
        let edition_file = self
            .edition_file
            .as_deref()
            .map(OsStr::to_str)
            .transpose_option(PreparationRefusal::EditionForm)?;
        let listen_pid = self
            .listen_pid
            .as_deref()
            .map(OsStr::to_str)
            .transpose_option(PreparationRefusal::ReservedInput)?;
        let listen_fds = self
            .listen_fds
            .as_deref()
            .map(OsStr::to_str)
            .transpose_option(PreparationRefusal::ReservedInput)?;
        let listen_fdnames = self
            .listen_fdnames
            .as_deref()
            .map(OsStr::to_str)
            .transpose_option(PreparationRefusal::ReservedInput)?;
        Ok(PreparationFacts {
            arguments,
            edition,
            edition_file,
            file_bytes: self.file_bytes.as_deref(),
            listen_pid,
            listen_fds,
            listen_fdnames,
            listen_pidfdid: self.listen_pidfdid,
            connection_input: self.connection_input,
            process_id: std::process::id(),
            notification_present: notification.present,
            notification_form_valid: notification.form_valid,
            notification_final_symlink: notification.final_symlink,
            notification_is_socket: notification.is_socket,
        })
    }
}

trait TransposeOption<T> {
    fn transpose_option(self, refusal: PreparationRefusal) -> Result<Option<T>, PreparationRefusal>;
}

impl<T> TransposeOption<T> for Option<Option<T>> {
    /// Justified: This pure conversion only carries an optional public preparation fact into the observed binary command.
    fn transpose_option(self, refusal: PreparationRefusal) -> Result<Option<T>, PreparationRefusal> {
        match self {
            None => Ok(None),
            Some(Some(value)) => Ok(Some(value)),
            Some(None) => Err(refusal),
        }
    }
}

fn read_bounded(source: impl Read) -> Result<Vec<u8>, PreparationRefusal> {
    let mut bytes = Vec::new();
    source
        .take(u64::try_from(MAX_EDITION_BYTES + 2).map_err(|_| PreparationRefusal::EditionForm)?)
        .read_to_end(&mut bytes)
        .map_err(|error| edition_io_refusal(&error))?;
    if bytes.len() > MAX_EDITION_BYTES + 1 {
        return Err(PreparationRefusal::EditionForm);
    }
    Ok(bytes)
}

fn edition_io_refusal(error: &std::io::Error) -> PreparationRefusal {
    tracing::error!(kind = ?error.kind(), os_code = ?error.raw_os_error(), "public edition file I/O refused");
    PreparationRefusal::EditionForm
}

#[tracing::instrument(
    name = "rule:observe:spans",
    ret,
    fields(
        execution_owner = "NODE",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "process_adapter::read_public_file"
    )
)]
fn read_public_file(path: &OsStr) -> Result<Vec<u8>, PreparationRefusal> {
    let text = path.to_str().ok_or(PreparationRefusal::EditionForm)?;
    if !text.starts_with('/') || text.as_bytes().contains(&0) {
        return Err(PreparationRefusal::EditionForm);
    }
    let file = File::open(Path::new(path)).map_err(|error| edition_io_refusal(&error))?;
    let metadata = file.metadata().map_err(|error| edition_io_refusal(&error))?;
    if !metadata.is_file() {
        return Err(PreparationRefusal::EditionForm);
    }
    read_bounded(file)
}

fn render_output(output: PublicOutput) -> Value {
    match output {
        PublicOutput::Inspection {
            edition,
            source,
            supported,
        } => json!({
            "edition": edition,
            "source": match source { EditionSource::Environment => "environment", EditionSource::File => "file" },
            "supported": supported,
        }),
        PublicOutput::Stopped { edition } => json!({"edition": edition, "outcome": "stopped"}),
    }
}

#[tracing::instrument(
    name = "rule:observe:spans",
    ret,
    fields(
        execution_owner = "NODE",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "process_adapter::classify_complete"
    )
)]
fn classify_complete(exit: u8, stdout: Option<PublicOutput>, cause: Option<Cause>) -> Result<Value, AdapterFailure> {
    if exit == 0 {
        stdout.map(render_output).ok_or(AdapterFailure::Configuration)
    } else {
        Err(cause.map_or(AdapterFailure::Configuration, AdapterFailure::Selected))
    }
}

fn selected_completion(actions: Vec<Action>, controller: &mut Controller) -> Result<Value, AdapterFailure> {
    for action in actions {
        if let Action::Complete {
            exit,
            stdout,
            cause,
            retirement_diagnostics: _,
        } = action
        {
            let _finalized = controller
                .advance(Event::Finalized)
                .map_err(|_| AdapterFailure::Configuration)?;
            return classify_complete(exit, stdout, cause);
        }
    }
    Err(AdapterFailure::Configuration)
}

#[tracing::instrument(
    name = "rule:observe:spans",
    ret,
    fields(
        execution_owner = "NODE",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "process_adapter::complete_retirement"
    )
)]
fn complete_retirement(prepared: &mut Prepared, mut actions: Vec<Action>) -> Result<Value, AdapterFailure> {
    if prepared.controller.state() != State::Retiring {
        return selected_completion(actions, &mut prepared.controller);
    }
    for action in actions.drain(..) {
        match action {
            Action::ReleaseEndpoint => drop(prepared.address.take()),
            Action::ReleaseBuffers
            | Action::ReleaseContext
            | Action::ReleasePreparation
            | Action::Close
            | Action::Cancel { .. } => {}
            _ => return Err(AdapterFailure::Configuration),
        }
    }
    let completed = prepared
        .controller
        .advance(Event::Retired {
            at: elapsed_ns(prepared.clock),
            cleanup_failed: false,
        })
        .map_err(|_| AdapterFailure::Configuration)?;
    selected_completion(completed, &mut prepared.controller)
}

/// Drive the checked pure lifecycle after the runner has attempted installation.
/// (´[ROOT-amend:api:health-lifecycle]´)
#[tracing::instrument(
    name = "rule:observe:spans",
    ret,
    fields(
        execution_owner = "NODE",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "process_adapter::run"
    )
)]
pub(super) fn run(mut prepared: Prepared) -> Result<Value, AdapterFailure> {
    prepared
        .controller
        .advance(Event::Installed)
        .map_err(|_| AdapterFailure::Configuration)?;
    let actions = prepared
        .controller
        .advance(Event::Continue)
        .map_err(|_| AdapterFailure::Configuration)?;
    match actions.as_slice() {
        [Action::Complete { .. }] => selected_completion(actions, &mut prepared.controller),
        [Action::Construct] => {
            let construction = prepared
                .controller
                .construct_context()
                .map_err(|_| AdapterFailure::Configuration)?;
            match construction {
                Ok(context) => run_served(prepared, context),
                Err(error) => {
                    let actions = prepared
                        .controller
                        .advance(Event::Constructed {
                            result: Err(error),
                            at: elapsed_ns(prepared.clock),
                        })
                        .map_err(|_| AdapterFailure::Configuration)?;
                    complete_retirement(&mut prepared, actions)
                }
            }
        }
        _ => Err(AdapterFailure::Configuration),
    }
}

fn stop_latched(flag: &AtomicBool) -> bool {
    flag.load(Ordering::SeqCst)
}

fn notification_sent(result: Result<usize, (io::ErrorKind, Option<i32>)>) -> bool {
    matches!(result, Ok(7))
}

fn subscribe_and_check<S, E>(flag: &AtomicBool, subscribe: impl FnOnce() -> Result<S, E>) -> Result<(S, bool), E> {
    let stream = subscribe()?;
    Ok((stream, stop_latched(flag)))
}

fn setup_endpoint_with(
    at: u64,
    create: impl FnOnce() -> io::Result<UnixDatagram>,
    mode: impl FnOnce(&UnixDatagram) -> io::Result<()>,
) -> Result<UnixDatagram, Event> {
    let endpoint = create().map_err(|error| {
        tracing::error!(reason = "endpoint_create_failed", kind = ?error.kind(), os_code = ?error.raw_os_error());
        Event::EndpointSetupFailed { at }
    })?;
    mode(&endpoint).map_err(|error| {
        tracing::error!(reason = "endpoint_mode_failed", kind = ?error.kind(), os_code = ?error.raw_os_error());
        Event::EndpointSetupFailed { at }
    })?;
    Ok(endpoint)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WaitPlan {
    poll_work: bool,
    deadline: Option<u64>,
}

#[tracing::instrument(
    name = "rule:observe:spans",
    ret,
    fields(
        execution_owner = "NODE",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "process_adapter::wait_plan"
    )
)]
fn wait_plan(state: State, active: (Option<u64>, Option<u64>, Option<u64>)) -> WaitPlan {
    match state {
        State::Starting => WaitPlan {
            poll_work: true,
            deadline: active.0,
        },
        State::Retiring => WaitPlan {
            poll_work: true,
            deadline: active.1.into_iter().chain(active.2).min(),
        },
        State::Ready => WaitPlan {
            poll_work: false,
            deadline: None,
        },
        _ => WaitPlan {
            poll_work: false,
            deadline: active.0.into_iter().chain(active.1).chain(active.2).min(),
        },
    }
}

fn deadline_reached(now: u64, deadline: Option<u64>) -> bool {
    deadline.is_some_and(|bound| now >= bound)
}

fn poll_before_bound<T>(now: u64, deadline: Option<u64>, poll: impl FnOnce() -> T) -> Option<T> {
    (!deadline_reached(now, deadline)).then(poll)
}

fn timer_at(clock: Instant, deadline: Option<u64>) -> Result<Option<Pin<Box<tokio::time::Sleep>>>, AdapterFailure> {
    deadline
        .map(|bound| {
            let absolute = clock
                .checked_add(Duration::from_nanos(bound))
                .ok_or(AdapterFailure::Configuration)?;
            Ok(Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(absolute))))
        })
        .transpose()
}

enum Wake {
    Entry(Result<pn_interchange::TransportMessage, pn::EntryError>, u64),
    PendingCheck(u64, bool),
    Signal(u64, bool),
}

async fn wait_entry<F>(
    mut work: Pin<&mut F>,
    signal: &mut tokio::signal::unix::Signal,
    flag: &AtomicBool,
    clock: Instant,
    deadline: Option<u64>,
) -> Result<Wake, AdapterFailure>
where
    F: Future<Output = Result<pn_interchange::TransportMessage, pn::EntryError>>,
{
    let mut receive = Box::pin(signal.recv());
    let mut timer = timer_at(clock, deadline)?;
    let mut work_was_pending = false;
    Ok(poll_fn(|cx| {
        let at = elapsed_ns(clock);
        let stop = stop_latched(flag);
        if work_was_pending && (stop || deadline_reached(at, deadline)) {
            return Poll::Ready(Wake::PendingCheck(at, stop));
        }
        if let Poll::Ready(result) = work.as_mut().poll(cx) {
            return Poll::Ready(Wake::Entry(result, at));
        }
        work_was_pending = true;
        if stop || deadline_reached(at, deadline) {
            return Poll::Ready(Wake::PendingCheck(at, stop));
        }
        if let Poll::Ready(received) = receive.as_mut().poll(cx) {
            return Poll::Ready(Wake::Signal(elapsed_ns(clock), received.is_some()));
        }
        if let Some(timer) = &mut timer
            && timer.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Wake::PendingCheck(elapsed_ns(clock), stop_latched(flag)));
        }
        Poll::Pending
    })
    .await)
}

async fn settle_work<F>(mut work: Pin<&mut F>, clock: Instant, deadline: Option<u64>) -> Result<bool, AdapterFailure>
where
    F: Future<Output = Result<pn_interchange::TransportMessage, pn::EntryError>>,
{
    let Some(deadline) = deadline else { return Ok(false) };
    let mut timer = timer_at(clock, Some(deadline))?.ok_or(AdapterFailure::Configuration)?;
    Ok(poll_fn(|cx| {
        match poll_before_bound(elapsed_ns(clock), Some(deadline), || work.as_mut().poll(cx)) {
            None => return Poll::Ready(false),
            Some(Poll::Ready(_)) => return Poll::Ready(true),
            Some(Poll::Pending) => {}
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(false);
        }
        Poll::Pending
    })
    .await)
}

async fn drive_entry(
    prepared: &mut Prepared,
    context: &pn::ExecutionContext,
    endpoint: &UnixDatagram,
    signal: &mut tokio::signal::unix::Signal,
    flag: &AtomicBool,
    bytes: &[u8],
) -> Result<Vec<Action>, AdapterFailure> {
    let work = pn::execute(bytes, context);
    let mut work = std::pin::pin!(work);
    loop {
        let actions = match prepared.controller.state() {
            State::Starting => {
                let plan = wait_plan(State::Starting, prepared.controller.active_deadlines());
                if !plan.poll_work {
                    return Err(AdapterFailure::Configuration);
                }
                match wait_entry(work.as_mut(), signal, flag, prepared.clock, plan.deadline).await? {
                    Wake::Entry(result, at) => prepared.controller.advance(Event::EntryCompleted { result, at }),
                    Wake::PendingCheck(at, stop) => prepared.controller.advance(Event::EntryPendingCheck { at, stop }),
                    Wake::Signal(at, true) => {
                        flag.store(true, Ordering::SeqCst);
                        prepared.controller.advance(Event::EntryPendingCheck { at, stop: true })
                    }
                    Wake::Signal(at, false) => prepared.controller.advance(Event::RuntimeFailure { at }),
                }
            }
            State::ReadyCheck => prepared.controller.advance(Event::ReadyChecked {
                at: elapsed_ns(prepared.clock),
                stop: stop_latched(flag),
                checked_failure: false,
            }),
            State::Ready => {
                let at = elapsed_ns(prepared.clock);
                if stop_latched(flag) {
                    prepared.controller.advance(Event::Stop { at })
                } else if signal.recv().await.is_some() {
                    flag.store(true, Ordering::SeqCst);
                    prepared.controller.advance(Event::Stop {
                        at: elapsed_ns(prepared.clock),
                    })
                } else {
                    prepared.controller.advance(Event::RuntimeFailure {
                        at: elapsed_ns(prepared.clock),
                    })
                }
            }
            _ => return Err(AdapterFailure::Configuration),
        }
        .map_err(|_| AdapterFailure::Configuration)?;
        if prepared.controller.state() == State::Notifying {
            let [Action::Notify(payload)] = actions.as_slice() else {
                return Err(AdapterFailure::Configuration);
            };
            let address = prepared.address.as_ref().ok_or(AdapterFailure::Configuration)?;
            let sent = notification_sent(address.send_once(endpoint, payload));
            let settled = prepared
                .controller
                .advance(Event::NotificationCompleted {
                    sent,
                    at: elapsed_ns(prepared.clock),
                    stop: stop_latched(flag),
                    checked_failure: false,
                })
                .map_err(|_| AdapterFailure::Configuration)?;
            if prepared.controller.state() == State::Retiring {
                return Ok(settled);
            }
        } else if prepared.controller.state() == State::Retiring {
            if actions.iter().any(|action| matches!(action, Action::Cancel { .. })) {
                let plan = wait_plan(State::Retiring, prepared.controller.active_deadlines());
                let complete = settle_work(work.as_mut(), prepared.clock, plan.deadline).await?;
                return prepared
                    .controller
                    .advance(Event::WorkSettled {
                        at: elapsed_ns(prepared.clock),
                        complete,
                    })
                    .map_err(|_| AdapterFailure::Configuration);
            }
            return Ok(actions);
        }
    }
}

fn fail_served(mut prepared: Prepared, context: pn::ExecutionContext, event: Event) -> Result<Value, AdapterFailure> {
    let actions = prepared
        .controller
        .advance(event)
        .map_err(|_| AdapterFailure::Configuration)?;
    drop(context);
    complete_retirement(&mut prepared, actions)
}

#[tracing::instrument(
    name = "rule:observe:spans",
    ret,
    fields(
        execution_owner = "NODE",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "process_adapter::run_served"
    )
)]
fn run_served(mut prepared: Prepared, context: pn::ExecutionContext) -> Result<Value, AdapterFailure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build();
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(reason = "runtime_build_failed", kind = ?error.kind(), os_code = ?error.raw_os_error());
            let at = elapsed_ns(prepared.clock);
            return fail_served(prepared, context, Event::RuntimeFailure { at });
        }
    };
    let subscribed = {
        let _entered = runtime.enter();
        let flag = prepared.stop.as_ref().ok_or(AdapterFailure::Configuration)?;
        subscribe_and_check(flag, || {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        })
    };
    let (mut signal, stop_after_subscription) = match subscribed {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(reason = "signal_subscription_failed", kind = ?error.kind(), os_code = ?error.raw_os_error());
            let at = elapsed_ns(prepared.clock);
            return fail_served(prepared, context, Event::RuntimeFailure { at });
        }
    };
    let Some(flag) = prepared.stop.as_ref().map(Arc::clone) else {
        let at = elapsed_ns(prepared.clock);
        return fail_served(prepared, context, Event::RuntimeFailure { at });
    };
    let at = elapsed_ns(prepared.clock);
    if stop_after_subscription || stop_latched(&flag) {
        return fail_served(prepared, context, Event::Stop { at });
    }
    if deadline_reached(at, prepared.controller.active_deadlines().0) {
        return fail_served(prepared, context, Event::Constructed { result: Ok(()), at });
    }
    let endpoint = match setup_endpoint_with(elapsed_ns(prepared.clock), UnixDatagram::unbound, |endpoint| {
        endpoint.set_nonblocking(true)
    }) {
        Ok(endpoint) => endpoint,
        Err(event) => return fail_served(prepared, context, event),
    };
    let at = elapsed_ns(prepared.clock);
    if stop_latched(&flag) {
        return fail_served(prepared, context, Event::Stop { at });
    }
    let actions = prepared
        .controller
        .advance(Event::Constructed { result: Ok(()), at })
        .map_err(|_| AdapterFailure::Configuration)?;
    let [Action::Dispatch(_)] = actions.as_slice() else {
        drop(endpoint);
        drop(context);
        return complete_retirement(&mut prepared, actions);
    };
    let Some(Action::Dispatch(bytes)) = actions.into_iter().next() else {
        return Err(AdapterFailure::Configuration);
    };
    let actions = runtime.block_on(drive_entry(&mut prepared, &context, &endpoint, &mut signal, &flag, &bytes))?;
    let mut owned_bytes = Some(bytes);
    let mut owned_context = Some(context);
    let mut owned_endpoint = Some(endpoint);
    for action in actions {
        match action {
            Action::Close | Action::Cancel { .. } | Action::ReleasePreparation => {}
            Action::ReleaseBuffers => drop(owned_bytes.take()),
            Action::ReleaseContext => drop(owned_context.take()),
            Action::ReleaseEndpoint => {
                drop(owned_endpoint.take());
                drop(prepared.address.take());
            }
            _ => return Err(AdapterFailure::Configuration),
        }
    }
    let completed = prepared
        .controller
        .advance(Event::Retired {
            at: elapsed_ns(prepared.clock),
            cleanup_failed: false,
        })
        .map_err(|_| AdapterFailure::Configuration)?;
    selected_completion(completed, &mut prepared.controller)
}

#[tracing::instrument(
    name = "rule:observe:spans",
    ret,
    fields(
        execution_owner = "NODE",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "process_adapter::acquire_actual_public_inputs"
    )
)]
fn acquire_actual_public_inputs() -> PublicInputs {
    acquire_public_inputs(std::env::var_os, read_public_file)
}

fn acquire_public_inputs(
    mut lookup: impl FnMut(&'static str) -> Option<OsString>,
    mut read_file: impl FnMut(&OsStr) -> Result<Vec<u8>, PreparationRefusal>,
) -> PublicInputs {
    let edition = lookup("PN_EDITION");
    let edition_file = lookup("PN_EDITION_FILE");
    let mut inputs = PublicInputs {
        edition,
        edition_file,
        file_bytes: None,
        file_refused: false,
        listen_pid: None,
        listen_fds: None,
        listen_fdnames: None,
        listen_pidfdid: false,
        connection_input: false,
    };
    if inputs.edition.is_some() == inputs.edition_file.is_some() {
        return inputs;
    }
    if let Some(path) = inputs.edition_file.as_deref() {
        let Ok(bytes) = read_file(path) else {
            inputs.file_refused = true;
            return inputs;
        };
        inputs.file_bytes = Some(bytes);
    }
    inputs.listen_pid = lookup("LISTEN_PID");
    inputs.listen_fds = lookup("LISTEN_FDS");
    inputs.listen_fdnames = lookup("LISTEN_FDNAMES");
    inputs.listen_pidfdid = lookup("LISTEN_PIDFDID").is_some();
    inputs.connection_input = lookup("PN_CONNECTION_INPUT").is_some();
    inputs
}

#[cfg(test)]
pub(super) fn tested_prepare(
    command: &Command,
    argument_views: (&[OsString], &[OsString]),
    clock: Instant,
    fixture: &FixtureRequest,
    edition: Option<&str>,
    valid_notification: bool,
    calls: &std::cell::RefCell<Vec<&'static str>>,
) -> OriginPreparation<Prepared> {
    prepare_with(
        command,
        argument_views,
        clock,
        fixture,
        || {
            calls.borrow_mut().push("public_inputs");
            PublicInputs {
                edition: edition.map(OsString::from),
                edition_file: None,
                file_bytes: None,
                file_refused: false,
                listen_pid: None,
                listen_fds: None,
                listen_fdnames: None,
                listen_pidfdid: false,
                connection_input: false,
            }
        },
        || {
            calls.borrow_mut().push("notification");
            (
                None,
                NotificationValidity {
                    present: true,
                    form_valid: valid_notification,
                    final_symlink: false,
                    is_socket: valid_notification,
                    reason: if valid_notification { "valid_socket" } else { "form_refused" },
                    error_kind: None,
                    os_code: None,
                },
            )
        },
        |_| {
            calls.borrow_mut().push("signal_registration");
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        io,
        rc::Rc,
    };

    /// Claim: Injected named lookups and one opened-file boundary preserve selector-first acquisition, refuse conflicting selectors without opening, and never inspect a reserved descriptor or credential directory.
    /// ´claim:lifecycle:adapter-preparation-order´
    /// ´test:unit:adapter-preparation-order´
    #[test]
    fn adapter_preparation_order() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let looked = Rc::clone(&calls);
        let opened = Rc::clone(&calls);
        let read = acquire_public_inputs(
            move |name| {
                looked.borrow_mut().push(name.to_owned());
                (name == "PN_EDITION_FILE").then(|| OsString::from("/tmp/public-edition"))
            },
            move |path| {
                opened.borrow_mut().push(format!("open:{}", path.to_string_lossy()));
                Ok(b"public\n".to_vec())
            },
        );
        assert!(read.edition.is_none());
        assert_eq!(read.edition_file.as_deref(), Some(OsStr::new("/tmp/public-edition")));
        assert_eq!(read.file_bytes.as_deref(), Some(b"public\n".as_slice()));
        assert!(!read.file_refused);
        assert!(read.listen_pid.is_none());
        assert!(read.listen_fds.is_none());
        assert!(read.listen_fdnames.is_none());
        assert!(!read.listen_pidfdid);
        assert!(!read.connection_input);
        assert_eq!(
            calls.borrow().as_slice(),
            [
                "PN_EDITION",
                "PN_EDITION_FILE",
                "open:/tmp/public-edition",
                "LISTEN_PID",
                "LISTEN_FDS",
                "LISTEN_FDNAMES",
                "LISTEN_PIDFDID",
                "PN_CONNECTION_INPUT",
            ]
        );
        for present in [false, true] {
            let calls = Rc::new(RefCell::new(Vec::new()));
            let looked = Rc::clone(&calls);
            let opened = Rc::clone(&calls);
            let result = acquire_public_inputs(
                move |name| {
                    looked.borrow_mut().push(name.to_owned());
                    present.then(|| OsString::from("selection"))
                },
                move |_| {
                    opened.borrow_mut().push("open".to_owned());
                    Ok(Vec::new())
                },
            );
            assert!(result.file_bytes.is_none());
            assert!(!result.file_refused);
            assert_eq!(calls.borrow().as_slice(), ["PN_EDITION", "PN_EDITION_FILE"]);
        }
        let calls = Rc::new(RefCell::new(Vec::new()));
        let looked = Rc::clone(&calls);
        let opened = Rc::clone(&calls);
        let failed = acquire_public_inputs(
            move |name| {
                looked.borrow_mut().push(name.to_owned());
                (name == "PN_EDITION_FILE").then(|| OsString::from("/tmp/missing"))
            },
            move |_| {
                opened.borrow_mut().push("open".to_owned());
                Err(PreparationRefusal::EditionForm)
            },
        );
        assert!(failed.file_refused);
        assert_eq!(calls.borrow().as_slice(), ["PN_EDITION", "PN_EDITION_FILE", "open"]);
    }

    /// Claim: A test-written regular edition file is read through its opened descriptor within the grammar ceiling, while excess, nonregular and failed reads refuse without another path.
    /// ´claim:lifecycle:adapter-edition-file-is-bounded´
    /// ´test:unit:adapter-edition-file-is-bounded´
    #[test]
    fn adapter_edition_file_is_bounded() {
        struct FailedRead;
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("test read failure"))
            }
        }
        let directory = std::env::temp_dir().join(format!("pn-adapter-file-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("test-owned directory");
        let file = directory.join("selection");
        let coordinate =
            b"schema=org.peer-network.test.api-control-schema@1.0.0;register=org.peer-network.test.api-control-register@1.0.0\n";
        fs::write(&file, coordinate).expect("test-written public file");
        assert_eq!(read_public_file(file.as_os_str()), Ok(coordinate.to_vec()));
        fs::write(&file, vec![b'x'; MAX_EDITION_BYTES + 2]).expect("test-written excess");
        assert_eq!(read_public_file(file.as_os_str()), Err(PreparationRefusal::EditionForm));
        assert_eq!(read_public_file(directory.as_os_str()), Err(PreparationRefusal::EditionForm));
        assert_eq!(
            read_public_file(directory.join("missing").as_os_str()),
            Err(PreparationRefusal::EditionForm)
        );
        assert_eq!(read_bounded(FailedRead), Err(PreparationRefusal::EditionForm));
        fs::remove_file(&file).expect("remove test file");
        fs::remove_dir(&directory).expect("remove test directory");
    }

    /// Claim: A stop set on the owned atomic before subscription handoff remains visible through handoff and repeated reads without clearing or counting deliveries.
    /// ´claim:lifecycle:adapter-stop-is-latched´
    /// ´test:unit:adapter-stop-is-latched´
    #[test]
    fn adapter_stop_is_latched() {
        let flag = Arc::new(AtomicBool::new(false));
        let producer = Arc::clone(&flag);
        producer.store(true, Ordering::SeqCst);
        let (stream, observed) = subscribe_and_check(&flag, || Ok::<_, ()>("test stream")).expect("handoff");
        assert_eq!(stream, "test stream");
        assert!(observed);
        assert!(stop_latched(&flag));
        assert!(stop_latched(&producer));
    }

    /// Claim: Supplied pending and wake phases schedule only the one active absolute bound, and a ready command waits for signal without work polling or a timer.
    /// ´claim:lifecycle:adapter-wait-plan´
    /// ´test:unit:adapter-wait-plan´
    #[test]
    fn adapter_wait_plan() {
        assert_eq!(
            wait_plan(State::Starting, (Some(20), None, None)),
            WaitPlan {
                poll_work: true,
                deadline: Some(20)
            }
        );
        assert_eq!(
            wait_plan(State::Retiring, (None, Some(100), Some(30))),
            WaitPlan {
                poll_work: true,
                deadline: Some(30)
            }
        );
        assert_eq!(
            wait_plan(State::Retiring, (None, Some(100), None)),
            WaitPlan {
                poll_work: true,
                deadline: Some(100)
            }
        );
        assert_eq!(
            wait_plan(State::Ready, (None, None, None)),
            WaitPlan {
                poll_work: false,
                deadline: None
            }
        );
    }

    /// Claim: At the retained stopping or capped drain bound, supplied instants prevent another work poll before release, while an earlier instant admits exactly one poll.
    /// ´claim:lifecycle:adapter-stop-bound-precedes-wait´
    /// ´test:unit:adapter-stop-bound-precedes-wait´
    #[test]
    fn adapter_stop_bound_precedes_wait() {
        let polls = Cell::new(0);
        for deadline in [Some(30), Some(100)] {
            let result = poll_before_bound(deadline.expect("finite bound"), deadline, || polls.set(polls.get() + 1));
            assert_eq!(result, None);
        }
        assert_eq!(polls.get(), 0);
        assert_eq!(poll_before_bound(29, Some(30), || polls.set(polls.get() + 1)), Some(()));
        assert_eq!(polls.get(), 1);
    }

    /// Claim: One unbound nonblocking sender enqueues exactly READY=1 to a test-owned local receiver, and injected failed counts or errors consume one attempt without a retry.
    /// ´claim:lifecycle:adapter-ready-datagram´
    /// ´test:unit:adapter-ready-datagram´
    #[test]
    fn adapter_ready_datagram() {
        let directory = std::env::temp_dir().join(format!("pa-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("test-owned socket directory");
        let path = directory.join("n");
        let receiver = UnixDatagram::bind(&path).expect("test-only receiver");
        receiver.set_nonblocking(true).expect("nonblocking receiver");
        let sender = UnixDatagram::unbound().expect("unbound sender");
        sender.set_nonblocking(true).expect("nonblocking sender");
        let address = NotificationAddress {
            bytes: SecretBox::new(path.clone().into_os_string().into_encoded_bytes().into_boxed_slice()),
        };
        let validity = address.validity();
        assert!(validity.form_valid && validity.is_socket && !validity.final_symlink);
        assert!(notification_sent(address.send_once(&sender, b"READY=1")));
        let mut datagram = [0_u8; 16];
        let count = receiver.recv(&mut datagram).expect("queued datagram");
        assert_eq!(&datagram[..count], b"READY=1");
        let calls = Cell::new(0);
        for outcome in [
            Ok(6),
            Err(io::Error::from(io::ErrorKind::Interrupted)),
            Err(io::Error::from(io::ErrorKind::WouldBlock)),
        ] {
            let result = address.send_once_with(b"READY=1", |_, _| {
                calls.set(calls.get() + 1);
                outcome
            });
            assert!(!notification_sent(result));
        }
        assert_eq!(calls.get(), 3);
        let setup_calls = Cell::new(0);
        let failed_setup = setup_endpoint_with(
            7,
            || {
                setup_calls.set(setup_calls.get() + 1);
                UnixDatagram::unbound()
            },
            |_| {
                setup_calls.set(setup_calls.get() + 1);
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            },
        );
        assert!(matches!(failed_setup, Err(Event::EndpointSetupFailed { at: 7 })));
        assert_eq!(cause_name(Cause::NotificationFailed), "NotificationFailed");
        assert_eq!(setup_calls.get(), 2);
        assert_eq!(calls.get(), 3);
        drop(receiver);
        fs::remove_file(&path).expect("remove test socket");
        fs::remove_dir(&directory).expect("remove test directory");
    }

    /// Claim: Supplied inspection, orderly stop and closed failure completions retain the decided stdout and exit classes without installing a process-global runner.
    /// ´claim:lifecycle:adapter-command-statuses´
    /// ´test:unit:adapter-command-statuses´
    #[test]
    fn adapter_command_statuses() {
        let inspection = classify_complete(
            0,
            Some(PublicOutput::Inspection {
                edition: "public".to_owned(),
                source: EditionSource::Environment,
                supported: false,
            }),
            None,
        )
        .expect("inspection output");
        assert_eq!(
            inspection,
            json!({"edition":"public","source":"environment","supported":false})
        );
        let stopped = classify_complete(
            0,
            Some(PublicOutput::Stopped {
                edition: "public".to_owned(),
            }),
            Some(Cause::AfterReadyStop),
        )
        .expect("orderly stop output");
        assert_eq!(stopped, json!({"edition":"public","outcome":"stopped"}));
        for cause in [Cause::BeforeReadyStop, Cause::StartupTimeout, Cause::NotificationFailed] {
            assert_eq!(
                classify_complete(1, None, Some(cause))
                    .expect_err("failure has no stdout")
                    .to_string(),
                cause_name(cause)
            );
        }
        assert_eq!(
            classify_complete(1, None, None)
                .expect_err("closed configuration")
                .to_string(),
            "Configuration"
        );
        assert_eq!(
            classify_complete(
                1,
                None,
                Some(Cause::PreDispatchFailure {
                    class: "Unsupported",
                    ceiling: Some("source_nesting"),
                }),
            )
            .expect_err("bounded refusal")
            .to_string(),
            "Unsupported ceiling=source_nesting"
        );
        assert_eq!(
            classify_complete(
                1,
                None,
                Some(Cause::PreDispatchFailure {
                    class: "Unsupported",
                    ceiling: None,
                }),
            )
            .expect_err("unbounded refusal")
            .to_string(),
            "Unsupported ceiling=null"
        );
    }

    /// Claim: Production public formatting retains test-written selector values and closed errors, while a private notification sentinel appears only as its role and marker in debug and error paths.
    /// ´claim:lifecycle:adapter-output-classification´
    /// ´test:unit:adapter-output-classification´
    #[test]
    fn adapter_output_classification() {
        let private = b"/tmp/private-notification-sentinel";
        let address = NotificationAddress {
            bytes: SecretBox::new(private.to_vec().into_boxed_slice()),
        };
        let debug = format!("{address:?}");
        assert!(debug.contains("role: notification"));
        assert!(!debug.contains("private-notification-sentinel"));
        let missing = address.validity();
        assert_eq!(missing.reason, "metadata_failed");
        assert_eq!(missing.error_kind, Some(io::ErrorKind::NotFound));
        assert!(missing.os_code.is_some());
        let detail = missing.public_detail().to_string();
        assert!(detail.contains("metadata_failed"));
        assert!(!detail.contains("private-notification-sentinel"));
        let regular_file = std::env::temp_dir().join(format!("pa-meta-{}", std::process::id()));
        fs::write(&regular_file, b"fixture").expect("test-owned regular file");
        let file_address = NotificationAddress {
            bytes: SecretBox::new(regular_file.clone().into_os_string().into_encoded_bytes().into_boxed_slice()),
        };
        let file_validity = file_address.validity();
        assert_eq!(file_validity.reason, "not_socket");
        assert_eq!(file_validity.error_kind, None);
        fs::remove_file(&regular_file).expect("remove test-owned regular file");
        let public = PublicInputs {
            edition: Some(OsString::from("public-selection")),
            edition_file: None,
            file_bytes: None,
            file_refused: false,
            listen_pid: Some(OsString::from("42")),
            listen_fds: Some(OsString::from("0")),
            listen_fdnames: Some(OsString::from("")),
            listen_pidfdid: false,
            connection_input: true,
        };
        let observed = public.observed(&[OsString::from("pn"), OsString::from("start")]);
        let rendered = observed.to_string();
        assert_eq!(observed["PN_EDITION"], json!(b"public-selection"));
        assert_eq!(observed["LISTEN_PID"], json!(b"42"));
        assert!(rendered.contains("PN_CONNECTION_INPUT"));
        assert!(!rendered.contains("private-notification-sentinel"));
        assert_eq!(AdapterFailure::Configuration.to_string(), "Configuration");
        assert_eq!(
            AdapterFailure::Selected(Cause::NotificationFailed).to_string(),
            "NotificationFailed"
        );
    }
}
