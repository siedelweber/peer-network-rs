//! Supplied-fact preparation and the pure control lifecycle.
//! (´[ROOT-amend:api:health-lifecycle]´) (´[ROOT-amend:api:node-package]´)

use crate::{EntryError, ExecutionContext};
use pn_interchange::{EncodingUsage, Map, Text, TransportLimits, TransportMessage, TransportUsage, Value};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

const SCHEMA_PREFIX: &str = "schema=org.peer-network.test.api-control-schema@";
const REGISTER_PREFIX: &str = ";register=org.peer-network.test.api-control-register@";
const MAX_EDITION_BYTES: usize = SCHEMA_PREFIX.len() + REGISTER_PREFIX.len() + 6 * 20 + 4;
const START_QUERY: &str = "mutation { start { ready edition failure } }";

/// The two public edition-delivery forms. (´[ROOT-amend:api:health-lifecycle]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditionSource {
    /// The public environment value was supplied.
    Environment,
    /// A designated regular public file was supplied.
    File,
}

/// Supplied public and protected-capability validity facts; the process adapter owns their acquisition.
/// (´[ROOT-amend:api:health-lifecycle]´)
// Justified: These independent supplied facts represent distinct public presence and endpoint checks without adding another public support type.
#[expect(clippy::struct_excessive_bools)]
pub struct PreparationFacts<'a> {
    /// Command arguments, including the program name.
    pub arguments: &'a [&'a str],
    /// Presence and public value of `PN_EDITION`.
    pub edition: Option<&'a str>,
    /// Presence and public value of `PN_EDITION_FILE`.
    pub edition_file: Option<&'a str>,
    /// The designated file's bounded bytes, if read successfully as a regular file.
    pub file_bytes: Option<&'a [u8]>,
    /// `LISTEN_PID` metadata.
    pub listen_pid: Option<&'a str>,
    /// `LISTEN_FDS` metadata.
    pub listen_fds: Option<&'a str>,
    /// `LISTEN_FDNAMES` metadata.
    pub listen_fdnames: Option<&'a str>,
    /// Presence of `LISTEN_PIDFDID`, including an empty value.
    pub listen_pidfdid: bool,
    /// Presence of `PN_CONNECTION_INPUT`, including an empty value.
    pub connection_input: bool,
    /// The current process identifier supplied by the adapter.
    pub process_id: u32,
    /// Whether the protected notification capability was supplied for start.
    pub notification_present: bool,
    /// Whether the adapter admitted its private absolute filesystem address form.
    pub notification_form_valid: bool,
    /// Whether the protected endpoint's final component is a symlink.
    pub notification_final_symlink: bool,
    /// Whether the protected endpoint is a socket.
    pub notification_is_socket: bool,
}

impl std::fmt::Debug for PreparationFacts<'_> {
    #[doc = "Justified: Redacted preparation formatting inherits the checked lifecycle preparation span and never reads or emits private capability values."]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparationFacts")
            .field("argument_count", &self.arguments.len())
            .field("edition_present", &self.edition.is_some())
            .field("edition_file_present", &self.edition_file.is_some())
            .field(
                "descriptor_metadata_present",
                &(self.listen_pid.is_some() || self.listen_fds.is_some() || self.listen_fdnames.is_some()),
            )
            .field("connection_input_present", &self.connection_input)
            .field("notification_present", &self.notification_present)
            .finish()
    }
}

/// A fixed public reason for a preparation refusal.
/// (´[ROOT-amend:api:health-lifecycle]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationRefusal {
    /// The argument grammar was not admitted.
    Arguments,
    /// Both edition sources or neither were supplied.
    EditionSources,
    /// The selected edition source was malformed or unreadable.
    EditionForm,
    /// Reserved supervisor input was advertised.
    ReservedInput,
    /// The start notification endpoint was absent or invalid.
    Notification,
}

/// A checked public selection with the empty credential barrier established.
/// It conveys no resolver, limits, artifact, or completion authority.
/// (´[ROOT-amend:api:node-package]´)
#[derive(Debug)]
pub struct CheckedBootstrap {
    edition: String,
    source: EditionSource,
}

impl CheckedBootstrap {
    /// Check the supplied start facts before any worker or dispatch can be requested.
    /// (´[ROOT-amend:api:health-lifecycle]´)
    ///
    /// # Errors
    /// Returns a public usage reason for an invalid command, selection, reserved input, or endpoint.
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::CheckedBootstrap::new"
        )
    )]
    pub fn new(facts: &PreparationFacts<'_>) -> Result<Self, PreparationRefusal> {
        command(facts.arguments, "start")?;
        let (edition, source) = select_edition(facts)?;
        reserved_input(facts)?;
        notification(facts)?;
        Ok(Self {
            edition: edition.to_owned(),
            source,
        })
    }

    /// The checked public coordinate text.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::CheckedBootstrap::edition"
        )
    )]
    pub fn edition(&self) -> &str {
        &self.edition
    }

    /// The public source of the selection.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::CheckedBootstrap::source"
        )
    )]
    pub fn source(&self) -> EditionSource {
        self.source
    }
}

/// The public inspection result; support is false until both assigned artifacts exist.
/// (´[ROOT-amend:api:health-lifecycle]´)
#[derive(Debug)]
pub struct EditionInspection {
    edition: String,
    source: EditionSource,
    supported: bool,
}

impl EditionInspection {
    /// Check edition-command facts without acquiring a notification endpoint.
    ///
    /// # Errors
    /// Returns a public usage reason for invalid arguments, selection or reserved input.
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::EditionInspection::new"
        )
    )]
    pub fn new(facts: &PreparationFacts<'_>) -> Result<Self, PreparationRefusal> {
        command(facts.arguments, "edition")?;
        let (edition, source) = select_edition(facts)?;
        reserved_input(facts)?;
        let supported = crate::admission::embedded_edition().is_ok_and(|embedded_pair| edition == embedded_pair);
        Ok(Self {
            edition: edition.to_owned(),
            source,
            supported,
        })
    }

    /// The exact checked public coordinate text.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::EditionInspection::edition"
        )
    )]
    pub fn edition(&self) -> &str {
        &self.edition
    }

    /// The public source of this inspection.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::EditionInspection::source"
        )
    )]
    pub fn source(&self) -> EditionSource {
        self.source
    }

    /// Whether both generated artifacts are in the embedded roster.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::EditionInspection::supported"
        )
    )]
    pub fn supported(&self) -> bool {
        self.supported
    }
}

fn command(arguments: &[&str], wanted: &str) -> Result<(), PreparationRefusal> {
    if arguments.len() == 2 && arguments[1] == wanted {
        Ok(())
    } else {
        Err(PreparationRefusal::Arguments)
    }
}

fn version(source: &str) -> bool {
    let mut parts = source.split('.');
    for _ in 0..3 {
        let Some(part) = parts.next() else { return false };
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if part.parse::<u64>().is_err() {
            return false;
        }
    }
    parts.next().is_none()
}

fn edition_form(source: &str) -> bool {
    if source.len() > MAX_EDITION_BYTES {
        return false;
    }
    let Some(rest) = source.strip_prefix(SCHEMA_PREFIX) else {
        return false;
    };
    let Some((schema, register)) = rest.split_once(REGISTER_PREFIX) else {
        return false;
    };
    version(schema) && version(register)
}

fn select_edition<'a>(facts: &'a PreparationFacts<'_>) -> Result<(&'a str, EditionSource), PreparationRefusal> {
    match (facts.edition, facts.edition_file) {
        (Some(_), Some(_)) | (None, None) => Err(PreparationRefusal::EditionSources),
        (Some(value), None) => edition_form(value)
            .then_some((value, EditionSource::Environment))
            .ok_or(PreparationRefusal::EditionForm),
        (None, Some(path)) => {
            if !path.starts_with('/') || path.as_bytes().contains(&0) {
                return Err(PreparationRefusal::EditionForm);
            }
            let bytes = facts.file_bytes.ok_or(PreparationRefusal::EditionForm)?;
            if bytes.len() < 2 || bytes.len() > MAX_EDITION_BYTES + 1 || bytes.last() != Some(&b'\n') {
                return Err(PreparationRefusal::EditionForm);
            }
            let value = std::str::from_utf8(&bytes[..bytes.len() - 1]).map_err(|_| PreparationRefusal::EditionForm)?;
            edition_form(value)
                .then_some((value, EditionSource::File))
                .ok_or(PreparationRefusal::EditionForm)
        }
    }
}

fn reserved_input(facts: &PreparationFacts<'_>) -> Result<(), PreparationRefusal> {
    if facts.listen_pidfdid || facts.connection_input {
        return Err(PreparationRefusal::ReservedInput);
    }
    match (facts.listen_pid, facts.listen_fds, facts.listen_fdnames) {
        (None, None, None) => Ok(()),
        (Some(pid), Some("0"), Some("")) if pid.parse::<u32>() == Ok(facts.process_id) => Ok(()),
        _ => Err(PreparationRefusal::ReservedInput),
    }
}

fn notification(facts: &PreparationFacts<'_>) -> Result<(), PreparationRefusal> {
    if !facts.notification_present
        || !facts.notification_form_valid
        || facts.notification_final_symlink
        || !facts.notification_is_socket
    {
        return Err(PreparationRefusal::Notification);
    }
    Ok(())
}

/// Closed lifecycle states, inspected but never assigned by an adapter.
/// (´[ROOT-amend:api:health-lifecycle]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Captured origin only.
    Captured,
    /// Synchronous preparation.
    Preparing,
    /// A terminal decision awaits installation.
    PreparedTerminal,
    /// Inspection awaits installation.
    PreparedInspection,
    /// A checked start awaits installation.
    PreparedStart,
    /// The shared runner attempted installation.
    Installed,
    /// The build-owned context is being constructed.
    Constructing,
    /// The one byte entry is outstanding.
    Starting,
    /// A complete ready candidate awaits the final check.
    ReadyCheck,
    /// The single send attempt is in flight.
    Notifying,
    /// Successful send has published readiness.
    Ready,
    /// Owned work is being cancelled and released.
    Retiring,
    /// The runner completes output and observation.
    Finalizing,
    /// No further work is admitted.
    Exited,
}

/// A programming-error refusal with no state change or effect request.
/// (´[ROOT-amend:api:node-package]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionRefused;

/// Fixed public command causes retained without private adapter values.
/// (´[ROOT-amend:api:health-lifecycle]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// A graceful stop before readiness.
    BeforeReadyStop,
    /// A graceful stop after readiness.
    AfterReadyStop,
    /// The enclosing startup deadline elapsed.
    StartupTimeout,
    /// The bounded retirement deadline elapsed.
    StoppingTimeout,
    /// Returned bytes or a typed refusal did not establish a start result.
    PresentationUnknown,
    /// A complete start failure was selected by the executor.
    StartFailure(&'static str),
    /// The fixed request or a pre-dispatch entry stage refused.
    EntryFailure(&'static str),
    /// A complete pre-dispatch message retains its fixed class and ceiling key.
    PreDispatchFailure {
        class: &'static str,
        ceiling: Option<&'static str>,
    },
    /// The notification send failed.
    NotificationFailed,
    /// A checked release failed.
    CleanupFailed,
    /// The controller driver reported an internal fault.
    TransitionRefused,
}

/// A finite supplied fact for one transition; effects are reported separately.
/// (´[ROOT-amend:api:node-package]´)
#[derive(Debug)]
pub enum Event {
    /// Enter synchronous preparation at the supplied monotonic instant.
    Prepare { at: u64 },
    /// Preparation chose a public terminal with the given exit class.
    PreparedTerminal { exit: u8 },
    /// Preparation chose a checked inspection.
    PreparedInspection(EditionInspection),
    /// Preparation established the empty barrier for start.
    PreparedStart(CheckedBootstrap),
    /// The runner found a result continuation with terminal stdout.
    TerminalOutputRefused,
    /// Observation installation succeeded or was unavailable.
    Installed,
    /// Observation installation failed as configuration.
    InstallationFailed,
    /// Continue the retained decision after installation.
    Continue,
    /// The adapter completed checked construction.
    Constructed { result: Result<(), EntryError>, at: u64 },
    /// Check a pending entry against a supplied instant and stop fact before another poll.
    EntryPendingCheck { at: u64, stop: bool },
    /// The adapter reports the actual bounded byte entry's completion instant and outcome.
    EntryCompleted {
        result: Result<TransportMessage, EntryError>,
        at: u64,
    },
    /// A final check just before authorizing notification.
    ReadyChecked { at: u64, stop: bool, checked_failure: bool },
    /// The adapter reports the one send outcome and facts first observed after authorization.
    NotificationCompleted {
        sent: bool,
        at: u64,
        stop: bool,
        checked_failure: bool,
    },
    /// A supported graceful stop at the supplied instant.
    Stop { at: u64 },
    /// An internal driver fault at the supplied instant.
    DriverFault { at: u64 },
    /// A checked runtime or adapter failure at the supplied instant.
    RuntimeFailure { at: u64 },
    /// Endpoint setup failed after checked construction, before dispatch.
    EndpointSetupFailed { at: u64 },
    /// The one cancellable future settled or reached its retained drain bound.
    WorkSettled { at: u64, complete: bool },
    /// Owned work and resources have been settled, with a checked release result.
    Retired { at: u64, cleanup_failed: bool },
    /// The shared runner finished its output and observation scope.
    Finalized,
}

impl Event {
    /// Classify only SIGTERM as a supported graceful stop; other signals keep inherited disposition.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::Event::supported_signal"
        )
    )]
    pub fn supported_signal(number: i32, at: u64) -> Option<Self> {
        if number == 15 { Some(Self::Stop { at }) } else { None }
    }
}

/// An adapter effect request; inspecting it performs no effect.
/// (´[ROOT-amend:api:node-package]´)
#[derive(Debug)]
pub enum Action {
    /// Attempt shared observation installation once.
    Install,
    /// Report the retained terminal through the shared runner.
    Complete {
        exit: u8,
        stdout: Option<PublicOutput>,
        cause: Option<Cause>,
        /// Timeout and checked cleanup diagnostics beside the retained first command cause.
        retirement_diagnostics: [Option<Cause>; 2],
    },
    /// Construct a checked context once.
    Construct,
    /// Call the existing byte entry with these bounded request bytes and the checked context.
    Dispatch(Vec<u8>),
    /// Send exactly these bytes once through the protected endpoint.
    Notify(&'static [u8]),
    /// Close dispatch and notification permission.
    Close,
    /// Request cancellation of the one owned future.
    Cancel { until: Option<u64> },
    /// Release retained request and response buffers.
    ReleaseBuffers,
    /// Release the execution context.
    ReleaseContext,
    /// Release the notification endpoint.
    ReleaseEndpoint,
    /// Release public preparation state.
    ReleasePreparation,
}

/// Bounded public output selected by the controller; the binary owns JSON serialization.
/// (´[ROOT-amend:api:health-lifecycle]´)
#[derive(Debug)]
pub enum PublicOutput {
    /// The edition inspection object's exact member order is edition, source, supported.
    Inspection {
        edition: String,
        source: EditionSource,
        supported: bool,
    },
    /// The only successful stop object has edition then outcome=stopped.
    Stopped { edition: String },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Caps {
    pub(crate) transport: usize,
    pub(crate) response: usize,
    pub(crate) decoded_bytes: usize,
    pub(crate) decoded_items: usize,
    pub(crate) input_nesting: usize,
    pub(crate) cbor_nesting: usize,
    pub(crate) decoding_work: usize,
    pub(crate) shell_start: u64,
    pub(crate) shell_stop: u64,
    pub(crate) cancellation_drain: u64,
}

/// Opaque owner of the finite state and its retained cause and deadlines.
/// It never reads the process environment or executes an action.
/// (´[ROOT-amend:api:node-package]´)
#[derive(Debug)]
// Justified: Each Boolean tracks a different phase or one-time effect in the decided closed lifecycle table.
#[expect(clippy::struct_excessive_bools)]
pub struct Controller {
    state: State,
    bootstrap: Option<CheckedBootstrap>,
    inspection: Option<EditionInspection>,
    terminal_exit: Option<u8>,
    caps: Option<Caps>,
    preparation_at: Option<u64>,
    startup_deadline: Option<u64>,
    stop_deadline: Option<u64>,
    drain_deadline: Option<u64>,
    cause: Option<Cause>,
    notified: bool,
    construction_attempted: bool,
    construction_succeeded: bool,
    dispatched: bool,
    work_pending: bool,
    cancelled: Arc<AtomicBool>,
    served_edition: Option<String>,
    work_settled: bool,
    release_requested: bool,
    cleanup_failed: bool,
    stopping_timed_out: bool,
    pending_stop: Option<u64>,
    pending_failure: Option<(u64, Cause)>,
    test_caps: Option<Caps>,
}

impl Controller {
    /// Create a controller with no installed limits or effects.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::Controller::new"
        )
    )]
    // Justified: The decided public surface has explicit construction and cannot add a second public Default constructor.
    #[expect(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            state: State::Captured,
            bootstrap: None,
            inspection: None,
            terminal_exit: None,
            caps: None,
            preparation_at: None,
            startup_deadline: None,
            stop_deadline: None,
            drain_deadline: None,
            cause: None,
            notified: false,
            construction_attempted: false,
            construction_succeeded: false,
            dispatched: false,
            work_pending: false,
            cancelled: Arc::new(AtomicBool::new(false)),
            served_edition: None,
            work_settled: false,
            release_requested: false,
            cleanup_failed: false,
            stopping_timed_out: false,
            pending_stop: None,
            pending_failure: None,
            test_caps: None,
        }
    }

    /// Inspect the current state without changing readiness.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::Controller::state"
        )
    )]
    pub fn state(&self) -> State {
        self.state
    }

    /// Inspect active absolute startup, stopping and cancellation-drain deadlines.
    /// Values use the supplied monotonic nanosecond timeline and inspection performs no effect.
    /// (´[ROOT-amend:api:health-lifecycle]´)
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::Controller::active_deadlines"
        )
    )]
    pub fn active_deadlines(&self) -> (Option<u64>, Option<u64>, Option<u64>) {
        let startup = matches!(
            self.state,
            State::Constructing | State::Starting | State::ReadyCheck | State::Notifying
        )
        .then_some(self.startup_deadline)
        .flatten();
        let stopping = (self.state == State::Retiring).then_some(self.stop_deadline).flatten();
        let drain = (self.state == State::Retiring && self.work_pending && !self.work_settled)
            .then_some(self.drain_deadline)
            .flatten();
        (startup, stopping, drain)
    }

    /// Construct only from the retained checked bootstrap and build-owned agreement.
    /// The currently pending register refuses before dispatch.
    ///
    /// # Errors
    /// An out-of-state or repeated attempt is a transition refusal; a pending or malformed
    /// build-owned artifact is the existing entry refusal, nested inside the successful transition.
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::Controller::construct_context"
        )
    )]
    pub fn construct_context(&mut self) -> Result<Result<ExecutionContext, EntryError>, TransitionRefused> {
        if self.state != State::Constructing || self.construction_attempted {
            return Err(TransitionRefused);
        }
        self.construction_attempted = true;
        let checked = self.bootstrap.as_ref().ok_or(TransitionRefused)?;
        #[cfg(not(test))]
        if self.test_caps.is_some() {
            return Err(TransitionRefused);
        }
        #[cfg(test)]
        let result = match self.test_caps {
            Some(caps) => ExecutionContext::test_checked_from_bootstrap(checked, self.cancelled.clone(), caps),
            None => ExecutionContext::checked_from_bootstrap(checked, self.cancelled.clone()),
        };
        #[cfg(not(test))]
        let result = ExecutionContext::checked_from_bootstrap(checked, self.cancelled.clone());
        let result = result.and_then(|context| {
            let caps = context.lifecycle_caps()?;
            let started = self.preparation_at.ok_or(EntryError::Configuration)?;
            let deadline = started.checked_add(caps.shell_start).ok_or(EntryError::Configuration)?;
            self.caps = Some(caps);
            self.startup_deadline = Some(deadline);
            self.construction_succeeded = true;
            Ok(context)
        });
        if let Ok(context) = &result {
            self.served_edition = Some(context.lifecycle_edition().to_owned());
        }
        Ok(result)
    }

    #[cfg(test)]
    fn with_test_caps(mut self, caps: Caps) -> Self {
        self.test_caps = Some(caps);
        self
    }

    /// Advance exactly one admitted table transition and return its bounded effect requests.
    ///
    /// # Errors
    /// An unlisted state/event pair refuses without effects or state mutation.
    #[tracing::instrument(
        name = "rule:observe:spans",
        ret,
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "lifecycle::Controller::advance"
        )
    )]
    // Justified: Keeping the closed transition table in one match lets each state and event pair be audited together.
    #[expect(clippy::too_many_lines)]
    pub fn advance(&mut self, event: Event) -> Result<Vec<Action>, TransitionRefused> {
        match (self.state, event) {
            (State::Captured, Event::Prepare { at }) => {
                self.preparation_at = Some(at);
                self.state = State::Preparing;
                Ok(Vec::new())
            }
            (State::Preparing, Event::PreparedTerminal { exit }) if exit == 0 || exit == 2 => {
                self.terminal_exit = Some(exit);
                self.state = State::PreparedTerminal;
                Ok(vec![Action::Install])
            }
            (State::Preparing, Event::PreparedInspection(inspection)) => {
                self.inspection = Some(inspection);
                self.state = State::PreparedInspection;
                Ok(vec![Action::Install])
            }
            (State::Preparing, Event::PreparedStart(bootstrap)) => {
                self.bootstrap = Some(bootstrap);
                self.state = State::PreparedStart;
                Ok(vec![Action::Install])
            }
            (State::PreparedTerminal | State::PreparedInspection | State::PreparedStart, Event::TerminalOutputRefused) => {
                self.inspection = None;
                self.bootstrap = None;
                self.terminal_exit = Some(2);
                self.state = State::PreparedTerminal;
                Ok(vec![Action::Install])
            }
            (State::PreparedTerminal | State::PreparedInspection | State::PreparedStart, Event::Installed) => {
                self.state = State::Installed;
                Ok(Vec::new())
            }
            (State::PreparedTerminal | State::PreparedInspection | State::PreparedStart, Event::InstallationFailed) => {
                self.state = State::Finalizing;
                Ok(vec![Action::Complete {
                    exit: 2,
                    stdout: None,
                    cause: None,
                    retirement_diagnostics: [None, None],
                }])
            }
            (State::Installed, Event::Continue) => self.continue_installed(),
            (State::Constructing, Event::EndpointSetupFailed { at }) if self.construction_succeeded => {
                self.retire(at, Cause::NotificationFailed)
            }
            (State::Constructing, Event::Constructed { result, at }) if self.construction_attempted => match result {
                Ok(()) => {
                    let Some(caps) = self.caps else {
                        return Err(TransitionRefused);
                    };
                    let Some(deadline) = self.startup_deadline else {
                        return Err(TransitionRefused);
                    };
                    if at >= deadline {
                        return self.retire(at, Cause::StartupTimeout);
                    }
                    self.state = State::Starting;
                    match fixed_request(caps.transport) {
                        Ok(bytes) => {
                            self.dispatched = true;
                            self.work_pending = true;
                            Ok(vec![Action::Dispatch(bytes)])
                        }
                        Err(()) => self.retire(at, Cause::EntryFailure("Configuration")),
                    }
                }
                Err(error) => self.retire(at, Cause::EntryFailure(entry_name(error))),
            },
            (State::Starting, Event::EntryPendingCheck { at, stop }) => {
                if stop {
                    self.retire(at, Cause::BeforeReadyStop)
                } else if self.startup_deadline.is_some_and(|deadline| at >= deadline) {
                    self.retire(at, Cause::StartupTimeout)
                } else {
                    Ok(Vec::new())
                }
            }
            (State::Starting, Event::EntryCompleted { result, at }) => {
                self.work_pending = false;
                let outcome = self.classify_entry(result);
                match outcome {
                    Ok(()) => {
                        self.state = State::ReadyCheck;
                        Ok(Vec::new())
                    }
                    Err(cause) => self.retire(at, cause),
                }
            }
            (
                State::ReadyCheck,
                Event::ReadyChecked {
                    at,
                    stop,
                    checked_failure,
                },
            ) => {
                if stop {
                    self.retire(at, Cause::BeforeReadyStop)
                } else if self.startup_deadline.is_some_and(|deadline| at >= deadline) {
                    self.retire(at, Cause::StartupTimeout)
                } else if checked_failure {
                    self.retire(at, Cause::EntryFailure("Configuration"))
                } else {
                    self.state = State::Notifying;
                    Ok(vec![Action::Notify(b"READY=1")])
                }
            }
            (
                State::Notifying,
                Event::NotificationCompleted {
                    sent,
                    at,
                    stop,
                    checked_failure,
                },
            ) => {
                let retirement_at = self
                    .pending_stop
                    .into_iter()
                    .chain(self.pending_failure.map(|(observed_at, _)| observed_at))
                    .fold(at, u64::min);
                if sent {
                    self.notified = true;
                    self.state = State::Ready;
                    if let Some((_, cause)) = self.pending_failure {
                        self.retire(retirement_at, cause)
                    } else if checked_failure {
                        self.retire(retirement_at, Cause::EntryFailure("Configuration"))
                    } else if self.startup_deadline.is_some_and(|deadline| at >= deadline) {
                        self.retire(retirement_at, Cause::StartupTimeout)
                    } else if stop || self.pending_stop.is_some() {
                        self.retire(retirement_at, Cause::AfterReadyStop)
                    } else {
                        self.startup_deadline = None;
                        Ok(Vec::new())
                    }
                } else {
                    self.retire(retirement_at, Cause::NotificationFailed)
                }
            }
            (State::Ready, Event::Stop { at }) => self.retire(at, Cause::AfterReadyStop),
            (State::Constructing | State::Starting | State::ReadyCheck, Event::Stop { at }) => {
                self.retire(at, Cause::BeforeReadyStop)
            }
            (
                State::Installed | State::Constructing | State::Starting | State::ReadyCheck | State::Ready,
                Event::DriverFault { at },
            ) => self.retire(at, Cause::TransitionRefused),
            (
                State::Installed | State::Constructing | State::Starting | State::ReadyCheck | State::Ready,
                Event::RuntimeFailure { at },
            ) => self.retire(at, Cause::EntryFailure("Configuration")),
            (State::Retiring, Event::EntryCompleted { at, .. }) if self.work_pending && !self.work_settled => {
                self.work_pending = false;
                self.work_settled = true;
                if self.drain_deadline.is_some_and(|deadline| at >= deadline)
                    || self.stop_deadline.is_some_and(|deadline| at >= deadline)
                {
                    self.stopping_timed_out = true;
                }
                self.drain_deadline = None;
                Ok(self.release_actions())
            }
            (State::Retiring, Event::WorkSettled { at, complete }) if self.work_pending && !self.work_settled => {
                self.work_pending = false;
                self.work_settled = true;
                if !complete || self.drain_deadline.is_some_and(|deadline| at >= deadline) {
                    self.stopping_timed_out = true;
                }
                self.drain_deadline = None;
                Ok(self.release_actions())
            }
            (State::Retiring, Event::Retired { at, cleanup_failed }) if self.release_requested => {
                self.cleanup_failed |= cleanup_failed;
                if self.stop_deadline.is_some_and(|deadline| at >= deadline) {
                    self.stopping_timed_out = true;
                }
                self.state = State::Finalizing;
                let cause = self.cause;
                let success = cause == Some(Cause::AfterReadyStop) && !self.cleanup_failed && !self.stopping_timed_out;
                let stdout = if success {
                    self.bootstrap.as_ref().map(|b| PublicOutput::Stopped {
                        edition: b.edition.clone(),
                    })
                } else {
                    None
                };
                Ok(vec![Action::Complete {
                    exit: u8::from(!success),
                    stdout,
                    cause,
                    retirement_diagnostics: [
                        self.stopping_timed_out.then_some(Cause::StoppingTimeout),
                        self.cleanup_failed.then_some(Cause::CleanupFailed),
                    ],
                }])
            }
            (State::Finalizing, Event::Finalized) => {
                self.state = State::Exited;
                Ok(Vec::new())
            }
            (State::Retiring | State::Finalizing | State::Exited, Event::Stop { .. }) => Ok(Vec::new()),
            (State::PreparedStart, Event::Stop { .. }) => {
                self.cause = Some(Cause::BeforeReadyStop);
                self.bootstrap = None;
                self.terminal_exit = Some(1);
                self.state = State::PreparedTerminal;
                Ok(vec![Action::Install])
            }
            (State::Installed, Event::Stop { at }) if self.bootstrap.is_some() => self.retire(at, Cause::BeforeReadyStop),
            (State::Notifying, Event::Stop { at }) => {
                self.pending_stop.get_or_insert(at);
                Ok(Vec::new())
            }
            (State::Notifying, Event::DriverFault { at }) => {
                self.pending_failure.get_or_insert((at, Cause::TransitionRefused));
                Ok(Vec::new())
            }
            (State::Notifying, Event::RuntimeFailure { at }) => {
                self.pending_failure.get_or_insert((at, Cause::EntryFailure("Configuration")));
                Ok(Vec::new())
            }
            (State::PreparedTerminal | State::PreparedInspection | State::PreparedStart, Event::DriverFault { .. }) => {
                self.inspection = None;
                self.bootstrap = None;
                self.terminal_exit = Some(1);
                self.cause = Some(Cause::TransitionRefused);
                self.state = State::PreparedTerminal;
                Ok(vec![Action::Install])
            }
            (State::Captured | State::Preparing, Event::DriverFault { .. }) => {
                self.state = State::Finalizing;
                Ok(vec![Action::Complete {
                    exit: 1,
                    stdout: None,
                    cause: Some(Cause::TransitionRefused),
                    retirement_diagnostics: [None, None],
                }])
            }
            (State::Retiring, Event::DriverFault { .. }) => {
                self.cleanup_failed = true;
                Ok(Vec::new())
            }
            _ => Err(TransitionRefused),
        }
    }

    fn continue_installed(&mut self) -> Result<Vec<Action>, TransitionRefused> {
        if let Some(exit) = self.terminal_exit {
            self.state = State::Finalizing;
            return Ok(vec![Action::Complete {
                exit,
                stdout: None,
                cause: self.cause,
                retirement_diagnostics: [None, None],
            }]);
        }
        if let Some(inspection) = self.inspection.as_ref() {
            self.state = State::Finalizing;
            return Ok(vec![Action::Complete {
                exit: 0,
                stdout: Some(PublicOutput::Inspection {
                    edition: inspection.edition.clone(),
                    source: inspection.source,
                    supported: inspection.supported,
                }),
                cause: None,
                retirement_diagnostics: [None, None],
            }]);
        }
        if self.bootstrap.is_some() {
            self.state = State::Constructing;
            return Ok(vec![Action::Construct]);
        }
        Err(TransitionRefused)
    }

    // Justified: The table's transition arms return one refusal-aware result type, including retirement arms that cannot themselves refuse.
    #[expect(clippy::unnecessary_wraps)]
    fn retire(&mut self, at: u64, cause: Cause) -> Result<Vec<Action>, TransitionRefused> {
        if self.cause.is_none() {
            self.cause = Some(cause);
        }
        self.state = State::Retiring;
        self.cancelled.store(true, Ordering::Release);
        if let Some(caps) = self.caps {
            self.stop_deadline = at.checked_add(caps.shell_stop);
            if self.work_pending {
                self.drain_deadline = at
                    .checked_add(caps.cancellation_drain)
                    .map(|end| self.stop_deadline.map_or(end, |stop| end.min(stop)));
            }
        }
        let mut actions = vec![Action::Close];
        if self.work_pending {
            actions.push(Action::Cancel {
                until: self.drain_deadline,
            });
        } else {
            actions.extend(self.release_actions());
        }
        Ok(actions)
    }

    fn release_actions(&mut self) -> Vec<Action> {
        self.release_requested = true;
        let mut actions = Vec::new();
        if self.dispatched {
            actions.push(Action::ReleaseBuffers);
        }
        if self.caps.is_some() {
            actions.push(Action::ReleaseContext);
        }
        if self.bootstrap.is_some() {
            actions.push(Action::ReleaseEndpoint);
        }
        actions.push(Action::ReleasePreparation);
        actions
    }

    fn classify_entry(&self, result: Result<TransportMessage, EntryError>) -> Result<(), Cause> {
        let message = result.map_err(|_| Cause::PresentationUnknown)?;
        let caps = self.caps.ok_or(Cause::PresentationUnknown)?;
        let selected = self.bootstrap.as_ref().ok_or(Cause::PresentationUnknown)?;
        let served = self.served_edition.as_deref().ok_or(Cause::PresentationUnknown)?;
        classify_message(message.as_bytes(), caps, served, &selected.edition)
    }
}

fn entry_name(error: EntryError) -> &'static str {
    match error {
        EntryError::LimitsUnadmitted => "LimitsUnadmitted",
        EntryError::Configuration => "Configuration",
        EntryError::DecoderContract => "DecoderContract",
        EntryError::ResponseLimit(_) => "ResponseLimit",
        EntryError::DuplicateResponseName => "DuplicateResponseName",
        EntryError::ResponseValueUnsupported => "ResponseValueUnsupported",
    }
}

fn fixed_request(ceiling: usize) -> Result<Vec<u8>, ()> {
    let map = Map::new([(
        Value::Text(Text::from("query".to_owned())),
        Value::Text(Text::from(START_QUERY.to_owned())),
    )])
    .map_err(|_| ())?;
    let mut usage = EncodingUsage::default();
    Value::Map(map)
        .to_canonical_bytes_budgeted(ceiling, &mut usage, |_| Ok(()))
        .map_err(|_| ())
}

fn item<'a>(map: &'a Map, key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(name, value)| match name {
        Value::Text(name) if name.as_str() == key => Some(value),
        _ => None,
    })
}

fn text<'a>(map: &'a Map, key: &str) -> Option<&'a str> {
    match item(map, key) {
        Some(Value::Text(value)) => Some(value.as_str()),
        _ => None,
    }
}

fn object<'a>(map: &'a Map, key: &str) -> Option<&'a Map> {
    match item(map, key) {
        Some(Value::Map(value)) => Some(value),
        _ => None,
    }
}

fn classify_message(bytes: &[u8], caps: Caps, served: &str, selected: &str) -> Result<(), Cause> {
    let mut usage = TransportUsage::default();
    let limits = TransportLimits {
        input_bytes: caps.response,
        allocation_bytes: caps.decoded_bytes,
        items: caps.decoded_items,
        depth: caps.input_nesting,
        nesting: caps.cbor_nesting,
        work: caps.decoding_work,
    };
    let value = Value::from_transport_bytes(bytes, limits, &mut usage).map_err(|_| Cause::PresentationUnknown)?;
    let Value::Map(root) = value else {
        return Err(Cause::PresentationUnknown);
    };
    if root.len() == 1 {
        if let Some(data) = object(&root, "data") {
            if data.len() != 1 {
                return Err(Cause::PresentationUnknown);
            }
            let start = object(data, "start").ok_or(Cause::PresentationUnknown)?;
            if start.len() != 3 {
                return Err(Cause::PresentationUnknown);
            }
            let ready = match item(start, "ready") {
                Some(Value::Bool(ready)) => *ready,
                _ => return Err(Cause::PresentationUnknown),
            };
            let edition = text(start, "edition").ok_or(Cause::PresentationUnknown)?;
            if edition != served {
                return Err(Cause::PresentationUnknown);
            }
            let failure = item(start, "failure").ok_or(Cause::PresentationUnknown)?;
            return match failure {
                Value::Null if ready && selected == served => Ok(()),
                Value::Text(name) if !ready => {
                    let name = match name.as_str() {
                        "EditionUnsupported" => "EditionUnsupported",
                        "BootstrapInvalid" => "BootstrapInvalid",
                        "ResourceLimit" => "ResourceLimit",
                        "Cancelled" => "Cancelled",
                        "StartFailed" => "StartFailed",
                        _ => return Err(Cause::PresentationUnknown),
                    };
                    Err(Cause::StartFailure(name))
                }
                _ => Err(Cause::PresentationUnknown),
            };
        }
        if let Some(Value::Array(errors)) = item(&root, "errors") {
            if errors.len() != 1 {
                return Err(Cause::PresentationUnknown);
            }
            let Some(Value::Map(error)) = errors.as_slice().first() else {
                return Err(Cause::PresentationUnknown);
            };
            if error.len() != 2 {
                return Err(Cause::PresentationUnknown);
            }
            let Some(extensions) = object(error, "extensions") else {
                return Err(Cause::PresentationUnknown);
            };
            if extensions.len() != 3 || text(extensions, "edition") != Some(served) || text(error, "message").is_none() {
                return Err(Cause::PresentationUnknown);
            }
            let class = text(extensions, "class").ok_or(Cause::PresentationUnknown)?;
            let ceiling = item(extensions, "ceiling").ok_or(Cause::PresentationUnknown)?;
            let (name, sentence) = match class {
                "Malformed" => ("Malformed", "Request syntax is malformed."),
                "Invalid" => ("Invalid", "Request validation failed."),
                "Unsupported" => ("Unsupported", "Request exceeds the supported operation or limits."),
                "Cancelled" => ("Cancelled", "Request was cancelled before dispatch."),
                "ResourceLimit" => ("ResourceLimit", "Response cannot be completed within the declared limits."),
                _ => return Err(Cause::PresentationUnknown),
            };
            if text(error, "message") != Some(sentence) {
                return Err(Cause::PresentationUnknown);
            }
            return match (name, ceiling) {
                ("ResourceLimit", Value::Text(key)) if key.as_str() == "execution" => Err(Cause::PreDispatchFailure {
                    class: name,
                    ceiling: Some("execution"),
                }),
                ("Malformed" | "Invalid" | "Cancelled" | "Unsupported", Value::Null) => Err(Cause::PreDispatchFailure {
                    class: name,
                    ceiling: None,
                }),
                ("Unsupported", Value::Text(key)) => Err(known_ceiling(key.as_str()).map_or(
                    Cause::PresentationUnknown,
                    |ceiling| Cause::PreDispatchFailure {
                        class: name,
                        ceiling: Some(ceiling),
                    },
                )),
                _ => Err(Cause::PresentationUnknown),
            };
        }
    }
    Err(Cause::PresentationUnknown)
}

fn known_ceiling(key: &str) -> Option<&'static str> {
    match key {
        "graphql_source" => Some("graphql_source"),
        "transport" => Some("transport"),
        "decoded_bytes" => Some("decoded_bytes"),
        "decoded_items" => Some("decoded_items"),
        "cbor_nesting" => Some("cbor_nesting"),
        "input_nesting" => Some("input_nesting"),
        "decoding_work" => Some("decoding_work"),
        "lexical_tokens" => Some("lexical_tokens"),
        "source_nesting" => Some("source_nesting"),
        "selection_depth" => Some("selection_depth"),
        "root_selections" => Some("root_selections"),
        "fields" => Some("fields"),
        "aliases" => Some("aliases"),
        "fragment_work" => Some("fragment_work"),
        "resolver_work" => Some("resolver_work"),
        "concurrency" => Some("concurrency"),
        "execution" => Some("execution"),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use async_graphql::futures_util::FutureExt;
    use pn_interchange::{ResponseView, write_transport_response};

    const EDITION: &str =
        "schema=org.peer-network.test.api-control-schema@1.0.0;register=org.peer-network.test.api-control-register@1.0.0";

    fn facts<'a>(arguments: &'a [&'a str]) -> PreparationFacts<'a> {
        PreparationFacts {
            arguments,
            edition: Some(EDITION),
            edition_file: None,
            file_bytes: None,
            listen_pid: None,
            listen_fds: None,
            listen_fdnames: None,
            listen_pidfdid: false,
            connection_input: false,
            process_id: 42,
            notification_present: true,
            notification_form_valid: true,
            notification_final_symlink: false,
            notification_is_socket: true,
        }
    }

    fn caps() -> Caps {
        Caps {
            transport: 16_384,
            response: 16_384,
            decoded_bytes: 16_384,
            decoded_items: 4_096,
            input_nesting: 32,
            cbor_nesting: 32,
            decoding_work: 65_536,
            shell_start: 1_000_000_000,
            shell_stop: 100,
            cancellation_drain: 20,
        }
    }

    fn prepared(with_caps: bool) -> Controller {
        let args = ["pn", "start"];
        let bootstrap = CheckedBootstrap::new(&facts(&args)).expect("checked test facts");
        let mut controller = if with_caps {
            Controller::new().with_test_caps(caps())
        } else {
            Controller::new()
        };
        controller.advance(Event::Prepare { at: 0 }).expect("preparation");
        let actions = controller.advance(Event::PreparedStart(bootstrap)).expect("checked start");
        assert!(matches!(actions.as_slice(), [Action::Install]));
        controller.advance(Event::Installed).expect("installation");
        assert!(matches!(
            controller.advance(Event::Continue).expect("continue").as_slice(),
            [Action::Construct]
        ));
        controller
    }

    fn starting_with_caps(caps: Caps) -> (Controller, ExecutionContext, Vec<u8>) {
        let mut controller = prepared(false).with_test_caps(caps);
        let context = controller
            .construct_context()
            .expect("constructing state")
            .expect("finite test caps");
        let actions = controller
            .advance(Event::Constructed { result: Ok(()), at: 1 })
            .expect("constructed");
        let [Action::Dispatch(bytes)] = <[Action; 1]>::try_from(actions).expect("one dispatch") else {
            panic!("fixed byte dispatch")
        };
        (controller, context, bytes)
    }

    fn starting() -> (Controller, ExecutionContext, Vec<u8>) {
        starting_with_caps(caps())
    }

    fn served_start_with(facts: &PreparationFacts<'_>) -> (Controller, ExecutionContext, Vec<u8>) {
        let bootstrap = CheckedBootstrap::new(facts).expect("checked public start facts");
        let mut controller = Controller::new();
        controller.advance(Event::Prepare { at: 0 }).expect("preparation");
        assert!(matches!(
            controller
                .advance(Event::PreparedStart(bootstrap))
                .expect("checked start")
                .as_slice(),
            [Action::Install]
        ));
        controller.advance(Event::Installed).expect("installation");
        assert!(matches!(
            controller.advance(Event::Continue).expect("continue").as_slice(),
            [Action::Construct]
        ));
        let context = controller
            .construct_context()
            .expect("constructing state")
            .expect("completed embedded register");
        let actions = controller
            .advance(Event::Constructed { result: Ok(()), at: 1 })
            .expect("constructed");
        let [Action::Dispatch(bytes)] = <[Action; 1]>::try_from(actions).expect("one dispatch") else {
            panic!("fixed byte dispatch")
        };
        (controller, context, bytes)
    }

    pub(crate) fn served_start() -> (Controller, ExecutionContext, Vec<u8>) {
        let args = ["pn", "start"];
        served_start_with(&facts(&args))
    }

    fn response(ready: bool, failure: Option<&str>) -> TransportMessage {
        let ready = Value::Bool(ready);
        let edition = Value::Text(Text::from(EDITION.to_owned()));
        let failure = failure.map_or(Value::Null, |name| Value::Text(Text::from(name.to_owned())));
        let start = [
            ("ready", ResponseView::Value(&ready)),
            ("edition", ResponseView::Value(&edition)),
            ("failure", ResponseView::Value(&failure)),
        ];
        let data = [("start", ResponseView::Object(&start))];
        let root = [("data", ResponseView::Object(&data))];
        write_transport_response(&root, 16_384, &mut EncodingUsage::default(), |_| Ok(())).expect("bounded test response")
    }

    fn completed(result: Result<TransportMessage, EntryError>) -> Event {
        Event::EntryCompleted { result, at: 2 }
    }

    fn error(class: &str, ceiling: Option<&str>) -> TransportMessage {
        let sentence = match class {
            "Malformed" => "Request syntax is malformed.",
            "Invalid" => "Request validation failed.",
            "Unsupported" => "Request exceeds the supported operation or limits.",
            "ResourceLimit" => "Response cannot be completed within the declared limits.",
            "Cancelled" => "Request was cancelled before dispatch.",
            _ => panic!("known test class"),
        };
        let sentence = Value::Text(Text::from(sentence.to_owned()));
        let class = Value::Text(Text::from(class.to_owned()));
        let edition = Value::Text(Text::from(EDITION.to_owned()));
        let ceiling = ceiling.map_or(Value::Null, |key| Value::Text(Text::from(key.to_owned())));
        let extensions = [
            ("class", ResponseView::Value(&class)),
            ("edition", ResponseView::Value(&edition)),
            ("ceiling", ResponseView::Value(&ceiling)),
        ];
        let detail = [
            ("message", ResponseView::Value(&sentence)),
            ("extensions", ResponseView::Object(&extensions)),
        ];
        let errors = [ResponseView::Object(&detail)];
        let root = [("errors", ResponseView::Array(&errors))];
        write_transport_response(&root, 16_384, &mut EncodingUsage::default(), |_| Ok(())).expect("bounded test error")
    }

    fn retire_to_completion(controller: &mut Controller, at: u64, cleanup_failed: bool) -> (u8, Option<Cause>, bool) {
        if controller.work_pending && !controller.work_settled {
            let actions = controller
                .advance(Event::WorkSettled { at, complete: true })
                .expect("work settled");
            assert!(matches!(actions.first(), Some(Action::ReleaseBuffers)));
        }
        let actions = controller.advance(Event::Retired { at, cleanup_failed }).expect("released");
        let [Action::Complete { exit, stdout, cause, .. }] = <[Action; 1]>::try_from(actions).expect("one completion") else {
            panic!("completed action")
        };
        (exit, cause, stdout.is_some())
    }

    /// Claim: An incomplete empty barrier refuses reserved input and cannot authorize construction or a worker.
    /// ´claim:lifecycle:barrier-precedes-workers´
    /// ´test:unit:barrier-precedes-workers´
    #[test]
    fn barrier_precedes_workers() {
        let args = ["pn", "start"];
        let mut supplied = facts(&args);
        supplied.connection_input = true;
        assert!(matches!(
            CheckedBootstrap::new(&supplied),
            Err(PreparationRefusal::ReservedInput)
        ));
        let mut controller = Controller::new();
        controller.advance(Event::Prepare { at: 0 }).expect("prepare");
        assert!(controller.advance(Event::Continue).is_err());
        assert_eq!(controller.state(), State::Preparing);
    }

    /// Claim: Public descriptor and directory advertisements refuse the reserved input before acquisition, while valid absence remains admitted.
    /// ´claim:lifecycle:reserved-input-refuses´
    /// ´test:unit:reserved-input-refuses´
    #[test]
    fn reserved_input_refuses() {
        let args = ["pn", "start"];
        let mut supplied = facts(&args);
        supplied.listen_pid = Some("42");
        supplied.listen_fds = Some("0");
        supplied.listen_fdnames = Some("");
        assert!(CheckedBootstrap::new(&supplied).is_ok());
        supplied.listen_fdnames = Some("pn-connection-input");
        assert!(matches!(
            CheckedBootstrap::new(&supplied),
            Err(PreparationRefusal::ReservedInput)
        ));
        supplied.listen_fdnames = Some("");
        supplied.listen_fds = Some("1");
        assert!(matches!(
            CheckedBootstrap::new(&supplied),
            Err(PreparationRefusal::ReservedInput)
        ));
        supplied.listen_fds = Some("0");
        supplied.listen_pidfdid = true;
        assert!(matches!(
            CheckedBootstrap::new(&supplied),
            Err(PreparationRefusal::ReservedInput)
        ));
        supplied.listen_pidfdid = false;
        supplied.connection_input = true;
        assert!(matches!(
            CheckedBootstrap::new(&supplied),
            Err(PreparationRefusal::ReservedInput)
        ));
    }

    /// Claim: A fixed bounded CBOR request crosses the actual byte executor and yields a complete ready result before notification is authorized.
    /// ´claim:lifecycle:byte-start-precedes-ready´
    /// ´test:unit:byte-start-precedes-ready´
    #[test]
    fn byte_start_precedes_ready() {
        let (mut controller, context, bytes) = starting();
        let output = crate::execute(&bytes, &context)
            .now_or_never()
            .expect("one immediate bounded entry");
        assert_eq!(context.lifecycle_start_calls(), 1);
        controller.advance(completed(output)).expect("entry completion");
        assert_eq!(controller.state(), State::ReadyCheck);
        let actions = controller
            .advance(Event::ReadyChecked {
                at: 2,
                stop: false,
                checked_failure: false,
            })
            .expect("final check");
        assert!(matches!(actions.as_slice(), [Action::Notify(bytes)] if *bytes == b"READY=1"));
        controller
            .advance(Event::NotificationCompleted {
                sent: true,
                at: 3,
                stop: false,
                checked_failure: false,
            })
            .expect("sent");
        assert_eq!(controller.state(), State::Ready);
    }

    /// Claim: Presentation uncertainty retires once with empty stdout and never turns into a ready notification or a guessed start failure.
    /// ´claim:lifecycle:presentation-refusal-never-notifies´
    /// ´test:unit:presentation-refusal-never-notifies´
    #[test]
    fn presentation_refusal_never_notifies() {
        let outcomes = [
            Ok(error("ResourceLimit", Some("response"))),
            Ok(error("ResourceLimit", None)),
            Err(EntryError::DecoderContract),
        ];
        for output in outcomes {
            let (mut controller, _, _) = starting();
            let actions = controller.advance(completed(output)).expect("presentation refusal");
            assert_eq!(controller.state(), State::Retiring);
            assert!(matches!(
                actions.as_slice(),
                [
                    Action::Close,
                    Action::ReleaseBuffers,
                    Action::ReleaseContext,
                    Action::ReleaseEndpoint,
                    Action::ReleasePreparation
                ]
            ));
            assert!(controller.cancelled.load(Ordering::Acquire));
            let (exit, cause, stdout) = retire_to_completion(&mut controller, 2, false);
            assert_eq!((exit, cause, stdout), (1, Some(Cause::PresentationUnknown), false));
        }
    }

    /// Claim: A classified graceful stop clears the ready state and closes dispatch before retirement.
    /// ´claim:lifecycle:stop-clears-ready´
    /// ´test:unit:stop-clears-ready´
    #[test]
    fn stop_clears_ready() {
        let (mut controller, _, _) = starting();
        controller
            .advance(completed(Ok(response(true, None))))
            .expect("ready candidate");
        controller
            .advance(Event::ReadyChecked {
                at: 2,
                stop: false,
                checked_failure: false,
            })
            .expect("check");
        controller
            .advance(Event::NotificationCompleted {
                sent: true,
                at: 3,
                stop: false,
                checked_failure: false,
            })
            .expect("sent");
        let actions = controller.advance(Event::Stop { at: 4 }).expect("stop");
        assert_eq!(controller.state(), State::Retiring);
        assert!(matches!(actions.first(), Some(Action::Close)));
    }

    /// Claim: A repeated stop retains the first stopping and cancellation deadlines instead of extending them.
    /// ´claim:lifecycle:repeated-stop-keeps-deadline´
    /// ´test:unit:repeated-stop-keeps-deadline´
    #[test]
    fn repeated_stop_keeps_deadline() {
        let (mut controller, _, _) = starting();
        controller.advance(Event::Stop { at: 5 }).expect("first stop");
        let stop = controller.stop_deadline;
        let drain = controller.drain_deadline;
        assert_eq!((stop, drain), (Some(105), Some(25)));
        assert!(controller.advance(Event::Stop { at: 20 }).expect("second stop").is_empty());
        assert_eq!((controller.stop_deadline, controller.drain_deadline), (stop, drain));
    }

    /// Claim: Both public edition sources refuse by presence before either value or file bytes can select an edition.
    /// ´claim:lifecycle:edition-both-sources-refuse´
    /// ´test:unit:edition-both-sources-refuse´
    #[test]
    fn edition_both_sources_refuse() {
        let args = ["pn", "edition"];
        let mut supplied = facts(&args);
        supplied.edition_file = Some("/run/pn/edition");
        supplied.file_bytes = Some(b"invalid");
        assert!(matches!(
            EditionInspection::new(&supplied),
            Err(PreparationRefusal::EditionSources)
        ));
        supplied.edition = Some("");
        assert!(matches!(
            EditionInspection::new(&supplied),
            Err(PreparationRefusal::EditionSources)
        ));
        supplied.edition = Some(EDITION);
        let equal_file = format!("{EDITION}\n");
        supplied.file_bytes = Some(equal_file.as_bytes());
        assert!(matches!(
            EditionInspection::new(&supplied),
            Err(PreparationRefusal::EditionSources)
        ));
    }

    /// Claim: Absent public edition sources refuse without manufacturing a default selection.
    /// ´claim:lifecycle:edition-neither-source-refuses´
    /// ´test:unit:edition-neither-source-refuses´
    #[test]
    fn edition_neither_source_refuses() {
        let args = ["pn", "edition"];
        let mut supplied = facts(&args);
        supplied.edition = None;
        assert!(matches!(
            EditionInspection::new(&supplied),
            Err(PreparationRefusal::EditionSources)
        ));
    }

    /// Claim: Bare and extra argument forms cannot select an edition or admit an operation outside the closed command grammar.
    /// ´claim:lifecycle:edition-arguments-refuse´
    /// ´test:unit:edition-arguments-refuse´
    #[test]
    fn edition_arguments_refuse() {
        for args in [
            &["pn"][..],
            &["pn", "edition", "1.0.0"],
            &["pn", "edition", "--edition=x"],
            &["pn", "start", "x"],
        ] {
            let supplied = facts(args);
            assert!(matches!(
                EditionInspection::new(&supplied),
                Err(PreparationRefusal::Arguments)
            ));
            assert!(matches!(CheckedBootstrap::new(&supplied), Err(PreparationRefusal::Arguments)));
        }
    }

    /// Claim: Inspection reports the selected public edition, source and embedded-roster membership without dispatch or notification, and terminal stdout refuses.
    /// ´claim:lifecycle:edition-reports-selection´
    /// ´test:unit:edition-reports-selection´
    #[test]
    fn edition_reports_selection() {
        let args = ["pn", "edition"];
        let supplied = facts(&args);
        let inspection = EditionInspection::new(&supplied).expect("public selection");
        let schema = pn_interchange::Document::from_canonical_bytes(include_bytes!("../../interchange/schema/control.cbor"))
            .expect("embedded schema envelope");
        let register =
            pn_interchange::Document::from_canonical_bytes(include_bytes!("../../interchange/schema/control-register.cbor"))
                .expect("embedded register envelope");
        let coordinate = |document: &pn_interchange::Document| {
            let envelope = document.envelope();
            let version = envelope.version();
            format!(
                "{}@{}.{}.{}",
                envelope.label().as_str(),
                version.major(),
                version.minor(),
                version.patch()
            )
        };
        let embedded = format!("schema={};register={}", coordinate(&schema), coordinate(&register));
        assert_eq!(inspection.edition(), embedded);
        assert_eq!(crate::admission::embedded_edition(), Ok(embedded));
        assert_eq!(
            (inspection.edition(), inspection.source()),
            (EDITION, EditionSource::Environment)
        );
        assert!(inspection.supported());
        let mut controller = Controller::new();
        controller.advance(Event::Prepare { at: 0 }).expect("preparation");
        assert!(matches!(
            controller
                .advance(Event::PreparedInspection(inspection))
                .expect("prepared")
                .as_slice(),
            [Action::Install]
        ));
        let actions = controller.advance(Event::TerminalOutputRefused).expect("terminal refusal");
        assert!(matches!(actions.as_slice(), [Action::Install]));
        controller.advance(Event::Installed).expect("installed");
        let actions = controller.advance(Event::Continue).expect("inspection terminal");
        assert!(matches!(
            actions.as_slice(),
            [Action::Complete {
                exit: 2,
                stdout: None,
                ..
            }]
        ));
        let mut file = facts(&args);
        file.edition = None;
        file.edition_file = Some("/run/pn/edition");
        let bytes = format!("{EDITION}\n");
        file.file_bytes = Some(bytes.as_bytes());
        let inspection = EditionInspection::new(&file).expect("file selection");
        assert_eq!((inspection.edition(), inspection.source()), (EDITION, EditionSource::File));
        assert!(inspection.supported());
        let mut controller = Controller::new();
        controller.advance(Event::Prepare { at: 0 }).expect("prepare");
        controller.advance(Event::PreparedInspection(inspection)).expect("inspection");
        controller.advance(Event::Installed).expect("installed");
        let actions = controller.advance(Event::Continue).expect("report");
        assert!(
            matches!(actions.as_slice(), [Action::Complete { exit: 0, stdout: Some(PublicOutput::Inspection { edition, source: EditionSource::File, supported: true }), .. }] if edition == EDITION)
        );
    }

    /// Claim: The public environment and bounded file forms enforce exact coordinate syntax while a valid unknown pair remains unsupported rather than malformed.
    /// ´claim:lifecycle:edition-input-forms´
    /// ´test:unit:edition-input-forms´
    #[test]
    fn edition_input_forms() {
        let args = ["pn", "edition"];
        let mut supplied = facts(&args);
        for value in [
            "",
            " schema=x",
            "schema=x@01.0.0;register=y@1.0.0",
            "schema=x@18446744073709551616.0.0;register=y@1.0.0",
        ] {
            supplied.edition = Some(value);
            assert!(matches!(
                EditionInspection::new(&supplied),
                Err(PreparationRefusal::EditionForm)
            ));
        }
        supplied.edition = None;
        supplied.edition_file = Some("relative");
        assert!(matches!(
            EditionInspection::new(&supplied),
            Err(PreparationRefusal::EditionForm)
        ));
        supplied.edition_file = Some("/run/pn/edition");
        for bytes in [
            &b""[..],
            &b"invalid\n"[..],
            &[239, 187, 191, b'g', b'a', b'r', b'b', b'a', b'g', b'e', b'\n'][..],
            &b"no-final-lf"[..],
        ] {
            supplied.file_bytes = Some(bytes);
            assert!(matches!(
                EditionInspection::new(&supplied),
                Err(PreparationRefusal::EditionForm)
            ));
        }
        let unknown =
            "schema=org.peer-network.test.api-control-schema@2.0.0;register=org.peer-network.test.api-control-register@2.0.0\n";
        supplied.file_bytes = Some(unknown.as_bytes());
        let inspection = EditionInspection::new(&supplied).expect("valid unsupported selection");
        assert!(!inspection.supported());
    }

    /// Claim: Only admitted protected notification validity facts permit a checked start, whose eventual ready action uses the exact payload; inspection needs no endpoint.
    /// ´claim:lifecycle:notification-contract´
    /// ´test:unit:notification-contract´
    #[test]
    fn notification_contract() {
        let args = ["pn", "start"];
        let mut supplied = facts(&args);
        supplied.notification_present = false;
        assert!(matches!(
            CheckedBootstrap::new(&supplied),
            Err(PreparationRefusal::Notification)
        ));
        supplied.notification_present = true;
        supplied.notification_form_valid = false;
        assert!(matches!(
            CheckedBootstrap::new(&supplied),
            Err(PreparationRefusal::Notification)
        ));
        supplied.notification_form_valid = true;
        supplied.notification_final_symlink = true;
        assert!(matches!(
            CheckedBootstrap::new(&supplied),
            Err(PreparationRefusal::Notification)
        ));
        supplied.notification_final_symlink = false;
        supplied.notification_is_socket = false;
        assert!(matches!(
            CheckedBootstrap::new(&supplied),
            Err(PreparationRefusal::Notification)
        ));
        supplied.notification_is_socket = true;
        let bootstrap = CheckedBootstrap::new(&supplied).expect("valid endpoint facts");
        let mut controller = Controller::new().with_test_caps(caps());
        controller.advance(Event::Prepare { at: 0 }).expect("prepare");
        controller.advance(Event::PreparedStart(bootstrap)).expect("checked start");
        controller.advance(Event::Installed).expect("installed");
        controller.advance(Event::Continue).expect("construct action");
        controller.construct_context().expect("state").expect("caps");
        controller
            .advance(Event::Constructed { result: Ok(()), at: 1 })
            .expect("dispatch");
        controller.advance(completed(Ok(response(true, None)))).expect("ready result");
        let actions = controller
            .advance(Event::ReadyChecked {
                at: 2,
                stop: false,
                checked_failure: false,
            })
            .expect("notification action");
        assert!(matches!(actions.as_slice(), [Action::Notify(bytes)] if *bytes == b"READY=1"));
        let edition_args = ["pn", "edition"];
        let mut inspection = facts(&edition_args);
        inspection.notification_present = false;
        assert!(EditionInspection::new(&inspection).is_ok());
    }

    /// Claim: Only SIGTERM classifies as graceful, and only an orderly stop after notification emits the minimal successful completion.
    /// ´claim:lifecycle:termination-output-contract´
    /// ´test:unit:termination-output-contract´
    #[test]
    fn termination_output_contract() {
        assert!(matches!(Event::supported_signal(15, 2), Some(Event::Stop { at: 2 })));
        assert!(Event::supported_signal(2, 2).is_none());
        assert!(Event::supported_signal(13, 2).is_none());
        let (mut early, _, _) = starting();
        early.advance(Event::Stop { at: 2 }).expect("before-ready stop");
        assert_eq!(
            retire_to_completion(&mut early, 3, false),
            (1, Some(Cause::BeforeReadyStop), false)
        );
        let (mut ready, _, _) = starting();
        ready.advance(completed(Ok(response(true, None)))).expect("ready result");
        ready
            .advance(Event::ReadyChecked {
                at: 2,
                stop: false,
                checked_failure: false,
            })
            .expect("clear check");
        ready
            .advance(Event::NotificationCompleted {
                sent: true,
                at: 3,
                stop: false,
                checked_failure: false,
            })
            .expect("send");
        ready.advance(Event::Stop { at: 4 }).expect("orderly stop");
        let actions = ready
            .advance(Event::Retired {
                at: 5,
                cleanup_failed: false,
            })
            .expect("released");
        let [Action::Complete { exit, stdout, cause, .. }] = <[Action; 1]>::try_from(actions).expect("completion") else {
            panic!("one completion")
        };
        assert_eq!((exit, cause), (0, Some(Cause::AfterReadyStop)));
        assert!(matches!(stdout, Some(PublicOutput::Stopped { edition }) if edition == EDITION));
    }

    /// Claim: Unlisted and duplicate transitions and a second construction in Constructing refuse without effects, while a driver fault enters retirement once.
    /// ´claim:lifecycle:lifecycle-transitions-are-closed´
    /// ´test:unit:lifecycle-transitions-are-closed´
    #[test]
    fn lifecycle_transitions_are_closed() {
        let mut controller = Controller::new();
        assert!(controller.advance(Event::Continue).is_err());
        assert!(controller.advance(Event::EndpointSetupFailed { at: 0 }).is_err());
        assert_eq!(controller.state(), State::Captured);
        let mut unsuccessful = prepared(false);
        assert!(unsuccessful.advance(Event::EndpointSetupFailed { at: 1 }).is_err());
        let pending = ExecutionContext::pending_unserved();
        assert!(matches!(pending, Err(EntryError::LimitsUnadmitted)));
        unsuccessful.construction_attempted = true;
        assert!(unsuccessful.advance(Event::EndpointSetupFailed { at: 1 }).is_err());
        assert_eq!(unsuccessful.state(), State::Constructing);
        let actions = unsuccessful
            .advance(Event::Constructed { result: pending, at: 1 })
            .expect("pending construction refusal");
        assert!(matches!(actions.first(), Some(Action::Close)));
        let mut constructing = prepared(true);
        constructing
            .construct_context()
            .expect("first construction")
            .expect("finite caps");
        assert!(constructing.construct_context().is_err());
        assert_eq!(constructing.state(), State::Constructing);
        constructing
            .advance(Event::EndpointSetupFailed { at: 2 })
            .expect("setup failure");
        assert_eq!(constructing.cause, Some(Cause::NotificationFailed));
        assert!(constructing.advance(Event::EndpointSetupFailed { at: 3 }).is_err());
        let (mut controller, _, _) = starting();
        assert!(controller.advance(Event::EndpointSetupFailed { at: 2 }).is_err());
        assert_eq!(controller.state(), State::Starting);
        assert_eq!(controller.cause, None);
        assert!(controller.construct_context().is_err());
        assert!(controller.advance(Event::Constructed { result: Ok(()), at: 2 }).is_err());
        let args = ["pn", "start"];
        assert!(
            controller
                .advance(Event::PreparedStart(CheckedBootstrap::new(&facts(&args)).expect("facts")))
                .is_err()
        );
        assert_eq!(controller.state(), State::Starting);
        controller
            .advance(completed(Ok(response(true, None))))
            .expect("first completion");
        assert!(controller.advance(completed(Ok(response(true, None)))).is_err());
        assert_eq!(controller.state(), State::ReadyCheck);
        let actions = controller.advance(Event::DriverFault { at: 3 }).expect("driver retirement");
        assert_eq!(controller.state(), State::Retiring);
        assert_eq!(controller.cause, Some(Cause::TransitionRefused));
        assert!(matches!(actions.first(), Some(Action::Close)));
        assert!(controller.advance(Event::WorkSettled { at: 5, complete: true }).is_err());
        for event in [Event::DriverFault { at: 7 }, Event::RuntimeFailure { at: 7 }] {
            let (mut controller, _, _) = starting();
            let expected = match event {
                Event::DriverFault { .. } => Cause::TransitionRefused,
                Event::RuntimeFailure { .. } => Cause::EntryFailure("Configuration"),
                _ => panic!("fixture fault"),
            };
            controller.advance(event).expect("fault retirement");
            assert_eq!(controller.cause, Some(expected));
            assert_eq!(controller.stop_deadline, Some(7 + caps().shell_stop));
        }
    }

    /// Claim: A pending build-owned register refuses construction before any byte entry or notification and yields runtime failure with empty stdout.
    /// ´claim:lifecycle:pending-lifecycle-cannot-start´
    /// ´test:unit:pending-lifecycle-cannot-start´
    #[test]
    fn pending_lifecycle_cannot_start() {
        let mut controller = prepared(false);
        let pending = ExecutionContext::pending_unserved();
        assert!(matches!(pending, Err(EntryError::LimitsUnadmitted)));
        controller.construction_attempted = true;
        let actions = controller
            .advance(Event::Constructed { result: pending, at: 1 })
            .expect("construction refusal");
        assert!(matches!(actions.first(), Some(Action::Close)));
        assert!(!actions.iter().any(|a| matches!(a, Action::Dispatch(_) | Action::Notify(_))));
        assert_eq!(
            retire_to_completion(&mut controller, 1, false),
            (1, Some(Cause::EntryFailure("LimitsUnadmitted")), false)
        );
    }

    /// Claim: Public edition sources and arguments cannot select the isolated conformance witness, while supported and unembedded coordinates retain their distinct checked served outcomes.
    /// ´claim:lifecycle:witness-configuration-refuses´
    /// ´test:unit:witness-configuration-refuses´
    #[test]
    fn witness_configuration_refuses() {
        let args = ["pn", "start"];
        let edition_file = format!("{EDITION}\n");
        for from_file in [false, true] {
            let mut selected = facts(&args);
            if from_file {
                selected.edition = None;
                selected.edition_file = Some("/edition.conf");
                selected.file_bytes = Some(edition_file.as_bytes());
            }
            let (_controller, context, _) = served_start_with(&selected);
            crate::executor::tests::assert_served_unsupported(&context, "query { __type(name:\"ControlQuery\"){name} }");
            assert!(!context.lifecycle_dependency_validation_entered());
            let (_neighbour_controller, neighbour, bytes) = served_start_with(&selected);
            crate::executor::tests::assert_served_start(&neighbour, &bytes, None);

            let mut invalid = facts(&args);
            if from_file {
                invalid.edition = None;
                invalid.edition_file = Some("/edition.conf");
                invalid.file_bytes = Some(b"witness\n");
            } else {
                invalid.edition = Some("witness");
            }
            assert!(matches!(
                CheckedBootstrap::new(&invalid),
                Err(PreparationRefusal::EditionForm)
            ));
        }

        let witness_args = ["pn", "start", "--witness"];
        assert!(matches!(
            CheckedBootstrap::new(&facts(&witness_args)),
            Err(PreparationRefusal::Arguments)
        ));

        let unembedded = EDITION.replace("register@1.0.0", "register@1.0.1");
        assert_ne!(unembedded, EDITION);
        let mut unsupported = facts(&args);
        unsupported.edition = Some(&unembedded);
        let (_controller, context, _) = served_start_with(&unsupported);
        crate::executor::tests::assert_served_unsupported(&context, "query { __type(name:\"ControlQuery\"){name} }");
        assert!(!context.lifecycle_dependency_validation_entered());
        let (_neighbour_controller, neighbour, bytes) = served_start_with(&unsupported);
        crate::executor::tests::assert_served_start(&neighbour, &bytes, Some("EditionUnsupported"));
    }

    /// Claim: Construction, complete start and pre-dispatch entry failures retain class and ceiling over coincident stop or elapsed startup bounds, retiring without retry or successful output.
    /// ´claim:lifecycle:entry-failures-retire´
    /// ´test:unit:entry-failures-retire´
    #[test]
    fn entry_failures_retire() {
        let failures = [
            "EditionUnsupported",
            "BootstrapInvalid",
            "ResourceLimit",
            "Cancelled",
            "StartFailed",
        ];
        for name in failures {
            let (mut controller, _, _) = starting();
            controller
                .advance(completed(Ok(response(false, Some(name)))))
                .expect("complete start failure");
            assert_eq!(controller.state(), State::Retiring);
            let (exit, cause, stdout) = retire_to_completion(&mut controller, 2, false);
            assert_eq!((exit, cause, stdout), (1, Some(Cause::StartFailure(name)), false));
        }
        let (mut coincident, _, _) = starting();
        coincident
            .advance(Event::EntryCompleted {
                result: Ok(response(false, Some("StartFailed"))),
                at: caps().shell_start,
            })
            .expect("completed failure at startup bound");
        assert_eq!(coincident.stop_deadline, caps().shell_start.checked_add(caps().shell_stop));
        assert!(
            coincident
                .advance(Event::Stop { at: caps().shell_start })
                .expect("coincident stop")
                .is_empty()
        );
        assert_eq!(
            retire_to_completion(&mut coincident, caps().shell_start + 1, false),
            (1, Some(Cause::StartFailure("StartFailed")), false)
        );
        for class in ["Malformed", "Invalid", "Unsupported", "Cancelled"] {
            let (mut controller, _, _) = starting();
            controller
                .advance(completed(Ok(error(class, None))))
                .expect("pre-dispatch class");
            assert_eq!(
                retire_to_completion(&mut controller, 2, false),
                (1, Some(Cause::PreDispatchFailure { class, ceiling: None }), false,)
            );
        }
        let (mut controller, _, _) = starting();
        controller
            .advance(completed(Ok(error("Unsupported", Some("lexical_tokens")))))
            .expect("bounded unsupported class");
        assert_eq!(
            retire_to_completion(&mut controller, 3, false),
            (
                1,
                Some(Cause::PreDispatchFailure {
                    class: "Unsupported",
                    ceiling: Some("lexical_tokens"),
                }),
                false,
            )
        );
        let (mut controller, _, _) = starting();
        controller
            .advance(completed(Ok(error("ResourceLimit", Some("execution")))))
            .expect("execution limit");
        assert_eq!(
            retire_to_completion(&mut controller, 2, false),
            (
                1,
                Some(Cause::PreDispatchFailure {
                    class: "ResourceLimit",
                    ceiling: Some("execution"),
                }),
                false,
            )
        );
        let mut controller = prepared(true);
        controller.construct_context().expect("state").expect("caps");
        controller
            .advance(Event::Constructed {
                result: Err(EntryError::Configuration),
                at: 1,
            })
            .expect("configuration");
        assert_eq!(
            retire_to_completion(&mut controller, 1, false),
            (1, Some(Cause::EntryFailure("Configuration")), false)
        );
    }

    fn assert_late_completion_and_cleared_bounds() {
        let (mut completed_late, _, _) = starting();
        completed_late.advance(Event::Stop { at: 10 }).expect("cancel pending entry");
        assert_eq!(completed_late.active_deadlines(), (None, Some(110), Some(30)));
        completed_late
            .advance(Event::EntryCompleted {
                result: Ok(response(true, None)),
                at: 30,
            })
            .expect("late completion only releases");
        assert_eq!(completed_late.active_deadlines(), (None, Some(110), None));
        let actions = completed_late
            .advance(Event::Retired {
                at: 31,
                cleanup_failed: false,
            })
            .expect("late completion retired");
        assert!(matches!(
            actions.as_slice(),
            [Action::Complete {
                retirement_diagnostics: [Some(Cause::StoppingTimeout), None],
                ..
            }]
        ));
        let (mut clear, _, _) = starting();
        clear.advance(completed(Ok(response(true, None)))).expect("ready candidate");
        assert_eq!(clear.active_deadlines(), (Some(caps().shell_start), None, None));
        clear
            .advance(Event::ReadyChecked {
                at: 2,
                stop: false,
                checked_failure: false,
            })
            .expect("notify");
        clear
            .advance(Event::NotificationCompleted {
                sent: true,
                at: 3,
                stop: false,
                checked_failure: false,
            })
            .expect("ready");
        assert_eq!(clear.active_deadlines(), (None, None, None));
    }

    /// Claim: Supplied instants gate a pending entry before polling, count elapsed preparation before dispatch, and retain separate stopping and capped cancellation deadlines.
    /// ´claim:lifecycle:lifecycle-deadlines-compose´
    /// ´test:unit:lifecycle-deadlines-compose´
    #[test]
    fn lifecycle_deadlines_compose() {
        assert_eq!(Controller::new().active_deadlines(), (None, None, None));
        let mut constructed = prepared(true);
        assert_eq!(constructed.active_deadlines(), (None, None, None));
        constructed.construct_context().expect("state").expect("caps");
        assert_eq!(constructed.active_deadlines(), (Some(caps().shell_start), None, None));
        let (mut pending, _, _) = starting();
        assert_eq!(pending.active_deadlines(), (Some(caps().shell_start), None, None));
        assert!(
            pending
                .advance(Event::EntryPendingCheck { at: 2, stop: false })
                .expect("entry still pending")
                .is_empty()
        );
        assert_eq!(pending.state(), State::Starting);
        let actions = pending
            .advance(Event::EntryPendingCheck {
                at: caps().shell_start,
                stop: true,
            })
            .expect("stop wins at startup bound");
        assert!(matches!(actions.as_slice(), [Action::Close, Action::Cancel { .. }]));
        assert_eq!(pending.cause, Some(Cause::BeforeReadyStop));
        assert_eq!(
            pending.active_deadlines(),
            (
                None,
                Some(caps().shell_start + caps().shell_stop),
                Some(caps().shell_start + caps().cancellation_drain),
            )
        );
        let (mut expired, _, _) = starting();
        let actions = expired
            .advance(Event::EntryPendingCheck {
                at: caps().shell_start,
                stop: false,
            })
            .expect("pending startup expired");
        assert!(matches!(actions.as_slice(), [Action::Close, Action::Cancel { .. }]));
        assert_eq!(expired.cause, Some(Cause::StartupTimeout));
        let mut narrow = caps();
        narrow.transport = 1;
        let mut encoding = prepared(false).with_test_caps(narrow);
        encoding.construct_context().expect("state").expect("caps");
        encoding
            .advance(Event::Constructed { result: Ok(()), at: 17 })
            .expect("bounded encoding refusal");
        assert_eq!(encoding.stop_deadline, Some(117));
        assert_eq!(encoding.cause, Some(Cause::EntryFailure("Configuration")));
        let mut late = prepared(true);
        late.construct_context().expect("state").expect("caps");
        let actions = late
            .advance(Event::Constructed {
                result: Ok(()),
                at: caps().shell_start,
            })
            .expect("late synchronous return");
        assert_eq!(late.state(), State::Retiring);
        assert!(!actions.iter().any(|a| matches!(a, Action::Dispatch(_))));
        assert_eq!(late.startup_deadline, Some(caps().shell_start));
        let mut capped = caps();
        capped.cancellation_drain = 200;
        let (mut controller, context, _) = starting_with_caps(capped);
        assert_eq!(
            context.lifecycle_caps().expect("admitted fixture").shell_start,
            caps().shell_start
        );
        controller.advance(Event::Stop { at: 10 }).expect("retirement");
        assert_eq!(controller.stop_deadline, Some(110));
        assert_eq!(controller.drain_deadline, Some(110));
        assert_eq!(controller.active_deadlines(), (None, Some(110), Some(110)));
        let actions = controller
            .advance(Event::WorkSettled {
                at: 110,
                complete: false,
            })
            .expect("drain bound");
        assert!(matches!(actions.first(), Some(Action::ReleaseBuffers)));
        assert_eq!(controller.active_deadlines(), (None, Some(110), None));
        let actions = controller
            .advance(Event::Retired {
                at: 111,
                cleanup_failed: false,
            })
            .expect("capped retirement");
        assert!(matches!(
            actions.as_slice(),
            [Action::Complete {
                exit: 1,
                stdout: None,
                cause: Some(Cause::BeforeReadyStop),
                retirement_diagnostics: [Some(Cause::StoppingTimeout), None],
            }]
        ));
        assert_eq!(controller.active_deadlines(), (None, None, None));
        assert_late_completion_and_cleared_bounds();
    }

    fn assert_retained_stop_and_endpoint_setup() {
        for sent in [true, false] {
            let (mut controller, _, _) = starting();
            controller.advance(completed(Ok(response(true, None)))).expect("ready result");
            controller
                .advance(Event::ReadyChecked {
                    at: 2,
                    stop: false,
                    checked_failure: false,
                })
                .expect("send authorization");
            controller.advance(Event::Stop { at: 3 }).expect("first retained stop");
            controller
                .advance(Event::DriverFault { at: 4 })
                .expect("later retained fault");
            controller
                .advance(Event::NotificationCompleted {
                    sent,
                    at: 5,
                    stop: false,
                    checked_failure: false,
                })
                .expect("settled send");
            assert_eq!(
                controller.cause,
                Some(if sent {
                    Cause::TransitionRefused
                } else {
                    Cause::NotificationFailed
                })
            );
            assert_eq!(controller.stop_deadline, Some(3 + caps().shell_stop));
        }
        let mut setup = prepared(true);
        setup.construct_context().expect("state").expect("caps");
        let actions = setup
            .advance(Event::EndpointSetupFailed { at: 7 })
            .expect("returned setup failure");
        assert!(matches!(actions.first(), Some(Action::Close)));
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, Action::Dispatch(_) | Action::Notify(_) | Action::Cancel { .. }))
        );
        assert_eq!(setup.cause, Some(Cause::NotificationFailed));
        assert_eq!(setup.stop_deadline, Some(7 + caps().shell_stop));
        setup
            .advance(Event::Stop { at: 8 })
            .expect("stop after returned setup failure");
        assert_eq!(setup.cause, Some(Cause::NotificationFailed));
        assert_eq!(setup.stop_deadline, Some(7 + caps().shell_stop));
        assert_eq!(
            retire_to_completion(&mut setup, 8, false),
            (1, Some(Cause::NotificationFailed), false)
        );
        let mut stopped = prepared(true);
        stopped.construct_context().expect("state").expect("caps");
        stopped.advance(Event::Stop { at: 7 }).expect("stop before setup");
        assert!(stopped.advance(Event::EndpointSetupFailed { at: 8 }).is_err());
        assert_eq!(stopped.cause, Some(Cause::BeforeReadyStop));
        let mut expired = prepared(true);
        expired.construct_context().expect("state").expect("caps");
        let deadline = expired.startup_deadline.expect("declared startup deadline");
        let actions = expired
            .advance(Event::Constructed {
                result: Ok(()),
                at: deadline,
            })
            .expect("deadline settled before setup");
        assert!(matches!(actions.first(), Some(Action::Close)));
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, Action::Dispatch(_) | Action::Notify(_)))
        );
        assert_eq!(expired.cause, Some(Cause::StartupTimeout));
        assert!(expired.advance(Event::EndpointSetupFailed { at: deadline + 1 }).is_err());
        assert_eq!(expired.state(), State::Retiring);
        assert_eq!(expired.cause, Some(Cause::StartupTimeout));
    }

    /// Claim: A stop, elapsed startup bound or checked failure before authorization prevents notification, while a stop after a successful send retires from ready.
    /// ´claim:lifecycle:ready-notification-arbitrates´
    /// ´test:unit:ready-notification-arbitrates´
    #[test]
    fn ready_notification_arbitrates() {
        for (stop, failure, at) in [(true, false, 2), (false, true, 2), (false, false, 1_000_000_000)] {
            let (mut controller, _, _) = starting();
            controller.advance(completed(Ok(response(true, None)))).expect("ready result");
            let actions = controller
                .advance(Event::ReadyChecked {
                    at,
                    stop,
                    checked_failure: failure,
                })
                .expect("final arbitration");
            assert!(!actions.iter().any(|a| matches!(a, Action::Notify(_))));
            assert_eq!(controller.state(), State::Retiring);
            if failure {
                assert_eq!(controller.cause, Some(Cause::EntryFailure("Configuration")));
            }
        }
        let (mut controller, _, _) = starting();
        controller.advance(completed(Ok(response(true, None)))).expect("ready result");
        let actions = controller
            .advance(Event::ReadyChecked {
                at: 2,
                stop: false,
                checked_failure: false,
            })
            .expect("send authorization");
        assert!(matches!(actions.as_slice(), [Action::Notify(_)]));
        controller.advance(Event::Stop { at: 3 }).expect("stop during send");
        assert_eq!(controller.state(), State::Notifying);
        controller
            .advance(Event::NotificationCompleted {
                sent: true,
                at: 4,
                stop: false,
                checked_failure: false,
            })
            .expect("late stop after send");
        assert_eq!(controller.cause, Some(Cause::AfterReadyStop));
        assert_eq!(controller.state(), State::Retiring);
        assert_eq!(controller.stop_deadline, Some(3 + caps().shell_stop));
        assert!(
            controller
                .advance(Event::NotificationCompleted {
                    sent: true,
                    at: 5,
                    stop: false,
                    checked_failure: false
                })
                .is_err()
        );
        for (event, expected) in [
            (Event::DriverFault { at: 3 }, Cause::TransitionRefused),
            (Event::RuntimeFailure { at: 3 }, Cause::EntryFailure("Configuration")),
        ] {
            let (mut controller, _, _) = starting();
            controller.advance(completed(Ok(response(true, None)))).expect("ready result");
            controller
                .advance(Event::ReadyChecked {
                    at: 2,
                    stop: false,
                    checked_failure: false,
                })
                .expect("send authorization");
            controller.advance(event).expect("retained fault");
            assert_eq!(controller.state(), State::Notifying);
            controller
                .advance(Event::NotificationCompleted {
                    sent: true,
                    at: 4,
                    stop: true,
                    checked_failure: true,
                })
                .expect("settled send");
            assert_eq!(controller.cause, Some(expected));
            assert_eq!(controller.stop_deadline, Some(3 + caps().shell_stop));
        }
        assert_retained_stop_and_endpoint_setup();
    }

    /// Claim: Ordered one-time release exposes checked cleanup and stopping timeout diagnostics beside the retained first command cause and forbids success.
    /// ´claim:lifecycle:cleanup-preserves-cause´
    /// ´test:unit:cleanup-preserves-cause´
    #[test]
    fn cleanup_preserves_cause() {
        let (mut controller, _, _) = starting();
        let actions = controller
            .advance(completed(Ok(response(false, Some("StartFailed")))))
            .expect("start failed");
        assert!(matches!(
            actions.as_slice(),
            [
                Action::Close,
                Action::ReleaseBuffers,
                Action::ReleaseContext,
                Action::ReleaseEndpoint,
                Action::ReleasePreparation
            ]
        ));
        let actions = controller
            .advance(Event::Retired {
                at: 3,
                cleanup_failed: true,
            })
            .expect("checked cleanup failure");
        assert!(matches!(
            actions.as_slice(),
            [Action::Complete {
                exit: 1,
                stdout: None,
                cause: Some(Cause::StartFailure("StartFailed")),
                retirement_diagnostics: [None, Some(Cause::CleanupFailed)],
            }]
        ));
        assert!(controller.cleanup_failed);
        assert!(
            controller
                .advance(Event::Retired {
                    at: 4,
                    cleanup_failed: false
                })
                .is_err()
        );
        let (mut both, _, _) = starting();
        both.advance(Event::Stop { at: 2 }).expect("first stop");
        both.advance(Event::WorkSettled { at: 22, complete: false })
            .expect("drain exhausted");
        let actions = both
            .advance(Event::Retired {
                at: 23,
                cleanup_failed: true,
            })
            .expect("cleanup also failed");
        assert!(matches!(
            actions.as_slice(),
            [Action::Complete {
                exit: 1,
                stdout: None,
                cause: Some(Cause::BeforeReadyStop),
                retirement_diagnostics: [Some(Cause::StoppingTimeout), Some(Cause::CleanupFailed)],
            }]
        ));
        for (retired_at, cleanup_failed, diagnostics) in [
            (5, true, [None, Some(Cause::CleanupFailed)]),
            (104, false, [Some(Cause::StoppingTimeout), None]),
        ] {
            let (mut ready, _, _) = starting();
            ready.advance(completed(Ok(response(true, None)))).expect("ready result");
            ready
                .advance(Event::ReadyChecked {
                    at: 2,
                    stop: false,
                    checked_failure: false,
                })
                .expect("notify");
            ready
                .advance(Event::NotificationCompleted {
                    sent: true,
                    at: 3,
                    stop: false,
                    checked_failure: false,
                })
                .expect("sent");
            ready.advance(Event::Stop { at: 4 }).expect("orderly stop");
            let actions = ready
                .advance(Event::Retired {
                    at: retired_at,
                    cleanup_failed,
                })
                .expect("release after ready");
            assert!(matches!(actions.as_slice(), [Action::Complete {
                exit: 1,
                stdout: None,
                cause: Some(Cause::AfterReadyStop),
                retirement_diagnostics,
            }] if *retirement_diagnostics == diagnostics));
        }
    }
}
