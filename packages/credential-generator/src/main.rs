#![doc = include_str!("../README.md")]

use std::collections::BTreeMap;
use std::process::ExitCode;

use pn_secret_home::{
    AcquisitionError, Credential, CredentialError, DeliveryError, PasswordReceiver, Protection, VerifierReceiver,
};

/// Only the shared public debug option is accepted; private values never enter argv.
/// (´def:generator:terminal-entry´)
#[derive(clap::Parser)]
#[command(name = "pn-credential-generator", version, about)]
struct Args {
    #[command(flatten)]
    common: cli_common::BaseArgs,
}

/// Justified: Public policy and the panic hook precede named acquisition without opening a descriptor; the labelled command records its inputs after handles settle.
fn main() -> ExitCode {
    cli_common::select_observation_policy_or_exit("pn-credential-generator");
    cli_common::install_json_panic_hook("pn-credential-generator");
    let receivers = pn_secret_home::acquire_receivers();
    let protection = receivers.as_ref().ok().map(|_| Protection::for_credential());
    let args = match cli_common::parse_args_from::<Args, _, _>(std::env::args_os()) {
        Ok(args) => args,
        Err(exit) => {
            let result = cli_common::emit_control_plane_record(&exit.record);
            return if result.is_ok() {
                exit.exit.exit_code()
            } else {
                cli_common::CommandExit::Failure.exit_code()
            };
        }
    };
    cli_common::run_stdout_json_command("pn-credential-generator", args.common.debug, tracing::Level::INFO, || {
        entry(receivers, protection)
    })
}

/// The complete terminal operation records public convention values, constructs
/// one credential, attempts both deliveries and both home completions, then returns.
/// (´def:generator:terminal-entry´)
#[tracing::instrument(
    name = "dec:observe:first-start-route",
    fields(
        execution_owner = "GENERATOR",
        claim_owner = "ROOT",
        claim_label = "dec:observe:first-start-route",
        source_item = "entry"
    ),
    ret
)]
fn entry(
    receivers: Result<(PasswordReceiver, VerifierReceiver), AcquisitionError>,
    protection: Option<Result<Protection, pn_secret_home::Error>>,
) -> Result<BTreeMap<&'static str, usize>, Failure> {
    tracing::info!(address = ?std::env::var_os("LISTEN_PID"), count = ?std::env::var_os("LISTEN_FDS"), names = ?std::env::var_os("LISTEN_FDNAMES"), identity = ?std::env::var_os("LISTEN_PIDFDID"), "public receiver convention");
    let (password, verifier) = receivers.map_err(Failure::Acquisition)?;
    let protection = protection
        .ok_or(Failure::Protection(pn_secret_home::Error::Protection))?
        .map_err(Failure::Protection)?;
    terminal(&mut Production {
        password: Some(password),
        verifier: Some(verifier),
        credential: None,
        protection,
    })
}

/// Content-free stage results preserve all observable failures without dependency text.
/// (´def:generator:terminal-entry´)
#[derive(Debug)]
enum Failure {
    Acquisition(AcquisitionError),
    Protection(pn_secret_home::Error),
    Construction(CredentialError),
    Delivery {
        password: Result<usize, DeliveryError>,
        verifier: Result<usize, DeliveryError>,
        completion: Result<(), CredentialError>,
    },
}

impl std::fmt::Display for Failure {
    /// Justified: The terminal failure exposes only closed classes and accepted-byte counts.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acquisition(error) => write!(f, "{error}"),
            Self::Protection(error) => write!(f, "credential protection refused: {error:?}"),
            Self::Construction(error) => write!(f, "credential construction refused: {error:?}; cleanup unconfirmed"),
            Self::Delivery {
                password,
                verifier,
                completion,
            } => write!(
                f,
                "credential terminal result: password={password:?} verifier={verifier:?} completion={completion:?}"
            ),
        }
    }
}

impl std::error::Error for Failure {}

// This private lifecycle interface carries only stage results, never protected
// bytes or a writer. The production adapter retains the opaque home and roles.
trait Stages {
    fn construct(&mut self) -> Result<(), Failure>;
    fn password(&mut self) -> Result<usize, DeliveryError>;
    fn verifier(&mut self) -> Result<usize, DeliveryError>;
    fn complete(&mut self) -> Result<(), CredentialError>;
}

fn terminal(stages: &mut impl Stages) -> Result<BTreeMap<&'static str, usize>, Failure> {
    stages.construct()?;
    let password = stages.password();
    let verifier = stages.verifier();
    let completion = stages.complete();
    if password == Ok(64) && verifier == Ok(135) && completion.is_ok() {
        Ok(BTreeMap::from([
            ("locked_pages", 2),
            ("password_bytes", 64),
            ("verifier_bytes", 135),
        ]))
    } else {
        Err(Failure::Delivery {
            password,
            verifier,
            completion,
        })
    }
}

struct Production {
    protection: Protection,
    password: Option<PasswordReceiver>,
    verifier: Option<VerifierReceiver>,
    credential: Option<Credential>,
}

impl Stages for Production {
    /// Justified: The terminal entry records this private stage's public outcome; protected construction records its own opaque result without exposing bytes.
    fn construct(&mut self) -> Result<(), Failure> {
        self.credential = Some(self.protection.credential().map_err(Failure::Construction)?);
        Ok(())
    }

    /// Justified: The terminal entry records this private stage's public progress and refusal; the typed home operation owns its sole password exit.
    fn password(&mut self) -> Result<usize, DeliveryError> {
        let receiver = self.password.take().ok_or(missing())?;
        self.credential.as_mut().ok_or(missing())?.deliver_password(receiver)
    }

    /// Justified: The terminal entry records this private stage's public progress and refusal; the typed home operation owns its sole verifier exit.
    fn verifier(&mut self) -> Result<usize, DeliveryError> {
        let receiver = self.verifier.take().ok_or(missing())?;
        self.credential.as_mut().ok_or(missing())?.deliver_verifier(receiver)
    }

    /// Justified: The terminal entry records this private stage's content-free completion result after both owning home attempts.
    fn complete(&mut self) -> Result<(), CredentialError> {
        self.credential.take().ok_or(CredentialError::Completion)?.complete()
    }
}

fn missing() -> DeliveryError {
    DeliveryError {
        accepted: 0,
        kind: pn_secret_home::DeliveryFailure::Home,
    }
}

#[cfg(test)]
mod tests;
