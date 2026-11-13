//! Named startup receivers and the two protected output exits.
//! (´def:home:named-delivery´)

use std::fs::File;
use std::io::{ErrorKind, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::sync::atomic::{AtomicBool, Ordering};

use super::Credential;
use rustix::process::{PidfdFlags, PidfdGetfdFlags};

static ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Public startup refusal; no dependency error or input value is retained.
/// (´def:home:named-delivery´)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquisitionError {
    Missing,
    Additional,
    NameMismatch,
    InvalidConvention,
    Unavailable,
    ReceiverInvalid,
}

impl std::fmt::Display for AcquisitionError {
    /// Justified: Startup diagnostics use only the closed public refusal vocabulary.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "credential receiver missing",
            Self::Additional => "additional credential receiver",
            Self::NameMismatch => "credential receiver name mismatch",
            Self::InvalidConvention => "invalid credential receiver convention",
            Self::Unavailable => "credential receiver acquisition unavailable",
            Self::ReceiverInvalid => "invalid credential receiver",
        })
    }
}

impl std::error::Error for AcquisitionError {}

/// An opaque receiver selected by the password name, never by argument position.
/// (´def:home:named-delivery´)
pub struct PasswordReceiver(File);

/// An opaque receiver selected by the verifier name, with no role conversion.
/// (´def:home:named-delivery´)
pub struct VerifierReceiver(File);

impl std::fmt::Debug for PasswordReceiver {
    /// Justified: The capability is observed by its role, never by its descriptor.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordReceiver")
    }
}

impl std::fmt::Debug for VerifierReceiver {
    /// Justified: The capability is observed by its role, never by its descriptor.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifierReceiver")
    }
}

/// Acquire the closed startup roster once, before other descriptor-opening work.
/// The caller must make this its first entry operation, as the executable census checks.
/// (´def:home:named-delivery´)
/// # Errors
/// Refuses malformed metadata, repeated acquisition, unavailable duplication or invalid pipes.
/// Justified: Startup acquisition precedes observation and all descriptor-opening bootstrap; its public inputs and outcome are recorded by the executable after the private handles are settled.
pub fn acquire_receivers() -> Result<(PasswordReceiver, VerifierReceiver), AcquisitionError> {
    if ATTEMPTED.swap(true, Ordering::SeqCst) {
        return Err(AcquisitionError::InvalidConvention);
    }
    acquire()
}

// Justified: These public convention values select only the fixed startup pipe roster; no secret has been acquired.
fn acquire() -> Result<(PasswordReceiver, VerifierReceiver), AcquisitionError> {
    let address = std::env::var_os("LISTEN_PID").ok_or(AcquisitionError::Missing)?;
    if decimal(&address).ok() != Some(u64::from(std::process::id())) {
        return Err(AcquisitionError::Missing);
    }
    let count = std::env::var_os("LISTEN_FDS").ok_or(AcquisitionError::Missing)?;
    match decimal(&count)? {
        0 | 1 => return Err(AcquisitionError::Missing),
        2 => (),
        _ => return Err(AcquisitionError::Additional),
    }
    let names = std::env::var_os("LISTEN_FDNAMES").ok_or(AcquisitionError::NameMismatch)?;
    let password_first = match names.as_encoded_bytes() {
        b"password:verifier" => true,
        b"verifier:password" => false,
        _ => return Err(AcquisitionError::NameMismatch),
    };
    let identity = std::env::var_os("LISTEN_PIDFDID");
    let process = open_process().map_err(|_| AcquisitionError::Unavailable)?;
    check_slot(&process)?;
    let first = duplicate(&process, 3).map_err(duplicate_error)?;
    check_slot(&first)?;
    let second = duplicate(&process, 4).map_err(duplicate_error)?;
    check_slot(&second)?;
    // The admitted process feature has no safe filesystem-kind query for the handle.
    // A shared anonymous inode cannot establish the optional identity's support.
    if identity.is_some() {
        return Err(AcquisitionError::InvalidConvention);
    }
    drop(process);
    let mut first = File::from(first);
    let mut second = File::from(second);
    validate(&mut first, &mut second)?;
    Ok(if password_first {
        (PasswordReceiver(first), VerifierReceiver(second))
    } else {
        (PasswordReceiver(second), VerifierReceiver(first))
    })
}

// Justified: Decimal public metadata is parsed without normalization or overflow.
fn decimal(value: &std::ffi::OsStr) -> Result<u64, AcquisitionError> {
    let bytes = value.as_encoded_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(AcquisitionError::InvalidConvention);
    }
    bytes.iter().try_fold(0_u64, |n, digit| {
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(digit - b'0')))
            .ok_or(AcquisitionError::InvalidConvention)
    })
}

// Justified: The only process handle is the current process.
fn open_process() -> rustix::io::Result<OwnedFd> {
    rustix::process::pidfd_open(rustix::process::getpid(), PidfdFlags::empty())
}

// Justified: The closed first-entry census confines foreign-number access to these inherited pipe slots.
fn duplicate(process: &OwnedFd, number: i32) -> rustix::io::Result<OwnedFd> {
    rustix::process::pidfd_getfd(process, number, PidfdGetfdFlags::empty())
}

// Justified: A kernel-allocated low slot must not replace a missing inherited receiver.
fn check_slot(handle: &OwnedFd) -> Result<(), AcquisitionError> {
    if handle.as_raw_fd() <= 4 {
        Err(AcquisitionError::Missing)
    } else {
        Ok(())
    }
}

// Justified: Only the closed public startup class crosses the dependency boundary.
fn duplicate_error(error: rustix::io::Errno) -> AcquisitionError {
    if error == rustix::io::Errno::BADF {
        AcquisitionError::Missing
    } else {
        AcquisitionError::Unavailable
    }
}

// Justified: Metadata identifies distinct pipes; a zero-byte write validates access without emitting material.
fn validate(first: &mut File, second: &mut File) -> Result<(), AcquisitionError> {
    let a = first.metadata().map_err(|_| AcquisitionError::ReceiverInvalid)?;
    let b = second.metadata().map_err(|_| AcquisitionError::ReceiverInvalid)?;
    if !a.file_type().is_fifo() || !b.file_type().is_fifo() || (a.dev(), a.ino()) == (b.dev(), b.ino()) {
        return Err(AcquisitionError::ReceiverInvalid);
    }
    first.write(&[]).map_err(|_| AcquisitionError::ReceiverInvalid)?;
    second.write(&[]).map_err(|_| AcquisitionError::ReceiverInvalid)?;
    Ok(())
}

/// Public delivery failure, retaining only accepted-byte progress and a fixed class.
/// (´def:home:named-delivery´)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryError {
    pub accepted: usize,
    pub kind: DeliveryFailure,
}

/// Closed delivery causes; dependency error strings are discarded.
/// (´def:home:named-delivery´)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryFailure {
    Home,
    ZeroProgress,
    ClosedReader,
    Write,
}

impl std::fmt::Display for DeliveryError {
    /// Justified: The public error never reads the protected source or a dependency message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("credential delivery refused")
    }
}

impl std::error::Error for DeliveryError {}

impl Credential {
    /// Consume only the password receiver and deliver the exact protected password.
    /// (´def:home:named-delivery´)
    /// # Errors
    /// Refuses unavailable ownership or an incomplete write, retaining public progress only.
    #[tracing::instrument(
        name = "amend:crypto:secret-home",
        fields(
            execution_owner = "SECRETHOME",
            claim_owner = "ROOT",
            claim_label = "amend:crypto:secret-home",
            source_item = "delivery::Credential::deliver_password"
        ),
        ret
    )]
    // Caveat: The checked password region is lent only to its named pipe until the write loop returns; the kernel copies accepted bytes into receiver custody and cannot accept a Home.
    // (´[ROOT-cav:observe:secret-home-password-pipe]´)
    // Justified: This typed delivery is the sole password-to-kernel exit.
    #[allow(clippy::disallowed_methods)]
    pub fn deliver_password(&mut self, mut receiver: PasswordReceiver) -> Result<usize, DeliveryError> {
        let bytes = self.password.checked_bytes().map_err(|_| DeliveryError {
            accepted: 0,
            kind: DeliveryFailure::Home,
        })?;
        write_protected /* (´[ROOT-cav:observe:secret-home-password-pipe]´) */ (&mut receiver.0, &bytes[..super::PASSWORD_LENGTH])
    }

    /// Consume only the verifier receiver and deliver the exact protected verifier.
    /// (´def:home:named-delivery´)
    /// # Errors
    /// Refuses unavailable ownership or an incomplete write, retaining public progress only.
    #[tracing::instrument(
        name = "amend:crypto:secret-home",
        fields(
            execution_owner = "SECRETHOME",
            claim_owner = "ROOT",
            claim_label = "amend:crypto:secret-home",
            source_item = "delivery::Credential::deliver_verifier"
        ),
        ret
    )]
    // Caveat: The checked verifier region is lent only to its named pipe until the write loop returns; the kernel copies accepted verifier bytes into sealer custody and cannot accept a Home.
    // (´[ROOT-cav:observe:secret-home-verifier-pipe]´)
    // Justified: This typed delivery is the sole verifier-to-kernel exit.
    #[allow(clippy::disallowed_methods)]
    pub fn deliver_verifier(&mut self, mut receiver: VerifierReceiver) -> Result<usize, DeliveryError> {
        let bytes = self.verifier.checked_bytes().map_err(|_| DeliveryError {
            accepted: 0,
            kind: DeliveryFailure::Home,
        })?;
        write_protected /* (´[ROOT-cav:observe:secret-home-verifier-pipe]´) */ (&mut receiver.0, &bytes[..pn_credential_derivation::VERIFIER_LENGTH])
    }
}

// Justified: This private loop accepts only an acquired file and lends its protected source directly to the kernel.
fn write_protected(file: &mut File, bytes: &[u8]) -> Result<usize, DeliveryError> {
    let mut accepted = 0;
    while accepted < bytes.len() {
        match write_call(file, &bytes[accepted..]) {
            Ok(0) => {
                return Err(DeliveryError {
                    accepted,
                    kind: DeliveryFailure::ZeroProgress,
                });
            }
            Ok(count) => accepted += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => (),
            Err(error) => {
                return Err(DeliveryError {
                    accepted,
                    kind: if error.kind() == ErrorKind::BrokenPipe {
                        DeliveryFailure::ClosedReader
                    } else {
                        DeliveryFailure::Write
                    },
                });
            }
        }
    }
    Ok(accepted)
}

// Justified: The test seam changes only the write outcome; production lends directly to the kernel.
fn write_call(file: &mut File, bytes: &[u8]) -> std::io::Result<usize> {
    #[cfg(test)]
    if let Some(result) = tests::write_outcome(file, bytes) {
        return result;
    }
    file.write(bytes)
}

#[cfg(test)]
mod tests;
