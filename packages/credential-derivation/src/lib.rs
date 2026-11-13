//! Borrowed salted-challenge primitives; callers own and protect all storage.
//! (´def:derivation:scope´)

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

/// Largest borrowed primitive input admitted by the transport profile.
/// (´def:derivation:primitives´)
pub const INPUT_LIMIT: usize = 1_048_576;
/// Lowest admitted password-derivation work factor.
/// (´def:derivation:primitives´)
pub const MIN_ITERATIONS: u32 = 4096;
/// Highest admitted work factor, also the restricted verifier's factor.
/// (´def:derivation:primitives´)
pub const MAX_ITERATIONS: u32 = 600_000;
/// Exact keyed and stored-key output length in bytes.
/// (´def:derivation:primitives´)
pub const KEY_LENGTH: usize = 32;
/// Exact restricted verifier salt length in bytes.
/// (´def:derivation:verifier´)
pub const SALT_LENGTH: usize = 16;
/// Exact restricted verifier text length, without a terminator.
/// (´def:derivation:verifier´)
pub const VERIFIER_LENGTH: usize = 135;

/// A caller's already authorized primitive input borrow, consumed by one call.
/// This view acquires no secret and provides no access to a protected container.
/// (´def:derivation:borrows´)
pub struct Input<'a>(pub &'a [u8]);

impl std::fmt::Debug for Input<'_> {
    /// Justified: Formatting a primitive input records its role and constant representation without inspecting its bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialInput([REDACTED])")
    }
}

/// A caller's already authorized protected destination borrow, consumed by one call.
/// No destination is allocated or returned by this library.
/// (´def:derivation:borrows´)
pub struct Output<'a>(pub &'a mut [u8]);

impl std::fmt::Debug for Output<'_> {
    /// Justified: Formatting a primitive destination records its role and constant representation without inspecting its bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialOutput([REDACTED])")
    }
}

/// Content-free refusal; neither variant retains input or dependency diagnostics.
/// (´def:derivation:scope´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bound,
    Primitive,
}

/// Derive one 32-byte salted password at the host's admitted work factor.
/// # Errors
/// Refuses inputs above one MiB, work outside 4096 through 600000, or a destination other than 32 bytes.
/// (´def:derivation:primitives´)
#[tracing::instrument(
    name = "dec:observe:credential-packages",
    fields(
        execution_owner = "DERIVATION",
        claim_owner = "ROOT",
        claim_label = "dec:observe:credential-packages",
        source_item = "salted_password"
    ),
    ret
)]
pub fn salted_password(password: Input<'_>, salt: Input<'_>, iterations: u32, output: Output<'_>) -> Result<(), Error> {
    if password.0.len() > INPUT_LIMIT
        || salt.0.len() > INPUT_LIMIT
        || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
        || output.0.len() != KEY_LENGTH
    {
        return Err(Error::Bound);
    }
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.0, salt.0, iterations, output.0).map_err(|_| Error::Primitive)
}

/// Compute a keyed SHA-256 value directly into the supplied 32-byte destination.
/// Client Key and Server Key use their protocol-fixed messages; transcript MACs use the same primitive.
/// # Errors
/// Refuses inputs above one MiB or a destination other than 32 bytes.
/// (´def:derivation:primitives´)
#[tracing::instrument(
    name = "dec:observe:credential-packages",
    fields(
        execution_owner = "DERIVATION",
        claim_owner = "ROOT",
        claim_label = "dec:observe:credential-packages",
        source_item = "mac"
    ),
    ret
)]
pub fn mac(key: Input<'_>, message: Input<'_>, output: Output<'_>) -> Result<(), Error> {
    if key.0.len() > INPUT_LIMIT || message.0.len() > INPUT_LIMIT || output.0.len() != KEY_LENGTH {
        return Err(Error::Bound);
    }
    let mut state = Hmac::<Sha256>::new_from_slice(key.0).map_err(|_| Error::Primitive)?;
    state.update(message.0);
    sha2::digest::FixedOutput::finalize_into(state, output.0.try_into().map_err(|_| Error::Bound)?);
    Ok(())
}

/// Hash the 32-byte client key directly into the 32-byte stored-key destination.
/// # Errors
/// Refuses either length other than 32 bytes before writing output.
/// (´def:derivation:primitives´)
#[tracing::instrument(
    name = "dec:observe:credential-packages",
    fields(
        execution_owner = "DERIVATION",
        claim_owner = "ROOT",
        claim_label = "dec:observe:credential-packages",
        source_item = "stored_key"
    ),
    ret
)]
pub fn stored_key(client_key: Input<'_>, output: Output<'_>) -> Result<(), Error> {
    if client_key.0.len() != KEY_LENGTH || output.0.len() != KEY_LENGTH {
        return Err(Error::Bound);
    }
    Digest::finalize_into(
        Sha256::new_with_prefix(client_key.0),
        output.0.try_into().map_err(|_| Error::Bound)?,
    );
    Ok(())
}

/// Format the admitted 600000-round verifier with a 16-byte salt and two 32-byte keys.
/// Writes exactly 135 bytes, with standard padded base64 and no line ending.
/// # Errors
/// Refuses any input or output length other than its fixed role length before writing output.
/// (´def:derivation:verifier´)
#[tracing::instrument(
    name = "dec:observe:credential-packages",
    fields(
        execution_owner = "DERIVATION",
        claim_owner = "ROOT",
        claim_label = "dec:observe:credential-packages",
        source_item = "verifier"
    ),
    ret
)]
pub fn verifier(salt: Input<'_>, stored_key: Input<'_>, server_key: Input<'_>, output: Output<'_>) -> Result<(), Error> {
    if salt.0.len() != SALT_LENGTH
        || stored_key.0.len() != KEY_LENGTH
        || server_key.0.len() != KEY_LENGTH
        || output.0.len() != VERIFIER_LENGTH
    {
        return Err(Error::Bound);
    }
    const { assert!(MAX_ITERATIONS == 600_000) };
    output.0[..21].copy_from_slice(b"SCRAM-SHA-256$600000:");
    STANDARD
        .encode_slice(salt.0, &mut output.0[21..45])
        .map_err(|_| Error::Primitive)?;
    output.0[45] = b'$';
    STANDARD
        .encode_slice(stored_key.0, &mut output.0[46..90])
        .map_err(|_| Error::Primitive)?;
    output.0[90] = b':';
    STANDARD
        .encode_slice(server_key.0, &mut output.0[91..])
        .map_err(|_| Error::Primitive)?;
    Ok(())
}
