//! Fixed-message public verification, pending independent integration review.
//! (´def:authentication:verification-admission´)

mod backend;

/// A parsed x-only point; there is no constructor from an unchecked carrier.
/// (´def:authentication:verification-admission´)
#[derive(Clone, Copy, Debug)]
pub struct VerificationKey(backend::Key);

/// Public verification refusal; no payload or binding error is retained.
/// (´def:authentication:verification-admission´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerificationError {
    #[error("verification key must contain exactly 32 bytes")]
    KeyLength,
    #[error("verification key is not an x-only point")]
    InvalidKey,
    #[error("verification message must contain exactly 32 bytes")]
    MessageLength,
    #[error("verification signature must contain exactly 64 bytes")]
    SignatureLength,
    #[error("verification context exceeds fixed storage")]
    ContextCapacity,
    #[error("signature verification failed")]
    InvalidSignature,
}

impl VerificationKey {
    /// Parse exactly one x-only point before it can authorize verification or membership.
    /// (´def:authentication:verification-admission´)
    /// # Errors
    /// Refuses a wrong length or an invalid curve point.
    #[tracing::instrument(
        name = "def:authentication:verification-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:verification-admission",
            operation = "parse-verification-key",
            source_item = "verification::VerificationKey::parse"
        ),
        ret
    )]
    pub fn parse(bytes: &[u8]) -> Result<Self, VerificationError> {
        let bytes = bytes.try_into().map_err(|_| VerificationError::KeyLength)?;
        backend::parse(bytes).map(Self)
    }

    /// Verify a 64-byte BIP-340 signature over exactly one 32-byte digest.
    /// Length admission precedes context construction and every binding call.
    /// (´def:authentication:verification-admission´)
    /// # Errors
    /// Refuses a wrong message or signature length, then an invalid signature.
    #[tracing::instrument(
        name = "def:authentication:verification-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:verification-admission",
            operation = "verify-signature",
            source_item = "verification::VerificationKey::verify"
        ),
        ret
    )]
    pub fn verify(&self, signature: &[u8], message: &[u8]) -> Result<(), VerificationError> {
        let message = message.try_into().map_err(|_| VerificationError::MessageLength)?;
        let signature = signature.try_into().map_err(|_| VerificationError::SignatureLength)?;
        backend::verify(&self.0, signature, message)
    }
}

/// Parse disclosed bytes before computing the digest offered for membership.
/// This returns a candidate digest, not a membership or chain verdict.
/// (´def:authentication:verification-admission´)
/// # Errors
/// Refuses wrong length or invalid point before hashing.
#[tracing::instrument(
    name = "def:authentication:verification-admission",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:verification-admission",
        operation = "parse-membership-key",
        source_item = "verification::membership_key"
    ),
    ret
)]
pub fn membership_key(bytes: &[u8]) -> Result<(VerificationKey, crate::KeyHash), VerificationError> {
    let key = VerificationKey::parse(bytes)?;
    let digest = crate::signing_key_hash(bytes).map_err(|_| VerificationError::KeyLength)?;
    Ok((key, digest))
}

#[cfg(test)]
pub(crate) mod tests;
