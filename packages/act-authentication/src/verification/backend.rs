//! The sole binding boundary; only public parsing and verification are reachable.

#[tracing::instrument(
    name = "def:authentication:verification-admission",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:verification-admission",
        operation = "parse-native-key",
        source_item = "verification::backend::parse"
    ),
    ret
)]
pub(super) fn parse(bytes: &[u8; 32]) -> Result<Key, super::VerificationError> {
    #[cfg(test)]
    super::tests::visit(super::tests::Stage::Parse);
    secp256k1_zkp::XOnlyPublicKey::from_slice(bytes)
        .map(Key)
        .map_err(|_| super::VerificationError::InvalidKey)
}

#[tracing::instrument(
    name = "def:authentication:verification-admission",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:verification-admission",
        operation = "verify-native-signature",
        source_item = "verification::backend::verify"
    ),
    ret
)]
pub(super) fn verify(key: &Key, signature: &[u8; 64], message: [u8; 32]) -> Result<(), super::VerificationError> {
    #[cfg(test)]
    super::tests::visit(super::tests::Stage::Verify);
    let signature =
        secp256k1_zkp::schnorr::Signature::from_slice(signature).map_err(|_| super::VerificationError::SignatureLength)?;
    let message = secp256k1_zkp::Message::from_digest(message);
    let mut storage = [secp256k1_zkp::ffi::types::AlignedType::zeroed(); 64];
    let context = secp256k1_zkp::Secp256k1::preallocated_verification_only(&mut storage)
        .map_err(|_| super::VerificationError::ContextCapacity)?;
    context
        .verify_schnorr(&signature, &message, &key.0)
        .map_err(|_| super::VerificationError::InvalidSignature)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Key(secp256k1_zkp::XOnlyPublicKey);
