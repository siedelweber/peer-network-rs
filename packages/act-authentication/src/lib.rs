//! Public byte recipes and fixed-size author-token carriers.
//! Byte recipes establish neither key validity nor chain truth; the verification
//! module separately parses keys and checks fixed-message signatures.
//! (´def:authentication:public-evidence´)

pub mod verification;

use sha2::{Digest, Sha256};

/// An Elements asset identifier, in displayed hexadecimal byte order.
/// Consensus encodings reverse these bytes. (´def:authentication:public-evidence´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssetId(pub [u8; 32]);

/// A declared key digest, not a parsed verification key.
/// (´def:authentication:public-evidence´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyHash(pub [u8; 32]);

/// A syntactically canonical qualification, before issuance validation.
/// (´def:authentication:public-evidence´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Qualification {
    pub run: [u8; 32],
    pub prevout: [u8; 36],
}

/// Why a supplied qualification script cannot be decoded.
/// Issuance qualification reasons belong to the wallet's private interpretation.
/// (´def:authentication:public-evidence´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QualificationRefusal {
    Version,
    Length,
    Push,
    Tag,
    Flags,
}

/// Public recipe input refusal. (´def:authentication:public-evidence´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecipeError {
    #[error("key encoding must contain exactly 32 bytes")]
    KeyLength,
    #[error("issuance prevout index contains a reserved flag")]
    PrevoutIndex,
}

/// Hash exactly 32 opaque bytes, without parsing a curve point.
/// This is raw recipe recomputation, not membership computation; use
/// `membership_key` before a membership comparison.
/// Membership and signature verification must parse the key before use.
/// (´[ROOT-amend:identity:signing-key-hash]´)
///
/// # Errors
/// Refuses any length other than 32.
#[tracing::instrument(
    name = "amend:identity:signing-key-hash",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ROOT",
        claim_label = "amend:identity:signing-key-hash",
        operation = "signing-key-hash",
        source_item = "signing_key_hash"
    ),
    ret
)]
pub fn signing_key_hash(bytes: &[u8]) -> Result<KeyHash, RecipeError> {
    #[cfg(test)]
    verification::tests::visit(verification::tests::Stage::Hash);
    let key: &[u8; 32] = bytes.try_into().map_err(|_| RecipeError::KeyLength)?;
    let mut hash = Sha256::new();
    hash.update(b"pn-act-authentication/signing-key-hash/v1\0");
    hash.update(key);
    Ok(KeyHash(hash.finalize().into()))
}

/// Derive an initial asset from a display-order transaction id, an unflagged
/// output index and the raw contract field. No semantic digest is introduced.
/// (´[ROOT-amend:identity:author-asset-recipe]´)
///
/// # Errors
/// Refuses an index containing issuance or peg-in flags.
#[tracing::instrument(
    name = "amend:identity:author-asset-recipe",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ROOT",
        claim_label = "amend:identity:author-asset-recipe",
        operation = "initial-asset-id",
        source_item = "initial_asset_id"
    ),
    ret
)]
pub fn initial_asset_id(display_txid: [u8; 32], index: u32, contract: [u8; 32]) -> Result<AssetId, RecipeError> {
    if index & 0xc000_0000 != 0 {
        return Err(RecipeError::PrevoutIndex);
    }
    let mut prevout = [0_u8; 36];
    let mut consensus_txid = display_txid;
    consensus_txid.reverse();
    prevout[..32].copy_from_slice(&consensus_txid);
    prevout[32..].copy_from_slice(&index.to_le_bytes());
    let hash = Sha256::digest(Sha256::digest(prevout));
    let entropy = midpoint(hash.into(), contract);
    let mut asset = midpoint(entropy, [0; 32]);
    asset.reverse();
    Ok(AssetId(asset))
}

fn midpoint(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut state = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut block = [0; 64];
    block[..32].copy_from_slice(&left);
    block[32..].copy_from_slice(&right);
    sha2::block_api::compress256(&mut state, &[block]);
    let mut result = [0; 32];
    for (chunk, word) in result.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    result
}

/// Decode the exact PNAT script; output asset/value/nonce and issuance are
/// separate obligations. Every other script qualifies nothing.
///
/// # Errors
/// Distinguishes unsupported versions, lengths, push forms, tags and flags.
/// (´[ROOT-rule:devnet:author-token]´)
#[tracing::instrument(
    name = "rule:devnet:author-token",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ROOT",
        claim_label = "rule:devnet:author-token",
        operation = "qualification-script",
        source_item = "qualification_script"
    ),
    ret
)]
pub fn qualification_script(script: &[u8]) -> Result<Qualification, QualificationRefusal> {
    if script.get(2..6) == Some(b"PNAT") && script.get(6).is_some_and(|version| *version != 2) {
        return Err(QualificationRefusal::Version);
    }
    let script: &[u8; 76] = script.try_into().map_err(|_| QualificationRefusal::Length)?;
    if script[..2] != [0x6a, 0x4a] {
        return Err(QualificationRefusal::Push);
    }
    if script[2..6] != *b"PNAT" {
        return Err(QualificationRefusal::Tag);
    }
    if script[75] != 0 {
        return Err(QualificationRefusal::Flags);
    }
    let mut run = [0; 32];
    run.copy_from_slice(&script[7..39]);
    let mut prevout = [0; 36];
    prevout.copy_from_slice(&script[39..75]);
    Ok(Qualification { run, prevout })
}

/// Decode the exact PNAK script; output asset/value/nonce are separate
/// obligations. A malformed tagged script names no key.
/// (´[ROOT-rule:devnet:author-key-output]´)
#[must_use]
#[tracing::instrument(
    name = "rule:devnet:author-key-output",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ROOT",
        claim_label = "rule:devnet:author-key-output",
        operation = "key-script",
        source_item = "key_script"
    ),
    ret
)]
pub fn key_script(script: &[u8]) -> Option<KeyHash> {
    let script: &[u8; 39] = script.try_into().ok()?;
    if script[..7] != *b"\x6a\x25PNAK\x01" {
        return None;
    }
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&script[7..]);
    Some(KeyHash(bytes))
}

mod encoding;
pub use encoding::{
    AUTHENTICATION_EDITION, AuthenticationMaterial, EncodingError, HeaderParts, VerifiedHeader, compare_act, compare_header,
    decode_header, decode_material, encode_header, encode_material,
};

mod messages;
pub use messages::{
    ApprovalMessage, ProposalMessage, SealMessage, UnestablishedProposalDigest, approval_message, proposal_message, seal_message,
    unopened_proposal_digest,
};
