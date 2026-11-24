//! Bounded reconstruction from complete supplied public block layouts.
//! Selection, signed-chain validity and record binding remain caller premises.
//! (´[ROOT-rule:identity:author-key-history]´)

use std::collections::BTreeSet;
use std::fmt::Write;

use pn_act_authentication::{AssetId, KeyHash};

use super::{
    SuppliedTokenInput, TokenLimits, TokenRefusal, TokenStatus, amount, explicit_asset, issued_asset, transaction_token_evidence,
};
use crate::{Block, Limits, Output, Refusal, Transaction, decode_block};

/// The six independently selected run ceilings; this module chooses no values.
#[derive(Clone, Copy, Debug)]
pub struct HistoryLimits {
    pub declaration_outputs: usize,
    pub history_bytes: usize,
    pub history_transactions: usize,
    pub active_entries: usize,
    pub scan_blocks: usize,
    pub scan_bytes: usize,
}

/// One Actor and the independently located qualified issuance input.
#[derive(Clone, Debug)]
pub struct ScanPart<'a> {
    pub actor: &'a str,
    pub height: u64,
    pub transaction_index: usize,
    pub input_index: usize,
    pub issuance_prevout: [u8; 36],
}

/// Complete raw blocks, including unrelated transactions and the stability buffer.
#[derive(Debug)]
pub struct AccountScan<'a> {
    pub first_height: u64,
    pub pin_height: u64,
    pub buffer: u64,
    pub blocks: &'a [Vec<u8>],
    pub parts: &'a [ScanPart<'a>],
    pub run: [u8; 32],
    pub fee_asset: AssetId,
    pub decoder: Limits,
    pub token: TokenLimits,
    pub limits: HistoryLimits,
}

/// One transaction on the supported path; its declarations belong to this token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathStep {
    pub height: u64,
    pub transaction_index: usize,
    pub txid: [u8; 32],
    pub keys: Vec<KeyHash>,
}

/// A reconstructed path and active set under an explicit retirement boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorHistory {
    pub actor: String,
    pub path: Vec<PathStep>,
    pub active: Vec<KeyHash>,
}

/// Finite reconstruction outcome, without a chain signature or inclusion verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanError {
    Budget,
    MissingEvidence,
    Qualification,
    Actor,
    Path,
    UnsupportedPath,
    Decoder(Refusal),
    Token(TokenRefusal),
}

/// Scan every transaction in each Actor's complete issuance-to-pin span.
/// Each Actor is charged independently, including unrelated transactions.
///
/// # Errors
/// Refuses incomplete evidence, a wrong issuance, an unsupported path or an
/// exhausted caller-selected bound without returning a partial key set.
#[tracing::instrument(
    name = "rule:identity:author-key-history",
    fields(
        execution_owner = "WALLET",
        claim_owner = "ROOT",
        claim_label = "rule:identity:author-key-history",
        operation = "token-history-scan-account",
        source_item = "token::history::scan_account"
    ),
    ret
)]
pub fn scan_account(input: AccountScan<'_>) -> Result<Vec<ActorHistory>, ScanError> {
    let expected_first = input.parts.iter().map(|part| part.height).min().unwrap_or(input.pin_height);
    if input.first_height != expected_first || expected_first > input.pin_height {
        return Err(ScanError::MissingEvidence);
    }
    let end = input.pin_height.checked_add(input.buffer).ok_or(ScanError::MissingEvidence)?;
    let count = end
        .checked_sub(input.first_height)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(ScanError::MissingEvidence)?;
    if count != input.blocks.len() {
        return Err(ScanError::MissingEvidence);
    }
    for part in input.parts {
        preflight_span(&input, part)?;
    }
    let mut decoded = Vec::new();
    decoded.try_reserve_exact(count).map_err(|_| ScanError::Budget)?;
    for block in input.blocks {
        if block.len() > input.decoder.bytes {
            return Err(ScanError::Budget);
        }
        decoded.push(decode_block(block, input.decoder).map_err(ScanError::Decoder)?);
    }
    let mut histories = Vec::new();
    histories
        .try_reserve_exact(input.parts.len())
        .map_err(|_| ScanError::Budget)?;
    for part in input.parts {
        histories.push(scan_part(&input, &decoded, part)?);
    }
    Ok(histories)
}

/// Check each supplied issuance and its derived Actor before path scanning.
/// The caller has already established the account's complete interval.
///
/// # Errors
/// Refuses a missing issuance, wrong asset or Actor, or unreadable issuance block.
#[tracing::instrument(
    name = "amend:identity:authority-account",
    fields(
        execution_owner = "WALLET",
        claim_owner = "ROOT",
        claim_label = "amend:identity:authority-account",
        operation = "token-history-qualify-account",
        source_item = "token::history::qualify_account"
    ),
    ret
)]
pub fn qualify_account(input: &AccountScan<'_>) -> Result<(), ScanError> {
    for part in input.parts {
        let offset = part
            .height
            .checked_sub(input.first_height)
            .ok_or(ScanError::MissingEvidence)?;
        if part.height > input.pin_height {
            return Err(ScanError::MissingEvidence);
        }
        let offset = usize::try_from(offset).map_err(|_| ScanError::Budget)?;
        let bytes = input.blocks.get(offset).ok_or(ScanError::MissingEvidence)?;
        if bytes.len() > input.decoder.bytes {
            return Err(ScanError::Budget);
        }
        let block = decode_block(bytes, input.decoder).map_err(ScanError::Decoder)?;
        let issuance = block
            .transactions
            .get(part.transaction_index)
            .ok_or(ScanError::MissingEvidence)?;
        let issuance_input = issuance
            .fields()
            .inputs
            .get(part.input_index)
            .ok_or(ScanError::Qualification)?;
        if issuance_input.outpoint.as_slice() != part.issuance_prevout.as_slice() || !issuance_input.has_issuance {
            return Err(ScanError::Qualification);
        }
        let asset = issued_asset(issuance_input).ok_or(ScanError::Qualification)?;
        if actor_name(input.run, asset) != part.actor {
            return Err(ScanError::Actor);
        }
    }
    Ok(())
}

fn preflight_span(input: &AccountScan<'_>, part: &ScanPart<'_>) -> Result<(), ScanError> {
    let first = part
        .height
        .checked_sub(input.first_height)
        .ok_or(ScanError::MissingEvidence)?;
    let last = input
        .pin_height
        .checked_sub(input.first_height)
        .ok_or(ScanError::MissingEvidence)?;
    let count = last
        .checked_sub(first)
        .and_then(|n| n.checked_add(1))
        .ok_or(ScanError::MissingEvidence)?;
    if count > u64::try_from(input.limits.scan_blocks).unwrap_or(u64::MAX) {
        return Err(ScanError::Budget);
    }
    let first = usize::try_from(first).map_err(|_| ScanError::Budget)?;
    let last = usize::try_from(last).map_err(|_| ScanError::Budget)?;
    let mut remaining = input.limits.scan_bytes;
    for block in input.blocks.get(first..=last).ok_or(ScanError::MissingEvidence)? {
        remaining = remaining.checked_sub(block.len()).ok_or(ScanError::Budget)?;
    }
    Ok(())
}

fn scan_part(input: &AccountScan<'_>, decoded: &[Block], part: &ScanPart<'_>) -> Result<ActorHistory, ScanError> {
    let (first, last) = scan_part_budget(input, part)?;
    let issuance = decoded[first]
        .transactions
        .get(part.transaction_index)
        .ok_or(ScanError::MissingEvidence)?;
    let issuance_input = issuance
        .fields()
        .inputs
        .get(part.input_index)
        .ok_or(ScanError::Qualification)?;
    if issuance_input.outpoint.as_slice() != part.issuance_prevout.as_slice() || !issuance_input.has_issuance {
        return Err(ScanError::Qualification);
    }
    let asset = issued_asset(issuance_input).ok_or(ScanError::Qualification)?;
    if actor_name(input.run, asset) != part.actor {
        return Err(ScanError::Actor);
    }
    let mut current: Option<([u8; 36], Output)> = None;
    let mut path = Vec::new();
    let mut history_bytes = 0_usize;
    let mut history_transactions = 0_usize;
    for (block_index, block) in decoded.iter().enumerate().take(last + 1).skip(first) {
        let height = input.first_height + u64::try_from(block_index).map_err(|_| ScanError::Budget)?;
        for (transaction_index, transaction) in block.transactions.iter().enumerate() {
            if block_index == first && transaction_index < part.transaction_index {
                continue;
            }
            let matching = current.as_ref().and_then(|(outpoint, _)| {
                transaction
                    .fields()
                    .inputs
                    .iter()
                    .position(|candidate| candidate.outpoint.as_slice() == outpoint.as_slice())
            });
            let issuing = current.is_none() && block_index == first && transaction_index == part.transaction_index;
            if !issuing && matching.is_none() {
                continue;
            }
            let supplied = matching.map(|index| {
                let (_, output) = current.as_ref().expect("matching input requires a current output");
                SuppliedTokenInput {
                    input: index,
                    asset,
                    amount: amount(&output.value).unwrap_or(0),
                    locking_script: &output.script,
                }
            });
            let supplied = supplied.as_slice();
            history_transactions = history_transactions.checked_add(1).ok_or(ScanError::Budget)?;
            history_bytes = history_bytes
                .checked_add(transaction.encoded_len())
                .ok_or(ScanError::Budget)?;
            if history_transactions > input.limits.history_transactions || history_bytes > input.limits.history_bytes {
                return Err(ScanError::Budget);
            }
            let mut token_limits = input.token;
            token_limits.declarations = token_limits.declarations.min(input.limits.declaration_outputs);
            let evidence = transaction_token_evidence(transaction, supplied, input.run, input.fee_asset, token_limits)
                .map_err(ScanError::Token)?;
            let token = evidence.tokens.iter().find(|token| {
                token.asset == asset
                    && token.input
                        == if issuing {
                            part.input_index
                        } else {
                            matching.unwrap_or(usize::MAX)
                        }
            });
            let Some(token) = token else {
                return Err(if issuing { ScanError::Qualification } else { ScanError::Path });
            };
            if token.status == TokenStatus::Unsupported {
                return Err(ScanError::UnsupportedPath);
            }
            if issuing && token.status != TokenStatus::Qualified {
                return Err(ScanError::Qualification);
            }
            if !issuing && token.status != TokenStatus::Moved {
                return Err(ScanError::Path);
            }
            let (output_index, output) = token_unit_output(transaction, asset).ok_or(ScanError::Path)?;
            current = Some((outpoint(transaction, output_index)?, output.clone()));
            path.try_reserve(1).map_err(|_| ScanError::Budget)?;
            path.push(PathStep {
                height,
                transaction_index,
                txid: *transaction.consensus_txid(),
                keys: evidence.declarations,
            });
        }
    }
    let active = active_keys(&path, 0, input.limits.active_entries)?;
    Ok(ActorHistory {
        actor: part.actor.to_owned(),
        path,
        active,
    })
}

fn scan_part_budget(input: &AccountScan<'_>, part: &ScanPart<'_>) -> Result<(usize, usize), ScanError> {
    let first = part
        .height
        .checked_sub(input.first_height)
        .ok_or(ScanError::MissingEvidence)?;
    let last = input
        .pin_height
        .checked_sub(input.first_height)
        .ok_or(ScanError::MissingEvidence)?;
    let count = last
        .checked_sub(first)
        .and_then(|n| n.checked_add(1))
        .ok_or(ScanError::MissingEvidence)?;
    if count > u64::try_from(input.limits.scan_blocks).unwrap_or(u64::MAX) {
        return Err(ScanError::Budget);
    }
    let first = usize::try_from(first).map_err(|_| ScanError::Budget)?;
    let last = usize::try_from(last).map_err(|_| ScanError::Budget)?;
    let mut scan_bytes = 0_usize;
    for index in first..=last {
        scan_bytes = scan_bytes.checked_add(input.blocks[index].len()).ok_or(ScanError::Budget)?;
        if scan_bytes > input.limits.scan_bytes {
            return Err(ScanError::Budget);
        }
    }
    Ok((first, last))
}

fn token_unit_output(transaction: &Transaction, asset: AssetId) -> Option<(usize, &Output)> {
    let mut found = None;
    for (index, output) in transaction.fields().outputs.iter().enumerate() {
        if explicit_asset(&output.asset) == Some(asset)
            && amount(&output.value) == Some(1)
            && output.nonce == [0]
            && !output.script.is_empty()
            && output.script[0] != 0x6a
        {
            if found.is_some() {
                return None;
            }
            found = Some((index, output));
        }
    }
    found
}

fn outpoint(transaction: &Transaction, output_index: usize) -> Result<[u8; 36], ScanError> {
    let index = u32::try_from(output_index).map_err(|_| ScanError::Path)?;
    let mut bytes = [0; 36];
    bytes[..32].copy_from_slice(transaction.consensus_txid());
    bytes[32..].copy_from_slice(&index.to_le_bytes());
    Ok(bytes)
}

fn active_keys(path: &[PathStep], boundary: usize, limit: usize) -> Result<Vec<KeyHash>, ScanError> {
    let mut keys = BTreeSet::new();
    for step in path.get(boundary..).ok_or(ScanError::MissingEvidence)? {
        keys.extend(step.keys.iter().copied());
        if keys.len() > limit {
            return Err(ScanError::Budget);
        }
    }
    Ok(keys.into_iter().collect())
}

fn actor_name(run: [u8; 32], asset: AssetId) -> String {
    let mut actor = String::from("pn-devnet-v1/");
    for byte in run {
        write!(&mut actor, "{byte:02x}").expect("writing to String cannot fail");
    }
    actor.push('/');
    for byte in asset.0 {
        write!(&mut actor, "{byte:02x}").expect("writing to String cannot fail");
    }
    actor
}

/// One act's signed retirement field, judged in its original epoch view.
#[derive(Clone, Copy, Debug)]
pub struct RetirementRequest {
    pub epoch: u64,
    pub point: [u8; 32],
}

/// Complete per-Actor original-epoch path and its ordered retirement requests.
#[derive(Debug)]
pub struct OriginalEpoch<'a> {
    pub epoch: u64,
    pub path: &'a [PathStep],
    pub requests: &'a [RetirementRequest],
}

/// Fold valid original-epoch retirement points into the next epoch's boundary.
/// A field absent from its original path has no effect and never activates later.
///
/// # Errors
/// Refuses missing ordered epoch evidence or an exhausted active-set bound.
#[tracing::instrument(
    name = "rule:identity:retirement-order",
    fields(
        execution_owner = "WALLET",
        claim_owner = "ROOT",
        claim_label = "rule:identity:retirement-order",
        operation = "token-history-project-retirements",
        source_item = "token::history::project_retirements"
    ),
    ret
)]
pub fn project_retirements(
    current: &[PathStep],
    originals: &[OriginalEpoch<'_>],
    selected_epoch: u64,
    active_limit: usize,
) -> Result<Vec<KeyHash>, ScanError> {
    let mut boundary = current.first().ok_or(ScanError::MissingEvidence)?.txid;
    for (index, original) in originals.iter().enumerate() {
        if original.epoch != u64::try_from(index).map_err(|_| ScanError::Budget)? || original.epoch >= selected_epoch {
            return Err(ScanError::MissingEvidence);
        }
        let mut maximum = original
            .path
            .iter()
            .position(|step| step.txid == boundary)
            .ok_or(ScanError::MissingEvidence)?;
        for request in original.requests {
            if request.epoch != original.epoch {
                return Err(ScanError::MissingEvidence);
            }
            if let Some(position) = original.path.iter().position(|step| step.txid == request.point) {
                maximum = maximum.max(position);
            }
        }
        boundary = original.path[maximum].txid;
    }
    if originals.len() != usize::try_from(selected_epoch).map_err(|_| ScanError::Budget)? {
        return Err(ScanError::MissingEvidence);
    }
    let boundary = current
        .iter()
        .position(|step| step.txid == boundary)
        .ok_or(ScanError::MissingEvidence)?;
    active_keys(current, boundary, active_limit)
}
