//! Conditional evidence for one transaction, never a chain-history verdict.
//! (´def:wallet:token-evidence´)

use pn_act_authentication::{AssetId, KeyHash, QualificationRefusal, initial_asset_id, key_script, qualification_script};

use crate::{Input, Output, Transaction};

#[cfg(test)]
mod tests;

/// A caller's claim that an input spends a previously qualified token unit.
/// The history verifier must authenticate this asset, amount and locking script
/// against the actual spent output. This carrier establishes none of them.
/// (´def:wallet:token-evidence´)
#[derive(Clone, Copy, Debug)]
pub struct SuppliedTokenInput<'a> {
    pub input: usize,
    pub asset: AssetId,
    pub amount: u64,
    pub locking_script: &'a [u8],
}

/// Finite inventory and reservation ceilings, checked before allocation.
/// (´def:wallet:token-evidence´)
#[derive(Clone, Copy, Debug)]
pub struct TokenLimits {
    pub inputs: usize,
    pub outputs: usize,
    pub declarations: usize,
    pub script: usize,
    pub witness: usize,
    pub allocation: usize,
}

/// Typed resource or supplied-evidence refusal, not a chain verdict.
/// (´def:wallet:token-evidence´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenRefusal {
    Limits,
    Inputs,
    Outputs,
    Script,
    Witness,
    Declarations,
    Allocation,
    SuppliedInput,
}

/// Whether shared declarations apply to this token under the supplied evidence.
/// (´def:wallet:token-evidence´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenStatus {
    Qualified,
    Moved,
    Unsupported,
}

/// One independently interpreted token; unsupported paths receive no keys.
/// (´def:wallet:token-evidence´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenEffect {
    pub asset: AssetId,
    pub input: usize,
    pub status: TokenStatus,
}

/// Shared declarations apply exactly to the qualified and moved effects.
/// Duplicate declarations remain counted and retained; history membership may
/// deduplicate them. Neither this result nor its supplied inputs prove inclusion.
/// (´def:wallet:token-evidence´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionTokenEvidence {
    pub declarations: Vec<KeyHash>,
    pub tokens: Vec<TokenEffect>,
}

/// Interpret one decoded transaction and bounded, supplied token prevouts.
/// Consensus validity is a premise; signatures are not verified here.
/// (´def:wallet:token-evidence´)
///
/// # Errors
/// Refuses oversized inventories before allocation, and absent or duplicate
/// supplied input indexes. Nonconforming spends affect only their own token.
#[tracing::instrument(
    name = "rule:devnet:author-public-evidence",
    fields(
        execution_owner = "WALLET",
        claim_owner = "ROOT",
        claim_label = "rule:devnet:author-public-evidence",
        operation = "token-evidence",
        source_item = "token::transaction_token_evidence"
    ),
    ret
)]
pub fn transaction_token_evidence(
    transaction: &Transaction,
    supplied: &[SuppliedTokenInput<'_>],
    run: [u8; 32],
    fee_asset: AssetId,
    limits: TokenLimits,
) -> Result<TransactionTokenEvidence, TokenRefusal> {
    let fields = transaction.fields();
    preflight(&fields.inputs, &fields.outputs, supplied, limits)?;
    let count = fields
        .outputs
        .iter()
        .filter(|output| declaration(output, fee_asset).is_some())
        .count();
    if count > limits.declarations {
        return Err(TokenRefusal::Declarations);
    }
    let capacity = fields
        .inputs
        .len()
        .checked_add(supplied.len())
        .ok_or(TokenRefusal::Allocation)?;
    let bytes = capacity
        .checked_mul(size_of::<TokenEffect>())
        .and_then(|n| count.checked_mul(size_of::<KeyHash>()).and_then(|k| n.checked_add(k)))
        .ok_or(TokenRefusal::Allocation)?;
    if bytes > limits.allocation {
        return Err(TokenRefusal::Allocation);
    }
    let mut result = TransactionTokenEvidence {
        declarations: Vec::new(),
        tokens: Vec::new(),
    };
    #[cfg(test)]
    tests::RESERVATIONS.with(|counter| counter.set(counter.get() + 1));
    result
        .declarations
        .try_reserve_exact(count)
        .map_err(|_| TokenRefusal::Allocation)?;
    result
        .tokens
        .try_reserve_exact(capacity)
        .map_err(|_| TokenRefusal::Allocation)?;
    for output in &fields.outputs {
        if let Some(key) = declaration(output, fee_asset) {
            result.declarations.push(key);
        }
    }
    for (index, input) in fields.inputs.iter().enumerate() {
        if qualifies(input, &fields.outputs, run, fee_asset).is_ok()
            && let Some(asset) = issued_asset(input)
            && unit_output(&fields.outputs, asset)
        {
            result.tokens.push(TokenEffect {
                asset,
                input: index,
                status: TokenStatus::Qualified,
            });
        }
    }
    for previous in supplied {
        let input = &fields.inputs[previous.input];
        let supported = previous.amount == 1
            && !input.pegin
            && supported_spend(input, previous.locking_script)
            && unit_output(&fields.outputs, previous.asset);
        result.tokens.push(TokenEffect {
            asset: previous.asset,
            input: previous.input,
            status: if supported {
                TokenStatus::Moved
            } else {
                TokenStatus::Unsupported
            },
        });
    }
    Ok(result)
}

fn qualifies(input: &Input, outputs: &[Output], run: [u8; 32], fee_asset: AssetId) -> Result<(), QualificationRefusal> {
    if !input.has_issuance {
        return Err(QualificationRefusal::NoIssuance);
    }
    let mut count = 0;
    let mut other_run = false;
    for output in outputs {
        if tagged_output(output, fee_asset)
            && let Ok(marker) = qualification_script(&output.script)
            && marker.prevout.as_slice() == input.outpoint
        {
            if marker.run == run {
                count += 1;
            } else {
                other_run = true;
            }
        }
    }
    match count {
        0 if other_run => Err(QualificationRefusal::Run),
        0 => Err(QualificationRefusal::Missing),
        1 => Ok(()),
        _ => Err(QualificationRefusal::Duplicate),
    }
}

fn preflight(
    inputs: &[Input],
    outputs: &[Output],
    supplied: &[SuppliedTokenInput<'_>],
    limits: TokenLimits,
) -> Result<(), TokenRefusal> {
    if limits.inputs == 0
        || limits.inputs > 4096
        || limits.outputs == 0
        || limits.outputs > 4096
        || limits.declarations > limits.outputs
        || limits.script > 10_000
        || limits.witness > 65_536
    {
        return Err(TokenRefusal::Limits);
    }
    if inputs.len() > limits.inputs || supplied.len() > limits.inputs {
        return Err(TokenRefusal::Inputs);
    }
    if outputs.len() > limits.outputs {
        return Err(TokenRefusal::Outputs);
    }
    for input in inputs {
        if input.script.len() > limits.script {
            return Err(TokenRefusal::Script);
        }
        if input.witness.len() > limits.witness {
            return Err(TokenRefusal::Witness);
        }
    }
    for output in outputs {
        if output.script.len() > limits.script {
            return Err(TokenRefusal::Script);
        }
    }
    for (position, input) in supplied.iter().enumerate() {
        if input.locking_script.len() > limits.script {
            return Err(TokenRefusal::Script);
        }
        if input.input >= inputs.len() || supplied[..position].iter().any(|prior| prior.input == input.input) {
            return Err(TokenRefusal::SuppliedInput);
        }
    }
    Ok(())
}

fn explicit_asset(bytes: &[u8]) -> Option<AssetId> {
    let bytes: &[u8; 33] = bytes.try_into().ok()?;
    if bytes[0] != 1 {
        return None;
    }
    let mut display = [0; 32];
    display.copy_from_slice(&bytes[1..]);
    display.reverse();
    Some(AssetId(display))
}

fn amount(bytes: &[u8]) -> Option<u64> {
    let bytes: &[u8; 9] = bytes.try_into().ok()?;
    if bytes[0] != 1 {
        return None;
    }
    Some(u64::from_be_bytes(bytes[1..].try_into().ok()?))
}

fn tagged_output(output: &Output, asset: AssetId) -> bool {
    explicit_asset(&output.asset) == Some(asset) && amount(&output.value) == Some(0) && output.nonce == [0]
}

fn declaration(output: &Output, asset: AssetId) -> Option<KeyHash> {
    tagged_output(output, asset).then(|| key_script(&output.script)).flatten()
}

fn unit_output(outputs: &[Output], asset: AssetId) -> bool {
    outputs
        .iter()
        .filter(|output| {
            explicit_asset(&output.asset) == Some(asset)
                && amount(&output.value) == Some(1)
                && output.nonce == [0]
                && !output.script.is_empty()
                && output.script[0] != 0x6a
        })
        .count()
        == 1
}

fn issued_asset(input: &Input) -> Option<AssetId> {
    if !input.has_issuance || input.pegin || input.issuance.len() < 74 || input.issuance[..32] != [0; 32] {
        return None;
    }
    if amount(&input.issuance[64..73]) != Some(1) {
        return None;
    }
    let inflation = &input.issuance[73..];
    if inflation != [0] && amount(inflation) != Some(0) {
        return None;
    }
    let prevout: &[u8; 36] = input.outpoint.as_slice().try_into().ok()?;
    let mut txid = [0; 32];
    txid.copy_from_slice(&prevout[..32]);
    txid.reverse();
    initial_asset_id(
        txid,
        u32::from_le_bytes(prevout[32..].try_into().ok()?),
        input.issuance[32..64].try_into().ok()?,
    )
    .ok()
}

fn supported_spend(input: &Input, locking: &[u8]) -> bool {
    if locking.len() != 22 || locking[..2] != [0, 20] || !input.script.is_empty() {
        return false;
    }
    let mut witness = input.witness.as_slice();
    let Some(_) = vector(&mut witness) else {
        return false;
    };
    let Some(_) = vector(&mut witness) else {
        return false;
    };
    if count(&mut witness) != Some(2) {
        return false;
    }
    let Some(signature) = vector(&mut witness) else {
        return false;
    };
    let Some(key) = vector(&mut witness) else {
        return false;
    };
    if count(&mut witness) != Some(0) || !witness.is_empty() {
        return false;
    }
    key.len() == 33
        && matches!(key[0], 2 | 3)
        && signature.len() >= 9
        && signature.len() <= 73
        && matches!(signature.last(), Some(1 | 0x81))
}

fn vector<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = count(bytes)?;
    let (head, tail) = bytes.split_at_checked(n)?;
    *bytes = tail;
    Some(head)
}

fn count(bytes: &mut &[u8]) -> Option<usize> {
    let (&first, tail) = bytes.split_first()?;
    *bytes = tail;
    match first {
        0..=252 => Some(usize::from(first)),
        253 => {
            let (head, tail) = bytes.split_at_checked(2)?;
            let n = usize::from(u16::from_le_bytes(head.try_into().ok()?));
            *bytes = tail;
            (n >= 253).then_some(n)
        }
        _ => None,
    }
}
