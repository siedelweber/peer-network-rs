use super::*;
use crate::{Limits, TransactionFields, decode_transaction};

thread_local! { pub(super) static RESERVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

fn decoder_limits() -> Limits {
    Limits {
        bytes: 100_000,
        items: 128,
        script: 10_000,
        witness: 65_536,
        allocation: 134_217_728,
    }
}

fn limits() -> TokenLimits {
    TokenLimits {
        inputs: 8,
        outputs: 16,
        declarations: 8,
        script: 100,
        witness: 1024,
        allocation: 4096,
    }
}

fn fixture() -> (TransactionFields, AssetId, AssetId, [u8; 32]) {
    let rows: serde_json::Value = serde_json::from_str(include_str!("../../../act-authentication/tests/golden.json")).unwrap();
    let row = &rows["assets"][0];
    let tx = decode_transaction(&hex(row["transaction"].as_str().unwrap()), decoder_limits()).unwrap();
    (
        tx.fields().clone(),
        AssetId(hex(rows["fee_asset"].as_str().unwrap()).try_into().unwrap()),
        AssetId(hex(row["asset"].as_str().unwrap()).try_into().unwrap()),
        hex(row["run"].as_str().unwrap()).try_into().unwrap(),
    )
}

fn chain_qualification() {
    let rows: serde_json::Value = serde_json::from_str(include_str!("../../../act-authentication/tests/golden.json")).unwrap();
    let fee = AssetId(hex(rows["fee_asset"].as_str().unwrap()).try_into().unwrap());
    for ordinal in [2, 0, 1] {
        let row = &rows["assets"][ordinal];
        let run: [u8; 32] = hex(row["run"].as_str().unwrap()).try_into().unwrap();
        let mut reversed_run = run;
        reversed_run.reverse();
        assert_ne!(run, reversed_run);
        for field in ["reordered_transaction", "transaction"] {
            let Some(raw) = row[field].as_str() else { continue };
            let tx = decode_transaction(&hex(raw), decoder_limits()).unwrap();
            let value = transaction_token_evidence(&tx, &[], run, fee, limits()).unwrap();
            assert_eq!(value.tokens.len(), 1, "only marked issuance qualifies");
            assert_eq!(
                value.tokens[0].asset,
                AssetId(hex(row["asset"].as_str().unwrap()).try_into().unwrap())
            );
            assert_eq!(
                value.tokens[0].input,
                usize::from(field == "reordered_transaction"),
                "prevout follows reordered input"
            );
            assert_eq!(value.tokens[0].status, TokenStatus::Qualified);
            assert!(
                transaction_token_evidence(&tx, &[], reversed_run, fee, limits())
                    .unwrap()
                    .tokens
                    .is_empty(),
                "reversed run never qualifies"
            );
        }
    }
    for row in rows["legacy_version_one"].as_array().unwrap().iter().rev() {
        let tx = decode_transaction(&hex(row["transaction"].as_str().unwrap()), decoder_limits()).unwrap();
        let run = hex(row["run"].as_str().unwrap()).try_into().unwrap();
        assert!(
            transaction_token_evidence(&tx, &[], run, fee, limits())
                .unwrap()
                .tokens
                .is_empty(),
            "version one is withdrawn"
        );
    }
}

fn sized(bytes: &[u8], target: &mut Vec<u8>) {
    target.push(u8::try_from(bytes.len()).unwrap());
    target.extend(bytes);
}

fn transaction(fields: &TransactionFields) -> Transaction {
    let mut wire = fields.version.to_le_bytes().to_vec();
    wire.push(1);
    wire.push(u8::try_from(fields.inputs.len()).unwrap());
    for input in &fields.inputs {
        let mut outpoint = input.outpoint.clone();
        if input.has_issuance {
            outpoint[35] |= 0x80;
        }
        if input.pegin {
            outpoint[35] |= 0x40;
        }
        wire.extend(outpoint);
        sized(&input.script, &mut wire);
        wire.extend(input.sequence.to_le_bytes());
        if input.has_issuance {
            wire.extend(&input.issuance);
        }
    }
    wire.push(u8::try_from(fields.outputs.len()).unwrap());
    for output in &fields.outputs {
        wire.extend(&output.asset);
        wire.extend(&output.value);
        wire.extend(&output.nonce);
        sized(&output.script, &mut wire);
    }
    wire.extend(fields.lock_time.to_le_bytes());
    for input in &fields.inputs {
        wire.extend(&input.witness);
    }
    for output in &fields.outputs {
        wire.extend(&output.witness);
    }
    decode_transaction(&wire, decoder_limits()).unwrap()
}

fn key_output(fields: &TransactionFields, byte: u8) -> Output {
    let mut output = fields
        .outputs
        .iter()
        .find(|o| qualification_script(&o.script).is_ok())
        .unwrap()
        .clone();
    output.script = b"\x6a\x25PNAK\x01".to_vec();
    output.script.extend([byte; 32]);
    output
}

/// Daemon issuance qualifies only under its run, unique marker and exact unit.
/// Unrelated issuance and malformed tagged outputs do not inherit authority.
/// ´claim:wallet:token-qualification-is-local´
/// ´test:unit:token-qualification´
#[test]
fn token_qualification() {
    chain_qualification();
    let (fields, fee, asset, run) = fixture();
    let tx = transaction(&fields);
    let value = transaction_token_evidence(&tx, &[], run, fee, limits()).unwrap();
    assert_eq!(
        value.tokens,
        [TokenEffect {
            asset,
            input: 0,
            status: TokenStatus::Qualified
        }]
    );
    assert_eq!(value.declarations, []);
    assert_eq!(
        qualifies(&fields.inputs[0], &fields.outputs, [9; 32], fee),
        Err(QualificationRefusal::Run)
    );
    let mut duplicate = fields.outputs.clone();
    duplicate.extend(fields.outputs.clone());
    assert_eq!(
        qualifies(&fields.inputs[0], &duplicate, run, fee),
        Err(QualificationRefusal::Duplicate)
    );
    let mut absent = fields.inputs[0].clone();
    absent.has_issuance = false;
    assert_eq!(
        qualifies(&absent, &fields.outputs, run, fee),
        Err(QualificationRefusal::NoIssuance)
    );
    absent.has_issuance = true;
    absent.outpoint[0] ^= 1;
    assert_eq!(
        qualifies(&absent, &fields.outputs, run, fee),
        Err(QualificationRefusal::Missing)
    );
    assert_eq!(
        transaction_token_evidence(&tx, &[], [9; 32], fee, limits()).unwrap().tokens,
        []
    );
    let marker = fields
        .outputs
        .iter()
        .position(|o| qualification_script(&o.script).is_ok())
        .unwrap();
    for mutation in [2, 0, 5, 4, 1, 3] {
        let mut changed = fields.clone();
        match mutation {
            0 => {
                changed.outputs.remove(marker);
            }
            1 => changed.outputs.push(fields.outputs[marker].clone()),
            2 => changed.outputs[marker].script[42] = 100,
            3 => changed.inputs[0].issuance[0] = 1,
            5 => changed.inputs[0].has_issuance = false,
            _ => changed.inputs[0].issuance[72] = 2,
        }
        assert_eq!(
            transaction_token_evidence(&transaction(&changed), &[], run, fee, limits())
                .unwrap()
                .tokens,
            []
        );
    }
    let mut changed = fields;
    changed.outputs.push(key_output(&changed, 8));
    let mut bad = key_output(&changed, 9);
    bad.script[6] = 2;
    changed.outputs.push(bad);
    assert_eq!(
        transaction_token_evidence(&transaction(&changed), &[], run, fee, limits())
            .unwrap()
            .declarations,
        [KeyHash([8; 32])]
    );
}

/// Exact inventories admit; one-below declarations and allocation refuse before
/// the reserve site. Counts are audited at that site, not inferred from errors.
/// ´claim:wallet:token-inventories-precede-reservation´
/// ´test:unit:token-limits´
#[test]
fn token_limits() {
    let (mut fields, fee, _, run) = fixture();
    fields.outputs.push(key_output(&fields, 7));
    fields.outputs.push(key_output(&fields, 7));
    let tx = transaction(&fields);
    let mut bound = limits();
    bound.inputs = 1;
    bound.outputs = fields.outputs.len();
    bound.declarations = 2;
    bound.script = fields.outputs.iter().map(|output| output.script.len()).max().unwrap();
    bound.witness = fields.inputs[0].witness.len();
    bound.allocation = size_of::<TokenEffect>() + 2 * size_of::<KeyHash>();
    let value = transaction_token_evidence(&tx, &[], run, fee, bound).unwrap();
    assert_eq!(value.declarations.len(), 2);
    for mode in [1, 3, 0, 4, 2] {
        let mut too_small = bound;
        let expected = match mode {
            0 => {
                too_small.declarations -= 1;
                TokenRefusal::Declarations
            }
            1 => {
                too_small.allocation -= 1;
                TokenRefusal::Allocation
            }
            2 => {
                too_small.outputs -= 1;
                TokenRefusal::Outputs
            }
            3 => {
                too_small.script -= 1;
                TokenRefusal::Script
            }
            _ => {
                too_small.witness -= 1;
                TokenRefusal::Witness
            }
        };
        RESERVATIONS.with(|counter| counter.set(0));
        assert_eq!(transaction_token_evidence(&tx, &[], run, fee, too_small), Err(expected));
        assert_eq!(RESERVATIONS.with(std::cell::Cell::get), 0, "refusal must precede reserve");
    }
    let mut excess = fields.clone();
    excess.inputs.push(fields.inputs[0].clone());
    RESERVATIONS.with(|counter| counter.set(0));
    assert_eq!(
        transaction_token_evidence(&transaction(&excess), &[], run, fee, bound),
        Err(TokenRefusal::Inputs)
    );
    assert_eq!(RESERVATIONS.with(std::cell::Cell::get), 0);
}

/// Only supplied token inputs with all-output commitments receive declarations;
/// a nonconforming co-mover is unsupported independently, not a shared failure.
/// ´claim:wallet:token-spend-commitment-is-per-input´
/// ´test:unit:token-spends´
#[test]
fn token_spends() {
    let (mut fields, fee, asset, run) = fixture();
    fields.inputs[0].has_issuance = false;
    fields.inputs[0].issuance.clear();
    fields.outputs.push(key_output(&fields, 6));
    let locking = fields
        .outputs
        .iter()
        .find(|o| explicit_asset(&o.asset) == Some(asset))
        .unwrap()
        .script
        .clone();
    let supplied = [SuppliedTokenInput {
        input: 0,
        asset,
        amount: 1,
        locking_script: &locking,
    }];
    let normal = transaction_token_evidence(&transaction(&fields), &supplied, run, fee, limits()).unwrap();
    assert_eq!(
        normal.tokens,
        [TokenEffect {
            asset,
            input: 0,
            status: TokenStatus::Moved
        }]
    );
    // The witness fixture is two empty proof vectors then a two-item stack.
    let length = usize::from(fields.inputs[0].witness[3]);
    for flag in [0x82, 1, 0x41, 0x81, 3, 0xc1] {
        let mut changed = fields.clone();
        changed.inputs[0].witness[3 + length] = flag;
        let value = transaction_token_evidence(&transaction(&changed), &supplied, run, fee, limits()).unwrap();
        assert_eq!(
            value.tokens[0].status,
            if matches!(flag, 1 | 0x81) {
                TokenStatus::Moved
            } else {
                TokenStatus::Unsupported
            }
        );
    }
    assert_eq!(
        transaction_token_evidence(&transaction(&fields), &[], run, fee, limits())
            .unwrap()
            .tokens,
        []
    );
    let mut mixed = fields.clone();
    let mut other = fields.inputs[0].clone();
    other.outpoint[0] ^= 1;
    other.witness[3 + length] = 0x82;
    mixed.inputs.push(other);
    let other_asset = AssetId([3; 32]);
    let mut unit = fields
        .outputs
        .iter()
        .find(|output| explicit_asset(&output.asset) == Some(asset))
        .unwrap()
        .clone();
    unit.asset[1..].copy_from_slice(&other_asset.0);
    mixed.outputs.push(unit);
    let both = [
        supplied[0],
        SuppliedTokenInput {
            input: 1,
            asset: other_asset,
            amount: 1,
            locking_script: &locking,
        },
    ];
    let value = transaction_token_evidence(&transaction(&mixed), &both, run, fee, limits()).unwrap();
    assert_eq!(
        value.tokens,
        [
            TokenEffect {
                asset,
                input: 0,
                status: TokenStatus::Moved
            },
            TokenEffect {
                asset: other_asset,
                input: 1,
                status: TokenStatus::Unsupported
            }
        ]
    );
}

/// Unsorted distinct issuance inputs qualify independently; the unmarked asset
/// receives no declarations, while duplicate hashes still consume the ceiling.
/// ´claim:wallet:shared-declarations-follow-only-qualified-tokens´
/// ´test:unit:multiple-tokens´
#[test]
fn multiple_tokens() {
    let rows: serde_json::Value = serde_json::from_str(include_str!("../../../act-authentication/tests/golden.json")).unwrap();
    let (mut fields, fee, _, run) = fixture();
    fields.inputs.clear();
    fields.outputs.clear();
    let mut expected = Vec::new();
    for (input, ordinal) in [2, 0, 1].into_iter().enumerate() {
        let row = &rows["assets"][ordinal];
        let tx = decode_transaction(&hex(row["transaction"].as_str().unwrap()), decoder_limits()).unwrap();
        let adapted = tx.fields().clone();
        fields.inputs.push(adapted.inputs[0].clone());
        for output in &adapted.outputs {
            let mut output = output.clone();
            if qualification_script(&output.script).is_ok() {
                if input == 2 {
                    continue;
                }
                output.script[7..39].copy_from_slice(&run);
            }
            fields.outputs.push(output);
        }
        if input != 2 {
            expected.push(TokenEffect {
                asset: AssetId(hex(row["asset"].as_str().unwrap()).try_into().unwrap()),
                input,
                status: TokenStatus::Qualified,
            });
        }
    }
    for count in [3, 0, 1] {
        let mut changed = fields.clone();
        for byte in [8, 2, 8].into_iter().take(count) {
            changed.outputs.push(key_output(&fields, byte));
        }
        let value = transaction_token_evidence(&transaction(&changed), &[], run, fee, limits()).unwrap();
        assert_eq!(value.tokens, expected);
        assert_eq!(value.declarations.len(), count);
    }
}
