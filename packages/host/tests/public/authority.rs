//! Conditional supplied-layout account scan under explicit synthetic premises.

use pn_act_authentication::{AssetId, KeyHash, qualification_script};
use pn_epoch::authentication::{
    AccountPin, ActorPart, AuthorityAccount, BoundaryConsumer, BoundaryContext, ConsumerResult, Inability, IssuanceLocator,
    PriorRange,
};
use pn_host::authority::{ActorOriginalEpochs, OriginalAccountEpoch, SuppliedAccountConsumer};
use pn_wallet::token::TokenLimits;
use pn_wallet::token::history::{
    AccountScan, HistoryLimits, OriginalEpoch, PathStep, RetirementRequest, ScanPart, project_retirements, scan_account,
};
use pn_wallet::{Limits, TransactionFields, decode_block, decode_transaction};

use super::boundary_components::Synthetic;

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn transaction_bytes(fields: &TransactionFields) -> Vec<u8> {
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
        wire.push(u8::try_from(input.script.len()).unwrap());
        wire.extend(&input.script);
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
        wire.push(u8::try_from(output.script.len()).unwrap());
        wire.extend(&output.script);
    }
    wire.extend(fields.lock_time.to_le_bytes());
    for input in &fields.inputs {
        wire.extend(&input.witness);
    }
    for output in &fields.outputs {
        wire.extend(&output.witness);
    }
    wire
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

fn token_limits() -> TokenLimits {
    TokenLimits {
        inputs: 8,
        outputs: 16,
        declarations: 8,
        script: 100,
        witness: 1024,
        allocation: 4096,
    }
}

/// Claim: Complete supplied layouts reconstruct the selected Actor's keys under
/// explicit chain and binding premises, with original-epoch retirement separate.
/// ´claim:publication:pinned-authority´
/// ´test:integration:pinned-authority´
#[test]
fn pinned_authority() {
    let boundary: serde_json::Value =
        serde_json::from_str(include_str!("../../../act-authentication/tests/boundary-golden.json")).unwrap();
    let scan_rows = boundary["scan_descriptors"].as_array().unwrap();
    let rows: serde_json::Value = serde_json::from_str(include_str!("../../../act-authentication/tests/golden.json")).unwrap();
    let row = &rows["assets"][0];
    let run: [u8; 32] = hex(row["run"].as_str().unwrap()).try_into().unwrap();
    let asset = AssetId(hex(row["asset"].as_str().unwrap()).try_into().unwrap());
    let fee_asset = AssetId(hex(rows["fee_asset"].as_str().unwrap()).try_into().unwrap());
    let mut fields = decode_transaction(&hex(scan_rows[0]["transaction"].as_str().unwrap()), decoder_limits())
        .unwrap()
        .fields()
        .clone();
    let mut declaration = fields
        .outputs
        .iter()
        .find(|output| qualification_script(&output.script).is_ok())
        .unwrap()
        .clone();
    declaration.script = b"\x6a\x25PNAK\x01".to_vec();
    declaration.script.extend([7; 32]);
    fields.outputs.push(declaration);
    let source = decode_block(include_bytes!("../../../wallet/fuzz/seeds/dynafed-block"), decoder_limits()).unwrap();
    let mut block = source.header.clone();
    block.push(1);
    block.extend(transaction_bytes(&fields));
    let actor = format!(
        "pn-devnet-v1/{}/{}",
        run.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        asset.0.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
    );
    let part = ActorPart {
        actor: actor.clone(),
        issuance: IssuanceLocator {
            height: 5,
            transaction_index: 0,
            input_index: 0,
            issuance_prevout: fields.inputs[0].outpoint.as_slice().try_into().unwrap(),
        },
        scan_from: 5,
        scan_through: 5,
        prior_range: PriorRange {
            history_scope: vec![128],
            first_epoch: 0,
            exclusive_end: 0,
        },
    };
    let context = BoundaryContext {
        run,
        history_scope: vec![128],
        epoch: 0,
    };
    let account = AuthorityAccount {
        context: context.clone(),
        pin: AccountPin {
            height: 5,
            block_hash: [5; 32],
            buffer: 0,
        },
        run_configuration: vec![128],
        chain_parameters: vec![128],
        first_height: 5,
        blocks: vec![block],
        prior_range: part.prior_range.clone(),
    };
    let mut selected = Synthetic::from_fixture();
    selected.context = context;
    let parts = [part];
    let originals: [ActorOriginalEpochs<'_>; 0] = [];
    let limits = HistoryLimits {
        declaration_outputs: 8,
        history_bytes: 100_000,
        history_transactions: 8,
        active_entries: 8,
        scan_blocks: 1,
        scan_bytes: account.blocks[0].len(),
    };
    let adapter = SuppliedAccountConsumer::new(
        &selected,
        &account,
        &parts,
        &originals,
        fee_asset,
        decoder_limits(),
        token_limits(),
        limits,
    );
    let value = match adapter.authority_set(&account, &parts[0]) {
        ConsumerResult::Confirmed(value) => value,
        other => panic!("expected conditional keys: {other:?}"),
    };
    assert_eq!(value.value.actor, actor);
    assert_eq!(value.value.keys, vec![KeyHash([7; 32]).0]);
    assert_eq!(value.premises.context, account.context);
    let mut wrong_locator = parts[0].clone();
    wrong_locator.issuance.input_index += 1;
    assert!(matches!(
        adapter.authority_set(&account, &wrong_locator),
        ConsumerResult::Unavailable(value) if value.value == Inability::NotCovered
    ));
    let too_small = HistoryLimits {
        scan_bytes: account.blocks[0].len() - 1,
        ..limits
    };
    let denied = SuppliedAccountConsumer::new(
        &selected,
        &account,
        &parts,
        &originals,
        fee_asset,
        decoder_limits(),
        token_limits(),
        too_small,
    );
    assert!(
        matches!(denied.authority_set(&account, &parts[0]), ConsumerResult::Unavailable(value) if value.value == Inability::UnavailableBudget)
    );

    let transaction_length = transaction_bytes(&fields).len();
    for lower in [
        HistoryLimits {
            declaration_outputs: 0,
            ..limits
        },
        HistoryLimits {
            history_bytes: transaction_length - 1,
            ..limits
        },
        HistoryLimits {
            history_transactions: 0,
            ..limits
        },
        HistoryLimits {
            active_entries: 0,
            ..limits
        },
        HistoryLimits {
            scan_blocks: 0,
            ..limits
        },
        too_small,
    ] {
        let denied = SuppliedAccountConsumer::new(
            &selected,
            &account,
            &parts,
            &originals,
            fee_asset,
            decoder_limits(),
            token_limits(),
            lower,
        );
        assert!(
            matches!(denied.authority_set(&account, &parts[0]), ConsumerResult::Unavailable(value) if value.value == Inability::UnavailableBudget)
        );
    }
    let exact = HistoryLimits {
        declaration_outputs: 1,
        history_bytes: transaction_length,
        history_transactions: 1,
        active_entries: 1,
        scan_blocks: 1,
        scan_bytes: account.blocks[0].len(),
    };
    let admitted = SuppliedAccountConsumer::new(
        &selected,
        &account,
        &parts,
        &originals,
        fee_asset,
        decoder_limits(),
        token_limits(),
        exact,
    );
    assert!(matches!(
        admitted.authority_set(&account, &parts[0]),
        ConsumerResult::Confirmed(_)
    ));

    let scan_parts = [ScanPart {
        actor: &parts[0].actor,
        height: 5,
        transaction_index: 0,
        input_index: 0,
        issuance_prevout: parts[0].issuance.issuance_prevout,
    }];
    let initial = scan_account(AccountScan {
        first_height: 5,
        pin_height: 5,
        buffer: 0,
        blocks: &account.blocks,
        parts: &scan_parts,
        run,
        fee_asset,
        decoder: decoder_limits(),
        token: token_limits(),
        limits,
    })
    .unwrap();
    let mut original_account = account.clone();
    original_account.context.epoch = 0;
    let mut next_account = account.clone();
    next_account.context.epoch = 1;
    let mut next_selected = Synthetic::from_fixture();
    next_selected.context = next_account.context.clone();
    let original_requests = [RetirementRequest {
        epoch: 0,
        point: initial[0].path[0].txid,
    }];
    let original_epochs = [OriginalAccountEpoch {
        epoch: 0,
        account: &original_account,
        parts: &parts,
        requests: &original_requests,
    }];
    let original_actor = [ActorOriginalEpochs {
        actor: &parts[0].actor,
        epochs: &original_epochs,
    }];
    let next_adapter = SuppliedAccountConsumer::new(
        &next_selected,
        &next_account,
        &parts,
        &original_actor,
        fee_asset,
        decoder_limits(),
        token_limits(),
        limits,
    );
    assert!(matches!(
        next_adapter.authority_set(&next_account, &parts[0]),
        ConsumerResult::Confirmed(value) if value.value.keys == [KeyHash([7; 32]).0]
    ));
    let mut asset_wire = asset.0;
    asset_wire.reverse();
    let unit = fields
        .outputs
        .iter()
        .position(|output| {
            output.asset.len() == 33 && output.asset[1..] == asset_wire && output.script.first().is_some_and(|head| *head != 0x6a)
        })
        .unwrap();
    let mut transfer_fields = fields.clone();
    transfer_fields.inputs[0].has_issuance = false;
    transfer_fields.inputs[0].issuance.clear();
    transfer_fields.inputs[0].outpoint[..32].copy_from_slice(&initial[0].path[0].txid);
    transfer_fields.inputs[0].outpoint[32..].copy_from_slice(&u32::try_from(unit).unwrap().to_le_bytes());
    transfer_fields.outputs.pop();
    let mut transfer_block = source.header.clone();
    transfer_block.push(1);
    transfer_block.extend(transaction_bytes(&transfer_fields));
    let mut transferred = account.clone();
    transferred.pin.height = 6;
    transferred.blocks.push(transfer_block);
    let transfer_limits = HistoryLimits {
        history_transactions: 2,
        scan_blocks: 2,
        scan_bytes: transferred.blocks.iter().map(Vec::len).sum(),
        ..limits
    };
    let transfer_adapter = SuppliedAccountConsumer::new(
        &selected,
        &transferred,
        &parts,
        &originals,
        fee_asset,
        decoder_limits(),
        token_limits(),
        transfer_limits,
    );
    assert!(matches!(
        transfer_adapter.authority_set(&transferred, &parts[0]),
        ConsumerResult::Confirmed(value) if value.value.keys == [KeyHash([7; 32]).0]
    ));
    let scanned = scan_account(AccountScan {
        first_height: 5,
        pin_height: 6,
        buffer: 0,
        blocks: &transferred.blocks,
        parts: &scan_parts,
        run,
        fee_asset,
        decoder: decoder_limits(),
        token: token_limits(),
        limits: transfer_limits,
    })
    .unwrap();
    assert_eq!(scanned[0].path.len(), 2);
    let mut omitted_fields = transfer_fields.clone();
    omitted_fields.outputs.remove(unit);
    let mut omitted_block = source.header.clone();
    omitted_block.push(1);
    omitted_block.extend(transaction_bytes(&omitted_fields));
    let mut omitted = transferred.clone();
    omitted.blocks[1] = omitted_block;
    let omitted_limits = HistoryLimits {
        scan_bytes: omitted.blocks.iter().map(Vec::len).sum(),
        ..transfer_limits
    };
    let mut unsupported_fields = transfer_fields.clone();
    let witness = &mut unsupported_fields.inputs[0].witness;
    let first_len = usize::from(witness[3]);
    witness[3 + first_len] = 0x82;
    let mut unsupported_block = source.header.clone();
    unsupported_block.push(1);
    unsupported_block.extend(transaction_bytes(&unsupported_fields));
    let mut unsupported = transferred.clone();
    unsupported.blocks[1] = unsupported_block;
    let unsupported_limits = HistoryLimits {
        scan_bytes: unsupported.blocks.iter().map(Vec::len).sum(),
        ..transfer_limits
    };

    let mut empty_fields = fields.clone();
    empty_fields.outputs.pop();
    let mut empty_block = source.header.clone();
    empty_block.push(1);
    empty_block.extend(transaction_bytes(&empty_fields));
    let mut empty_account = account.clone();
    empty_account.blocks[0] = empty_block.clone();
    assert!(
        matches!(adapter.authority_set(&empty_account, &parts[0]), ConsumerResult::Unavailable(value) if value.value == Inability::UnavailableEvaluation)
    );
    let mut duplicate_fields = fields.clone();
    duplicate_fields.outputs.push(fields.outputs.last().unwrap().clone());
    let mut duplicate_block = source.header.clone();
    duplicate_block.push(1);
    duplicate_block.extend(transaction_bytes(&duplicate_fields));
    let mut duplicate_account = account.clone();
    duplicate_account.blocks[0] = duplicate_block;
    let mut malformed_fields = fields.clone();
    let mut malformed = fields.outputs.last().unwrap().clone();
    malformed.script.pop();
    malformed_fields.outputs.push(malformed);
    let mut malformed_block = source.header.clone();
    malformed_block.push(1);
    malformed_block.extend(transaction_bytes(&malformed_fields));
    let mut malformed_account = account.clone();
    malformed_account.blocks[0] = malformed_block;
    let no_keys = SuppliedAccountConsumer::new(
        &selected,
        &empty_account,
        &parts,
        &originals,
        fee_asset,
        decoder_limits(),
        token_limits(),
        limits,
    );
    assert!(
        matches!(no_keys.authority_set(&empty_account, &parts[0]), ConsumerResult::Confirmed(value) if value.value.keys.is_empty())
    );

    let mut buffered = empty_account.clone();
    buffered.pin.buffer = 1;
    buffered.blocks.push(account.blocks[0].clone());
    let buffer_only = SuppliedAccountConsumer::new(
        &selected,
        &buffered,
        &parts,
        &originals,
        fee_asset,
        decoder_limits(),
        token_limits(),
        limits,
    );
    assert!(
        matches!(buffer_only.authority_set(&buffered, &parts[0]), ConsumerResult::Confirmed(value) if value.value.keys.is_empty())
    );

    let mut unrelated = source.header;
    unrelated.push(2);
    unrelated.extend(transaction_bytes(&fields));
    unrelated.extend(transaction_bytes(&fields));
    let mut two_transactions = account.clone();
    two_transactions.blocks[0] = unrelated;
    let under_transactions = HistoryLimits {
        history_transactions: 1,
        scan_bytes: two_transactions.blocks[0].len() - 1,
        ..limits
    };
    let charged = SuppliedAccountConsumer::new(
        &selected,
        &two_transactions,
        &parts,
        &originals,
        fee_asset,
        decoder_limits(),
        token_limits(),
        under_transactions,
    );
    assert!(
        matches!(charged.authority_set(&two_transactions, &parts[0]), ConsumerResult::Unavailable(value) if value.value == Inability::UnavailableBudget)
    );

    let path = [
        PathStep {
            height: 5,
            transaction_index: 0,
            txid: [1; 32],
            keys: vec![KeyHash([7; 32])],
        },
        PathStep {
            height: 6,
            transaction_index: 0,
            txid: [2; 32],
            keys: vec![KeyHash([8; 32])],
        },
        PathStep {
            height: 7,
            transaction_index: 0,
            txid: [3; 32],
            keys: vec![KeyHash([9; 32])],
        },
    ];
    assert_eq!(project_retirements(&path, &[], 0, 3).unwrap().len(), 3);
    let requests = [
        RetirementRequest {
            epoch: 0,
            point: [3; 32],
        },
        RetirementRequest {
            epoch: 0,
            point: [2; 32],
        },
        RetirementRequest {
            epoch: 0,
            point: [99; 32],
        },
    ];
    let original = [OriginalEpoch {
        epoch: 0,
        path: &path,
        requests: &requests,
    }];
    assert_eq!(project_retirements(&path, &original, 1, 3).unwrap(), vec![KeyHash([9; 32])]);

    let expected_ids = [
        "scan:qualified-key",
        "scan:declaration-ceiling",
        "scan:history-byte-ceiling",
        "scan:history-transaction-ceiling",
        "scan:active-ceiling",
        "scan:block-ceiling",
        "scan:scan-byte-ceiling",
        "scan:unrelated-transaction",
        "scan:buffer-only-declaration",
        "scan:missing-last-block",
        "scan:wrong-issuance-input",
        "scan:duplicate-keys",
        "scan:malformed-pnak-neighbor",
        "scan:retirement-same-epoch",
        "scan:retirement-next-epoch",
        "scan:earlier-maximum",
        "scan:no-effect-point",
        "scan:boundary-declaration",
        "scan:redeclaration",
        "scan:no-key-transfer",
        "scan:later-spend-without-unit",
        "scan:unsupported-token-path",
        "scan:decoder-items-bound",
        "scan:decoder-script-bound",
        "scan:decoder-witness-bound",
        "scan:decoder-allocation-bound",
        "scan:decoder-truncated-block",
    ];
    let mut executed = Vec::new();
    for descriptor in scan_rows {
        let id = descriptor["id"].as_str().unwrap();
        let scenario = descriptor["scenario"].as_str().unwrap();
        let actual = match scenario {
            "retirement-same" => {
                let actual = project_retirements(&path, &[], 0, 3).unwrap();
                if actual.len() == 3 {
                    "StartingSetUnchanged"
                } else {
                    "WrongSet"
                }
            }
            "retirement-next" => {
                let next = [RetirementRequest {
                    epoch: 0,
                    point: [2; 32],
                }];
                let originals = [OriginalEpoch {
                    epoch: 0,
                    path: &path,
                    requests: &next,
                }];
                let actual = project_retirements(&path, &originals, 1, 3).unwrap();
                if actual == [KeyHash([8; 32]), KeyHash([9; 32])] {
                    "NextEpochRetirement"
                } else {
                    "WrongSet"
                }
            }
            "retirement-maximum" => {
                let actual = project_retirements(&path, &original, 1, 3).unwrap();
                if actual == [KeyHash([9; 32])] {
                    "MaximumRetained"
                } else {
                    "WrongSet"
                }
            }
            "retirement-no-effect" => {
                let no_effect = [RetirementRequest {
                    epoch: 0,
                    point: [99; 32],
                }];
                let originals = [OriginalEpoch {
                    epoch: 0,
                    path: &path,
                    requests: &no_effect,
                }];
                let actual = project_retirements(&path, &originals, 1, 3).unwrap();
                if actual.len() == 3 { "NeverActivated" } else { "WrongSet" }
            }
            "retirement-boundary-declaration" => {
                let next = [RetirementRequest {
                    epoch: 0,
                    point: [2; 32],
                }];
                let originals = [OriginalEpoch {
                    epoch: 0,
                    path: &path,
                    requests: &next,
                }];
                let active = project_retirements(&path, &originals, 1, 3).unwrap();
                if active.contains(&KeyHash([8; 32])) {
                    "Included"
                } else {
                    "WrongSet"
                }
            }
            "retirement-redeclaration" => {
                let mut continued = path.clone();
                continued[1].keys.clear();
                continued[2].keys = vec![KeyHash([8; 32])];
                let next = [RetirementRequest {
                    epoch: 0,
                    point: [2; 32],
                }];
                let originals = [OriginalEpoch {
                    epoch: 0,
                    path: &continued,
                    requests: &next,
                }];
                let active = project_retirements(&continued, &originals, 1, 3).unwrap();
                if active == [KeyHash([8; 32])] {
                    "MembershipRestored"
                } else {
                    "WrongSet"
                }
            }
            "wrong-issuance" => {
                let mut wrong_part = parts[0].clone();
                wrong_part.issuance.issuance_prevout[0] ^= 1;
                let wrong_parts = [wrong_part];
                let adapter = SuppliedAccountConsumer::new(
                    &selected,
                    &account,
                    &wrong_parts,
                    &originals,
                    fee_asset,
                    decoder_limits(),
                    token_limits(),
                    limits,
                );
                match adapter.authority_set(&account, &wrong_parts[0]) {
                    ConsumerResult::Refused(value) if value.value == pn_epoch::authentication::Refusal::Qualification => {
                        "RefusedQualification"
                    }
                    _ => "WrongResult",
                }
            }
            "later-spend-omitted" => {
                let result = scan_account(AccountScan {
                    first_height: 5,
                    pin_height: 6,
                    buffer: 0,
                    blocks: &omitted.blocks,
                    parts: &scan_parts,
                    run,
                    fee_asset,
                    decoder: decoder_limits(),
                    token: token_limits(),
                    limits: omitted_limits,
                });
                if matches!(result, Err(pn_wallet::token::history::ScanError::UnsupportedPath)) {
                    "LocalUnavailable"
                } else {
                    "WrongResult"
                }
            }
            "decoder-items" | "decoder-script" | "decoder-witness" | "decoder-allocation" | "decoder-truncated" => {
                let mut decoder = decoder_limits();
                let mut candidate = account.clone();
                match scenario {
                    "decoder-items" => decoder.items = 1,
                    "decoder-script" => decoder.script = 1,
                    "decoder-witness" => decoder.witness = 1,
                    "decoder-allocation" => decoder.allocation = 1,
                    "decoder-truncated" => {
                        candidate.blocks[0].pop();
                    }
                    _ => unreachable!(),
                }
                let decoded = decode_block(&candidate.blocks[0], decoder).unwrap_err();
                let expected_cause = match scenario {
                    "decoder-items" => pn_wallet::Refusal::Items,
                    "decoder-script" => pn_wallet::Refusal::Script,
                    "decoder-witness" => pn_wallet::Refusal::Witness,
                    "decoder-allocation" => pn_wallet::Refusal::Allocation,
                    "decoder-truncated" => pn_wallet::Refusal::Truncated,
                    _ => unreachable!(),
                };
                assert_eq!(decoded, expected_cause, "{id}");
                let adapter = SuppliedAccountConsumer::new(
                    &selected,
                    &candidate,
                    &parts,
                    &originals,
                    fee_asset,
                    decoder,
                    token_limits(),
                    limits,
                );
                match adapter.authority_set(&candidate, &parts[0]) {
                    ConsumerResult::Unavailable(value) if value.value == Inability::UnavailableBudget => "UnavailableBudget",
                    ConsumerResult::Unavailable(value) if value.value == Inability::UnavailableEvaluation => "LocalUnavailable",
                    _ => "WrongResult",
                }
            }
            _ => {
                let (candidate, bound) = match scenario {
                    "base" => (&account, limits),
                    "declaration-under" => (
                        &account,
                        HistoryLimits {
                            declaration_outputs: 0,
                            ..limits
                        },
                    ),
                    "history-byte-under" => (
                        &account,
                        HistoryLimits {
                            history_bytes: transaction_length - 1,
                            ..limits
                        },
                    ),
                    "history-transaction-under" => (
                        &account,
                        HistoryLimits {
                            history_transactions: 0,
                            ..limits
                        },
                    ),
                    "active-under" => (
                        &account,
                        HistoryLimits {
                            active_entries: 0,
                            ..limits
                        },
                    ),
                    "scan-block-under" => (
                        &account,
                        HistoryLimits {
                            scan_blocks: 0,
                            ..limits
                        },
                    ),
                    "scan-byte-under" => (&account, too_small),
                    "unrelated-transaction" => (&two_transactions, under_transactions),
                    "duplicate-keys" => (
                        &duplicate_account,
                        HistoryLimits {
                            scan_bytes: duplicate_account.blocks[0].len(),
                            ..limits
                        },
                    ),
                    "malformed-neighbor" => (
                        &malformed_account,
                        HistoryLimits {
                            scan_bytes: malformed_account.blocks[0].len(),
                            ..limits
                        },
                    ),
                    "buffer-only" => (&buffered, limits),
                    "no-key-transfer" => (&transferred, transfer_limits),
                    "unsupported-token-path" => (&unsupported, unsupported_limits),
                    "missing-block" => {
                        let mut missing = transferred.clone();
                        missing.blocks.pop();
                        let outcome = SuppliedAccountConsumer::new(
                            &selected,
                            &missing,
                            &parts,
                            &originals,
                            fee_asset,
                            decoder_limits(),
                            token_limits(),
                            limits,
                        )
                        .authority_set(&missing, &parts[0]);
                        let actual = match outcome {
                            ConsumerResult::Refused(value)
                                if value.value == pn_epoch::authentication::Refusal::MissingEvidence =>
                            {
                                "RefusedMissingEvidence"
                            }
                            _ => "WrongResult",
                        };
                        assert_eq!(actual, descriptor["expected"].as_str().unwrap(), "{id}");
                        executed.push(id);
                        continue;
                    }
                    _ => panic!("unknown scan descriptor {id}"),
                };
                let adapter = SuppliedAccountConsumer::new(
                    &selected,
                    candidate,
                    &parts,
                    &originals,
                    fee_asset,
                    decoder_limits(),
                    token_limits(),
                    bound,
                );
                match adapter.authority_set(candidate, &parts[0]) {
                    ConsumerResult::Confirmed(value) if value.value.keys == [KeyHash([7; 32]).0] => "ConfirmedKey",
                    ConsumerResult::Confirmed(value) if value.value.keys.is_empty() => "ConfirmedEmpty",
                    ConsumerResult::Unavailable(value) if value.value == Inability::UnavailableBudget => "UnavailableBudget",
                    ConsumerResult::Unavailable(value) if value.value == Inability::UnavailableEvaluation => "LocalUnavailable",
                    ConsumerResult::Refused(value) if value.value == pn_epoch::authentication::Refusal::MissingEvidence => {
                        "RefusedMissingEvidence"
                    }
                    _ => "WrongResult",
                }
            }
        };
        assert_eq!(actual, descriptor["expected"].as_str().unwrap(), "{id}");
        executed.push(id);
    }
    assert_eq!(executed, expected_ids);
}

/// Claim: A selected complete-scan ceiling refuses before unreadable block bytes are decoded.
/// ´claim:publication:account-scan-ceiling´
/// ´test:integration:account-scan-ceiling´
#[test]
fn account_scan_ceiling() {
    let blocks = [vec![0xff]];
    let parts = [ScanPart {
        actor: "actor",
        height: 1,
        transaction_index: 0,
        input_index: 0,
        issuance_prevout: [0; 36],
    }];
    let limits = HistoryLimits {
        declaration_outputs: 1,
        history_bytes: 1,
        history_transactions: 1,
        active_entries: 1,
        scan_blocks: 0,
        scan_bytes: 1,
    };
    let result = scan_account(AccountScan {
        first_height: 1,
        pin_height: 1,
        buffer: 0,
        blocks: &blocks,
        parts: &parts,
        run: [0; 32],
        fee_asset: AssetId([0; 32]),
        decoder: decoder_limits(),
        token: token_limits(),
        limits,
    });
    assert_eq!(result, Err(pn_wallet::token::history::ScanError::Budget));
}

/// Claim: Earlier retirement fields use the maximum effective point of their original path.
/// ´claim:publication:retirement-path-maximum´
/// ´test:integration:retirement-path-maximum´
#[test]
fn retirement_path_maximum() {
    let path = [
        PathStep {
            height: 1,
            transaction_index: 0,
            txid: [1; 32],
            keys: vec![KeyHash([1; 32])],
        },
        PathStep {
            height: 2,
            transaction_index: 0,
            txid: [2; 32],
            keys: vec![KeyHash([2; 32])],
        },
        PathStep {
            height: 3,
            transaction_index: 0,
            txid: [3; 32],
            keys: vec![KeyHash([3; 32])],
        },
    ];
    let requests = [
        RetirementRequest {
            epoch: 0,
            point: [3; 32],
        },
        RetirementRequest {
            epoch: 0,
            point: [2; 32],
        },
    ];
    let originals = [OriginalEpoch {
        epoch: 0,
        path: &path,
        requests: &requests,
    }];
    assert_eq!(project_retirements(&path, &originals, 1, 3), Ok(vec![KeyHash([3; 32])]));
}
