//! Conditional development-network account scan over supplied public layouts.
//! The caller still selects and establishes binding, signed-chain and role premises.
//! (´[ROOT-amend:identity:authority-account]´)

use std::fmt;
use std::sync::OnceLock;

use pn_act_authentication::AssetId;
use pn_epoch::authentication::{
    AccountPin, ActorPart, Assessed, AssessmentPremises, AuthorityAccount, AuthorizedKeysWithPremises, BoundaryConsumer,
    BoundaryContext, ConsumerResult, Inability, PaperCaseBoundary, PaperHistory, PriorRange, Refusal, RetainedIdentity, Role,
};
use pn_records::cases::{ComponentRef, LocalAuthorityDeclaration, PaperCaseDeclaration};
use pn_records::closure::{ClosureAct, ClosureHeader};
use pn_wallet::Limits;
use pn_wallet::token::TokenLimits;
use pn_wallet::token::history::{
    AccountScan, ActorHistory, HistoryLimits, OriginalEpoch, RetirementRequest, ScanError, ScanPart, project_retirements,
    qualify_account, scan_account,
};

/// One complete original-epoch account, with retirement fields from retained acts.
#[derive(Debug)]
pub struct OriginalAccountEpoch<'a> {
    pub epoch: u64,
    pub account: &'a AuthorityAccount,
    pub parts: &'a [ActorPart],
    pub requests: &'a [RetirementRequest],
}

/// Original-epoch accounts for one Actor, supplied with their record-binding premise.
#[derive(Debug)]
pub struct ActorOriginalEpochs<'a> {
    pub actor: &'a str,
    pub epochs: &'a [OriginalAccountEpoch<'a>],
}

/// A selected pure consumer wrapped with a shared, lazy public-layout scan.
/// Debug intentionally excludes the wrapped consumer and any credentials it holds.
pub struct SuppliedAccountConsumer<'a, B> {
    pub selected: &'a B,
    pub account: &'a AuthorityAccount,
    pub parts: &'a [ActorPart],
    pub originals: &'a [ActorOriginalEpochs<'a>],
    pub fee_asset: AssetId,
    pub decoder_limits: Limits,
    pub token_limits: TokenLimits,
    pub history_limits: HistoryLimits,
    scan: OnceLock<Result<Vec<ActorHistory>, ScanError>>,
}

impl<B> fmt::Debug for SuppliedAccountConsumer<'_, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SuppliedAccountConsumer")
    }
}

impl<'a, B: BoundaryConsumer> SuppliedAccountConsumer<'a, B> {
    #[must_use]
    pub fn new(
        selected: &'a B,
        account: &'a AuthorityAccount,
        parts: &'a [ActorPart],
        originals: &'a [ActorOriginalEpochs<'a>],
        fee_asset: AssetId,
        decoder_limits: Limits,
        token_limits: TokenLimits,
        history_limits: HistoryLimits,
    ) -> Self {
        Self {
            selected,
            account,
            parts,
            originals,
            fee_asset,
            decoder_limits,
            token_limits,
            history_limits,
            scan: OnceLock::new(),
        }
    }

    fn scan_parts(parts: &[ActorPart]) -> Result<Vec<ScanPart<'_>>, ScanError> {
        let mut parts = parts
            .iter()
            .map(|part| {
                Ok(ScanPart {
                    actor: &part.actor,
                    height: part.issuance.height,
                    transaction_index: usize::try_from(part.issuance.transaction_index).map_err(|_| ScanError::Budget)?,
                    input_index: usize::try_from(part.issuance.input_index).map_err(|_| ScanError::Budget)?,
                    issuance_prevout: part.issuance.issuance_prevout,
                })
            })
            .collect::<Result<Vec<_>, ScanError>>()?;
        parts.sort_by(|left, right| left.actor.cmp(right.actor));
        Ok(parts)
    }

    fn scan_input<'b>(&self, account: &'b AuthorityAccount, parts: &'b [ScanPart<'b>]) -> AccountScan<'b> {
        AccountScan {
            first_height: account.first_height,
            pin_height: account.pin.height,
            buffer: account.pin.buffer,
            blocks: &account.blocks,
            parts,
            run: account.context.run,
            fee_asset: self.fee_asset,
            decoder: self.decoder_limits,
            token: self.token_limits,
            limits: self.history_limits,
        }
    }

    fn scan(&self, account: &AuthorityAccount) -> Result<&[ActorHistory], ScanError> {
        let scanned = self.scan.get_or_init(|| {
            let parts = Self::scan_parts(self.parts)?;
            scan_account(self.scan_input(account, &parts))
        });
        scanned.as_ref().map(Vec::as_slice).map_err(|cause| *cause)
    }

    fn assessed_error<T>(&self, cause: ScanError, premises: AssessmentPremises) -> ConsumerResult<T> {
        match cause {
            ScanError::Budget
            | ScanError::Decoder(
                pn_wallet::Refusal::Bytes
                | pn_wallet::Refusal::Allocation
                | pn_wallet::Refusal::Items
                | pn_wallet::Refusal::Script
                | pn_wallet::Refusal::Witness
                | pn_wallet::Refusal::Limits,
            ) => ConsumerResult::Unavailable(Assessed {
                value: Inability::UnavailableBudget,
                premises,
            }),
            ScanError::UnsupportedPath | ScanError::Decoder(pn_wallet::Refusal::Truncated) => {
                ConsumerResult::Unavailable(Assessed {
                    value: Inability::UnavailableEvaluation,
                    premises,
                })
            }
            ScanError::MissingEvidence => ConsumerResult::Refused(Assessed {
                value: Refusal::MissingEvidence,
                premises,
            }),
            ScanError::Qualification => ConsumerResult::Refused(Assessed {
                value: Refusal::Qualification,
                premises,
            }),
            ScanError::Actor => ConsumerResult::Refused(Assessed {
                value: Refusal::Actor,
                premises,
            }),
            ScanError::Path => ConsumerResult::Refused(Assessed {
                value: Refusal::Path,
                premises,
            }),
            ScanError::Token(_) => ConsumerResult::Unavailable(Assessed {
                value: Inability::UnavailableBudget,
                premises,
            }),
            ScanError::Decoder(_) => ConsumerResult::Refused(Assessed {
                value: Refusal::Chain,
                premises,
            }),
        }
    }
}

impl<B: BoundaryConsumer> BoundaryConsumer for SuppliedAccountConsumer<'_, B> {
    fn required_boundary_context(&self, candidate: &BoundaryContext) -> ConsumerResult<BoundaryContext> {
        self.selected.required_boundary_context(candidate)
    }
    fn paper_declaration_definition(
        &self,
        selected: &BoundaryContext,
        reference: &ComponentRef,
    ) -> ConsumerResult<PaperCaseDeclaration> {
        self.selected.paper_declaration_definition(selected, reference)
    }
    fn local_declaration_definition(&self, selected: &BoundaryContext) -> ConsumerResult<LocalAuthorityDeclaration> {
        self.selected.local_declaration_definition(selected)
    }
    fn paper_declaration_history(&self, candidate: &PaperCaseBoundary) -> ConsumerResult<PaperHistory> {
        self.selected.paper_declaration_history(candidate)
    }
    fn prior_epoch(&self, candidate: &PriorRange) -> ConsumerResult<()> {
        self.selected.prior_epoch(candidate)
    }
    fn compare_marker_prefix(&self, candidate: &AccountPin) -> ConsumerResult<()> {
        self.selected.compare_marker_prefix(candidate)
    }
    fn selected_chain_rules(&self, selected: &BoundaryContext) -> ConsumerResult<()> {
        self.selected.selected_chain_rules(selected)
    }
    fn compare_public_binding(&self, candidate: &AuthorityAccount) -> ConsumerResult<()> {
        self.selected.compare_public_binding(candidate)
    }
    fn evaluate_chain_evidence(&self, candidate: &AuthorityAccount) -> ConsumerResult<()> {
        self.selected.evaluate_chain_evidence(candidate)
    }
    fn qualified_first_height(&self, candidate: &AuthorityAccount) -> ConsumerResult<u64> {
        let selected = self.selected.qualified_first_height(candidate);
        let ConsumerResult::Confirmed(assessed) = selected else {
            return selected;
        };
        if candidate != self.account {
            return ConsumerResult::Unavailable(Assessed {
                value: Inability::UnavailableEvaluation,
                premises: assessed.premises,
            });
        }
        let parts = match Self::scan_parts(self.parts) {
            Ok(value) => value,
            Err(cause) => return self.assessed_error(cause, assessed.premises),
        };
        if let Err(cause) = qualify_account(&self.scan_input(candidate, &parts)) {
            return self.assessed_error(cause, assessed.premises);
        }
        ConsumerResult::Confirmed(assessed)
    }
    fn compare_retained_act<H: ClosureHeader>(&self, candidate: &ClosureAct<H>) -> ConsumerResult<RetainedIdentity> {
        self.selected.compare_retained_act(candidate)
    }
    fn verify_recorded_role<H: ClosureHeader>(&self, candidate: &ClosureAct<H>, role: Role) -> ConsumerResult<()> {
        self.selected.verify_recorded_role(candidate, role)
    }
    #[tracing::instrument(
        name = "amend:identity:authority-account",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "amend:identity:authority-account",
            operation = "authority-supplied-account-set",
            source_item = "authority::SuppliedAccountConsumer::authority_set"
        ),
        ret
    )]
    fn authority_set(&self, account: &AuthorityAccount, part: &ActorPart) -> ConsumerResult<AuthorizedKeysWithPremises> {
        let context = match self.selected.required_boundary_context(&account.context) {
            ConsumerResult::Confirmed(context) => context,
            ConsumerResult::Refused(value) => return ConsumerResult::Refused(value),
            ConsumerResult::Unavailable(value) => return ConsumerResult::Unavailable(value),
        };
        let premises = context.premises;
        if context.value != account.context {
            return ConsumerResult::Refused(Assessed {
                value: Refusal::Context,
                premises,
            });
        }
        if account != self.account {
            return ConsumerResult::Unavailable(Assessed {
                value: Inability::UnavailableEvaluation,
                premises,
            });
        }
        let histories = match self.scan(account) {
            Ok(value) => value,
            Err(cause) => return self.assessed_error(cause, premises),
        };
        if !self.parts.contains(part) {
            return ConsumerResult::Unavailable(Assessed {
                value: Inability::NotCovered,
                premises,
            });
        }
        let Some(history) = histories.iter().find(|history| history.actor == part.actor) else {
            return ConsumerResult::Unavailable(Assessed {
                value: Inability::NotCovered,
                premises,
            });
        };
        let originals = match self.originals.iter().find(|original| original.actor == part.actor) {
            Some(value) => value.epochs,
            None if account.context.epoch == 0 => &[],
            None => {
                return ConsumerResult::Refused(Assessed {
                    value: Refusal::MissingEvidence,
                    premises,
                });
            }
        };
        let mut original_histories = Vec::new();
        for original in originals {
            if original.account.context.epoch != original.epoch
                || original.account.context.run != account.context.run
                || original.account.context.history_scope != account.context.history_scope
            {
                return self.assessed_error(ScanError::MissingEvidence, premises);
            }
            let parts = match Self::scan_parts(original.parts) {
                Ok(value) => value,
                Err(cause) => return self.assessed_error(cause, premises),
            };
            let histories = match scan_account(self.scan_input(original.account, &parts)) {
                Ok(value) => value,
                Err(cause) => return self.assessed_error(cause, premises),
            };
            let Some(history) = histories.into_iter().find(|candidate| candidate.actor == part.actor) else {
                return ConsumerResult::Unavailable(Assessed {
                    value: Inability::NotCovered,
                    premises,
                });
            };
            original_histories.push(history);
        }
        let original_paths = originals
            .iter()
            .zip(&original_histories)
            .map(|(original, history)| OriginalEpoch {
                epoch: original.epoch,
                path: &history.path,
                requests: original.requests,
            })
            .collect::<Vec<_>>();
        let active = match project_retirements(
            &history.path,
            &original_paths,
            account.context.epoch,
            self.history_limits.active_entries,
        ) {
            Ok(value) => value,
            Err(cause) => return self.assessed_error(cause, premises),
        };
        ConsumerResult::Confirmed(Assessed {
            value: AuthorizedKeysWithPremises {
                actor: part.actor.clone(),
                keys: active.into_iter().map(|key| key.0).collect(),
                pin: account.pin.clone(),
            },
            premises,
        })
    }
    fn evaluate_case(&self, declaration: &PaperCaseDeclaration) -> ConsumerResult<()> {
        self.selected.evaluate_case(declaration)
    }
}
