//! Joined deterministic compiler over a verified completed package.
//! (´def:compiler:joined-state´)

use crate::{
    base::{BaseAllocation, BaseError, compile_base},
    cells::{CellIdentity, StandingCell},
    coefficients::{CoefficientError, coefficient},
    ledger::{FinalLedger, LedgerError, compile_ledger},
    package::VerifiedPackage,
    recipients::{RecipientError, ResolvedCell, resolve_recipients},
    support::{StandingSupport, SupportError, compile_support},
};
use nrz_cas::limits::Limits;
use pn_graph::registration::RegistrationVerifier;
use pn_records::numerics::NumericContext;
use std::collections::BTreeMap;

/// Exact cell magnitude or its retained numeric-evidence hold.
/// (´def:compiler:joined-state´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoefficientEvidence {
    Exact(String),
    Irrational { radicand: String },
}

/// Public immutable compilation view; no independently supplied intermediate results.
/// (´def:compiler:joined-state´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledView {
    pub title: pn_graph::title::TitleReplay,
    pub ledger: FinalLedger,
    pub cells: Vec<StandingCell>,
    pub coefficients: BTreeMap<CellIdentity, CoefficientEvidence>,
    pub recipients: Vec<ResolvedCell>,
    pub base: BaseAllocation,
    pub support: StandingSupport,
}

/// Frozen joined output, not an admitted epoch or a persistence capability.
/// (´def:compiler:joined-state´)
#[derive(Clone, Debug)]
pub struct CompiledState {
    source: VerifiedPackage,
    view: CompiledView,
}

/// Whole-result refusal; no partial compiled state escapes.
/// (´def:compiler:joined-state´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    #[error("verified package has no completed boundary")]
    Boundary,
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    #[error("recipients: {0}")]
    Recipients(#[from] RecipientError),
    #[error("title: {0}")]
    Title(#[from] pn_graph::recognition::RecognitionError),
    #[error("coefficient: {0}")]
    Coefficient(#[from] CoefficientError),
    #[error("base: {0}")]
    Base(#[from] BaseError),
    #[error("support: {0}")]
    Support(#[from] SupportError),
}

/// Derive every compiler output from the same verified package and writing vintages.
/// (´[ROOT-sig:design:epoch]´)
/// The public formation verifier must be deterministic. This computes no equilibrium,
/// certificate admission, next price or storage write. Irrational magnitudes remain holds.
/// # Errors
/// Refuses the complete result if any constituent derivation or resource bound refuses.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "compiler::compile_final_state"
    ),
    ret
)]
pub fn compile_final_state(
    package: &VerifiedPackage,
    verifier: &impl RegistrationVerifier,
    numeric: &mut NumericContext,
    limits: Limits,
    maximum_products: u64,
) -> Result<CompiledState, CompileError> {
    let source = package.input();
    let inputs = source.inputs.last().ok_or(CompileError::Boundary)?;
    let price = source.prices.last().ok_or(CompileError::Boundary)?;
    let ledger = compile_ledger(
        &source.inputs,
        &source.prices,
        &source.markers,
        &source.history,
        verifier,
        numeric,
        limits.clone(),
    )?;
    let graph = pn_graph::formation::reconstruct_replay(&source.history, verifier).map_err(LedgerError::Formation)?;
    let title = pn_graph::title::replay_title(&graph, &source.history, verifier, inputs.parameters().boundary)?;
    let recipients = resolve_recipients(&source.history, inputs.parameters().boundary, verifier, limits.clone())?;
    let cells: Vec<_> = recipients.iter().map(|row| row.cell.clone()).collect();
    let mut coefficients = BTreeMap::new();
    for cell in &cells {
        let evidence = match coefficient(cell, limits.clone()) {
            Ok(value) => CoefficientEvidence::Exact(value),
            Err(CoefficientError::Irrational { radicand }) => CoefficientEvidence::Irrational { radicand },
            Err(error) => return Err(error.into()),
        };
        coefficients.insert(cell.identity.clone(), evidence);
    }
    let base = compile_base(inputs, &source.history, verifier, limits.clone())?;
    let support = compile_support(inputs, price, &ledger, &base, numeric, limits, maximum_products)?;
    Ok(CompiledState {
        source: package.clone(),
        view: CompiledView {
            title,
            ledger,
            cells,
            coefficients,
            recipients,
            base,
            support,
        },
    })
}

impl CompiledState {
    /// Borrow the verified source prefix retained with every compiled result.
    /// (´def:compiler:joined-state´)
    /// Justified: Immutable access inherits the joined compiler operation.
    #[must_use]
    pub fn package(&self) -> &VerifiedPackage {
        &self.source
    }

    /// Borrow all joined outputs without permitting mutation of the frozen state.
    /// (´def:compiler:joined-state´)
    /// Justified: Immutable access inherits the joined compiler operation.
    #[must_use]
    pub fn view(&self) -> &CompiledView {
        &self.view
    }
}
