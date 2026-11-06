//! Joined deterministic compiler retaining published or candidate cause authority.
//! (´def:compiler:joined-state´)

use crate::{
    base::{BaseAllocation, compile_base},
    cells::{CellIdentity, StandingCell},
    coefficients::{CoefficientError, coefficient},
    ledger::{FinalLedger, LedgerError, compile_ledger},
    package::{CandidateContext, VerifiedPackage},
    recipients::{ResolvedCell, resolve_recipients},
    support::compact::{StandingSupport, compile_support},
};
use nrz_cas::limits::Limits;
use pn_graph::registration::RegistrationVerifier;
use pn_records::numerics::NumericContext;
use std::collections::BTreeMap;

use super::{CoefficientEvidence, CompileError, CompiledSource};

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
    source: CompiledSource,
    view: CompiledView,
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
        source_item = "compiler::compact::compile_final_state"
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
    compile_source(
        CompiledSource::Published(package.clone()),
        verifier,
        numeric,
        limits,
        maximum_products,
    )
}

/// Compile checked proposed causes through the same structural and numerical derivation.
/// The retained source remains a candidate and supplies no publication authority.
/// (´[ROOT-alg:design:admission]´)
/// # Errors
/// Refuses any formation, ledger, support or bounded arithmetic defect atomically.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "compiler::compact::compile_candidate"
    ),
    ret
)]
pub fn compile_candidate(
    candidate: &CandidateContext,
    verifier: &impl RegistrationVerifier,
    numeric: &mut NumericContext,
    limits: Limits,
    maximum_products: u64,
) -> Result<CompiledState, CompileError> {
    compile_source(
        CompiledSource::Candidate(candidate.clone()),
        verifier,
        numeric,
        limits,
        maximum_products,
    )
}

fn compile_source(
    package: CompiledSource,
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
        source: package,
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
    /// Borrow the checked source prefix and its publication or candidate authority.
    /// (´def:compiler:joined-state´)
    /// Justified: Immutable access inherits the joined compiler operation.
    #[must_use]
    pub fn package(&self) -> &CompiledSource {
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

/// Compile a locally admitted boundary without asserting external publication.
/// (´rule:admission:semantic-carrier´)
/// # Errors
/// Refuses any changed formation, charge or bounded derivation.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "compiler::compact::compile_admitted"
    ),
    ret
)]
pub fn compile_admitted(
    admitted: &crate::package::AdmittedBoundary,
    verifier: &impl RegistrationVerifier,
    numeric: &mut NumericContext,
    limits: Limits,
    maximum_products: u64,
) -> Result<CompiledState, CompileError> {
    compile_source(
        CompiledSource::Admitted(Box::new(admitted.clone())),
        verifier,
        numeric,
        limits,
        maximum_products,
    )
}
