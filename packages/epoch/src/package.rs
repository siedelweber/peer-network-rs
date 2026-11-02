//! Shared cause coherence with separate candidate and published verification.
//! (´def:compiler:completed-package´)

use crate::CompilerInputs;
use pn_records::{
    ValidatedAct, ValidatedHistory,
    burn::{Marker, RecognizedMarkers},
    numerics::ChargedPrice,
};

/// One epoch's explicit package binding, separate from the marker's burn acceptance.
/// (´def:compiler:completed-package´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochBinding {
    pub marker: Marker,
    pub predecessor: Marker,
    pub inputs: CompilerInputs,
    pub price: ChargedPrice,
    /// Full immutable acts in asserted position order; publication is verified separately.
    pub sequence: Vec<ValidatedAct>,
}

/// Untrusted full-prefix package; no independently asserted balance is accepted.
/// (´def:compiler:completed-package´)
#[derive(Clone, Debug)]
pub struct PackageInput {
    pub markers: RecognizedMarkers,
    pub history: ValidatedHistory,
    pub inputs: Vec<CompilerInputs>,
    pub prices: Vec<ChargedPrice>,
    pub bindings: Vec<EpochBinding>,
}

/// Public verification of the published ties, beyond equality of supplied components.
/// (´def:compiler:completed-package´)
/// Implementations must deterministically establish that this complete package is the
/// published one: settled marker lineage and evidence, accepted write sequences,
/// effective constants and writing prices, and predecessor completed-state bindings.
/// Equality checks alone or an unconditional mock do not establish those facts.
/// No canonical package bytes or digest are defined here: bite 8 owns that boundary
/// under record 006's identity gate. An implementation requiring a new recipe must
/// admit it there before it can establish this contract.
pub trait PackageVerifier: std::fmt::Debug {
    fn published_package(&self, input: &PackageInput) -> bool;
}

/// Frozen package, constructible only by the verification operation.
/// (´def:compiler:completed-package´)
#[derive(Clone, Debug)]
pub struct VerifiedPackage {
    input: PackageInput,
}

/// Structural coherence refusals precede public binding verification.
/// (´def:compiler:completed-package´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackageError {
    #[error("package components belong to different marker histories")]
    History,
    #[error("package mixes marker policy identities or editions")]
    Policy,
    #[error("package drops or substitutes the preceding marker or epoch")]
    Predecessor,
    #[error("package constants differ from the bound effective inputs")]
    Constants,
    #[error("package write sequence differs from the validated history")]
    Sequence,
    #[error("package epochs and markers are not aligned one to one")]
    Alignment,
    #[error("package substitutes the writing epoch's debit vintage")]
    Vintage,
    #[error("public verification does not establish the package binding")]
    Binding,
    #[error("candidate verification does not establish the proposed causes")]
    CandidateBinding,
    #[error("closure declaration or attestation is invalid")]
    Closure,
}

/// Verify the structural prefix and its published coherence before compilation.
/// (´[ROOT-dec:design:final-state]´)
/// # Errors
/// Returns the first named coherence defect or failed public verification.
#[tracing::instrument(
    name = "dec:design:final-state",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "dec:design:final-state",
        source_item = "package::verify_package"
    ),
    ret
)]
pub fn verify_package(input: PackageInput, verifier: &impl PackageVerifier) -> Result<VerifiedPackage, PackageError> {
    verify_causes(&input)?;
    if !verifier.published_package(&input) {
        return Err(PackageError::Binding);
    }
    Ok(VerifiedPackage { input })
}

impl VerifiedPackage {
    /// Borrow the checked complete prefix; no mutable access escapes verification.
    /// (´def:compiler:completed-package´)
    /// Justified: Immutable access preserves the enclosing verification result.
    #[must_use]
    pub fn input(&self) -> &PackageInput {
        &self.input
    }
}

/// Check common cause coherence without asserting candidate or publication authority.
/// (´[ROOT-amend:design:candidate-admission-boundary]´)
fn verify_causes(input: &PackageInput) -> Result<(), PackageError> {
    let count = input.bindings.len();
    let markers = input.markers.markers();
    if count == 0 || input.inputs.len() != count || input.prices.len() != count || markers.len() <= count {
        return Err(PackageError::Alignment);
    }
    let last = u64::try_from(count).map_err(|_| PackageError::Alignment)?;
    if input.history.acts().iter().any(|act| act.position().0 > last) {
        return Err(PackageError::Sequence);
    }
    let basis = input.markers.basis();
    for (offset, binding) in input.bindings.iter().enumerate() {
        let boundary = u64::try_from(offset).map_err(|_| PackageError::Alignment)? + 1;
        if binding.marker.history != basis.history || binding.predecessor.history != basis.history {
            return Err(PackageError::History);
        }
        if [&binding.marker, &binding.predecessor]
            .iter()
            .any(|marker| marker.policy_identity != basis.policy_identity || marker.policy_edition != basis.policy_edition)
        {
            return Err(PackageError::Policy);
        }
        if binding.marker.index != boundary || input.inputs[offset].parameters().boundary != boundary {
            return Err(PackageError::Alignment);
        }
        if binding.predecessor != *markers[offset].identity() {
            return Err(PackageError::Predecessor);
        }
        if binding.marker != *markers[offset + 1].identity() {
            return Err(PackageError::Alignment);
        }
        if binding.inputs != input.inputs[offset] {
            return Err(PackageError::Constants);
        }
        if binding.price != input.prices[offset] {
            return Err(PackageError::Vintage);
        }
        let mut sequence: Vec<_> = input
            .history
            .acts()
            .iter()
            .filter(|act| act.position().0 == boundary)
            .collect();
        sequence.sort_by_key(|act| act.position());
        if !sequence.into_iter().eq(binding.sequence.iter()) {
            return Err(PackageError::Sequence);
        }
    }
    Ok(())
}

/// Published closure conditions measured in the explicitly named clock's ticks.
/// (´[ROOT-amend:design:candidate-admission-boundary]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosurePolicy {
    pub target: u64,
    pub minimum_ticks: u64,
    pub maximum_ticks: u64,
    pub clock: String,
}

/// The attested condition under which the candidate boundary closes.
/// (´[ROOT-amend:design:candidate-admission-boundary]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosureCause {
    TargetAfterMinimum,
    MaximumDuration,
}

/// Public assertion, whose earliest-host-determination premise needs a verifier.
/// (´[ROOT-amend:design:candidate-admission-boundary]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosureStatement {
    pub policy: ClosurePolicy,
    pub opened_at: u64,
    pub determined_at: u64,
    pub cause: ClosureCause,
    pub attestation: String,
}

/// Proposed complete prefix, without an assertion that its last write is published.
/// (´[ROOT-amend:design:candidate-admission-boundary]´)
#[derive(Clone, Debug)]
pub struct CandidateInput {
    pub causes: PackageInput,
    pub closure: ClosureStatement,
}

/// Establish the finalized predecessor and the complete proposed causes independently.
/// The current sequence is proposed; this method must not assume its publication.
/// Approval, marker evidence, constants and price declarations require their declared
/// public verification. Equality with unchecked caller assertions is insufficient.
/// (´[ROOT-amend:design:candidate-admission-boundary]´)
pub trait CandidateVerifier: std::fmt::Debug {
    fn candidate_causes(&self, input: &CandidateInput) -> bool;
}

/// Verify the published policy and its attested earliest host determination for this
/// exact candidate. Timestamps and structural duration checks alone are insufficient.
/// (´[ROOT-amend:design:candidate-admission-boundary]´)
pub trait ClosureVerifier: std::fmt::Debug {
    fn host_determination(&self, input: &CandidateInput) -> bool;
}

/// Checked candidate context, neither a published package nor an admitted result.
/// (´[ROOT-amend:design:candidate-admission-boundary]´)
/// ```compile_fail
/// fn publish(candidate: pn_epoch::package::CandidateContext, verifier: &impl pn_epoch::package::PackageVerifier) {
///     pn_epoch::package::verify_package(candidate, verifier);
/// }
/// ```
#[derive(Clone, Debug)]
pub struct CandidateContext {
    input: CandidateInput,
}

/// Immutable admitted boundary constructed only after every final gate passes.
/// (´[ROOT-inv:design:atomic-admission]´)
/// ```compile_fail
/// fn admit(candidate: pn_epoch::package::CandidateContext, evidence: pn_epoch::admission::FinalEvidence) -> pn_epoch::package::AdmittedBoundary {
///     pn_epoch::package::AdmittedBoundary { candidate, evidence }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct AdmittedBoundary {
    candidate: CandidateContext,
    evidence: crate::admission::FinalEvidence,
}

/// Validate candidate coherence and independent cause/closure premises, not final gates.
/// (´[ROOT-alg:design:admission]´)
/// # Errors
/// Returns the shared cause defect, invalid closure condition or either verifier refusal.
#[tracing::instrument(
    name = "alg:design:admission",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "alg:design:admission",
        source_item = "package::verify_candidate"
    ),
    ret
)]
pub fn verify_candidate(
    input: CandidateInput,
    causes: &impl CandidateVerifier,
    closure: &impl ClosureVerifier,
) -> Result<CandidateContext, PackageError> {
    verify_causes(&input.causes)?;
    check_closure(&input)?;
    if !causes.candidate_causes(&input) {
        return Err(PackageError::CandidateBinding);
    }
    if !closure.host_determination(&input) {
        return Err(PackageError::Closure);
    }
    Ok(CandidateContext { input })
}

/// Check only computable declared closure conditions; a verifier supplies earliestness.
/// (´[ROOT-amend:design:candidate-admission-boundary]´)
fn check_closure(input: &CandidateInput) -> Result<(), PackageError> {
    let statement = &input.closure;
    let policy = &statement.policy;
    let elapsed = statement
        .determined_at
        .checked_sub(statement.opened_at)
        .ok_or(PackageError::Closure)?;
    let last = input.causes.bindings.last().ok_or(PackageError::Alignment)?;
    let count = u64::try_from(last.sequence.len()).map_err(|_| PackageError::Closure)?;
    if policy.target == 0
        || policy.maximum_ticks == 0
        || policy.minimum_ticks > policy.maximum_ticks
        || policy.clock.is_empty()
        || statement.attestation.is_empty()
        || count > policy.target
    {
        return Err(PackageError::Closure);
    }
    let condition = match statement.cause {
        ClosureCause::TargetAfterMinimum => count == policy.target && elapsed >= policy.minimum_ticks,
        ClosureCause::MaximumDuration => elapsed >= policy.maximum_ticks,
    };
    if !condition {
        return Err(PackageError::Closure);
    }
    Ok(())
}

impl CandidateContext {
    /// Borrow proposed causes; this access carries no publication or admission authority.
    /// (´[ROOT-amend:design:candidate-admission-boundary]´)
    /// Justified: Immutable field access retains candidate verification without promotion.
    #[must_use]
    pub fn input(&self) -> &CandidateInput {
        &self.input
    }
}

impl AdmittedBoundary {
    pub(crate) fn checked(candidate: CandidateContext, evidence: crate::admission::FinalEvidence) -> Self {
        Self { candidate, evidence }
    }

    /// Borrow the final gate evidence without changing the admitted result.
    /// (´[ROOT-inv:design:atomic-admission]´)
    /// Justified: Immutable field access inherits the complete admission operation.
    #[must_use]
    pub fn evidence(&self) -> &crate::admission::FinalEvidence {
        &self.evidence
    }
    /// Borrow the admitted result's candidate without a mutable or constructing path.
    /// (´[ROOT-inv:design:atomic-admission]´)
    /// Justified: Immutable field access does not create an admitted result.
    #[must_use]
    pub fn candidate(&self) -> &CandidateContext {
        &self.candidate
    }
}

// Compare the complete admitted predecessor, allowing later recognized markers only.
pub(crate) fn same_prefix(earlier: &PackageInput, later: &PackageInput) -> bool {
    let n = earlier.bindings.len();
    earlier.markers.basis() == later.markers.basis()
        && later.bindings.get(..n) == Some(earlier.bindings.as_slice())
        && later.markers.markers().get(..=n) == earlier.markers.markers().get(..=n)
}
