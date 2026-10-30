//! Structural completed-package verification, without a publication encoding.
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
    /// Full immutable acts in published position order, including all projection evidence.
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
