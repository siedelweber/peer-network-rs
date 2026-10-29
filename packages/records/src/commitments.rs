//! Typed retained residues, with no encoding, hash or authenticity decision.
//! (´def:acts:commitment-residues´)

/// Actor proposal residue; exact recipe identity travels with its bytes.
/// (´def:acts:commitment-residues´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalCommitment {
    /// Immutable recipe identifier, interpreted only by its profile.
    pub recipe: String,
    /// Opaque public residue, not evidence of its producer.
    pub bytes: [u8; 32],
}

/// Independently removable content's retained residue.
/// (´def:acts:commitment-residues´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentCommitment {
    /// Immutable recipe identifier.
    pub recipe: String,
    /// Opaque public residue, retained after content reduction.
    pub bytes: [u8; 32],
}

/// Independently removable dependency set's retained residue.
/// (´def:acts:commitment-residues´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyCommitment {
    /// Immutable recipe identifier.
    pub recipe: String,
    /// Opaque public residue, retained after dependency tombstoning.
    pub bytes: [u8; 32],
}

/// Three distinct public residues kept outside the removable projections.
/// Absence on an internal candidate does not manufacture an anchor.
/// (´def:acts:commitment-residues´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActCommitments {
    /// Actor-owned proposal commitment.
    pub proposal: ProposalCommitment,
    /// Host-owned content commitment.
    pub content: ContentCommitment,
    /// Host-owned dependency commitment.
    pub dependency: DependencyCommitment,
}

/// Refusal of supplied opening evidence, never a refusal of retained history.
/// (´def:acts:opening-evidence´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpeningError {
    /// The evidence target is absent, repeated or not tombstoned.
    #[error("opening target is not a unique retained tombstone")]
    Target,
    /// No supported recorded anchor was supplied.
    #[error("opening has no supported retained anchor")]
    Anchor,
    /// The opening's shape or bounds are invalid.
    #[error("opening representation is invalid")]
    Representation,
    /// The supplied bytes do not match the supplied recorded anchor.
    #[error("opening does not match the supplied commitment")]
    Mismatch,
    /// The opened representation is refused independently of placement faults.
    #[error("opened history representation is invalid")]
    History,
}

/// Caller-supplied pure commitment checker, separate from anchor authentication.
/// The shared profile implements this boundary; records supplies the retained
/// act so an opener cannot silently substitute its own anchor.
/// (´def:acts:opening-evidence´)
pub trait DependencyOpener: std::fmt::Debug {
    /// Exact targets for which this checker holds supplied opening evidence.
    fn targets(&self) -> Vec<crate::ActId>;
    /// Check this opening against this act's retained residues, then release
    /// the complete opened list for public fault assessment and replay.
    /// # Errors
    /// Refuses absent anchors and malformed or mismatched supplied evidence.
    fn open(&self, act: &crate::ValidatedAct) -> Result<Vec<crate::ActId>, OpeningError>;
}
