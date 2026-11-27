//! Pure successor marker payloads and judgement over supplied facts.
//! (´[ROOT-amend:identity:marker-static-admission]´)

/// The fixed test namespace of the successor marker payload.
pub const MARKER_NAMESPACE: &str = "o.pn.t.m";

/// Constructed major-one marker payload, with its complete unsigned stamp.
/// The fixed namespace is `MARKER_NAMESPACE` and is never a digest identity.
/// (´[ROOT-tab:identity:marker-operations]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarkerPayload {
    /// Major, minor and patch, in that order.
    version: [u64; 3],
    /// Literal preceding accepted root, or origin zeros.
    value: [u8; 32],
}

impl MarkerPayload {
    /// Read the complete constructed stamp.
    /// (´[ROOT-tab:identity:marker-operations]´)
    #[tracing::instrument(
        name = "amend:identity:marker-static-admission",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "amend:identity:marker-static-admission",
            operation = "marker-payload-version",
            source_item = "successor_marker::MarkerPayload::version"
        ),
        ret
    )]
    #[must_use]
    pub fn version(self) -> [u64; 3] {
        self.version
    }

    /// Read the exact constructed value word.
    /// (´[ROOT-tab:identity:marker-operations]´)
    #[tracing::instrument(
        name = "amend:identity:marker-static-admission",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "amend:identity:marker-static-admission",
            operation = "marker-payload-value",
            source_item = "successor_marker::MarkerPayload::value"
        ),
        ret
    )]
    #[must_use]
    pub fn value(self) -> [u8; 32] {
        self.value
    }
}

/// Major-one decoded view supplied by the canonical adapter.
/// It retains the received stamp and exact value; it conveys no chain evidence.
/// (´[ROOT-tab:identity:marker-operations]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedMarker {
    /// Received major, minor and patch, in that order.
    version: [u64; 3],
    /// Exact received root word.
    value: [u8; 32],
}

/// A supplied decoded stamp cannot form a major-one view.
/// (´[ROOT-tab:identity:marker-operations]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MarkerDecodedError {
    /// The stamp names a major other than one.
    #[error("decoded marker major is not one")]
    WrongMajor,
}

impl DecodedMarker {
    /// Form the major-one view from parts already decoded by the epoch reader.
    /// This checks the view's major only. The caller must have validated the
    /// canonical bytes and selected theory before this handoff.
    /// (´[ROOT-tab:identity:marker-operations]´)
    ///
    /// # Errors
    /// Returns `WrongMajor` for every major other than one.
    #[tracing::instrument(
        name = "amend:identity:marker-static-admission",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "amend:identity:marker-static-admission",
            operation = "decoded-marker-from-decoded-parts",
            source_item = "successor_marker::DecodedMarker::from_decoded_parts"
        ),
        ret
    )]
    pub fn from_decoded_parts(version: [u64; 3], value: [u8; 32]) -> Result<Self, MarkerDecodedError> {
        if version[0] != 1 {
            crate::refused();
            return Err(MarkerDecodedError::WrongMajor);
        }
        Ok(Self { version, value })
    }

    /// Read the complete received stamp.
    /// (´[ROOT-tab:identity:marker-operations]´)
    #[tracing::instrument(
        name = "amend:identity:marker-static-admission",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "amend:identity:marker-static-admission",
            operation = "decoded-marker-version",
            source_item = "successor_marker::DecodedMarker::version"
        ),
        ret
    )]
    #[must_use]
    pub fn version(self) -> [u64; 3] {
        self.version
    }

    /// Read the exact received value word.
    /// (´[ROOT-tab:identity:marker-operations]´)
    #[tracing::instrument(
        name = "amend:identity:marker-static-admission",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "amend:identity:marker-static-admission",
            operation = "decoded-marker-value",
            source_item = "successor_marker::DecodedMarker::value"
        ),
        ret
    )]
    #[must_use]
    pub fn value(self) -> [u8; 32] {
        self.value
    }
}

/// Whether the held theory was exact or a higher-minor open companion.
/// (´[ROOT-rule:identity:marker-read-order]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerAcceptance {
    /// An assigned theory accepted the complete payload.
    Strict,
    /// A higher-minor floor companion accepted the complete payload.
    Tolerant,
}

/// The one local refusal of following construction.
/// (´[ROOT-tab:identity:marker-operations]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MarkerConstructionError {
    /// Major one reserves zero for the authenticated origin.
    #[error("zero cannot be a following marker root")]
    ZeroFollowingRoot,
}

/// Exact root comparison, with no lookup or byte-order conversion.
/// (´[ROOT-tab:identity:marker-operations]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerRootComparison {
    /// The supplied words are equal in every byte.
    Equal,
    /// At least one byte differs.
    Different,
}

/// The coordinate of the standard for the epoch following this marker.
/// (´[ROOT-rule:identity:marker-standard]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarkerStandard {
    /// Fixed namespace of the marker theory.
    pub namespace: &'static str,
    /// Supported major, independent of minor and patch.
    pub major: u64,
}

/// Where independently authenticated evidence places the marker.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerPlace {
    /// The selected marker is the authenticated origin.
    AuthenticatedOrigin,
    /// The selected marker follows a preceding epoch.
    AuthenticatedFollowing,
    /// Placement has not been established.
    Unknown,
}

/// Whether the caller established the selected marker-token movement context.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerMovementContext {
    /// The caller supplies one selected marker-token context.
    Established,
    /// The caller has not established that context.
    Unknown,
}

/// Supplied result of the applicable movement rule.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerMovement {
    /// Movement satisfies the selected rule.
    Satisfied,
    /// Movement demonstrably breaches the selected rule.
    Breached,
    /// Movement evidence is unavailable.
    Unknown,
}

/// Separately supplied preceding accepted root.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecedingRoot {
    /// A separately established preceding root.
    Known([u8; 32]),
    /// No preceding root is established.
    Unknown,
}

/// Closed facts from one selected marker context and history.
/// Their authenticity remains the external producer's duty.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarkerFacts {
    /// Selected marker-token context.
    pub marker_movement: MarkerMovementContext,
    /// Authenticated placement, if known.
    pub place: MarkerPlace,
    /// Movement rule result, if known.
    pub movement: MarkerMovement,
    /// Preceding accepted root, if known.
    pub preceding_root: PrecedingRoot,
}

/// Bounded canonical-validation usage in records-owned plain values.
/// The last two fields mirror interchange `CanonicalUsage` exactly.
/// (´[ROOT-rule:identity:marker-read-order]´)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MarkerReadUsage {
    /// Received input length, including the length-before-budget case.
    pub received_bytes: usize,
    /// Caller-declared input limit.
    pub declared_input_bytes: usize,
    /// Interchange `CanonicalUsage::allocation_calls`.
    pub allocation_calls: usize,
    /// Interchange `CanonicalUsage::allocation_bytes`.
    pub allocation_bytes: usize,
}

/// The three budgeted read inability causes.
/// (´[ROOT-rule:identity:marker-read-order]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerReadBudgetReason {
    /// Received bytes exceed the caller's input declaration.
    InputBytes,
    /// Canonical validation exceeded its allocation declaration.
    CanonicalAllocation,
    /// A canonical validator allocation failed.
    Allocation,
}

/// Records-owned malformed-payload causes.
/// (´[ROOT-rule:identity:marker-read-order]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerInvalidReason {
    /// The protocol's 80-byte ceiling was exceeded.
    PayloadLength,
    /// The supplied bytes are not one complete canonical item.
    Canonical,
    /// The base namespace/version envelope is malformed.
    Envelope,
    /// The selected theory rejects the content.
    Theory,
}

/// Reader-relative version rejection, before content validation.
/// (´[ROOT-rule:identity:marker-read-order]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerVersionRejection {
    /// No theory for this major is held.
    UnheldMajor,
    /// A minor within the held ceiling has no assignment.
    UnassignedMinor,
}

/// Fixed assessment view returned by the later canonical adapter.
/// The view itself proves neither movement nor accepted-epoch lookup.
/// (´[ROOT-tab:identity:marker-operations]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerRead {
    /// A fully validated supported major-one payload.
    Decoded(DecodedMarker, MarkerAcceptance),
    /// The held registry rejects the stamped version.
    VersionRejected(MarkerVersionRejection, [u64; 3]),
    /// A structurally accepted major has no supported marker meaning.
    UnsupportedMeaning([u64; 3], MarkerAcceptance),
    /// Malformed or over-protocol-length bytes.
    Invalid(MarkerInvalidReason),
    /// A different namespace, not an invalid marker theory instance.
    NotMarker,
    /// The budgeted read could not finish inspecting the supplied bytes.
    UnavailableBudget(MarkerReadBudgetReason, MarkerReadUsage),
}

/// Ordered, fixed record of independently established errors.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
// Justified: The marker judgement requires six independently established error flags in one fixed record.
#[expect(clippy::struct_excessive_bools)]
pub struct MarkerErrors {
    /// Supplied movement breach.
    pub movement_breach: bool,
    /// Reader rejected an unheld major.
    pub unheld_major: bool,
    /// Reader rejected an unassigned minor.
    pub unassigned_minor: bool,
    /// A proven origin carries nonzero bytes.
    pub origin_nonzero: bool,
    /// A proven following marker carries zero bytes.
    pub following_zero: bool,
    /// A known preceding root differs from a nonzero following value.
    pub root_mismatch: bool,
}

impl MarkerErrors {
    fn any(self) -> bool {
        self.movement_breach
            || self.unheld_major
            || self.unassigned_minor
            || self.origin_nonzero
            || self.following_zero
            || self.root_mismatch
    }
}

/// Ordered, fixed record of missing supplied facts.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MarkerMissingFacts {
    /// The authenticated place is unknown.
    pub place: bool,
    /// The applicable movement rule has no result.
    pub movement: bool,
    /// A nonzero following marker lacks a preceding root.
    pub preceding_root: bool,
}

impl MarkerMissingFacts {
    fn any(self) -> bool {
        self.place || self.movement || self.preceding_root
    }
}

/// Why a marker cannot yet be judged from supplied evidence.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerMissing {
    /// Selected marker-token context has not been established.
    MarkerContext,
    /// A budgeted read stopped with its charged usage.
    ReadBudget(MarkerReadBudgetReason, MarkerReadUsage),
    /// A structurally accepted major has no assigned meaning.
    Interpretation,
    /// One or more supplied facts are missing, in the fixed field order.
    Facts(MarkerMissingFacts),
}

/// Pure lineage judgement over supplied facts only.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerJudgement {
    /// One stopped marker with every established error.
    Error(MarkerErrors),
    /// Insufficient supplied evidence, with every applicable missing fact.
    Unavailable(MarkerMissing),
    /// All applicable supplied facts establish the local pure rule.
    Valid,
}

/// Boundary left to the owner of invalid-payload policy.
/// A consumer must carry this without turning it into a lineage verdict.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerBoundary {
    /// Otherwise invalid bytes or a different namespace.
    UnclassifiedPayload(MarkerUnclassifiedPayload),
}

/// The two forms of an unclassified payload boundary.
/// (´[ROOT-rule:identity:marker-judgement]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerUnclassifiedPayload {
    /// Records-owned invalidity, without an assigned lineage decision.
    Invalid(MarkerInvalidReason),
    /// A distinct namespace, without an assigned marker decision.
    NotMarker,
}

/// Construct the fixed major-one origin payload without claiming its place.
/// (´[ROOT-tab:identity:marker-operations]´)
#[tracing::instrument(
    name = "amend:identity:marker-static-admission",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "amend:identity:marker-static-admission",
        operation = "first-marker",
        source_item = "successor_marker::first_marker"
    ),
    ret
)]
#[must_use]
pub fn first_marker(patch: u64) -> MarkerPayload {
    MarkerPayload {
        version: [1, 0, patch],
        value: [0; 32],
    }
}

/// Construct a following payload, refusing the major-one reserved zero root.
/// (´[ROOT-tab:identity:marker-operations]´)
///
/// # Errors
/// Returns `ZeroFollowingRoot` when the supplied root is all zero.
#[tracing::instrument(
    name = "amend:identity:marker-static-admission",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "amend:identity:marker-static-admission",
        operation = "following-marker",
        source_item = "successor_marker::following_marker"
    ),
    ret
)]
pub fn following_marker(root: [u8; 32], patch: u64) -> Result<MarkerPayload, MarkerConstructionError> {
    if root == [0; 32] {
        crate::refused();
        return Err(MarkerConstructionError::ZeroFollowingRoot);
    }
    Ok(MarkerPayload {
        version: [1, 0, patch],
        value: root,
    })
}

/// Compare every version component and every value byte exactly.
/// (´[ROOT-tab:identity:marker-operations]´)
#[tracing::instrument(
    name = "amend:identity:marker-static-admission",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "amend:identity:marker-static-admission",
        operation = "same-marker",
        source_item = "successor_marker::same_marker"
    ),
    ret
)]
#[must_use]
pub fn same_marker(left: MarkerPayload, right: MarkerPayload) -> bool {
    left == right
}

/// Compare a decoded major-one value with a separately supplied root.
/// (´[ROOT-tab:identity:marker-operations]´)
#[tracing::instrument(
    name = "amend:identity:marker-static-admission",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "amend:identity:marker-static-admission",
        operation = "compare-marker-root",
        source_item = "successor_marker::compare_marker_root"
    ),
    ret
)]
#[must_use]
pub fn compare_marker_root(decoded: DecodedMarker, root: [u8; 32]) -> MarkerRootComparison {
    if decoded.value == root {
        MarkerRootComparison::Equal
    } else {
        MarkerRootComparison::Different
    }
}

/// Name only the supported major-one standard coordinate.
/// (´[ROOT-rule:identity:marker-standard]´)
#[tracing::instrument(
    name = "amend:identity:marker-static-admission",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "amend:identity:marker-static-admission",
        operation = "marker-standard",
        source_item = "successor_marker::marker_standard"
    ),
    ret
)]
#[must_use]
pub fn marker_standard(decoded: DecodedMarker) -> MarkerStandard {
    let _ = decoded;
    MarkerStandard {
        namespace: MARKER_NAMESPACE,
        major: 1,
    }
}

/// Judge only the supplied assessment view and supplied facts.
/// (´[ROOT-rule:identity:marker-judgement]´)
///
/// # Errors
/// Returns an unclassified-payload boundary for an invalid or foreign payload
/// when no independent lineage error has been established.
#[tracing::instrument(
    name = "amend:identity:marker-static-admission",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "amend:identity:marker-static-admission",
        operation = "assess-marker",
        source_item = "successor_marker::assess_marker"
    ),
    ret
)]
pub fn assess_marker(read: MarkerRead, facts: MarkerFacts) -> Result<MarkerJudgement, MarkerBoundary> {
    if facts.marker_movement == MarkerMovementContext::Unknown {
        return Ok(MarkerJudgement::Unavailable(MarkerMissing::MarkerContext));
    }

    let decoded = match read {
        MarkerRead::Decoded(value, _) => Some(value),
        _ => None,
    };
    let mut errors = MarkerErrors {
        movement_breach: facts.movement == MarkerMovement::Breached,
        unheld_major: matches!(read, MarkerRead::VersionRejected(MarkerVersionRejection::UnheldMajor, _)),
        unassigned_minor: matches!(read, MarkerRead::VersionRejected(MarkerVersionRejection::UnassignedMinor, _)),
        ..MarkerErrors::default()
    };
    if let Some(value) = decoded {
        errors.origin_nonzero = facts.place == MarkerPlace::AuthenticatedOrigin && value.value != [0; 32];
        if facts.place == MarkerPlace::AuthenticatedFollowing {
            errors.following_zero = value.value == [0; 32];
            errors.root_mismatch =
                value.value != [0; 32] && matches!(facts.preceding_root, PrecedingRoot::Known(root) if root != value.value);
        }
    }
    if errors.any() {
        return Ok(MarkerJudgement::Error(errors));
    }

    match read {
        MarkerRead::Invalid(reason) => {
            return Err(MarkerBoundary::UnclassifiedPayload(MarkerUnclassifiedPayload::Invalid(
                reason,
            )));
        }
        MarkerRead::NotMarker => return Err(MarkerBoundary::UnclassifiedPayload(MarkerUnclassifiedPayload::NotMarker)),
        MarkerRead::UnavailableBudget(reason, usage) => {
            return Ok(MarkerJudgement::Unavailable(MarkerMissing::ReadBudget(reason, usage)));
        }
        MarkerRead::UnsupportedMeaning(_, _) => return Ok(MarkerJudgement::Unavailable(MarkerMissing::Interpretation)),
        // Every established-context version rejection returned with its error above.
        MarkerRead::VersionRejected(..) | MarkerRead::Decoded(..) => {}
    }

    let mut missing = MarkerMissingFacts {
        place: facts.place == MarkerPlace::Unknown,
        movement: facts.movement == MarkerMovement::Unknown,
        ..MarkerMissingFacts::default()
    };
    if let Some(value) = decoded {
        missing.preceding_root = facts.place == MarkerPlace::AuthenticatedFollowing
            && value.value != [0; 32]
            && facts.preceding_root == PrecedingRoot::Unknown;
    }
    if missing.any() {
        Ok(MarkerJudgement::Unavailable(MarkerMissing::Facts(missing)))
    } else {
        Ok(MarkerJudgement::Valid)
    }
}
