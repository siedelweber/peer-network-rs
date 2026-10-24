//! Internal burn evidence and marker recognition; no chain adapter or snapshot summation.
//! (´def:burn:carriers´)
use crate::numerics::{BurnAmount, RecordingEventCost, UnitCost};
use std::collections::{BTreeMap, BTreeSet};

/// A name in a declared opaque address space, with no identity or ownership inference.
/// (´def:burn:carriers´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub String);

/// Required operator evidence; absence is explained rather than represented as a zero proof.
/// (´def:burn:disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperatorEvidence {
    /// Public bound and proof, whose external validity remains a realization obligation.
    Bound { amount: BurnAmount, proof: String },
    /// Why no operational role accrues burn.
    Absent { explanation: String },
}

/// Public bootstrap disclosure; the bound applies only to this acquisition interval.
/// (´def:burn:disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bootstrap {
    pub bound: BurnAmount,
    pub empty_interval: bool,
    pub explanation: String,
}

/// Publication candidate; missing disclosures remain distinguishable from explicit empty costs.
/// (´def:burn:disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnInput {
    pub address_space: String,
    pub edition: String,
    pub sample_convention: String,
    pub boundary: u64,
    pub read_addresses: BTreeSet<Address>,
    pub amounts: BTreeMap<Address, BurnAmount>,
    pub bootstrap: Option<Bootstrap>,
    pub unit_cost: Option<UnitCost>,
    pub evidence: BurnEvidence,
}

/// Companion public audit record bound to the same effective edition and sample convention.
/// These disclosures are not additional arithmetic inputs.
/// (´def:burn:disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnEvidence {
    pub edition: String,
    pub sample_convention: String,
    pub settlement_depth: Option<u64>,
    pub finality_assumptions: Option<String>,
    pub provenance: Option<String>,
    pub recording_costs: Option<Vec<RecordingEventCost>>,
    pub operator: Option<OperatorEvidence>,
}

/// Complete disclosures; amounts are carried, not certified as a marker-derived snapshot.
/// (´def:burn:disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedBurn(BurnInput);

/// Declared policy encoding; order is sufficient only in the explicit whole-prefix case.
/// (´def:burn:marker-policy´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    CompleteList,
    PublicCommitment,
    WholePrefixAcceptAll,
}

/// Deterministic identification among candidates at the same index.
/// (´def:burn:marker-policy´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateRule {
    /// Try candidates in their disclosed history order, retaining the first that passes.
    FirstValidInHistoryOrder,
    /// A deployment promises one candidate per index; a violation stops at that index.
    UniquePerIndex,
}

/// Immutable policy identity includes its edition and sequence, not merely its display name.
/// (´def:burn:marker-policy´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyInput {
    pub identity: String,
    pub edition: String,
    pub sequence: String,
    pub published_at: u64,
    /// Asserted copy only; binding requires the deployment structural declaration to agree.
    pub genesis_at: u64,
    pub initial_marker: String,
    pub open_placement: bool,
    pub placement_procedure: String,
    pub cadence: String,
    pub encoding: Encoding,
    pub candidate_rule: CandidateRule,
    pub verification_profile: String,
    pub stability_buffer: u64,
}

/// Policy checked against the disclosed settlement depth before any recognition.
/// (´def:burn:marker-policy´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPolicy {
    input: PolicyInput,
    burn: ValidatedBurn,
}

/// One referring record; aliases retain a single destruction identity, amount and attribution.
/// (´def:burn:lineage´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnRecord {
    pub identity: String,
    pub destruction: String,
    pub address: Address,
    pub amount: BurnAmount,
    pub evidence: Vec<u8>,
}

/// Complete public opening, including its proof bytes; private choices are not accepted.
/// (´def:burn:accepted-set´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub members: BTreeSet<String>,
    pub proof: Vec<u8>,
}

/// Fixed interpretation data read only under the matching declared policy encoding.
/// (´def:burn:accepted-set´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptedSet {
    CompleteList(BTreeSet<String>),
    Commitment { commitment: Vec<u8>, openings: Vec<Opening> },
    WholePrefix,
}

/// Structural marker identity includes every fixed interpretation and lineage field.
/// The external name is only a lookup key; equality compares the whole carrier.
/// (´def:burn:lineage´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marker {
    pub name: String,
    pub history: String,
    pub policy_identity: String,
    pub policy_edition: String,
    pub sequence: String,
    pub index: u64,
    /// Unique position fixed by this history disclosure, not by vector presentation.
    pub history_position: u64,
    /// Unique disclosed history position of the selected predecessor; names are lookup labels.
    pub predecessor: Option<u64>,
    pub lineage: BTreeSet<String>,
    pub accepted: AcceptedSet,
    /// Only the initial marker carries this explicit empty snapshot declaration.
    pub initial_snapshot: Option<BTreeMap<Address, BurnAmount>>,
}

/// One complete disclosed history, never a union of competing histories.
/// (´def:burn:lineage´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryInput {
    pub identity: String,
    pub records: Vec<BurnRecord>,
    pub markers: Vec<Marker>,
}

/// External verification boundary. Implementations must be deterministic public checks of
/// the named profile, with sound destruction proofs and binding complete-set openings.
/// This trait does not turn a mock into evidence of cryptographic or chain validity.
/// (´def:burn:verification-boundary´)
pub trait PublicVerifier: std::fmt::Debug {
    /// Exact profile this implementation checks.
    fn profile(&self) -> &str;
    /// Verify genuine destruction, exact amount and original address from retained evidence.
    /// Bind `destruction` to the destroyed object's unique canonical identity under this profile;
    /// aliases of one destruction must never verify under distinct destruction identities.
    fn destruction(&self, record: &BurnRecord) -> bool;
    /// Verify a binding public opening of the complete member set, not just inclusion proofs.
    fn opening(&self, commitment: &[u8], opening: &Opening) -> bool;
}

/// Local evidence checks retained for pure recognition; fields cannot be forged by consumers.
/// (´def:burn:verification-boundary´)
#[derive(Clone, Debug)]
pub struct ValidatedMarkerHistory {
    input: HistoryInput,
    policy: ValidatedPolicy,
    verified: BTreeSet<String>,
    openings: Vec<Result<BTreeSet<String>, BurnError>>,
}

/// Inputs identifying an unsettled recognition, not host finality evidence.
/// (´def:burn:recognition´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecognitionBasis {
    pub history: String,
    pub policy_identity: String,
    pub policy_edition: String,
    pub verifier_profile: String,
    pub burn_publication_edition: String,
    pub sample_convention: String,
}

/// Recognized sequence, retaining complete marker identities and deduplicated destructions.
/// Recognition is not finality: settlement requires the host's evidence at the published depth.
/// No first-accepted increment or amount snapshot is computed here.
/// (´def:burn:recognition´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecognizedMarkers {
    basis: RecognitionBasis,
    markers: Vec<RecognizedMarker>,
    first_refusal: Option<CandidateRefusal>,
}

/// First rejected candidate in index order, with ties in disclosed history order.
/// An empty history has no candidate. A later valid competitor may still extend the prefix.
/// (´def:burn:recognition´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateRefusal {
    pub candidate: Option<Marker>,
    pub cause: BurnError,
    /// All refused competitors in disclosed position order; empty for a single-candidate refusal.
    pub competitors: Vec<Marker>,
}

/// A complete accepted record set and one representative per destruction.
/// (´def:burn:recognition´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecognizedMarker {
    identity: Marker,
    accepted: BTreeSet<String>,
    destructions: BTreeMap<String, BurnRecord>,
}

/// Named required publications, including evidence that no numeric formula consumes.
/// (´def:burn:disclosures´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disclosure {
    AddressSpace,
    Edition,
    SampleConvention,
    Bootstrap,
    UnitCost,
    SettlementDepth,
    Finality,
    Provenance,
    RecordingCosts,
    Operator,
}

/// Exhaustive local refusals while unpublished; no refusal repairs candidate contents.
/// (´def:burn:recognition´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BurnError {
    #[error("marker policy declaration selection: {0}")]
    PolicySelection(#[from] crate::ValidationError),
    #[error("policy identity, edition or publication differs from the declaration effective at genesis")]
    PolicyBinding,
    #[error("missing, ambiguous or mismatched structural deployment genesis")]
    DeploymentBinding,
    #[error("marker policy content differs from its declared digest")]
    PolicyDigest,
    #[error("missing required publication: {0:?}")]
    Publication(Disclosure),
    #[error("audit evidence belongs to another edition or sample convention")]
    EvidenceBinding,
    #[error("sampled address map differs from required reads")]
    SampleCoverage,
    #[error("burn unit mismatch")]
    Units,
    #[error("empty bootstrap interval requires a published zero and explanation")]
    Bootstrap,
    #[error("invalid fixed pre-genesis open-placement policy")]
    Policy,
    #[error("stability buffer does not exceed settlement depth")]
    Buffer,
    #[error("wrong verification profile")]
    Verifier,
    #[error("empty or duplicate record identity")]
    RecordIdentity,
    #[error("marker belongs to another history or policy")]
    HistoryPolicy,
    #[error("duplicate disclosed marker history position")]
    HistoryPosition,
    #[error("invalid initial marker")]
    Initial,
    #[error("duplicate or skipped marker index, name or predecessor")]
    Succession,
    #[error("lineage member is absent from this history")]
    MissingLineage,
    #[error("successor lineage regressed")]
    RegressedLineage,
    #[error("accepted set uses an undeclared encoding")]
    Encoding,
    #[error("missing public commitment opening")]
    MissingOpening,
    #[error("ambiguous public commitment opening")]
    AmbiguousOpening,
    #[error("invalid public commitment opening")]
    InvalidOpening,
    #[error("accepted set regressed")]
    RegressedAcceptance,
    #[error("accepted record outside lineage")]
    OutOfLineage,
    #[error("accepted member fails destruction verification")]
    InvalidMember,
    #[error("aliases disagree on destruction amount or original address")]
    InconsistentAlias,
}

fn required(text: &str, field: Disclosure) -> Result<(), BurnError> {
    if text.trim().is_empty() {
        Err(BurnError::Publication(field))
    } else {
        Ok(())
    }
}

/// Check complete publication, typed units and explicit empty-bootstrap evidence.
/// (´def:burn:disclosures´)
/// # Errors
/// Returns the missing publication or malformed coverage/unit/bootstrap cause.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "validate-burn",
        source_item = "burn::validate_burn"
    ),
    ret
)]
pub fn validate_burn(input: BurnInput) -> Result<ValidatedBurn, BurnError> {
    let result = validate_disclosures(input);
    if result.is_err() {
        super::refused();
    }
    result
}

fn validate_disclosures(input: BurnInput) -> Result<ValidatedBurn, BurnError> {
    required(&input.address_space, Disclosure::AddressSpace)?;
    required(&input.edition, Disclosure::Edition)?;
    required(&input.sample_convention, Disclosure::SampleConvention)?;
    required(&input.evidence.edition, Disclosure::Edition)?;
    required(&input.evidence.sample_convention, Disclosure::SampleConvention)?;
    if input.edition != input.evidence.edition || input.sample_convention != input.evidence.sample_convention {
        return Err(BurnError::EvidenceBinding);
    }
    let bootstrap = input
        .bootstrap
        .as_ref()
        .ok_or(BurnError::Publication(Disclosure::Bootstrap))?;
    let cost = input.unit_cost.as_ref().ok_or(BurnError::Publication(Disclosure::UnitCost))?;
    input
        .evidence
        .settlement_depth
        .ok_or(BurnError::Publication(Disclosure::SettlementDepth))?;
    required(
        input.evidence.finality_assumptions.as_deref().unwrap_or(""),
        Disclosure::Finality,
    )?;
    required(input.evidence.provenance.as_deref().unwrap_or(""), Disclosure::Provenance)?;
    input
        .evidence
        .recording_costs
        .as_ref()
        .ok_or(BurnError::Publication(Disclosure::RecordingCosts))?;
    let operator = input
        .evidence
        .operator
        .as_ref()
        .ok_or(BurnError::Publication(Disclosure::Operator))?;
    match operator {
        OperatorEvidence::Bound { amount, proof } => {
            required(proof, Disclosure::Operator)?;
            if amount.unit() != bootstrap.bound.unit() {
                return Err(BurnError::Units);
            }
        }
        OperatorEvidence::Absent { explanation } => required(explanation, Disclosure::Operator)?,
    }
    required(&bootstrap.explanation, Disclosure::Bootstrap)?;
    if bootstrap.empty_interval && bootstrap.bound.exact() != "0" {
        return Err(BurnError::Bootstrap);
    }
    if input.read_addresses.iter().any(|a| a.0.is_empty()) || input.read_addresses != input.amounts.keys().cloned().collect() {
        return Err(BurnError::SampleCoverage);
    }
    if cost.burn_unit() != bootstrap.bound.unit() || input.amounts.values().any(|a| a.unit() != bootstrap.bound.unit()) {
        return Err(BurnError::Units);
    }
    Ok(ValidatedBurn(input))
}

/// Freeze policy content and require publication before genesis and a sufficient buffer.
/// (´def:burn:marker-policy´)
/// # Errors
/// Refuses incomplete, late, privileged-placement or insufficient-buffer policy declarations.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "validate-marker-policy",
        source_item = "burn::validate_policy"
    ),
    ret
)]
pub(crate) fn validate_policy(input: PolicyInput, burn: &ValidatedBurn) -> Result<ValidatedPolicy, BurnError> {
    let result = (|| {
        if [
            &input.identity,
            &input.edition,
            &input.sequence,
            &input.initial_marker,
            &input.placement_procedure,
            &input.cadence,
            &input.verification_profile,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
            || !input.open_placement
            || input.published_at >= input.genesis_at
        {
            return Err(BurnError::Policy);
        }
        if input.stability_buffer <= burn.0.evidence.settlement_depth.unwrap_or(u64::MAX) {
            return Err(BurnError::Buffer);
        }
        Ok(ValidatedPolicy {
            input,
            burn: burn.clone(),
        })
    })();
    if result.is_err() {
        super::refused();
    }
    result
}

fn recover(marker: &Marker, policy: &PolicyInput, verifier: &impl PublicVerifier) -> Result<BTreeSet<String>, BurnError> {
    match (&marker.accepted, policy.encoding) {
        (AcceptedSet::CompleteList(members), Encoding::CompleteList) => Ok(members.clone()),
        (AcceptedSet::WholePrefix, Encoding::WholePrefixAcceptAll) => Ok(marker.lineage.clone()),
        (AcceptedSet::Commitment { commitment, openings }, Encoding::PublicCommitment) => {
            if openings.is_empty() {
                return Err(BurnError::MissingOpening);
            }
            if openings.len() != 1 {
                return Err(BurnError::AmbiguousOpening);
            }
            let opening = &openings[0];
            if commitment.is_empty() || opening.proof.is_empty() || !verifier.opening(commitment, opening) {
                return Err(BurnError::InvalidOpening);
            }
            Ok(opening.members.clone())
        }
        _ => Err(BurnError::Encoding),
    }
}

/// Check public realization proofs under the policy's explicit verifier profile.
/// Rejected unaccepted records remain in lineage; recognition refuses only their acceptance.
/// (´def:burn:verification-boundary´)
/// # Errors
/// Refuses a mismatched verifier or ambiguous record identity; candidate and proof failures are retained.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "validate-marker-history",
        source_item = "burn::validate_marker_history"
    ),
    ret
)]
pub fn validate_marker_history(
    input: HistoryInput,
    policy: &ValidatedPolicy,
    verifier: &impl PublicVerifier,
) -> Result<ValidatedMarkerHistory, BurnError> {
    let result = (|| {
        if verifier.profile() != policy.input.verification_profile {
            return Err(BurnError::Verifier);
        }
        if input.identity.is_empty() {
            return Err(BurnError::HistoryPolicy);
        }
        let mut positions = BTreeSet::new();
        if input.markers.iter().any(|marker| !positions.insert(marker.history_position)) {
            return Err(BurnError::HistoryPosition);
        }
        let mut names = BTreeSet::new();
        let mut proofs = BTreeSet::new();
        for record in &input.records {
            if record.identity.is_empty() || !names.insert(record.identity.clone()) {
                return Err(BurnError::RecordIdentity);
            }
            if !record.destruction.is_empty()
                && !record.address.0.is_empty()
                && !record.evidence.is_empty()
                && verifier.destruction(record)
            {
                proofs.insert(record.identity.clone());
            }
        }
        let openings = input
            .markers
            .iter()
            .map(|marker| recover(marker, &policy.input, verifier))
            .collect();
        Ok(ValidatedMarkerHistory {
            input,
            policy: policy.clone(),
            verified: proofs,
            openings,
        })
    })();
    if result.is_err() {
        super::refused();
    }
    result
}

/// Recognize M1–M3 and deduplicate consistent destruction aliases for M4, within one history.
/// Never computes the first-accepted increment or repairs an invalid complete accepted set.
/// (´def:burn:recognition´)
/// Returns the recognized prefix and its first candidate refusal, without discarding predecessors.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "recognize-markers",
        source_item = "burn::recognize_markers"
    ),
    ret
)]
pub fn recognize_markers(history: &ValidatedMarkerHistory) -> RecognizedMarkers {
    let result = recognize(history);
    if result.first_refusal.is_some() {
        super::refused();
    }
    result
}

fn recognize(history: &ValidatedMarkerHistory) -> RecognizedMarkers {
    let mut candidates: Vec<_> = history.input.markers.iter().enumerate().collect();
    // Disclosure fixes tie order even when a caller reverses or shuffles presentation.
    candidates.sort_by_key(|(_, marker)| (marker.index, marker.history_position));
    let records: BTreeMap<_, _> = history.input.records.iter().map(|r| (&r.identity, r)).collect();
    let mut result = RecognizedMarkers {
        basis: RecognitionBasis {
            history: history.input.identity.clone(),
            policy_identity: history.policy.input.identity.clone(),
            policy_edition: history.policy.input.edition.clone(),
            verifier_profile: history.policy.input.verification_profile.clone(),
            burn_publication_edition: history.policy.burn.0.edition.clone(),
            sample_convention: history.policy.burn.0.sample_convention.clone(),
        },
        markers: Vec::new(),
        first_refusal: None,
    };
    if candidates.is_empty() {
        result.first_refusal = Some(CandidateRefusal {
            candidate: None,
            cause: BurnError::Initial,
            competitors: Vec::new(),
        });
    }
    for group in candidates.chunk_by(|(_, left), (_, right)| left.index == right.index) {
        if history.policy.input.candidate_rule == CandidateRule::UniquePerIndex && group.len() != 1 {
            result.first_refusal.get_or_insert_with(|| CandidateRefusal {
                candidate: Some(group[0].1.clone()),
                cause: BurnError::Succession,
                competitors: group.iter().map(|(_, marker)| (*marker).clone()).collect(),
            });
            break;
        }
        let mut selected = None;
        for &(position, marker) in group {
            let candidate = if marker.name.is_empty() {
                Err(BurnError::Succession)
            } else {
                recognize_candidate(history, position, marker, result.markers.last(), &records)
            };
            match candidate {
                Ok(marker) => {
                    selected = Some(marker);
                    break;
                }
                Err(cause) => {
                    result.first_refusal.get_or_insert_with(|| CandidateRefusal {
                        candidate: Some(marker.clone()),
                        cause,
                        competitors: Vec::new(),
                    });
                }
            }
        }
        if let Some(marker) = selected {
            result.markers.push(marker);
        } else {
            break;
        }
    }
    result
}

fn recognize_candidate(
    history: &ValidatedMarkerHistory,
    position: usize,
    marker: &Marker,
    previous: Option<&RecognizedMarker>,
    records: &BTreeMap<&String, &BurnRecord>,
) -> Result<RecognizedMarker, BurnError> {
    let policy = &history.policy.input;
    let unit = history
        .policy
        .burn
        .0
        .bootstrap
        .as_ref()
        .ok_or(BurnError::Publication(Disclosure::Bootstrap))?
        .bound
        .unit();
    if marker.history != history.input.identity
        || marker.policy_identity != policy.identity
        || marker.policy_edition != policy.edition
        || marker.sequence != policy.sequence
    {
        return Err(BurnError::HistoryPolicy);
    }
    let accepted = history.openings[position].clone()?;
    if let Some(previous) = previous {
        if previous.identity.index.checked_add(1) != Some(marker.index)
            || marker.predecessor != Some(previous.identity.history_position)
            || marker.initial_snapshot.is_some()
        {
            return Err(BurnError::Succession);
        }
        if !previous.identity.lineage.is_subset(&marker.lineage) {
            return Err(BurnError::RegressedLineage);
        }
        if !previous.accepted.is_subset(&accepted) {
            return Err(BurnError::RegressedAcceptance);
        }
    } else if marker.index != 0
        || marker.name != policy.initial_marker
        || marker.predecessor.is_some()
        || !accepted.is_empty()
        || !marker.initial_snapshot.as_ref().is_some_and(BTreeMap::is_empty)
    {
        return Err(BurnError::Initial);
    }
    if marker.lineage.iter().any(|id| !records.contains_key(id)) {
        return Err(BurnError::MissingLineage);
    }
    if !accepted.is_subset(&marker.lineage) {
        return Err(BurnError::OutOfLineage);
    }
    let mut aliases = previous.map_or_else(BTreeMap::new, |m| m.destructions.clone());
    let mut destructions = BTreeMap::new();
    for id in &accepted {
        let record = records[id];
        if !history.verified.contains(id) || record.amount.unit() != unit {
            return Err(BurnError::InvalidMember);
        }
        if let Some(previous) = aliases.get(&record.destruction) {
            if previous.address != record.address || previous.amount != record.amount {
                return Err(BurnError::InconsistentAlias);
            }
        } else {
            aliases.insert(record.destruction.clone(), record.clone());
        }
        destructions
            .entry(record.destruction.clone())
            .or_insert_with(|| record.clone());
    }
    Ok(RecognizedMarker {
        identity: marker.clone(),
        accepted,
        destructions,
    })
}

impl ValidatedBurn {
    /// Borrow the complete publication, including noncomputational audit evidence.
    /// (´def:burn:disclosures´)
    /// Justified: Pure immutable field access inherits the labelled burn operation that produced this carrier; it performs no recognition or computation.
    #[must_use]
    pub fn publication(&self) -> &BurnInput {
        &self.0
    }
}
impl RecognizedMarkers {
    /// Borrow the fixed computation keys; these identify recognition, not settled evidence.
    /// (´def:burn:recognition´)
    /// Justified: Pure immutable field access inherits the labelled burn operation that produced this carrier; it performs no recognition or computation.
    #[must_use]
    pub fn basis(&self) -> &RecognitionBasis {
        &self.basis
    }

    /// Borrow the first rejected candidate and cause; a valid competitor can still extend the prefix.
    /// (´def:burn:recognition´)
    /// Justified: Pure immutable field access inherits the labelled burn operation that produced this carrier; it performs no recognition or computation.
    #[must_use]
    pub fn first_refusal(&self) -> Option<&CandidateRefusal> {
        self.first_refusal.as_ref()
    }

    /// Borrow the fixed history identity; alternative histories are separate recognitions.
    /// (´def:burn:recognition´)
    /// Justified: Pure immutable field access inherits the labelled burn operation that produced this carrier; it performs no recognition or computation.
    #[must_use]
    pub fn history(&self) -> &str {
        &self.basis.history
    }
    /// Borrow the complete recognized sequence in immediate predecessor order.
    /// (´def:burn:recognition´)
    /// Justified: Pure immutable field access inherits the labelled burn operation that produced this carrier; it performs no recognition or computation.
    #[must_use]
    pub fn markers(&self) -> &[RecognizedMarker] {
        &self.markers
    }
}
impl RecognizedMarker {
    /// Borrow the entire structural marker identity, including interpretation data.
    /// (´def:burn:recognition´)
    /// Justified: Pure immutable field access inherits the labelled burn operation that produced this carrier; it performs no recognition or computation.
    #[must_use]
    pub fn identity(&self) -> &Marker {
        &self.identity
    }
    /// Borrow the complete accepted record set without clipping or enlargement.
    /// (´def:burn:recognition´)
    /// Justified: Pure immutable field access inherits the labelled burn operation that produced this carrier; it performs no recognition or computation.
    #[must_use]
    pub fn accepted(&self) -> &BTreeSet<String> {
        &self.accepted
    }
    /// Borrow one representative per destruction, retaining its original amount and address.
    /// This is not a first-accepted increment or summed snapshot.
    /// (´def:burn:recognition´)
    /// Justified: Pure immutable field access inherits the labelled burn operation that produced this carrier; it performs no recognition or computation.
    #[must_use]
    pub fn destructions(&self) -> &BTreeMap<String, BurnRecord> {
        &self.destructions
    }
}
