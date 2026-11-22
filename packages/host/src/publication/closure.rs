//! Caller-selected successor fragments; no version-one publication fallback.
//! (´[ROOT-amend:identity:closure-components]´)

use pn_act_authentication::v3::{self as authentication, AuthenticationMaterial, HeaderParts, MaterialContext, VerifiedHeader};
use pn_act_profile::{DependencyIds, v3 as profile};
use pn_interchange::{Array, Bytes, Value};
use pn_records::ActId;
use pn_records::closure::{ClosureAct, ClosureDependencyOpener, ClosureHeader, DependencyProof, SuppliedOpening};
use pn_records::commitments::ProposalCommitment;
use secrecy::SecretBox;

const ACT_LIMIT: usize = 2_097_152;
const PROOF_LIMIT: usize = 262_453;
const DEPENDENCIES_LIMIT: usize = 262_144;
const DEPENDENCIES_COUNT: usize = 1_024;

fn array(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(values))
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned().into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(Bytes::from(value.to_vec()))
}

fn values(value: &Value) -> Option<&[Value]> {
    match value {
        Value::Array(items) => Some(items.as_slice()),
        _ => None,
    }
}

fn octets(value: &Value) -> Option<&[u8]> {
    match value {
        Value::Bytes(items) => Some(items.as_slice()),
        _ => None,
    }
}

fn unsigned(value: &Value) -> Option<u64> {
    match value {
        Value::Unsigned(number) => Some(*number),
        _ => None,
    }
}

fn id_value(id: &ActId) -> Value {
    array([text("act"), text(&id.author), Value::Unsigned(id.sequence), text(&id.family)])
}

fn id_from(value: &Value) -> Option<ActId> {
    let [tag, author, sequence, family] = values(value)? else {
        return None;
    };
    let (Value::Text(tag), Value::Text(author), Value::Text(family)) = (tag, author, family) else {
        return None;
    };
    if tag.as_str() != "act" {
        return None;
    }
    Some(ActId {
        author: author.as_str().to_owned(),
        sequence: unsigned(sequence)?,
        family: family.as_str().to_owned(),
    })
}

/// Ordered successor act-fragment refusal, including nested selected causes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActError {
    Bound,
    Canonical,
    Shape,
    Edition,
    Header(authentication::EncodingError),
    Material(authentication::EncodingError),
    Seal,
    Approval,
    Epoch,
    Position,
    Time,
}

impl std::fmt::Display for ActError {
    /// Justified: Pure formatting of a closed public refusal inherits its enclosing act comparison and cannot recurse into observation.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ActError {}

/// Independent values expected when comparing a complete selected act.
#[derive(Clone, Debug)]
pub struct ActExpectation {
    pub selected_run: [u8; 32],
    pub expected_host: String,
    pub header: HeaderParts,
    pub material: AuthenticationMaterial,
    pub host_seal: [u8; 64],
    pub actor_approval: [u8; 64],
    pub epoch: u64,
    pub position: u64,
    pub logical_time: u64,
}

fn act_value(act: &ClosureAct<VerifiedHeader>) -> Value {
    array([
        Value::Unsigned(2),
        bytes(act.header().bytes()),
        bytes(act.material()),
        bytes(act.host_seal()),
        bytes(act.actor_approval()),
        Value::Unsigned(act.epoch()),
        Value::Unsigned(act.position()),
        Value::Unsigned(act.logical_time()),
    ])
}

/// Encode a typed act after checking its nested selected representations.
/// # Errors
/// Refuses typed size, shape or contextual nested defects.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "publication::closure::encode_act"
    ),
    ret
)]
pub fn encode_act(act: &ClosureAct<VerifiedHeader>, selected_run: [u8; 32], expected_host: &str) -> Result<Vec<u8>, ActError> {
    let encoded = act_value(act).to_canonical_bytes();
    decode_act(&encoded, selected_run, expected_host)?;
    Ok(encoded)
}

fn act_path(
    input: &[u8],
    selected_run: [u8; 32],
    expected_host: &str,
    expected: Option<&ActExpectation>,
) -> Result<ClosureAct<VerifiedHeader>, ActError> {
    if input.len() > ACT_LIMIT {
        return Err(ActError::Bound);
    }
    let value = Value::from_canonical_bytes(input).map_err(|_| ActError::Canonical)?;
    let [edition, header, material, seal, approval, epoch, position, time] = values(&value).ok_or(ActError::Shape)? else {
        return Err(ActError::Shape);
    };
    let edition = unsigned(edition).ok_or(ActError::Shape)?;
    let header_bytes = octets(header).ok_or(ActError::Shape)?;
    let material_bytes = octets(material).ok_or(ActError::Shape)?;
    let seal: [u8; 64] = octets(seal).ok_or(ActError::Shape)?.try_into().map_err(|_| ActError::Shape)?;
    let approval: [u8; 64] = octets(approval)
        .ok_or(ActError::Shape)?
        .try_into()
        .map_err(|_| ActError::Shape)?;
    let epoch = unsigned(epoch).ok_or(ActError::Shape)?;
    let position = unsigned(position).ok_or(ActError::Shape)?;
    let time = unsigned(time).ok_or(ActError::Shape)?;
    if edition != 2 {
        return Err(ActError::Edition);
    }
    let header = authentication::decode_header(header_bytes).map_err(ActError::Header)?;
    if let Some(expected) = expected {
        authentication::compare_header(header_bytes, &expected.header).map_err(ActError::Header)?;
    }
    let context = MaterialContext {
        selected_run,
        act: header.parts().body.id.clone(),
        expected_host: expected_host.to_owned(),
        header_version: [3, 0, 0],
    };
    let decoded_material = authentication::decode_material(material_bytes, &context).map_err(ActError::Material)?;
    if let Some(expected) = expected {
        if decoded_material != expected.material {
            return Err(ActError::Material(authentication::EncodingError::Host));
        }
        if seal != expected.host_seal {
            return Err(ActError::Seal);
        }
        if approval != expected.actor_approval {
            return Err(ActError::Approval);
        }
        if epoch != expected.epoch {
            return Err(ActError::Epoch);
        }
        if position != expected.position {
            return Err(ActError::Position);
        }
        if time != expected.logical_time {
            return Err(ActError::Time);
        }
    }
    Ok(ClosureAct::new(
        header,
        material_bytes.to_vec(),
        seal,
        approval,
        epoch,
        position,
        time,
    ))
}

/// Decode the selected fragment without claiming signature or inclusion.
/// # Errors
/// Refuses the admitted representation and nested context stages.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "publication::closure::decode_act"
    ),
    ret
)]
pub fn decode_act(input: &[u8], selected_run: [u8; 32], expected_host: &str) -> Result<ClosureAct<VerifiedHeader>, ActError> {
    act_path(input, selected_run, expected_host, None)
}

/// Compare the selected act with independently supplied exact expectations.
/// # Errors
/// Refuses in the admitted nested and outer stage order.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "publication::closure::compare_act"
    ),
    ret
)]
pub fn compare_act(input: &[u8], expected: &ActExpectation) -> Result<ClosureAct<VerifiedHeader>, ActError> {
    act_path(input, expected.selected_run, &expected.expected_host, Some(expected))
}

/// Ordered opening-proof refusal; absence is a result, not a malformed fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    Bound,
    Canonical,
    Shape,
    Edition,
    Identity,
    Digest,
    Blinding,
    DependenciesBound,
    Dependencies,
    AnchorIdentity,
    AnchorEpoch,
    AnchorPosition,
    AnchorProposal,
    AnchorCommitment,
    OpeningMismatch,
}

impl std::fmt::Display for ProofError {
    /// Justified: Pure formatting of a closed public refusal inherits its enclosing proof comparison and cannot recurse into observation.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProofError {}

/// The independently retained act is the stated authenticated-selection premise.
/// This wrapper does not authenticate that premise.
#[derive(Clone, Copy, Debug)]
pub struct OpeningAnchor<'a, H: ClosureHeader> {
    pub act: &'a ClosureAct<H>,
}

/// Structural absence remains distinct from successful exact comparison.
#[derive(Debug)]
pub enum ProofComparison {
    UnavailableOpening,
    UnavailableAnchor,
    Matches(Box<DependencyProof>),
}

/// Exact compared complete lists made available beside, never inside, history.
/// Only successful comparison results enter this adapter.
#[derive(Debug, Default)]
pub struct ComparedProofs(Vec<DependencyProof>);

impl ComparedProofs {
    #[must_use]
    #[tracing::instrument(
        name = "rule:publication:codec",
        fields(
            execution_owner = "HOST",
            claim_owner = "HOST",
            claim_label = "rule:publication:codec",
            source_item = "publication::closure::ComparedProofs::from_comparisons"
        ),
        ret
    )]
    pub fn from_comparisons(comparisons: Vec<ProofComparison>) -> Self {
        Self(
            comparisons
                .into_iter()
                .filter_map(|result| match result {
                    ProofComparison::Matches(proof) => Some(*proof),
                    ProofComparison::UnavailableOpening | ProofComparison::UnavailableAnchor => None,
                })
                .collect(),
        )
    }
}

impl<H: ClosureHeader> ClosureDependencyOpener<H> for ComparedProofs {
    #[tracing::instrument(
        name = "rule:publication:codec",
        fields(
            execution_owner = "HOST",
            claim_owner = "HOST",
            claim_label = "rule:publication:codec",
            source_item = "publication::closure::<ComparedProofs as ClosureDependencyOpener < H >>::targets"
        ),
        ret
    )]
    fn targets(&self) -> Vec<&ActId> {
        self.0.iter().map(DependencyProof::id).collect()
    }

    #[tracing::instrument(
        name = "rule:publication:codec",
        fields(
            execution_owner = "HOST",
            claim_owner = "HOST",
            claim_label = "rule:publication:codec",
            source_item = "publication::closure::<ComparedProofs as ClosureDependencyOpener < H >>::opening"
        ),
        ret
    )]
    fn opening<'a>(&'a self, act: &ClosureAct<H>) -> SuppliedOpening<'a> {
        self.0
            .iter()
            .find(|proof| {
                let commitments = act.header().commitments();
                proof.id() == act.id()
                    && proof.epoch() == act.epoch()
                    && proof.position() == act.position()
                    && proof.proposal() == &commitments.proposal.bytes
                    && proof.dependency() == &commitments.dependency.bytes
            })
            .map_or(SuppliedOpening::Unavailable, |proof| {
                SuppliedOpening::Available(proof.dependencies())
            })
    }
}

fn proof_value(proof: &DependencyProof) -> Value {
    array([
        Value::Unsigned(2),
        id_value(proof.id()),
        Value::Unsigned(proof.epoch()),
        Value::Unsigned(proof.position()),
        bytes(proof.proposal()),
        bytes(proof.dependency()),
        bytes(proof.host_dependency_blinding_value()),
        array(proof.dependencies().iter().map(id_value)),
    ])
}

/// Encode one complete typed opening after its structural checks.
/// # Errors
/// Refuses invalid identity, list or fixed dimensions.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "publication::closure::encode_proof"
    ),
    ret
)]
pub fn encode_proof(proof: &DependencyProof) -> Result<Vec<u8>, ProofError> {
    let encoded = proof_value(proof).to_canonical_bytes();
    decode_proof(&encoded)?;
    Ok(encoded)
}

/// Decode only the selected proof's representation and structural stages.
/// # Errors
/// Refuses the first admitted structural cause.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "publication::closure::decode_proof"
    ),
    ret
)]
pub fn decode_proof(input: &[u8]) -> Result<DependencyProof, ProofError> {
    if input.len() > PROOF_LIMIT {
        return Err(ProofError::Bound);
    }
    let value = Value::from_canonical_bytes(input).map_err(|_| ProofError::Canonical)?;
    let [edition, id, epoch, position, proposal, dependency, blinding, members] = values(&value).ok_or(ProofError::Shape)? else {
        return Err(ProofError::Shape);
    };
    let edition = unsigned(edition).ok_or(ProofError::Shape)?;
    if values(id).is_none() {
        return Err(ProofError::Shape);
    }
    let epoch = unsigned(epoch).ok_or(ProofError::Shape)?;
    let position = unsigned(position).ok_or(ProofError::Shape)?;
    let proposal = octets(proposal).ok_or(ProofError::Shape)?;
    let dependency = octets(dependency).ok_or(ProofError::Shape)?;
    let blinding = octets(blinding).ok_or(ProofError::Shape)?;
    let members = values(members).ok_or(ProofError::Shape)?;
    if edition != 2 {
        return Err(ProofError::Edition);
    }
    let id = id_from(id).filter(profile::valid_act_id).ok_or(ProofError::Identity)?;
    let proposal: [u8; 32] = proposal.try_into().map_err(|_| ProofError::Digest)?;
    let dependency: [u8; 32] = dependency.try_into().map_err(|_| ProofError::Digest)?;
    let blinding: [u8; 48] = blinding.try_into().map_err(|_| ProofError::Blinding)?;
    let encoded_members = array(members.iter().cloned()).to_canonical_bytes();
    if encoded_members.len() > DEPENDENCIES_LIMIT || members.len() > DEPENDENCIES_COUNT {
        return Err(ProofError::DependenciesBound);
    }
    let mut dependencies = Vec::with_capacity(members.len());
    for member in members {
        dependencies.push(id_from(member).filter(profile::valid_act_id).ok_or(ProofError::Identity)?);
    }
    if dependencies.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ProofError::Dependencies);
    }
    Ok(DependencyProof::new(
        id,
        epoch,
        position,
        proposal,
        dependency,
        blinding,
        dependencies,
    ))
}

fn profile_cause(error: profile::ProfileError) -> ProofError {
    match error {
        profile::ProfileError::Bound => ProofError::Bound,
        // Earlier proof guards make these causes unreachable here. A future
        // escape fails within the admitted post-anchor tail, without claiming coverage.
        profile::ProfileError::Representation
        | profile::ProfileError::Blinding
        | profile::ProfileError::Dependencies
        | profile::ProfileError::Dependency
        | profile::ProfileError::Recipe
        | profile::ProfileError::Canonical
        | profile::ProfileError::BodyShape
        | profile::ProfileError::Body
        | profile::ProfileError::ContentPreDigest
        | profile::ProfileError::Proposal
        | profile::ProfileError::Content => ProofError::OpeningMismatch,
    }
}

/// Compare a present proof with a separately supplied authenticated anchor.
/// # Errors
/// Refuses the first structural, association or recomputation cause.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "publication::closure::compare_proof"
    ),
    ret
)]
pub fn compare_proof<H: ClosureHeader>(
    input: Option<&[u8]>,
    anchor: Option<OpeningAnchor<'_, H>>,
) -> Result<ProofComparison, ProofError> {
    let Some(input) = input else {
        return Ok(ProofComparison::UnavailableOpening);
    };
    let proof = decode_proof(input)?;
    let Some(anchor) = anchor else {
        return Ok(ProofComparison::UnavailableAnchor);
    };
    let act = anchor.act;
    if proof.id() != act.id() {
        return Err(ProofError::AnchorIdentity);
    }
    if proof.epoch() != act.epoch() {
        return Err(ProofError::AnchorEpoch);
    }
    if proof.position() != act.position() {
        return Err(ProofError::AnchorPosition);
    }
    let commitments = act.header().commitments();
    if proof.proposal() != &commitments.proposal.bytes {
        return Err(ProofError::AnchorProposal);
    }
    if proof.dependency() != &commitments.dependency.bytes {
        return Err(ProofError::AnchorCommitment);
    }
    let proposal = ProposalCommitment {
        recipe: profile::PROPOSAL_RECIPE.to_owned(),
        bytes: *proof.proposal(),
    };
    let blinding = proof.host_dependency_blinding_value().to_vec().into();
    let dependencies = SecretBox::new(Box::new(DependencyIds(proof.dependencies().to_vec())));
    let computed = profile::dependency_commitment(proof.id(), &proposal, &blinding, &dependencies).map_err(profile_cause)?;
    if computed.bytes != *proof.dependency() {
        return Err(ProofError::OpeningMismatch);
    }
    Ok(ProofComparison::Matches(Box::new(proof)))
}
