//! Caller-selected third formation. Equality here authenticates no anchor.
//! (´def:profile:version-three´)
use super::{
    DependencyIds, array, author_blinding_value_format, hash_with_limits, identifier, license_projection, projection, public,
    publish, quantities_projection, role, schema, secret_length, text, valid_id,
};
use pn_interchange::{Bytes, SecretValue, Value};
use pn_records::commitments::{ContentCommitment, DependencyCommitment, ProposalCommitment};
use pn_records::{ActId, CandidateLeg, Layout, PublicReference, Role, StructuralBody};
use secrecy::{SecretBox, SecretSlice};

/// Third proposal recipe, selected by the caller.
pub const PROPOSAL_RECIPE: &str = "pn-act-profile/act-proposal/v3";
/// Third content recipe, selected by the caller.
pub const CONTENT_RECIPE: &str = "pn-act-profile/act-content/v3";
/// Third dependency recipe, selected by the caller.
pub const DEPENDENCY_RECIPE: &str = "pn-act-profile/act-dependency/v3";
const BODY_LIMIT: usize = 1_048_576;
const PREIMAGE_LIMIT: usize = 2_097_152;
const DEPENDENCY_LIMIT: usize = 262_144;

/// A third-formation refusal, without translating an earlier edition's causes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    #[error("unsupported commitment recipe")]
    Recipe,
    #[error("formation bound exceeded")]
    Bound,
    #[error("noncanonical body encoding")]
    Canonical,
    #[error("invalid body shape")]
    BodyShape,
    #[error("proposal body differs")]
    Body,
    #[error("invalid blinding value")]
    Blinding,
    #[error("invalid dependency list")]
    Dependencies,
    #[error("invalid content pre-digest")]
    ContentPreDigest,
    #[error("invalid representation")]
    Representation,
    #[error("proposal commitment differs")]
    Proposal,
    #[error("content commitment differs")]
    Content,
    #[error("dependency commitment differs")]
    Dependency,
}

/// Exact authored third body. Request fields do not exist in this edition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalBody {
    pub id: ActId,
    pub retirement_point: [u8; 32],
    pub body: StructuralBody,
    pub legs: Vec<CandidateLeg>,
    pub protocol_references: Vec<PublicReference>,
    pub signed_extension: Vec<u8>,
}

/// A supplied content opening; protected bytes have no public accessor.
#[derive(Debug)]
pub struct ContentPair {
    pub payload: SecretSlice<u8>,
    pub author_content_blinding_value: SecretSlice<u8>,
}

/// An opaque received pre-digest with its asserted `ActId` association.
#[derive(Debug)]
pub struct ContentPreDigest {
    pub act: ActId,
    pub bytes: SecretSlice<u8>,
}

/// The Actor's computed P, constructible only from the complete opening.
#[derive(Debug)]
pub struct ComputedProposalCommitment(ProposalCommitment);
impl ComputedProposalCommitment {
    /// Borrow the public residue; no authenticity or custody follows.
    #[must_use]
    #[tracing::instrument(
        name = "def:profile:version-three",
        fields(
            execution_owner = "ACTPROFILE",
            claim_owner = "ACTPROFILE",
            claim_label = "def:profile:version-three",
            source_item = "v3::ComputedProposalCommitment::as_recorded"
        ),
        ret
    )]
    pub fn as_recorded(&self) -> &ProposalCommitment {
        &self.0
    }
}

/// Comparison with a supplied opening, or its absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpeningComparison {
    Unavailable,
    Matches,
}

fn map_shape(_: super::ProfileError) -> ProfileError {
    ProfileError::BodyShape
}

fn ref_value(value: &PublicReference) -> Value {
    match value {
        PublicReference::Act(id) => identifier(id),
        PublicReference::Edge(edge) => array([text("record"), identifier(&edge.act), text(role(edge.role))]),
        PublicReference::Minted(id) => array([text("mint"), identifier(id)]),
        PublicReference::Named { namespace, name } => array([text("named"), text(namespace), text(name)]),
    }
}

fn leg_value(leg: &CandidateLeg) -> Value {
    array([text(role(leg.id.role)), ref_value(&leg.source), ref_value(&leg.target)])
}

fn structural_value(body: &ProposalBody) -> Value {
    let structure = &body.body;
    let quantities = array(structure.quantities.iter().map(|(name, quantity)| {
        array([
            text(name),
            Value::integer(i128::from(quantity.value)).expect("i64 fits interchange integer domain"),
            text(&quantity.unit),
            Value::Unsigned(quantity.vintage),
        ])
    }));
    let license = match structure.license.as_ref() {
        None => Value::Null,
        Some(license) => array([license.attribution, license.provenance].map(|degree| {
            array([
                Value::integer(i128::from(degree.numerator)).expect("i64 fits interchange integer domain"),
                Value::integer(i128::from(degree.denominator)).expect("i64 fits interchange integer domain"),
            ])
        })),
    };
    let settlement = match &structure.settlement {
        Some(pn_records::SettlementReferences::Accept { settles }) => array([text("Accept"), identifier(settles)]),
        Some(pn_records::SettlementReferences::Ratify { settles, accepts }) => {
            array([text("Ratify"), identifier(settles), identifier(accepts)])
        }
        None => Value::Null,
    };
    array([
        identifier(&body.id),
        Value::Bytes(Bytes::from(body.retirement_point.to_vec())),
        text(match structure.layout {
            Layout::Binary => "binary",
            Layout::Paired => "paired",
        }),
        array(body.legs.iter().map(leg_value)),
        quantities,
        license,
        array(structure.asserted_parents.iter().map(identifier)),
        array(body.protocol_references.iter().map(ref_value)),
        settlement,
        Value::Bytes(Bytes::from(body.signed_extension.clone())),
    ])
}

fn validate_body(body: &ProposalBody) -> Result<(), ProfileError> {
    let id = &body.id;
    let structure = &body.body;
    if !valid_id(id) {
        return Err(ProfileError::BodyShape);
    }
    let (layout, coordinates) = schema(&id.family).ok_or(ProfileError::BodyShape)?;
    if structure.layout != layout {
        return Err(ProfileError::BodyShape);
    }
    let roles: &[Role] = match layout {
        Layout::Binary => &[Role::Binary],
        Layout::Paired => &[Role::A, Role::T],
    };
    if body.legs.len() != roles.len()
        || body
            .legs
            .iter()
            .zip(roles)
            .any(|(leg, role)| leg.id.act != *id || leg.id.role != *role || leg.removal.is_some())
    {
        return Err(ProfileError::BodyShape);
    }
    if body.legs[0].source
        != (PublicReference::Named {
            namespace: "addr".into(),
            name: id.author.clone(),
        })
        || (layout == Layout::Paired && body.legs[0].target != body.legs[1].source)
    {
        return Err(ProfileError::BodyShape);
    }
    for leg in &body.legs {
        super::reference(&leg.source).map_err(map_shape)?;
        super::reference(&leg.target).map_err(map_shape)?;
    }
    quantities_projection(&structure.quantities, coordinates).map_err(map_shape)?;
    license_projection(id, &body.legs, structure.license.as_ref()).map_err(map_shape)?;
    if structure.asserted_parents.len() > 1024
        || structure
            .asserted_parents
            .iter()
            .any(|parent| !valid_id(parent) || parent == id)
        || structure.asserted_parents.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ProfileError::BodyShape);
    }
    if !body.protocol_references.is_empty() {
        return Err(ProfileError::BodyShape);
    }
    match (&id.family[..], &structure.settlement) {
        ("Accept", Some(pn_records::SettlementReferences::Accept { settles })) if valid_id(settles) => {}
        ("Ratify", Some(pn_records::SettlementReferences::Ratify { settles, accepts }))
            if valid_id(settles) && valid_id(accepts) => {}
        ("Accept" | "Ratify", _) => return Err(ProfileError::BodyShape),
        (_, None) => {}
        _ => return Err(ProfileError::BodyShape),
    }
    Ok(())
}

/// Project the complete typed B3 value.
/// # Errors
/// Refuses an oversized value before its structural predicates.
/// # Panics
/// Panics only if an i64 cannot fit the interchange integer domain.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::body_projection"
    ),
    ret
)]
pub fn body_projection(body: &ProposalBody) -> Result<Value, ProfileError> {
    let value = structural_value(body);
    if value.canonical_len() > BODY_LIMIT {
        return Err(ProfileError::Bound);
    }
    validate_body(body)?;
    Ok(value)
}

fn items(value: &Value) -> Result<&[Value], ProfileError> {
    projection::items(value).map_err(map_shape)
}
fn string(value: &Value) -> Result<&str, ProfileError> {
    projection::string(value).map_err(map_shape)
}
fn id(value: &Value) -> Result<ActId, ProfileError> {
    projection::id(value).map_err(map_shape)
}

fn parse_settlement(value: &Value) -> Result<Option<pn_records::SettlementReferences>, ProfileError> {
    if *value == Value::Null {
        return Ok(None);
    }
    match items(value)? {
        [tag, settles] if string(tag)? == "Accept" => {
            Ok(Some(pn_records::SettlementReferences::Accept { settles: id(settles)? }))
        }
        [tag, settles, accepts] if string(tag)? == "Ratify" => Ok(Some(pn_records::SettlementReferences::Ratify {
            settles: id(settles)?,
            accepts: id(accepts)?,
        })),
        _ => Err(ProfileError::BodyShape),
    }
}

fn parse_body(value: &Value) -> Result<ProposalBody, ProfileError> {
    let [
        identity,
        retirement,
        layout,
        legs,
        quantities,
        license,
        parents,
        protocols,
        settlement,
        extension,
    ] = items(value)?
    else {
        return Err(ProfileError::BodyShape);
    };
    let identity = id(identity)?;
    let Value::Bytes(retirement) = retirement else {
        return Err(ProfileError::BodyShape);
    };
    let retirement_point = retirement.as_slice().try_into().map_err(|_| ProfileError::BodyShape)?;
    let layout = match string(layout)? {
        "binary" => Layout::Binary,
        "paired" => Layout::Paired,
        _ => return Err(ProfileError::BodyShape),
    };
    let legs = items(legs)?
        .iter()
        .map(|value| {
            let [role, source, target] = items(value)? else {
                return Err(ProfileError::BodyShape);
            };
            Ok(CandidateLeg {
                id: pn_records::EdgeId {
                    act: identity.clone(),
                    role: projection::rrole(role).map_err(map_shape)?,
                },
                source: projection::rref(source).map_err(map_shape)?,
                target: projection::rref(target).map_err(map_shape)?,
                removal: None,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let quantities = items(quantities)?
        .iter()
        .map(|value| {
            let [name, amount, unit, vintage] = items(value)? else {
                return Err(ProfileError::BodyShape);
            };
            Ok((
                string(name)?.into(),
                pn_records::Quantity {
                    value: projection::signed(amount).map_err(map_shape)?,
                    unit: string(unit)?.into(),
                    vintage: projection::unsigned(vintage).map_err(map_shape)?,
                },
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let license = if *license == Value::Null {
        None
    } else {
        let [attribution, provenance] = items(license)? else {
            return Err(ProfileError::BodyShape);
        };
        Some(pn_records::LicenseQualifiers {
            attribution: projection::degree(attribution).map_err(map_shape)?,
            provenance: projection::degree(provenance).map_err(map_shape)?,
        })
    };
    let parents = items(parents)?.iter().map(id).collect::<Result<Vec<_>, _>>()?;
    let protocols = items(protocols)?
        .iter()
        .map(|value| projection::rref(value).map_err(map_shape))
        .collect::<Result<Vec<_>, _>>()?;
    let settlement = parse_settlement(settlement)?;
    let Value::Bytes(extension) = extension else {
        return Err(ProfileError::BodyShape);
    };
    Ok(ProposalBody {
        id: identity,
        retirement_point,
        body: StructuralBody {
            layout,
            quantities,
            license,
            settlement,
            asserted_parents: parents,
        },
        legs,
        protocol_references: protocols,
        signed_extension: extension.as_slice().to_vec(),
    })
}

/// Invert a B3 projection after its shape and predicates.
/// # Errors
/// Refuses malformed B3 values in the admitted order.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::body_from_projection"
    ),
    ret
)]
pub fn body_from_projection(value: &Value) -> Result<ProposalBody, ProfileError> {
    if value.canonical_len() > BODY_LIMIT {
        return Err(ProfileError::Bound);
    }
    let body = parse_body(value)?;
    validate_body(&body)?;
    if structural_value(&body) != *value {
        return Err(ProfileError::BodyShape);
    }
    Ok(body)
}

/// Encode B3 as canonical CBOR.
/// # Errors
/// Refuses body bounds or shape.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::encode_body"
    ),
    ret
)]
pub fn encode_body(body: &ProposalBody) -> Result<Vec<u8>, ProfileError> {
    Ok(body_projection(body)?.to_canonical_bytes())
}

/// Decode only a caller-selected B3 body.
/// # Errors
/// Refuses byte, canonical and structural defects.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::decode_body"
    ),
    ret
)]
pub fn decode_body(bytes: &[u8]) -> Result<ProposalBody, ProfileError> {
    if bytes.len() > BODY_LIMIT {
        return Err(ProfileError::Bound);
    }
    let value = Value::from_canonical_bytes(bytes).map_err(|_| ProfileError::Canonical)?;
    body_from_projection(&value)
}

/// Compare a B3 value with independent expected parts.
/// # Errors
/// Refuses shape or unequal complete typed bodies.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::compare_body"
    ),
    ret
)]
pub fn compare_body(body: &ProposalBody, expected_body: &ProposalBody) -> Result<(), ProfileError> {
    body_projection(body)?;
    body_projection(expected_body)?;
    if body != expected_body {
        return Err(ProfileError::Body);
    }
    Ok(())
}

fn frame_hash(recipe: &str, tag: &str, fields: Vec<SecretValue>) -> Result<SecretSlice<u8>, ProfileError> {
    let encoded_value_limit = PREIMAGE_LIMIT - recipe.len() - 1;
    hash_with_limits(recipe, tag, fields, encoded_value_limit, encoded_value_limit + 65_536).map_err(|_| ProfileError::Bound)
}

fn check_author(id: &ActId, value: &SecretSlice<u8>) -> Result<(), ProfileError> {
    author_blinding_value_format(id, value).map_err(|_| ProfileError::Blinding)
}

fn check_host(value: &SecretSlice<u8>) -> Result<(), ProfileError> {
    super::host_blinding_value_format(value).map_err(|_| ProfileError::Blinding)
}

fn dependency_projection(list: &SecretBox<DependencyIds>) -> Result<SecretValue, ProfileError> {
    let (value, count) = super::dependencies(list, None).map_err(|_| ProfileError::Dependencies)?;
    let bytes = value
        .to_secret_canonical_bytes(DEPENDENCY_LIMIT)
        .map_err(|_| ProfileError::Dependencies)?;
    check_dependency_bounds(count, secret_length(&bytes))?;
    Ok(value)
}

fn check_dependency_bounds(count: usize, encoded_bytes: usize) -> Result<(), ProfileError> {
    if count > 1024 || encoded_bytes > DEPENDENCY_LIMIT {
        Err(ProfileError::Dependencies)
    } else {
        Ok(())
    }
}

fn received(id: &ActId, content: &ContentPreDigest, cause: ProfileError) -> Result<SecretValue, ProfileError> {
    if !valid_id(id) || content.act != *id || secret_length(&content.bytes) != 32 {
        return Err(cause);
    }
    Ok(SecretValue::Bytes(content.bytes.clone()))
}

/// Compute the protected hY for a full opening.
/// # Errors
/// Refuses I, author blinding form or the complete preimage bound.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::content_pre_digest"
    ),
    ret
)]
pub fn content_pre_digest(id: &ActId, pair: &ContentPair) -> Result<ContentPreDigest, ProfileError> {
    if !valid_id(id) {
        return Err(ProfileError::Representation);
    }
    check_author(id, &pair.author_content_blinding_value)?;
    let digest = frame_hash(
        PROPOSAL_RECIPE,
        "PN-content-pre-v3",
        vec![
            public(identifier(id)),
            SecretValue::Bytes(pair.author_content_blinding_value.clone()),
            SecretValue::Bytes(pair.payload.clone()),
        ],
    )?;
    Ok(ContentPreDigest {
        act: id.clone(),
        bytes: digest,
    })
}

fn proposal_from_checked(
    body: &ProposalBody,
    projected: Value,
    content: SecretValue,
    author_dependency_blinding_value: &SecretSlice<u8>,
    dependency: SecretValue,
) -> Result<ProposalCommitment, ProfileError> {
    let h_d = frame_hash(
        PROPOSAL_RECIPE,
        "PN-dependency-pre-v3",
        vec![
            public(identifier(&body.id)),
            SecretValue::Bytes(author_dependency_blinding_value.clone()),
            dependency,
        ],
    )?;
    let digest = frame_hash(
        PROPOSAL_RECIPE,
        "PN-act-proposal-v3",
        vec![public(projected), content, SecretValue::Bytes(h_d)],
    )?;
    Ok(ProposalCommitment {
        recipe: PROPOSAL_RECIPE.into(),
        bytes: publish(&digest).map_err(|_| ProfileError::Proposal)?,
    })
}

/// Recompute P from a received hY and complete dependency opening.
/// # Errors
/// Refuses B3, hY, blinding, dependency and preimage defects in order.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::proposal_commitment"
    ),
    ret
)]
pub fn proposal_commitment(
    body: &ProposalBody,
    content_pre_digest: &ContentPreDigest,
    author_dependency_blinding_value: &SecretSlice<u8>,
    dependencies: &SecretBox<DependencyIds>,
) -> Result<ProposalCommitment, ProfileError> {
    let projected = body_projection(body)?;
    let content = received(&body.id, content_pre_digest, ProfileError::ContentPreDigest)?;
    check_author(&body.id, author_dependency_blinding_value)?;
    let dependency = dependency_projection(dependencies)?;
    proposal_from_checked(body, projected, content, author_dependency_blinding_value, dependency)
}

/// Compute P from the Actor's complete private opening.
/// # Errors
/// Refuses B3, blinding, dependency or preimage defects in order.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::computed_proposal_commitment"
    ),
    ret
)]
pub fn computed_proposal_commitment(
    body: &ProposalBody,
    content_pair: &ContentPair,
    author_dependency_blinding_value: &SecretSlice<u8>,
    dependencies: &SecretBox<DependencyIds>,
) -> Result<ComputedProposalCommitment, ProfileError> {
    let projected = body_projection(body)?;
    check_author(&body.id, &content_pair.author_content_blinding_value)?;
    check_author(&body.id, author_dependency_blinding_value)?;
    let dependency = dependency_projection(dependencies)?;
    let content = content_pre_digest(&body.id, content_pair)?;
    let proposal = proposal_from_checked(
        body,
        projected,
        SecretValue::Bytes(content.bytes),
        author_dependency_blinding_value,
        dependency,
    )?;
    Ok(ComputedProposalCommitment(proposal))
}

/// Compare a supplied P on the host route.
/// # Errors
/// Refuses recipe before body and opening defects.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::proposal_matches_supplied_commitment"
    ),
    ret
)]
pub fn proposal_matches_supplied_commitment(
    body: &ProposalBody,
    recorded_proposal: &ProposalCommitment,
    content_pre_digest: &ContentPreDigest,
    author_dependency_blinding_value: &SecretSlice<u8>,
    dependencies: &SecretBox<DependencyIds>,
) -> Result<(), ProfileError> {
    if recorded_proposal.recipe != PROPOSAL_RECIPE {
        return Err(ProfileError::Recipe);
    }
    let computed = proposal_commitment(body, content_pre_digest, author_dependency_blinding_value, dependencies)?;
    if computed != *recorded_proposal {
        return Err(ProfileError::Proposal);
    }
    Ok(())
}

/// Compare a supplied P on the full Actor opening route.
/// # Errors
/// Refuses recipe before body and opening defects.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::computed_proposal_matches_supplied_commitment"
    ),
    ret
)]
pub fn computed_proposal_matches_supplied_commitment(
    body: &ProposalBody,
    recorded_proposal: &ProposalCommitment,
    content_pair: &ContentPair,
    author_dependency_blinding_value: &SecretSlice<u8>,
    dependencies: &SecretBox<DependencyIds>,
) -> Result<(), ProfileError> {
    if recorded_proposal.recipe != PROPOSAL_RECIPE {
        return Err(ProfileError::Recipe);
    }
    let computed = computed_proposal_commitment(body, content_pair, author_dependency_blinding_value, dependencies)?;
    if computed.as_recorded() != recorded_proposal {
        return Err(ProfileError::Proposal);
    }
    Ok(())
}

fn content_from_checked(
    id: &ActId,
    proposal: &ProposalCommitment,
    host_content_blinding_value: &SecretSlice<u8>,
    content: SecretValue,
) -> Result<ContentCommitment, ProfileError> {
    let digest = frame_hash(
        CONTENT_RECIPE,
        "PN-content-v3",
        vec![
            public(identifier(id)),
            public(Value::Bytes(Bytes::from(proposal.bytes.to_vec()))),
            SecretValue::Bytes(host_content_blinding_value.clone()),
            content,
        ],
    )?;
    Ok(ContentCommitment {
        recipe: CONTENT_RECIPE.into(),
        bytes: publish(&digest).map_err(|_| ProfileError::Content)?,
    })
}

/// Construct `C_Y` from a protected received hY.
/// # Errors
/// Refuses recipe, identity, blinding and preimage defects.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::content_commitment"
    ),
    ret
)]
pub fn content_commitment(
    id: &ActId,
    proposal: &ProposalCommitment,
    host_content_blinding_value: &SecretSlice<u8>,
    content_pre_digest: &ContentPreDigest,
) -> Result<ContentCommitment, ProfileError> {
    if proposal.recipe != PROPOSAL_RECIPE {
        return Err(ProfileError::Recipe);
    }
    let content = received(id, content_pre_digest, ProfileError::Representation)?;
    check_host(host_content_blinding_value)?;
    content_from_checked(id, proposal, host_content_blinding_value, content)
}

/// Compare `C_Y` with a complete supplied content opening when available.
/// # Errors
/// Refuses malformed selected recipes and supplied inputs before equality.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::content_matches_supplied_commitment"
    ),
    ret
)]
pub fn content_matches_supplied_commitment(
    id: &ActId,
    proposal: &ProposalCommitment,
    recorded_content: &ContentCommitment,
    host_content_blinding_value: &SecretSlice<u8>,
    content_pair: Option<&ContentPair>,
) -> Result<OpeningComparison, ProfileError> {
    if proposal.recipe != PROPOSAL_RECIPE || recorded_content.recipe != CONTENT_RECIPE {
        return Err(ProfileError::Recipe);
    }
    if !valid_id(id) {
        return Err(ProfileError::Representation);
    }
    if let Some(pair) = content_pair {
        check_author(id, &pair.author_content_blinding_value)?;
    }
    check_host(host_content_blinding_value)?;
    let Some(pair) = content_pair else {
        return Ok(OpeningComparison::Unavailable);
    };
    let content = content_pre_digest(id, pair)?;
    let computed = content_from_checked(id, proposal, host_content_blinding_value, SecretValue::Bytes(content.bytes))?;
    if computed != *recorded_content {
        return Err(ProfileError::Content);
    }
    Ok(OpeningComparison::Matches)
}

/// Construct `C_D` from a complete protected dependency list.
/// # Errors
/// Refuses recipe, identity, blinding and dependency defects.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::dependency_commitment"
    ),
    ret
)]
pub fn dependency_commitment(
    id: &ActId,
    proposal: &ProposalCommitment,
    host_dependency_blinding_value: &SecretSlice<u8>,
    dependencies: &SecretBox<DependencyIds>,
) -> Result<DependencyCommitment, ProfileError> {
    if proposal.recipe != PROPOSAL_RECIPE {
        return Err(ProfileError::Recipe);
    }
    if !valid_id(id) {
        return Err(ProfileError::Representation);
    }
    check_host(host_dependency_blinding_value)?;
    let dependencies = dependency_projection(dependencies)?;
    let digest = frame_hash(
        DEPENDENCY_RECIPE,
        "PN-dependency-v3",
        vec![
            public(identifier(id)),
            public(Value::Bytes(Bytes::from(proposal.bytes.to_vec()))),
            SecretValue::Bytes(host_dependency_blinding_value.clone()),
            dependencies,
        ],
    )?;
    Ok(DependencyCommitment {
        recipe: DEPENDENCY_RECIPE.into(),
        bytes: publish(&digest).map_err(|_| ProfileError::Dependency)?,
    })
}

/// Compare `C_D` with a complete supplied dependency opening when available.
/// # Errors
/// Refuses recipe before an absent opening, then its ordered defects.
#[tracing::instrument(
    name = "def:profile:version-three",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-three",
        source_item = "v3::dependencies_match_supplied_commitment"
    ),
    ret
)]
pub fn dependencies_match_supplied_commitment(
    proposal: &ProposalCommitment,
    recorded_dependency: &DependencyCommitment,
    opening: Option<&super::DependencyOpening>,
) -> Result<OpeningComparison, ProfileError> {
    if proposal.recipe != PROPOSAL_RECIPE || recorded_dependency.recipe != DEPENDENCY_RECIPE {
        return Err(ProfileError::Recipe);
    }
    let Some(opening) = opening else {
        return Ok(OpeningComparison::Unavailable);
    };
    let computed = dependency_commitment(
        &opening.act,
        proposal,
        &opening.host_dependency_blinding_value,
        &opening.dependencies,
    )?;
    if computed != *recorded_dependency {
        return Err(ProfileError::Dependency);
    }
    Ok(OpeningComparison::Matches)
}

/// Carriage-only checks remain separate from closure formation.
pub mod courtesy {
    use super::{ContentPair, ProfileError};

    /// Check the unchanged 65,536-byte carriage bound without admitting a service request.
    /// # Errors
    /// Refuses only an oversized supplied payload.
    #[tracing::instrument(
        name = "def:profile:version-three",
        fields(
            execution_owner = "ACTPROFILE",
            claim_owner = "ACTPROFILE",
            claim_label = "def:profile:version-three",
            source_item = "v3::courtesy::check_payload_bound"
        ),
        ret
    )]
    pub fn check_payload_bound(pair: &ContentPair) -> Result<(), ProfileError> {
        super::super::payload_length(&pair.payload)
            .map(|_| ())
            .map_err(|_| ProfileError::Bound)
    }

    #[cfg(test)]
    mod tests {
        use super::{ContentPair, ProfileError, check_payload_bound};
        use crate::v3::content_pre_digest;
        use pn_records::ActId;

        /// Carriage rejects 65,537 while formation accepts it.
        /// ´claim:profile:version-three-carriage-bound-is-separate´
        /// ´test:unit:payload-bound´
        #[test]
        fn payload_bound() {
            let id = ActId {
                author: format!("pn-devnet-v1/{}/{}", "01".repeat(32), "02".repeat(32)),
                sequence: 0,
                family: "Registration".into(),
            };
            for (len, result) in [(65_536, Ok(())), (65_537, Err(ProfileError::Bound))] {
                let pair = ContentPair {
                    payload: vec![0; len].into(),
                    author_content_blinding_value: vec![0; 40].into(),
                };
                assert_eq!(check_payload_bound(&pair), result);
                assert!(content_pre_digest(&id, &pair).is_ok());
            }
        }
    }
}

#[cfg(test)]
mod tests;
