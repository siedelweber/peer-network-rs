//! Independent-nonce proposal and supplied-opening recipes.
//! (´def:profile:version-two´)
use super::{
    ContentRequest, DependencyIds, DependencyOpening, DependencyRequest, ProfileError, array, dependencies, hash, identifier,
    nonce_format, payload_length, public, publish, salt_format, valid_id,
};
use pn_interchange::{Bytes, SecretValue, Value};
use pn_records::ActId;
use pn_records::commitments::{ContentCommitment, DependencyCommitment, ProposalCommitment};
use secrecy::{ExposeSecret, SecretBox, SecretSlice};

/// Immutable second-edition proposal recipe. (´def:profile:version-two´)
pub const PROPOSAL_RECIPE: &str = "pn-act-profile/act-proposal/v2";
/// Immutable second-edition content recipe. (´def:profile:version-two´)
pub const CONTENT_RECIPE: &str = "pn-act-profile/act-content/v2";
/// Immutable second-edition dependency recipe. (´def:profile:version-two´)
pub const DEPENDENCY_RECIPE: &str = "pn-act-profile/act-dependency/v2";

/// The structural proposal and its separate handshake retirement point.
/// The point never enters `ActId` equality. (´def:profile:version-two´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalBody {
    pub structural: super::ProposalBody,
    pub retirement_point: [u8; 32],
}

/// Optional carriage is this whole pair, never payload bytes alone.
/// (´def:profile:version-two´)
#[derive(Debug)]
pub struct ContentPair {
    pub payload: SecretSlice<u8>,
    pub nonce: SecretSlice<u8>,
}

/// Opaque, secret-owned content pre-digest supplied on the proposal path.
/// Its presence does not prove an opening exists. (´def:profile:version-two´)
#[derive(Debug)]
pub struct ContentPreDigest {
    pub act: ActId,
    pub bytes: SecretSlice<u8>,
}

/// A proposal computed with the Actor's two complete private openings.
/// (´def:profile:version-two´)
#[derive(Debug)]
pub struct ComputedProposalCommitment(ProposalCommitment);

impl ComputedProposalCommitment {
    /// Borrow the public result without an opening or authority claim.
    /// (´def:profile:version-two´)
    #[must_use]
    #[tracing::instrument(
        name = "def:profile:version-two",
        fields(
            execution_owner = "ACTPROFILE",
            claim_owner = "ACTPROFILE",
            claim_label = "def:profile:version-two",
            source_item = "v2::ComputedProposalCommitment::as_recorded"
        ),
        ret
    )]
    pub fn as_recorded(&self) -> &ProposalCommitment {
        &self.0
    }
}

/// Project the eleven-element B without changing its structural components.
/// # Errors
/// Refuses the same structural and byte bounds as the original projection.
/// # Panics
/// Panics only if an i64 cannot fit the wider interchange integer domain.
/// (´def:profile:version-two´)
#[tracing::instrument(
    name = "def:profile:version-two",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-two",
        source_item = "v2::body_projection"
    ),
    ret
)]
pub fn body_projection(body: &ProposalBody) -> Result<Value, ProfileError> {
    let Value::Array(original) = super::body_projection(&body.structural)? else {
        return Err(ProfileError::Representation);
    };
    let mut fields = original.as_slice().to_vec();
    fields.insert(1, Value::Bytes(Bytes::from(body.retirement_point.to_vec())));
    let result = array(fields);
    if result.canonical_len() > 1_048_576 {
        return Err(ProfileError::Bound);
    }
    Ok(result)
}

/// Decode exactly the second-edition body, never infer an absent point.
/// # Errors
/// Refuses missing, extra, malformed or out-of-bound fields.
/// # Panics
/// Panics only if an i64 cannot fit the wider interchange integer domain.
/// (´def:profile:version-two´)
#[tracing::instrument(
    name = "def:profile:version-two",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-two",
        source_item = "v2::body_from_projection"
    ),
    ret
)]
pub fn body_from_projection(value: &Value) -> Result<ProposalBody, ProfileError> {
    let Value::Array(fields) = value else {
        return Err(ProfileError::Representation);
    };
    if fields.as_slice().len() != 11 {
        return Err(ProfileError::Representation);
    }
    let Value::Bytes(point) = &fields.as_slice()[1] else {
        return Err(ProfileError::Representation);
    };
    let retirement_point = point.as_slice().try_into().map_err(|_| ProfileError::Representation)?;
    let original = array(
        fields
            .as_slice()
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, value)| value.clone()),
    );
    let body = ProposalBody {
        structural: super::body_from_projection(&original)?,
        retirement_point,
    };
    if body_projection(&body)? != *value {
        return Err(ProfileError::Representation);
    }
    Ok(body)
}

fn anchor(p: &ProposalCommitment) -> Result<SecretValue, ProfileError> {
    if p.recipe != PROPOSAL_RECIPE {
        return Err(ProfileError::Recipe);
    }
    Ok(public(Value::Bytes(Bytes::from(p.bytes.to_vec()))))
}

fn received(id: &ActId, content: &ContentPreDigest) -> Result<SecretValue, ProfileError> {
    if !valid_id(id) || content.act != *id || payload_length(&content.bytes)? != 32 {
        return Err(ProfileError::Representation);
    }
    Ok(SecretValue::Bytes(content.bytes.clone()))
}

// Caveat: The received content pre-digest is borrowed only for a fixed-width equality check; no byte leaves the comparison; this item-local exit remains until a workspace-owned container offers verdict-only equality, and a second comparison site must use that container without adding a new borrow pair; container ownership is a separate decision.
// (´[ROOT-cav:observe:secret-profile-received-content]´)
// Caveat: The recomputed content pre-digest is borrowed only for a fixed-width equality check; no byte leaves the comparison; this item-local exit remains until a workspace-owned container offers verdict-only equality, and a second comparison site must use that container without adding a new borrow pair; container ownership is a separate decision.
// (´[ROOT-cav:observe:secret-profile-recomputed-content]´)
// Justified: Carriage compares secret pre-digests directly and returns only equality after checking all thirty-two bytes; this item-local exit lasts until a workspace-owned container offers verdict-only equality, and a second comparison site must use that container without a new borrow pair; ownership is not selected here.
#[allow(clippy::disallowed_methods)]
fn same_content(left: &SecretSlice<u8>, right: &SecretSlice<u8>) -> bool {
    let left = left.expose_secret(/* (´[ROOT-cav:observe:secret-profile-received-content]´) */);
    let right = right.expose_secret(/* (´[ROOT-cav:observe:secret-profile-recomputed-content]´) */);
    left.len() == 32 && right.len() == 32 && left.iter().zip(right).fold(0_u8, |difference, (a, b)| difference | (a ^ b)) == 0
}

/// Check optional carriage independently of act verification; absence is false.
/// A matching pair establishes neither freshness nor entropy nor custody.
/// # Errors
/// Refuses malformed, nonempty full-empty or unequal supplied content pairs.
/// (´def:profile:version-two´)
#[tracing::instrument(
    name = "def:profile:version-two",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-two",
        source_item = "v2::content_pair_matches"
    ),
    ret
)]
pub fn content_pair_matches(
    body: &ProposalBody,
    content: &ContentPreDigest,
    pair: Option<&ContentPair>,
) -> Result<bool, ProfileError> {
    received(&body.structural.id, content)?;
    let Some(pair) = pair else {
        return Ok(false);
    };
    if body.structural.content == ContentRequest::FullEmpty && payload_length(&pair.payload)? != 0 {
        return Err(ProfileError::Representation);
    }
    let recomputed = content_pre_digest(&body.structural.id, pair)?;
    if !same_content(&content.bytes, &recomputed.bytes) {
        return Err(ProfileError::Mismatch);
    }
    Ok(true)
}

/// Compute hY while retaining it in a secret carrier.
/// # Errors
/// Refuses malformed identity, nonce format or payload bounds.
/// (´def:profile:version-two´)
#[tracing::instrument(
    name = "def:profile:version-two",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-two",
        source_item = "v2::content_pre_digest"
    ),
    ret
)]
pub fn content_pre_digest(id: &ActId, pair: &ContentPair) -> Result<ContentPreDigest, ProfileError> {
    if !valid_id(id) {
        return Err(ProfileError::Representation);
    }
    nonce_format(id, &pair.nonce)?;
    payload_length(&pair.payload)?;
    Ok(ContentPreDigest {
        act: id.clone(),
        bytes: hash(
            PROPOSAL_RECIPE,
            "PN-content-pre-v2",
            vec![
                public(identifier(id)),
                SecretValue::Bytes(pair.nonce.clone()),
                SecretValue::Bytes(pair.payload.clone()),
            ],
        )?,
    })
}

/// Recompute P without inspecting or requiring an optional content pair.
/// # Errors
/// Refuses malformed body, hY scope, dependency nonce/list or request mismatch.
/// # Panics
/// Panics only if an i64 cannot fit the wider interchange integer domain.
/// (´def:profile:version-two´)
#[tracing::instrument(
    name = "def:profile:version-two",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-two",
        source_item = "v2::proposal_commitment"
    ),
    ret
)]
pub fn proposal_commitment(
    body: &ProposalBody,
    content: &ContentPreDigest,
    nonce: &SecretSlice<u8>,
    list: &SecretBox<DependencyIds>,
) -> Result<ProposalCommitment, ProfileError> {
    let projected = body_projection(body)?;
    let id = &body.structural.id;
    nonce_format(id, nonce)?;
    let (dependencies, count) = dependencies(list, Some(id))?;
    if body.structural.dependency == DependencyRequest::FullEmpty && count != 0 {
        return Err(ProfileError::Representation);
    }
    let content = received(id, content)?;
    let dependency = hash(
        PROPOSAL_RECIPE,
        "PN-dependency-pre-v2",
        vec![public(identifier(id)), SecretValue::Bytes(nonce.clone()), dependencies],
    )?;
    let digest = hash(
        PROPOSAL_RECIPE,
        "PN-act-proposal-v2",
        vec![public(projected), content, SecretValue::Bytes(dependency)],
    )?;
    Ok(ProposalCommitment {
        recipe: PROPOSAL_RECIPE.into(),
        bytes: publish(&digest)?,
    })
}

/// Compute the Actor's P from independently supplied content/dependency nonces.
/// No entropy, freshness or generation claim follows from supplied values.
/// # Errors
/// Refuses the proposal and content-pair representation bounds.
/// # Panics
/// Panics only if an i64 cannot fit the wider interchange integer domain.
/// (´def:profile:version-two´)
#[tracing::instrument(
    name = "def:profile:version-two",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-two",
        source_item = "v2::computed_proposal_commitment"
    ),
    ret
)]
pub fn computed_proposal_commitment(
    body: &ProposalBody,
    pair: &ContentPair,
    dependency_nonce: &SecretSlice<u8>,
    list: &SecretBox<DependencyIds>,
) -> Result<ComputedProposalCommitment, ProfileError> {
    if body.structural.content == ContentRequest::FullEmpty && payload_length(&pair.payload)? != 0 {
        return Err(ProfileError::Representation);
    }
    let content = content_pre_digest(&body.structural.id, pair)?;
    proposal_commitment(body, &content, dependency_nonce, list).map(ComputedProposalCommitment)
}

/// Form `C_Y` from opaque hY, identically with or without content carriage.
/// # Errors
/// Refuses malformed identity, salt, hY or a non-v2 proposal recipe.
/// (´def:profile:version-two´)
#[tracing::instrument(
    name = "def:profile:version-two",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-two",
        source_item = "v2::content_commitment"
    ),
    ret
)]
pub fn content_commitment(
    id: &ActId,
    proposal: &ProposalCommitment,
    salt: &SecretSlice<u8>,
    content: &ContentPreDigest,
) -> Result<ContentCommitment, ProfileError> {
    salt_format(salt)?;
    let digest = hash(
        CONTENT_RECIPE,
        "PN-content-v2",
        vec![
            public(identifier(id)),
            anchor(proposal)?,
            SecretValue::Bytes(salt.clone()),
            received(id, content)?,
        ],
    )?;
    Ok(ContentCommitment {
        recipe: CONTENT_RECIPE.into(),
        bytes: publish(&digest)?,
    })
}

/// Check the content pair against a supplied retained `C_Y`.
/// A refusal concerns carriage only; it is not an act-admission verdict.
/// # Errors
/// Refuses malformed or mismatching content openings and recipe substitutions.
/// (´def:profile:version-two´)
#[tracing::instrument(
    name = "def:profile:version-two",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-two",
        source_item = "v2::content_matches_supplied_commitment"
    ),
    ret
)]
pub fn content_matches_supplied_commitment(
    id: &ActId,
    proposal: &ProposalCommitment,
    recorded: &ContentCommitment,
    salt: &SecretSlice<u8>,
    pair: &ContentPair,
) -> Result<(), ProfileError> {
    if recorded.recipe != CONTENT_RECIPE {
        return Err(ProfileError::Recipe);
    }
    let content = content_pre_digest(id, pair)?;
    if content_commitment(id, proposal, salt, &content)? != *recorded {
        return Err(ProfileError::Mismatch);
    }
    Ok(())
}

/// Form `C_D` from the canonical dependency list with its supplied host salt.
/// # Errors
/// Refuses malformed identity, salt, list or a non-v2 proposal recipe.
/// (´def:profile:version-two´)
#[tracing::instrument(
    name = "def:profile:version-two",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-two",
        source_item = "v2::dependency_commitment"
    ),
    ret
)]
pub fn dependency_commitment(
    id: &ActId,
    proposal: &ProposalCommitment,
    salt: &SecretSlice<u8>,
    list: &SecretBox<DependencyIds>,
) -> Result<DependencyCommitment, ProfileError> {
    if !valid_id(id) {
        return Err(ProfileError::Representation);
    }
    salt_format(salt)?;
    let (list, _) = dependencies(list, None)?;
    let digest = hash(
        DEPENDENCY_RECIPE,
        "PN-dependency-v2",
        vec![
            public(identifier(id)),
            anchor(proposal)?,
            SecretValue::Bytes(salt.clone()),
            list,
        ],
    )?;
    Ok(DependencyCommitment {
        recipe: DEPENDENCY_RECIPE.into(),
        bytes: publish(&digest)?,
    })
}

/// Compare the complete three-part dependency opening with supplied anchors.
/// This establishes no anchor authenticity or finalized placement verdict.
/// # Errors
/// Refuses malformed openings, unsupported recipes or unequal residues.
/// (´def:profile:version-two´)
#[tracing::instrument(
    name = "def:profile:version-two",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:version-two",
        source_item = "v2::dependencies_match_supplied_commitment"
    ),
    ret
)]
pub fn dependencies_match_supplied_commitment(
    opening: &DependencyOpening,
    proposal: &ProposalCommitment,
    recorded: &DependencyCommitment,
) -> Result<(), ProfileError> {
    if recorded.recipe != DEPENDENCY_RECIPE {
        return Err(ProfileError::Recipe);
    }
    if dependency_commitment(&opening.act, proposal, &opening.salt, &opening.dependencies)? != *recorded {
        return Err(ProfileError::Mismatch);
    }
    Ok(())
}
