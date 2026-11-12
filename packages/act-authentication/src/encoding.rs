//! Canonical authentication values; no signature or authority is established.
use pn_act_profile::{CONTENT_RECIPE, DEPENDENCY_RECIPE, PROPOSAL_RECIPE, ProposalBody};
use pn_interchange::{Array, Map, Value};
use pn_records::authentication::AuthenticationFields;
use pn_records::commitments::{ActCommitments, ContentCommitment, DependencyCommitment, ProposalCommitment};

/// The sole admitted authentication interpretation. (´def:authentication:encoding´)
pub const AUTHENTICATION_EDITION: &str = "pn-act-authentication/author-token-bip340/v1";
const HEADER_NAMESPACE: &str = "org.peer-network.test.verified-act";
// The profile bounds B at 1,048,576 bytes; fixed header fields add fewer than
// 512. The admitted ceiling and derivation are in def:identity:verified-header-name.
const BYTE_LIMIT: usize = 2_097_152;

/// Representation and comparison refusals, not signature verdicts. (´def:authentication:encoding´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodingError {
    #[error("noncanonical encoding")]
    Canonical,
    #[error("verified header bytes differ")]
    HeaderBytes,
    #[error("representation bound exceeded")]
    Bound,
    #[error("unsupported authentication edition")]
    Edition,
    #[error("invalid authentication shape")]
    Shape,
    #[error("unsupported commitment recipe")]
    Recipe,
    #[error("proposal body differs")]
    Body,
    #[error("proposal commitment differs")]
    Proposal,
    #[error("content commitment differs")]
    Content,
    #[error("dependency commitment differs")]
    Dependency,
    #[error("Actor signature differs")]
    ActorSignature,
    #[error("content edition differs")]
    ContentEdition,
    #[error("dependency edition differs")]
    DependencyEdition,
}

/// Original authored values and retained public commitments. (´def:authentication:encoding´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderParts {
    pub body: ProposalBody,
    pub commitments: ActCommitments,
    pub actor_signature: [u8; 64],
    pub content_edition: String,
    pub dependency_edition: String,
}

/// Decoded parts beside the exact supplied canonical bytes. (´def:authentication:encoding´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHeader {
    parts: HeaderParts,
    bytes: Vec<u8>,
}
impl VerifiedHeader {
    /// Justified: Immutable access inherits the checked encoding boundary.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:encoding",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:encoding",
            operation = "verifiedheader-parts",
            source_item = "encoding::VerifiedHeader::parts"
        ),
        ret
    )]
    pub fn parts(&self) -> &HeaderParts {
        &self.parts
    }
    /// Justified: Immutable access preserves the supplied canonical representation.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:encoding",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:encoding",
            operation = "verifiedheader-bytes",
            source_item = "encoding::VerifiedHeader::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(super) fn text(s: &str) -> Value {
    Value::Text(s.to_owned().into())
}
pub(super) fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec().into())
}
pub(super) fn array(v: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(v))
}
pub(super) fn items(v: &Value) -> Result<&[Value], EncodingError> {
    match v {
        Value::Array(a) => Ok(a.as_slice()),
        _ => Err(EncodingError::Shape),
    }
}
pub(super) fn string(v: &Value) -> Result<&str, EncodingError> {
    match v {
        Value::Text(t) => Ok(t.as_str()),
        _ => Err(EncodingError::Shape),
    }
}
pub(super) fn fixed<const N: usize>(v: &Value) -> Result<[u8; N], EncodingError> {
    match v {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| EncodingError::Shape),
        _ => Err(EncodingError::Shape),
    }
}
pub(super) fn canonical(input: &[u8]) -> Result<Value, EncodingError> {
    if input.len() > BYTE_LIMIT {
        return Err(EncodingError::Bound);
    }
    Value::from_canonical_bytes(input).map_err(|_| EncodingError::Canonical)
}
fn pair(recipe: &str, digest: &[u8; 32]) -> Value {
    array([text(recipe), bytes(digest)])
}
fn read_pair(v: &Value, expected: &str) -> Result<[u8; 32], EncodingError> {
    let [recipe, digest] = items(v)? else {
        return Err(EncodingError::Shape);
    };
    if string(recipe)? != expected {
        return Err(EncodingError::Recipe);
    }
    fixed(digest)
}
fn header_value(parts: &HeaderParts) -> Result<Value, EncodingError> {
    if parts.content_edition != "1" || parts.dependency_edition != "1" {
        return Err(EncodingError::Edition);
    }
    let ActCommitments {
        proposal,
        content,
        dependency,
    } = &parts.commitments;
    if proposal.recipe != PROPOSAL_RECIPE || content.recipe != CONTENT_RECIPE || dependency.recipe != DEPENDENCY_RECIPE {
        return Err(EncodingError::Recipe);
    }
    let body = pn_act_profile::body_projection(&parts.body).map_err(|_| EncodingError::Body)?;
    let fields = [
        text(HEADER_NAMESPACE),
        array([Value::Unsigned(1), Value::Unsigned(0), Value::Unsigned(0)]),
        body,
        pair(PROPOSAL_RECIPE, &proposal.bytes),
        bytes(&parts.actor_signature),
        pair(CONTENT_RECIPE, &content.bytes),
        pair(DEPENDENCY_RECIPE, &dependency.bytes),
        text(&parts.content_edition),
        text(&parts.dependency_edition),
    ];
    Map::new((0_u64..).zip(fields).map(|(i, v)| (Value::Unsigned(i), v)))
        .map(Value::Map)
        .map_err(|_| EncodingError::Shape)
}

/// Encode original typed parts, without signing or admitting the act.
/// # Errors
/// Refuses unsupported editions, recipes and proposal representations.
/// # Panics
/// Panics only if an i64 does not fit the wider interchange integer domain.
/// (´def:authentication:encoding´)
#[tracing::instrument(
    name = "def:authentication:encoding",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:encoding",
        operation = "encode-header",
        source_item = "encoding::encode_header"
    ),
    ret
)]
pub fn encode_header(parts: &HeaderParts) -> Result<VerifiedHeader, EncodingError> {
    let value = header_value(parts)?;
    let bytes = value.to_canonical_bytes();
    if bytes.len() > BYTE_LIMIT {
        return Err(EncodingError::Bound);
    }
    Ok(VerifiedHeader {
        parts: parts.clone(),
        bytes,
    })
}

/// Decode only the unique admitted header and retain its exact input bytes.
/// # Errors
/// Refuses noncanonical input, wrong keys, shape, editions and recipes.
/// # Panics
/// Panics only if an i64 does not fit the wider interchange integer domain.
/// (´def:authentication:encoding´)
#[tracing::instrument(
    name = "def:authentication:encoding",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:encoding",
        operation = "decode-header",
        source_item = "encoding::decode_header"
    ),
    ret
)]
pub fn decode_header(input: &[u8]) -> Result<VerifiedHeader, EncodingError> {
    let value = canonical(input)?;
    let Value::Map(map) = &value else {
        return Err(EncodingError::Shape);
    };
    let fields: Vec<_> = map.iter().collect();
    if fields.len() != 9 || fields.iter().zip(0_u64..).any(|((k, _), i)| **k != Value::Unsigned(i)) {
        return Err(EncodingError::Shape);
    }
    let f = |i: usize| fields[i].1;
    if string(f(0))? != HEADER_NAMESPACE {
        return Err(EncodingError::Shape);
    }
    if f(1) != &array([Value::Unsigned(1), Value::Unsigned(0), Value::Unsigned(0)]) {
        return Err(EncodingError::Edition);
    }
    let parts = HeaderParts {
        body: pn_act_profile::body_from_projection(f(2)).map_err(|_| EncodingError::Body)?,
        commitments: ActCommitments {
            proposal: ProposalCommitment {
                recipe: PROPOSAL_RECIPE.into(),
                bytes: read_pair(f(3), PROPOSAL_RECIPE)?,
            },
            content: ContentCommitment {
                recipe: CONTENT_RECIPE.into(),
                bytes: read_pair(f(5), CONTENT_RECIPE)?,
            },
            dependency: DependencyCommitment {
                recipe: DEPENDENCY_RECIPE.into(),
                bytes: read_pair(f(6), DEPENDENCY_RECIPE)?,
            },
        },
        actor_signature: fixed(f(4))?,
        content_edition: string(f(7))?.into(),
        dependency_edition: string(f(8))?.into(),
    };
    if header_value(&parts)? != value {
        return Err(EncodingError::Shape);
    }
    Ok(VerifiedHeader {
        parts,
        bytes: input.to_vec(),
    })
}

/// Public disclosed keys; these bytes are not parsed curve points. (´def:authentication:encoding´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationMaterial {
    pub run: [u8; 32],
    pub actor_key: [u8; 32],
    pub host_identity: String,
    pub host_key: [u8; 32],
}
pub(crate) fn host(identity: &str) -> bool {
    identity
        .strip_prefix("pn-host-bip340-v1/")
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}
/// Encode the sole edition; key validity and configured authority are separate.
/// # Errors
/// Refuses a malformed host identity.
/// (´def:authentication:encoding´)
#[tracing::instrument(
    name = "def:authentication:encoding",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:encoding",
        operation = "encode-material",
        source_item = "encoding::encode_material"
    ),
    ret
)]
pub fn encode_material(material: &AuthenticationMaterial) -> Result<Vec<u8>, EncodingError> {
    if !host(&material.host_identity) {
        return Err(EncodingError::Shape);
    }
    Ok(array([
        text(AUTHENTICATION_EDITION),
        bytes(&material.run),
        bytes(&material.actor_key),
        text(&material.host_identity),
        bytes(&material.host_key),
    ])
    .to_canonical_bytes())
}
/// Decode and compare the separately retained edition before exposing material.
/// # Errors
/// Refuses noncanonical, unsupported or malformed material without aliases.
/// (´def:authentication:encoding´)
#[tracing::instrument(
    name = "def:authentication:encoding",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:encoding",
        operation = "decode-material",
        source_item = "encoding::decode_material"
    ),
    ret
)]
pub fn decode_material(input: &[u8], edition: &str) -> Result<AuthenticationMaterial, EncodingError> {
    if edition != AUTHENTICATION_EDITION {
        return Err(EncodingError::Edition);
    }
    let value = canonical(input)?;
    let [e, run, actor_key, host_identity, host_key] = items(&value)? else {
        return Err(EncodingError::Shape);
    };
    if string(e)? != edition {
        return Err(EncodingError::Edition);
    }
    let result = AuthenticationMaterial {
        run: fixed(run)?,
        actor_key: fixed(actor_key)?,
        host_identity: string(host_identity)?.into(),
        host_key: fixed(host_key)?,
    };
    if !host(&result.host_identity) {
        return Err(EncodingError::Shape);
    }
    Ok(result)
}

/// Compare decoded values with independently supplied original parts and disclosure.
/// Original requests must not be inferred from subsequent removal states.
/// # Errors
/// Returns the first distinct field mismatch; it verifies no signature.
/// (´def:authentication:encoding´)
#[tracing::instrument(
    name = "def:authentication:encoding",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:encoding",
        operation = "compare-header",
        source_item = "encoding::compare_header"
    ),
    ret
)]
pub fn compare_header(
    header: &VerifiedHeader,
    expected: &HeaderParts,
    disclosure: &AuthenticationFields,
) -> Result<(), EncodingError> {
    let actual = &header.parts;
    if actual.body != expected.body {
        return Err(EncodingError::Body);
    }
    if actual.commitments.proposal != expected.commitments.proposal
        || actual.commitments.proposal.bytes.as_slice() != disclosure.proposal_precommitment
    {
        return Err(EncodingError::Proposal);
    }
    if actual.commitments.content != expected.commitments.content {
        return Err(EncodingError::Content);
    }
    if actual.commitments.dependency != expected.commitments.dependency {
        return Err(EncodingError::Dependency);
    }
    if actual.actor_signature != expected.actor_signature
        || actual.actor_signature.as_slice() != disclosure.actor_proposal_signature
    {
        return Err(EncodingError::ActorSignature);
    }
    if actual.content_edition != expected.content_edition || actual.content_edition != disclosure.content_edition {
        return Err(EncodingError::ContentEdition);
    }
    if actual.dependency_edition != expected.dependency_edition || actual.dependency_edition != disclosure.dependency_edition {
        return Err(EncodingError::DependencyEdition);
    }
    if header.bytes != disclosure.verified_header {
        return Err(EncodingError::HeaderBytes);
    }
    decode_material(&disclosure.public_verification_material, &disclosure.authentication_edition)?;
    Ok(())
}

/// Compare the header with the immutable fields and disclosure of its act.
/// Current removal states and final placement are not authored proposal fields;
/// original requests remain in V and are compared separately when the original
/// proposal is available through `compare_header`.
/// # Errors
/// Refuses a missing commitment or any differing retained field.
/// (´def:authentication:encoding´)
#[tracing::instrument(
    name = "def:authentication:encoding",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:encoding",
        operation = "compare-act",
        source_item = "encoding::compare_act"
    ),
    ret
)]
pub fn compare_act(header: &VerifiedHeader, act: &pn_records::CandidateAct) -> Result<(), EncodingError> {
    let disclosure = &act.authentication_evidence;
    let expected = HeaderParts {
        body: ProposalBody {
            id: act.id.clone(),
            body: act.body.clone(),
            legs: act.legs.clone(),
            protocol_references: act.protocol_references.clone(),
            content: header.parts.body.content,
            dependency: header.parts.body.dependency,
        },
        commitments: act.commitments.clone().ok_or(EncodingError::Proposal)?,
        actor_signature: disclosure
            .actor_proposal_signature
            .as_slice()
            .try_into()
            .map_err(|_| EncodingError::ActorSignature)?,
        content_edition: disclosure.content_edition.clone(),
        dependency_edition: disclosure.dependency_edition.clone(),
    };
    compare_header(header, &expected, disclosure)
}
