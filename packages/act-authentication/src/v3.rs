//! Caller-selected third authentication representation and role messages.
//! No encoding comparison establishes a signature or authority.
//! (´def:authentication:version-three´)
use pn_act_profile::v3 as profile;
use pn_interchange::{Array, Bytes, Map, Value};
use pn_records::ActId;
use pn_records::commitments::{ActCommitments, ContentCommitment, DependencyCommitment, ProposalCommitment};

/// Immutable third authentication edition.
pub const AUTHENTICATION_EDITION: &str = "pn-act-authentication/author-token-bip340/v3";
const HEADER_NAMESPACE: &str = "org.peer-network.test.verified-act";
const HEADER_LIMIT: usize = 2_097_152;
const MATERIAL_LIMIT: usize = 512;

/// Refusals of the selected third representation, not signature verdicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodingError {
    #[error("representation bound exceeded")]
    Bound,
    #[error("noncanonical encoding")]
    Canonical,
    #[error("invalid shape")]
    Shape,
    #[error("unsupported edition")]
    Edition,
    #[error("unsupported recipe")]
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
    #[error("complete header bytes differ")]
    HeaderBytes,
    #[error("selected run differs")]
    Run,
    #[error("selected host differs")]
    Host,
    #[error("profile: {0}")]
    Profile(profile::ProfileError),
}

/// Public B3, residues and signing-boundary fields, without authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderParts {
    pub body: profile::ProposalBody,
    pub commitments: ActCommitments,
    pub actor_signature: [u8; 64],
    pub content_edition: String,
    pub dependency_edition: String,
}

/// Encoding-checked header; “verified” does not mean a signature was checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHeader {
    parts: HeaderParts,
    bytes: Vec<u8>,
}
impl VerifiedHeader {
    /// Immutable, structurally checked parts.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:version-three",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:version-three",
            source_item = "v3::VerifiedHeader::parts"
        ),
        ret
    )]
    pub fn parts(&self) -> &HeaderParts {
        &self.parts
    }
    /// Exact supplied canonical bytes.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:version-three",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:version-three",
            source_item = "v3::VerifiedHeader::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Public material selected by an independent run and host context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationMaterial {
    pub run: [u8; 32],
    pub actor_key: [u8; 32],
    pub host_identity: String,
    pub host_key: [u8; 32],
}

/// Independently selected expectations for the public material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterialContext {
    pub selected_run: [u8; 32],
    pub act: ActId,
    pub expected_host: String,
    pub header_version: [u64; 3],
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned().into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(Bytes::from(value.to_vec()))
}
fn array(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(values))
}
fn items(value: &Value) -> Result<&[Value], EncodingError> {
    let Value::Array(values) = value else {
        return Err(EncodingError::Shape);
    };
    Ok(values.as_slice())
}
fn string(value: &Value) -> Result<&str, EncodingError> {
    let Value::Text(value) = value else {
        return Err(EncodingError::Shape);
    };
    Ok(value.as_str())
}
fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], EncodingError> {
    let Value::Bytes(value) = value else {
        return Err(EncodingError::Shape);
    };
    value.as_slice().try_into().map_err(|_| EncodingError::Shape)
}
fn canonical(input: &[u8], limit: usize) -> Result<Value, EncodingError> {
    if input.len() > limit {
        return Err(EncodingError::Bound);
    }
    Value::from_canonical_bytes(input).map_err(|_| EncodingError::Canonical)
}
fn pair(recipe: &str, digest: &[u8; 32]) -> Value {
    array([text(recipe), bytes(digest)])
}
fn read_pair(value: &Value, recipe: &str) -> Result<[u8; 32], EncodingError> {
    let [actual, digest] = items(value)? else {
        return Err(EncodingError::Shape);
    };
    if string(actual)? != recipe {
        return Err(EncodingError::Recipe);
    }
    fixed(digest)
}
fn header_value(parts: &HeaderParts) -> Result<Value, EncodingError> {
    let body = profile::body_projection(&parts.body).map_err(EncodingError::Profile)?;
    let ActCommitments {
        proposal,
        content,
        dependency,
    } = &parts.commitments;
    if proposal.recipe != profile::PROPOSAL_RECIPE
        || content.recipe != profile::CONTENT_RECIPE
        || dependency.recipe != profile::DEPENDENCY_RECIPE
    {
        return Err(EncodingError::Recipe);
    }
    if parts.content_edition != "3" {
        return Err(EncodingError::ContentEdition);
    }
    if parts.dependency_edition != "3" {
        return Err(EncodingError::DependencyEdition);
    }
    Map::new(
        (0_u64..)
            .zip([
                text(HEADER_NAMESPACE),
                array([Value::Unsigned(3), Value::Unsigned(0), Value::Unsigned(0)]),
                body,
                pair(profile::PROPOSAL_RECIPE, &proposal.bytes),
                bytes(&parts.actor_signature),
                pair(profile::CONTENT_RECIPE, &content.bytes),
                pair(profile::DEPENDENCY_RECIPE, &dependency.bytes),
                text(&parts.content_edition),
                text(&parts.dependency_edition),
            ])
            .map(|(index, value)| (Value::Unsigned(index), value)),
    )
    .map(Value::Map)
    .map_err(|_| EncodingError::Shape)
}

/// Construct only the selected major-three canonical header.
/// # Errors
/// Refuses body, recipe or edition defects and the header byte limit.
/// # Panics
/// Panics only if an i64 cannot fit the interchange integer domain.
#[tracing::instrument(
    name = "def:authentication:version-three",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:version-three",
        source_item = "v3::encode_header"
    ),
    ret
)]
pub fn encode_header(parts: &HeaderParts) -> Result<VerifiedHeader, EncodingError> {
    let encoded = header_value(parts)?.to_canonical_bytes();
    if encoded.len() > HEADER_LIMIT {
        return Err(EncodingError::Bound);
    }
    Ok(VerifiedHeader {
        parts: parts.clone(),
        bytes: encoded,
    })
}

/// Decode a major-three header without selecting an edition from its bytes.
/// # Errors
/// Refuses byte ceiling, canonical form, closed shape and ordered fields.
/// # Panics
/// Panics only if an i64 cannot fit the interchange integer domain.
#[tracing::instrument(
    name = "def:authentication:version-three",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:version-three",
        source_item = "v3::decode_header"
    ),
    ret
)]
pub fn decode_header(input: &[u8]) -> Result<VerifiedHeader, EncodingError> {
    let value = canonical(input, HEADER_LIMIT)?;
    let Value::Map(map) = &value else {
        return Err(EncodingError::Shape);
    };
    let fields: Vec<_> = map.iter().collect();
    if fields.len() != 9
        || fields
            .iter()
            .zip(0_u64..)
            .any(|((key, _), index)| **key != Value::Unsigned(index))
    {
        return Err(EncodingError::Shape);
    }
    let field = |index: usize| fields[index].1;
    if !matches!(field(0), Value::Text(namespace) if namespace.as_str() == HEADER_NAMESPACE) {
        return Err(EncodingError::Edition);
    }
    if field(1) != &array([Value::Unsigned(3), Value::Unsigned(0), Value::Unsigned(0)]) {
        return Err(EncodingError::Edition);
    }
    let body = profile::body_from_projection(field(2)).map_err(EncodingError::Profile)?;
    let proposal = ProposalCommitment {
        recipe: profile::PROPOSAL_RECIPE.into(),
        bytes: read_pair(field(3), profile::PROPOSAL_RECIPE)?,
    };
    let actor_signature = fixed(field(4))?;
    let content = ContentCommitment {
        recipe: profile::CONTENT_RECIPE.into(),
        bytes: read_pair(field(5), profile::CONTENT_RECIPE)?,
    };
    let dependency = DependencyCommitment {
        recipe: profile::DEPENDENCY_RECIPE.into(),
        bytes: read_pair(field(6), profile::DEPENDENCY_RECIPE)?,
    };
    let content_edition = string(field(7))?.to_owned();
    if content_edition != "3" {
        return Err(EncodingError::ContentEdition);
    }
    let dependency_edition = string(field(8))?.to_owned();
    if dependency_edition != "3" {
        return Err(EncodingError::DependencyEdition);
    }
    let parts = HeaderParts {
        body,
        commitments: ActCommitments {
            proposal,
            content,
            dependency,
        },
        actor_signature,
        content_edition,
        dependency_edition,
    };
    if header_value(&parts)? != value {
        return Err(EncodingError::Shape);
    }
    Ok(VerifiedHeader {
        parts,
        bytes: input.to_vec(),
    })
}

fn compare_header_bytes(supplied: &[u8], expected: &[u8]) -> Result<(), EncodingError> {
    if supplied == expected {
        Ok(())
    } else {
        Err(EncodingError::HeaderBytes)
    }
}

/// Compare canonical supplied bytes against independently expected parts.
/// # Errors
/// Returns the first ordered representation or field mismatch.
/// # Panics
/// Panics only if an i64 cannot fit the interchange integer domain.
#[tracing::instrument(
    name = "def:authentication:version-three",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:version-three",
        source_item = "v3::compare_header"
    ),
    ret
)]
pub fn compare_header(input: &[u8], expected: &HeaderParts) -> Result<(), EncodingError> {
    let actual = decode_header(input)?;
    profile::compare_body(&actual.parts.body, &expected.body).map_err(|cause| {
        if cause == profile::ProfileError::Body {
            EncodingError::Body
        } else {
            EncodingError::Profile(cause)
        }
    })?;
    if actual.parts.commitments.proposal != expected.commitments.proposal {
        return Err(EncodingError::Proposal);
    }
    if actual.parts.commitments.content != expected.commitments.content {
        return Err(EncodingError::Content);
    }
    if actual.parts.commitments.dependency != expected.commitments.dependency {
        return Err(EncodingError::Dependency);
    }
    if actual.parts.actor_signature != expected.actor_signature {
        return Err(EncodingError::ActorSignature);
    }
    if actual.parts.content_edition != expected.content_edition {
        return Err(EncodingError::ContentEdition);
    }
    if actual.parts.dependency_edition != expected.dependency_edition {
        return Err(EncodingError::DependencyEdition);
    }
    compare_header_bytes(input, &encode_header(expected)?.bytes)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

fn host_identity(key: &[u8; 32]) -> String {
    format!("pn-host-bip340-v1/{}", lowercase_hex(key))
}

fn selected_run_for(act: &ActId, run: &[u8; 32]) -> bool {
    act.author
        .strip_prefix("pn-devnet-v1/")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(author_run, _)| author_run == lowercase_hex(run))
}

fn selected_run(context: &MaterialContext) -> bool {
    selected_run_for(&context.act, &context.selected_run)
}

fn check_material(material: &AuthenticationMaterial, context: &MaterialContext) -> Result<(), EncodingError> {
    if material.run != context.selected_run || !selected_run(context) {
        return Err(EncodingError::Run);
    }
    if material.host_identity != host_identity(&material.host_key) || material.host_identity != context.expected_host {
        return Err(EncodingError::Host);
    }
    if context.header_version != [3, 0, 0] {
        return Err(EncodingError::Edition);
    }
    Ok(())
}

fn material_value(material: &AuthenticationMaterial) -> Value {
    array([
        text(AUTHENTICATION_EDITION),
        bytes(&material.run),
        bytes(&material.actor_key),
        text(&material.host_identity),
        bytes(&material.host_key),
    ])
}

/// Construct selected public material under an independently supplied context.
/// # Errors
/// Refuses run, host or major-version disagreement.
#[tracing::instrument(
    name = "def:authentication:version-three",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:version-three",
        source_item = "v3::encode_material"
    ),
    ret
)]
pub fn encode_material(material: &AuthenticationMaterial, context: &MaterialContext) -> Result<Vec<u8>, EncodingError> {
    let bytes = material_value(material).to_canonical_bytes();
    if bytes.len() > MATERIAL_LIMIT {
        return Err(EncodingError::Bound);
    }
    check_material(material, context)?;
    Ok(bytes)
}

/// Decode and compare public material against a selected run and host.
/// # Errors
/// Refuses the first ordered byte, shape, edition or contextual defect.
#[tracing::instrument(
    name = "def:authentication:version-three",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:version-three",
        source_item = "v3::decode_material"
    ),
    ret
)]
pub fn decode_material(input: &[u8], context: &MaterialContext) -> Result<AuthenticationMaterial, EncodingError> {
    let value = canonical(input, MATERIAL_LIMIT)?;
    let [edition, run, actor_key, host_identity, host_key] = items(&value)? else {
        return Err(EncodingError::Shape);
    };
    let edition = string(edition)?;
    let result = AuthenticationMaterial {
        run: fixed(run)?,
        actor_key: fixed(actor_key)?,
        host_identity: string(host_identity)?.into(),
        host_key: fixed(host_key)?,
    };
    if edition != AUTHENTICATION_EDITION {
        return Err(EncodingError::Edition);
    }
    check_material(&result, context)?;
    Ok(result)
}

/// V3 proposal role bytes, never convertible to an earlier verifier's role.
///
/// ```compile_fail
/// fn old_verifier(_: &pn_act_authentication::ProposalMessage) {}
/// fn check(message: &pn_act_authentication::v3::ProposalMessage) {
///     old_verifier(message);
/// }
/// ```
///
/// ```compile_fail
/// fn expect_proposal(_: &pn_act_authentication::v3::ProposalMessage) {}
/// fn check(message: &pn_act_authentication::v3::SealMessage) {
///     expect_proposal(message);
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalMessage([u8; 32]);
impl ProposalMessage {
    /// Exact public role bytes.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:version-three",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:version-three",
            source_item = "v3::ProposalMessage::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Compare only this role with independently supplied bytes.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:version-three",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:version-three",
            source_item = "v3::ProposalMessage::matches_bytes"
        ),
        ret
    )]
    pub fn matches_bytes(&self, expected: &[u8]) -> bool {
        self.0.as_slice() == expected
    }
}
/// V3 host seal role bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealMessage([u8; 32]);
impl SealMessage {
    /// Exact public role bytes.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:version-three",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:version-three",
            source_item = "v3::SealMessage::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Compare only this role with independently supplied bytes.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:version-three",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:version-three",
            source_item = "v3::SealMessage::matches_bytes"
        ),
        ret
    )]
    pub fn matches_bytes(&self, expected: &[u8]) -> bool {
        self.0.as_slice() == expected
    }
}
/// V3 Actor approval role bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalMessage([u8; 32]);
impl ApprovalMessage {
    /// Exact public role bytes.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:version-three",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:version-three",
            source_item = "v3::ApprovalMessage::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Compare only this role with independently supplied bytes.
    #[must_use]
    #[tracing::instrument(
        name = "def:authentication:version-three",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ACTAUTH",
            claim_label = "def:authentication:version-three",
            source_item = "v3::ApprovalMessage::matches_bytes"
        ),
        ret
    )]
    pub fn matches_bytes(&self, expected: &[u8]) -> bool {
        self.0.as_slice() == expected
    }
}

/// Construct the v3 proposal role only from a computed complete opening.
#[must_use]
#[tracing::instrument(
    name = "def:authentication:version-three",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:version-three",
        source_item = "v3::proposal_message"
    ),
    ret
)]
pub fn proposal_message(proposal: &profile::ComputedProposalCommitment) -> ProposalMessage {
    ProposalMessage(proposal.as_recorded().bytes)
}

fn checked_role_context(
    material: &AuthenticationMaterial,
    context: &MaterialContext,
    header: &VerifiedHeader,
) -> Result<(), EncodingError> {
    check_material(material, context)?;
    if !selected_run_for(&header.parts.body.id, &context.selected_run) {
        return Err(EncodingError::Run);
    }
    Ok(())
}

/// Frame the unchanged host seal role over the selected v3 V and context.
/// # Errors
/// Refuses context and header disagreement before framing.
#[tracing::instrument(
    name = "def:authentication:version-three",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:version-three",
        source_item = "v3::seal_message"
    ),
    ret
)]
pub fn seal_message(
    material: &AuthenticationMaterial,
    context: &MaterialContext,
    header: &VerifiedHeader,
) -> Result<SealMessage, EncodingError> {
    checked_role_context(material, context, header)?;
    Ok(SealMessage(crate::messages::framed(
        "pn-act-authentication/host-seal/v1",
        "PN-verified-act-v1",
        vec![bytes(&material.run), text(&material.host_identity), bytes(header.bytes())],
    )))
}

/// Frame the unchanged approval role over selected v3 V and its host seal.
/// # Errors
/// Refuses context and header disagreement before framing.
#[tracing::instrument(
    name = "def:authentication:version-three",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ACTAUTH",
        claim_label = "def:authentication:version-three",
        source_item = "v3::approval_message"
    ),
    ret
)]
pub fn approval_message(
    material: &AuthenticationMaterial,
    context: &MaterialContext,
    header: &VerifiedHeader,
    host_seal: &[u8; 64],
) -> Result<ApprovalMessage, EncodingError> {
    checked_role_context(material, context, header)?;
    Ok(ApprovalMessage(crate::messages::framed(
        "pn-act-authentication/actor-approval/v1",
        "PN-act-approval-v1",
        vec![
            bytes(&material.run),
            text(&material.host_identity),
            bytes(header.bytes()),
            bytes(host_seal),
        ],
    )))
}

#[cfg(test)]
mod tests {
    use super::{EncodingError, compare_header_bytes};

    /// The private final byte guard has equal and unequal canonical operands.
    /// ´claim:authentication:version-three-header-byte-guard´
    /// ´test:unit:header-bytes-guard´
    #[test]
    fn header_bytes_guard() {
        let left = [0x80];
        assert_eq!(compare_header_bytes(&left, &left), Ok(()));
        assert_eq!(compare_header_bytes(&left, &[0x81, 0]), Err(EncodingError::HeaderBytes));
    }
}
