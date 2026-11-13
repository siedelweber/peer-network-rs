//! Exact source carriage for the admitted control schema envelope.
//! (´[ROOT-dec:api:schema]´)

use crate::{Content, ContentKey, Document, Envelope, EnvelopeError, NamespaceLabel, Value, Version};

/// The admitted control-schema role; the other three artifact roles stay reserved.
/// (´[ROOT-dec:api:schema]´)
pub const NAMESPACE: &str = "org.peer-network.test.api-control-schema";

/// Refusal of canonical document membership or the closed control-schema theory.
/// (´[ROOT-dec:api:schema]´)
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The complete original bytes are not a canonical document.
    #[error("control schema document: {0}")]
    Document(#[from] EnvelopeError),
    /// Another role cannot supply this schema.
    #[error("expected the control schema namespace")]
    Role,
    /// Only the assigned major/minor is implemented; patch is unconstrained.
    #[error("expected control schema major one and minor zero")]
    Edition,
    /// Exactly key two with text is required.
    #[error("expected exactly one text content field at key two")]
    Content,
}

/// Encode the initial control-schema envelope without interpreting or changing its source.
/// (´[ROOT-dec:api:schema]´)
///
/// # Errors
/// Returns an envelope refusal if the fixed admitted label or content key is invalid.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "INTERCHANGE",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "control_schema::encode"
    ),
    ret
)]
pub fn encode(source: &str) -> Result<Vec<u8>, EnvelopeError> {
    let label = NamespaceLabel::parse(NAMESPACE).map_err(EnvelopeError::BadLabel)?;
    let mut content = Content::new();
    content.insert(ContentKey::new(2)?, Value::Text(source.to_owned().into()));
    Ok(Document::new(Envelope::new(label, Version::new(1, 0, 0)), content).to_canonical_bytes())
}

/// Validate the complete canonical envelope and return its source unchanged.
/// (´[ROOT-dec:api:schema]´)
/// This establishes text carriage only, not SDL validity or a served edition.
///
/// # Errors
/// Refuses malformed original bytes, another role or edition, missing/extra fields,
/// and non-text content. It never repairs input or accepts only an envelope prefix.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "INTERCHANGE",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "control_schema::decode"
    ),
    ret
)]
pub fn decode(bytes: &[u8]) -> Result<String, Refusal> {
    let document = Document::from_canonical_bytes(bytes)?;
    if document.envelope().label().as_str() != NAMESPACE {
        return Err(Refusal::Role);
    }
    let edition = document.envelope().version();
    if edition.major() != 1 || edition.minor() != 0 {
        return Err(Refusal::Edition);
    }
    if document.content().len() != 1 {
        return Err(Refusal::Content);
    }
    let Some(Value::Text(source)) = document.content().get(2) else {
        return Err(Refusal::Content);
    };
    Ok(source.as_str().to_owned())
}
