//! Pure major-one common act documents. These operations do not resolve a reference or verify an approval.
//! (´[ROOT-amend:identity:common-static-admission]´)

use pn_interchange::{
    Array, CanonicalUsage, Coordinate, DecodeError, EncodingError, EncodingUsage, Map, NamespaceLabel, Registry, Text, Theory,
    Value,
};
use sha2::{Digest, Sha256};

const ACT_NAMESPACE: &str = "org.peer-network.test.act";
const WITNESS_NAMESPACE: &str = "org.peer-network.test.act.witness";
const ACT_THEORY: &str = include_str!("../schema/common-act.cddl");
const WITNESS_THEORY: &str = include_str!("../schema/common-witnessed-act.cddl");

/// Mandatory caller declarations. The list fields are reserved for the later list cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub canonical_allocation_bytes: usize,
    pub max_pairs: usize,
    pub collection_allocation_bytes: usize,
}

/// A reason within the single operational inability class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetReason {
    InputBytes,
    OutputBytes,
    Representation,
    CanonicalAllocation,
    Allocation,
}

/// A strict common-document refusal or publication defect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CommonError {
    #[error("owned theory cannot be published")]
    RegistryDefinition,
    #[error("canonical document resources unavailable: {reason:?}, charged {charged_bytes} bytes")]
    UnavailableBudget { reason: BudgetReason, charged_bytes: usize },
    #[error("noncanonical document bytes")]
    Canonical,
    #[error("wrong envelope or header shape")]
    Envelope,
    #[error("wrong namespace")]
    Namespace,
    #[error("operation version unavailable")]
    OperationVersion,
    #[error("wrong content key or body shape")]
    Body,
    #[error("wrong body member count")]
    Count,
    #[error("wrong body member type")]
    MemberType,
    #[error("wrong body member width")]
    MemberWidth,
    #[error("operation patch unavailable")]
    OperationPatch,
}

fn unavailable(reason: BudgetReason, charged_bytes: usize) -> CommonError {
    CommonError::UnavailableBudget { reason, charged_bytes }
}

/// Build the two published assignments from their exact embedded source files.
///
/// # Errors
/// Returns `RegistryDefinition` if an owned theory or assignment cannot be acquired.
#[tracing::instrument(
    name = "amend:identity:common-static-admission",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ROOT",
        claim_label = "amend:identity:common-static-admission",
        source_item = "common::registry"
    ),
    ret
)]
pub fn registry() -> Result<Registry, CommonError> {
    let mut registry = Registry::new();
    for (namespace, source) in [(ACT_NAMESPACE, ACT_THEORY), (WITNESS_NAMESPACE, WITNESS_THEORY)] {
        let label = NamespaceLabel::parse(namespace).map_err(|_| CommonError::RegistryDefinition)?;
        let theory = Theory::parse(source).map_err(|_| CommonError::RegistryDefinition)?;
        registry
            .acquire(Coordinate::new(label, 1, 0), theory)
            .map_err(|_| CommonError::RegistryDefinition)?;
    }
    Ok(registry)
}

/// The complete SHA-256 name of an act document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActDocumentName([u8; 32]);

impl ActDocumentName {
    /// Retain a supplier's opaque name without inferring a referent.
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocumentName::from_bytes"
        ),
        ret
    )]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact digest-order bytes.
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocumentName::as_bytes"
        ),
        ret
    )]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The complete SHA-256 name of a witnessed-act document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessedActDocumentName([u8; 32]);

impl WitnessedActDocumentName {
    /// Retain a supplier's opaque name without inferring a referent.
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocumentName::from_bytes"
        ),
        ret
    )]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact digest-order bytes.
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocumentName::as_bytes"
        ),
        ret
    )]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Seven opaque fixed-width members in the published act order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActDocument {
    author: [u8; 32],
    sequence: [u8; 32],
    act_type: [u8; 32],
    typed_document: [u8; 32],
    parents_document: [u8; 32],
    content_document: [u8; 32],
    dependency_document: [u8; 32],
}

impl ActDocument {
    /// Construct a patch-zero typed act without resolving any member.
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::new"
        ),
        ret
    )]
    pub fn new(
        author: [u8; 32],
        sequence: [u8; 32],
        act_type: [u8; 32],
        typed_document: [u8; 32],
        parents_document: [u8; 32],
        content_document: [u8; 32],
        dependency_document: [u8; 32],
    ) -> Self {
        Self {
            author,
            sequence,
            act_type,
            typed_document,
            parents_document,
            content_document,
            dependency_document,
        }
    }

    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::author"
        ),
        ret
    )]
    pub fn author(&self) -> &[u8; 32] {
        &self.author
    }
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::sequence"
        ),
        ret
    )]
    pub fn sequence(&self) -> &[u8; 32] {
        &self.sequence
    }
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::act_type"
        ),
        ret
    )]
    pub fn act_type(&self) -> &[u8; 32] {
        &self.act_type
    }
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::typed_document"
        ),
        ret
    )]
    pub fn typed_document(&self) -> &[u8; 32] {
        &self.typed_document
    }
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::parents_document"
        ),
        ret
    )]
    pub fn parents_document(&self) -> &[u8; 32] {
        &self.parents_document
    }
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::content_document"
        ),
        ret
    )]
    pub fn content_document(&self) -> &[u8; 32] {
        &self.content_document
    }
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::dependency_document"
        ),
        ret
    )]
    pub fn dependency_document(&self) -> &[u8; 32] {
        &self.dependency_document
    }

    fn words(&self) -> [[u8; 32]; 7] {
        [
            self.author,
            self.sequence,
            self.act_type,
            self.typed_document,
            self.parents_document,
            self.content_document,
            self.dependency_document,
        ]
    }

    /// Encode exactly the canonical patch-zero act document.
    ///
    /// # Errors
    /// Returns the first output or canonical-allocation inability.
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::encode"
        ),
        ret
    )]
    pub fn encode(&self, limits: Limits) -> Result<Vec<u8>, CommonError> {
        encode_fixed(ACT_NAMESPACE, &self.words(), 274, limits)
    }

    /// Read a complete canonical act document without repairing its bytes.
    ///
    /// # Errors
    /// Returns the ordered resource, canonical, envelope, version, body, member or patch refusal.
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::decode_strict"
        ),
        ret
    )]
    pub fn decode_strict(input: &[u8], limits: Limits) -> Result<Self, CommonError> {
        let [
            author,
            sequence,
            act_type,
            typed_document,
            parents_document,
            content_document,
            dependency_document,
        ] = decode_fixed::<7>(input, ACT_NAMESPACE, limits)?;
        Ok(Self::new(
            author,
            sequence,
            act_type,
            typed_document,
            parents_document,
            content_document,
            dependency_document,
        ))
    }

    /// Hash the entire canonical act encoding in digest order.
    ///
    /// # Errors
    /// Returns the same resource inability as `encode`.
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::name"
        ),
        ret
    )]
    pub fn name(&self, limits: Limits) -> Result<ActDocumentName, CommonError> {
        Ok(ActDocumentName(Sha256::digest(self.encode(limits)?).into()))
    }

    /// Recompute and compare an independently supplied act name.
    ///
    /// # Errors
    /// Returns the same resource inability as `name`.
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::ActDocument::matches_name"
        ),
        ret
    )]
    pub fn matches_name(&self, supplied: ActDocumentName, limits: Limits) -> Result<bool, CommonError> {
        Ok(self.name(limits)? == supplied)
    }
}

/// Four opaque fixed-width members in the published witnessed-act order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessedActDocument {
    act: [u8; 32],
    key: [u8; 32],
    signature_first: [u8; 32],
    signature_second: [u8; 32],
}

impl WitnessedActDocument {
    /// Construct a patch-zero typed witness without checking a signature.
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocument::new"
        ),
        ret
    )]
    pub fn new(act: [u8; 32], key: [u8; 32], signature_first: [u8; 32], signature_second: [u8; 32]) -> Self {
        Self {
            act,
            key,
            signature_first,
            signature_second,
        }
    }

    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocument::act"
        ),
        ret
    )]
    pub fn act(&self) -> &[u8; 32] {
        &self.act
    }
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocument::key"
        ),
        ret
    )]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocument::signature_first"
        ),
        ret
    )]
    pub fn signature_first(&self) -> &[u8; 32] {
        &self.signature_first
    }
    #[must_use]
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocument::signature_second"
        ),
        ret
    )]
    pub fn signature_second(&self) -> &[u8; 32] {
        &self.signature_second
    }

    fn words(&self) -> [[u8; 32]; 4] {
        [self.act, self.key, self.signature_first, self.signature_second]
    }

    /// Encode exactly the canonical patch-zero witnessed-act document.
    ///
    /// # Errors
    /// Returns the first output or canonical-allocation inability.
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocument::encode"
        ),
        ret
    )]
    pub fn encode(&self, limits: Limits) -> Result<Vec<u8>, CommonError> {
        encode_fixed(WITNESS_NAMESPACE, &self.words(), 180, limits)
    }

    /// Read a complete canonical witnessed-act document without checking a signature.
    ///
    /// # Errors
    /// Returns the ordered resource, canonical, envelope, version, body, member or patch refusal.
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocument::decode_strict"
        ),
        ret
    )]
    pub fn decode_strict(input: &[u8], limits: Limits) -> Result<Self, CommonError> {
        let [act, key, signature_first, signature_second] = decode_fixed::<4>(input, WITNESS_NAMESPACE, limits)?;
        Ok(Self::new(act, key, signature_first, signature_second))
    }

    /// Hash the entire canonical witnessed-act encoding in digest order.
    ///
    /// # Errors
    /// Returns the same resource inability as `encode`.
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocument::name"
        ),
        ret
    )]
    pub fn name(&self, limits: Limits) -> Result<WitnessedActDocumentName, CommonError> {
        Ok(WitnessedActDocumentName(Sha256::digest(self.encode(limits)?).into()))
    }

    /// Recompute and compare an independently supplied witnessed-act name.
    ///
    /// # Errors
    /// Returns the same resource inability as `name`.
    #[tracing::instrument(
        name = "amend:identity:common-static-admission",
        fields(
            execution_owner = "ACTAUTH",
            claim_owner = "ROOT",
            claim_label = "amend:identity:common-static-admission",
            source_item = "common::WitnessedActDocument::matches_name"
        ),
        ret
    )]
    pub fn matches_name(&self, supplied: WitnessedActDocumentName, limits: Limits) -> Result<bool, CommonError> {
        Ok(self.name(limits)? == supplied)
    }
}

/// The act's approval message is its recomputed document name, not a caller-chosen digest.
///
/// # Errors
/// Returns the same resource inability as act encoding.
#[tracing::instrument(
    name = "amend:identity:common-static-admission",
    fields(
        execution_owner = "ACTAUTH",
        claim_owner = "ROOT",
        claim_label = "amend:identity:common-static-admission",
        source_item = "common::act_approval_message"
    ),
    ret
)]
pub fn act_approval_message(act: &ActDocument, limits: Limits) -> Result<[u8; 32], CommonError> {
    Ok(*act.name(limits)?.as_bytes())
}

fn encode_fixed<const N: usize>(
    namespace: &str,
    words: &[[u8; 32]; N],
    output_len: usize,
    limits: Limits,
) -> Result<Vec<u8>, CommonError> {
    if output_len > limits.output_bytes {
        return Err(unavailable(BudgetReason::OutputBytes, 0));
    }
    // Charge the fixed payload copies and the three container buffers before their construction.
    let construction = N
        .checked_mul(32 + std::mem::size_of::<Value>())
        .and_then(|n| {
            n.checked_add(namespace.len() + 3 * std::mem::size_of::<Value>() + 3 * std::mem::size_of::<(Value, Value)>())
        })
        .ok_or_else(|| unavailable(BudgetReason::Representation, 0))?;
    let remaining = limits
        .canonical_allocation_bytes
        .checked_sub(construction)
        .ok_or_else(|| unavailable(BudgetReason::CanonicalAllocation, 0))?;
    let body = Value::Array(Array::new(words.iter().map(|word| Value::Bytes(word.to_vec().into()))));
    let version = Value::Array(Array::new([Value::Unsigned(1), Value::Unsigned(0), Value::Unsigned(0)]));
    let value = Value::Map(
        Map::new([
            (Value::Unsigned(0), Value::Text(Text::from(namespace.to_owned()))),
            (Value::Unsigned(1), version),
            (Value::Unsigned(2), body),
        ])
        .map_err(|_| CommonError::RegistryDefinition)?,
    );
    let mut usage = EncodingUsage::default();
    let bytes = value
        .to_canonical_bytes_budgeted(remaining, &mut usage, |_| Ok(()))
        .map_err(|error| {
            let reason = match error {
                EncodingError::Allocation => BudgetReason::Allocation,
                EncodingError::Length | EncodingError::Limit | EncodingError::Reservation => BudgetReason::CanonicalAllocation,
            };
            unavailable(reason, construction + usage.allocation_bytes)
        })?;
    tracing::event!(
        tracing::Level::TRACE,
        canonical_allocation_bytes = construction + usage.allocation_bytes,
        output_bytes = bytes.len()
    );
    Ok(bytes)
}

#[derive(Clone, Copy)]
struct Item {
    offset: usize,
    end: usize,
    payload: usize,
    major: u8,
    argument: u64,
}

impl Item {
    fn from_canonical(item: pn_interchange::CanonicalItem<'_>) -> Self {
        Self {
            offset: item.offset,
            end: item.offset + item.bytes.len(),
            payload: item.offset + item.payload_offset,
            major: item.major,
            argument: item.argument,
        }
    }
}

fn child(item: Option<Item>, error: CommonError) -> Result<Item, CommonError> {
    item.ok_or(error)
}

struct CanonicalItems {
    root: Option<Item>,
    level_two: [Option<Item>; 8],
    level_three: [Option<Item>; 24],
    usage_bytes: usize,
}

fn validated_items(input: &[u8], limit: usize) -> Result<CanonicalItems, CommonError> {
    let mut usage = CanonicalUsage::default();
    let mut root = None;
    let mut level_two = [None; 8];
    let mut level_three = [None; 24];
    let mut two_count = 0;
    let mut three_count = 0;
    Value::validate_canonical_bytes(
        input,
        limit,
        &mut usage,
        |_| Ok(()),
        |event| {
            let depth = event.depth;
            let item = Item::from_canonical(event);
            match depth {
                1 => root = Some(item),
                2 => {
                    if let Some(slot) = level_two.get_mut(two_count) {
                        *slot = Some(item);
                    }
                    two_count += 1;
                }
                3 => {
                    if let Some(slot) = level_three.get_mut(three_count) {
                        *slot = Some(item);
                    }
                    three_count += 1;
                }
                _ => {}
            }
        },
    )
    .map_err(|error| match error {
        DecodeError::CanonicalLimit { .. } => unavailable(BudgetReason::CanonicalAllocation, usage.allocation_bytes),
        DecodeError::CanonicalAllocation { .. } | DecodeError::CanonicalReservation { .. } => {
            unavailable(BudgetReason::Allocation, usage.allocation_bytes)
        }
        _ => CommonError::Canonical,
    })?;
    Ok(CanonicalItems {
        root,
        level_two,
        level_three,
        usage_bytes: usage.allocation_bytes,
    })
}

fn decode_fixed<const N: usize>(input: &[u8], namespace: &str, limits: Limits) -> Result<[[u8; 32]; N], CommonError> {
    if input.len() > limits.input_bytes {
        return Err(unavailable(BudgetReason::InputBytes, 0));
    }
    let CanonicalItems {
        root,
        level_two,
        level_three,
        usage_bytes,
    } = validated_items(input, limits.canonical_allocation_bytes)?;

    let envelope = child(root, CommonError::Envelope)?;
    if envelope.major != 5 || envelope.argument < 2 {
        return Err(CommonError::Envelope);
    }
    let key_zero = child(level_two[0], CommonError::Envelope)?;
    let name = child(level_two[1], CommonError::Envelope)?;
    let key_one = child(level_two[2], CommonError::Envelope)?;
    let version = child(level_two[3], CommonError::Envelope)?;
    if key_zero.major != 0
        || key_zero.argument != 0
        || key_one.major != 0
        || key_one.argument != 1
        || name.major != 3
        || version.major != 4
        || version.argument != 3
    {
        return Err(CommonError::Envelope);
    }
    let mut coordinates = [0_u64; 3];
    let mut coordinate_count = 0;
    for item in level_three.into_iter().flatten() {
        if item.offset >= version.payload && item.end <= version.end {
            if coordinate_count >= 3 || item.major != 0 {
                return Err(CommonError::Envelope);
            }
            coordinates[coordinate_count] = item.argument;
            coordinate_count += 1;
        }
    }
    if coordinate_count != 3 {
        return Err(CommonError::Envelope);
    }
    if input.get(name.payload..name.end) != Some(namespace.as_bytes()) {
        return Err(CommonError::Namespace);
    }
    if coordinates[0] != 1 || coordinates[1] != 0 {
        return Err(CommonError::OperationVersion);
    }

    if envelope.argument != 3 {
        return Err(CommonError::Body);
    }
    let key_two = child(level_two[4], CommonError::Body)?;
    let body = child(level_two[5], CommonError::Body)?;
    if key_two.major != 0 || key_two.argument != 2 || body.major != 4 {
        return Err(CommonError::Body);
    }
    if body.argument != N as u64 {
        return Err(CommonError::Count);
    }
    let mut words = [[0_u8; 32]; N];
    let mut word_count = 0;
    for item in level_three.into_iter().flatten() {
        if item.offset >= body.payload && item.end <= body.end {
            let Some(word) = words.get_mut(word_count) else {
                return Err(CommonError::Count);
            };
            if item.major != 2 {
                return Err(CommonError::MemberType);
            }
            if item.argument != 32 {
                return Err(CommonError::MemberWidth);
            }
            let bytes = input.get(item.payload..item.end).ok_or(CommonError::Canonical)?;
            if bytes.len() != 32 {
                return Err(CommonError::MemberWidth);
            }
            word.copy_from_slice(bytes);
            word_count += 1;
        }
    }
    if word_count != N {
        return Err(CommonError::Count);
    }
    if coordinates[2] != 0 {
        return Err(CommonError::OperationPatch);
    }
    tracing::event!(
        tracing::Level::TRACE,
        canonical_allocation_bytes = usage_bytes,
        input_bytes = input.len()
    );
    Ok(words)
}
