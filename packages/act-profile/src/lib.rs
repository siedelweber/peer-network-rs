//! Pure act-profile projections and comparison with supplied recorded anchors.
//! No matching result authenticates its anchor or generates entropy.
//! (´def:profile:scope´)

use pn_interchange::{Array, Bytes, SecretValue, Text, Value};
use pn_records::commitments::{ContentCommitment, DependencyCommitment, ProposalCommitment};
use pn_records::{ActId, CandidateLeg, Layout, PublicReference, Role, StructuralBody};
use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretBox, SecretSlice, SecretString};
use sha2::{Digest, Sha256};

/// Permanent proposal recipe, including its two private intermediates.
/// (´def:profile:recipes´)
pub const PROPOSAL_RECIPE: &str = "pn-act-profile/act-proposal/v1";
/// Permanent content recipe.
/// (´def:profile:recipes´)
pub const CONTENT_RECIPE: &str = "pn-act-profile/act-content/v1";
/// Permanent dependency recipe.
/// (´def:profile:recipes´)
pub const DEPENDENCY_RECIPE: &str = "pn-act-profile/act-dependency/v1";

/// Original authored carriage request, never inferred from later removal.
/// (´def:profile:body´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentRequest {
    FullEmpty,
    Full,
    Reduced,
}
/// Original authored dependency request.
/// (´def:profile:body´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyRequest {
    FullEmpty,
    Full,
    Tombstoned,
}

/// Public authored fields; no private projection or host-attached field occurs.
/// Structural equality preserves every authored integer pair exactly.
/// (´def:profile:body´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalBody {
    pub id: ActId,
    pub body: StructuralBody,
    pub legs: Vec<CandidateLeg>,
    pub protocol_references: Vec<PublicReference>,
    pub content: ContentRequest,
    pub dependency: DependencyRequest,
}

/// Dependency material intended to live inside `SecretBox` on commitment paths.
/// Its list is opened publicly only after a successful explicit opening check.
/// (´def:profile:private-inputs´)
pub struct DependencyIds(pub Vec<ActId>);
impl std::fmt::Debug for DependencyIds {
    /// Justified: Private dependency formatting inherits the commitment boundary and emits only a fixed redaction, never identifiers.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DependencyIds([REDACTED])")
    }
}

impl Zeroize for DependencyIds {
    /// Justified: Container destruction erases private identifier fields without observation.
    fn zeroize(&mut self) {
        for id in &mut self.0 {
            id.author.zeroize();
            id.sequence.zeroize();
            id.family.zeroize();
        }
        self.0.clear();
    }
}

/// Content-free representation or binding refusal.
/// (´def:profile:scope´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    #[error("unsupported act-profile representation")]
    Representation,
    #[error("act-profile bound exceeded")]
    Bound,
    #[error("unsupported commitment recipe")]
    Recipe,
    #[error("supplied opening differs from supplied recorded commitment")]
    Mismatch,
}

fn text(s: &str) -> Value {
    Value::Text(Text::from(s.to_owned()))
}
fn array(v: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(v))
}
fn identifier(id: &ActId) -> Value {
    array([text("act"), text(&id.author), Value::Unsigned(id.sequence), text(&id.family)])
}
fn public(v: Value) -> SecretValue {
    SecretValue::Public(v)
}
fn address(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("pn-devnet-v1/") else {
        return false;
    };
    let Some((run, target)) = rest.split_once('/') else {
        return false;
    };
    [run, target]
        .iter()
        .all(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}
fn valid_id(id: &ActId) -> bool {
    address(&id.author) && schema(&id.family).is_some()
}
fn schema(family: &str) -> Option<(Layout, &'static [(&'static str, bool)])> {
    use Layout::{Binary as B, Paired as P};
    Some(match family {
        "Registration" | "Withdraw" | "Rescind" | "Leave" => (B, &[]),
        "Publish" | "Owner" => (B, &[("attachment", false)]),
        "Opinion" => (B, &[("polarity", false), ("reaction", false)]),
        "Affinity" => (B, &[("association", false), ("attraction", false)]),
        "Join Request" => (B, &[("formality", false), ("urgency", false)]),
        "Accept" | "Ratify" => (B, &[("comfort", false), ("equity", false)]),
        "Participant" => (
            P,
            &[("continuity", true), ("interactivity", false), ("responsibility", false)],
        ),
        "Invitation" => (P, &[("formality", false), ("relevance", true), ("urgency", false)]),
        "De-invite" => (P, &[]),
        "Tag" => (P, &[("confidence", true), ("relevance", false)]),
        "Review" | "Reference" => (P, &[("effort", false), ("enthusiasm", false)]),
        "Bid" => (P, &[("generosity", false), ("urgency", true)]),
        "Send" => (P, &[("importance", false)]),
        _ => return None,
    })
}
fn reference(r: &PublicReference) -> Result<Value, ProfileError> {
    Ok(match r {
        PublicReference::Act(id) if valid_id(id) => identifier(id),
        PublicReference::Edge(edge) if valid_id(&edge.act) => {
            array([text("record"), identifier(&edge.act), text(role(edge.role))])
        }
        PublicReference::Minted(id) if valid_id(id) => array([text("mint"), identifier(id)]),
        PublicReference::Named { namespace, name }
            if ((namespace == "addr" || namespace == "prof") && address(name))
                || (namespace == "name" && !name.is_empty() && name.len() <= 1024) =>
        {
            array([text("named"), text(namespace), text(name)])
        }
        _ => return Err(ProfileError::Representation),
    })
}
fn role(role: Role) -> &'static str {
    match role {
        Role::Binary => "binary",
        Role::A => "A",
        Role::T => "T",
    }
}

// Caveat: The protected canonical preimage is borrowed only by SHA-256 update after the public prefix; the borrow ends at update, and the hash's fixed-width output immediately enters a secret carrier with the temporary array erased, without an observation field.
// (´[ROOT-cav:observe:secret-profile-hash-input]´)
// Justified: The admitted hash accepts a byte slice, so its single update borrows the protected encoding without an ordinary copy.
#[allow(clippy::disallowed_methods)]
fn hash(recipe: &str, tag: &str, fields: Vec<SecretValue>) -> Result<SecretSlice<u8>, ProfileError> {
    let value = SecretValue::Array(vec![public(text(tag)), SecretValue::Array(fields)]);
    let bytes = value.to_secret_canonical_bytes(2_097_152).map_err(|_| ProfileError::Bound)?;
    let mut h = Sha256::new();
    h.update(recipe.as_bytes());
    h.update([0]);
    h.update(bytes.expose_secret(/* (´[ROOT-cav:observe:secret-profile-hash-input]´) */));
    let mut result: [u8; 32] = h.finalize().into();
    let protected = SecretSlice::from(result.to_vec());
    result.zeroize();
    Ok(protected)
}

// Caveat: The proposal nonce is borrowed to check its forty-byte format and public sequence prefix; the borrow ends at validation and reveals neither its suffix nor a claim of entropy.
// (´[ROOT-cav:observe:secret-profile-nonce-format]´)
// Justified: These exact format checks require a temporary slice; production freshness and entropy are separate held duties.
#[allow(clippy::disallowed_methods)]
fn nonce_format(id: &ActId, nonce: &SecretSlice<u8>) -> Result<(), ProfileError> {
    let bytes = nonce.expose_secret(/* (´[ROOT-cav:observe:secret-profile-nonce-format]´) */);
    if bytes.len() != 40 || bytes[..8] != id.sequence.to_be_bytes() {
        return Err(ProfileError::Representation);
    }
    Ok(())
}
// Caveat: The host salt is borrowed only to check its forty-eight-byte format; the borrow ends at len and establishes no allocation, uniqueness or entropy.
// (´[ROOT-cav:observe:secret-profile-salt-format]´)
// Justified: The private container has no length accessor, and no content is copied for this check.
#[allow(clippy::disallowed_methods)]
fn salt_format(salt: &SecretSlice<u8>) -> Result<(), ProfileError> {
    if salt.expose_secret(/* (´[ROOT-cav:observe:secret-profile-salt-format]´) */).len() != 48 {
        return Err(ProfileError::Representation);
    }
    Ok(())
}
// Caveat: Payload bytes are borrowed only to enforce the independent byte bound and original empty-state request; the borrow ends with the check and no payload content is observed.
// (´[ROOT-cav:observe:secret-profile-payload-length]´)
// Justified: The protected container's length is needed before projection allocation; only the permitted size and empty predicate leave this borrow.
#[allow(clippy::disallowed_methods)]
fn payload_length(payload: &SecretSlice<u8>) -> Result<usize, ProfileError> {
    let len = payload.expose_secret(/* (´[ROOT-cav:observe:secret-profile-payload-length]´) */).len();
    if len > 65_536 {
        return Err(ProfileError::Bound);
    }
    Ok(len)
}

// Caveat: The dependency list is borrowed for identifier validation, strict records ordering and projection into private canonical fields; its borrow ends before encoding and no ordinary Value contains its identifiers.
// (´[ROOT-cav:observe:secret-profile-dependency-projection]´)
// Justified: Validation and projection must inspect the supplied private list; every copied field immediately enters a secrecy container.
#[allow(clippy::disallowed_methods)]
fn dependencies(list: &SecretBox<DependencyIds>, forbidden: Option<&ActId>) -> Result<(SecretValue, usize), ProfileError> {
    let ids = &list.expose_secret(/* (´[ROOT-cav:observe:secret-profile-dependency-projection]´) */).0;
    if ids.len() > 1024 {
        return Err(ProfileError::Bound);
    }
    if ids.iter().any(|id| !valid_id(id) || forbidden == Some(id)) || ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ProfileError::Representation);
    }
    let values = ids
        .iter()
        .map(|id| {
            SecretValue::Array(vec![
                public(text("act")),
                SecretValue::Text(SecretString::from(id.author.clone())),
                SecretValue::Unsigned(SecretBox::new(Box::new(id.sequence))),
                SecretValue::Text(SecretString::from(id.family.clone())),
            ])
        })
        .collect();
    let value = SecretValue::Array(values);
    // Fixed-length authors and the closed family vocabulary imply fewer than
    // 262144 canonical bytes at the independent 1024-identifier count bound.
    Ok((value, ids.len()))
}

// Caveat: The completed public commitment digest is borrowed for a single copy into its retained thirty-two-byte residue; this is the declared commitment publication, not publication of a pre-digest or its inputs, and the borrow ends at conversion.
// (´[ROOT-cav:observe:secret-profile-publish-residue]´)
// Justified: Retained public residues have ordinary fixed-width carriers; only final P, content and dependency results use this publication boundary.
#[allow(clippy::disallowed_methods)]
fn publish(digest: &SecretSlice<u8>) -> Result<[u8; 32], ProfileError> {
    digest.expose_secret(/* (´[ROOT-cav:observe:secret-profile-publish-residue]´) */).try_into().map_err(|_|ProfileError::Representation)
}

fn proposal_anchor(p: &ProposalCommitment) -> Result<SecretValue, ProfileError> {
    if p.recipe != PROPOSAL_RECIPE {
        return Err(ProfileError::Recipe);
    }
    Ok(public(Value::Bytes(Bytes::from(p.bytes.to_vec()))))
}

fn quantities_projection(
    quantities: &[(String, pn_records::Quantity)],
    coordinates: &[(&str, bool)],
) -> Result<Value, ProfileError> {
    let mut expected = Vec::new();
    for &(name, nonnegative) in coordinates {
        let denominator = format!("{name}.denominator");
        let numerator = format!("{name}.numerator");
        let d = quantities
            .iter()
            .find(|(key, _)| key == &denominator)
            .ok_or(ProfileError::Representation)?
            .1
            .value;
        let n = quantities
            .iter()
            .find(|(key, _)| key == &numerator)
            .ok_or(ProfileError::Representation)?
            .1
            .value;
        if d <= 0 || i128::from(n).abs() > i128::from(d) || (nonnegative && n < 0) {
            return Err(ProfileError::Representation);
        }
        expected.extend([denominator, numerator]);
    }
    expected.sort();
    if quantities.len() != expected.len()
        || quantities
            .iter()
            .zip(&expected)
            .any(|((key, q), want)| key != want || q.unit != "one" || q.vintage != 0)
    {
        return Err(ProfileError::Representation);
    }
    let values = quantities.iter().map(|(name, q)| {
        array([
            text(name),
            Value::integer(i128::from(q.value)).expect("i64 fits the interchange integer domain"),
            text(&q.unit),
            Value::Unsigned(q.vintage),
        ])
    });
    Ok(array(values))
}

fn license_projection(
    id: &ActId,
    legs: &[CandidateLeg],
    license: Option<&pn_records::LicenseQualifiers>,
) -> Result<Value, ProfileError> {
    let own_mint = legs.iter().any(|leg| leg.target == PublicReference::Minted(id.clone()));
    if license.is_some() != (id.family == "Publish" && own_mint) {
        return Err(ProfileError::Representation);
    }
    let license = match license {
        None => Value::Null,
        Some(license) => {
            let mut degrees = Vec::new();
            for d in [license.attribution, license.provenance] {
                if d.denominator <= 0 || d.numerator < 0 || d.numerator > d.denominator {
                    return Err(ProfileError::Representation);
                }
                degrees.push(array([
                    Value::Unsigned(d.numerator.unsigned_abs()),
                    Value::Unsigned(d.denominator.unsigned_abs()),
                ]));
            }
            array(degrees)
        }
    };
    Ok(license)
}

fn body_projection(input: &ProposalBody) -> Result<Value, ProfileError> {
    let ProposalBody {
        id,
        body,
        legs,
        protocol_references,
        content,
        dependency,
    } = input;
    let StructuralBody {
        settlement,
        license,
        asserted_parents,
        layout,
        quantities,
    } = body;
    if !valid_id(id) || !protocol_references.is_empty() {
        return Err(ProfileError::Representation);
    }
    let (shape, coordinates) = schema(&id.family).ok_or(ProfileError::Representation)?;
    if *layout != shape || asserted_parents.len() > 1024 || quantities.len() > 6 {
        return Err(ProfileError::Bound);
    }
    if asserted_parents.iter().any(|parent| !valid_id(parent) || parent == id)
        || asserted_parents.windows(2).any(|p| p[0] >= p[1])
    {
        return Err(ProfileError::Representation);
    }
    let roles: &[Role] = match layout {
        Layout::Binary => &[Role::Binary],
        Layout::Paired => &[Role::A, Role::T],
    };
    if legs.len() != roles.len()
        || legs
            .iter()
            .zip(roles)
            .any(|(leg, role)| leg.id.act != *id || leg.id.role != *role || leg.removal.is_some())
    {
        return Err(ProfileError::Representation);
    }
    if legs[0].source
        != (PublicReference::Named {
            namespace: "addr".into(),
            name: id.author.clone(),
        })
        || (*layout == Layout::Paired && legs[0].target != legs[1].source)
    {
        return Err(ProfileError::Representation);
    }
    let values = quantities_projection(quantities, coordinates)?;
    let license = license_projection(id, legs, license.as_ref())?;
    let settlement = match (id.family.as_str(), settlement) {
        ("Accept", Some(pn_records::SettlementReferences::Accept { settles })) if valid_id(settles) => {
            array([text("Accept"), identifier(settles)])
        }
        ("Ratify", Some(pn_records::SettlementReferences::Ratify { settles, accepts }))
            if valid_id(settles) && valid_id(accepts) =>
        {
            array([text("Ratify"), identifier(settles), identifier(accepts)])
        }
        ("Accept" | "Ratify", _) => return Err(ProfileError::Representation),
        (_, None) => Value::Null,
        _ => return Err(ProfileError::Representation),
    };
    let legs = legs
        .iter()
        .map(|leg| {
            Ok(array([
                text(role(leg.id.role)),
                reference(&leg.source)?,
                reference(&leg.target)?,
            ]))
        })
        .collect::<Result<Vec<_>, ProfileError>>()?;
    let value = array([
        identifier(id),
        text(match layout {
            Layout::Binary => "binary",
            Layout::Paired => "paired",
        }),
        array(legs),
        values,
        license,
        array(asserted_parents.iter().map(identifier)),
        array([]),
        settlement,
        text(match content {
            ContentRequest::FullEmpty => "full-empty",
            ContentRequest::Full => "full",
            ContentRequest::Reduced => "reduced",
        }),
        text(match dependency {
            DependencyRequest::FullEmpty => "full-empty",
            DependencyRequest::Full => "full",
            DependencyRequest::Tombstoned => "tombstoned",
        }),
    ]);
    if value.canonical_len() > 1_048_576 {
        return Err(ProfileError::Bound);
    }
    Ok(value)
}

/// Compute the Actor proposal, retaining both pre-digests only in secret carriers.
/// Authored integer pairs are committed exactly, never reduced as rationals.
/// # Errors
/// Refuses profile shape, request/opening disagreement, bounds or nonce format.
/// # Panics
/// Panics only if an i64 fails to fit the interchange integer domain, which its
/// constructor's declared range cannot arrange.
/// (´def:profile:recipes´)
#[tracing::instrument(
    name = "amend:decomposition:act-profile",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ROOT",
        claim_label = "amend:decomposition:act-profile",
        source_item = "proposal_commitment"
    ),
    ret
)]
pub fn proposal_commitment(
    body: &ProposalBody,
    nonce: &SecretSlice<u8>,
    payload: &SecretSlice<u8>,
    list: &SecretBox<DependencyIds>,
) -> Result<ProposalCommitment, ProfileError> {
    let projected = body_projection(body)?;
    nonce_format(&body.id, nonce)?;
    let ylen = payload_length(payload)?;
    let (d, dlen) = dependencies(list, Some(&body.id))?;
    if matches!(body.content, ContentRequest::FullEmpty) && ylen != 0
        || matches!(body.content, ContentRequest::Full) && ylen == 0
        || matches!(body.dependency, DependencyRequest::FullEmpty) && dlen != 0
        || matches!(body.dependency, DependencyRequest::Full) && dlen == 0
    {
        return Err(ProfileError::Representation);
    }
    let content = hash(
        PROPOSAL_RECIPE,
        "PN-content-pre-v1",
        vec![
            public(identifier(&body.id)),
            SecretValue::Bytes(nonce.clone()),
            SecretValue::Bytes(payload.clone()),
        ],
    )?;
    let dependency = hash(
        PROPOSAL_RECIPE,
        "PN-dependency-pre-v1",
        vec![public(identifier(&body.id)), SecretValue::Bytes(nonce.clone()), d],
    )?;
    let result = hash(
        PROPOSAL_RECIPE,
        "PN-act-proposal-v1",
        vec![public(projected), SecretValue::Bytes(content), SecretValue::Bytes(dependency)],
    )?;
    Ok(ProposalCommitment {
        recipe: PROPOSAL_RECIPE.into(),
        bytes: publish(&result)?,
    })
}

/// Compute the content residue from supplied private opening material.
/// No authenticity, producer authority or entropy follows from this computation.
/// (´def:profile:recipes´)
/// # Errors
/// Refuses unsupported identity/recipe, salt format and payload bounds.
#[tracing::instrument(
    name = "amend:decomposition:act-profile",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ROOT",
        claim_label = "amend:decomposition:act-profile",
        source_item = "content_commitment"
    ),
    ret
)]
pub fn content_commitment(
    id: &ActId,
    p: &ProposalCommitment,
    salt: &SecretSlice<u8>,
    payload: &SecretSlice<u8>,
) -> Result<ContentCommitment, ProfileError> {
    if !valid_id(id) {
        return Err(ProfileError::Representation);
    }
    salt_format(salt)?;
    payload_length(payload)?;
    let digest = hash(
        CONTENT_RECIPE,
        "PN-content-v1",
        vec![
            public(identifier(id)),
            proposal_anchor(p)?,
            SecretValue::Bytes(salt.clone()),
            SecretValue::Bytes(payload.clone()),
        ],
    )?;
    Ok(ContentCommitment {
        recipe: CONTENT_RECIPE.into(),
        bytes: publish(&digest)?,
    })
}

/// Compute the dependency residue, independently of finalized placement.
/// An absent, self or later opened target is not a malformed identifier list.
/// (´def:profile:recipes´)
/// # Errors
/// Refuses unsupported recipe, malformed input or count/byte bounds.
#[tracing::instrument(
    name = "amend:decomposition:act-profile",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ROOT",
        claim_label = "amend:decomposition:act-profile",
        source_item = "dependency_commitment"
    ),
    ret
)]
pub fn dependency_commitment(
    id: &ActId,
    p: &ProposalCommitment,
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
        "PN-dependency-v1",
        vec![
            public(identifier(id)),
            proposal_anchor(p)?,
            SecretValue::Bytes(salt.clone()),
            list,
        ],
    )?;
    Ok(DependencyCommitment {
        recipe: DEPENDENCY_RECIPE.into(),
        bytes: publish(&digest)?,
    })
}

/// Establish only equality to this supplied recorded content commitment.
/// Replacing both anchor and opening can still match; authenticity is separate.
/// (´def:profile:matching´)
/// # Errors
/// Refuses malformed inputs, unsupported recipes and unequal residues.
#[tracing::instrument(
    name = "amend:decomposition:act-profile",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ROOT",
        claim_label = "amend:decomposition:act-profile",
        source_item = "content_matches_supplied_commitment"
    ),
    ret
)]
pub fn content_matches_supplied_commitment(
    id: &ActId,
    p: &ProposalCommitment,
    recorded: &ContentCommitment,
    salt: &SecretSlice<u8>,
    payload: &SecretSlice<u8>,
) -> Result<(), ProfileError> {
    if recorded.recipe != CONTENT_RECIPE {
        return Err(ProfileError::Recipe);
    }
    if content_commitment(id, p, salt, payload)? != *recorded {
        return Err(ProfileError::Mismatch);
    }
    Ok(())
}

/// Establish only equality to this supplied recorded dependency commitment.
/// The result does not authenticate P, the residue or finalized inclusion.
/// (´def:profile:matching´)
/// # Errors
/// Refuses malformed inputs, unsupported recipes and unequal residues.
#[tracing::instrument(
    name = "amend:decomposition:act-profile",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ROOT",
        claim_label = "amend:decomposition:act-profile",
        source_item = "dependencies_match_supplied_commitment"
    ),
    ret
)]
pub fn dependencies_match_supplied_commitment(
    id: &ActId,
    p: &ProposalCommitment,
    recorded: &DependencyCommitment,
    salt: &SecretSlice<u8>,
    list: &SecretBox<DependencyIds>,
) -> Result<(), ProfileError> {
    if recorded.recipe != DEPENDENCY_RECIPE {
        return Err(ProfileError::Recipe);
    }
    if dependency_commitment(id, p, salt, list)? != *recorded {
        return Err(ProfileError::Mismatch);
    }
    Ok(())
}

/// Establish only equality to the supplied Actor-proposal residue.
/// # Errors
/// Refuses malformed input, unsupported recipe or a mismatching residue.
/// # Panics
/// Panics only if an i64 does not fit interchange's wider integer domain.
/// (´def:profile:matching´)
#[tracing::instrument(
    name = "amend:decomposition:act-profile",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ROOT",
        claim_label = "amend:decomposition:act-profile",
        source_item = "proposal_matches_supplied_commitment"
    ),
    ret
)]
pub fn proposal_matches_supplied_commitment(
    body: &ProposalBody,
    recorded: &ProposalCommitment,
    nonce: &SecretSlice<u8>,
    payload: &SecretSlice<u8>,
    list: &SecretBox<DependencyIds>,
) -> Result<(), ProfileError> {
    if recorded.recipe != PROPOSAL_RECIPE {
        return Err(ProfileError::Recipe);
    }
    if proposal_commitment(body, nonce, payload, list)? != *recorded {
        return Err(ProfileError::Mismatch);
    }
    Ok(())
}

/// Supplied private material for one complete dependency opening.
/// Opening publication is explicit and does not restore retained carriage.
/// (´def:profile:matching´)
#[derive(Debug)]
pub struct DependencyOpening {
    pub act: ActId,
    pub salt: SecretSlice<u8>,
    pub dependencies: SecretBox<DependencyIds>,
}

/// A pure checker for externally supplied tombstone openings.
/// It reads anchors from the exact retained act passed by records.
/// (´def:profile:matching´)
#[derive(Debug)]
pub struct DependencyOpenings(pub Vec<DependencyOpening>);

impl pn_records::commitments::DependencyOpener for DependencyOpenings {
    /// Justified: This target roster is public opening metadata and inherits the enclosing replay operation.
    fn targets(&self) -> Vec<ActId> {
        self.0.iter().map(|opening| opening.act.clone()).collect()
    }

    #[tracing::instrument(
        name = "amend:decomposition:act-profile",
        fields(
            execution_owner = "ACTPROFILE",
            claim_owner = "ROOT",
            claim_label = "amend:decomposition:act-profile",
            source_item = "<DependencyOpenings as pn_records :: commitments :: DependencyOpener>::open"
        ),
        ret
    )]
    fn open(&self, act: &pn_records::ValidatedAct) -> Result<Vec<ActId>, pn_records::commitments::OpeningError> {
        use pn_records::commitments::OpeningError as E;
        let anchor = act.commitments().ok_or(E::Anchor)?;
        let supplied = self.0.iter().find(|opening| &opening.act == act.id()).ok_or(E::Target)?;
        dependencies_match_supplied_commitment(
            act.id(),
            &anchor.proposal,
            &anchor.dependency,
            &supplied.salt,
            &supplied.dependencies,
        )
        .map_err(|e| match e {
            ProfileError::Mismatch => E::Mismatch,
            ProfileError::Recipe => E::Anchor,
            _ => E::Representation,
        })?;
        Ok(publish_opened_dependencies(&supplied.dependencies))
    }
}

// Caveat: A successfully matched dependency opening releases its complete list to records for public fault assessment and recurrence; the borrow ends after cloning that explicitly opened list and releases no nonce, salt or payload.
// (´[ROOT-cav:observe:secret-profile-opened-dependencies]´)
// Justified: Public replay must inspect the opened identifiers, and this boundary is called only after comparison with the retained residue succeeds.
#[allow(clippy::disallowed_methods)]
fn publish_opened_dependencies(ids: &SecretBox<DependencyIds>) -> Vec<ActId> {
    ids.expose_secret(/* (´[ROOT-cav:observe:secret-profile-opened-dependencies]´) */).0.clone()
}

/// Render one aggregate payload without putting either leg in a public Value.
/// Empty paired legs use the single distinguished zero-length aggregate.
/// The recipe itself treats the resulting bytes opaquely.
/// (´def:profile:payload´)
/// # Errors
/// Refuses a mismatched family/layout or payload bounds, including framing bytes.
#[tracing::instrument(
    name = "amend:decomposition:act-profile",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ROOT",
        claim_label = "amend:decomposition:act-profile",
        source_item = "render_payload"
    ),
    ret
)]
pub fn render_payload(family: &str, a: &SecretSlice<u8>, t: Option<&SecretSlice<u8>>) -> Result<SecretSlice<u8>, ProfileError> {
    let (layout, _) = schema(family).ok_or(ProfileError::Representation)?;
    let alen = payload_length(a)?;
    match (layout, t) {
        (Layout::Binary, None) => Ok(a.clone()),
        (Layout::Paired, Some(t)) => {
            let tlen = payload_length(t)?;
            if matches!(family, "Invitation" | "De-invite" | "Tag" | "Reference") && tlen != 0 {
                return Err(ProfileError::Representation);
            }
            if alen == 0 && tlen == 0 {
                return Ok(SecretSlice::from(Vec::new()));
            }
            if alen + tlen > 65_536 {
                return Err(ProfileError::Bound);
            }
            let encoded = SecretValue::Array(vec![SecretValue::Bytes(a.clone()), SecretValue::Bytes(t.clone())])
                .to_secret_canonical_bytes(65_563)
                .map_err(|_| ProfileError::Bound)?;
            payload_buffer(&encoded)
        }
        _ => Err(ProfileError::Representation),
    }
}

// Caveat: The protected paired-payload encoding is borrowed to check its exact aggregate bound and copy it directly into the payload's secret byte carrier; the borrow ends with that copy and no aggregate byte is observed.
// (´[ROOT-cav:observe:secret-profile-payload-buffer]´)
// Justified: The canonical boundary returns a protected vector while the recipe consumes a protected byte slice; this bounded container conversion preserves secrecy.
#[allow(clippy::disallowed_methods)]
fn payload_buffer(encoded: &SecretBox<Vec<u8>>) -> Result<SecretSlice<u8>, ProfileError> {
    let bytes = encoded.expose_secret(/* (´[ROOT-cav:observe:secret-profile-payload-buffer]´) */);
    if bytes.len() > 65_536 {
        return Err(ProfileError::Bound);
    }
    Ok(SecretSlice::from(bytes.clone()))
}

#[cfg(test)]
mod tests;
