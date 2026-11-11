//! Inverse of the single public version-one proposal projection.
use super::{ContentRequest, DependencyRequest, ProfileError, ProposalBody, body_projection};
use pn_interchange::Value;
use pn_records::{ActId, CandidateLeg, Layout, PublicReference, Role, StructuralBody};
use pn_records::{EdgeId, LicenseDegree, LicenseQualifiers, Quantity, SettlementReferences};
fn items(v: &Value) -> Result<&[Value], ProfileError> {
    match v {
        Value::Array(a) => Ok(a.as_slice()),
        _ => Err(ProfileError::Representation),
    }
}
fn string(v: &Value) -> Result<&str, ProfileError> {
    match v {
        Value::Text(t) => Ok(t.as_str()),
        _ => Err(ProfileError::Representation),
    }
}
fn unsigned(v: &Value) -> Result<u64, ProfileError> {
    match v {
        Value::Unsigned(n) => Ok(*n),
        _ => Err(ProfileError::Representation),
    }
}
fn signed(v: &Value) -> Result<i64, ProfileError> {
    let n = match v {
        Value::Unsigned(n) => i128::from(*n),
        Value::Negative(n) => n.get(),
        _ => return Err(ProfileError::Representation),
    };
    n.try_into().map_err(|_| ProfileError::Representation)
}
fn id(v: &Value) -> Result<ActId, ProfileError> {
    let [tag, author, sequence, family] = items(v)? else {
        return Err(ProfileError::Representation);
    };
    if string(tag)? != "act" {
        return Err(ProfileError::Representation);
    }
    Ok(ActId {
        author: string(author)?.into(),
        sequence: unsigned(sequence)?,
        family: string(family)?.into(),
    })
}
fn rrole(v: &Value) -> Result<Role, ProfileError> {
    match string(v)? {
        "binary" => Ok(Role::Binary),
        "A" => Ok(Role::A),
        "T" => Ok(Role::T),
        _ => Err(ProfileError::Representation),
    }
}
fn rref(v: &Value) -> Result<PublicReference, ProfileError> {
    let a = items(v)?;
    match a {
        [tag, ..] if string(tag)? == "act" => Ok(PublicReference::Act(id(v)?)),
        [tag, value] if string(tag)? == "mint" => Ok(PublicReference::Minted(id(value)?)),
        [tag, value, role] if string(tag)? == "record" => Ok(PublicReference::Edge(EdgeId {
            act: id(value)?,
            role: rrole(role)?,
        })),
        [tag, namespace, name] if string(tag)? == "named" => Ok(PublicReference::Named {
            namespace: string(namespace)?.into(),
            name: string(name)?.into(),
        }),
        _ => Err(ProfileError::Representation),
    }
}
fn degree(v: &Value) -> Result<LicenseDegree, ProfileError> {
    let [n, d] = items(v)? else {
        return Err(ProfileError::Representation);
    };
    Ok(LicenseDegree {
        numerator: signed(n)?,
        denominator: signed(d)?,
    })
}
/// Recover public proposal parts from the exact version-one body value.
/// # Errors
/// Refuses values outside the profile bounds or without an identical re-encoding.
/// (´def:profile:body´)
#[tracing::instrument(
    name = "def:profile:body",
    fields(
        execution_owner = "ACTPROFILE",
        claim_owner = "ACTPROFILE",
        claim_label = "def:profile:body",
        source_item = "projection::body_from_projection"
    ),
    ret
)]
pub fn body_from_projection(value: &Value) -> Result<ProposalBody, ProfileError> {
    if value.canonical_len() > 1_048_576 {
        return Err(ProfileError::Bound);
    }
    let [
        identity,
        layout,
        legs,
        quantities,
        license,
        parents,
        protocols,
        settlement,
        content,
        dependency,
    ] = items(value)?
    else {
        return Err(ProfileError::Representation);
    };
    let identity = id(identity)?;
    let layout = match string(layout)? {
        "binary" => Layout::Binary,
        "paired" => Layout::Paired,
        _ => return Err(ProfileError::Representation),
    };
    if items(legs)?.len() > 2 || items(quantities)?.len() > 6 || items(parents)?.len() > 1024 || !items(protocols)?.is_empty() {
        return Err(ProfileError::Bound);
    }
    let legs = items(legs)?
        .iter()
        .map(|v| {
            let [role, source, target] = items(v)? else {
                return Err(ProfileError::Representation);
            };
            Ok(CandidateLeg {
                id: EdgeId {
                    act: identity.clone(),
                    role: rrole(role)?,
                },
                source: rref(source)?,
                target: rref(target)?,
                removal: None,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let quantities = items(quantities)?
        .iter()
        .map(|v| {
            let [name, value, unit, vintage] = items(v)? else {
                return Err(ProfileError::Representation);
            };
            Ok((
                string(name)?.into(),
                Quantity {
                    value: signed(value)?,
                    unit: string(unit)?.into(),
                    vintage: unsigned(vintage)?,
                },
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (license, settlement) = qualifiers(license, settlement)?;
    let result = ProposalBody {
        id: identity,
        body: StructuralBody {
            layout,
            quantities,
            license,
            settlement,
            asserted_parents: items(parents)?.iter().map(id).collect::<Result<_, _>>()?,
        },
        legs,
        protocol_references: Vec::new(),
        content: match string(content)? {
            "full-empty" => ContentRequest::FullEmpty,
            "full" => ContentRequest::Full,
            "reduced" => ContentRequest::Reduced,
            _ => return Err(ProfileError::Representation),
        },
        dependency: match string(dependency)? {
            "full-empty" => DependencyRequest::FullEmpty,
            "full" => DependencyRequest::Full,
            "tombstoned" => DependencyRequest::Tombstoned,
            _ => return Err(ProfileError::Representation),
        },
    };
    if body_projection(&result)? != *value {
        return Err(ProfileError::Representation);
    }
    Ok(result)
}

fn qualifiers(
    license: &Value,
    settlement: &Value,
) -> Result<(Option<LicenseQualifiers>, Option<SettlementReferences>), ProfileError> {
    let license = if *license == Value::Null {
        None
    } else {
        let [a, p] = items(license)? else {
            return Err(ProfileError::Representation);
        };
        Some(LicenseQualifiers {
            attribution: degree(a)?,
            provenance: degree(p)?,
        })
    };
    let settlement = if *settlement == Value::Null {
        None
    } else {
        match items(settlement)? {
            [tag, settles] if string(tag)? == "Accept" => Some(SettlementReferences::Accept { settles: id(settles)? }),
            [tag, settles, accepts] if string(tag)? == "Ratify" => Some(SettlementReferences::Ratify {
                settles: id(settles)?,
                accepts: id(accepts)?,
            }),
            _ => return Err(ProfileError::Representation),
        }
    };
    Ok((license, settlement))
}
