//! Public proposal projection for header comparison.
use pn_act_profile::{ContentRequest, DependencyRequest, ProfileError, ProposalBody};
use pn_interchange::{Array, Text, Value};
use pn_records::{ActId, CandidateLeg, Layout, PublicReference, Role, StructuralBody};
fn text(s: &str) -> Value {
    Value::Text(Text::from(s.to_owned()))
}
fn array(v: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(v))
}
fn identifier(id: &ActId) -> Value {
    array([text("act"), text(&id.author), Value::Unsigned(id.sequence), text(&id.family)])
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

pub(super) fn body_projection(input: &ProposalBody) -> Result<Value, ProfileError> {
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
pub(super) fn decode(value: &Value) -> Result<ProposalBody, ProfileError> {
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
