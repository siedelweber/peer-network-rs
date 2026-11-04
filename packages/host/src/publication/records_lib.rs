//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_records::ActId {
    author,
    sequence,
    family
});
impl Wire for pn_records::Role {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Binary => Ok(array([Value::Unsigned(0)])),
            Self::A => Ok(array([Value::Unsigned(1)])),
            Self::T => Ok(array([Value::Unsigned(2)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Binary,
            1 => Self::A,
            2 => Self::T,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::EdgeId { act, role });
impl Wire for pn_records::PublicReference {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Act(v0) => Ok(array([Value::Unsigned(0), v0.write(c)?])),
            Self::Edge(v0) => Ok(array([Value::Unsigned(1), v0.write(c)?])),
            Self::Named { namespace, name } => Ok(array([Value::Unsigned(2), namespace.write(c)?, name.write(c)?])),
            Self::Minted(v0) => Ok(array([Value::Unsigned(3), v0.write(c)?])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Act(take(&mut fields, c)?),
            1 => Self::Edge(take(&mut fields, c)?),
            2 => Self::Named {
                namespace: take(&mut fields, c)?,
                name: take(&mut fields, c)?,
            },
            3 => Self::Minted(take(&mut fields, c)?),
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::Layout {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Binary => Ok(array([Value::Unsigned(0)])),
            Self::Paired => Ok(array([Value::Unsigned(1)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Binary,
            1 => Self::Paired,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::TimeVerdict {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Matches => Ok(array([Value::Unsigned(0)])),
            Self::Mismatch { attached, expected } => Ok(array([Value::Unsigned(1), attached.write(c)?, expected.write(c)?])),
            Self::UnavailableOpening => Ok(array([Value::Unsigned(2)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Matches,
            1 => Self::Mismatch {
                attached: take(&mut fields, c)?,
                expected: take(&mut fields, c)?,
            },
            2 => Self::UnavailableOpening,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::RecomputedTime {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Available(v0) => Ok(array([Value::Unsigned(0), v0.write(c)?])),
            Self::Unavailable(v0) => Ok(array([Value::Unsigned(1), v0.write(c)?])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Available(take(&mut fields, c)?),
            1 => Self::Unavailable(take(&mut fields, c)?),
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::TimeEvidence {
    act,
    verdict,
    recomputed
});
impl Wire for pn_records::Removal {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Live => Ok(array([Value::Unsigned(0)])),
            Self::Tombstoned(v0) => Ok(array([Value::Unsigned(1), v0.write(c)?])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Live,
            1 => Self::Tombstoned(take(&mut fields, c)?),
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::CandidateLeg {
    id,
    source,
    target,
    removal
});
structure!(pn_records::Quantity { value, unit, vintage });
structure!(pn_records::LicenseDegree { numerator, denominator });
structure!(pn_records::LicenseQualifiers { attribution, provenance });
impl Wire for pn_records::SettlementReferences {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Accept { settles } => Ok(array([Value::Unsigned(0), settles.write(c)?])),
            Self::Ratify { settles, accepts } => Ok(array([Value::Unsigned(1), settles.write(c)?, accepts.write(c)?])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Accept {
                settles: take(&mut fields, c)?,
            },
            1 => Self::Ratify {
                settles: take(&mut fields, c)?,
                accepts: take(&mut fields, c)?,
            },
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::StructuralBody {
    settlement,
    license,
    asserted_parents,
    layout,
    quantities
});
structure!(pn_records::CandidateAct {
    commitments,
    id,
    body,
    legs,
    projections,
    protocol_references,
    authentication_evidence,
    finalization_epoch,
    authoritative_position,
    logical_time
});
structure!(pn_records::RemovableProjections { content, dependency });
impl Wire for pn_records::DependencyProjection {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::FullEmpty => Ok(array([Value::Unsigned(0)])),
            Self::Full(v0) => Ok(array([Value::Unsigned(1), v0.write(c)?])),
            Self::Tombstoned(v0) => Ok(array([Value::Unsigned(2), v0.write(c)?])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::FullEmpty,
            1 => Self::Full(take(&mut fields, c)?),
            2 => Self::Tombstoned(take(&mut fields, c)?),
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::DeclarationId {
    namespace,
    name,
    edition
});
impl Wire for pn_records::DeclarationContent {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Opaque => Ok(array([Value::Unsigned(0)])),
            Self::Deployment { genesis_at } => Ok(array([Value::Unsigned(1), genesis_at.write(c)?])),
            Self::MarkerPolicy { recipe, digest } => Ok(array([Value::Unsigned(2), recipe.write(c)?, digest.write(c)?])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Opaque,
            1 => Self::Deployment {
                genesis_at: take(&mut fields, c)?,
            },
            2 => Self::MarkerPolicy {
                recipe: take(&mut fields, c)?,
                digest: take(&mut fields, c)?,
            },
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::Declaration {
    id,
    announced_at,
    effective_at,
    content
});
impl Wire for pn_records::ValidationError {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Parent { act, parent, cause } => {
                Ok(array([Value::Unsigned(0), act.write(c)?, parent.write(c)?, cause.write(c)?]))
            }
            Self::DuplicateAct(v0) => Ok(array([Value::Unsigned(1), v0.write(c)?])),
            Self::DuplicateEdge(v0) => Ok(array([Value::Unsigned(2), v0.write(c)?])),
            Self::UnresolvedReference(v0) => Ok(array([Value::Unsigned(3), v0.write(c)?])),
            Self::MissingCoLeg { act, role } => Ok(array([Value::Unsigned(4), act.write(c)?, role.write(c)?])),
            Self::InvalidRepresentation { act, cause } => Ok(array([Value::Unsigned(5), act.write(c)?, cause.write(c)?])),
            Self::InvalidReference(v0) => Ok(array([Value::Unsigned(6), v0.write(c)?])),
            Self::InvalidDeclaration { id, cause } => Ok(array([Value::Unsigned(7), id.write(c)?, cause.write(c)?])),
            Self::InvalidSelectionKey(v0) => Ok(array([Value::Unsigned(8), v0.write(c)?])),
            Self::Dependency { act, dependency, cause } => Ok(array([
                Value::Unsigned(9),
                act.write(c)?,
                dependency.write(c)?,
                cause.write(c)?,
            ])),
            Self::DuplicateDeclaration(v0) => Ok(array([Value::Unsigned(10), v0.write(c)?])),
            Self::AmbiguousDeclaration(v0) => Ok(array([Value::Unsigned(11), v0.write(c)?])),
            Self::MissingDeclaration {
                namespace,
                name,
                boundary,
            } => Ok(array([
                Value::Unsigned(12),
                namespace.write(c)?,
                name.write(c)?,
                boundary.write(c)?,
            ])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Parent {
                act: take(&mut fields, c)?,
                parent: take(&mut fields, c)?,
                cause: take(&mut fields, c)?,
            },
            1 => Self::DuplicateAct(take(&mut fields, c)?),
            2 => Self::DuplicateEdge(take(&mut fields, c)?),
            3 => Self::UnresolvedReference(take(&mut fields, c)?),
            4 => Self::MissingCoLeg {
                act: take(&mut fields, c)?,
                role: take(&mut fields, c)?,
            },
            5 => Self::InvalidRepresentation {
                act: take(&mut fields, c)?,
                cause: take(&mut fields, c)?,
            },
            6 => Self::InvalidReference(take(&mut fields, c)?),
            7 => Self::InvalidDeclaration {
                id: take(&mut fields, c)?,
                cause: take(&mut fields, c)?,
            },
            8 => Self::InvalidSelectionKey(take(&mut fields, c)?),
            9 => Self::Dependency {
                act: take(&mut fields, c)?,
                dependency: take(&mut fields, c)?,
                cause: take(&mut fields, c)?,
            },
            10 => Self::DuplicateDeclaration(take(&mut fields, c)?),
            11 => Self::AmbiguousDeclaration(take(&mut fields, c)?),
            12 => Self::MissingDeclaration {
                namespace: take(&mut fields, c)?,
                name: take(&mut fields, c)?,
                boundary: take(&mut fields, c)?,
            },
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::ParentCause {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::TooMany => Ok(array([Value::Unsigned(0)])),
            Self::NonCanonical => Ok(array([Value::Unsigned(1)])),
            Self::SelfParent => Ok(array([Value::Unsigned(2)])),
            Self::Missing => Ok(array([Value::Unsigned(3)])),
            Self::NotEarlier => Ok(array([Value::Unsigned(4)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::TooMany,
            1 => Self::NonCanonical,
            2 => Self::SelfParent,
            3 => Self::Missing,
            4 => Self::NotEarlier,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::InvalidCause {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::FinalizationEpoch => Ok(array([Value::Unsigned(0)])),
            Self::FinalizedPosition => Ok(array([Value::Unsigned(1)])),
            Self::RepeatedPosition => Ok(array([Value::Unsigned(2)])),
            Self::MissingPosition => Ok(array([Value::Unsigned(3)])),
            Self::PositionOutsideEpoch => Ok(array([Value::Unsigned(4)])),
            Self::EmptyAuthor => Ok(array([Value::Unsigned(5)])),
            Self::EmptyFamily => Ok(array([Value::Unsigned(6)])),
            Self::EmptyAuthentication => Ok(array([Value::Unsigned(7)])),
            Self::EmptyQuantityName => Ok(array([Value::Unsigned(8)])),
            Self::DuplicateQuantityName => Ok(array([Value::Unsigned(9)])),
            Self::EmptyUnit => Ok(array([Value::Unsigned(10)])),
            Self::ProjectionParent => Ok(array([Value::Unsigned(11)])),
            Self::ProjectionRole => Ok(array([Value::Unsigned(12)])),
            Self::ReferenceComponent => Ok(array([Value::Unsigned(13)])),
            Self::LicenseQualifiers => Ok(array([Value::Unsigned(14)])),
            Self::SettlementReferences => Ok(array([Value::Unsigned(15)])),
            Self::CoLegRemoval => Ok(array([Value::Unsigned(16)])),
            Self::TombstonePosition => Ok(array([Value::Unsigned(17)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::FinalizationEpoch,
            1 => Self::FinalizedPosition,
            2 => Self::RepeatedPosition,
            3 => Self::MissingPosition,
            4 => Self::PositionOutsideEpoch,
            5 => Self::EmptyAuthor,
            6 => Self::EmptyFamily,
            7 => Self::EmptyAuthentication,
            8 => Self::EmptyQuantityName,
            9 => Self::DuplicateQuantityName,
            10 => Self::EmptyUnit,
            11 => Self::ProjectionParent,
            12 => Self::ProjectionRole,
            13 => Self::ReferenceComponent,
            14 => Self::LicenseQualifiers,
            15 => Self::SettlementReferences,
            16 => Self::CoLegRemoval,
            17 => Self::TombstonePosition,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::DeclarationCause {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::EmptyNamespace => Ok(array([Value::Unsigned(0)])),
            Self::EmptyName => Ok(array([Value::Unsigned(1)])),
            Self::LateAnnouncement => Ok(array([Value::Unsigned(2)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::EmptyNamespace,
            1 => Self::EmptyName,
            2 => Self::LateAnnouncement,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::DependencyCause {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::EmptyFull => Ok(array([Value::Unsigned(0)])),
            Self::TooMany => Ok(array([Value::Unsigned(1)])),
            Self::NonCanonical => Ok(array([Value::Unsigned(2)])),
            Self::SelfDependency => Ok(array([Value::Unsigned(3)])),
            Self::Missing => Ok(array([Value::Unsigned(4)])),
            Self::NotEarlier => Ok(array([Value::Unsigned(5)])),
            Self::BoundaryPlacement => Ok(array([Value::Unsigned(6)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::EmptyFull,
            1 => Self::TooMany,
            2 => Self::NonCanonical,
            3 => Self::SelfDependency,
            4 => Self::Missing,
            5 => Self::NotEarlier,
            6 => Self::BoundaryPlacement,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
