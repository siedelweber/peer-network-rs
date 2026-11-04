//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, take};
use pn_epoch::publication::disclosures as d;

impl Wire for d::InvalidCode {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::UnsupportedCertificate => Ok(array([Value::Unsigned(0)])),
            Self::DecisionOptionMismatch => Ok(array([Value::Unsigned(1)])),
            Self::DecisionBox => Ok(array([Value::Unsigned(2)])),
            Self::DecisionBoundaryIntersection => Ok(array([Value::Unsigned(3)])),
            Self::DecisionOutsideRegion => Ok(array([Value::Unsigned(4)])),
            Self::DecisionIntegerRange => Ok(array([Value::Unsigned(5)])),
            Self::DecisionMaterializationCapacity => Ok(array([Value::Unsigned(6)])),
            Self::DecisionPartitionOverlap => Ok(array([Value::Unsigned(7)])),
            Self::DecisionPartitionOutsideDomain => Ok(array([Value::Unsigned(8)])),
            Self::StrictSignUnavailable => Ok(array([Value::Unsigned(9)])),
            Self::JacobianReadingCycle => Ok(array([Value::Unsigned(10)])),
            Self::JacobianFixedSource => Ok(array([Value::Unsigned(11)])),
            Self::JacobianDuplicateSource => Ok(array([Value::Unsigned(12)])),
            Self::JacobianDomain => Ok(array([Value::Unsigned(13)])),
            Self::ReuseKeyMismatch => Ok(array([Value::Unsigned(14)])),
            Self::ReadingSingular => Ok(array([Value::Unsigned(15)])),
            Self::ReadingNonsingularity => Ok(array([Value::Unsigned(16)])),
            Self::DependencyWitness => Ok(array([Value::Unsigned(17)])),
            Self::SelectionExpected => Ok(array([Value::Unsigned(18)])),
            Self::SelectionBase => Ok(array([Value::Unsigned(19)])),
            Self::SelectionDeclaration => Ok(array([Value::Unsigned(20)])),
            Self::SelectionDefinition => Ok(array([Value::Unsigned(21)])),
            Self::SelectionShape => Ok(array([Value::Unsigned(22)])),
            Self::SelectionOutOfRange => Ok(array([Value::Unsigned(23)])),
            Self::SelectionDuplicate => Ok(array([Value::Unsigned(24)])),
            Self::SelectionOrder => Ok(array([Value::Unsigned(25)])),
            Self::ReadingShape => Ok(array([Value::Unsigned(26)])),
            Self::ReadingDefinition => Ok(array([Value::Unsigned(27)])),
            Self::ReadingUnrelated => Ok(array([Value::Unsigned(28)])),
            Self::ReadingMismatch => Ok(array([Value::Unsigned(29)])),
            Self::SpaceRegistrationUnavailable => Ok(array([Value::Unsigned(30)])),
            Self::SpacePlacementUnavailable => Ok(array([Value::Unsigned(31)])),
            Self::AmbientSpaceAmbiguous => Ok(array([Value::Unsigned(32)])),
            Self::SymbolSortMismatch => Ok(array([Value::Unsigned(33)])),
            Self::AmbientSpaceMismatch => Ok(array([Value::Unsigned(34)])),
            Self::PullbackMultipleZero => Ok(array([Value::Unsigned(35)])),
            Self::PullbackIncompleteZeros => Ok(array([Value::Unsigned(36)])),
            Self::PullbackMapMismatch => Ok(array([Value::Unsigned(37)])),
            Self::AnalyticDisagreement => Ok(array([Value::Unsigned(38)])),
            Self::DistributionPointValue => Ok(array([Value::Unsigned(39)])),
            Self::DistributionProductUndefined => Ok(array([Value::Unsigned(40)])),
            Self::TestSpaceMismatch => Ok(array([Value::Unsigned(41)])),
            Self::UnknownTotality => Ok(array([Value::Unsigned(42)])),
            Self::PendingPremise => Ok(array([Value::Unsigned(43)])),
            Self::OverlapConflict => Ok(array([Value::Unsigned(44)])),
            Self::CoverageHole => Ok(array([Value::Unsigned(45)])),
            Self::Literal => Ok(array([Value::Unsigned(46)])),
            Self::ZeroDenominator => Ok(array([Value::Unsigned(47)])),
            Self::UndefinedPower => Ok(array([Value::Unsigned(48)])),
            Self::Span => Ok(array([Value::Unsigned(49)])),
            Self::ForeignHandle => Ok(array([Value::Unsigned(50)])),
            Self::Reference => Ok(array([Value::Unsigned(51)])),
            Self::Scope => Ok(array([Value::Unsigned(52)])),
            Self::Sort => Ok(array([Value::Unsigned(53)])),
            Self::Context => Ok(array([Value::Unsigned(54)])),
            Self::Policy => Ok(array([Value::Unsigned(55)])),
            Self::SourceConflict => Ok(array([Value::Unsigned(56)])),
            Self::OccurrenceParent => Ok(array([Value::Unsigned(57)])),
            Self::Receipt => Ok(array([Value::Unsigned(58)])),
            Self::Encoding => Ok(array([Value::Unsigned(59)])),
            Self::Rule => Ok(array([Value::Unsigned(60)])),
            Self::EndpointMismatch => Ok(array([Value::Unsigned(61)])),
            Self::ConditionMismatch => Ok(array([Value::Unsigned(62)])),
            Self::UnsupportedVersion => Ok(array([Value::Unsigned(63)])),
            Self::UnsupportedFragment => Ok(array([Value::Unsigned(64)])),
            Self::PolynomialFragment => Ok(array([Value::Unsigned(65)])),
            Self::CoefficientField => Ok(array([Value::Unsigned(66)])),
            Self::ZeroPolynomial => Ok(array([Value::Unsigned(67)])),
            Self::RefutedDomain => Ok(array([Value::Unsigned(68)])),
            Self::EmptyDomain => Ok(array([Value::Unsigned(69)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::UnsupportedCertificate,
            1 => Self::DecisionOptionMismatch,
            2 => Self::DecisionBox,
            3 => Self::DecisionBoundaryIntersection,
            4 => Self::DecisionOutsideRegion,
            5 => Self::DecisionIntegerRange,
            6 => Self::DecisionMaterializationCapacity,
            7 => Self::DecisionPartitionOverlap,
            8 => Self::DecisionPartitionOutsideDomain,
            9 => Self::StrictSignUnavailable,
            10 => Self::JacobianReadingCycle,
            11 => Self::JacobianFixedSource,
            12 => Self::JacobianDuplicateSource,
            13 => Self::JacobianDomain,
            14 => Self::ReuseKeyMismatch,
            15 => Self::ReadingSingular,
            16 => Self::ReadingNonsingularity,
            17 => Self::DependencyWitness,
            18 => Self::SelectionExpected,
            19 => Self::SelectionBase,
            20 => Self::SelectionDeclaration,
            21 => Self::SelectionDefinition,
            22 => Self::SelectionShape,
            23 => Self::SelectionOutOfRange,
            24 => Self::SelectionDuplicate,
            25 => Self::SelectionOrder,
            26 => Self::ReadingShape,
            27 => Self::ReadingDefinition,
            28 => Self::ReadingUnrelated,
            29 => Self::ReadingMismatch,
            30 => Self::SpaceRegistrationUnavailable,
            31 => Self::SpacePlacementUnavailable,
            32 => Self::AmbientSpaceAmbiguous,
            33 => Self::SymbolSortMismatch,
            34 => Self::AmbientSpaceMismatch,
            35 => Self::PullbackMultipleZero,
            36 => Self::PullbackIncompleteZeros,
            37 => Self::PullbackMapMismatch,
            38 => Self::AnalyticDisagreement,
            39 => Self::DistributionPointValue,
            40 => Self::DistributionProductUndefined,
            41 => Self::TestSpaceMismatch,
            42 => Self::UnknownTotality,
            43 => Self::PendingPremise,
            44 => Self::OverlapConflict,
            45 => Self::CoverageHole,
            46 => Self::Literal,
            47 => Self::ZeroDenominator,
            48 => Self::UndefinedPower,
            49 => Self::Span,
            50 => Self::ForeignHandle,
            51 => Self::Reference,
            52 => Self::Scope,
            53 => Self::Sort,
            54 => Self::Context,
            55 => Self::Policy,
            56 => Self::SourceConflict,
            57 => Self::OccurrenceParent,
            58 => Self::Receipt,
            59 => Self::Encoding,
            60 => Self::Rule,
            61 => Self::EndpointMismatch,
            62 => Self::ConditionMismatch,
            63 => Self::UnsupportedVersion,
            64 => Self::UnsupportedFragment,
            65 => Self::PolynomialFragment,
            66 => Self::CoefficientField,
            67 => Self::ZeroPolynomial,
            68 => Self::RefutedDomain,
            69 => Self::EmptyDomain,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for d::Exhaustion {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Limit => Ok(array([Value::Unsigned(0)])),
            Self::ArithmeticRange => Ok(array([Value::Unsigned(1)])),
            Self::Allocation => Ok(array([Value::Unsigned(2)])),
            Self::Capacity => Ok(array([Value::Unsigned(3)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Limit,
            1 => Self::ArithmeticRange,
            2 => Self::Allocation,
            3 => Self::Capacity,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for d::FaultKind {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Invalid(v0) => Ok(array([Value::Unsigned(0), v0.write(c)?])),
            Self::Exhausted {
                reason,
                budget,
                limit,
                needed,
            } => Ok(array([
                Value::Unsigned(1),
                reason.write(c)?,
                budget.write(c)?,
                limit.write(c)?,
                needed.write(c)?,
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
            0 => Self::Invalid(take(&mut fields, c)?),
            1 => Self::Exhausted {
                reason: take(&mut fields, c)?,
                budget: take(&mut fields, c)?,
                limit: take(&mut fields, c)?,
                needed: take(&mut fields, c)?,
            },
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
