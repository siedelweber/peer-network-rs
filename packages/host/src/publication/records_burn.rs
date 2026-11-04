//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, newtype, structure, take};

newtype!(pn_records::burn::Address);
impl Wire for pn_records::burn::OperatorEvidence {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::Bound { amount, proof } => Ok(array([Value::Unsigned(0), amount.write(c)?, proof.write(c)?])),
            Self::Absent { explanation } => Ok(array([Value::Unsigned(1), explanation.write(c)?])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::Bound {
                amount: take(&mut fields, c)?,
                proof: take(&mut fields, c)?,
            },
            1 => Self::Absent {
                explanation: take(&mut fields, c)?,
            },
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::burn::Bootstrap {
    bound,
    empty_interval,
    explanation
});
structure!(pn_records::burn::BurnInput {
    address_space,
    edition,
    sample_convention,
    boundary,
    read_addresses,
    amounts,
    bootstrap,
    unit_cost,
    evidence
});
structure!(pn_records::burn::BurnEvidence {
    edition,
    sample_convention,
    settlement_depth,
    finality_assumptions,
    provenance,
    recording_costs,
    operator
});
impl Wire for pn_records::burn::Encoding {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::CompleteList => Ok(array([Value::Unsigned(0)])),
            Self::PublicCommitment => Ok(array([Value::Unsigned(1)])),
            Self::WholePrefixAcceptAll => Ok(array([Value::Unsigned(2)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::CompleteList,
            1 => Self::PublicCommitment,
            2 => Self::WholePrefixAcceptAll,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::burn::CandidateRule {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::FirstValidInHistoryOrder => Ok(array([Value::Unsigned(0)])),
            Self::UniquePerIndex => Ok(array([Value::Unsigned(1)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::FirstValidInHistoryOrder,
            1 => Self::UniquePerIndex,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::burn::PolicyInput {
    identity,
    edition,
    sequence,
    published_at,
    genesis_at,
    initial_marker,
    open_placement,
    placement_procedure,
    cadence,
    encoding,
    candidate_rule,
    verification_profile,
    stability_buffer
});
structure!(pn_records::burn::BurnRecord {
    identity,
    destruction,
    address,
    amount,
    evidence
});
structure!(pn_records::burn::Opening { members, proof });
impl Wire for pn_records::burn::AcceptedSet {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::CompleteList(v0) => Ok(array([Value::Unsigned(0), v0.write(c)?])),
            Self::Commitment { commitment, openings } => {
                Ok(array([Value::Unsigned(1), commitment.write(c)?, openings.write(c)?]))
            }
            Self::WholePrefix => Ok(array([Value::Unsigned(2)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::CompleteList(take(&mut fields, c)?),
            1 => Self::Commitment {
                commitment: take(&mut fields, c)?,
                openings: take(&mut fields, c)?,
            },
            2 => Self::WholePrefix,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
structure!(pn_records::burn::Marker {
    name,
    history,
    policy_identity,
    policy_edition,
    sequence,
    index,
    history_position,
    predecessor,
    lineage,
    accepted,
    initial_snapshot
});
structure!(pn_records::burn::HistoryInput {
    identity,
    records,
    markers
});
structure!(pn_records::burn::RecognitionBasis {
    history,
    policy_identity,
    policy_edition,
    verifier_profile,
    burn_publication_edition,
    sample_convention
});
structure!(pn_records::burn::CandidateRefusal {
    candidate,
    cause,
    competitors
});
impl Wire for pn_records::burn::Disclosure {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::AddressSpace => Ok(array([Value::Unsigned(0)])),
            Self::Edition => Ok(array([Value::Unsigned(1)])),
            Self::SampleConvention => Ok(array([Value::Unsigned(2)])),
            Self::Bootstrap => Ok(array([Value::Unsigned(3)])),
            Self::UnitCost => Ok(array([Value::Unsigned(4)])),
            Self::SettlementDepth => Ok(array([Value::Unsigned(5)])),
            Self::Finality => Ok(array([Value::Unsigned(6)])),
            Self::Provenance => Ok(array([Value::Unsigned(7)])),
            Self::RecordingCosts => Ok(array([Value::Unsigned(8)])),
            Self::Operator => Ok(array([Value::Unsigned(9)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::AddressSpace,
            1 => Self::Edition,
            2 => Self::SampleConvention,
            3 => Self::Bootstrap,
            4 => Self::UnitCost,
            5 => Self::SettlementDepth,
            6 => Self::Finality,
            7 => Self::Provenance,
            8 => Self::RecordingCosts,
            9 => Self::Operator,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
impl Wire for pn_records::burn::BurnError {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        match self {
            Self::PolicySelection(v0) => Ok(array([Value::Unsigned(0), v0.write(c)?])),
            Self::PolicyBinding => Ok(array([Value::Unsigned(1)])),
            Self::DeploymentBinding => Ok(array([Value::Unsigned(2)])),
            Self::PolicyDigest => Ok(array([Value::Unsigned(3)])),
            Self::UnsupportedPolicyRecipe => Ok(array([Value::Unsigned(4)])),
            Self::Publication(v0) => Ok(array([Value::Unsigned(5), v0.write(c)?])),
            Self::EvidenceBinding => Ok(array([Value::Unsigned(6)])),
            Self::SampleCoverage => Ok(array([Value::Unsigned(7)])),
            Self::Units => Ok(array([Value::Unsigned(8)])),
            Self::Bootstrap => Ok(array([Value::Unsigned(9)])),
            Self::Policy => Ok(array([Value::Unsigned(10)])),
            Self::Buffer => Ok(array([Value::Unsigned(11)])),
            Self::Verifier => Ok(array([Value::Unsigned(12)])),
            Self::RecordIdentity => Ok(array([Value::Unsigned(13)])),
            Self::HistoryPolicy => Ok(array([Value::Unsigned(14)])),
            Self::HistoryPosition => Ok(array([Value::Unsigned(15)])),
            Self::Initial => Ok(array([Value::Unsigned(16)])),
            Self::Succession => Ok(array([Value::Unsigned(17)])),
            Self::MissingLineage => Ok(array([Value::Unsigned(18)])),
            Self::RegressedLineage => Ok(array([Value::Unsigned(19)])),
            Self::Encoding => Ok(array([Value::Unsigned(20)])),
            Self::MissingOpening => Ok(array([Value::Unsigned(21)])),
            Self::AmbiguousOpening => Ok(array([Value::Unsigned(22)])),
            Self::InvalidOpening => Ok(array([Value::Unsigned(23)])),
            Self::RegressedAcceptance => Ok(array([Value::Unsigned(24)])),
            Self::OutOfLineage => Ok(array([Value::Unsigned(25)])),
            Self::InvalidMember => Ok(array([Value::Unsigned(26)])),
            Self::InconsistentAlias => Ok(array([Value::Unsigned(27)])),
        }
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let Some(Value::Unsigned(tag)) = fields.next() else {
            return Err(Error::Shape);
        };
        let result = match tag {
            0 => Self::PolicySelection(take(&mut fields, c)?),
            1 => Self::PolicyBinding,
            2 => Self::DeploymentBinding,
            3 => Self::PolicyDigest,
            4 => Self::UnsupportedPolicyRecipe,
            5 => Self::Publication(take(&mut fields, c)?),
            6 => Self::EvidenceBinding,
            7 => Self::SampleCoverage,
            8 => Self::Units,
            9 => Self::Bootstrap,
            10 => Self::Policy,
            11 => Self::Buffer,
            12 => Self::Verifier,
            13 => Self::RecordIdentity,
            14 => Self::HistoryPolicy,
            15 => Self::HistoryPosition,
            16 => Self::Initial,
            17 => Self::Succession,
            18 => Self::MissingLineage,
            19 => Self::RegressedLineage,
            20 => Self::Encoding,
            21 => Self::MissingOpening,
            22 => Self::AmbiguousOpening,
            23 => Self::InvalidOpening,
            24 => Self::RegressedAcceptance,
            25 => Self::OutOfLineage,
            26 => Self::InvalidMember,
            27 => Self::InconsistentAlias,
            _ => return Err(Error::Shape),
        };
        finish(fields)?;
        Ok(result)
    }
}
