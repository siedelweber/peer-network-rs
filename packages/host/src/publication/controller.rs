//! Explicit controller edition-two fragment codecs, never a publication producer.
//! (´[ROOT-dec:design:comparison-verdict-record]´)

use super::{
    comparison::{self, Limits},
    scalars::ExactText,
    wire::{Context, Wire, array},
};
use pn_interchange::Value;
use pn_records::{
    controller::{
        Inputs,
        v2::{Attempt, Branches, Context as Request, Record, ResultKind, Stage},
    },
    numerics::{ExactLimits, NumericContext},
    solve::Procedure,
};

/// Structural decoding or carrier-validation refusal, never a verdict.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Debug)]
pub enum Error {
    /// Shared canonical or nested comparison framing refused.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Comparison(comparison::Error),
    /// An inherited publication projection refused its member.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Projection(super::Error),
    /// A stage code is outside the second edition's closed seven.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Stage,
    /// A result code is outside the four disjoint constructors.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Result,
    /// The typed carrier refused its first semantic clause.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Record(pn_records::controller::v2::Error),
}

impl From<comparison::Error> for Error {
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "publication::controller::<Error as From < comparison :: Error >>::from"
        ),
        ret
    )]
    fn from(error: comparison::Error) -> Self {
        Self::Comparison(error)
    }
}

fn stage(value: &Value) -> Result<Stage, Error> {
    let members = comparison::fields(value, 1)?;
    match comparison::unsigned(&members[0])? {
        0 => Ok(Stage::Floor),
        1 => Ok(Stage::InverseGain),
        2 => Ok(Stage::Deadband),
        3 => Ok(Stage::Direction),
        4 => Ok(Stage::AbsoluteCap),
        5 => Ok(Stage::RelativeCap),
        6 => Ok(Stage::Delivery),
        _ => Err(Error::Stage),
    }
}

fn stage_value(stage: Stage) -> Value {
    array([Value::Unsigned(match stage {
        Stage::Floor => 0,
        Stage::InverseGain => 1,
        Stage::Deadband => 2,
        Stage::Direction => 3,
        Stage::AbsoluteCap => 4,
        Stage::RelativeCap => 5,
        Stage::Delivery => 6,
    })])
}

fn option<T>(value: &Value, read: impl FnOnce(&Value) -> Result<T, Error>) -> Result<Option<T>, Error> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        read(value).map(Some)
    }
}

fn branches(value: &Value, context: &mut Context<'_>, limits: &ExactLimits) -> Result<Branches, Error> {
    let members = comparison::fields(value, 8)?;
    Ok(Branches {
        zero_width: bool::read(&members[0], context).map_err(Error::Projection)?,
        floor: option(&members[1], |value| {
            comparison::floor_read(value, limits).map_err(Error::Comparison)
        })?,
        deadband: option(&members[2], |value| {
            comparison::floor_read(value, limits).map_err(Error::Comparison)
        })?,
        absolute_cap: option(&members[3], |value| {
            comparison::floor_read(value, limits).map_err(Error::Comparison)
        })?,
        relative_cap: option(&members[4], |value| {
            comparison::floor_read(value, limits).map_err(Error::Comparison)
        })?,
        direction: option(&members[5], |value| {
            comparison::floor_read(value, limits).map_err(Error::Comparison)
        })?,
        proposal: Wire::read(&members[6], context).map_err(Error::Projection)?,
        ideal: option(&members[7], |value| Wire::read(value, context).map_err(Error::Projection))?,
    })
}

fn branches_value(branches: &Branches, context: &mut Context<'_>) -> Result<Value, Error> {
    Ok(array([
        branches.zero_width.write(context).map_err(Error::Projection)?,
        branches.floor.as_ref().map_or(Value::Null, comparison::floor_value),
        branches.deadband.as_ref().map_or(Value::Null, comparison::floor_value),
        branches.absolute_cap.as_ref().map_or(Value::Null, comparison::floor_value),
        branches.relative_cap.as_ref().map_or(Value::Null, comparison::floor_value),
        branches.direction.as_ref().map_or(Value::Null, comparison::floor_value),
        branches.proposal.write(context).map_err(Error::Projection)?,
        branches.ideal.write(context).map_err(Error::Projection)?,
    ]))
}

fn result(value: &Value, limits: &ExactLimits) -> Result<ResultKind, Error> {
    let Value::Array(items) = value else {
        return Err(comparison::Error::Member.into());
    };
    let code = comparison::unsigned(items.as_slice().first().ok_or(comparison::Error::Arity)?)?;
    match code {
        0 => {
            comparison::fields(value, 1)?;
            Ok(ResultKind::Delivered)
        }
        1 | 3 => {
            let members = comparison::fields(value, 3)?;
            let stage = stage(&members[1])?;
            let comparison = comparison::floor_read(&members[2], limits)?;
            Ok(if code == 1 {
                ResultKind::Indecisive { stage, comparison }
            } else {
                ResultKind::Refused { stage, comparison }
            })
        }
        2 => {
            let members = comparison::fields(value, 3)?;
            Ok(ResultKind::Operational {
                stage: stage(&members[1])?,
                cause: comparison::unsigned(&members[2])?,
            })
        }
        _ => Err(Error::Result),
    }
}

fn result_value(result: &ResultKind) -> Value {
    match result {
        ResultKind::Delivered => array([Value::Unsigned(0)]),
        ResultKind::Indecisive { stage, comparison } => {
            array([Value::Unsigned(1), stage_value(*stage), comparison::floor_value(comparison)])
        }
        ResultKind::Operational { stage, cause } => array([Value::Unsigned(2), stage_value(*stage), Value::Unsigned(*cause)]),
        ResultKind::Refused { stage, comparison } => {
            array([Value::Unsigned(3), stage_value(*stage), comparison::floor_value(comparison)])
        }
    }
}

fn attempt(value: &Value, context: &mut Context<'_>, limits: &ExactLimits) -> Result<Attempt, Error> {
    let members = comparison::selected(value, 9)?;
    let precision = u32::read(&members[1], context).map_err(Error::Projection)?;
    let stopped_at = option(&members[2], stage)?;
    let inverse = Wire::read(&members[3], context).map_err(Error::Projection)?;
    let Value::Array(checks) = &members[4] else {
        return Err(comparison::Error::Member.into());
    };
    let floor_checks = checks
        .as_slice()
        .iter()
        .map(|check| comparison::ridge_read(check, context, limits).map_err(Error::Comparison))
        .collect::<Result<_, _>>()?;
    let branches = option(&members[5], |value| branches(value, context, limits))?;
    let delivered = Option::<String>::read_exact(&members[6], context).map_err(Error::Projection)?;
    let delivery_error = Wire::read(&members[7], context).map_err(Error::Projection)?;
    let result = result(&members[8], limits)?;
    Ok(Attempt {
        precision,
        stopped_at,
        inverse,
        floor_checks,
        branches,
        delivered,
        delivery_error,
        result,
    })
}

fn attempt_value(attempt: &Attempt, context: &mut Context<'_>) -> Result<Value, Error> {
    Ok(array([
        Value::Unsigned(2),
        attempt.precision.write(context).map_err(Error::Projection)?,
        attempt.stopped_at.map_or(Value::Null, stage_value),
        attempt.inverse.write(context).map_err(Error::Projection)?,
        array(
            attempt
                .floor_checks
                .iter()
                .map(|check| comparison::ridge_value(check, context))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        attempt
            .branches
            .as_ref()
            .map(|branches| branches_value(branches, context))
            .transpose()?
            .unwrap_or(Value::Null),
        attempt.delivered.write_exact(context).map_err(Error::Projection)?,
        attempt.delivery_error.write(context).map_err(Error::Projection)?,
        result_value(&attempt.result),
    ]))
}

/// Decode only the caller-selected second-edition attempt against an independent context.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
/// # Errors
/// Refuses canonical spelling, framing, a nested edition or the first carrier clause.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        operation = "controller-attempt-decode",
        source_item = "publication::controller::decode_attempt"
    ),
    ret
)]
pub fn decode_attempt(
    bytes: &[u8],
    request: &Request<'_>,
    expected: &Request<'_>,
    numeric: &mut NumericContext,
    limits: &Limits,
) -> Result<Attempt, Error> {
    let value = comparison::read(bytes, limits)?;
    comparison::selected(&value, 9)?;
    let mut context = comparison::context(numeric, &limits.arithmetic)?;
    let attempt = attempt(&value, &mut context, &limits.arithmetic)?;
    attempt
        .validate(request, expected, &mut context.arithmetic)
        .map_err(Error::Record)?;
    Ok(attempt)
}

/// Encode an explicitly selected attempt without changing a publication producer.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
/// # Errors
/// Refuses a carrier violation, invalid projection or exhausted supplied ceiling.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        operation = "controller-attempt-encode",
        source_item = "publication::controller::encode_attempt"
    ),
    ret
)]
pub fn encode_attempt(
    attempt: &Attempt,
    request: &Request<'_>,
    expected: &Request<'_>,
    numeric: &mut NumericContext,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    let mut context = comparison::context(numeric, &limits.arithmetic)?;
    attempt
        .validate(request, expected, &mut context.arithmetic)
        .map_err(Error::Record)?;
    let value = attempt_value(attempt, &mut context)?;
    let bytes = value.to_canonical_bytes();
    comparison::read(&bytes, limits)?;
    Ok(bytes)
}

/// Decode a record whose complete final attempt supplies the outcome.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
/// # Errors
/// Refuses old nesting, extra summary members, foreign context or a carrier violation.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        operation = "controller-record-decode",
        source_item = "publication::controller::decode_record"
    ),
    ret
)]
pub fn decode_record(
    bytes: &[u8],
    expected: &Request<'_>,
    numeric: &mut NumericContext,
    limits: &Limits,
) -> Result<Record, Error> {
    let value = comparison::read(bytes, limits)?;
    let members = comparison::selected(&value, 4)?;
    let mut context = comparison::context(numeric, &limits.arithmetic)?;
    let procedure = Procedure::read(&members[1], &mut context).map_err(Error::Projection)?;
    let inputs = Inputs::read(&members[2], &mut context).map_err(Error::Projection)?;
    let Value::Array(attempts) = &members[3] else {
        return Err(comparison::Error::Member.into());
    };
    let attempts = attempts
        .as_slice()
        .iter()
        .map(|value| attempt(value, &mut context, &limits.arithmetic))
        .collect::<Result<_, _>>()?;
    let record = Record {
        procedure,
        inputs,
        attempts,
    };
    record
        .validate(expected.procedure, expected.inputs, expected.proof, &mut context.arithmetic)
        .map_err(Error::Record)?;
    Ok(record)
}

/// Encode an explicit record with no duplicate top-level verdict.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
/// # Errors
/// Refuses a carrier violation, invalid projection or exhausted supplied ceiling.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        operation = "controller-record-encode",
        source_item = "publication::controller::encode_record"
    ),
    ret
)]
pub fn encode_record(
    record: &Record,
    expected: &Request<'_>,
    numeric: &mut NumericContext,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    let mut context = comparison::context(numeric, &limits.arithmetic)?;
    record
        .validate(expected.procedure, expected.inputs, expected.proof, &mut context.arithmetic)
        .map_err(Error::Record)?;
    let value = array([
        Value::Unsigned(2),
        record.procedure.write(&mut context).map_err(Error::Projection)?,
        record.inputs.write(&mut context).map_err(Error::Projection)?,
        array(
            record
                .attempts
                .iter()
                .map(|attempt| attempt_value(attempt, &mut context))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    ]);
    let bytes = value.to_canonical_bytes();
    comparison::read(&bytes, limits)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pn_records::numerics::ComparisonLimits;

    fn limits() -> Limits {
        Limits {
            transport: pn_interchange::TransportLimits {
                input_bytes: 2_000_000,
                allocation_bytes: 8_000_000,
                items: 200_000,
                depth: 64,
                nesting: 64,
                work: 20_000_000,
            },
            arithmetic: ExactLimits {
                work: 20_000_000,
                literal_bytes: 4096,
                ..ExactLimits::default()
            },
        }
    }

    /// Claim: First-edition controller projections still round-trip their own values and refuse valid second-edition fragments; selected second-edition framing refuses first-edition attempts and records and an old attempt nested inside a new record.
    /// ´claim:host:controller-editions-are-disjoint´
    /// ´test:unit:controller-editions´
    #[test]
    fn controller_editions() {
        let data: serde_json::Value = serde_json::from_str(include_str!("../../tests/data/controller-carriers.json")).unwrap();
        let limits = limits();
        let mut numeric = NumericContext::new(limits.arithmetic.clone(), ComparisonLimits::new(1, 20_000_000)).unwrap();
        let mut context = comparison::context(&mut numeric, &limits.arithmetic).unwrap();
        let value = |name: &str| {
            let row = data["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["case"] == name)
                .unwrap();
            let raw: Vec<_> = row["canonical"]
                .as_str()
                .unwrap()
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            comparison::read(&raw, &limits).unwrap()
        };
        let new_attempt = value("operational-1-5");
        assert!(
            pn_records::controller::Attempt::read(&new_attempt, &mut context).is_err(),
            "first edition refuses second-edition attempt"
        );
        assert!(
            attempt(&new_attempt, &mut context, &limits.arithmetic).is_ok(),
            "second-edition attempt framing witness"
        );
        let old_attempt = pn_records::controller::Attempt {
            precision: 8,
            stopped_at: Some(pn_records::controller::Stage::InverseGain),
            inverse: None,
            floor_checks: vec![],
            branches: None,
            delivered: None,
            delivery_error: None,
        };
        let old_value = old_attempt.write(&mut context).unwrap();
        assert_eq!(
            pn_records::controller::Attempt::read(&old_value, &mut context).unwrap(),
            old_attempt,
            "first-edition attempt round trip"
        );
        assert!(
            attempt(&old_value, &mut context, &limits.arithmetic).is_err(),
            "second edition refuses first-edition attempt"
        );
        let new_record = value("record-operational");
        assert!(
            pn_records::controller::Record::read(&new_record, &mut context).is_err(),
            "first edition refuses second-edition record"
        );
        let members = comparison::selected(&new_record, 4).unwrap();
        let old_record = pn_records::controller::Record {
            procedure: Procedure::read(&members[1], &mut context).unwrap(),
            inputs: Inputs::read(&members[2], &mut context).unwrap(),
            attempts: vec![old_attempt],
            verdict: pn_records::controller::Verdict::Indecisive,
        };
        let old_value = old_record.write(&mut context).unwrap();
        assert_eq!(
            pn_records::controller::Record::read(&old_value, &mut context).unwrap(),
            old_record,
            "first-edition record round trip"
        );
        assert!(
            comparison::selected(&old_value, 4).is_err(),
            "second edition refuses first-edition record"
        );
        let mixed = value("record-old-attempt");
        let fields = comparison::selected(&mixed, 4).unwrap();
        let Value::Array(values) = &fields[3] else {
            panic!("fixture attempts array");
        };
        assert!(
            attempt(&values.as_slice()[0], &mut context, &limits.arithmetic).is_err(),
            "old attempt cannot nest in second-edition record"
        );
    }
}
