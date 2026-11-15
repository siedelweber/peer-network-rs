//! Explicit comparison fragments, never publication or numerical admission.
//! (´[ROOT-dec:design:comparison-verdict-record]´)

use super::wire::{Context, Wire, array};
use pn_interchange::{CanonicalUsage, DecodeError, TransportLimits, TransportUsage, Value};
use pn_records::{
    binary64::Fraction,
    numerics::{
        ExactLimits, Floor, NumericContext,
        comparison::{ComparisonRecordV2, DefiningProof, Enclosure, Expected, FloorComparisonV2, Question, ResultKind},
    },
    ridge::Wall,
};

/// Mandatory byte-reader and exact-arithmetic reconstruction ceilings.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug)]
pub struct Limits {
    pub transport: TransportLimits,
    pub arithmetic: ExactLimits,
}

/// Independent original question and binding, with optional checked defining evidence.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Debug)]
pub struct Request<'a> {
    pub question: &'a Question,
    pub expected: &'a Expected,
    pub proof: Option<&'a DefiningProof<'a>>,
}

/// Structural fragment refusal, never a mathematical verdict.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Debug)]
pub enum Error {
    /// Existing canonical reader refused the spelling.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Canonical(DecodeError),
    /// A caller-declared representation or arithmetic ceiling was exhausted.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Resource,
    /// A tag is not part of a comparison fragment.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Tag,
    /// A floating item is not an exact rational endpoint.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Float,
    /// The explicitly selected edition does not match.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Edition,
    /// An array does not have its exact stated arity.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Arity,
    /// A member has the wrong item kind.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Member,
    /// The result constructor is outside the closed three.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Constructor,
    /// An exact rational pair is not canonical.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Number,
    /// An inherited publication field projection refused.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Projection(super::Error),
    /// The records validator refused its first semantic clause.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Record(pn_records::numerics::comparison::Error),
}

fn fields(value: &Value, length: usize) -> Result<&[Value], Error> {
    let Value::Array(values) = value else {
        return Err(Error::Member);
    };
    if values.as_slice().len() != length {
        return Err(Error::Arity);
    }
    Ok(values.as_slice())
}

fn unsigned(value: &Value) -> Result<u64, Error> {
    let Value::Unsigned(value) = value else {
        return Err(Error::Member);
    };
    Ok(*value)
}

fn text(value: &Value) -> Result<String, Error> {
    let Value::Text(value) = value else {
        return Err(Error::Member);
    };
    Ok(value.as_str().to_owned())
}

fn boolean(value: &Value) -> Result<bool, Error> {
    let Value::Bool(value) = value else {
        return Err(Error::Member);
    };
    Ok(*value)
}

fn q(value: &Value, limits: &ExactLimits) -> Result<Fraction, Error> {
    let pair = fields(value, 2)?;
    Fraction::new(text(&pair[0])?, text(&pair[1])?, limits.clone()).map_err(|error| match error {
        pn_records::binary64::Error::Resource => Error::Resource,
        _ => Error::Number,
    })
}

fn q_value(value: &Fraction) -> Value {
    let (numerator, denominator) = value.parts();
    array([
        Value::Text(numerator.to_owned().into()),
        Value::Text(denominator.to_owned().into()),
    ])
}

fn floor_read(value: &Value, limits: &ExactLimits) -> Result<FloorComparisonV2, Error> {
    let outer = selected(value, 2)?;
    let Value::Array(result) = &outer[1] else {
        return Err(Error::Member);
    };
    let constructor = unsigned(result.as_slice().first().ok_or(Error::Arity)?)?;
    let result = match constructor {
        0 => {
            let members = fields(&outer[1], 7)?;
            let enclosure = fields(&members[3], 4)?;
            ResultKind::Evaluated {
                reduction: unsigned(&members[1])?,
                predicate: unsigned(&members[2])?,
                enclosure: Enclosure {
                    lower: q(&enclosure[0], limits)?,
                    lower_included: boolean(&enclosure[1])?,
                    upper: q(&enclosure[2], limits)?,
                    upper_included: boolean(&enclosure[3])?,
                },
                threshold: q(&members[4], limits)?,
                relation: unsigned(&members[5])?,
                verdict: unsigned(&members[6])?,
            }
        }
        1 => {
            let members = fields(&outer[1], 6)?;
            ResultKind::Exact {
                left: q(&members[1], limits)?,
                predicate: unsigned(&members[2])?,
                right: q(&members[3], limits)?,
                relation: unsigned(&members[4])?,
                verdict: unsigned(&members[5])?,
            }
        }
        2 => {
            let members = fields(&outer[1], 2)?;
            ResultKind::Operational {
                cause: unsigned(&members[1])?,
            }
        }
        _ => return Err(Error::Constructor),
    };
    Ok(FloorComparisonV2 { result })
}

fn selected(value: &Value, length: usize) -> Result<&[Value], Error> {
    let Value::Array(values) = value else {
        return Err(Error::Member);
    };
    if unsigned(values.as_slice().first().ok_or(Error::Arity)?)? != 2 {
        return Err(Error::Edition);
    }
    fields(value, length)
}

fn floor_value(comparison: &FloorComparisonV2) -> Value {
    let result = match &comparison.result {
        ResultKind::Evaluated {
            reduction,
            predicate,
            enclosure,
            threshold,
            relation,
            verdict,
        } => array([
            Value::Unsigned(0),
            Value::Unsigned(*reduction),
            Value::Unsigned(*predicate),
            array([
                q_value(&enclosure.lower),
                Value::Bool(enclosure.lower_included),
                q_value(&enclosure.upper),
                Value::Bool(enclosure.upper_included),
            ]),
            q_value(threshold),
            Value::Unsigned(*relation),
            Value::Unsigned(*verdict),
        ]),
        ResultKind::Exact {
            left,
            predicate,
            right,
            relation,
            verdict,
        } => array([
            Value::Unsigned(1),
            q_value(left),
            Value::Unsigned(*predicate),
            q_value(right),
            Value::Unsigned(*relation),
            Value::Unsigned(*verdict),
        ]),
        ResultKind::Operational { cause } => array([Value::Unsigned(2), Value::Unsigned(*cause)]),
    };
    array([Value::Unsigned(2), result])
}

fn read(bytes: &[u8], limits: &Limits) -> Result<Value, Error> {
    if bytes.len() > limits.transport.input_bytes {
        return Err(Error::Resource);
    }
    let mut forbidden = None;
    Value::validate_canonical_bytes(
        bytes,
        limits.transport.allocation_bytes,
        &mut CanonicalUsage::default(),
        |_| Ok(()),
        |item| {
            if forbidden.is_none() {
                if item.major == 6 {
                    forbidden = Some(Error::Tag);
                } else if item.major == 7 && matches!(item.bytes[0] & 31, 25..=27) {
                    forbidden = Some(Error::Float);
                }
            }
        },
    )
    .map_err(Error::Canonical)?;
    if let Some(error) = forbidden {
        return Err(error);
    }
    Value::from_transport_bytes(bytes, limits.transport, &mut TransportUsage::default()).map_err(Error::Canonical)
}

fn context<'a>(numeric: &'a mut NumericContext, limits: &ExactLimits) -> Result<Context<'a>, Error> {
    Ok(Context {
        numeric,
        arithmetic: pn_epoch::publication::disclosures::limits::Budget::new(limits.clone()).map_err(|_| Error::Resource)?,
    })
}

/// Decode only the explicitly selected second-edition floor fragment.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
/// # Errors
/// Returns canonical, framing or first records refusal; decoding grants no admission.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        operation = "comparison-floor-decode",
        source_item = "publication::comparison::decode_floor"
    ),
    ret
)]
pub fn decode_floor(
    bytes: &[u8],
    request: &Request<'_>,
    numeric: &mut NumericContext,
    limits: &Limits,
) -> Result<FloorComparisonV2, Error> {
    let value = read(bytes, limits)?;
    let comparison = floor_read(&value, &limits.arithmetic)?;
    comparison
        .validate(
            request.question,
            request.expected,
            request.proof,
            &mut context(numeric, &limits.arithmetic)?.arithmetic,
        )
        .map_err(Error::Record)?;
    Ok(comparison)
}

/// Encode the explicitly selected second-edition floor fragment after validation.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
/// # Errors
/// Refuses inconsistent fields or exhausted supplied ceilings.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        operation = "comparison-floor-encode",
        source_item = "publication::comparison::encode_floor"
    ),
    ret
)]
pub fn encode_floor(
    comparison: &FloorComparisonV2,
    request: &Request<'_>,
    numeric: &mut NumericContext,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    comparison
        .validate(
            request.question,
            request.expected,
            request.proof,
            &mut context(numeric, &limits.arithmetic)?.arithmetic,
        )
        .map_err(Error::Record)?;
    let bytes = floor_value(comparison).to_canonical_bytes();
    read(&bytes, limits)?;
    Ok(bytes)
}

/// Decode only the explicitly selected ridge fragment with a nested second edition.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
/// # Errors
/// Refuses inherited projections, outer binding or the first nested clause.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        operation = "comparison-ridge-decode",
        source_item = "publication::comparison::decode_ridge"
    ),
    ret
)]
pub fn decode_ridge(
    bytes: &[u8],
    expected_floor: Floor,
    request: &Request<'_>,
    numeric: &mut NumericContext,
    limits: &Limits,
) -> Result<ComparisonRecordV2, Error> {
    let value = read(bytes, limits)?;
    let members = selected(&value, 6)?;
    let mut context = context(numeric, &limits.arithmetic)?;
    let wall = Wall::read(&members[1], &mut context).map_err(Error::Projection)?;
    let floor = Floor::read(&members[2], &mut context).map_err(Error::Projection)?;
    let queries = Vec::read(&members[3], &mut context).map_err(Error::Projection)?;
    let work = u64::read(&members[5], &mut context).map_err(Error::Projection)?;
    let comparison = floor_read(&members[4], &limits.arithmetic)?;
    let record = ComparisonRecordV2 {
        wall,
        floor,
        queries,
        comparison,
        work,
    };
    record
        .validate(
            &request.expected.question.left,
            expected_floor,
            request.expected,
            request.proof,
            &mut context.arithmetic,
        )
        .map_err(Error::Record)?;
    Ok(record)
}

/// Encode retained ridge projections without switching any publication producer.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
/// # Errors
/// Refuses inconsistent context, projections or exhausted supplied ceilings.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        operation = "comparison-ridge-encode",
        source_item = "publication::comparison::encode_ridge"
    ),
    ret
)]
pub fn encode_ridge(
    record: &ComparisonRecordV2,
    expected_floor: Floor,
    request: &Request<'_>,
    numeric: &mut NumericContext,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    let mut context = context(numeric, &limits.arithmetic)?;
    record
        .validate(
            &request.expected.question.left,
            expected_floor,
            request.expected,
            request.proof,
            &mut context.arithmetic,
        )
        .map_err(Error::Record)?;
    let value = array([
        Value::Unsigned(2),
        record.wall.write(&mut context).map_err(Error::Projection)?,
        record.floor.write(&mut context).map_err(Error::Projection)?,
        record.queries.write(&mut context).map_err(Error::Projection)?,
        floor_value(&record.comparison),
        record.work.write(&mut context).map_err(Error::Projection)?,
    ]);
    let bytes = value.to_canonical_bytes();
    read(&bytes, limits)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pn_records::numerics::{ComparisonLimits, FloorComparison};

    /// Claim: The existing floor and ridge projections reject second-edition fragments, the selected second-edition readers reject the existing projections, and an old comparison cannot occupy the new ridge's nested slot.
    /// ´claim:host:comparison-editions-are-disjoint´
    /// ´test:unit:comparison-editions´
    #[test]
    fn comparison_editions() {
        let limits = ExactLimits::default();
        let mut numeric = NumericContext::new(limits.clone(), ComparisonLimits::new(1, 1_000_000)).unwrap();
        let mut context = context(&mut numeric, &limits).unwrap();
        let new = FloorComparisonV2 {
            result: ResultKind::Operational { cause: 1 },
        };
        let encoded = floor_value(&new);
        assert!(
            FloorComparison::read(&encoded, &mut context).is_err(),
            "old floor reader refuses edition two"
        );
        for old in [
            FloorComparison::Below,
            FloorComparison::Equal,
            FloorComparison::Above,
            FloorComparison::Indecisive,
        ] {
            let bytes = old.write(&mut context).unwrap();
            assert!(
                floor_read(&bytes, &limits).is_err(),
                "edition two refuses old floor projection"
            );
        }
        let old = pn_records::ridge::ComparisonRecord {
            wall: Wall::Rational("1/10".into()),
            floor: Floor::RationalThreeThirtySevenths,
            queries: Vec::new(),
            verdict: FloorComparison::Below,
            work: 0,
        };
        let old_value = old.write(&mut context).unwrap();
        assert!(selected(&old_value, 6).is_err(), "edition two refuses old ridge projection");
        let new_value = array([
            Value::Unsigned(2),
            old.wall.write(&mut context).unwrap(),
            old.floor.write(&mut context).unwrap(),
            array([]),
            encoded,
            Value::Text("0".to_owned().into()),
        ]);
        assert!(
            pn_records::ridge::ComparisonRecord::read(&new_value, &mut context).is_err(),
            "old ridge reader refuses edition two"
        );
        assert!(
            floor_read(&old.verdict.write(&mut context).unwrap(), &limits).is_err(),
            "old nested floor projection refuses"
        );
    }
}
