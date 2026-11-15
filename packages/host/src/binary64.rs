//! Explicit canonical fragments, separate from publication and store codecs.
//! (´[ROOT-rule:design:binary64-evidence]´)

use model::{
    Carrier, Coordinate, Data, Enclosure, Endpoint, Fields, Fraction, Hypothesis, Input, Node, Path, Predicate, Question, Row,
    Rungs, Test,
};
use pn_records::binary64 as model;
use pn_records::numerics::ExactLimits;

/// Closed byte refusals, separate from typed structural refusals.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A required byte is absent.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Truncated,
    /// Bytes remain after the complete fragment.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Trailing,
    /// An indefinite-length head is present.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Indefinite,
    /// A tag is present.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Tag,
    /// A floating-point item is present.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Float,
    /// A head is longer than its value requires.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    ShortestHead,
    /// An item has the wrong major or simple kind.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    ItemKind,
    /// A closed map, array or constructor has the wrong member count.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Arity,
    /// A map key is outside the closed roster.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    UnknownKey,
    /// A map key is repeated, or the canonical writer reports a duplicate.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    DuplicateKey,
    /// A known map key is out of order.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    MemberOrder,
    /// An edition or vocabulary code is unknown.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    UnknownCode,
    /// A text item is not valid UTF-8.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Utf8,
    /// A byte, item, depth, allocation or arithmetic bound is exhausted.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Resource,
    /// A typed carrier invariant refuses the decoded members.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Structure(model::Error),
    /// An edition-two structural rule refuses.
    /// (´[ROOT-dec:design:rung-anchor-representation]´)
    SecondEdition(model::ErrorV2),
}

/// Explicit reader ceilings; exhaustion supplies no mathematical result.
/// Each fraction is first constructed under a fresh arithmetic budget before the carrier checks all fractions under one cumulative budget; there are at most items preliminary constructions, each bounded by arithmetic, followed by the cumulative pass.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug)]
pub struct Limits {
    pub bytes: usize,
    pub items: usize,
    pub depth: usize,
    pub arithmetic: ExactLimits,
}

#[derive(Clone, Debug)]
enum Value {
    UInt(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Boolean(bool),
    Null,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    items: usize,
    limits: &'a Limits,
}
impl Reader<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], Error> {
        let end = self.offset.checked_add(count).ok_or(Error::Resource)?;
        let value = self.bytes.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn head(&mut self) -> Result<(u8, u64), Error> {
        self.items = self.items.checked_add(1).ok_or(Error::Resource)?;
        if self.items > self.limits.items {
            return Err(Error::Resource);
        }
        let byte = self.take(1)?[0];
        let kind = byte >> 5;
        let extra = byte & 31;
        if extra == 31 {
            return Err(Error::Indefinite);
        }
        if kind == 6 {
            return Err(Error::Tag);
        }
        if kind == 7 && matches!(extra, 25..=27) {
            return Err(Error::Float);
        }
        let (width, minimum) = match extra {
            0..=23 => return Ok((kind, u64::from(extra))),
            24 => (1, 24),
            25 => (2, 256),
            26 => (4, 65536),
            27 => (8, 1_u64 << 32),
            _ => return Err(Error::ItemKind),
        };
        let mut value = 0_u64;
        for byte in self.take(width)? {
            value = (value << 8) | u64::from(*byte);
        }
        if value < minimum {
            return Err(Error::ShortestHead);
        }
        Ok((kind, value))
    }
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > self.limits.depth {
            return Err(Error::Resource);
        }
        let (kind, value) = self.head()?;
        match kind {
            0 => Ok(Value::UInt(value)),
            2 | 3 => {
                let length = usize::try_from(value).map_err(|_| Error::Resource)?;
                let bytes = self.take(length)?;
                if kind == 2 {
                    Ok(Value::Bytes(bytes.to_vec()))
                } else {
                    Ok(Value::Text(std::str::from_utf8(bytes).map_err(|_| Error::Utf8)?.to_owned()))
                }
            }
            4 => {
                let length = usize::try_from(value).map_err(|_| Error::Resource)?;
                if length > self.limits.items.saturating_sub(self.items) {
                    return Err(Error::Resource);
                }
                let mut values = Vec::new();
                values.try_reserve(length).map_err(|_| Error::Resource)?;
                for _ in 0..length {
                    values.push(self.value(depth.checked_add(1).ok_or(Error::Resource)?)?);
                }
                Ok(Value::Array(values))
            }
            7 => match value {
                20 => Ok(Value::Boolean(false)),
                21 => Ok(Value::Boolean(true)),
                22 => Ok(Value::Null),
                _ => Err(Error::ItemKind),
            },
            _ => Err(Error::ItemKind),
        }
    }
}

fn uint(value: &Value) -> Result<u64, Error> {
    if let Value::UInt(v) = value {
        Ok(*v)
    } else {
        Err(Error::ItemKind)
    }
}
fn text(value: &Value) -> Result<&str, Error> {
    if let Value::Text(v) = value {
        Ok(v)
    } else {
        Err(Error::ItemKind)
    }
}
fn bytes(value: &Value) -> Result<&[u8], Error> {
    if let Value::Bytes(v) = value {
        Ok(v)
    } else {
        Err(Error::ItemKind)
    }
}
fn boolean(value: &Value) -> Result<bool, Error> {
    if let Value::Boolean(v) = value {
        Ok(*v)
    } else {
        Err(Error::ItemKind)
    }
}
fn array(value: &Value) -> Result<&[Value], Error> {
    if let Value::Array(v) = value {
        Ok(v)
    } else {
        Err(Error::ItemKind)
    }
}
fn members<const N: usize>(value: &Value) -> Result<&[Value; N], Error> {
    array(value)?.try_into().map_err(|_| Error::Arity)
}
fn fraction(value: &Value, limits: &Limits) -> Result<Fraction, Error> {
    let [n, d] = members(value)?;
    Fraction::new(text(n)?.into(), text(d)?.into(), limits.arithmetic.clone()).map_err(Error::Structure)
}
fn endpoint(value: &Value) -> Result<Endpoint, Error> {
    Endpoint::new(uint(value)?).map_err(Error::Structure)
}
fn enclosure(value: &Value) -> Result<Enclosure, Error> {
    let [lo, li, hi, ui] = members(value)?;
    Enclosure::new(endpoint(lo)?, boolean(li)?, endpoint(hi)?, boolean(ui)?).map_err(Error::Structure)
}
fn data(value: &Value, limits: &Limits) -> Result<Data, Error> {
    let values = array(value)?;
    let code = uint(values.first().ok_or(Error::Arity)?)?;
    if code == 7 {
        members::<1>(value)?;
        return Ok(Data::Absent);
    }
    let [_, item] = members(value)?;
    Ok(match code {
        0 => Data::Rational(fraction(item, limits)?),
        1 => Data::Binary64(endpoint(item)?),
        2 => Data::Bytes(bytes(item)?.into()),
        3 => Data::Text(text(item)?.into()),
        4 => Data::Array(array(item)?.iter().map(|v| data(v, limits)).collect::<Result<_, _>>()?),
        5 => Data::Record(
            array(item)?
                .iter()
                .map(|v| {
                    let [n, d] = members(v)?;
                    Ok((text(n)?.into(), data(d, limits)?))
                })
                .collect::<Result<_, Error>>()?,
        ),
        6 => Data::Boolean(boolean(item)?),
        _ => return Err(Error::UnknownCode),
    })
}
fn node(value: &Value, limits: &Limits) -> Result<Node, Error> {
    let values = array(value)?;
    let code = uint(values.first().ok_or(Error::Arity)?)?;
    if code == 0 {
        let [_, name, path] = members(value)?;
        let path = array(path)?
            .iter()
            .map(|v| {
                let [code, item] = members(v)?;
                match uint(code)? {
                    0 => Ok(Path::Index(uint(item)?)),
                    1 => Ok(Path::Field(text(item)?.into())),
                    _ => Err(Error::UnknownCode),
                }
            })
            .collect::<Result<_, _>>()?;
        return Ok(Node::Input(text(name)?.into(), path));
    }
    if matches!(code,4..=7 | 13..=16) {
        let [_, a, b] = members(value)?;
        let a = uint(a)?;
        return Ok(match code {
            4 => Node::Add(a, uint(b)?),
            5 => Node::Subtract(a, uint(b)?),
            6 => Node::Multiply(a, uint(b)?),
            7 => Node::Divide(a, uint(b)?),
            13 => Node::Power(a, fraction(b, limits)?),
            14 => Node::Derivative(a, uint(b)?),
            15 => Node::Clamp(a, uint(b)?),
            16 => Node::GeneralizedDerivative(a, uint(b)?),
            _ => return Err(Error::UnknownCode),
        });
    }
    let [_, a] = members(value)?;
    Ok(match code {
        1 => Node::Coordinate(uint(a)?),
        2 => Node::Constant(fraction(a, limits)?),
        3 => Node::Negate(uint(a)?),
        8 => Node::SquareRoot(uint(a)?),
        9 => Node::Logarithm(uint(a)?),
        10 => Node::Exponential(uint(a)?),
        11 => Node::Sigmoid(uint(a)?),
        12 => Node::Tanh(uint(a)?),
        _ => return Err(Error::UnknownCode),
    })
}
fn polarity(value: &Value) -> Result<model::Polarity, Error> {
    match uint(value)? {
        0 => Ok(model::Polarity::Proposition),
        1 => Ok(model::Polarity::Negation),
        2 => Ok(model::Polarity::Uncertified),
        _ => Err(Error::UnknownCode),
    }
}

/// Decode only the explicitly selected fragment; success grants no evidence authority.
/// (´[ROOT-rule:design:binary64-evidence]´)
/// # Errors
/// Refuses noncanonical bytes, unsupported members, invalid structure or exhausted bounds.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        source_item = "binary64::decode"
    ),
    ret
)]
pub fn decode(bytes: &[u8], limits: &Limits) -> Result<Carrier, Error> {
    if bytes.len() > limits.bytes {
        return Err(Error::Resource);
    }
    let mut reader = Reader {
        bytes,
        offset: 0,
        items: 0,
        limits,
    };
    if reader.head()? != (5, 10) {
        return Err(Error::Arity);
    }
    let mut values = Vec::new();
    let mut seen = [false; 10];
    for expected in 0..10 {
        let (kind, key) = reader.head()?;
        if kind != 0 {
            return Err(Error::ItemKind);
        }
        let key = usize::try_from(key).map_err(|_| Error::UnknownKey)?;
        if key >= 10 {
            return Err(Error::UnknownKey);
        }
        if seen[key] {
            return Err(Error::DuplicateKey);
        }
        if key != expected {
            return Err(Error::MemberOrder);
        }
        seen[key] = true;
        values.push(reader.value(1)?);
    }
    if reader.offset != bytes.len() {
        return Err(Error::Trailing);
    }
    read_fields(&values, limits)
}

fn read_fields(values: &[Value], limits: &Limits) -> Result<Carrier, Error> {
    if uint(&values[0])? != 1 {
        return Err(Error::UnknownCode);
    }
    let question = read_question(values, limits)?;
    let [original, actual] = members(&values[4])?;
    let enclosures = if matches!((original, actual), (Value::Null, Value::Null)) {
        None
    } else {
        Some((enclosure(original)?, enclosure(actual)?))
    };
    let adjusted = match uint(&values[5])? {
        0 => false,
        1 => true,
        _ => return Err(Error::UnknownCode),
    };
    let [predicate, threshold, sign, consumer] = members(&values[6])?;
    let predicate = match uint(predicate)? {
        0 if matches!(threshold, Value::Null) => Predicate::Membership,
        1 => Predicate::AtMost(fraction(threshold, limits)?),
        2 => Predicate::Less(fraction(threshold, limits)?),
        3 => Predicate::Equal(fraction(threshold, limits)?),
        4 => Predicate::AtLeast(fraction(threshold, limits)?),
        5 => Predicate::Greater(fraction(threshold, limits)?),
        _ => return Err(Error::UnknownCode),
    };
    let consumer = match uint(consumer)? {
        0 => model::Consumer::Free,
        1 => model::Consumer::Value,
        2 => model::Consumer::Map,
        3 => model::Consumer::Residual,
        4 => model::Consumer::Rung,
        5 => model::Consumer::Fixed,
        6 => model::Consumer::Local,
        _ => return Err(Error::UnknownCode),
    };
    let tests = array(&values[7])?
        .iter()
        .map(|v| {
            let [subject, evaluated, result] = members(v)?;
            Ok(Test {
                subject: if matches!(subject, Value::Null) {
                    None
                } else {
                    Some(uint(subject)?)
                },
                evaluated: enclosure(evaluated)?,
                result: polarity(result)?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let rungs = read_rungs(&values[8], limits)?;
    let outcome = match uint(&values[9])? {
        0 => model::Outcome::Completed,
        1 => model::Outcome::InvalidInput,
        2 => model::Outcome::InvalidEvidence,
        3 => model::Outcome::Unsupported,
        4 => model::Outcome::TargetNotCertifiable,
        5 => model::Outcome::Resource,
        6 => model::Outcome::Interrupted,
        _ => return Err(Error::UnknownCode),
    };
    Carrier::new(
        Fields {
            question,
            enclosures,
            adjusted,
            predicate,
            polarity: polarity(sign)?,
            consumer,
            tests,
            rungs,
            outcome,
        },
        limits.arithmetic.clone(),
    )
    .map_err(Error::Structure)
}
fn bytes_value(value: &Value) -> Result<Vec<u8>, Error> {
    Ok(bytes(value)?.into())
}

fn u(value: u64) -> Value {
    Value::UInt(value)
}
fn a(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(values.into_iter().collect())
}
fn s(value: &str) -> Value {
    Value::Text(value.into())
}
fn q(value: &Fraction) -> Value {
    let (n, d) = value.parts();
    a([s(n), s(d)])
}
fn e(value: Enclosure) -> Value {
    let (lo, li, hi, ui) = value.parts();
    a([u(lo.bits()), Value::Boolean(li), u(hi.bits()), Value::Boolean(ui)])
}
fn p(value: model::Polarity) -> Value {
    u(match value {
        model::Polarity::Proposition => 0,
        model::Polarity::Negation => 1,
        model::Polarity::Uncertified => 2,
    })
}
fn data_value(value: &Data) -> Value {
    match value {
        Data::Rational(v) => a([u(0), q(v)]),
        Data::Binary64(v) => a([u(1), u(v.bits())]),
        Data::Bytes(v) => a([u(2), Value::Bytes(v.clone())]),
        Data::Text(v) => a([u(3), s(v)]),
        Data::Array(v) => a([u(4), a(v.iter().map(data_value))]),
        Data::Record(v) => a([u(5), a(v.iter().map(|(n, v)| a([s(n), data_value(v)])))]),
        Data::Boolean(v) => a([u(6), Value::Boolean(*v)]),
        Data::Absent => a([u(7)]),
    }
}
fn node_value(value: &Node) -> Value {
    match value {
        Node::Input(n, path) => a([
            u(0),
            s(n),
            a(path.iter().map(|v| match v {
                Path::Index(i) => a([u(0), u(*i)]),
                Path::Field(n) => a([u(1), s(n)]),
            })),
        ]),
        Node::Coordinate(c) => a([u(1), u(*c)]),
        Node::Constant(v) => a([u(2), q(v)]),
        Node::Negate(v) => a([u(3), u(*v)]),
        Node::Add(l, r) => a([u(4), u(*l), u(*r)]),
        Node::Subtract(l, r) => a([u(5), u(*l), u(*r)]),
        Node::Multiply(l, r) => a([u(6), u(*l), u(*r)]),
        Node::Divide(l, r) => a([u(7), u(*l), u(*r)]),
        Node::SquareRoot(v) => a([u(8), u(*v)]),
        Node::Logarithm(v) => a([u(9), u(*v)]),
        Node::Exponential(v) => a([u(10), u(*v)]),
        Node::Sigmoid(v) => a([u(11), u(*v)]),
        Node::Tanh(v) => a([u(12), u(*v)]),
        Node::Power(v, x) => a([u(13), u(*v), q(x)]),
        Node::Derivative(v, c) => a([u(14), u(*v), u(*c)]),
        Node::Clamp(l, r) => a([u(15), u(*l), u(*r)]),
        Node::GeneralizedDerivative(v, c) => a([u(16), u(*v), u(*c)]),
    }
}
fn interchange(value: Value) -> pn_interchange::Value {
    use pn_interchange::Value as I;
    match value {
        Value::UInt(v) => I::Unsigned(v),
        Value::Bytes(v) => I::Bytes(v.into()),
        Value::Text(v) => I::Text(v.into()),
        Value::Array(v) => I::Array(pn_interchange::Array::new(v.into_iter().map(interchange))),
        Value::Boolean(v) => I::Bool(v),
        Value::Null => I::Null,
    }
}

fn consumer_code(consumer: model::Consumer) -> u64 {
    match consumer {
        model::Consumer::Free => 0,
        model::Consumer::Value => 1,
        model::Consumer::Map => 2,
        model::Consumer::Residual => 3,
        model::Consumer::Rung => 4,
        model::Consumer::Fixed => 5,
        model::Consumer::Local => 6,
    }
}
fn outcome_code(outcome: model::Outcome) -> u64 {
    match outcome {
        model::Outcome::Completed => 0,
        model::Outcome::InvalidInput => 1,
        model::Outcome::InvalidEvidence => 2,
        model::Outcome::Unsupported => 3,
        model::Outcome::TargetNotCertifiable => 4,
        model::Outcome::Resource => 5,
        model::Outcome::Interrupted => 6,
    }
}

/// Encode the separate checked fragment; no surrounding document or identity is assigned.
/// (´[ROOT-rule:design:binary64-evidence]´)
/// # Errors
/// Maps an unrepresentable member index to `Resource` and a canonical writer's duplicate key to `DuplicateKey`; the fixed ten-key construction supplies neither condition for a validated carrier.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        source_item = "binary64::encode"
    ),
    ret
)]
pub fn encode(carrier: &Carrier) -> Result<Vec<u8>, Error> {
    let f = carrier.fields();
    let question = &f.question;
    let (predicate, threshold) = match &f.predicate {
        Predicate::Membership => (0, Value::Null),
        Predicate::AtMost(v) => (1, q(v)),
        Predicate::Less(v) => (2, q(v)),
        Predicate::Equal(v) => (3, q(v)),
        Predicate::AtLeast(v) => (4, q(v)),
        Predicate::Greater(v) => (5, q(v)),
    };
    let consumer = consumer_code(f.consumer);
    let outcome = outcome_code(f.outcome);
    let values = [
        u(1),
        a([u(1), a(question.nodes.iter().map(node_value)), u(question.root)]),
        a(question
            .inputs
            .iter()
            .map(|v| a([s(&v.name), Value::Bytes(v.source.clone()), data_value(&v.value)]))),
        a([
            a(question.coordinates.iter().map(|v| {
                a([
                    s(&v.name),
                    q(&v.lower),
                    Value::Boolean(v.lower_included),
                    q(&v.upper),
                    Value::Boolean(v.upper_included),
                ])
            })),
            a(question.hypotheses.iter().map(|v| {
                a([
                    u(match v.relation {
                        model::Relation::Equal => 0,
                        model::Relation::Less => 1,
                        model::Relation::AtMost => 2,
                    }),
                    u(v.left),
                    u(v.right),
                ])
            })),
        ]),
        match f.enclosures {
            None => a([Value::Null, Value::Null]),
            Some((original, actual)) => a([e(original), e(actual)]),
        },
        u(u64::from(f.adjusted)),
        a([u(predicate), threshold, p(f.polarity), u(consumer)]),
        a(f.tests
            .iter()
            .map(|v| a([v.subject.map_or(Value::Null, u), e(v.evaluated), p(v.result)]))),
        match &f.rungs {
            None => Value::Null,
            Some(v) => a([
                u(v.coordinate),
                a(v.grid.iter().map(q)),
                a(v.rows.iter().map(|row| a([u(row.grid), u(row.test), p(row.result)]))),
            ]),
        },
        u(outcome),
    ];
    let entries = values
        .into_iter()
        .enumerate()
        .map(|(key, value)| {
            Ok((
                pn_interchange::Value::Unsigned(u64::try_from(key).map_err(|_| Error::Resource)?),
                interchange(value),
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let map = pn_interchange::Map::new(entries).map_err(|_| Error::DuplicateKey)?;
    Ok(pn_interchange::Value::Map(map).to_canonical_bytes())
}

fn read_question(values: &[Value], limits: &Limits) -> Result<Question, Error> {
    let [edition, nodes, root] = members(&values[1])?;
    if uint(edition)? != 1 {
        return Err(Error::UnknownCode);
    }
    let nodes = array(nodes)?.iter().map(|v| node(v, limits)).collect::<Result<_, _>>()?;
    let inputs = array(&values[2])?
        .iter()
        .map(|v| {
            let [name, source, value] = members(v)?;
            Ok(Input {
                name: text(name)?.into(),
                source: bytes_value(source)?,
                value: data(value, limits)?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let [coordinates, hypotheses] = members(&values[3])?;
    let coordinates = array(coordinates)?
        .iter()
        .map(|v| {
            let [name, lower, li, upper, ui] = members(v)?;
            Ok(Coordinate {
                name: text(name)?.into(),
                lower: fraction(lower, limits)?,
                lower_included: boolean(li)?,
                upper: fraction(upper, limits)?,
                upper_included: boolean(ui)?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let hypotheses = array(hypotheses)?
        .iter()
        .map(|v| {
            let [relation, left, right] = members(v)?;
            let relation = match uint(relation)? {
                0 => model::Relation::Equal,
                1 => model::Relation::Less,
                2 => model::Relation::AtMost,
                _ => return Err(Error::UnknownCode),
            };
            Ok(Hypothesis {
                relation,
                left: uint(left)?,
                right: uint(right)?,
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(Question {
        nodes,
        root: uint(root)?,
        inputs,
        coordinates,
        hypotheses,
    })
}

fn read_rungs(value: &Value, limits: &Limits) -> Result<Option<Rungs>, Error> {
    let rungs = if matches!(value, Value::Null) {
        None
    } else {
        let [coordinate, grid, rows] = members(value)?;
        Some(Rungs {
            coordinate: uint(coordinate)?,
            grid: array(grid)?.iter().map(|v| fraction(v, limits)).collect::<Result<_, _>>()?,
            rows: array(rows)?
                .iter()
                .map(|v| {
                    let [grid, test, result] = members(v)?;
                    Ok(Row {
                        grid: uint(grid)?,
                        test: uint(test)?,
                        result: polarity(result)?,
                    })
                })
                .collect::<Result<_, Error>>()?,
        })
    };
    Ok(rungs)
}

/// Decode the explicitly selected second edition without numerical admission.
/// (´[ROOT-dec:design:rung-anchor-representation]´)
/// # Errors
/// Returns the first named byte or structural refusal under the supplied bounds.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        source_item = "binary64::decode_v2"
    ),
    ret
)]
pub fn decode_v2(bytes: &[u8], limits: &Limits) -> Result<model::CarrierV2, Error> {
    if bytes.len() > limits.bytes {
        return Err(Error::Resource);
    }
    let mut reader = Reader {
        bytes,
        offset: 0,
        items: 0,
        limits,
    };
    if reader.head()? != (5, 10) {
        return Err(Error::Arity);
    }
    let mut values = Vec::new();
    let mut seen = [false; 10];
    for expected in 0..10 {
        let (kind, key) = reader.head()?;
        if kind != 0 {
            return Err(Error::ItemKind);
        }
        let key = usize::try_from(key).map_err(|_| Error::UnknownKey)?;
        if key >= 10 {
            return Err(Error::UnknownKey);
        }
        if seen[key] {
            return Err(Error::DuplicateKey);
        }
        if key != expected {
            return Err(Error::MemberOrder);
        }
        seen[key] = true;
        values.push(reader.value(1)?);
    }
    if reader.offset != bytes.len() {
        return Err(Error::Trailing);
    }
    read_fields_v2(&values, limits)
}

fn read_fields_v2(values: &[Value], limits: &Limits) -> Result<model::CarrierV2, Error> {
    if uint(&values[0])? != 2 {
        return Err(Error::UnknownCode);
    }
    let question = read_question(values, limits)?;
    let [original, actual] = members(&values[4])?;
    let enclosures = if matches!((original, actual), (Value::Null, Value::Null)) {
        None
    } else {
        Some((enclosure(original)?, enclosure(actual)?))
    };
    let adjusted = match uint(&values[5])? {
        0 => false,
        1 => true,
        _ => return Err(Error::UnknownCode),
    };
    let [predicate, threshold, sign, consumer] = members(&values[6])?;
    let predicate = match uint(predicate)? {
        0 if matches!(threshold, Value::Null) => Predicate::Membership,
        1 => Predicate::AtMost(fraction(threshold, limits)?),
        2 => Predicate::Less(fraction(threshold, limits)?),
        3 => Predicate::Equal(fraction(threshold, limits)?),
        4 => Predicate::AtLeast(fraction(threshold, limits)?),
        5 => Predicate::Greater(fraction(threshold, limits)?),
        _ => return Err(Error::UnknownCode),
    };
    let consumer = match uint(consumer)? {
        0 => model::Consumer::Free,
        1 => model::Consumer::Value,
        2 => model::Consumer::Map,
        3 => model::Consumer::Residual,
        4 => model::Consumer::Rung,
        5 => model::Consumer::Fixed,
        6 => model::Consumer::Local,
        _ => return Err(Error::UnknownCode),
    };
    let tests = array(&values[7])?
        .iter()
        .map(|v| {
            let [subject, evaluated, result] = members(v)?;
            Ok(Test {
                subject: if matches!(subject, Value::Null) {
                    None
                } else {
                    Some(uint(subject)?)
                },
                evaluated: enclosure(evaluated)?,
                result: polarity(result)?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let rungs = read_rungs(&values[8], limits)?;
    let ending = match array(&values[9])? {
        [Value::UInt(0)] => model::Ending::Complete,
        [Value::UInt(1)] => model::Ending::Anchor,
        [Value::UInt(2), cause] => model::Ending::Operational(uint(cause)?),
        [Value::UInt(0..=2), ..] => return Err(Error::Arity),
        _ => return Err(Error::UnknownCode),
    };
    model::CarrierV2::new(
        model::FieldsV2 {
            question,
            enclosures,
            adjusted,
            predicate,
            polarity: if matches!(sign, Value::Null) {
                None
            } else {
                Some(polarity(sign)?)
            },
            consumer,
            tests,
            rungs,
            ending,
        },
        limits.arithmetic.clone(),
    )
    .map_err(Error::SecondEdition)
}
/// Encode the explicitly selected second edition without numerical admission.
/// (´[ROOT-dec:design:rung-anchor-representation]´)
/// # Errors
/// Returns the first named byte or structural refusal under the supplied bounds.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        source_item = "binary64::encode_v2"
    ),
    ret
)]
pub fn encode_v2(carrier: &model::CarrierV2) -> Result<Vec<u8>, Error> {
    let f = carrier.fields();
    let question = &f.question;
    let (predicate, threshold) = match &f.predicate {
        Predicate::Membership => (0, Value::Null),
        Predicate::AtMost(v) => (1, q(v)),
        Predicate::Less(v) => (2, q(v)),
        Predicate::Equal(v) => (3, q(v)),
        Predicate::AtLeast(v) => (4, q(v)),
        Predicate::Greater(v) => (5, q(v)),
    };
    let consumer = consumer_code(f.consumer);
    let ending = match f.ending {
        model::Ending::Complete => a([u(0)]),
        model::Ending::Anchor => a([u(1)]),
        model::Ending::Operational(cause) => a([u(2), u(cause)]),
    };
    let values = [
        u(2),
        a([u(1), a(question.nodes.iter().map(node_value)), u(question.root)]),
        a(question
            .inputs
            .iter()
            .map(|v| a([s(&v.name), Value::Bytes(v.source.clone()), data_value(&v.value)]))),
        a([
            a(question.coordinates.iter().map(|v| {
                a([
                    s(&v.name),
                    q(&v.lower),
                    Value::Boolean(v.lower_included),
                    q(&v.upper),
                    Value::Boolean(v.upper_included),
                ])
            })),
            a(question.hypotheses.iter().map(|v| {
                a([
                    u(match v.relation {
                        model::Relation::Equal => 0,
                        model::Relation::Less => 1,
                        model::Relation::AtMost => 2,
                    }),
                    u(v.left),
                    u(v.right),
                ])
            })),
        ]),
        match f.enclosures {
            None => a([Value::Null, Value::Null]),
            Some((original, actual)) => a([e(original), e(actual)]),
        },
        u(u64::from(f.adjusted)),
        a([u(predicate), threshold, f.polarity.map_or(Value::Null, p), u(consumer)]),
        a(f.tests
            .iter()
            .map(|v| a([v.subject.map_or(Value::Null, u), e(v.evaluated), p(v.result)]))),
        match &f.rungs {
            None => Value::Null,
            Some(v) => a([
                u(v.coordinate),
                a(v.grid.iter().map(q)),
                a(v.rows.iter().map(|row| a([u(row.grid), u(row.test), p(row.result)]))),
            ]),
        },
        ending,
    ];
    let entries = values
        .into_iter()
        .enumerate()
        .map(|(key, value)| {
            Ok((
                pn_interchange::Value::Unsigned(u64::try_from(key).map_err(|_| Error::Resource)?),
                interchange(value),
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let map = pn_interchange::Map::new(entries).map_err(|_| Error::DuplicateKey)?;
    Ok(pn_interchange::Value::Map(map).to_canonical_bytes())
}
