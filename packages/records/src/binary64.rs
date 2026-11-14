//! Separate scalar evidence fragments; structural consistency is not numerical evidence.
//! (´[ROOT-rule:design:binary64-evidence]´)

use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use std::cmp::Ordering;

/// Closed structural refusal classes, without a mathematical sign.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The sign bit is set on zero.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    NegativeZero,
    /// The exponent is all ones.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    NonFinite,
    /// The exact rational spelling is not canonical and reduced.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Rational,
    /// A name is malformed, duplicated or out of order.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Name,
    /// An enclosure is reversed or empty.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Enclosure,
    /// A coordinate domain is reversed, empty or excludes a required point.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Domain,
    /// An index, input name, path or numeric leaf is unavailable.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Reference,
    /// The quantity list is not maximally shared first-occurrence post-order.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    CanonicalNodes,
    /// The adjustment flag or enclosure pair contradicts its predicate.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Adjustment,
    /// The predicate is incompatible with the required carrier form.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Predicate,
    /// A stated polarity disagrees with its enclosure or operational outcome.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Polarity,
    /// The non-rung test list disagrees with its outcome or polarity.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Tests,
    /// The rung grid or prefix has an invalid shape or descent.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    RungPrefix,
    /// The completed prefix lacks its terminal pass or continues after one.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    TerminalPass,
    /// The operational prefix skips an attempt or exhausts its grid.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    RefusalPrefix,
    /// The supplied public inputs differ from the expected inputs.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    OriginalInputs,
    /// The supplied enclosure pair differs from the expected pair.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    ActualEnclosure,
    /// The supplied expression, domain or hypotheses differ from the expected question.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Question,
    /// The requested consumer cannot use the supplied predicate or polarity.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Consumer,
    /// A declared arithmetic or representation bound is exhausted.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    Resource,
}

/// A finite binary64 pattern with one spelling for zero.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint(u64);

impl Endpoint {
    /// Refuse negative zero and every all-ones exponent without floating arithmetic.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    /// # Errors
    /// Returns the named pattern refusal.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "binary64-endpoint-new",
            source_item = "binary64::Endpoint::new"
        ),
        ret
    )]
    pub fn new(bits: u64) -> Result<Self, Error> {
        if bits == 1_u64 << 63 {
            return Err(Error::NegativeZero);
        }
        if (bits >> 52) & 2047 == 2047 {
            return Err(Error::NonFinite);
        }
        Ok(Self(bits))
    }

    /// The retained pattern, not a host floating value.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "binary64-endpoint-bits",
            source_item = "binary64::Endpoint::bits"
        ),
        ret
    )]
    pub fn bits(self) -> u64 {
        self.0
    }

    fn key(self) -> i128 {
        if self.0 < 1_u64 << 63 {
            i128::from(self.0)
        } else {
            -i128::from(self.0 - (1_u64 << 63))
        }
    }

    fn compare_fraction(self, fraction: &Fraction, budget: &mut Budget) -> Result<Ordering, Error> {
        let exponent = (self.0 >> 52) & 2047;
        let trailing = self.0 & ((1_u64 << 52) - 1);
        let mantissa = if exponent == 0 { trailing } else { trailing + (1_u64 << 52) };
        let power = if self.0 == 0 {
            0
        } else if exponent == 0 {
            -1074
        } else {
            i64::try_from(exponent).map_err(|_| Error::Resource)? - 1075
        };
        let numerator = i64::try_from(mantissa).map_err(|_| Error::Resource)?;
        let signed = if self.0 >> 63 == 0 { numerator } else { -numerator };
        let mut numerator = Rational::from_ratio(signed, 1, budget).map_err(|_| Error::Resource)?;
        let scale = Rational::from_ratio(2, 1, budget)
            .map_err(|_| Error::Resource)?
            .pow(power.abs(), budget)
            .map_err(|_| Error::Resource)?;
        let denominator = if power < 0 {
            scale
        } else {
            numerator = numerator.mul(&scale, budget).map_err(|_| Error::Resource)?;
            Rational::one()
        };
        let other_numerator = Rational::parse(&fraction.numerator, budget).map_err(|_| Error::Resource)?;
        let other_denominator = Rational::parse(&fraction.denominator, budget).map_err(|_| Error::Resource)?;
        let left = numerator.mul(&other_denominator, budget).map_err(|_| Error::Resource)?;
        let right = other_numerator.mul(&denominator, budget).map_err(|_| Error::Resource)?;
        left.compare(&right, budget).map_err(|_| Error::Resource)
    }
}

impl Ord for Endpoint {
    /// Integer order of the exact dyadic values.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    /// Justified: Pure integer comparison of validated public endpoints inherits the enclosing checked carrier operation and records no second operation.
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}
impl PartialOrd for Endpoint {
    /// Total finite order; no unordered floating value exists.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    /// Justified: Pure integer comparison of validated public endpoints inherits the enclosing checked carrier operation and records no second operation.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A canonical reduced rational pair, validated under the caller's arithmetic ceiling.
/// (´[ROOT-rule:design:binary64-evidence]´)
/// Its derived order compares decimal text and serves node uniqueness only; numeric comparison uses exact rational arithmetic.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fraction {
    numerator: String,
    denominator: String,
}

impl Fraction {
    /// Check canonical decimal syntax and reduction without rounded conversion.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    /// # Errors
    /// Refuses noncanonical pairs or exhausted arithmetic ceilings.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "binary64-fraction-new",
            source_item = "binary64::Fraction::new"
        ),
        ret
    )]
    pub fn new(numerator: String, denominator: String, limits: Limits) -> Result<Self, Error> {
        let value = Self { numerator, denominator };
        let mut budget = Budget::new(limits).map_err(|_| Error::Resource)?;
        value.read(&mut budget)?;
        Ok(value)
    }

    /// The exact two text members in their fixed order.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "binary64-fraction-parts",
            source_item = "binary64::Fraction::parts"
        ),
        ret
    )]
    pub fn parts(&self) -> (&str, &str) {
        (&self.numerator, &self.denominator)
    }

    fn read(&self, budget: &mut Budget) -> Result<Rational, Error> {
        fn positive(text: &str) -> bool {
            text.as_bytes().first().is_some_and(|b| matches!(b, b'1'..=b'9')) && text.bytes().all(|b| b.is_ascii_digit())
        }
        let magnitude = self.numerator.strip_prefix('-').unwrap_or(&self.numerator);
        if !positive(&self.denominator) || !(positive(magnitude) || self.numerator == "0") {
            return Err(Error::Rational);
        }
        let text = if self.denominator == "1" {
            self.numerator.clone()
        } else {
            format!("{}/{}", self.numerator, self.denominator)
        };
        let rational = Rational::parse(&text, budget).map_err(|_| Error::Resource)?;
        if rational.exact_string(budget).map_err(|_| Error::Resource)? != text {
            return Err(Error::Rational);
        }
        Ok(rational)
    }
}

/// A nonempty finite interval with explicit endpoint inclusion.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enclosure {
    lower: Endpoint,
    lower_included: bool,
    upper: Endpoint,
    upper_included: bool,
}
impl Enclosure {
    /// Refuse reversed endpoints and open singletons.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    /// # Errors
    /// Returns the enclosure refusal for an empty interval.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "binary64-enclosure-new",
            source_item = "binary64::Enclosure::new"
        ),
        ret
    )]
    pub fn new(lower: Endpoint, lower_included: bool, upper: Endpoint, upper_included: bool) -> Result<Self, Error> {
        if lower > upper || (lower == upper && !(lower_included && upper_included)) {
            return Err(Error::Enclosure);
        }
        Ok(Self {
            lower,
            lower_included,
            upper,
            upper_included,
        })
    }
    /// The four fixed members of the enclosure.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "binary64-enclosure-parts",
            source_item = "binary64::Enclosure::parts"
        ),
        ret
    )]
    pub fn parts(self) -> (Endpoint, bool, Endpoint, bool) {
        (self.lower, self.lower_included, self.upper, self.upper_included)
    }
    fn membership(self, target: Self) -> Polarity {
        let lower = self.lower > target.lower || (self.lower == target.lower && (!self.lower_included || target.lower_included));
        let upper = self.upper < target.upper || (self.upper == target.upper && (!self.upper_included || target.upper_included));
        if lower && upper {
            Polarity::Proposition
        } else if self.upper < target.lower
            || self.lower > target.upper
            || (self.upper == target.lower && !(self.upper_included && target.lower_included))
            || (self.lower == target.upper && !(self.lower_included && target.upper_included))
        {
            Polarity::Negation
        } else {
            Polarity::Uncertified
        }
    }
}

/// Exact public data; its constructor follows the source field's type.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    Rational(Fraction),
    Binary64(Endpoint),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Record(Vec<(String, Self)>),
    Boolean(bool),
    Absent,
}

/// A path into an original numeric source field.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Path {
    Index(u64),
    Field(String),
}

/// Closed mathematical syntax, with ordered children and no execution schedule.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Node {
    Input(String, Vec<Path>),
    Coordinate(u64),
    Constant(Fraction),
    Negate(u64),
    Add(u64, u64),
    Subtract(u64, u64),
    Multiply(u64, u64),
    Divide(u64, u64),
    SquareRoot(u64),
    Logarithm(u64),
    Exponential(u64),
    Sigmoid(u64),
    Tanh(u64),
    Power(u64, Fraction),
    Derivative(u64, u64),
    Clamp(u64, u64),
    GeneralizedDerivative(u64, u64),
}
impl Node {
    fn children(&self) -> Vec<u64> {
        match self {
            Self::Input(..) | Self::Coordinate(_) | Self::Constant(_) => vec![],
            Self::Add(a, b) | Self::Subtract(a, b) | Self::Multiply(a, b) | Self::Divide(a, b) | Self::Clamp(a, b) => {
                vec![*a, *b]
            }
            Self::Negate(a)
            | Self::SquareRoot(a)
            | Self::Logarithm(a)
            | Self::Exponential(a)
            | Self::Sigmoid(a)
            | Self::Tanh(a)
            | Self::Power(a, _)
            | Self::Derivative(a, _)
            | Self::GeneralizedDerivative(a, _) => vec![*a],
        }
    }
}

/// Original source bytes and their separately retained interpretation.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub name: String,
    pub source: Vec<u8>,
    pub value: Data,
}
/// One coordinate of the complete original domain.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coordinate {
    pub name: String,
    pub lower: Fraction,
    pub lower_included: bool,
    pub upper: Fraction,
    pub upper_included: bool,
}
/// A hypothesis relation, retaining its declared position.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    Equal,
    Less,
    AtMost,
}
/// A relation between two quantity nodes, not a proof of domain feasibility.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hypothesis {
    pub relation: Relation,
    pub left: u64,
    pub right: u64,
}
/// Original mathematical question, compared as a complete value.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub nodes: Vec<Node>,
    pub root: u64,
    pub inputs: Vec<Input>,
    pub coordinates: Vec<Coordinate>,
    pub hypotheses: Vec<Hypothesis>,
}
/// Closed comparison predicates; membership alone has no rational threshold.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Predicate {
    Membership,
    AtMost(Fraction),
    Less(Fraction),
    Equal(Fraction),
    AtLeast(Fraction),
    Greater(Fraction),
}
/// Mathematical sign, separate from operational outcome.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polarity {
    Proposition,
    Negation,
    Uncertified,
}
/// Consumer role; this code grants no authority to adjust a question.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consumer {
    Free,
    Value,
    Map,
    Residual,
    Rung,
    Fixed,
    Local,
}
/// Operational results never imply mathematical negation.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    InvalidInput,
    InvalidEvidence,
    Unsupported,
    TargetNotCertifiable,
    Resource,
    Interrupted,
}
/// One completed interval test; refusal creates no interval.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Test {
    pub subject: Option<u64>,
    pub evaluated: Enclosure,
    pub result: Polarity,
}
/// One completed rung, with explicit consecutive grid and test indices.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub grid: u64,
    pub test: u64,
    pub result: Polarity,
}
/// The candidate grid and its complete attempted prefix.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rungs {
    pub coordinate: u64,
    pub grid: Vec<Fraction>,
    pub rows: Vec<Row>,
}
/// Untrusted typed members awaiting structural validation; no evidence capability.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fields {
    pub question: Question,
    pub enclosures: Option<(Enclosure, Enclosure)>,
    pub adjusted: bool,
    pub predicate: Predicate,
    pub polarity: Polarity,
    pub consumer: Consumer,
    pub tests: Vec<Test>,
    pub rungs: Option<Rungs>,
    pub outcome: Outcome,
}
/// Structurally consistent supplied intervals, never an admission or soundness proof.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carrier(Fields);

/// Independently fixed consumer question and permitted result, never read from the carrier.
/// (´[ROOT-rule:design:binary64-evidence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    pub question: Question,
    pub enclosures: Option<(Enclosure, Enclosure)>,
    pub adjusted: bool,
    pub predicate: Predicate,
    pub polarity: Polarity,
    pub consumer: Consumer,
    pub grid: Option<(u64, Vec<Fraction>)>,
}

fn name(text: &str) -> bool {
    text.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn names<'a>(values: impl Iterator<Item = &'a str>) -> Result<(), Error> {
    let mut previous = None;
    for value in values {
        if !name(value) || previous.is_some_and(|p| p >= value) {
            return Err(Error::Name);
        }
        previous = Some(value);
    }
    Ok(())
}
fn index(value: u64, len: usize) -> Result<usize, Error> {
    let result = usize::try_from(value).map_err(|_| Error::Reference)?;
    if result >= len { Err(Error::Reference) } else { Ok(result) }
}

impl Carrier {
    /// Validate the closed carrier and interval implications under explicit arithmetic limits.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    /// # Errors
    /// Returns a named structural refusal or a resource refusal, never a sign.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "binary64-carrier-new",
            source_item = "binary64::Carrier::new"
        ),
        ret
    )]
    pub fn new(fields: Fields, limits: Limits) -> Result<Self, Error> {
        let mut budget = Budget::new(limits).map_err(|_| Error::Resource)?;
        validate_question(&fields.question, &mut budget)?;
        validate_tests(&fields, &mut budget)?;
        Ok(Self(fields))
    }
    /// Immutable checked members; their intervals remain unproved assertions.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "binary64-carrier-fields",
            source_item = "binary64::Carrier::fields"
        ),
        ret
    )]
    pub fn fields(&self) -> &Fields {
        &self.0
    }

    /// Compare the complete independent question; success proves binding, not interval soundness.
    /// (´[ROOT-rule:design:binary64-evidence]´)
    /// # Errors
    /// Refuses substitutions of inputs, context, target, sign or consumer permission.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "binary64-carrier-bind",
            source_item = "binary64::Carrier::bind"
        ),
        ret
    )]
    pub fn bind(&self, expected: &Expected) -> Result<(), Error> {
        let fields = &self.0;
        if fields.question.inputs != expected.question.inputs {
            return Err(Error::OriginalInputs);
        }
        if fields.question.nodes != expected.question.nodes
            || fields.question.root != expected.question.root
            || fields.question.coordinates != expected.question.coordinates
            || fields.question.hypotheses != expected.question.hypotheses
        {
            return Err(Error::Question);
        }
        if fields.enclosures != expected.enclosures {
            return Err(Error::ActualEnclosure);
        }
        if fields.predicate != expected.predicate {
            return Err(Error::Predicate);
        }
        if fields.polarity != expected.polarity {
            return Err(Error::Polarity);
        }
        if fields.adjusted != expected.adjusted {
            return Err(Error::Adjustment);
        }
        if fields.consumer != expected.consumer {
            return Err(Error::Consumer);
        }
        let grid = fields.rungs.as_ref().map(|r| (r.coordinate, r.grid.clone()));
        if grid != expected.grid {
            return Err(Error::RungPrefix);
        }
        Ok(())
    }
}

fn validate_question(question: &Question, budget: &mut Budget) -> Result<(), Error> {
    names(question.inputs.iter().map(|v| v.name.as_str()))?;
    names(question.coordinates.iter().map(|v| v.name.as_str()))?;
    let mut pending: Vec<_> = question.inputs.iter().map(|input| &input.value).collect();
    while let Some(value) = pending.pop() {
        match value {
            Data::Rational(q) => {
                q.read(budget)?;
            }
            Data::Array(values) => pending.extend(values),
            Data::Record(fields) => {
                names(fields.iter().map(|(name, _)| name.as_str()))?;
                pending.extend(fields.iter().map(|(_, v)| v));
            }
            _ => {}
        }
    }
    for coordinate in &question.coordinates {
        let lower = coordinate.lower.read(budget)?;
        let upper = coordinate.upper.read(budget)?;
        let order = lower.compare(&upper, budget).map_err(|_| Error::Resource)?;
        if order == Ordering::Greater || (order == Ordering::Equal && !(coordinate.lower_included && coordinate.upper_included)) {
            return Err(Error::Domain);
        }
    }
    validate_nodes(question, budget)
}

fn validate_nodes(question: &Question, budget: &mut Budget) -> Result<(), Error> {
    let root = index(question.root, question.nodes.len())?;
    if root + 1 != question.nodes.len() {
        return Err(Error::CanonicalNodes);
    }
    let mut unique = std::collections::BTreeSet::new();
    for (position, node) in question.nodes.iter().enumerate() {
        if !unique.insert(node) {
            return Err(Error::CanonicalNodes);
        }
        for child in node.children() {
            index(child, position)?;
        }
        match node {
            Node::Input(input, path) => {
                // validate_question checks every input and record name list
                // before entering this walk, including unused nested records.
                let position = question
                    .inputs
                    .binary_search_by(|v| v.name.cmp(input))
                    .map_err(|_| Error::Reference)?;
                let mut value = &question.inputs[position].value;
                for step in path {
                    value = match (step, value) {
                        (Path::Index(i), Data::Array(values)) => &values[index(*i, values.len())?],
                        (Path::Field(key), Data::Record(values)) => {
                            let position = values
                                .binary_search_by(|(name, _)| name.cmp(key))
                                .map_err(|_| Error::Reference)?;
                            &values[position].1
                        }
                        _ => return Err(Error::Reference),
                    };
                }
                if !matches!(value, Data::Rational(_) | Data::Binary64(_)) {
                    return Err(Error::Reference);
                }
            }
            Node::Coordinate(c) | Node::Derivative(_, c) | Node::GeneralizedDerivative(_, c) => {
                index(*c, question.coordinates.len())?;
            }
            Node::Constant(q) | Node::Power(_, q) => {
                q.read(budget)?;
            }
            _ => {}
        }
    }
    let mut starts = Vec::new();
    for hypothesis in &question.hypotheses {
        for operand in [hypothesis.left, hypothesis.right] {
            let operand = index(operand, question.nodes.len())?;
            if operand != root {
                starts.push(operand);
            }
        }
    }
    starts.push(root);
    let mut visited = vec![false; question.nodes.len()];
    let mut emitted = 0;
    for start in starts {
        let mut stack = vec![(start, false)];
        while let Some((position, finish)) = stack.pop() {
            if visited[position] {
                continue;
            }
            if finish {
                if position != emitted {
                    return Err(Error::CanonicalNodes);
                }
                visited[position] = true;
                emitted += 1;
            } else {
                stack.push((position, true));
                for child in question.nodes[position].children().into_iter().rev() {
                    stack.push((index(child, position)?, false));
                }
            }
        }
    }
    if emitted != question.nodes.len() {
        return Err(Error::CanonicalNodes);
    }
    Ok(())
}

fn test_result(test: &Test, fields: &Fields, budget: &mut Budget) -> Result<Polarity, Error> {
    let threshold = match &fields.predicate {
        Predicate::Membership => return Ok(test.evaluated.membership(fields.enclosures.ok_or(Error::Predicate)?.1)),
        Predicate::AtMost(q) | Predicate::Less(q) | Predicate::Equal(q) | Predicate::AtLeast(q) | Predicate::Greater(q) => {
            q.read(budget)?;
            q
        }
    };
    let interval = test.evaluated;
    let lo = interval.lower.compare_fraction(threshold, budget)?;
    let hi = interval.upper.compare_fraction(threshold, budget)?;
    let (proved, disproved) = match &fields.predicate {
        Predicate::AtMost(_) => (
            hi != Ordering::Greater,
            lo == Ordering::Greater || (lo == Ordering::Equal && !interval.lower_included),
        ),
        Predicate::Less(_) => (
            hi == Ordering::Less || (hi == Ordering::Equal && !interval.upper_included),
            lo != Ordering::Less,
        ),
        Predicate::AtLeast(_) => (
            lo != Ordering::Less,
            hi == Ordering::Less || (hi == Ordering::Equal && !interval.upper_included),
        ),
        Predicate::Greater(_) => (
            lo == Ordering::Greater || (lo == Ordering::Equal && !interval.lower_included),
            hi != Ordering::Greater,
        ),
        Predicate::Equal(_) => (
            lo == Ordering::Equal && hi == Ordering::Equal,
            lo == Ordering::Greater
                || hi == Ordering::Less
                || (lo == Ordering::Equal && !interval.lower_included)
                || (hi == Ordering::Equal && !interval.upper_included),
        ),
        Predicate::Membership => return Err(Error::Predicate),
    };
    Ok(if proved {
        Polarity::Proposition
    } else if disproved {
        Polarity::Negation
    } else {
        Polarity::Uncertified
    })
}

fn validate_tests(fields: &Fields, budget: &mut Budget) -> Result<(), Error> {
    match (&fields.predicate, fields.enclosures) {
        (Predicate::Membership, Some((original, actual))) => {
            if fields.adjusted == (original == actual) {
                return Err(Error::Adjustment);
            }
        }
        (Predicate::Membership, None) => return Err(Error::Predicate),
        (_, None) if !fields.adjusted => {}
        _ => return Err(Error::Adjustment),
    }
    if matches!(fields.consumer, Consumer::Value | Consumer::Map | Consumer::Residual)
        && (fields.predicate != Predicate::Membership || fields.polarity != Polarity::Proposition)
    {
        return Err(Error::Consumer);
    }
    if fields.consumer == Consumer::Fixed && fields.predicate == Predicate::Membership {
        return Err(Error::Consumer);
    }
    if fields.outcome != Outcome::Completed && fields.polarity != Polarity::Uncertified {
        return Err(Error::Polarity);
    }
    for test in &fields.tests {
        if test_result(test, fields, budget)? != test.result {
            return Err(Error::Polarity);
        }
    }
    if fields.consumer != Consumer::Rung {
        if fields.rungs.is_some() {
            return Err(Error::RungPrefix);
        }
        match fields.tests.as_slice() {
            [test] if fields.outcome == Outcome::Completed && test.subject.is_none() && test.result == fields.polarity => {}
            [] if fields.outcome != Outcome::Completed => {}
            _ => return Err(Error::Tests),
        }
        return Ok(());
    }
    validate_rungs(fields, budget)
}

fn validate_rungs(fields: &Fields, budget: &mut Budget) -> Result<(), Error> {
    if !matches!(&fields.predicate, Predicate::AtMost(q) if q.parts() == ("1","1")) {
        return Err(Error::Predicate);
    }
    let rungs = fields.rungs.as_ref().ok_or(Error::RungPrefix)?;
    let coordinate = &fields.question.coordinates[index(rungs.coordinate, fields.question.coordinates.len())?];
    if rungs.grid.is_empty()
        || rungs.grid.last().map(Fraction::parts) != Some(("0", "1"))
        || rungs.rows.len() != fields.tests.len()
        || rungs.rows.len() > rungs.grid.len()
    {
        return Err(Error::RungPrefix);
    }
    let lower = coordinate.lower.read(budget)?;
    let upper = coordinate.upper.read(budget)?;
    let mut previous: Option<Rational> = None;
    for q in &rungs.grid {
        let value = q.read(budget)?;
        let lo = value.compare(&lower, budget).map_err(|_| Error::Resource)?;
        let hi = value.compare(&upper, budget).map_err(|_| Error::Resource)?;
        if value.is_negative()
            || lo == Ordering::Less
            || hi == Ordering::Greater
            || (lo == Ordering::Equal && !coordinate.lower_included)
            || (hi == Ordering::Equal && !coordinate.upper_included)
        {
            return Err(Error::Domain);
        }
        if let Some(p) = previous
            && p.compare(&value, budget).map_err(|_| Error::Resource)? != Ordering::Greater
        {
            return Err(Error::RungPrefix);
        }
        previous = Some(value);
    }
    for (position, (row, test)) in rungs.rows.iter().zip(&fields.tests).enumerate() {
        let expected = u64::try_from(position).map_err(|_| Error::Resource)?;
        if row.grid != expected || row.test != expected || test.subject != Some(expected) || row.result != test.result {
            return Err(Error::RefusalPrefix);
        }
        if !(test.evaluated.lower_included && test.evaluated.upper_included) {
            return Err(Error::Enclosure);
        }
        if row.result == Polarity::Proposition && (position + 1 != rungs.rows.len() || fields.outcome != Outcome::Completed) {
            return Err(Error::TerminalPass);
        }
    }
    if fields.outcome == Outcome::Completed {
        if rungs.rows.last().map(|row| row.result) != Some(Polarity::Proposition) || fields.polarity != Polarity::Proposition {
            return Err(Error::TerminalPass);
        }
    } else if rungs.rows.len() >= rungs.grid.len() {
        return Err(Error::RefusalPrefix);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Claim: Exact-route rational arithmetic independently checks the corpus's dyadic operands, threshold signs and membership relations, including original rational inputs distinct from their rounded surrogate; these checks establish no native law.
    /// ´claim:numerics:binary64-exact-golden-relations´
    /// ´test:unit:binary64-exact-golden-relations´
    #[test]
    fn binary64_exact_golden_relations() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../host/tests/data/binary64-carriers.json")).unwrap();
        let limits = Limits {
            integer_exponent: 1074,
            work: 20_000_000,
            literal_bytes: 1024,
            ..Limits::default()
        };
        for row in corpus["cases"].as_array().unwrap() {
            if !row["refusal"].is_null() {
                continue;
            }
            check_operands(row, &limits);
            check_membership(row, &limits);
            check_threshold(row, &limits);
        }
        let mut budget = Budget::new(limits).unwrap();
        let row = corpus["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["case"] == "original-not-rounded")
            .unwrap();
        let original_pair = &row["original_question"][1][0][2][1];
        let evaluated_pair = &row["exact_operands"][0];
        let original = Rational::parse(
            &format!(
                "{}/{}",
                original_pair[0].as_str().unwrap(),
                original_pair[1].as_str().unwrap()
            ),
            &mut budget,
        )
        .unwrap();
        let rounded = Rational::parse(
            &format!(
                "{}/{}",
                evaluated_pair[0].as_str().unwrap(),
                evaluated_pair[1].as_str().unwrap()
            ),
            &mut budget,
        )
        .unwrap();
        assert_eq!(
            original.compare(&rounded, &mut budget).unwrap(),
            Ordering::Greater,
            "original exact input differs from rounded surrogate"
        );
    }
    fn check_operands(row: &serde_json::Value, limits: &Limits) {
        let patterns = row["endpoint_patterns"].as_array().unwrap();
        let operands = row["exact_operands"].as_array().unwrap();
        for (pattern, pair) in patterns.iter().zip(operands) {
            let mut budget = Budget::new(limits.clone()).unwrap();
            let bits = u64::from_str_radix(pattern.as_str().unwrap(), 16).unwrap();
            let exponent = (bits / (1_u64 << 52)) % 2048;
            let significand = (bits % (1_u64 << 52)) + if exponent == 0 { 0 } else { 1_u64 << 52 };
            let signed = if bits >= 1_u64 << 63 {
                format!("-{significand}")
            } else {
                significand.to_string()
            };
            let integer = Rational::parse(&signed, &mut budget).unwrap();
            let shift = if exponent == 0 {
                -1074
            } else {
                i64::try_from(exponent).unwrap() - 1075
            };
            let power = Rational::from_ratio(2, 1, &mut budget)
                .unwrap()
                .pow(shift, &mut budget)
                .unwrap();
            let exact = integer.mul(&power, &mut budget).unwrap();
            let golden = Rational::parse(
                &format!("{}/{}", pair[0].as_str().unwrap(), pair[1].as_str().unwrap()),
                &mut budget,
            )
            .unwrap();
            assert_eq!(
                exact.compare(&golden, &mut budget).unwrap(),
                Ordering::Equal,
                "exact-route operand {}",
                row["case"]
            );
        }
    }

    fn check_threshold(row: &serde_json::Value, limits: &Limits) {
        let predicate = &row["original_question"][3];
        let code = predicate[0].as_u64().unwrap();
        if code == 0 {
            return;
        }
        let mut budget = Budget::new(limits.clone()).unwrap();
        let pair = &predicate[1];
        let threshold = Rational::parse(
            &format!("{}/{}", pair[0].as_str().unwrap(), pair[1].as_str().unwrap()),
            &mut budget,
        )
        .unwrap();
        for (test, endpoints) in row["tests"]
            .as_array()
            .unwrap()
            .iter()
            .zip(row["exact_operands"].as_array().unwrap().as_chunks::<2>().0)
        {
            let mut read = |pair: &serde_json::Value| {
                Rational::parse(
                    &format!("{}/{}", pair[0].as_str().unwrap(), pair[1].as_str().unwrap()),
                    &mut budget,
                )
                .unwrap()
            };
            let lower = read(&endpoints[0]);
            let upper = read(&endpoints[1]);
            let lo = lower.compare(&threshold, &mut budget).unwrap();
            let hi = upper.compare(&threshold, &mut budget).unwrap();
            let possible = [
                lo == Ordering::Less,
                lo != Ordering::Greater
                    && hi != Ordering::Less
                    && (lo != Ordering::Equal || test[1][1].as_bool().unwrap())
                    && (hi != Ordering::Equal || test[1][3].as_bool().unwrap()),
                hi == Ordering::Greater,
            ];
            let admitted = match code {
                1 => [true, true, false],
                2 => [true, false, false],
                3 => [false, true, false],
                4 => [false, true, true],
                5 => [false, false, true],
                _ => panic!("closed threshold vocabulary"),
            };
            let positive = possible.iter().zip(admitted).any(|(p, a)| *p && a);
            let negative = possible.iter().zip(admitted).any(|(p, a)| *p && !a);
            let result = if !negative {
                0
            } else if !positive {
                1
            } else {
                2
            };
            assert_eq!(
                test[2].as_u64().unwrap(),
                result,
                "exact-route enclosure and threshold {}",
                row["case"]
            );
        }
    }

    fn check_membership(row: &serde_json::Value, limits: &Limits) {
        if let Some(intervals) = row["membership_operands"].as_array() {
            let mut budget = Budget::new(limits.clone()).unwrap();
            let mut read = |pair: &serde_json::Value| {
                Rational::parse(
                    &format!("{}/{}", pair[0].as_str().unwrap(), pair[1].as_str().unwrap()),
                    &mut budget,
                )
                .unwrap()
            };
            let lo = read(&intervals[0][0]);
            let hi = read(&intervals[0][2]);
            let tl = read(&intervals[1][0]);
            let th = read(&intervals[1][2]);
            let li = intervals[0][1].as_bool().unwrap();
            let ui = intervals[0][3].as_bool().unwrap();
            let tli = intervals[1][1].as_bool().unwrap();
            let tui = intervals[1][3].as_bool().unwrap();
            let lower = lo.compare(&tl, &mut budget).unwrap();
            let upper = hi.compare(&th, &mut budget).unwrap();
            let left = hi.compare(&tl, &mut budget).unwrap();
            let right = lo.compare(&th, &mut budget).unwrap();
            let contained = (lower == Ordering::Greater || (lower == Ordering::Equal && (!li || tli)))
                && (upper == Ordering::Less || (upper == Ordering::Equal && (!ui || tui)));
            let disjoint = left == Ordering::Less
                || right == Ordering::Greater
                || (left == Ordering::Equal && !(ui && tli))
                || (right == Ordering::Equal && !(li && tui));
            let result = if contained {
                0
            } else if disjoint {
                1
            } else {
                2
            };
            assert_eq!(
                row["expected_relation"].as_u64().unwrap(),
                result,
                "exact-route membership {}",
                row["case"]
            );
        }
    }
}
