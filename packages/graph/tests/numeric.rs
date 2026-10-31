use nrz_cas::{enclosure::RefinementPolicy, limits::Limits};
use pn_graph::numeric::{Error, evaluate, preflight, replay};
use pn_records::{
    DeclarationId,
    primitive::{EnclosurePolicy, Goal, Node, Outcome, Query, Range},
    solve::{Equality, Precision, Primitive, Procedure},
};
use std::collections::BTreeSet;

fn procedure() -> Procedure {
    let limits = Limits {
        work: 20_000_000,
        ..Limits::default()
    };
    Procedure {
        edition: DeclarationId {
            namespace: "numeric-test".into(),
            name: "primitives".into(),
            edition: 1,
        },
        boundary: 1,
        name: "certified-primitives".into(),
        backend: "nrz-cas".into(),
        primitives: BTreeSet::from([
            Primitive::Rational,
            Primitive::Root,
            Primitive::Logarithm,
            Primitive::Exponential,
            Primitive::Sigmoid,
            Primitive::Tanh,
            Primitive::Power,
            Primitive::SmoothDerivative,
            Primitive::ClampGeneralized,
        ]),
        precision: Precision::AbsoluteWidthBits(vec![4]),
        equality: Equality::ExactRationalOnly,
        grid: vec!["1".into(), "0".into()],
        margin: "5/4".into(),
        maximum_work: limits.work,
        maximum_iterations: 2,
        endpoint_grid: "1/64".into(),
        enclosure: Some(EnclosurePolicy {
            store: limits.clone(),
            operation: limits,
            refinement: RefinementPolicy {
                version: 1,
                precision: 4,
                grid_ceiling: 96,
                rounds: 2,
                reduction_ceiling: 4,
                term_ceiling: 64,
                checking_work: 1_000_000,
            },
        }),
    }
}
fn query(nodes: Vec<Node>) -> Query {
    Query {
        target: nodes.len() - 1,
        nodes,
        coordinates: Vec::new(),
        goal: Goal::Width,
    }
}
fn range(a: &str, b: &str) -> Range {
    Range {
        lower: a.into(),
        upper: b.into(),
    }
}

// Independent small-integer oracle. No nrz numbers, producer, interval or checker calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Q(i128, i128);
impl Q {
    fn new(n: i128, d: i128) -> Self {
        assert_ne!(d, 0);
        let (mut a, mut b) = (n.abs(), d.abs());
        while b != 0 {
            (a, b) = (b, a % b);
        }
        Self(n / a * d.signum(), d.abs() / a)
    }
    fn parse(s: &str) -> Self {
        let (n, d) = s.split_once('/').unwrap_or((s, "1"));
        Self::new(n.parse().unwrap(), d.parse().unwrap())
    }
    fn add(self, b: Self) -> Self {
        Self::new(self.0 * b.1 + b.0 * self.1, self.1 * b.1)
    }
    fn neg(self) -> Self {
        Self(-self.0, self.1)
    }
    fn mul(self, b: Self) -> Self {
        Self::new(self.0 * b.0, self.1 * b.1)
    }
    fn div(self, b: Self) -> Self {
        Self::new(self.0 * b.1, self.1 * b.0)
    }
    fn pow(self, n: u32) -> Self {
        Self::new(self.0.pow(n), self.1.pow(n))
    }
    fn le(self, b: Self) -> bool {
        self.0 * b.1 <= b.0 * self.1
    }
    fn grid(self, upper: bool) -> Self {
        self.round(6, upper)
    }
    fn round(self, bits: u32, upper: bool) -> Self {
        let scale = 1_i128 << bits;
        let n = self.0 * scale;
        Self::new(n.div_euclid(self.1) + i128::from(upper && n.rem_euclid(self.1) != 0), scale)
    }
}
fn endpoints(result: &pn_records::primitive::PrimitiveEvidence) -> (Q, Q) {
    let bounds = text_bounds(result);
    (Q::parse(&bounds.lower), Q::parse(&bounds.upper))
}
fn text_bounds(result: &pn_records::primitive::PrimitiveEvidence) -> Range {
    let bounds = result.bounds.as_ref().unwrap();
    let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    range(
        &bounds.lower().exact_string(&mut budget).unwrap(),
        &bounds.upper().exact_string(&mut budget).unwrap(),
    )
}
fn checked(input: &Query) -> pn_records::primitive::PrimitiveEvidence {
    let result = evaluate(&procedure(), input, None).unwrap();
    assert!(
        matches!(result.outcome, Outcome::Bound | Outcome::Indecisive(_)),
        "{input:?}: {result:?}"
    );
    let replayed = replay(&procedure(), input, result.attachment.as_ref().unwrap(), None).unwrap();
    assert_eq!(result.bounds, replayed.bounds);
    assert_eq!(result.outcome, replayed.outcome);
    result
}
fn oracle_contains(input: &Query, lower: Q, upper: Q) {
    let (a, b) = endpoints(&checked(input));
    assert!(
        lower.grid(false).le(a) && b.le(upper.grid(true)),
        "{lower:?} <= {a:?} <= {b:?} <= {upper:?}"
    );
}
fn contains_oracle(input: &Query, lower: Q, upper: Q) {
    let (a, b) = endpoints(&checked(input));
    assert!(
        a.le(lower) && lower.le(upper) && upper.le(b),
        "{a:?} <= {lower:?} <= {upper:?} <= {b:?}"
    );
}

// Directed integer rounding on a fixed grid bounds every product in the
// independent binomial oracle; it shares no analytic series with the backend.
fn rounded_power(mut base: Q, mut exponent: u32, upper: bool) -> Q {
    let mut result = Q(1, 1);
    while exponent != 0 {
        if exponent % 2 == 1 {
            result = result.mul(base).round(32, upper);
        }
        exponent /= 2;
        if exponent != 0 {
            base = base.mul(base).round(32, upper);
        }
    }
    result
}

fn tight_exp(x: Q) -> (Q, Q) {
    let one = Q(1, 1);
    if x.0 < 0 {
        let (a, b) = tight_exp(x.neg());
        return (one.div(b), one.div(a));
    }
    let h = x.div(Q(4096, 1));
    (
        rounded_power(one.add(h), 4096, false),
        one.div(rounded_power(one.add(h.neg()), 4096, false)),
    )
}

fn tight_log(x: Q) -> (Q, Q) {
    if x.le(Q(1, 1)) {
        if x == Q(1, 1) {
            return (Q(0, 1), Q(0, 1));
        }
        let (a, b) = tight_log(Q(1, 1).div(x));
        return (b.neg(), a.neg());
    }
    let h = x.add(Q(-1, 1)).div(Q(4096, 1));
    let (mut lower, mut upper) = (Q(0, 1), Q(0, 1));
    for i in 0..4096 {
        lower = lower.add(h.div(Q(1, 1).add(h.mul(Q(i + 1, 1)))).round(32, false));
        upper = upper.add(h.div(Q(1, 1).add(h.mul(Q(i, 1)))).round(32, true));
    }
    (lower, upper)
}
fn exp_bracket(x: Q) -> (Q, Q) {
    let one = Q(1, 1);
    if x.0 < 0 {
        let (a, b) = exp_bracket(x.neg());
        return (one.div(b), one.div(a));
    }
    let h = x.div(Q(4, 1));
    (one.add(h).pow(4), one.div(one.add(h.neg()).pow(4)))
}
fn log_bracket(x: Q) -> (Q, Q) {
    if x.le(Q(1, 1)) {
        if x == Q(1, 1) {
            return (Q(0, 1), Q(0, 1));
        }
        let (a, b) = log_bracket(Q(1, 1).div(x));
        return (b.neg(), a.neg());
    }
    let h = x.add(Q(-1, 1)).div(Q(8, 1));
    let (mut lower, mut upper) = (Q(0, 1), Q(0, 1));
    for i in 0..8 {
        lower = lower.add(h.div(Q(1, 1).add(h.mul(Q(i + 1, 1)))));
        upper = upper.add(h.div(Q(1, 1).add(h.mul(Q(i, 1)))));
    }
    (lower, upper)
}

/// Claim: Shuffled exact inputs exercise roots and all analytic primitive adapters against independent integer squaring, cubing, integral logarithm and binomial exponential brackets, with fresh expected-scope replay; these finite checks support the admitted subset and assert no solver result.
/// ´claim:numerics:primitive-bounds-agree-with-independent-oracles´
/// ´test:integration:primitive-oracles´
#[test]
fn primitive_oracles() {
    for text in ["2", "0", "1/4", "9", "1", "1/1024"] {
        let input = query(vec![Node::Rational(text.into()), Node::SquareRoot(0)]);
        let (a, b) = endpoints(&checked(&input));
        let x = Q::parse(text);
        assert!(a.pow(2).le(x) && x.le(b.pow(2)));
    }
    for text in ["2", "1/2", "1", "3/2"] {
        let (a, b) = log_bracket(Q::parse(text));
        oracle_contains(&query(vec![Node::Rational(text.into()), Node::Logarithm(0)]), a, b);
        let (a, b) = tight_log(Q::parse(text));
        contains_oracle(&query(vec![Node::Rational(text.into()), Node::Logarithm(0)]), a, b);
    }
    for text in ["1/2", "-1/4", "0", "-1/2", "1/4"] {
        let x = Q::parse(text);
        let (a, b) = exp_bracket(x);
        oracle_contains(&query(vec![Node::Rational(text.into()), Node::Exponential(0)]), a, b);
        let (tight_a, tight_b) = tight_exp(x);
        contains_oracle(
            &query(vec![Node::Rational(text.into()), Node::Exponential(0)]),
            tight_a,
            tight_b,
        );
        let one = Q(1, 1);
        oracle_contains(
            &query(vec![Node::Rational(text.into()), Node::Sigmoid(0)]),
            a.div(one.add(a)),
            b.div(one.add(b)),
        );
        contains_oracle(
            &query(vec![Node::Rational(text.into()), Node::Sigmoid(0)]),
            tight_a.div(one.add(tight_a)),
            tight_b.div(one.add(tight_b)),
        );
        let (a, b) = exp_bracket(x.mul(Q(2, 1)));
        oracle_contains(
            &query(vec![Node::Rational(text.into()), Node::Tanh(0)]),
            a.add(Q(-1, 1)).div(a.add(one)),
            b.add(Q(-1, 1)).div(b.add(one)),
        );
        let (a, b) = tight_exp(x.mul(Q(2, 1)));
        contains_oracle(
            &query(vec![Node::Rational(text.into()), Node::Tanh(0)]),
            a.add(Q(-1, 1)).div(a.add(one)),
            b.add(Q(-1, 1)).div(b.add(one)),
        );
    }
    for text in ["2", "1/2", "8", "1/8"] {
        let (a, b) = endpoints(&checked(&query(vec![
            Node::Rational(text.into()),
            Node::PositivePower(0, "1/3".into()),
        ])));
        assert!(a.pow(3).le(Q::parse(text)) && Q::parse(text).le(b.pow(3)));
    }
}

/// Claim: Full-box polynomial derivatives and four wall placements retain exact branch bounds and generalized slopes, while a zero-root derivative and a smooth derivative across a kink refuse without a mathematical verdict.
/// ´claim:numerics:primitive-domains-keep-generalized-slopes-distinct´
/// ´test:integration:primitive-domains´
#[test]
fn primitive_domains() {
    let mut derivative = query(vec![Node::Coordinate(0), Node::Multiply(0, 0), Node::Derivative(1, 0)]);
    derivative.coordinates = vec![range("-2", "3")];
    assert_eq!(text_bounds(&checked(&derivative)), range("-4", "6"));
    for (a, b, value, slope) in [
        ("-2", "-1", range("0", "0"), range("0", "0")),
        ("1", "2", range("1", "2"), range("1", "1")),
        ("-1", "0", range("0", "0"), range("0", "1")),
        ("-1", "1", range("0", "1"), range("0", "1")),
    ] {
        let mut input = query(vec![Node::Coordinate(0), Node::Rational("0".into()), Node::Clamp(0, 1)]);
        input.coordinates = vec![range(a, b)];
        assert_eq!(text_bounds(&checked(&input)), value);
        input.nodes.push(Node::GeneralizedDerivative(2, 0));
        input.target = 3;
        assert_eq!(text_bounds(&checked(&input)), slope);
        if a == "-1" && b == "1" {
            input.nodes[3] = Node::Derivative(2, 0);
            let refused = evaluate(&procedure(), &input, None);
            assert!(refused.is_err() || refused.unwrap().outcome == Outcome::Unsupported);
        }
    }
    derivative.nodes = vec![Node::Coordinate(0), Node::SquareRoot(0), Node::Derivative(1, 0)];
    derivative.coordinates = vec![range("0", "1")];
    assert!(evaluate(&procedure(), &derivative, None).is_err());
    for input in [
        query(vec![Node::Rational("-1".into()), Node::SquareRoot(0)]),
        query(vec![Node::Rational("0".into()), Node::Logarithm(0)]),
        query(vec![Node::Rational("0".into()), Node::PositivePower(0, "0".into())]),
        query(vec![
            Node::Rational("1".into()),
            Node::Rational("0".into()),
            Node::Divide(0, 1),
        ]),
    ] {
        let refused = evaluate(&procedure(), &input, None);
        assert!(refused.is_err() || refused.unwrap().outcome == Outcome::Unsupported);
    }
}

/// Claim: The primitive boundary preserves original comparison outcomes, distinguishes width-only bounds and interruption, refuses altered certificates and scopes, and admits no unknown schema or held composition through a backend name.
/// ´claim:numerics:primitive-replay-binds-scope-and-outcome´
/// ´test:integration:primitive-replay´
#[test]
fn primitive_replay() {
    assert_eq!(
        nrz_cas::enclosure::ENCLOSURE_SCHEMAS.map(|schema| (schema.name, schema.version)),
        pn_graph::numeric::SCHEMAS.map(|name| (name, 1))
    );
    let mut input = query(vec![Node::Rational("1/2".into())]);
    for (goal, expected) in [
        (Goal::Equal("1/2".into()), Outcome::Pass),
        (Goal::LessThan("0".into()), Outcome::Fail),
        (Goal::Width, Outcome::Bound),
    ] {
        input.goal = goal;
        assert_eq!(evaluate(&procedure(), &input, None).unwrap().outcome, expected);
    }
    input.goal = Goal::Width;
    let result = checked(&input);
    let original = result.attachment.unwrap();
    for case in 0..5 {
        let mut attachment = original.clone();
        match case {
            0 => attachment.certificate.version += 1,
            1 => attachment.certificate.scope.push(0),
            2 => attachment.certificate.records.clear(),
            3 => attachment.schemas[0].version += 1,
            _ => attachment.schemas[0].name.push_str("-unknown"),
        }
        assert!(replay(&procedure(), &input, &attachment, None).is_err());
    }
    input.goal = Goal::Equal("1/2".into());
    assert!(replay(&procedure(), &input, &original, None).is_err());
    assert_eq!(evaluate(&procedure(), &input, Some(0)).unwrap().outcome, Outcome::Interrupted);
    let mut interval = query(vec![Node::Coordinate(0)]);
    interval.coordinates = vec![range("-1", "1")];
    interval.goal = Goal::Equal("0".into());
    assert!(matches!(
        evaluate(&procedure(), &interval, None).unwrap().outcome,
        Outcome::Indecisive(_)
    ));
    for primitive in [Primitive::Matrix, Primitive::Krawczyk, Primitive::InverseGain] {
        let mut bad = procedure();
        bad.primitives.insert(primitive);
        assert!(preflight(&bad).is_err());
    }
    let mut bad = procedure();
    bad.precision = Precision::BinaryBits(vec![4]);
    assert_eq!(preflight(&bad), Err(Error::Unsupported));
}

/// Claim: Declared cold-store Work caps bound complete requests without padding consumption, with a one-unit-short refusal and exact-boundary success; tiny exact inputs, zero cancellation and finite size refusal preserve operational categories rather than fabricating a verdict.
/// ´claim:numerics:primitive-limits-retain-actual-work´
/// ´test:integration:primitive-limits´
#[test]
fn primitive_limits() {
    let input = query(vec![
        Node::Rational("2/3".into()),
        Node::Rational("3/5".into()),
        Node::Multiply(0, 1),
    ]);
    let mut p = procedure();
    p.enclosure.as_mut().unwrap().refinement.checking_work = 0;
    let measured = evaluate(&p, &input, None).unwrap();
    assert_eq!(measured.outcome, Outcome::Bound);
    assert_eq!((measured.work, measured.evaluation_work), (82_289, 76_872));
    for (limit, success) in [(measured.work - 1, false), (measured.work, true)] {
        let mut bounded = p.clone();
        let policy = bounded.enclosure.as_mut().unwrap();
        policy.store.work = limit;
        policy.operation.work = limit;
        let result = evaluate(&bounded, &input, None);
        assert_eq!(
            result.as_ref().is_ok_and(|value| value.outcome == Outcome::Bound),
            success,
            "{result:?}"
        );
        if let Ok(result) = result {
            assert!(result.work <= limit);
        }
    }
    assert_eq!(evaluate(&p, &input, None).unwrap(), measured);
    let mut bounded = p.clone();
    bounded.enclosure.as_mut().unwrap().store.work = 1;
    bounded.enclosure.as_mut().unwrap().operation.work = 1;
    assert!(evaluate(&bounded, &input, None).is_err());
    bounded.enclosure.as_mut().unwrap().store.work = 10_000;
    bounded.enclosure.as_mut().unwrap().operation.work = 10_000;
    let exhausted = evaluate(&bounded, &input, None).unwrap();
    assert_eq!(exhausted.outcome, Outcome::Exhausted);
    assert!(exhausted.bounds.is_none());
    assert!(exhausted.attachment.is_none());
    for text in ["1/1048576", "-1/1048576", "0"] {
        let input = query(vec![Node::Rational(text.into()), Node::Subtract(0, 0), Node::Exponential(1)]);
        assert_eq!(text_bounds(&checked(&input)), range("1", "1"));
        let input = query(vec![Node::Rational(text.into()), Node::Tanh(0)]);
        let (lower, upper) = endpoints(&checked(&input));
        if text != "0" {
            assert_ne!(lower, upper);
            assert!(lower.le(Q::parse(text)) && Q::parse(text).le(upper));
        }
    }
    let huge = query(vec![Node::Rational("1".repeat(5000))]);
    assert!(evaluate(&p, &huge, None).is_err());
    let fourth = query(vec![Node::Rational("2".into()), Node::SquareRoot(0), Node::SquareRoot(1)]);
    let (a, b) = endpoints(&checked(&fourth));
    assert!(a.pow(4).le(Q(2, 1)) && Q(2, 1).le(b.pow(4)));
    let beta = query(vec![Node::Rational("2".into()), Node::Logarithm(0), Node::Multiply(0, 1)]);
    let (a, b) = log_bracket(Q(2, 1));
    oracle_contains(&beta, a.mul(Q(2, 1)), b.mul(Q(2, 1)));
    let (a, b) = tight_log(Q(2, 1));
    contains_oracle(&beta, a.mul(Q(2, 1)), b.mul(Q(2, 1)));
}

// Independent directed fixed-grid computation, using integral/binomial brackets
// and integer root comparisons rather than the backend's analytic series.
#[derive(Clone, Copy, Debug)]
struct I(Q, Q);
impl I {
    fn point(value: Q) -> Self {
        Self(value, value)
    }
    fn rounded(a: Q, b: Q) -> Self {
        Self(a.round(24, false), b.round(24, true))
    }
    fn add(self, b: Self) -> Self {
        Self::rounded(self.0.add(b.0), self.1.add(b.1))
    }
    fn sub(self, b: Self) -> Self {
        Self::rounded(self.0.add(b.1.neg()), self.1.add(b.0.neg()))
    }
    fn mul(self, b: Self) -> Self {
        let values = [self.0.mul(b.0), self.0.mul(b.1), self.1.mul(b.0), self.1.mul(b.1)];
        let (mut low, mut high) = (values[0], values[0]);
        for value in values {
            if value.le(low) {
                low = value;
            }
            if high.le(value) {
                high = value;
            }
        }
        Self::rounded(low, high)
    }
    fn div(self, b: Self) -> Self {
        assert!(b.0.0 > 0);
        self.mul(Self::rounded(Q(1, 1).div(b.1), Q(1, 1).div(b.0)))
    }
    fn root(self, degree: u32) -> Self {
        fn endpoint(x: Q, degree: u32, upper: bool) -> Q {
            assert!(x.0 >= 0 && x.0 < 8_i128.pow(degree) * x.1);
            let scale = 1_i128 << 24;
            let target = x.0 * scale.pow(degree);
            let (mut low, mut high) = (0_i128, 8 * scale);
            while high - low > 1 {
                let middle = high.midpoint(low);
                if middle.pow(degree) * x.1 <= target {
                    low = middle;
                } else {
                    high = middle;
                }
            }
            Q::new(low + i128::from(upper && low.pow(degree) * x.1 != target), scale)
        }
        Self(endpoint(self.0, degree, false), endpoint(self.1, degree, true))
    }
    fn sigmoid(self) -> Self {
        let one = Q(1, 1);
        let (a, _) = tight_exp(self.0);
        let (_, b) = tight_exp(self.1);
        Self::rounded(a.div(one.add(a)), b.div(one.add(b)))
    }
    fn tanh(self) -> Self {
        let one = Q(1, 1);
        let (a, _) = tight_exp(self.0.mul(Q(2, 1)));
        let (_, b) = tight_exp(self.1.mul(Q(2, 1)));
        Self::rounded(a.add(one.neg()).div(a.add(one)), b.add(one.neg()).div(b.add(one)))
    }
}

fn independent_activation(x: Q, clean: bool, gain: bool) -> I {
    let one = I::point(Q(1, 1));
    let (log_lower, log_upper) = tight_log(Q(2, 1));
    let beta = I::rounded(log_lower.mul(Q(2, 1)), log_upper.mul(Q(2, 1)));
    let eta = I::point(if clean { Q(0, 1) } else { Q(1, 400) });
    let denominator = I::point(Q(1, 1).add(x));
    let p = I::point(x.div(Q(1, 1).add(x)));
    let core = |p: I| {
        let t = p.tanh();
        beta.mul(p).sigmoid().mul(t.mul(one.sub(eta.mul(t))).root(2))
    };
    if gain {
        let t = p.tanh();
        let slope = one.sub(t.mul(t));
        let kernel = beta
            .mul(one.sub(beta.mul(p).sigmoid()))
            .add(slope.div(I::point(Q(2, 1)).mul(t)))
            .sub(eta.mul(slope).div(I::point(Q(2, 1)).mul(one.sub(eta.mul(t)))));
        let gain = kernel.div(denominator.mul(denominator));
        if clean { gain } else { gain.mul(I::point(Q(1, 4))) }
    } else {
        core(p).div(core(one)).root(2).root(2)
    }
}

fn activation_request(text: &str, quantity: pn_graph::numeric::activation::Quantity) -> pn_graph::numeric::activation::Request {
    pn_graph::numeric::activation::Request {
        standing: range(text, text),
        bleed_squared: "1/400".into(),
        wall: None,
        quantity,
    }
}

fn activation_policy() -> Procedure {
    let mut p = procedure();
    p.maximum_work = 200_000_000;
    let policy = p.enclosure.as_mut().unwrap();
    policy.store.work = p.maximum_work;
    policy.operation.work = p.maximum_work;
    // The composed original expression's certificate preflight exceeds the
    // primitive default's one MiB. This is the fixture's declared ceiling.
    policy.store.output_bytes = 32 * 1024 * 1024;
    policy.operation.output_bytes = policy.store.output_bytes;
    policy.store.arithmetic_steps = 5_000_000;
    policy.operation.arithmetic_steps = policy.store.arithmetic_steps;
    // Full-box interval division loses correlation between x and 1+x; its
    // outward endpoints can exceed the exact p range. Retain the declared
    // reduction headroom rather than substituting a point-domain estimate.
    policy.refinement.reduction_ceiling = 4;
    policy.refinement.checking_work = 30_000_000;
    p
}

fn activation_checked(input: &pn_graph::numeric::activation::Request) -> (Q, Q) {
    use pn_graph::numeric::activation;
    let p = activation_policy();
    let result = activation::evaluate(&p, input, None);
    assert!(result.is_ok(), "{input:?}: {result:?}");
    let result = result.unwrap();
    assert!(
        matches!(result.primitive.evidence.outcome, Outcome::Bound | Outcome::Indecisive(_)),
        "{result:?}"
    );
    let replayed = activation::replay(&p, input, result.primitive.evidence.attachment.as_ref().unwrap(), None).unwrap();
    assert_eq!(replayed.primitive.evidence.bounds, result.primitive.evidence.bounds);
    assert_eq!(result.input, *input);
    endpoints(&result.primitive.evidence)
}

/// Claim: Responsive activation uses the normalized deployed core and its fourth root; independent directed integral, binomial and integer-root brackets lie inside the checked bounds on six unsorted standing inputs. Deployed reduced-standing gain and the clean full-core screen have distinct checked bounds on three positive inputs, without claiming a fence or a solve.
/// ´claim:numerics:activation-and-gain-agree-with-independent-brackets´
/// ´test:integration:activation-oracles´
#[test]
fn activation_oracles() {
    use pn_graph::numeric::activation::Quantity;
    for text in ["2", "0", "1/4", "8", "1", "1/2"] {
        let (a, b) = activation_checked(&activation_request(text, Quantity::Responsive));
        let oracle = independent_activation(Q::parse(text), false, false);
        assert!(a.le(oracle.0) && oracle.1.le(b), "{text}: {a:?} {oracle:?} {b:?}");
        if text == "0" {
            assert_eq!((a, b), (Q(0, 1), Q(0, 1)));
        } else {
            assert!(a.0 > 0 && b.le(Q(1, 1)));
        }
    }
    for text in ["2", "1/2", "1"] {
        let deployed = activation_checked(&activation_request(text, Quantity::ResponsiveLogGain));
        let clean = activation_checked(&activation_request(text, Quantity::CleanScreenLogGain));
        for (bounds, is_clean) in [(deployed, false), (clean, true)] {
            let oracle = independent_activation(Q::parse(text), is_clean, true);
            assert!(
                bounds.0.le(oracle.0) && oracle.1.le(bounds.1),
                "{text}: {bounds:?} {oracle:?}"
            );
        }
        assert!(deployed.1.le(clean.0));
    }
}

/// Claim: The wall clamp keeps the same below-wall value and zero generalized gain, retains the zero-to-responsive generalized join on touching and crossing boxes, and composes non-dyadic hop powers from the exact strength times shape. Expected-input replay rejects a changed wall; invalid domains and deterministic interruption carry no mathematical verdict.
/// ´claim:numerics:activation-clamp-keeps-generalized-wall-gain´
/// ´test:integration:activation-walls´
#[test]
fn activation_walls() {
    use pn_graph::numeric::activation::{self, Quantity};
    let mut input = activation_request("0", Quantity::Clamped);
    input.wall = Some("1".into());
    let wall_value = activation_checked(&input);
    for (a, b) in [("1/4", "1/2"), ("2", "3"), ("1/2", "1"), ("1/2", "2")] {
        input.standing = range(a, b);
        input.quantity = Quantity::Clamped;
        let values = activation_checked(&input);
        let at_wall = Q(1, 1);
        let lower_x = if Q::parse(a).le(at_wall) { at_wall } else { Q::parse(a) };
        let upper_x = if Q::parse(b).le(at_wall) { at_wall } else { Q::parse(b) };
        assert!(values.0.le(independent_activation(lower_x, false, false).0));
        assert!(independent_activation(upper_x, false, false).1.le(values.1));
        if b == "1/2" {
            assert_eq!(values, wall_value);
        }
        input.quantity = Quantity::GeneralizedLogGain;
        let slopes = activation_checked(&input);
        if b == "1/2" {
            assert_eq!(slopes, (Q(0, 1), Q(0, 1)));
        }
        if a == "1/2" {
            let oracle = independent_activation(Q(1, 1), false, true);
            assert!(slopes.0.le(Q(0, 1)) && oracle.1.le(slopes.1));
        }
        if a == "2" {
            assert!(slopes.0.le(independent_activation(Q(3, 1), false, true).0));
            assert!(independent_activation(Q(2, 1), false, true).1.le(slopes.1));
        }
    }
    input.standing = range("1/2", "1/2");
    input.quantity = Quantity::Hop {
        strength: "2/3".into(),
        shape: "1/2".into(),
    };
    let hop = activation_checked(&input);
    let oracle = independent_activation(Q(1, 1), false, false).root(3);
    assert!(hop.0.le(oracle.0) && oracle.1.le(hop.1));
    let mut zero_hop = input.clone();
    zero_hop.quantity = Quantity::Hop {
        strength: "0".into(),
        shape: "17/3".into(),
    };
    assert_eq!(activation_checked(&zero_hop), (Q(1, 1), Q(1, 1)));
    let policy = activation_policy();
    let result = activation::evaluate(&policy, &input, None).unwrap();
    assert!(matches!(result.primitive.query.nodes.last(), Some(Node::PositivePower(_, exponent)) if exponent == "1/3"));
    activation_refusals(input, &result);
}

fn activation_refusals(mut input: pn_graph::numeric::activation::Request, result: &pn_graph::numeric::activation::Evaluation) {
    use pn_graph::numeric::activation;
    let policy = activation_policy();
    let mut bounded = policy.clone();
    let limits = bounded.enclosure.as_mut().unwrap();
    limits.store.output_bytes = 1_048_576;
    limits.operation.output_bytes = 1_048_576;
    let exhausted = activation::evaluate(&bounded, &input, None).unwrap();
    assert_eq!(exhausted.primitive.evidence.outcome, Outcome::Exhausted);
    assert!(exhausted.primitive.evidence.bounds.is_none());
    assert!(matches!(
        exhausted.primitive.evidence.resource_fault.unwrap().kind,
        nrz_cas::FaultKind::Exhausted {
            budget: nrz_cas::limits::BudgetKind::OutputBytes,
            ..
        }
    ));
    input.wall = Some("2".into());
    assert!(activation::replay(&policy, &input, result.primitive.evidence.attachment.as_ref().unwrap(), None).is_err());
    assert_eq!(
        activation::evaluate(&policy, &input, Some(0))
            .unwrap()
            .primitive
            .evidence
            .outcome,
        Outcome::Interrupted
    );
    for (standing, wall, bleed) in [("-1", "1", "1/400"), ("1", "0", "1/400"), ("1", "1", "1")] {
        input.standing = range(standing, standing);
        input.wall = Some(wall.into());
        input.bleed_squared = bleed.into();
        assert!(activation::evaluate(&policy, &input, None).is_err());
    }
}

fn cost_inputs() -> Vec<pn_graph::numeric::activation::Request> {
    use pn_graph::numeric::activation::Quantity;
    let mut hop = activation_request(
        "1/2",
        Quantity::Hop {
            strength: "2/3".into(),
            shape: "1/2".into(),
        },
    );
    hop.wall = Some("1".into());
    let mut crossing = activation_request("1/2", Quantity::GeneralizedLogGain);
    crossing.standing = range("1/2", "2");
    crossing.wall = Some("1".into());
    vec![
        activation_request("1", Quantity::ResponsiveLogGain),
        activation_request("1/2", Quantity::Responsive),
        hop,
        crossing,
    ]
}

fn cost_policy() -> Procedure {
    let mut policy = activation_policy();
    policy.enclosure.as_mut().unwrap().refinement.checking_work = 0;
    policy
}

fn set_cost_limit(policy: &mut Procedure, resource: usize, value: u64) {
    let limits = policy.enclosure.as_mut().unwrap();
    match resource {
        0 => {
            limits.store.work = value;
            limits.operation.work = value;
        }
        1 => {
            limits.store.output_bytes = value;
            limits.operation.output_bytes = value;
        }
        _ => {
            limits.store.arithmetic_steps = value;
            limits.operation.arithmetic_steps = value;
        }
    }
}

/// Claim: Four composed requests pin cold total Work, evaluation Work, arithmetic steps, certificate bytes and minimum output ceilings; each Work, output and step ceiling succeeds at N and refuses complete evaluation at N minus one. A crossing-box width limit remains incomplete evidence, never a mathematical verdict.
/// ´claim:numerics:activation-costs-have-exact-resource-boundaries´
/// ´test:integration:activation-costs´
#[test]
fn activation_costs() {
    use pn_graph::numeric::activation;
    let pins = [
        (26_346_212, 26_303_212, 685_790, 8_483, 2_573_905),
        (22_122_299, 22_081_009, 578_260, 6_250, 12_191_733),
        (25_083_341, 25_035_921, 670_062, 7_445, 2_332_677),
        (120_143_841, 120_098_356, 2_388_598, 10_019, 2_673_792),
    ];
    for (input, (work, evaluation, steps, bytes, output)) in cost_inputs().into_iter().zip(pins) {
        let policy = cost_policy();
        let result = activation::evaluate(&policy, &input, None).unwrap().primitive.evidence;
        assert_eq!(
            (result.work, result.evaluation_work, result.usage.arithmetic_steps),
            (work, evaluation, steps)
        );
        let mut budget = nrz_cas::limits::Budget::new(policy.enclosure.as_ref().unwrap().operation.clone()).unwrap();
        assert_eq!(
            result
                .attachment
                .as_ref()
                .unwrap()
                .certificate
                .to_bytes(&mut budget)
                .unwrap()
                .len(),
            bytes
        );
        for (resource, ceiling) in [work, output, steps].into_iter().enumerate() {
            for (limit, expected) in [(ceiling, true), (ceiling - 1, false)] {
                let mut bounded = policy.clone();
                set_cost_limit(&mut bounded, resource, limit);
                let observed = activation::evaluate(&bounded, &input, None);
                assert_eq!(
                    observed.as_ref().is_ok_and(|x| x.primitive.evidence.bounds == result.bounds
                        && x.primitive.evidence.completed_rounds == result.completed_rounds
                        && x.primitive.evidence.resource_fault.is_none()),
                    expected,
                    "{input:?} {resource} {limit} {observed:?}"
                );
            }
        }
    }
}

/// Claim: Reference-profile monotone endpoint composition contains independent value and gain brackets on unsorted wall placements, keeps zero below the kink and its generalized join across it, and reuses a sealed activation for positive hop powers with every source premise retained. It admits no other bleed profile or gain as a reusable activation.
/// ´claim:numerics:activation-endpoints-retain-monotone-premises´
/// ´test:integration:activation-endpoints´
#[test]
fn activation_endpoints() {
    use pn_graph::numeric::activation::{self, Quantity, monotone};
    let policy = cost_policy();
    for (a, b) in [("1/2", "2"), ("2", "3"), ("1/4", "1/2"), ("1/2", "1")] {
        for quantity in [Quantity::Clamped, Quantity::GeneralizedLogGain] {
            let mut input = activation_request(a, quantity.clone());
            input.standing = range(a, b);
            input.wall = Some("1".into());
            let direct = activation::evaluate(&policy, &input, None).unwrap();
            let result = monotone::evaluate(&policy, &input).unwrap();
            let bounds = result.bounds().unwrap();
            let (low, high) = (Q::parse(&bounds.lower), Q::parse(&bounds.upper));
            let (outer_low, outer_high) = endpoints(&direct.primitive.evidence);
            assert!(outer_low.le(low) && high.le(outer_high));
            if quantity == Quantity::Clamped {
                let lower = if Q::parse(a).le(Q(1, 1)) { Q(1, 1) } else { Q::parse(a) };
                let upper = if Q::parse(b).le(Q(1, 1)) { Q(1, 1) } else { Q::parse(b) };
                assert!(low.le(independent_activation(lower, false, false).0));
                assert!(independent_activation(upper, false, false).1.le(high));
                let powered = monotone::power(&policy, &result, "1/3").unwrap();
                assert_eq!(powered.source(), Some(&result));
                let power_bounds = powered.bounds().unwrap();
                assert!(Q::parse(&power_bounds.lower).le(independent_activation(lower, false, false).root(3).0));
                assert!(
                    independent_activation(upper, false, false)
                        .root(3)
                        .1
                        .le(Q::parse(&power_bounds.upper))
                );
            } else if b == "1/2" {
                assert_eq!((low, high), (Q(0, 1), Q(0, 1)));
            } else if a == "1/2" {
                assert_eq!(low, Q(0, 1));
                assert!(independent_activation(Q(1, 1), false, true).1.le(high));
            }
            for record in result.records() {
                assert!(replay(&policy, &record.query, record.evidence.attachment.as_ref().unwrap(), None).is_ok());
            }
            assert!(result.work() > 0);
        }
    }
    let mut other = activation_request("1", Quantity::Responsive);
    other.bleed_squared = "1/100".into();
    assert!(monotone::evaluate(&policy, &other).is_err());
    other.bleed_squared = "1/400".into();
    other.quantity = Quantity::ResponsiveLogGain;
    let gain = monotone::evaluate(&policy, &other).unwrap();
    assert!(monotone::power(&policy, &gain, "1/3").is_err());
}
