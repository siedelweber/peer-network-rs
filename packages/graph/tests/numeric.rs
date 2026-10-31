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
        let n = self.0 * 64;
        Self::new(n.div_euclid(self.1) + i128::from(upper && n.rem_euclid(self.1) != 0), 64)
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
    }
    for text in ["1/2", "-1/4", "0", "-1/2", "1/4"] {
        let x = Q::parse(text);
        let (a, b) = exp_bracket(x);
        oracle_contains(&query(vec![Node::Rational(text.into()), Node::Exponential(0)]), a, b);
        let one = Q(1, 1);
        oracle_contains(
            &query(vec![Node::Rational(text.into()), Node::Sigmoid(0)]),
            a.div(one.add(a)),
            b.div(one.add(b)),
        );
        let (a, b) = exp_bracket(x.mul(Q(2, 1)));
        oracle_contains(
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
}
