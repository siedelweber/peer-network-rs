use nrz_cas::{Rational, enclosure::Interval, limits::Budget};
use pn_graph::numeric::activation::{Quantity, Request, bounded, sharing::Session};
use pn_records::primitive::{Goal, Node, Query};
use pn_records::{
    primitive::Range,
    solve::{Precision, Procedure},
};

fn procedure(bits: u32) -> Procedure {
    let mut p = super::procedure();
    p.maximum_work = 20_000_000_000;
    p.precision = Precision::AbsoluteWidthBits(vec![bits]);
    let e = p.enclosure.as_mut().unwrap();
    e.operation.work = p.maximum_work;
    e.operation.output_bytes = 32 * 1024 * 1024;
    e.operation.arithmetic_steps = 1_000_000_000;
    e.store = e.operation.clone();
    e.refinement.precision = bits;
    e.refinement.rounds = 1;
    e.refinement.checking_work = 0;
    p
}
fn interval(lower: &str, upper: &str, b: &mut Budget) -> Interval {
    Interval::new(Rational::parse(lower, b).unwrap(), Rational::parse(upper, b).unwrap(), b).unwrap()
}

/// Claim: Bounded activation contains independently certified finer exact-route enclosures on distinct zero, near-zero, wall and standing-box fixtures; every published result meets its declared width and an unattained target supplies no scalar.
/// ´claim:numerics:bounded-activation-retains-oracle-enclosure´
/// ´test:integration:bounded-activation-oracle´
#[test]
fn bounded_activation_oracle() {
    let p = procedure(16);
    let constants = Session::prepared(&p, "1/400", None)
        .unwrap()
        .premises()
        .iter()
        .map(|r| r.evidence.bounds.clone().unwrap())
        .collect::<Vec<_>>();
    let constants: [Interval; 2] = constants.try_into().unwrap();
    let oracle = procedure(32);
    let mut session = Session::prepared(&oracle, "1/400", None).unwrap();
    let mut policy = p.enclosure.as_ref().unwrap().refinement;
    policy.grid_ceiling = 48;
    for (lower, upper, wall) in [
        ("1/2", "1/2", Some("3/37")),
        ("0", "0", None),
        ("1/1024", "1/1024", None),
        ("0", "0", Some("1/1024")),
        ("1", "16777217/16777216", None),
        ("3", "3", None),
    ] {
        let request = Request {
            standing: Range {
                lower: lower.into(),
                upper: upper.into(),
            },
            bleed_squared: "1/400".into(),
            wall: wall.map(str::to_owned),
            wall_enclosure: None,
            quantity: if wall.is_some() {
                Quantity::Clamped
            } else {
                Quantity::Responsive
            },
        };
        let index = session.evaluate(&request).unwrap();
        let certified = session.evidence(index).unwrap().primitive.evidence.bounds.as_ref().unwrap();
        let mut b = Budget::new(p.enclosure.as_ref().unwrap().operation.clone()).unwrap();
        let got = bounded::activation(&request, &constants, &policy, 16, &mut b).unwrap();
        assert!(got.contains(certified, &mut b).unwrap(), "{lower}..{upper}");
        assert!(
            !got.width(&mut b)
                .unwrap()
                .compare(&Rational::parse("1/65536", &mut b).unwrap(), &mut b)
                .unwrap()
                .is_gt()
        );
        if lower == "0" && wall.is_none() {
            assert!(got.lower().is_zero() && got.upper().is_zero());
        }
        assert!(b.usage().work > 0);
    }
    let request = Request {
        standing: Range {
            lower: "1/2".into(),
            upper: "1/2".into(),
        },
        bleed_squared: "1/400".into(),
        wall: None,
        wall_enclosure: None,
        quantity: Quantity::Responsive,
    };
    let mut b = Budget::new(p.enclosure.as_ref().unwrap().operation.clone()).unwrap();
    policy.term_ceiling = 1;
    assert!(matches!(
        bounded::activation(&request, &constants, &policy, 16, &mut b),
        Err(bounded::Error::Refused(bounded::Refusal::TargetNotCertifiable))
    ));
    assert!(session.evaluate(&request).is_ok());
}

/// Claim: The elementary plan preserves exact zeros and endpoint width contracts, refuses domain, subnormal, non-dyadic and finite-target failures, and bounds roots and dyadic powers by exact squared comparisons.
/// ´claim:numerics:bounded-elementary-plans-retain-contracts´
/// ´test:integration:bounded-elementary-contracts´
#[test]
fn bounded_elementary_contracts() {
    let p = procedure(16);
    let mut b = Budget::new(p.enclosure.as_ref().unwrap().operation.clone()).unwrap();
    let zero = interval("0", "0", &mut b);
    for minus_one in [true, false] {
        let v = bounded::exponential(&zero, 16, 48, 64, minus_one, &mut b).unwrap();
        assert_eq!(
            v,
            interval(if minus_one { "0" } else { "1" }, if minus_one { "0" } else { "1" }, &mut b)
        );
    }
    assert_eq!(bounded::tanh(&zero, 16, 48, 64, &mut b).unwrap(), zero);
    for x in ["-1", "-2", "-1/1024", "-3/2"] {
        let value = interval(x, x, &mut b);
        for relative in [false, true] {
            let got = bounded::exponential(&value, 16, 48, 64, relative, &mut b).unwrap();
            let mut nodes = vec![Node::Coordinate(0), Node::Exponential(0)];
            let target_node = if relative {
                nodes.extend([Node::Rational("1".into()), Node::Subtract(1, 2)]);
                3
            } else {
                1
            };
            let query = Query {
                coordinates: vec![Range {
                    lower: x.into(),
                    upper: x.into(),
                }],
                nodes,
                target: target_node,
                goal: Goal::Width,
            };
            let certified = pn_graph::numeric::evaluate(&procedure(48), &query, None).unwrap();
            assert!(certified.resource_fault.is_none());
            assert!(
                got.contains(certified.bounds.as_ref().unwrap(), &mut b).unwrap(),
                "{x} expm1={relative}"
            );
            let mut target = Rational::parse("1/65536", &mut b).unwrap();
            if relative {
                target = target.mul(&got.upper().negated(&mut b).unwrap(), &mut b).unwrap();
            }
            assert!(!got.width(&mut b).unwrap().compare(&target, &mut b).unwrap().is_gt());
        }
    }
    roots(&mut b);
    transforms(&mut b);
    refusals(&mut b);
}
fn transforms(b: &mut Budget) {
    for x in ["1", "0", "1/1024", "1/2"] {
        let value = interval(x, x, b);
        for hyperbolic in [true, false] {
            let got = if hyperbolic {
                bounded::tanh(&value, 16, 48, 64, b)
            } else {
                bounded::sigmoid(&value, 16, 48, 64, b)
            }
            .unwrap();
            let query = Query {
                coordinates: vec![Range {
                    lower: x.into(),
                    upper: x.into(),
                }],
                nodes: vec![Node::Coordinate(0), if hyperbolic { Node::Tanh(0) } else { Node::Sigmoid(0) }],
                target: 1,
                goal: Goal::Width,
            };
            let certified = pn_graph::numeric::evaluate(&procedure(48), &query, None).unwrap();
            assert!(certified.resource_fault.is_none());
            assert!(
                got.contains(certified.bounds.as_ref().unwrap(), b).unwrap(),
                "{x} tanh={hyperbolic}"
            );
            let mut target = Rational::parse("1/65536", b).unwrap();
            if hyperbolic {
                target = target.mul(got.lower(), b).unwrap();
            }
            assert!(!got.width(b).unwrap().compare(&target, b).unwrap().is_gt());
        }
    }
}
fn roots(b: &mut Budget) {
    for x in ["2", "65537/65536", "1/1024"] {
        let value = interval(x, x, b);
        let root = bounded::square_root(&value, 32, b).unwrap();
        assert!(
            !root
                .lower()
                .mul(root.lower(), b)
                .unwrap()
                .compare(value.lower(), b)
                .unwrap()
                .is_gt()
        );
        assert!(
            !root
                .upper()
                .mul(root.upper(), b)
                .unwrap()
                .compare(value.upper(), b)
                .unwrap()
                .is_lt()
        );
        let power = bounded::power(&value, &Rational::parse("1/4", b).unwrap(), 32, b).unwrap();
        assert!(!power.lower().pow(4, b).unwrap().compare(value.lower(), b).unwrap().is_gt());
        assert!(!power.upper().pow(4, b).unwrap().compare(value.upper(), b).unwrap().is_lt());
        let reciprocal = bounded::power(&value, &Rational::parse("-1/4", b).unwrap(), 32, b).unwrap();
        let one = Rational::parse("1", b).unwrap();
        assert!(
            !reciprocal
                .lower()
                .pow(4, b)
                .unwrap()
                .mul(value.lower(), b)
                .unwrap()
                .compare(&one, b)
                .unwrap()
                .is_gt()
        );
        assert!(
            !reciprocal
                .upper()
                .pow(4, b)
                .unwrap()
                .mul(value.upper(), b)
                .unwrap()
                .compare(&one, b)
                .unwrap()
                .is_lt()
        );
    }
}
fn refusals(b: &mut Budget) {
    let negative = interval("-3", "-3", b);
    assert!(matches!(
        bounded::exponential(&negative, 16, 48, 64, false, b),
        Err(bounded::Error::Refused(bounded::Refusal::OutsideDomain))
    ));
    let one = interval("1", "1", b);
    assert!(matches!(
        bounded::power(&one, &Rational::parse("1/3", b).unwrap(), 32, b),
        Err(bounded::Error::Refused(bounded::Refusal::NonDyadicExponent))
    ));
    let negative = interval("-1", "-1", b);
    assert!(matches!(
        bounded::exponential(&negative, 16, 48, 1, false, b),
        Err(bounded::Error::Refused(bounded::Refusal::TargetNotCertifiable))
    ));
    let chunk = Rational::parse("2", b).unwrap().pow(-128, b).unwrap();
    let mut tiny = chunk.clone();
    for _ in 0..7 {
        tiny = tiny.mul(&chunk, b).unwrap();
    }
    let tiny = Interval::singleton(&tiny.negated(b).unwrap(), b).unwrap();
    assert!(matches!(
        bounded::exponential(&tiny, 16, 48, 64, false, b),
        Err(bounded::Error::Refused(bounded::Refusal::BelowNormalOperand))
    ));
    let mut exhausted = Budget::new(nrz_cas::limits::Limits {
        work: 1,
        ..nrz_cas::limits::Limits::default()
    })
    .unwrap();
    assert!(matches!(
        bounded::exponential(&negative, 16, 48, 64, false, &mut exhausted),
        Err(bounded::Error::Arithmetic(nrz_cas::Fault {
            kind: nrz_cas::FaultKind::Exhausted {
                budget: nrz_cas::limits::BudgetKind::Work,
                ..
            },
            ..
        }))
    ));
}
