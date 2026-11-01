#[path = "../../documents/src/pins.rs"]
pub mod pins;
use pins::NumberId;

#[path = "numeric/corpus.rs"]
mod corpus;

use nrz_cas::{enclosure::RefinementPolicy, limits::Limits};
use pn_graph::numeric::{Error, evaluate, preflight, replay};
use pn_records::{
    DeclarationId,
    primitive::{EnclosurePolicy, Goal, Node, Outcome, Query, Range},
    solve::{Equality, Precision, Primitive, Procedure},
};
use std::collections::BTreeSet;

fn wall_floor_rational() -> String {
    pins::DesignConstantId::EpochWallFloorRational.value().to_owned()
}

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
        maximum_solve_work: limits.work,
        maximum_replay_work: limits.work,
        maximum_iterations: 2,
        endpoint_grid: "1/64".into(),
        fence: None,
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

fn wall_policy() -> Procedure {
    let mut p = activation_policy();
    p.precision = Precision::AbsoluteWidthBits(vec![8, 16, 24]);
    p.maximum_work = NumberId::NumbersReferenceWorkCeiling.integer();
    p.maximum_iterations = 64;
    let policy = p.enclosure.as_mut().unwrap();
    policy.operation.work = p.maximum_work;
    policy.store.work = p.maximum_work;
    policy.operation.arithmetic_steps = 100_000_000;
    policy.store.arithmetic_steps = 100_000_000;
    policy.refinement.precision = 8;
    policy.refinement.reduction_ceiling = 2;
    policy.refinement.checking_work = 0;
    p
}

fn wall_input() -> pn_records::wall::Inputs {
    pn_records::wall::Inputs {
        width: "1".into(),
        cumulative_tilt: "15/8".into(),
        bracket: range("1/2", "1"),
        stopping_width: "1/128".into(),
        maximum_steps: 64,
        maximum_work: NumberId::NumbersReferenceWorkCeiling.integer(),
        maximum_replay_work: NumberId::NumbersReferenceWorkCeiling.integer(),
        floor: pn_records::wall::Floor::Rational,
        previous: pn_records::wall::Previous::Target,
        door: "1".into(),
        absolute_cap: "1/10".into(),
        relative_cap: "1/4".into(),
        deadband: "1/20".into(),
    }
}

fn verification_policy() -> Procedure {
    let mut p = wall_policy();
    p.precision = Precision::AbsoluteWidthBits(vec![16]);
    p.maximum_work = NumberId::NumbersVerificationTrialWorkCeiling.integer();
    let policy = p.enclosure.as_mut().unwrap();
    policy.refinement.precision = 16;
    policy.operation.work = p.maximum_work;
    policy.operation.arithmetic_steps = 1_000_000_000;
    policy.operation.literal_bytes = 4096;
    policy.operation.output_bytes = 32 * 1024 * 1024;
    policy.store = policy.operation.clone();
    p
}

fn verification_reference() -> pn_records::conserved::VerificationInput {
    use NumberId as N;
    use pn_records::conserved::{VerificationEdge, VerificationInput, VerificationSource};
    VerificationInput {
        sources: [
            (
                "carol",
                N::NumbersPublishedCarolCount,
                N::NumbersPublishedCarolIntercept,
                N::NumbersPublishedCarolSlope,
            ),
            (
                "alice",
                N::NumbersPublishedAliceCount,
                N::NumbersPublishedAliceIntercept,
                N::NumbersPublishedAliceSlope,
            ),
            (
                "eve",
                N::NumbersPublishedEveCount,
                N::NumbersPublishedEveIntercept,
                N::NumbersPublishedEveSlope,
            ),
            (
                "bob",
                N::NumbersPublishedBobCount,
                N::NumbersPublishedBobIntercept,
                N::NumbersPublishedBobSlope,
            ),
            (
                "dave",
                N::NumbersPublishedDaveCount,
                N::NumbersPublishedDaveIntercept,
                N::NumbersPublishedDaveSlope,
            ),
        ]
        .into_iter()
        .map(|(name, count, intercept, slope)| VerificationSource {
            name: name.into(),
            count: count.value().into(),
            intercept: intercept.value().into(),
            slope: slope.value().into(),
        })
        .collect(),
        edges: [
            ("carol", "eve", N::NumbersPublishedVouchCarolEveRadicand),
            ("alice", "bob", N::NumbersPublishedVouchAliceBobRadicand),
            ("bob", "dave", N::NumbersPublishedVouchBobDaveRadicand),
            ("dave", "eve", N::NumbersPublishedVouchDaveEveRadicand),
            ("alice", "carol", N::NumbersPublishedVouchAliceCarolRadicand),
            ("carol", "dave", N::NumbersPublishedVouchCarolDaveRadicand),
            ("bob", "carol", N::NumbersPublishedVouchBobCarolRadicand),
            ("alice", "eve", N::NumbersPublishedVouchAliceEveRadicand),
            ("bob", "eve", N::NumbersPublishedVouchBobEveRadicand),
        ]
        .into_iter()
        .map(|(source, target, radicand)| VerificationEdge {
            source: source.into(),
            target: target.into(),
            radicand: radicand.value().into(),
        })
        .collect(),
        wall: range(N::NumbersReferenceWallLower.value(), N::NumbersReferenceWallUpper.value()),
        shape: [
            N::NumbersPublishedShapeFirst,
            N::NumbersPublishedShapeSecond,
            N::NumbersPublishedShapeThird,
            N::NumbersPublishedShapeFourth,
        ]
        .map(|id| id.value().to_owned())
        .to_vec(),
        depth_mass: [
            N::NumbersPublishedMassFirst,
            N::NumbersPublishedMassSecond,
            N::NumbersPublishedMassThird,
            N::NumbersPublishedMassFourth,
        ]
        .map(|id| id.value().to_owned())
        .to_vec(),
        retention: N::NumbersPublishedRetention.value().into(),
        strength: "1".into(),
        endpoint_bits: u32::try_from(N::NumbersVerificationCompositionBits.integer()).unwrap(),
    }
}

/// Claim: The separately declared five-Actor reference map checks its lower-wall fence, carries affine source-rate uncertainty and the independent wall through two complete box evaluations, and independently replays both maps and the image-first residual radius. The finite witness does not compare unpublished corpus figures.
/// ´claim:numerics:two-map-reference-keeps-box-and-residual-evidence´
/// ´test:integration:verification-box´
#[test]
fn verification_box() {
    use pn_graph::numeric::verification;
    let p = verification_policy();
    let input = verification_reference();
    let candidate = vec![range("11/10", "11/10"); 5];
    let result = verification::two_map(&p, &input, &candidate).unwrap();
    let checked = verification::replay_two_map(&p, &input, &candidate, &result).unwrap();
    assert_eq!(result.enclosure, checked.enclosure);
    let mut changed_support = result.first.clone();
    changed_support.support[0].clear();
    assert!(verification::replay_box(&p, &input, &candidate, &changed_support).is_err());
    assert_eq!(
        (
            result.first.work,
            result.second.work,
            result.one_map_radius.as_str(),
            result.radius.as_str()
        ),
        (
            NumberId::NumbersReferencePointMapWork.integer(),
            NumberId::NumbersReferenceBoxMapWork.integer(),
            NumberId::NumbersReferenceOneMapRadius.value(),
            NumberId::NumbersReferenceImageFirstRadius.value()
        )
    );
    let wall = pn_graph::numeric::wall::evaluate(&wall_policy(), &wall_input()).unwrap();
    assert_eq!(wall.target.as_ref(), Some(&input.wall));
    for cap in [
        NumberId::NumbersReferenceBoxMapWork.integer() - 1,
        NumberId::NumbersReferenceBoxMapWork.integer(),
    ] {
        let mut limited = p.clone();
        limited.maximum_work = cap;
        limited.enclosure.as_mut().unwrap().operation.work = cap;
        let actual = verification::evaluate_box(&limited, &input, &result.first.image);
        assert_eq!(actual.is_ok(), cap == NumberId::NumbersReferenceBoxMapWork.integer());
    }
    for mutation in [1, 0] {
        let mut changed = result.clone();
        if mutation == 0 {
            changed.second.coordinates[0].upper = "2".into();
        } else {
            changed.radius = "0".into();
        }
        assert!(verification::replay_two_map(&p, &input, &candidate, &changed).is_err());
    }
}

/// Claim: On the tagged reference fixture, the certified two-map residual enclosure contains every published slack-free equilibrium interval. The wall is contained, the fence and active local root intervals intersect, and computed full-strength fence and inclusion verdicts agree with the published verdicts. Both global contraction bounds are below one. Method-specific bounds retain separate scopes; this finite witness establishes neither arbitrary-input coverage nor certificate authentication.
/// ´claim:certificate:certified-residuals-enclose-the-selected-solution´
/// ´test:integration:verification-corpus´
#[test]
fn verification_corpus() {
    use pn_graph::numeric::verification;
    let p = verification_policy();
    let input = verification_reference();
    let coordinate = NumberId::NumbersReferenceCandidateCoordinate.value();
    let candidate = vec![range(coordinate, coordinate); input.sources.len()];
    corpus::declaration_controls(&input);
    let residual = verification::two_map(&p, &input, &candidate).unwrap();
    let declaration = pn_records::conserved::LocalDeclaration {
        inflation: NumberId::NumbersLocalInflation.value().into(),
        padding: NumberId::NumbersLocalBoxRadius.value().into(),
        maximum_work: NumberId::NumbersLocalCheckWork.integer(),
    };
    let local = verification::local_check(&p, &input, &candidate, &residual, &declaration).unwrap();
    corpus::check(&residual, &local);
}

fn touching_declaration(
    p: &Procedure,
    input: &pn_records::conserved::VerificationInput,
    result: &pn_records::conserved::LocalRecord,
) -> pn_records::conserved::LocalDeclaration {
    use nrz_cas::{Rational, limits::Budget};
    let mut budget = Budget::new(p.enclosure.as_ref().unwrap().operation.clone()).unwrap();
    let mut minimum = Rational::parse(&result.center[result.active[0]].lower, &mut budget).unwrap();
    for i in &result.active {
        let point = Rational::parse(&result.center[*i].lower, &mut budget).unwrap();
        if point.compare(&minimum, &mut budget).unwrap().is_lt() {
            minimum = point;
        }
    }
    let wall = Rational::parse(&input.wall.upper, &mut budget).unwrap();
    let old_padding = Rational::parse(&result.declaration.padding, &mut budget).unwrap();
    let radius = Rational::parse(&result.inflation_radius, &mut budget).unwrap();
    let base = radius.sub(&old_padding, &mut budget).unwrap();
    let padding = minimum
        .sub(&wall, &mut budget)
        .unwrap()
        .sub(&base, &mut budget)
        .unwrap()
        .exact_string(&mut budget)
        .unwrap();
    pn_records::conserved::LocalDeclaration {
        padding,
        maximum_work: p.enclosure.as_ref().unwrap().operation.work,
        ..result.declaration.clone()
    }
}

/// Claim: The unsorted reference declaration independently replays its image-first residual and a separate interval-forward local inclusion. An unnormalized depth mass, changed asserted coordinate, preconditioner or box refuses; a wall-touching inflation retains generalized scalar derivatives and no local inclusion verdict.
/// ´claim:numerics:local-inclusion-retains-generalized-derivatives´
/// ´test:integration:verification-local´
#[test]
fn verification_local() {
    use pn_graph::numeric::verification;
    use pn_records::conserved::{LocalDeclaration, LocalVerdict};
    let p = verification_policy();
    let input = verification_reference();
    let candidate = vec![range("11/10", "11/10"); 5];
    let residual = verification::two_map(&p, &input, &candidate).unwrap();
    let declaration = LocalDeclaration {
        inflation: "2".into(),
        padding: "1/1024".into(),
        maximum_work: NumberId::NumbersLocalCheckWork.integer(),
    };
    let result = verification::local_check(&p, &input, &candidate, &residual, &declaration).unwrap();
    assert_eq!(
        result.verdict,
        LocalVerdict::Included,
        "norm={} radius={} inflation={}",
        result.jacobian_norm,
        result.image_radius,
        result.inflation_radius
    );
    assert_eq!(
        (
            result.work,
            result.inflation_radius.as_str(),
            result.image_radius.as_str(),
            result.jacobian_norm.as_str()
        ),
        (
            NumberId::NumbersLocalCheckWork.integer(),
            NumberId::NumbersLocalReferenceResidualRadius.value(),
            NumberId::NumbersLocalImageRadiusUpper.value(),
            NumberId::NumbersLocalJacobianNormUpper.value()
        )
    );
    for cap in [
        NumberId::NumbersLocalCheckWork.integer(),
        NumberId::NumbersLocalCheckWork.integer() - 1,
    ] {
        let limited = LocalDeclaration {
            maximum_work: cap,
            ..declaration.clone()
        };
        assert_eq!(
            verification::local_check(&p, &input, &candidate, &residual, &limited).is_ok(),
            cap == NumberId::NumbersLocalCheckWork.integer()
        );
    }
    let replayed = verification::replay_local(&p, &input, &candidate, &residual, &declaration, &result).unwrap();
    assert_eq!(replayed.asserted, result.asserted);
    assert!(replayed.work <= declaration.maximum_work);
    for mutation in [2, 0, 1] {
        let mut changed = result.clone();
        match mutation {
            0 => changed.preconditioner[0][0] = "2".into(),
            1 => changed.domain[0].upper = "2".into(),
            _ => changed.asserted[0].upper = "2".into(),
        }
        assert!(verification::replay_local(&p, &input, &candidate, &residual, &declaration, &changed).is_err());
    }
    let mut changed = input.clone();
    changed.depth_mass[0] = "1".into();
    assert!(verification::evaluate_box(&p, &changed, &candidate).is_err());
    assert!(verification::local_check(&p, &changed, &candidate, &residual, &declaration).is_err());
    let touching = touching_declaration(&p, &input, &result);
    let result = verification::local_check(&p, &input, &candidate, &residual, &touching).unwrap();
    assert!(result.domain.iter().any(|v| v.lower == input.wall.upper));
    assert!(!result.above_wall);
    assert_eq!(result.verdict, LocalVerdict::Unresolved);
    let derivatives: Vec<_> = result
        .primitives
        .iter()
        .filter(|r| matches!(r.query.nodes[r.query.target], Node::GeneralizedDerivative(_, _)))
        .collect();
    assert_eq!(derivatives.len(), 16);
    assert!(derivatives.iter().any(|r| {
        let bounds = r.evidence.bounds.as_ref().unwrap();
        r.query.coordinates[0].lower == input.wall.upper
            && (bounds.lower().is_zero() || bounds.lower().is_negative())
            && !bounds.upper().is_negative()
            && r.evidence
                .attachment
                .as_ref()
                .unwrap()
                .schemas
                .iter()
                .any(|s| s.name == "enclosure.clamp-generalized")
    }));
    assert!(
        result
            .primitives
            .iter()
            .filter(|r| r.query.nodes.iter().any(|n| matches!(n, Node::Clamp(_, _))))
            .all(|r| !r.query.nodes.iter().any(|n| matches!(n, Node::Derivative(_, _))))
    );
}

/// Claim: Three unsorted widths produce reference target enclosures with independently separated gain-equation endpoint signs; the target identity holds the previous wall and replay checks the same defining inputs.
/// ´claim:numerics:reference-wall-encloses-independent-gain-root´
/// ´test:integration:reference-wall-oracle´
#[test]
fn reference_wall_oracle() {
    use pn_graph::numeric::wall;
    use pn_records::wall::Verdict;
    let p = wall_policy();
    for width in ["3/2", "1", "2"] {
        let mut input = wall_input();
        input.width = width.into();
        let record = wall::evaluate(&p, &input).unwrap();
        assert!(!record.indecisive, "{record:?}");
        let target = record.target.as_ref().unwrap();
        let required = Q(16, 75).div(Q::parse(width));
        let left = independent_activation(Q::parse(&target.lower), false, true);
        let right = independent_activation(Q::parse(&target.upper), false, true);
        assert!(!left.0.le(required));
        assert!(!required.le(right.1));
        assert!(Q::parse(&target.upper).add(Q::parse(&target.lower).neg()).le(Q(1, 128)));
        assert_eq!(record.bisections, 6);
        let branches = record.branches.as_ref().unwrap();
        assert!(!branches.floor_binding);
        assert!(branches.deadband_hold);
        assert_eq!(branches.above_floor, Verdict::Pass);
        assert_eq!(branches.policy_valid, Verdict::Pass);
        assert_eq!(&branches.delivered, target);
        assert_eq!(wall::replay(&p, &input, &record).unwrap().target, record.target);
        if width == "1" {
            input.floor = pn_records::wall::Floor::Ridge;
            let ridge = wall::evaluate(&p, &input).unwrap();
            assert_eq!(ridge.target, record.target);
            assert_eq!(ridge.branches, record.branches);
            assert_eq!(wall::replay(&p, &input, &ridge).unwrap().target, ridge.target);
        }
    }
}

/// Claim: Seven unsorted reference stopping widths have literal cumulative Work boundaries at N and N minus one; ordered query and bisection charges accompany the six-step enclosure at width 1/128.
/// ´claim:numerics:reference-wall-retains-measured-work´
/// ´test:integration:reference-wall-work´
#[test]
fn reference_wall_work() {
    let p = wall_policy();
    let queries = [
        NumberId::NumbersReferenceLowerSignWork.integer(),
        NumberId::NumbersReferenceUpperSignWork.integer(),
        19_865_237,
        20_282_653,
        20_005_822,
        20_076_095,
        20_290_890,
        20_464_969,
    ];
    let bisections = [
        NumberId::NumbersReferenceBisectionFirstWork.integer(),
        NumberId::NumbersReferenceBisectionSecondWork.integer(),
        NumberId::NumbersReferenceBisectionThirdWork.integer(),
        NumberId::NumbersReferenceBisectionFourthWork.integer(),
        NumberId::NumbersReferenceBisectionFifthWork.integer(),
        NumberId::NumbersReferenceBisectionSixthWork.integer(),
    ];
    for (width, count, work) in [
        ("1/16", 3, NumberId::NumbersReferenceSixteenthPrefixWork.integer()),
        ("1/2", 0, NumberId::NumbersReferenceHalfPrefixWork.integer()),
        ("1/128", 6, NumberId::NumbersReferenceProductionWork.integer()),
        ("1/4", 1, NumberId::NumbersReferenceQuarterPrefixWork.integer()),
        ("1/32", 4, NumberId::NumbersReferenceThirtySecondPrefixWork.integer()),
        ("1/8", 2, NumberId::NumbersReferenceEighthPrefixWork.integer()),
        ("1/64", 5, NumberId::NumbersReferenceSixtyFourthPrefixWork.integer()),
    ] {
        let mut input = wall_input();
        input.stopping_width = width.into();
        input.maximum_work = work;
        let record = pn_graph::numeric::wall::evaluate(&p, &input).unwrap();
        assert_eq!(record.work, work);
        assert_eq!(record.bisections, count);
        assert_eq!(
            record.steps.iter().map(|s| s.work).collect::<Vec<_>>(),
            queries[..record.steps.len()]
        );
        assert!(record.steps.iter().all(|s| s.primitive.precision == 8));
        assert_eq!(record.bisection_work, bisections[..record.bisection_work.len()]);
        input.maximum_work = work - 1;
        let result = pn_graph::numeric::wall::evaluate(&p, &input);
        assert!(result.is_err(), "{width} cap={}: {result:?}", work - 1);
        if count == 6 {
            assert_eq!(record.target, Some(range("1/2", "65/128")));
        }
    }
}

/// Claim: Wrong-sign brackets and unsupported lower endpoints refuse; an unresolved declared sign stops without bisection, and replay distinguishes a changed query from a changed attachment.
/// ´claim:numerics:reference-wall-refuses-unproved-signs-and-replay-changes´
/// ´test:integration:reference-wall-controls´
#[test]
fn reference_wall_controls() {
    use pn_graph::numeric::wall::{self, Error};
    let p = wall_policy();
    let input = wall_input();
    let mut wrong = input.clone();
    wrong.bracket = range("1", "2");
    assert_eq!(wall::evaluate(&p, &wrong), Err(Error::Bracket));
    wrong.bracket = range("1/2", "513/1024");
    assert_eq!(wall::evaluate(&p, &wrong), Err(Error::Bracket));
    wrong.bracket = range("1/4", "1");
    assert_eq!(wall::evaluate(&p, &wrong), Err(Error::Binding));
    let mut coarse = p.clone();
    coarse.precision = Precision::AbsoluteWidthBits(vec![1, 2]);
    coarse.enclosure.as_mut().unwrap().refinement.precision = 1;
    let stopped = wall::evaluate(&coarse, &input).unwrap();
    assert!(stopped.indecisive);
    assert_eq!(stopped.bisections, 0);
    assert!(stopped.target.is_none() && stopped.branches.is_none());
    assert_eq!(
        stopped.steps.iter().map(|s| s.primitive.precision).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(stopped.steps.iter().all(|s| s.sign == pn_records::wall::Sign::Indecisive));
    assert!(wall::replay(&coarse, &input, &stopped).unwrap().indecisive);
    coarse.precision = Precision::AbsoluteWidthBits(vec![1, 8]);
    let refined = wall::evaluate(&coarse, &input).unwrap();
    assert!(!refined.indecisive);
    assert_eq!(refined.steps[0].primitive.precision, 1);
    assert_eq!(refined.steps[1].primitive.precision, 8);
    let record = wall::evaluate(&p, &input).unwrap();
    let mut unresolved = input.clone();
    unresolved.door.clone_from(&record.target.as_ref().unwrap().lower);
    let unresolved = wall::evaluate(&p, &unresolved).unwrap();
    assert!(unresolved.indecisive);
    assert_eq!(
        unresolved.branches.unwrap().participation,
        pn_records::wall::Participation::Indecisive
    );
    let mut changed = record.clone();
    changed.steps[0].primitive.query.coordinates[0].lower = "3/4".into();
    assert_eq!(wall::replay(&p, &input, &changed), Err(Error::Query));
    changed = record.clone();
    changed.steps[0].primitive.evidence.attachment = record.steps.last().unwrap().primitive.evidence.attachment.clone();
    assert_eq!(wall::replay(&p, &input, &changed), Err(Error::Attachment));
}

/// Claim: Four unsorted rational previous walls exercise zero-width floor proposals, deadband equality, capped and uncapped moves without scalar requests; two doors distinguish valid and invalid policy branches. A positive-width inverse target is certified below the rational floor, while the ridge declaration in that range refuses without its defining object.
/// ´claim:numerics:reference-wall-certifies-floor-deadband-and-policy´
/// ´test:integration:reference-wall-branches´
#[test]
fn reference_wall_branches() {
    use pn_graph::numeric::wall;
    use pn_records::wall::{Previous, Verdict};
    let p = wall_policy();
    let floor = wall_floor_rational();
    for (previous, deadband, hold, capped, delivered) in [
        ("1", "0", false, true, "3/4"),
        (floor.as_str(), "0", true, false, floor.as_str()),
        ("1/10", "0", false, false, floor.as_str()),
        ("6/37", "1/2", true, false, "6/37"),
    ] {
        for (door, valid) in [("1", Verdict::Pass), ("1/100", Verdict::Fail)] {
            let mut input = wall_input();
            input.width = "0".into();
            input.previous = Previous::Rational(previous.into());
            input.absolute_cap = "1/4".into();
            input.relative_cap = "1/2".into();
            input.deadband = deadband.into();
            input.door = door.into();
            let record = wall::evaluate(&p, &input).unwrap();
            assert!(record.steps.is_empty() && record.target.is_none());
            let branch = record.branches.as_ref().unwrap();
            assert!(branch.floor_binding);
            assert_eq!((branch.deadband_hold, branch.step_capped), (hold, capped));
            assert_eq!(branch.delivered, range(delivered, delivered));
            assert_eq!(branch.above_floor, Verdict::Pass);
            assert_eq!(branch.policy_valid, valid);
            assert_eq!(
                branch.participation,
                if valid == Verdict::Pass {
                    pn_records::wall::Participation::Door
                } else {
                    pn_records::wall::Participation::Wall
                }
            );
            assert_eq!(wall::replay(&p, &input, &record).unwrap(), record);
        }
    }
    reference_floor_binding();
}

fn reference_floor_binding() {
    use pn_graph::numeric::wall::{self, Error};
    use pn_records::wall::{Floor, Previous};
    let mut p = wall_policy();
    p.enclosure.as_mut().unwrap().refinement.reduction_ceiling = 5;
    let mut input = wall_input();
    input.width = "1/8".into();
    input.bracket = range("1/16", "1/8");
    input.previous = Previous::Rational(wall_floor_rational());
    let record = wall::evaluate(&p, &input).unwrap();
    assert!(!record.indecisive);
    let target = record.target.as_ref().unwrap();
    assert!(Q::parse(&target.upper).le(Q::parse(&wall_floor_rational())));
    let required = Q(128, 75);
    assert!(!independent_activation(Q::parse(&target.lower), false, true).0.le(required));
    assert!(!required.le(independent_activation(Q::parse(&target.upper), false, true).1));
    let branches = record.branches.as_ref().unwrap();
    assert!(branches.floor_binding && branches.deadband_hold);
    assert_eq!(branches.delivered, range(&wall_floor_rational(), &wall_floor_rational()));
    assert_eq!(wall::replay(&p, &input, &record).unwrap().branches, record.branches);
    input.floor = Floor::Ridge;
    assert_eq!(wall::evaluate(&p, &input), Err(Error::Ridge));
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
    let construction_stop = evaluate(&bounded, &input, None).unwrap();
    assert_eq!(construction_stop.outcome, Outcome::Exhausted);
    assert!(construction_stop.work <= 1 && construction_stop.bounds.is_none());
    assert!(construction_stop.resource_fault.is_some());
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

/// Claim: Four unsorted standing boxes with an independent wall interval contain independently computed activation brackets at three rational walls; crossing generalized gains retain zero and responsive slopes, the bare clamp has slope interval zero to one, smooth differentiation refuses, and changed wall evidence and unsupported lower endpoints refuse.
/// ´claim:numerics:enclosed-wall-clamp-retains-independent-coordinate´
/// ´test:integration:enclosed-wall-clamp´
#[test]
fn enclosed_wall_clamp() {
    use pn_graph::numeric::activation::{self, Quantity};
    let mut p = wall_policy();
    p.precision = Precision::AbsoluteWidthBits(vec![4]);
    p.enclosure.as_mut().unwrap().refinement.precision = 4;
    for (a, z) in [("3/4", "1"), ("1/4", "1/2"), ("1/2", "3/4"), ("1/4", "3/4")] {
        let mut input = activation_request(a, Quantity::Clamped);
        input.standing = range(a, z);
        input.wall_enclosure = Some(range("1/2", "65/128"));
        let result = activation::evaluate(&p, &input, None).unwrap();
        let (lower, upper) = endpoints(&result.primitive.evidence);
        assert_eq!(result.primitive.query.coordinates[1], range("1/2", "65/128"));
        let mut session = activation::sharing::Session::new(&p, "1/400").unwrap();
        let index = session.evaluate(&input).unwrap();
        let shared = session.evidence(index).unwrap();
        assert_eq!(shared.primitive.query.coordinates[3], range("1/2", "65/128"));
        assert!(shared.primitive.query.nodes.iter().any(|node| matches!(node,
            Node::Clamp(0, wall) if shared.primitive.query.nodes[*wall] == Node::Coordinate(3)
        )));
        let (shared_lower, shared_upper) = endpoints(&shared.primitive.evidence);
        for wall in ["65/128", "1/2", "129/256"] {
            let wall = Q::parse(wall);
            let lo = if Q::parse(a).le(wall) { wall } else { Q::parse(a) };
            let hi = if Q::parse(z).le(wall) { wall } else { Q::parse(z) };
            assert!(lower.le(independent_activation(lo, false, false).0));
            assert!(independent_activation(hi, false, false).1.le(upper));
            assert!(shared_lower.le(independent_activation(lo, false, false).0));
            assert!(independent_activation(hi, false, false).1.le(shared_upper));
        }
        activation::replay(&p, &input, result.primitive.evidence.attachment.as_ref().unwrap(), None).unwrap();
        let mut changed = input.clone();
        changed.wall_enclosure.as_mut().unwrap().upper = "3/4".into();
        assert!(activation::replay(&p, &changed, result.primitive.evidence.attachment.as_ref().unwrap(), None).is_err());
        input.quantity = Quantity::GeneralizedLogGain;
        let slopes = activation::evaluate(&p, &input, None).unwrap();
        let (lo, hi) = endpoints(&slopes.primitive.evidence);
        if z == "3/4" {
            assert!(lo.le(Q(0, 1)));
            assert!(independent_activation(Q(1, 2), false, true).1.le(hi));
        }
        input.wall_enclosure.as_mut().unwrap().lower = "1/4".into();
        assert!(activation::evaluate(&p, &input, None).is_err());
    }
    enclosed_floor_slope(&p);
}

fn enclosed_floor_slope(p: &Procedure) {
    let mut q = Query {
        coordinates: vec![range("1/4", "3/4"), range("1/2", "65/128")],
        nodes: vec![
            Node::Coordinate(0),
            Node::Coordinate(1),
            Node::Clamp(0, 1),
            Node::GeneralizedDerivative(2, 0),
        ],
        target: 3,
        goal: Goal::Width,
    };
    let result = evaluate(p, &q, None).unwrap();
    assert_eq!(endpoints(&result), (Q(0, 1), Q(1, 1)));
    replay(p, &q, result.attachment.as_ref().unwrap(), None).unwrap();
    q.nodes[3] = Node::Derivative(2, 0);
    let result = evaluate(p, &q, None).unwrap();
    assert_eq!(result.outcome, Outcome::Unsupported);
}

fn activation_request(text: &str, quantity: pn_graph::numeric::activation::Quantity) -> pn_graph::numeric::activation::Request {
    pn_graph::numeric::activation::Request {
        standing: range(text, text),
        bleed_squared: "1/400".into(),
        wall: None,
        wall_enclosure: None,
        quantity,
    }
}

fn activation_policy() -> Procedure {
    let mut p = procedure();
    p.maximum_work = NumberId::NumbersEvaluationWorkCeiling.integer();
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
        (20_986_736, 20_955_085, 558_565, 7_015, 1_791_495),
        (
            NumberId::NumbersQuarterPowerRequestWork.integer(),
            22_108_551,
            579_066,
            NumberId::NumbersQuarterPowerCertificateBytes
                .value()
                .parse::<usize>()
                .unwrap(),
            NumberId::NumbersQuarterPowerOutputCeilingBytes.integer(),
        ),
        (25_112_350, 25_067_131, 670_962, 7_507, 2_340_998),
        (102_500_767, 102_466_631, 2_044_492, 8_500, 1_891_382),
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
            } else {
                assert!(low.le(independent_activation(Q(3, 1), false, true).0));
                assert!(independent_activation(Q(2, 1), false, true).1.le(high));
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

/// Claim: One declared evaluation checks beta and Q(1) in order, uses their checked boxes as explicit premises and contains independent activation brackets on three unsorted points. Identical requests borrow identical retained evidence with charged lookup; fresh replay checks constants before dependent requests and refuses a changed constant query or dependent argument. Sixty-five exact repeats replay within the same allowance as production; changed repeat queries, precisions and attachments refuse. Replay receivers cannot generate requests, and producers cannot switch into replay.
/// ´claim:numerics:evaluation-sharing-keeps-checked-premises´
/// ´test:integration:evaluation-sharing´
#[test]
fn evaluation_sharing() {
    use pn_graph::numeric::activation::{Quantity, sharing::Session};
    let mut p = cost_policy();
    p.enclosure.as_mut().unwrap().refinement.reduction_ceiling = 2;
    let mut session = Session::new(&p, "1/400").unwrap();
    let premises = session.premises().to_vec();
    let mut swapped = premises.clone();
    swapped.swap(0, 1);
    assert!(Session::from_evidence(&p, "1/400", &swapped).is_err());
    let mut receiver = Session::from_evidence(&p, "1/400", &premises).unwrap();
    for text in ["2", "1/2", "1"] {
        let input = activation_request(text, Quantity::Responsive);
        let index = session.evaluate(&input).unwrap();
        let first = session.evidence(index).unwrap().clone();
        let before = session.work();
        let repeated = session.evaluate(&input).unwrap();
        assert_eq!(repeated, index);
        let repeat = session.evidence(repeated).unwrap().clone();
        assert_eq!(first, repeat);
        assert!(session.work() > before);
        assert!(session.work() - before < first.primitive.evidence.work);
        let (lo, hi) = endpoints(&first.primitive.evidence);
        let oracle = independent_activation(Q::parse(text), false, false);
        assert!(lo.le(oracle.0) && oracle.1.le(hi));
        let checked = receiver.replay(&first).unwrap();
        assert_eq!(checked.evidence.bounds, first.primitive.evidence.bounds);
        let mut changed = first.clone();
        changed.input.standing = range("7", "7");
        let mut negative = Session::from_evidence(&p, "1/400", &premises).unwrap();
        assert!(negative.replay(&changed).is_err());
        assert!(negative.replay(&first).is_err());
    }
    let mut limited = p.clone();
    limited.maximum_work = 20_000_000;
    assert!(Session::from_evidence(&limited, "1/400", &premises).is_err());
    set_cost_limit(&mut limited, 0, 20_000_000);
    let mut limited_source = Session::new(&limited, "1/400").unwrap();
    let index = limited_source
        .evaluate(&activation_request("2", Quantity::Responsive))
        .unwrap();
    for _ in 0..64 {
        assert_eq!(
            limited_source
                .evaluate(&activation_request("2", Quantity::Responsive))
                .unwrap(),
            index
        );
    }
    assert!(limited_source.work() <= limited.maximum_work);
    let mut repeated = Session::from_evidence(&limited, "1/400", limited_source.premises()).unwrap();
    for _ in 0..65 {
        repeated.replay(limited_source.evidence(index).unwrap()).unwrap();
    }
    assert!(repeated.work() <= limited_source.work());
    for mutation in [2, 0, 1] {
        let first = limited_source.evidence(index).unwrap();
        let mut receiver = Session::from_evidence(&limited, "1/400", limited_source.premises()).unwrap();
        receiver.replay(first).unwrap();
        let mut changed = first.clone();
        match mutation {
            0 => changed.primitive.query.target = 0,
            1 => changed.primitive.precision += 1,
            _ => changed.primitive.evidence.attachment = None,
        }
        assert!(receiver.replay(&changed).is_err());
    }
    let mut changed = premises;
    let mut replay_only = Session::from_evidence(&p, "1/400", &changed).unwrap();
    assert!(replay_only.evaluate(&activation_request("1", Quantity::Responsive)).is_err());
    let mut production_only = Session::new(&p, "1/400").unwrap();
    assert!(production_only.replay(session.evidence(0).unwrap()).is_err());
    changed[0].query.nodes[0] = Node::Rational("3".into());
    assert!(Session::from_evidence(&p, "1/400", &changed).is_err());
    let mut other = activation_request("1", Quantity::Responsive);
    other.bleed_squared = "1/100".into();
    assert!(session.evaluate(&other).is_err());
}

fn sharing_prefix(limit: u64, count: usize) -> Result<u64, pn_graph::numeric::Error> {
    use pn_graph::numeric::activation::{Quantity, sharing::Session};
    let mut p = cost_policy();
    p.maximum_work = limit;
    set_cost_limit(&mut p, 0, limit);
    p.enclosure.as_mut().unwrap().refinement.reduction_ceiling = 2;
    let mut session = Session::new(&p, "1/400")?;
    for text in ["1", "1/2", "2", "1"].into_iter().take(count) {
        session.evaluate(&activation_request(text, Quantity::Responsive))?;
    }
    Ok(session.work())
}

fn reduction_boundaries() {
    use pn_graph::numeric::activation;
    let inputs = cost_inputs();
    for (ceiling, works) in [
        (
            3,
            [
                NumberId::NumbersWallGainRequestWork.integer(),
                15_514_999,
                18_011_396,
                64_092_367,
            ],
        ),
        (2, [13_553_427, 12_699_480, 14_778_128, 49_222_716]),
    ] {
        for (input, work) in inputs.iter().zip(works) {
            let mut p = cost_policy();
            p.enclosure.as_mut().unwrap().refinement.reduction_ceiling = ceiling;
            let expected = activation::evaluate(&p, input, None).unwrap().primitive.evidence;
            assert_eq!(expected.work, work);
            for (cap, succeeds) in [(work, true), (work - 1, false)] {
                let mut limited = p.clone();
                set_cost_limit(&mut limited, 0, cap);
                let got = activation::evaluate(&limited, input, None);
                assert_eq!(
                    got.as_ref().is_ok_and(|v| v.primitive.evidence.bounds == expected.bounds
                        && v.primitive.evidence.completed_rounds == expected.completed_rounds
                        && v.primitive.evidence.resource_fault.is_none()),
                    succeeds
                );
            }
        }
    }
}

fn power_boundaries() {
    use pn_graph::numeric::activation::{Quantity, monotone};
    let mut p = cost_policy();
    p.enclosure.as_mut().unwrap().refinement.reduction_ceiling = 2;
    let mut input = activation_request("1", Quantity::Clamped);
    input.wall = Some("1".into());
    let base = monotone::evaluate(&p, &input).unwrap();
    assert_eq!(base.work(), 10_689_380);
    for (cap, succeeds) in [(10_689_380, true), (10_689_379, false)] {
        let mut limited = p.clone();
        set_cost_limit(&mut limited, 0, cap);
        let got = monotone::evaluate(&limited, &input);
        assert_eq!(got.as_ref().is_ok_and(|v| v.bounds() == base.bounds()), succeeds);
    }
    for (exponent, work) in [
        ("1/4", NumberId::NumbersQuarterHopPairWork.integer()),
        ("1/3", NumberId::NumbersThirdHopPairWork.integer()),
    ] {
        let expected = monotone::power(&p, &base, exponent).unwrap();
        assert_eq!(expected.work(), work);
        for (cap, succeeds) in [(work, true), (work - 1, false)] {
            let mut limited = p.clone();
            set_cost_limit(&mut limited, 0, cap);
            let got = monotone::power(&limited, &base, exponent);
            assert_eq!(got.as_ref().is_ok_and(|v| v.bounds() == expected.bounds()), succeeds);
        }
    }
}

fn endpoint_cost_boundaries() {
    use pn_graph::numeric::activation::monotone;
    let inputs = cost_inputs();
    for (ceiling, works) in [(3, [15_861_820, 15_863_749]), (2, [13_556_391, 13_558_320])] {
        for (input, work) in [&inputs[0], &inputs[3]].into_iter().zip(works) {
            let mut p = cost_policy();
            p.enclosure.as_mut().unwrap().refinement.reduction_ceiling = ceiling;
            let expected = monotone::evaluate(&p, input).unwrap();
            assert_eq!(expected.work(), work);
            for (cap, succeeds) in [(work, true), (work - 1, false)] {
                let mut limited = p.clone();
                set_cost_limit(&mut limited, 0, cap);
                let got = monotone::evaluate(&limited, input);
                assert_eq!(got.as_ref().is_ok_and(|v| v.bounds() == expected.bounds()), succeeds);
            }
        }
    }
}

fn sharing_cost_comparison() {
    use pn_graph::numeric::activation::{self, Quantity, monotone, sharing::Session};
    let mut p = cost_policy();
    p.enclosure.as_mut().unwrap().refinement.reduction_ceiling = 2;
    let input = activation_request("1", Quantity::Responsive);
    let direct = activation::evaluate(&p, &input, None).unwrap();
    assert_eq!(
        direct.primitive.evidence.work,
        NumberId::NumbersSecondActivationSessionWork.integer()
    );
    for (cap, succeeds) in [
        (NumberId::NumbersSecondActivationSessionWork.integer(), true),
        (NumberId::NumbersSecondActivationSessionWork.integer() - 1, false),
    ] {
        let mut limited = p.clone();
        set_cost_limit(&mut limited, 0, cap);
        let got = activation::evaluate(&limited, &input, None);
        assert_eq!(
            got.as_ref()
                .is_ok_and(|v| v.primitive.evidence.bounds == direct.primitive.evidence.bounds
                    && v.primitive.evidence.resource_fault.is_none()),
            succeeds
        );
    }
    let mut session = Session::new(&p, "1/400").unwrap();
    let index = session.evaluate(&input).unwrap();
    let shared = session.evidence(index).unwrap().primitive.evidence.bounds.as_ref().unwrap();
    let mut clamped = activation_request("1", Quantity::Clamped);
    clamped.wall = Some("1".into());
    let base = monotone::evaluate(&p, &clamped).unwrap();
    let mut budget = nrz_cas::limits::Budget::new(p.enclosure.as_ref().unwrap().operation.clone()).unwrap();
    assert_eq!(
        shared.lower().exact_string(&mut budget).unwrap(),
        base.bounds().unwrap().lower
    );
    assert_eq!(
        shared.upper().exact_string(&mut budget).unwrap(),
        base.bounds().unwrap().upper
    );
}

/// Claim: The declared reduction ceilings have literal Work boundaries for four compositions each; root-route and log-exp endpoint pairs and every prefix of the constant-sharing and memo schedule succeed at N and cannot complete at N minus one. Session-prefix controls distinguish constant preparation, three distinct requests and a memo hit; they do not isolate query-construction Work from scalar evidence Work.
/// ´claim:numerics:evaluation-policy-has-measured-work-boundaries´
/// ´test:integration:evaluation-costs´
#[test]
fn evaluation_costs() {
    reduction_boundaries();
    power_boundaries();
    endpoint_cost_boundaries();
    sharing_cost_comparison();
    for (count, work) in [
        NumberId::NumbersCertifyingPrefixWork.integer(),
        NumberId::NumbersDirectActivationWork.integer(),
        16_229_668,
        23_651_776,
        23_651_792,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(sharing_prefix(work, count).unwrap(), work);
        assert!(sharing_prefix(work - 1, count).is_err());
    }
}
