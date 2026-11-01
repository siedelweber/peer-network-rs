//! Reference figures produced by the paper's own build at network-v0.31.1.
//! (´[ROOT-rec:design:pending-reference-corpus]´)
use super::NumberId;
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    conserved::{LocalRecord, LocalVerdict, TwoMapRecord},
    primitive::Range,
};

#[derive(Debug, PartialEq, Eq)]
enum PublishedVerdict {
    Pass,
    NotCertified,
}

impl PublishedVerdict {
    fn from_pass(pass: bool) -> Self {
        if pass { Self::Pass } else { Self::NotCertified }
    }
}

fn number(text: &str, budget: &mut Budget) -> Rational {
    Rational::parse(text, budget).unwrap()
}

fn compare(label: &str, paper: &Range, ours: &Range, contain: bool, budget: &mut Budget) {
    let pl = number(&paper.lower, budget);
    let pu = number(&paper.upper, budget);
    let ol = number(&ours.lower, budget);
    let ou = number(&ours.upper, budget);
    assert!(
        !ol.compare(&pu, budget).unwrap().is_gt() && !pl.compare(&ou, budget).unwrap().is_gt(),
        "{label}: paper={paper:?}, ours={ours:?}"
    );
    if contain {
        assert!(
            !ol.compare(&pl, budget).unwrap().is_gt() && !pu.compare(&ou, budget).unwrap().is_gt(),
            "{label}: containment paper={paper:?}, ours={ours:?}"
        );
    }
}

fn inflate(value: &Range, radius: &Rational, budget: &mut Budget) -> Range {
    Range {
        lower: number(&value.lower, budget)
            .sub(radius, budget)
            .unwrap()
            .exact_string(budget)
            .unwrap(),
        upper: number(&value.upper, budget)
            .add(radius, budget)
            .unwrap()
            .exact_string(budget)
            .unwrap(),
    }
}

/// Compare the common mathematical objects, retaining method-specific bounds separately.
/// # Panics
/// Panics only if the declared reference comparison fails or its comparison budget is exhausted.
pub(super) fn check(residual: &TwoMapRecord, local: &LocalRecord) {
    let p = super::verification_policy();
    let mut budget = Budget::new(p.enclosure.unwrap().operation).unwrap();
    let standing_label = "ver:standing:conserved-equilibrium-enclosure";
    let wall = super::range(
        NumberId::NumbersPublishedWallLower.value(),
        NumberId::NumbersPublishedWallUpper.value(),
    );
    compare(
        "ver:floor:fixture-regime",
        &wall,
        &residual.first.input.wall,
        true,
        &mut budget,
    );
    let fence = super::range(
        NumberId::NumbersPublishedFenceLower.value(),
        NumberId::NumbersPublishedFenceUpper.value(),
    );
    // Positivity and strict decrease extend the lower-wall upper bound to
    // the defining wall. This enclosure is not the lower-wall scalar interval.
    let conservative_fence = super::range("0", &residual.first.fence.upper);
    compare(standing_label, &fence, &conservative_fence, false, &mut budget);
    let one = number("1", &mut budget);
    assert!(number(&fence.upper, &mut budget).compare(&one, &mut budget).unwrap().is_lt());
    assert_eq!(residual.first.input.strength, "1");
    // Full strength is the first declared rung, so this passing fence accepts one.
    let published_rung = "1";
    let published_strength = "1";
    let published_fence_verdict = PublishedVerdict::Pass;
    assert_eq!(p.grid.first().map(String::as_str), Some(published_rung));
    assert_eq!(published_rung, residual.first.input.strength);
    assert_eq!(published_strength, residual.first.input.strength);
    assert_eq!(
        published_fence_verdict,
        PublishedVerdict::from_pass(
            number(&conservative_fence.upper, &mut budget)
                .compare(&one, &mut budget)
                .unwrap()
                .is_lt()
        )
    );
    let global = number(super::NumberId::NumbersPublishedGlobalContractionUpper.value(), &mut budget);
    let our_global = number(&residual.first.contraction, &mut budget);
    assert!(global.compare(&one, &mut budget).unwrap().is_lt());
    assert!(our_global.compare(&one, &mut budget).unwrap().is_lt());
    fixture(residual, &mut budget);
    parameters(residual, local, &mut budget);
    standing(residual, &mut budget);
    roots(residual, local, &mut budget);
    // These bounds are properties of distinct centres, operators and boxes.
    // Their data are retained without an ordering or containment assertion.
    let separate = [
        (
            "residual-radius",
            NumberId::NumbersPublishedResidualRadiusUpper.value(),
            residual.radius.as_str(),
        ),
        (
            "local-contraction",
            NumberId::NumbersPublishedLocalContractionUpper.value(),
            local.jacobian_norm.as_str(),
        ),
        (
            "local-radius",
            NumberId::NumbersPublishedLocalRadiusUpper.value(),
            local.image_radius.as_str(),
        ),
        (
            "candidate-iterations",
            NumberId::NumbersPublishedCandidateIterations.value(),
            NumberId::NumbersReferenceCandidateIterations.value(),
        ),
    ];
    assert_eq!(separate.len(), 4);
    for (_, paper, ours) in separate {
        assert_ne!(paper, "");
        assert_ne!(ours, "");
    }
}

fn parameters(residual: &TwoMapRecord, local: &LocalRecord, budget: &mut Budget) {
    use NumberId as N;
    let input = &residual.first.input;
    for (actor, intercept, slope) in [
        ("carol", N::NumbersPublishedCarolIntercept, N::NumbersPublishedCarolSlope),
        ("alice", N::NumbersPublishedAliceIntercept, N::NumbersPublishedAliceSlope),
        ("eve", N::NumbersPublishedEveIntercept, N::NumbersPublishedEveSlope),
        ("bob", N::NumbersPublishedBobIntercept, N::NumbersPublishedBobSlope),
        ("dave", N::NumbersPublishedDaveIntercept, N::NumbersPublishedDaveSlope),
    ] {
        let source = input.sources.iter().find(|source| source.name == actor).unwrap();
        assert_eq!(number(&source.intercept, budget), number(intercept.value(), budget));
        assert_eq!(number(&source.slope, budget), number(slope.value(), budget));
    }
    for (actual, declared) in [
        (
            &input.shape,
            [
                N::NumbersPublishedShapeFirst,
                N::NumbersPublishedShapeSecond,
                N::NumbersPublishedShapeThird,
                N::NumbersPublishedShapeFourth,
            ],
        ),
        (
            &input.depth_mass,
            [
                N::NumbersPublishedMassFirst,
                N::NumbersPublishedMassSecond,
                N::NumbersPublishedMassThird,
                N::NumbersPublishedMassFourth,
            ],
        ),
    ] {
        assert_eq!(actual.len(), declared.len());
        for (actual, declared) in actual.iter().zip(declared) {
            assert_eq!(number(actual, budget), number(declared.value(), budget));
        }
    }
    assert_eq!(
        number(&input.retention, budget),
        number(N::NumbersPublishedRetention.value(), budget)
    );
    // The reduced coordinate removes the positive numeraire before comparison.
    assert!(
        number(N::NumbersPublishedNumeraire.value(), budget)
            .compare(&number("0", budget), budget)
            .unwrap()
            .is_gt()
    );
    // Distinct local boxes retain their own construction parameters.
    for (published, ours) in [
        (N::NumbersPublishedLocalInflation, &local.declaration.inflation),
        (N::NumbersPublishedLocalPadding, &local.declaration.padding),
    ] {
        assert!(
            number(published.value(), budget)
                .compare(&number("0", budget), budget)
                .unwrap()
                .is_gt()
        );
        assert!(number(ours, budget).compare(&number("0", budget), budget).unwrap().is_gt());
    }
}

fn standing(residual: &TwoMapRecord, budget: &mut Budget) {
    let standing_label = "ver:standing:conserved-equilibrium-enclosure";
    let radius = number(NumberId::NumbersPublishedStandingInflationRadius.value(), budget);
    let coordinates = [
        (
            "carol",
            super::range(
                NumberId::NumbersPublishedImageCarolLower.value(),
                NumberId::NumbersPublishedImageCarolUpper.value(),
            ),
        ),
        (
            "alice",
            super::range(
                NumberId::NumbersPublishedImageAliceLower.value(),
                NumberId::NumbersPublishedImageAliceUpper.value(),
            ),
        ),
        (
            "eve",
            super::range(
                NumberId::NumbersPublishedImageEveLower.value(),
                NumberId::NumbersPublishedImageEveUpper.value(),
            ),
        ),
        (
            "bob",
            super::range(
                NumberId::NumbersPublishedImageBobLower.value(),
                NumberId::NumbersPublishedImageBobUpper.value(),
            ),
        ),
        (
            "dave",
            super::range(
                NumberId::NumbersPublishedImageDaveLower.value(),
                NumberId::NumbersPublishedImageDaveUpper.value(),
            ),
        ),
    ];
    for (actor, image) in &coordinates {
        let index = residual.first.input.sources.iter().position(|s| s.name == *actor).unwrap();
        let standing = inflate(image, &radius, budget);
        compare(
            &format!("{standing_label}:equilibrium:{actor}"),
            &standing,
            &residual.enclosure[index],
            true,
            budget,
        );
    }
}

fn roots(residual: &TwoMapRecord, local: &LocalRecord, budget: &mut Budget) {
    let standing_label = "ver:standing:conserved-equilibrium-enclosure";
    let roots = [
        (
            "eve",
            super::range(
                NumberId::NumbersPublishedRootEveLower.value(),
                NumberId::NumbersPublishedRootEveUpper.value(),
            ),
        ),
        (
            "bob",
            super::range(
                NumberId::NumbersPublishedRootBobLower.value(),
                NumberId::NumbersPublishedRootBobUpper.value(),
            ),
        ),
        (
            "dave",
            super::range(
                NumberId::NumbersPublishedRootDaveLower.value(),
                NumberId::NumbersPublishedRootDaveUpper.value(),
            ),
        ),
        (
            "carol",
            super::range(
                NumberId::NumbersPublishedRootCarolLower.value(),
                NumberId::NumbersPublishedRootCarolUpper.value(),
            ),
        ),
    ];
    assert_eq!(local.verdict, LocalVerdict::Included);
    let published_local_verdict = PublishedVerdict::Pass;
    assert_eq!(
        published_local_verdict,
        PublishedVerdict::from_pass(local.verdict == LocalVerdict::Included)
    );
    assert_eq!(local.active.len(), roots.len());
    for (actor, root) in &roots {
        let index = residual.first.input.sources.iter().position(|s| s.name == *actor).unwrap();
        assert!(local.active.contains(&index));
        compare(
            &format!("{standing_label}:local-root:{actor}"),
            root,
            &local.asserted[index],
            false,
            budget,
        );
    }
}

type FixtureRow = (&'static str, &'static str, &'static [&'static str], Range, Range);

fn fixture_rows() -> [FixtureRow; 5] {
    [
        (
            "carol",
            NumberId::NumbersPublishedCarolCount.value(),
            &["alice", "bob", "carol"][..],
            super::range(
                NumberId::NumbersPublishedCarolRateLower.value(),
                NumberId::NumbersPublishedCarolRateUpper.value(),
            ),
            super::range(
                NumberId::NumbersPublishedCarolHullLower.value(),
                NumberId::NumbersPublishedCarolHullUpper.value(),
            ),
        ),
        (
            "alice",
            NumberId::NumbersPublishedAliceCount.value(),
            &["alice"][..],
            super::range(
                NumberId::NumbersPublishedAliceRateLower.value(),
                NumberId::NumbersPublishedAliceRateUpper.value(),
            ),
            super::range(
                NumberId::NumbersPublishedAliceHullLower.value(),
                NumberId::NumbersPublishedAliceHullUpper.value(),
            ),
        ),
        (
            "eve",
            NumberId::NumbersPublishedEveCount.value(),
            &["alice", "bob", "carol", "dave", "eve"][..],
            super::range(
                NumberId::NumbersPublishedEveRateLower.value(),
                NumberId::NumbersPublishedEveRateUpper.value(),
            ),
            super::range(
                NumberId::NumbersPublishedEveHullLower.value(),
                NumberId::NumbersPublishedEveHullUpper.value(),
            ),
        ),
        (
            "bob",
            NumberId::NumbersPublishedBobCount.value(),
            &["alice", "bob"][..],
            super::range(
                NumberId::NumbersPublishedBobRateLower.value(),
                NumberId::NumbersPublishedBobRateUpper.value(),
            ),
            super::range(
                NumberId::NumbersPublishedBobHullLower.value(),
                NumberId::NumbersPublishedBobHullUpper.value(),
            ),
        ),
        (
            "dave",
            NumberId::NumbersPublishedDaveCount.value(),
            &["alice", "bob", "carol", "dave"][..],
            super::range(
                NumberId::NumbersPublishedDaveRateLower.value(),
                NumberId::NumbersPublishedDaveRateUpper.value(),
            ),
            super::range(
                NumberId::NumbersPublishedDaveHullLower.value(),
                NumberId::NumbersPublishedDaveHullUpper.value(),
            ),
        ),
    ]
}

// The paper's tagged reference supports and rate data, under
// ver:standing:conserved-equilibrium-enclosure, in deliberately unsorted Actor order.
fn fixture(residual: &TwoMapRecord, budget: &mut Budget) {
    let record = &residual.first;
    let rows = fixture_rows();
    assert_eq!(record.input.sources.len(), rows.len());
    for (actor, count, support, rate, hull) in rows {
        let index = record.input.sources.iter().position(|source| source.name == actor).unwrap();
        let source = &record.input.sources[index];
        assert_eq!(number(&source.count, budget), number(count, budget), "count:{actor}");
        let actual: std::collections::BTreeSet<_> = record.support[index]
            .iter()
            .map(|i| record.input.sources[*i].name.as_str())
            .collect();
        assert_eq!(actual, support.iter().copied().collect(), "support:{actor}");
        let at_lower = rate_at(source, &record.input.wall.lower, budget);
        let at_upper = rate_at(source, &record.input.wall.upper, budget);
        let (lower, upper) = if at_lower.compare(&at_upper, budget).unwrap().is_gt() {
            (at_upper, at_lower)
        } else {
            (at_lower, at_upper)
        };
        let ours = super::range(&lower.exact_string(budget).unwrap(), &upper.exact_string(budget).unwrap());
        compare(
            &format!("ver:standing:conserved-equilibrium-enclosure:rate:{actor}"),
            &rate,
            &ours,
            true,
            budget,
        );
        compare(
            &format!("ver:standing:conserved-equilibrium-enclosure:hull:{actor}"),
            &hull,
            &record.hull[index],
            true,
            budget,
        );
    }
    // In this fixture Carol minus Dave realizes the maximum contributing width
    // at both endpoints. Every competing difference is affine, hence endpoint
    // domination proves domination throughout the independent wall interval.
    let left = contributing_width(record, &record.input.wall.lower, budget);
    let right = contributing_width(record, &record.input.wall.upper, budget);
    assert!(right.compare(&left, budget).unwrap().is_lt());
    let ours = super::range(&right.exact_string(budget).unwrap(), &left.exact_string(budget).unwrap());
    let published = super::range(
        NumberId::NumbersPublishedWidthLower.value(),
        NumberId::NumbersPublishedWidthUpper.value(),
    );
    compare(
        "ver:standing:conserved-equilibrium-enclosure:width",
        &published,
        &ours,
        true,
        budget,
    );
}

fn rate_at(source: &pn_records::conserved::VerificationSource, wall: &str, budget: &mut Budget) -> Rational {
    let intercept = number(&source.intercept, budget);
    let slope = number(&source.slope, budget);
    let wall = number(wall, budget);
    intercept.add(&slope.mul(&wall, budget).unwrap(), budget).unwrap()
}

fn contributing_width(record: &pn_records::conserved::BoxMapRecord, wall: &str, budget: &mut Budget) -> Rational {
    let rates: Vec<_> = record
        .input
        .sources
        .iter()
        .map(|source| rate_at(source, wall, budget))
        .collect();
    let carol = record.input.sources.iter().position(|source| source.name == "carol").unwrap();
    let dave = record.input.sources.iter().position(|source| source.name == "dave").unwrap();
    assert!(
        record
            .support
            .iter()
            .any(|support| support.contains(&carol) && support.contains(&dave))
    );
    let maximum = rates[carol].sub(&rates[dave], budget).unwrap();
    for support in &record.support {
        for u in support {
            for v in support {
                let gap = rates[*u].sub(&rates[*v], budget).unwrap();
                assert!(!gap.compare(&maximum, budget).unwrap().is_gt());
            }
        }
    }
    maximum
}

// Exact declaration rows supplement the outward certificate rows.
// network-v0.31.1, ver:standing:conserved-equilibrium-enclosure.
fn declaration_matches(input: &pn_records::conserved::VerificationInput, budget: &mut Budget) -> bool {
    use NumberId as N;
    let expected = super::verification_reference();
    if input != &expected {
        return false;
    }
    let coordinates = [
        (
            "carol",
            "eve",
            N::NumbersPublishedVouchCarolEveCoordinateFirst,
            N::NumbersPublishedVouchCarolEveCoordinateSecond,
        ),
        (
            "alice",
            "bob",
            N::NumbersPublishedVouchAliceBobCoordinateFirst,
            N::NumbersPublishedVouchAliceBobCoordinateSecond,
        ),
        (
            "bob",
            "dave",
            N::NumbersPublishedVouchBobDaveCoordinateFirst,
            N::NumbersPublishedVouchBobDaveCoordinateSecond,
        ),
        (
            "dave",
            "eve",
            N::NumbersPublishedVouchDaveEveCoordinateFirst,
            N::NumbersPublishedVouchDaveEveCoordinateSecond,
        ),
        (
            "alice",
            "carol",
            N::NumbersPublishedVouchAliceCarolCoordinateFirst,
            N::NumbersPublishedVouchAliceCarolCoordinateSecond,
        ),
        (
            "carol",
            "dave",
            N::NumbersPublishedVouchCarolDaveCoordinateFirst,
            N::NumbersPublishedVouchCarolDaveCoordinateSecond,
        ),
        (
            "bob",
            "carol",
            N::NumbersPublishedVouchBobCarolCoordinateFirst,
            N::NumbersPublishedVouchBobCarolCoordinateSecond,
        ),
        (
            "alice",
            "eve",
            N::NumbersPublishedVouchAliceEveCoordinateFirst,
            N::NumbersPublishedVouchAliceEveCoordinateSecond,
        ),
        (
            "bob",
            "eve",
            N::NumbersPublishedVouchBobEveCoordinateFirst,
            N::NumbersPublishedVouchBobEveCoordinateSecond,
        ),
    ];
    input.edges.len() == coordinates.len()
        && coordinates.into_iter().all(|(source, target, first, second)| {
            let product = number(first.value(), budget)
                .mul(&number(second.value(), budget), budget)
                .unwrap();
            input
                .edges
                .iter()
                .any(|edge| edge.source == source && edge.target == target && number(&edge.radicand, budget) == product)
        })
}

/// Check the exact tagged declaration and separate single-field mutations.
/// # Panics
/// Panics only if a declaration row disagrees or a changed field is accepted.
pub(super) fn declaration_controls(input: &pn_records::conserved::VerificationInput) {
    let mut budget = Budget::new(super::verification_policy().enclosure.unwrap().operation).unwrap();
    assert!(declaration_matches(input, &mut budget));
    for field in [2, 0, 1] {
        let mut changed = input.clone();
        // Each replacement is another declared quantity, distinct from this field.
        match field {
            0 => changed.edges[0].radicand.clone_from(&input.edges[1].radicand),
            1 => changed.shape[0].clone_from(&input.shape[1]),
            _ => changed.sources[0].intercept.clone_from(&input.sources[1].intercept),
        }
        assert!(!declaration_matches(&changed, &mut budget));
    }
}
