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
        NumberId::NumbersCorpusPublished1.value(),
        NumberId::NumbersCorpusPublished2.value(),
    );
    compare(
        "ver:floor:fixture-regime",
        &wall,
        &residual.first.input.wall,
        true,
        &mut budget,
    );
    let fence = super::range(
        NumberId::NumbersCorpusPublished3.value(),
        NumberId::NumbersCorpusPublished4.value(),
    );
    // Positivity and strict decrease extend the lower-wall upper bound to
    // the defining wall. This enclosure is not the lower-wall scalar interval.
    let conservative_fence = super::range("0", &residual.first.fence.upper);
    compare(standing_label, &fence, &conservative_fence, false, &mut budget);
    let one = number("1", &mut budget);
    assert!(number(&fence.upper, &mut budget).compare(&one, &mut budget).unwrap().is_lt());
    assert_eq!(residual.first.input.strength, "1");
    // Full strength is the first declared rung, so this passing fence accepts one.
    let published_rung = NumberId::NumbersReferenceWallBranchesValue2.value();
    let published_strength = NumberId::NumbersReferenceWallBranchesValue2.value();
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
    let global = number(super::NumberId::NumbersPendingReferenceCorpusValue2.value(), &mut budget);
    let our_global = number(&residual.first.contraction, &mut budget);
    assert!(global.compare(&one, &mut budget).unwrap().is_lt());
    assert!(our_global.compare(&one, &mut budget).unwrap().is_lt());
    fixture(residual, &mut budget);
    standing(residual, &mut budget);
    roots(residual, local, &mut budget);
    // These bounds are properties of distinct centres, operators and boxes.
    // Their data are retained without an ordering or containment assertion.
    let separate = [
        (
            "residual-radius",
            NumberId::NumbersCorpusResidualRadiusUpper.value(),
            residual.radius.as_str(),
        ),
        (
            "local-contraction",
            NumberId::NumbersCorpusPublished5.value(),
            local.jacobian_norm.as_str(),
        ),
        (
            "local-radius",
            NumberId::NumbersCorpusLocalRadiusUpper.value(),
            local.image_radius.as_str(),
        ),
        (
            "candidate-iterations",
            NumberId::NumbersFixtureCountEighteen.value(),
            NumberId::NumbersReferenceWallMeasurementsValue21.value(),
        ),
    ];
    assert_eq!(separate.len(), 4);
    for (_, paper, ours) in separate {
        assert_ne!(paper, "");
        assert_ne!(ours, "");
    }
}

fn standing(residual: &TwoMapRecord, budget: &mut Budget) {
    let standing_label = "ver:standing:conserved-equilibrium-enclosure";
    let radius = number(NumberId::NumbersCorpusPublished6.value(), budget);
    let coordinates = [
        (
            "carol",
            super::range(
                NumberId::NumbersCorpusPublished7.value(),
                NumberId::NumbersCorpusPublished8.value(),
            ),
        ),
        (
            "alice",
            super::range(
                NumberId::NumbersCorpusPublished9.value(),
                NumberId::NumbersCorpusPublished10.value(),
            ),
        ),
        (
            "eve",
            super::range(
                NumberId::NumbersCorpusPublished11.value(),
                NumberId::NumbersCorpusPublished12.value(),
            ),
        ),
        (
            "bob",
            super::range(
                NumberId::NumbersCorpusPublished13.value(),
                NumberId::NumbersCorpusPublished14.value(),
            ),
        ),
        (
            "dave",
            super::range(
                NumberId::NumbersCorpusPublished15.value(),
                NumberId::NumbersCorpusPublished16.value(),
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
                NumberId::NumbersCorpusPublished17.value(),
                NumberId::NumbersCorpusPublished18.value(),
            ),
        ),
        (
            "bob",
            super::range(
                NumberId::NumbersCorpusPublished19.value(),
                NumberId::NumbersCorpusPublished20.value(),
            ),
        ),
        (
            "dave",
            super::range(
                NumberId::NumbersCorpusPublished21.value(),
                NumberId::NumbersCorpusPublished22.value(),
            ),
        ),
        (
            "carol",
            super::range(
                NumberId::NumbersCorpusPublished23.value(),
                NumberId::NumbersCorpusPublished24.value(),
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
            NumberId::NumbersCorpusCountCarol.value(),
            &["alice", "bob", "carol"][..],
            super::range(
                NumberId::NumbersCorpusRateCarolLo.value(),
                NumberId::NumbersCorpusRateCarolHi.value(),
            ),
            super::range(
                NumberId::NumbersCorpusHullCarolLo.value(),
                NumberId::NumbersCorpusHullCarolHi.value(),
            ),
        ),
        (
            "alice",
            NumberId::NumbersCorpusCountAlice.value(),
            &["alice"][..],
            super::range(
                NumberId::NumbersCorpusRateAliceLo.value(),
                NumberId::NumbersCorpusRateAliceHi.value(),
            ),
            super::range(
                NumberId::NumbersCorpusHullAliceLo.value(),
                NumberId::NumbersCorpusHullAliceHi.value(),
            ),
        ),
        (
            "eve",
            NumberId::NumbersCorpusCountEve.value(),
            &["alice", "bob", "carol", "dave", "eve"][..],
            super::range(
                NumberId::NumbersCorpusRateEveLo.value(),
                NumberId::NumbersCorpusRateEveHi.value(),
            ),
            super::range(
                NumberId::NumbersCorpusHullEveLo.value(),
                NumberId::NumbersCorpusHullEveHi.value(),
            ),
        ),
        (
            "bob",
            NumberId::NumbersCorpusCountBob.value(),
            &["alice", "bob"][..],
            super::range(
                NumberId::NumbersCorpusRateBobLo.value(),
                NumberId::NumbersCorpusRateBobHi.value(),
            ),
            super::range(
                NumberId::NumbersCorpusHullBobLo.value(),
                NumberId::NumbersCorpusHullBobHi.value(),
            ),
        ),
        (
            "dave",
            NumberId::NumbersCorpusCountDave.value(),
            &["alice", "bob", "carol", "dave"][..],
            super::range(
                NumberId::NumbersCorpusRateDaveLo.value(),
                NumberId::NumbersCorpusRateDaveHi.value(),
            ),
            super::range(
                NumberId::NumbersCorpusHullDaveLo.value(),
                NumberId::NumbersCorpusHullDaveHi.value(),
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
    let published = super::range(NumberId::NumbersCorpusWidthLo.value(), NumberId::NumbersCorpusWidthHi.value());
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
