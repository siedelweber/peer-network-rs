//! Pending reference publications are distinct from locally proved enclosures.
//! (´[ROOT-alg:design:two-map-verification]´)
use pn_records::{
    conserved::{LocalRecord, LocalVerdict, TwoMapRecord},
    primitive::Range,
};

#[derive(Debug, PartialEq, Eq)]
enum PublishedValue {
    PendingInterval,
    PendingVerdict,
}

#[derive(Debug, PartialEq, Eq)]
enum ComputedValue {
    Enclosure(Range),
    Verdict(LocalVerdict),
}

#[derive(Debug, PartialEq, Eq)]
struct Figure {
    label: &'static str,
    field: &'static str,
    published: PublishedValue,
    computed: ComputedValue,
}

fn bound(label: &'static str, field: &'static str, upper: &str) -> Figure {
    Figure {
        label,
        field,
        published: PublishedValue::PendingInterval,
        computed: ComputedValue::Enclosure(super::range("0", upper)),
    }
}

/// Check the pending publication shape against the locally certified results.
/// # Panics
/// Panics only if a figure is missing, mistyped or inconsistent with the checked local verdict.
pub(super) fn check(residual: &TwoMapRecord, local: &LocalRecord) {
    let label = "ver:standing:conserved-equilibrium-enclosure";
    // Bounds use [0, certified upper]: the conservative lower-wall fence is not
    // asserted to equal the defining wall's evaluated scalar interval.
    let figures = [
        bound(label, "krawczyk-radius", &local.image_radius),
        Figure {
            label: "ver:floor:fixture-regime",
            field: "fixture-wall",
            published: PublishedValue::PendingInterval,
            computed: ComputedValue::Enclosure(residual.first.input.wall.clone()),
        },
        bound(label, "global-contraction", &residual.first.contraction),
        Figure {
            label,
            field: "krawczyk-verdict",
            published: PublishedValue::PendingVerdict,
            computed: ComputedValue::Verdict(local.verdict.clone()),
        },
        bound(label, "fence", &residual.first.fence.upper),
        bound(label, "residual-radius", &residual.radius),
        bound(label, "krawczyk-contraction", &local.jacobian_norm),
    ];
    let mut fields = std::collections::BTreeSet::new();
    for figure in &figures {
        assert!(fields.insert((figure.label, figure.field)));
        match (&figure.published, &figure.computed) {
            (PublishedValue::PendingInterval, ComputedValue::Enclosure(value)) => {
                assert_ne!(value.lower, "");
                assert_ne!(value.upper, "");
            }
            (PublishedValue::PendingVerdict, ComputedValue::Verdict(verdict)) => assert_eq!(*verdict, LocalVerdict::Included),
            _ => panic!("publication type does not match the computed figure"),
        }
    }
    assert_eq!(fields.len(), 7);
    assert_eq!(
        figures
            .iter()
            .filter(|v| v.published == PublishedValue::PendingInterval)
            .count(),
        6
    );
    assert_eq!(
        figures
            .iter()
            .filter(|v| v.published == PublishedValue::PendingVerdict)
            .count(),
        1
    );
}
