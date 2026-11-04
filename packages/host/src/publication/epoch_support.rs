//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::support::SourceEmission {
    reduced_rate: exact,
    emission: exact,
    retained: exact
});
structure!(pn_epoch::support::ContributingRange {
    minimum: exact,
    maximum: exact,
    width: exact
});
structure!(pn_epoch::support::StandingSupport {
    boundary,
    sources,
    by_depth,
    emitted,
    contributors,
    ranges,
    products
});
