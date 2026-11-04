//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};
use pn_epoch::publication::disclosures as d;

structure!(d::enclosure::ExpSeries {
    degree,
    sum,
    omitted,
    tail
});
structure!(d::enclosure::ExpEndpoint {
    squarings,
    argument,
    series
});
structure!(d::enclosure::ExpEvidence { record, lower, upper });
