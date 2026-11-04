//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};
use pn_epoch::publication::disclosures as d;

structure!(d::enclosure::LogSeries { terms, sum, power, tail });
structure!(d::enclosure::LogEndpoint {
    exponent,
    mantissa,
    argument,
    reduced,
    two
});
structure!(d::enclosure::LogEvidence { record, lower, upper });
