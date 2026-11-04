//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};
use pn_epoch::publication::disclosures as d;

structure!(pn_records::transport::TransportInput<d::enclosure::Interval> { hops, depth_mass, emission, counts, rates });
structure!(pn_records::transport::TransportOutput<d::enclosure::Interval> { normalized, raw, emitted, numerator, denominator, standing, hull });
