//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::fence::Search {
    evidence,
    selected: exact,
    operational_stop
});
