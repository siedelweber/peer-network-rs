//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::cells::CellIdentity {
    author,
    family,
    incidence,
    singleton
});
structure!(pn_epoch::cells::StandingCell {
    identity,
    members,
    coordinates: exact
});
