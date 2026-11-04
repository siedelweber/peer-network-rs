//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::schedules::Record {
    declaration,
    initial,
    publications
});
structure!(pn_epoch::schedules::Publication {
    marker,
    announced_at,
    effective,
    proposal
});
structure!(pn_epoch::schedules::Effective {
    boundary,
    wall: exact,
    charge: exact,
    numeraire,
    policy_floor: exact
});
