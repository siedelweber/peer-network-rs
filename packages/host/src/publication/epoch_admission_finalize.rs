//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::admission::FinalProcedure {
    solve,
    arithmetic,
    maximum_products
});
structure!(pn_epoch::admission::FinalEvidence {
    effective,
    solvency,
    standing,
    rounds
});
structure!(pn_epoch::admission::Solvency {
    act,
    before: exact,
    debit: exact,
    after: exact
});
structure!(pn_epoch::admission::StampRound {
    precision,
    stamps,
    epoch,
    headroom
});
