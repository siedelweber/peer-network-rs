//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_records::numerics::PriceInput {
    wall: exact,
    numeraire,
    price: exact,
    floor,
    ridge
});
