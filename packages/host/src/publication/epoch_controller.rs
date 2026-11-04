//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::controller::InverseSearch {
    bracket,
    stopping_width: exact,
    maximum_steps
});
structure!(pn_epoch::controller::Evidence {
    declaration,
    search,
    fence,
    controller,
    burn_image: exact
});
