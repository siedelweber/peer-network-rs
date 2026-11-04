//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::ParameterInput {
    boundary,
    edition,
    numeraire,
    profiles,
    domain_weights,
    hop_limit,
    self_base,
    depth_mass
});
structure!(pn_epoch::FamilyProfile {
    family,
    name,
    edition,
    weights
});
