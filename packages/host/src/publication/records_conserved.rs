//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_records::conserved::MapRecord {
    edition,
    boundary,
    point: exact,
    rung: exact,
    precision,
    wall_enclosure,
    primitives,
    image,
    transport_input,
    transport,
    work,
    composition_work
});
structure!(pn_records::conserved::SolveRecord {
    fence,
    rounds,
    work,
    replay_work
});
structure!(pn_records::conserved::ResidualRound {
    proposals,
    certified,
    residual: exact,
    contraction: exact,
    radius: exact,
    standing,
    candidate_work,
    work
});
