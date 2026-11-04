//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_records::commitments::ActCommitments {
    proposal,
    content,
    dependency
});
structure!(pn_records::commitments::ProposalCommitment { recipe, bytes });
structure!(pn_records::commitments::ContentCommitment { recipe, bytes });
structure!(pn_records::commitments::DependencyCommitment { recipe, bytes });
