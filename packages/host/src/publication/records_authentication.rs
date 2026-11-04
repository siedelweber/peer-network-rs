//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_records::authentication::AuthenticationFields {
    proposal_precommitment,
    actor_proposal_signature,
    content_edition,
    dependency_edition,
    verified_header,
    host_seal,
    approval_binding,
    authentication_edition,
    public_verification_material
});
