//! Explicit field and variant mapping for the test publication theory.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, structure, take};

structure!(pn_epoch::publication::disclosures::Metadata { position, logical_time });
structure!(pn_epoch::publication::disclosures::Settlement {
    acts,
    references,
    targets_bind,
    partners,
    chain,
    times,
    item,
    prior_owner,
    clauses,
    withdrawals,
    rescissions,
    consumed,
    recognized
});
structure!(pn_epoch::publication::disclosures::TitleBoundary {
    premises,
    candidates,
    certificate,
    consumed
});
structure!(pn_epoch::publication::disclosures::Title {
    epoch,
    certificate,
    consumed,
    boundaries,
    events
});
structure!(pn_epoch::publication::disclosures::Recognition {
    basis,
    markers,
    first_refusal
});
structure!(pn_epoch::publication::disclosures::Marker {
    identity,
    accepted,
    destructions
});
structure!(pn_epoch::publication::disclosures::Inputs { parameters, constants });
structure!(pn_epoch::publication::disclosures::Binding {
    marker,
    predecessor,
    inputs,
    price,
    sequence
});
structure!(pn_epoch::publication::disclosures::Closure {
    markers,
    bindings,
    statement,
    partition,
    final_gates,
    schedule
});
structure!(pn_epoch::publication::disclosures::Debit {
    price,
    boundary,
    charged
});
structure!(pn_epoch::publication::disclosures::Ledger {
    snapshots,
    balances,
    counts,
    debits
});
structure!(pn_epoch::publication::disclosures::Compiled {
    title,
    ledger,
    cells,
    coefficients,
    recipients,
    base,
    support
});
structure!(pn_epoch::publication::disclosures::Boundary {
    realization,
    burn,
    marker_policy,
    marker_history,
    parameters,
    price,
    sequence,
    procedure,
    compiled,
    closure,
    standing,
    next
});
structure!(pn_epoch::publication::disclosures::Disclosure { causes, numeric, frames });
