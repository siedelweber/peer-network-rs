//! Code-built publication input for the disposable fixture instance.
//! (´[ROOT-amend:storage:fixture-replay-interface]´)

mod base;
mod expected;
mod root;

use pn_epoch::publication::disclosures::Disclosure;
use pn_host::{
    publication,
    storage::{
        ReadBudget,
        tree::{
            AuditBudget, Generation,
            rebuild::{
                self, AssertedUse, PreparedReplay, ReplayAssertion, ReplayEntry, ReplayExecution, ReplayFailure, ReplayInput,
                ReplayPreparation, ReplaySchedule, ReplayUsage,
            },
        },
    },
};
use pn_interchange::EncodingUsage;
use pn_records::numerics::{ComparisonLimits, NumericContext};

/// The single closed fixture selection. Its bytes are encoded anew for each construction.
#[derive(Debug)]
pub struct Fixture {
    disclosure: Disclosure,
    bytes: Vec<u8>,
    verifier: root::Check,
    generation: Generation,
    uses: Vec<AssertedUse>,
}

/// Choose one admitted, code-built fixture by its closed name.
/// # Panics
/// Panics only if the fixed root's public owner validations or canonical encoding refuse their authored constant inputs.
#[must_use]
#[tracing::instrument(
    name = "amend:storage:fixture-replay-interface",
    fields(
        execution_owner = "FIXTURES",
        claim_owner = "ROOT",
        claim_label = "amend:storage:fixture-replay-interface",
        operation = "fixture-select",
        source_item = "select"
    ),
    ret
)]
pub fn select(name: &str) -> Option<Fixture> {
    if name != "root" {
        return None;
    }
    let (closed, carrier, verifier) = root::fixture();
    let admitted = pn_epoch::publication::assemble(&closed, carrier, &verifier).unwrap();
    let disclosure = admitted.disclosures();
    let mut numeric = encoding_numeric();
    let bytes = publication::encode(&disclosure, &mut numeric, encoding_limits()).unwrap();
    let uses = expected::uses();
    let generation = expected::generation(&uses);
    Some(Fixture {
        disclosure,
        bytes,
        verifier,
        generation,
        uses,
    })
}

fn encoding_numeric() -> NumericContext {
    NumericContext::new(encoding_limits(), ComparisonLimits::new(1_000, 1_000)).unwrap()
}

fn preparation_numeric() -> NumericContext {
    NumericContext::new(preparation_limits(), ComparisonLimits::new(1_000, 1_000)).unwrap()
}

fn encoding_limits() -> pn_epoch::publication::disclosures::Limits {
    pn_epoch::publication::disclosures::Limits {
        source_bytes: 262_144,
        name_bytes: 256,
        original_occurrences: 10_000,
        depth: 128,
        vertices: 50_000,
        edges: 200_000,
        staged_vertices: 50_000,
        staged_edges: 200_000,
        payload_bytes: 16_777_216,
        staged_payload_bytes: 16_777_216,
        work: 100_000_000,
        arithmetic_steps: 5_000_000,
        component_bits: 4096,
        intermediate_bits: 8192,
        literal_bytes: 256,
        decimal_exponent: 128,
        integer_exponent: 256,
        polynomial_degree: 64,
        polynomial_variables: 16,
        polynomial_terms: 4096,
        matrix_entries: 4096,
        condition_atoms: 256,
        condition_steps: 100_000,
        match_attempts: 50_000,
        match_batch: 32,
        frontier_labels: 8192,
        queue_entries: 16_384,
        transitions: 20_000,
        expansion_credits: 20_000,
        peak_expression_size: 50_000,
        proof_nodes: 20_000,
        witness_bytes: 1_048_576,
        output_bytes: 1_048_576,
        diagnostic_records: 128,
        replay_work: 100_000_000,
        cost_quota: 4,
        progress_quota: 1,
        case_arms: 256,
        region_nodes: 2048,
        region_cells: 256,
        refinement_pairs: 4096,
        local_contexts: 128,
        hypothesis_depth: 32,
        boundary_nodes: 128,
        jet_order: 8,
        jet_entries: 4096,
        delta_order: 8,
        test_nodes: 256,
        pairing_steps: 4096,
        pullback_zeros: 64,
        coefficient_ops: 2_000_000,
        denominator_factors: 256,
        coefficient_maps: 256,
        tower_levels: 8,
        tower_degree: 256,
        tower_reductions: 100_000,
        gcd_steps: 100_000,
        component_splits: 128,
        orbit_permutations: 40_320,
        orbit_members: 256,
        orbit_terms: 262_144,
        symmetric_steps: 4_096,
        resolvent_depth: 8,
        resolvent_degree: 32,
        selection_slots: 64,
        solution_branches: 256,
        family_parameters: 64,
        solve_identities: 8_192,
        linear_pivots: 256,
        isolation_steps: 100_000,
        local_branches: 64,
    }
}

fn preparation_limits() -> pn_epoch::publication::disclosures::Limits {
    pn_epoch::publication::disclosures::Limits {
        source_bytes: 262_144,
        name_bytes: 256,
        original_occurrences: 10_000,
        depth: 128,
        vertices: 50_000,
        edges: 200_000,
        staged_vertices: 50_000,
        staged_edges: 200_000,
        payload_bytes: 16_777_216,
        staged_payload_bytes: 16_777_216,
        work: 100_000_000,
        arithmetic_steps: 5_000_000,
        component_bits: 4096,
        intermediate_bits: 8192,
        literal_bytes: 256,
        decimal_exponent: 128,
        integer_exponent: 256,
        polynomial_degree: 64,
        polynomial_variables: 16,
        polynomial_terms: 4096,
        matrix_entries: 4096,
        condition_atoms: 256,
        condition_steps: 100_000,
        match_attempts: 50_000,
        match_batch: 32,
        frontier_labels: 8192,
        queue_entries: 16_384,
        transitions: 20_000,
        expansion_credits: 20_000,
        peak_expression_size: 50_000,
        proof_nodes: 20_000,
        witness_bytes: 1_048_576,
        output_bytes: 1_048_576,
        diagnostic_records: 128,
        replay_work: 100_000_000,
        cost_quota: 4,
        progress_quota: 1,
        case_arms: 256,
        region_nodes: 2048,
        region_cells: 256,
        refinement_pairs: 4096,
        local_contexts: 128,
        hypothesis_depth: 32,
        boundary_nodes: 128,
        jet_order: 8,
        jet_entries: 4096,
        delta_order: 8,
        test_nodes: 256,
        pairing_steps: 4096,
        pullback_zeros: 64,
        coefficient_ops: 2_000_000,
        denominator_factors: 256,
        coefficient_maps: 256,
        tower_levels: 8,
        tower_degree: 256,
        tower_reductions: 100_000,
        gcd_steps: 100_000,
        component_splits: 128,
        orbit_permutations: 40_320,
        orbit_members: 256,
        orbit_terms: 262_144,
        symmetric_steps: 4_096,
        resolvent_depth: 8,
        resolvent_degree: 32,
        selection_slots: 64,
        solution_branches: 256,
        family_parameters: 64,
        solve_identities: 8_192,
        linear_pivots: 256,
        isolation_steps: 100_000,
        local_branches: 64,
    }
}

fn read_budget() -> ReadBudget {
    ReadBudget {
        rows: 256,
        bytes: 262_144,
    }
}

fn audit_budget() -> AuditBudget {
    AuditBudget {
        page_rows: 16,
        rows: 256,
        allocation_bytes: 262_144,
        retained_bytes: 65_536,
        items: 512,
    }
}

impl Fixture {
    /// Borrow the code-built disclosure before encoding or inspection.
    #[must_use]
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-disclosure",
            source_item = "Fixture::disclosure"
        ),
        ret
    )]
    pub fn disclosure(&self) -> &Disclosure {
        &self.disclosure
    }

    /// Borrow the bytes encoded during this construction.
    #[must_use]
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-bytes",
            source_item = "Fixture::bytes"
        ),
        ret
    )]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Prepare independently authored declarations and the encoded root before opening a target.
    /// # Errors
    /// Returns the ordinary replay preparation failure.
    // Justified: This public operation returns the admitted replay failure unchanged.
    #[expect(clippy::result_large_err)]
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-prepare",
            source_item = "Fixture::prepare"
        ),
        ret
    )]
    pub fn prepare(&self) -> Result<PreparedReplay, ReplayFailure> {
        let entry = ReplayEntry {
            bytes: &self.bytes,
            assertion: ReplayAssertion {
                label: Some("unstable"),
                ordinal: 1,
                scope: expected::scope(),
                identity: expected::IDENTITY,
                parent: None,
                depth: 1,
                uses: &self.uses,
            },
        };
        let mut numeric = preparation_numeric();
        let mut encoding_usage = EncodingUsage::default();
        let mut reserved = 0usize;
        let mut reserve = |requested: usize| {
            reserved = reserved.checked_add(requested).ok_or(())?;
            if reserved <= 8_192 { Ok(()) } else { Err(()) }
        };
        let mut resources = ReplayPreparation {
            numeric: &mut numeric,
            encoding_usage: &mut encoding_usage,
            reservation: &mut reserve,
            limits: preparation_limits(),
            position_ceiling: 4_096,
        };
        let result = rebuild::prepare(
            ReplayInput {
                generations: std::slice::from_ref(&self.generation),
                entries: std::slice::from_ref(&entry),
            },
            &self.verifier,
            &mut resources,
        );
        if result.is_err() {
            tracing::event!(
                name: "amend:storage:fixture-replay-interface",
                tracing::Level::TRACE,
                execution_owner = "FIXTURES",
                claim_owner = "ROOT",
                claim_label = "amend:storage:fixture-replay-interface",
                operation = "fixture-prepare",
                event_kind = "completion",
                outcome = "refusal"
            );
        }
        result
    }

    /// Form the complete memory route's call-indexed allowance from prepared inspections.
    #[must_use]
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-memory-schedule",
            source_item = "Fixture::memory_schedule"
        ),
        ret
    )]
    pub fn memory_schedule(prepared: &PreparedReplay) -> ReplaySchedule {
        let (generations, results) = prepared.counts();
        ReplaySchedule {
            installation: vec![read_budget(); generations],
            commit: vec![read_budget(); results],
            target_read: vec![read_budget(); results],
            reference_read: Vec::new(),
            opening_audit: None,
            final_audit: audit_budget(),
        }
    }

    /// Form the complete server route's allowance, including its opening audit and paired reads.
    #[must_use]
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-server-schedule",
            source_item = "Fixture::server_schedule"
        ),
        ret
    )]
    pub fn server_schedule(prepared: &PreparedReplay) -> ReplaySchedule {
        let (generations, results) = prepared.counts();
        ReplaySchedule {
            installation: vec![read_budget(); generations],
            commit: vec![read_budget(); results],
            target_read: vec![read_budget(); results],
            reference_read: vec![read_budget(); results],
            opening_audit: Some(audit_budget()),
            final_audit: audit_budget(),
        }
    }

    /// Execute a complete memory reference for this fixture.
    /// # Errors
    /// Returns the ordinary replay execution failure.
    // Justified: This public operation returns the admitted replay failure unchanged.
    #[expect(clippy::result_large_err)]
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-replay-memory",
            source_item = "Fixture::replay_memory"
        ),
        ret
    )]
    pub fn replay_memory<'p>(
        prepared: &'p PreparedReplay,
        usage: &mut ReplayUsage,
    ) -> Result<rebuild::CompletedMemory<'p>, ReplayFailure> {
        let schedule = Self::memory_schedule(prepared);
        let result = rebuild::replay_memory(
            prepared,
            &mut ReplayExecution {
                schedule: &schedule,
                usage,
            },
        );
        if result.is_err() {
            tracing::event!(
                name: "amend:storage:fixture-replay-interface",
                tracing::Level::TRACE,
                execution_owner = "FIXTURES",
                claim_owner = "ROOT",
                claim_label = "amend:storage:fixture-replay-interface",
                operation = "fixture-replay-memory",
                event_kind = "completion",
                outcome = "refusal"
            );
        }
        result
    }
}

#[cfg(test)]
mod tests;
