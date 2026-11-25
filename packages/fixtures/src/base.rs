pub(super) use d::Limits;
pub(super) use pn_epoch::publication::{
    self, Carrier, Frame, NumericPolicy, OpeningKind, RegistrationVerifier, disclosures as d,
};
pub(super) use pn_epoch::{
    admission::{self, FinalProcedure, FinalRefusal},
    closure::{self, ClosedBoundary, ClosureInput},
    package, schedules,
    solve::{ProcedureVerifier, bind_procedure},
};
pub(super) use pn_records::{
    burn,
    numerics::{Floor, NumericContext},
    primitive::Range,
    solve::{Equality, Precision, Primitive, Procedure},
    *,
};
pub(super) use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub(super) struct RawVerifier;
impl RegistrationVerifier for RawVerifier {
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-raw-approval",
            source_item = "base::<RawVerifier as RegistrationVerifier>::approval"
        ),
        ret
    )]
    fn approval(&self, act: &ValidatedAct) -> bool {
        let id = act.id();
        id.author == "a" && ((id.family == "Registration" && id.sequence == 1) || (id.family == "Opinion" && id.sequence == 2))
    }
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-raw-removal",
            source_item = "base::<RawVerifier as RegistrationVerifier>::removal"
        ),
        ret
    )]
    fn removal(&self, act: &ValidatedAct, kind: OpeningKind, position: Position) -> bool {
        let _ = (act, kind, position);
        false
    }
}
#[derive(Debug)]
pub(super) struct Published(pub(super) Procedure);
impl ProcedureVerifier for Published {
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-published-procedure",
            source_item = "base::<Published as ProcedureVerifier>::published_procedure"
        ),
        ret
    )]
    fn published_procedure(&self, p: &Procedure) -> bool {
        &self.0 == p
    }
}
pub(crate) fn numeric() -> pn_records::numerics::NumericContext {
    pn_records::numerics::NumericContext::new(construction_limits(), pn_records::numerics::ComparisonLimits::new(1000, 1000))
        .unwrap()
}
pub(super) fn named(namespace: &str, name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: name.into(),
    }
}
pub(super) fn id(family: &str, author: &str, sequence: u64) -> ActId {
    ActId {
        family: family.into(),
        author: author.into(),
        sequence,
    }
}
pub(super) fn coordinates(act: &mut CandidateAct, names: &[&str], numerator: i64) {
    act.body.quantities = names
        .iter()
        .flat_map(|name| [(format!("{name}.numerator"), numerator), (format!("{name}.denominator"), 1)])
        .map(|(name, value)| {
            (
                name,
                Quantity {
                    value,
                    unit: "one".into(),
                    vintage: 0,
                },
            )
        })
        .collect();
}
pub(super) fn positions(inputs: &[CandidateAct]) -> Vec<CandidateAct> {
    // Compact raw fixture gaps without sorting the presentation or changing its order of record.
    let mut keys: Vec<_> = inputs
        .iter()
        .map(|act| (act.finalization_epoch, act.authoritative_position, act.id.clone()))
        .collect();
    keys.sort();
    let mut counters = BTreeMap::new();
    let assigned: BTreeMap<_, _> = keys
        .into_iter()
        .map(|(epoch, _, id)| {
            let next = counters.entry(epoch).or_insert(0);
            *next += 1;
            (id, *next)
        })
        .collect();
    inputs
        .iter()
        .cloned()
        .map(|mut act| {
            act.authoritative_position = assigned[&act.id];
            act
        })
        .collect()
}
pub(super) fn authentication() -> pn_records::authentication::AuthenticationFields {
    pn_records::authentication::AuthenticationFields {
        proposal_precommitment: b"fixture-P".to_vec(),
        actor_proposal_signature: vec![1],
        content_edition: "fixture-content".into(),
        dependency_edition: "fixture-dependency".into(),
        verified_header: b"fixture-V".to_vec(),
        host_seal: b"fixture-seal".to_vec(),
        approval_binding: b"fixture-approval".to_vec(),
        authentication_edition: "fixture-authentication".into(),
        public_verification_material: b"fixture-public-key".to_vec(),
    }
}
pub(super) fn act(family: &str, author: &str, sequence: u64, epoch: u64) -> CandidateAct {
    let id = id(family, author, sequence);
    let mut value = CandidateAct {
        commitments: None,
        id: id.clone(),
        body: StructuralBody {
            layout: Layout::Binary,
            quantities: vec![],
            license: None,
            settlement: None,
            asserted_parents: vec![],
        },
        legs: vec![CandidateLeg {
            id: EdgeId {
                act: id,
                role: Role::Binary,
            },
            source: named("addr", author),
            target: named("prof", author),
            removal: None,
        }],
        projections: RemovableProjections {
            content: Removal::Live,
            dependency: DependencyProjection::FullEmpty,
        },
        protocol_references: vec![],
        authentication_evidence: authentication(),
        finalization_epoch: epoch,
        authoritative_position: sequence,
        logical_time: sequence,
    };
    if family == "Opinion" {
        coordinates(&mut value, &["polarity", "reaction"], 1);
    }
    value
}
pub(super) use pn_epoch::{FamilyProfile, ParameterInput};
pub(super) use pn_records::constants::{ConstantDefinition, EditionInput};
pub(super) use pn_records::numerics::ComparisonLimits;
pub(super) fn constants_fixture_with_negative(negative: &str) -> (Declaration, EditionInput, ParameterInput) {
    let mut c = NumericContext::new(construction_limits(), ComparisonLimits::new(100, 100)).unwrap();
    let one = c.literal("1").unwrap();
    let unit = c.burn_per_action(&one, "burn").unwrap();
    let numeraire = c.numeraire("nu", &unit).unwrap();
    let id = DeclarationId {
        namespace: "numeric".into(),
        name: "constants".into(),
        edition: 1,
    };
    let declaration = Declaration {
        id: id.clone(),
        announced_at: 0,
        effective_at: 1,
        content: DeclarationContent::Opaque,
    };
    let definitions = [
        ("one", "1"),
        ("zero", "0"),
        ("negative", negative),
        ("third", "1/3"),
        ("rest", "2/3"),
        ("hops", "4"),
        ("bleed", "1/400"),
    ]
    .into_iter()
    .map(|(name, value)| ConstantDefinition::Literal {
        name: name.into(),
        value: c.literal(value).unwrap(),
    })
    .collect();
    let edition = EditionInput {
        id: id.clone(),
        floor: Floor::RationalThreeThirtySevenths,
        numeraire: numeraire.clone(),
        formula_edition: "formula".into(),
        controller_edition: "controller".into(),
        constants: definitions,
        permitted_overrides: vec![],
        domain_profiles: vec!["declared".into()],
        numerical_procedure: "exact-rational".into(),
        authentication_realization: "declared".into(),
        publication_profile: "internal".into(),
    };
    let mut profiles: Vec<_> = [
        ("Registration", "Identity"),
        ("Publish", "Economic"),
        ("Owner", "Economic"),
        ("Bid", "Economic"),
        ("Opinion", "Tribal"),
        ("Affinity", "Epistemic"),
        ("Tag", "Epistemic"),
        ("Participant", "Relational"),
        ("Invitation", "Relational"),
        ("Review", "Tribal"),
        ("Reference", "Epistemic"),
        ("Join Request", "Relational"),
        ("Accept", "Relational"),
        ("Ratify", "Relational"),
        ("Send", "Minimal"),
        ("De-invite", "Minimal"),
        ("Leave", "Minimal"),
        ("Withdraw", "Minimal"),
        ("Rescind", "Minimal"),
    ]
    .into_iter()
    .map(|(family, domain)| FamilyProfile {
        family: family.into(),
        name: "declared".into(),
        edition: id.clone(),
        weights: BTreeMap::from([(domain.into(), "one".into())]),
    })
    .collect();
    profiles[7].weights = BTreeMap::from([("Relational".into(), "third".into()), ("Epistemic".into(), "rest".into())]);
    let input = ParameterInput {
        boundary: 1,
        edition: id,
        numeraire,
        profiles,
        domain_weights: ["Identity", "Economic", "Tribal", "Epistemic", "Relational", "Minimal"]
            .into_iter()
            .map(|domain| (domain.into(), if domain == "Economic" { "rest" } else { "one" }.into()))
            .collect(),
        hop_limit: "hops".into(),
        self_base: "one".into(),
        depth_mass: vec!["third".into(), "rest".into()],
    };
    (declaration, edition, input)
}
#[derive(Debug)]
pub(super) struct Causes(pub(super) package::CandidateInput);
impl package::CandidateVerifier for Causes {
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-causes-candidate",
            source_item = "base::<Causes as package :: CandidateVerifier>::candidate_causes"
        ),
        ret
    )]
    fn candidate_causes(&self, input: &package::CandidateInput) -> bool {
        input.causes.bindings == self.0.causes.bindings
            && input.causes.history.acts() == self.0.causes.history.acts()
            && input.causes.inputs == self.0.causes.inputs
            && input.causes.prices == self.0.causes.prices
    }
}
impl package::ClosureVerifier for Causes {
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-causes-host",
            source_item = "base::<Causes as package :: ClosureVerifier>::host_determination"
        ),
        ret
    )]
    fn host_determination(&self, input: &package::CandidateInput) -> bool {
        input.closure == self.0.closure
    }
}

pub(super) fn compiled(context: &package::CandidateContext) -> pn_epoch::compiler::CompiledState {
    pn_epoch::compiler::compile_candidate(context, &RawVerifier, &mut numeric(), construction_limits(), 10_000_u64).unwrap()
}
pub(super) fn procedure(context: &package::CandidateContext) -> FinalProcedure {
    let state = compiled(context);
    assert!(matches!(state.package(), pn_epoch::compiler::CompiledSource::Candidate(_)));
    let bits = u32::try_from(4_u64).unwrap();
    let mut plan = fence_procedure(&state);
    plan.precision = Precision::AbsoluteWidthBits(vec![bits]);
    plan.enclosure.as_mut().unwrap().refinement.precision = bits;
    plan.endpoint_grid = "1/16".into();
    FinalProcedure {
        solve: plan,
        arithmetic: declared_limits(),
        maximum_products: 10_000_u64,
    }
}
pub(super) fn schedule(context: &package::CandidateContext, policy: &str) -> schedules::CheckedSchedule {
    let binding = context.input().causes.bindings.last().unwrap();
    let d = admission::declare_schedule(
        admission::ScheduleInput {
            controller: "canonical-interim-v1".into(),
            announced_at: binding.marker.index - 1,
            initialization: admission::InitializationInput {
                floor: Some(binding.inputs.constants().content().floor),
                wall: Some(binding.price.wall().exact().into()),
                policy_floor: Some(policy.into()),
                effective_boundary: Some(binding.marker.index),
                parameters: Some(admission::ControllerParameters {
                    absolute_cap: "1".into(),
                    relative_cap: "1/8".into(),
                    deadband: "0".into(),
                    margin: "5/4".into(),
                }),
            },
            numeraire: binding.price.numeraire().clone(),
            delivery: admission::Delivery::ExactRational,
            refinement: admission::Refinement {
                precision_bits: vec![u32::try_from(4_u64).unwrap()],
                maximum_work: 100_000_000_u64,
                maximum_replay_work: 100_000_000_u64,
            },
        },
        construction_limits(),
    )
    .unwrap();
    let r = schedules::evaluate(&d, &[], None, construction_limits()).unwrap();
    schedules::replay(&d, &[], None, construction_limits(), &r).unwrap()
}
pub(super) fn run(
    context: &package::CandidateContext,
    plan: &FinalProcedure,
    led_schedule: &schedules::CheckedSchedule,
) -> Result<package::AdmittedBoundary, FinalRefusal> {
    admission::admit(
        context,
        led_schedule,
        plan,
        &RawVerifier,
        &Published(plan.solve.clone()),
        numeric(),
    )
}
pub(super) fn self_acts() -> Vec<pn_records::CandidateAct> {
    let mut opinion = act("Opinion", "a", 2, 1);
    opinion.legs[0].target = named("prof", "a");
    vec![opinion, act("Registration", "a", 1, 1)]
}
pub(super) fn declaration(state: &pn_epoch::compiler::CompiledState) -> Procedure {
    let inputs = state.package().input().inputs.last().unwrap();
    Procedure {
        edition: inputs.parameters().edition.clone(),
        boundary: inputs.parameters().boundary,
        name: inputs.constants().content().numerical_procedure.clone(),
        backend: "unselected".into(),
        primitives: BTreeSet::from([
            Primitive::Rational,
            Primitive::Root,
            Primitive::Exponential,
            Primitive::Logarithm,
            Primitive::Power,
        ]),
        precision: Precision::BinaryBits(vec![32, 64]),
        equality: Equality::ExactRationalOnly,
        grid: vec!["1".into(), "1/2".into(), "0".into()],
        margin: "5/4".into(),
        maximum_work: 10,
        maximum_solve_work: 10,
        maximum_replay_work: 10,
        maximum_iterations: 20,
        endpoint_grid: "1/1000".into(),
        fence: None,
        enclosure: None,
    }
}
pub(super) fn base_procedure(state: &pn_epoch::compiler::CompiledState) -> Procedure {
    let mut input = declaration(state);
    input.backend = "nrz-cas".into();
    input.precision = Precision::AbsoluteWidthBits(vec![4]);
    input.maximum_work = 10_000_000;
    let limits = Limits {
        work: input.maximum_work,
        ..declared_limits()
    };
    input.enclosure = Some(pn_records::primitive::EnclosurePolicy {
        store: limits.clone(),
        operation: limits,
        refinement: d::enclosure::RefinementPolicy {
            version: 1,
            precision: 4,
            grid_ceiling: 64,
            rounds: 2,
            reduction_ceiling: 4,
            term_ceiling: 64,
            checking_work: 1_000_000,
        },
    });
    input
}
pub(super) fn fence_procedure(state: &pn_epoch::compiler::CompiledState) -> Procedure {
    let mut p = base_procedure(state);
    p.maximum_work = 100_000_000_u64;
    p.maximum_solve_work = 100_000_000_u64;
    p.maximum_replay_work = 100_000_000_u64;
    p.primitives.extend([
        Primitive::Sigmoid,
        Primitive::Tanh,
        Primitive::SmoothDerivative,
        Primitive::ClampGeneralized,
    ]);
    p.precision = Precision::AbsoluteWidthBits(vec![4, 8]);
    let policy = p.enclosure.as_mut().unwrap();
    policy.store.work = p.maximum_work;
    policy.store.output_bytes = 32 * 1024 * 1024;
    policy.store.arithmetic_steps = 5_000_000;
    policy.operation = policy.store.clone();
    policy.refinement.grid_ceiling = 96;
    policy.refinement.checking_work = 0;
    policy.refinement.rounds = 1;
    p.fence = Some(pn_records::solve::FenceProfile {
        bleed_squared: "bleed".into(),
        shape: vec!["one".into(), "rest".into(), "third".into(), "zero".into()],
        inverse_wall: false,
    });
    p
}

// Explicit finite CAS policy for this code-built root. Every field is supplied here.
pub(super) fn declared_limits() -> Limits {
    Limits {
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
        work: 2_000_000,
        arithmetic_steps: 500_000,
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
        replay_work: 2_000_000,
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

pub(super) fn premise_limits() -> Limits {
    Limits {
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
        work: 2_000_000,
        arithmetic_steps: 500_000,
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
        replay_work: 2_000_000,
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

pub(super) fn construction_limits() -> Limits {
    Limits {
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
        work: 2_000_000,
        arithmetic_steps: 500_000,
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
        replay_work: 2_000_000,
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
