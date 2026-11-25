use super::base::{
    BTreeMap, BTreeSet, Carrier, Causes, ClosedBoundary, ClosureInput, Declaration, DeclarationContent, DeclarationId,
    FinalProcedure, Frame, NumericPolicy, OpeningKind, Position, Published, Range, RawVerifier, RegistrationVerifier,
    ValidatedAct, admission, bind_procedure, burn, closure, constants_fixture_with_negative, construction_limits,
    declared_limits, numeric, package, positions, premise_limits, procedure, publication, run, schedule, schedules, self_acts,
};

#[derive(Clone)]
pub(super) struct BurnCase {
    pub(super) burn: burn::BurnInput,
    pub(super) policy: burn::PolicyInput,
    pub(super) history: burn::HistoryInput,
}

fn destruction_bytes(record: &burn::BurnRecord) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        record.destruction,
        record.address.0,
        record.amount.exact(),
        record.amount.unit()
    )
    .into_bytes()
}

fn recognized(case: &BurnCase, verifier: &impl burn::PublicVerifier) -> burn::RecognizedMarkers {
    let validated_burn = burn::validate_burn(case.burn.clone()).unwrap();
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let declarations = [
        Declaration {
            id: DeclarationId {
                namespace: "marker".into(),
                name: "policy".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: DeclarationContent::MarkerPolicy {
                recipe: pn_records::constants::MARKER_POLICY_RECIPE.into(),
                digest: pn_records::constants::marker_policy_digest(&case.policy),
            },
        },
        Declaration {
            id: DeclarationId {
                namespace: "deployment".into(),
                name: "genesis".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: DeclarationContent::Deployment { genesis_at: 1 },
        },
    ];
    let records = pn_records::validate_record(&[], &empty, &declarations).unwrap();
    let policy = pn_records::constants::bind_marker_policy(&records, case.policy.clone(), &validated_burn).unwrap();
    let history = burn::validate_marker_history(case.history.clone(), &policy, verifier).unwrap();
    burn::recognize_markers(&history)
}

#[derive(Debug)]
pub(crate) struct Check {
    numeric: NumericPolicy,
    pub(super) ridge_profile: Option<publication::RidgeReplayProfile>,
}
impl Check {
    pub(super) fn fixed() -> Self {
        Self {
            numeric: NumericPolicy {
                arithmetic: premise_limits(),
                comparison_attempts: 4,
                comparison_work: 100_000_000,
            },
            ridge_profile: None,
        }
    }
    fn accepted_procedure(procedure: &pn_records::solve::Procedure) -> bool {
        procedure.edition.namespace == "numeric"
            && procedure.edition.name == "constants"
            && procedure.edition.edition == 1
            && procedure.boundary == 1
            && procedure.name == "exact-rational"
            && procedure.backend == "nrz-cas"
            && procedure.maximum_work == 100_000_000
            && procedure.maximum_solve_work == 100_000_000
            && procedure.maximum_replay_work == 100_000_000
    }
}
impl burn::PublicVerifier for Check {
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-burn-profile",
            source_item = "root::<Check as burn :: PublicVerifier>::profile"
        ),
        ret
    )]
    fn profile(&self) -> &'static str {
        "fixture-public-v1"
    }
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-burn-destruction",
            source_item = "root::<Check as burn :: PublicVerifier>::destruction"
        ),
        ret
    )]
    fn destruction(&self, record: &burn::BurnRecord) -> bool {
        record.evidence == destruction_bytes(record)
    }
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-burn-opening",
            source_item = "root::<Check as burn :: PublicVerifier>::opening"
        ),
        ret
    )]
    fn opening(&self, commitment: &[u8], opening: &burn::Opening) -> bool {
        let bytes = format!("set:{}", opening.members.iter().cloned().collect::<Vec<_>>().join("|")).into_bytes();
        commitment == bytes && opening.proof == bytes
    }
}
impl RegistrationVerifier for Check {
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-registration-approval",
            source_item = "root::<Check as RegistrationVerifier>::approval"
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
            operation = "fixture-verifier-registration-removal",
            source_item = "root::<Check as RegistrationVerifier>::removal"
        ),
        ret
    )]
    fn removal(&self, act: &ValidatedAct, kind: OpeningKind, position: Position) -> bool {
        let _ = (act, kind, position);
        false
    }
}
impl package::CandidateVerifier for Check {
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-candidate-causes",
            source_item = "root::<Check as package :: CandidateVerifier>::candidate_causes"
        ),
        ret
    )]
    fn candidate_causes(&self, input: &package::CandidateInput) -> bool {
        let acts = input.causes.history.acts();
        acts.len() == 2
            && acts
                .iter()
                .any(|act| act.id().family == "Registration" && act.id().author == "a" && act.id().sequence == 1)
            && acts
                .iter()
                .any(|act| act.id().family == "Opinion" && act.id().author == "a" && act.id().sequence == 2)
            && input.causes.bindings.len() == 1
            && input.causes.inputs.len() == 1
            && input.causes.prices.len() == 1
            && input.causes.bindings[0].marker.name == "m1"
    }
}
impl package::ClosureVerifier for Check {
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-host-determination",
            source_item = "root::<Check as package :: ClosureVerifier>::host_determination"
        ),
        ret
    )]
    fn host_determination(&self, input: &package::CandidateInput) -> bool {
        input.closure.policy.target == 12
            && input.closure.policy.maximum_ticks == 12
            && input.closure.policy.clock == "fixture-clock"
            && input.closure.opened_at == 0
            && input.closure.determined_at == 12
            && input.closure.attestation == "fixture-determination"
    }
}
impl pn_epoch::solve::ProcedureVerifier for Check {
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-solve-procedure",
            source_item = "root::<Check as pn_epoch :: solve :: ProcedureVerifier>::published_procedure"
        ),
        ret
    )]
    fn published_procedure(&self, procedure: &pn_records::solve::Procedure) -> bool {
        Self::accepted_procedure(procedure)
    }
}
impl publication::Verifier for Check {
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-ridge-charge",
            source_item = "root::<Check as publication :: Verifier>::ridge_charge_profile"
        ),
        ret
    )]
    fn ridge_charge_profile(&self, index: u64) -> Option<&publication::RidgeReplayProfile> {
        let _ = index;
        self.ridge_profile.as_ref()
    }
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-publication-profile",
            source_item = "root::<Check as publication :: Verifier>::publication_profile"
        ),
        ret
    )]
    fn publication_profile(&self, carrier: &Carrier) -> bool {
        carrier.numeric == self.numeric
            && carrier.frames.iter().all(|f| {
                f.realization == realization()
                    && Self::accepted_procedure(&f.procedure.solve)
                    && f.procedure.arithmetic == premise_limits()
                    && f.procedure.maximum_products == 10_000_u64
            })
    }
    #[tracing::instrument(
        name = "amend:storage:fixture-replay-interface",
        fields(
            execution_owner = "FIXTURES",
            claim_owner = "ROOT",
            claim_label = "amend:storage:fixture-replay-interface",
            operation = "fixture-verifier-disclosure-profile",
            source_item = "root::<Check as publication :: Verifier>::disclosure_profile"
        ),
        ret
    )]
    fn disclosure_profile(&self, carrier: &publication::disclosures::Disclosure) -> bool {
        carrier.numeric == self.numeric
            && carrier.frames.iter().all(|f| {
                f.realization == realization()
                    && Self::accepted_procedure(&f.procedure.solve)
                    && f.procedure.arithmetic == premise_limits()
                    && f.procedure.maximum_products == 10_000_u64
            })
    }
}

fn realization() -> publication::RealizationEvidence {
    publication::RealizationEvidence {
        edition: "fixture-audit".into(),
        provenance: b"fixture destruction verifier".to_vec(),
        capacity_bound: b"fixture capacity declaration".to_vec(),
        dimensioned_unit_cost: b"fixture unit cost and denomination".to_vec(),
        recording_event_costs: b"fixture separate event costs and terms".to_vec(),
        settlement_and_finality: b"fixture settled history assumption".to_vec(),
        operator: publication::OperatorEvidence::Absent {
            statement: b"fixture has no accruing operator".to_vec(),
            explanation: b"synthetic destruction source".to_vec(),
        },
    }
}
pub(super) fn raw_burn() -> BurnCase {
    let mut n = numeric();
    let amount = n.literal("30").unwrap();
    let amount = n.burn(&amount, "burn").unwrap();
    let zero = n.literal("0").unwrap();
    let bootstrap = n.burn(&zero, "burn").unwrap();
    let quarter = n.literal("1/4").unwrap();
    let cost = n.unit_cost(&quarter, "fixture-unit", "burn", "fixture-terms").unwrap();
    let address = burn::Address("a".into());
    let mut record = burn::BurnRecord {
        identity: "r0".into(),
        destruction: "d0".into(),
        address: address.clone(),
        amount: amount.clone(),
        evidence: Vec::new(),
    };
    record.evidence = destruction_bytes(&record);
    let policy = burn::PolicyInput {
        identity: "policy".into(),
        edition: "1".into(),
        sequence: "sequence".into(),
        published_at: 0,
        genesis_at: 1,
        initial_marker: "m0".into(),
        open_placement: true,
        placement_procedure: "any party submits public evidence".into(),
        cadence: "one candidate per index; no liveness guarantee".into(),
        encoding: burn::Encoding::CompleteList,
        candidate_rule: burn::CandidateRule::UniquePerIndex,
        verification_profile: "fixture-public-v1".into(),
        stability_buffer: 7,
    };
    let marker =
        |name: &str,
         index: u64,
         history_position: u64,
         predecessor: Option<u64>,
         lineage: BTreeSet<String>,
         accepted: BTreeSet<String>,
         initial_snapshot: Option<BTreeMap<burn::Address, pn_records::numerics::BurnAmount>>| burn::Marker {
            name: name.into(),
            history: "history".into(),
            policy_identity: policy.identity.clone(),
            policy_edition: policy.edition.clone(),
            sequence: policy.sequence.clone(),
            index,
            history_position,
            predecessor,
            lineage,
            accepted: burn::AcceptedSet::CompleteList(accepted),
            initial_snapshot,
        };
    let markers = vec![
        marker("m0", 0, 0, None, BTreeSet::new(), BTreeSet::new(), Some(BTreeMap::new())),
        marker(
            "m1",
            1,
            10,
            Some(0),
            BTreeSet::from(["r0".into()]),
            BTreeSet::from(["r0".into()]),
            None,
        ),
    ];
    BurnCase {
        burn: burn::BurnInput {
            address_space: "opaque-fixture".into(),
            edition: "edition-1".into(),
            sample_convention: "settled-boundary".into(),
            boundary: 2,
            read_addresses: BTreeSet::from([address.clone()]),
            amounts: BTreeMap::from([(address, amount)]),
            bootstrap: Some(burn::Bootstrap {
                bound: bootstrap,
                empty_interval: true,
                explanation: "external acquisition starts at opening".into(),
            }),
            unit_cost: Some(cost),
            evidence: burn::BurnEvidence {
                edition: "edition-1".into(),
                sample_convention: "settled-boundary".into(),
                settlement_depth: Some(6),
                finality_assumptions: Some("fixture assumption, not chain evidence".into()),
                provenance: Some("public fixture proof profile".into()),
                recording_costs: Some(vec![]),
                operator: Some(burn::OperatorEvidence::Absent {
                    explanation: "fixture rules grant no operational accrual".into(),
                }),
            },
        },
        policy,
        history: burn::HistoryInput {
            identity: "history".into(),
            records: vec![record],
            markers,
        },
    }
}
struct Prelude {
    raw: BurnCase,
    causes: publication::Causes,
    parameters: pn_epoch::ParameterInput,
    price: pn_records::numerics::ChargedPrice,
    candidate_input: package::CandidateInput,
}

fn prelude(negative: &str) -> Prelude {
    let raw = raw_burn();
    let mut n = numeric();
    let markers = recognized(&raw, &Check::fixed());
    let mut acts = positions(&self_acts());
    acts.sort_by_key(|a| a.id.sequence);
    let history = pn_records::validate_history(&acts, &[]).unwrap();
    let (declaration, edition, mut parameters) = constants_fixture_with_negative(negative);
    for name in parameters.domain_weights.values_mut() {
        *name = "one".into();
    }
    parameters.depth_mass = vec!["one".into()];
    let mut declarations = vec![
        declaration,
        Declaration {
            id: DeclarationId {
                namespace: "marker".into(),
                name: "policy".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: DeclarationContent::MarkerPolicy {
                recipe: "pn-records/marker-policy/v1".into(),
                digest: pn_records::constants::marker_policy_digest(&raw.policy),
            },
        },
        Declaration {
            id: DeclarationId {
                namespace: "deployment".into(),
                name: "genesis".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: DeclarationContent::Deployment { genesis_at: 1 },
        },
    ];
    // These distinct fixture namespaces determine their canonical structural order.
    declarations.sort_by_key(|row| (row.id.namespace.len(), row.id.namespace.clone()));
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let declared = pn_records::validate_record(&[], &empty, &declarations).unwrap();
    let constants = pn_records::constants::bind_constants(&declared, vec![edition.clone()]).unwrap();
    let input = pn_epoch::bind_inputs(&constants, parameters.clone(), construction_limits()).unwrap();
    let wall = n.literal("1/4").unwrap();
    let wall = n.computed(&wall).unwrap();
    let price = n.charged_price(&wall, &edition.numeraire, edition.floor).unwrap();
    let mut sequence = history.acts().to_vec();
    sequence.sort_by_key(ValidatedAct::position);
    let candidate_input = package::CandidateInput {
        causes: package::PackageInput {
            markers: markers.clone(),
            history,
            inputs: vec![input.clone()],
            prices: vec![price.clone()],
            bindings: vec![package::EpochBinding {
                marker: markers.markers()[1].identity().clone(),
                predecessor: markers.markers()[0].identity().clone(),
                inputs: input,
                price: price.clone(),
                sequence: sequence.clone(),
            }],
        },
        closure: package::ClosureStatement {
            policy: package::ClosurePolicy {
                target: 12_u64,
                minimum_ticks: 0,
                maximum_ticks: 12_u64,
                clock: "fixture-clock".into(),
            },
            opened_at: 0,
            determined_at: 12_u64,
            cause: package::ClosureCause::MaximumDuration,
            attestation: "fixture-determination".into(),
        },
    };
    Prelude {
        raw,
        causes: publication::Causes {
            acts,
            names: BTreeSet::new(),
            declarations,
            editions: vec![edition],
        },
        parameters,
        price,
        candidate_input,
    }
}

fn announce(
    state: &pn_epoch::compiler::CompiledState,
    plan: &FinalProcedure,
    d: &admission::ScheduleDeclaration,
) -> schedules::Record {
    let published = Published(plan.solve.clone());
    let bound = bind_procedure(state, plan.solve.clone(), &published, construction_limits()).unwrap();
    let search = pn_epoch::controller::InverseSearch {
        bracket: Range {
            lower: "1/100".into(),
            upper: "1".into(),
        },
        stopping_width: "1/16".into(),
        maximum_steps: 8_u64,
    };
    schedules::evaluate(
        d,
        &[schedules::Boundary {
            completed: &bound,
            search: &search,
            announced_at: 1,
            effective_at: 2,
            policy_floor: None,
        }],
        None,
        construction_limits(),
    )
    .unwrap()
}
#[tracing::instrument(
    name = "amend:storage:fixture-replay-interface",
    fields(
        execution_owner = "FIXTURES",
        claim_owner = "ROOT",
        claim_label = "amend:storage:fixture-replay-interface",
        operation = "fixture-construct",
        source_item = "root::fixture"
    ),
    ret
)]
pub(super) fn fixture() -> (ClosedBoundary, Carrier, Check) {
    fixture_with_negative("-1/3")
}

#[cfg(test)]
pub(super) fn altered_constant_fixture() -> (ClosedBoundary, Carrier, Check) {
    fixture_with_negative("-1/2")
}

fn fixture_with_negative(negative: &str) -> (ClosedBoundary, Carrier, Check) {
    let Prelude {
        raw,
        causes: public_causes,
        parameters,
        price,
        candidate_input,
    } = prelude(negative);
    let causes = Causes(candidate_input.clone());
    let candidate = package::verify_candidate(candidate_input.clone(), &causes, &causes).unwrap();
    let plan = procedure(&candidate);
    let declaration = schedule(&candidate, "1/4").record().declaration.clone();
    let d = admission::declare_schedule(declaration, construction_limits()).unwrap();
    let initial = schedules::evaluate(&d, &[], None, construction_limits()).unwrap();
    let led = schedules::replay(&d, &[], None, construction_limits(), &initial).unwrap();
    let admitted = run(&candidate, &plan, &led).unwrap();
    let partition = closure::partition(&candidate).unwrap();
    let closed = closure::close(
        &ClosureInput {
            candidate: &candidate,
            partition: &partition,
            schedule: &led,
            previous: None,
        },
        &plan,
        &RawVerifier,
        &Published(plan.solve.clone()),
        numeric(),
    )
    .unwrap();
    let state =
        pn_epoch::compiler::compile_admitted(&admitted, &RawVerifier, &mut numeric(), construction_limits(), 10_000_u64).unwrap();
    let next = announce(&state, &plan, &d);
    let numeric = NumericPolicy {
        arithmetic: declared_limits(),
        comparison_attempts: u32::try_from(4_u64).unwrap(),
        comparison_work: 100_000_000_u64,
    };
    let carrier = Carrier {
        causes: public_causes,
        numeric: numeric.clone(),
        frames: vec![Frame {
            realization: realization(),
            burn: raw.burn,
            marker_policy: raw.policy,
            marker_history: raw.history,
            parameters,
            price: price.disclosure(),
            sequence: candidate_input.causes.bindings[0]
                .sequence
                .iter()
                .map(|a| a.id().clone())
                .collect(),
            procedure: plan.clone(),
            compiled: state.view().clone(),
            closure: closed.record().clone(),
            standing: admitted.evidence().standing.clone().unwrap(),
            next,
        }],
    };
    let check = Check::fixed();
    (closed, carrier, check)
}
