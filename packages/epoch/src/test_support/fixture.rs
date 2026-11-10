use super::base::{
    BTreeSet, Carrier, Causes, ClosedBoundary, ClosureInput, Declaration, DeclarationContent, DeclarationId, FinalProcedure,
    Floor, Frame, Limits, NumericPolicy, OpeningKind, Position, Precision, Published, Range, RawVerifier, RegistrationVerifier,
    ValidatedAct, admission, bind_procedure, burn, closure, compiled, constants_fixture, d, fence_procedure, numeric, package,
    positions, procedure, publication, run, schedule, schedules, self_acts,
};
use pn_graph::numeric::ridge as kernel;
use pn_records::ridge::ChargeEvidence;
/// Finite synthetic verifier paired with the epoch-owned disclosure fixture.
/// It is not a deployment authentication verifier.
/// (´def:admission:test-support´)
#[derive(Debug)]
pub struct Check {
    candidates: Vec<package::CandidateInput>,
    procedures: Vec<pn_records::solve::Procedure>,
    numeric: NumericPolicy,
    ridge_profile: Option<publication::RidgeReplayProfile>,
}
impl burn::PublicVerifier for Check {
    fn profile(&self) -> &'static str {
        burn::PublicVerifier::profile(&pn_records::test_support::burn::FixtureVerifier)
    }
    fn destruction(&self, record: &burn::BurnRecord) -> bool {
        pn_records::test_support::burn::FixtureVerifier.destruction(record)
    }
    fn opening(&self, commitment: &[u8], opening: &burn::Opening) -> bool {
        pn_records::test_support::burn::FixtureVerifier.opening(commitment, opening)
    }
}
impl RegistrationVerifier for Check {
    fn approval(&self, act: &ValidatedAct) -> bool {
        RawVerifier.approval(act)
    }
    fn removal(&self, act: &ValidatedAct, kind: OpeningKind, position: Position) -> bool {
        RawVerifier.removal(act, kind, position)
    }
}
impl package::CandidateVerifier for Check {
    fn candidate_causes(&self, input: &package::CandidateInput) -> bool {
        let ordered = |history: &pn_records::ValidatedHistory| {
            let mut acts = history.acts().to_vec();
            acts.sort_by_key(|act| act.id().clone());
            acts
        };
        self.candidates.iter().any(|candidate| {
            input.causes.bindings == candidate.causes.bindings
                && input.causes.inputs == candidate.causes.inputs
                && input.causes.prices == candidate.causes.prices
                && ordered(&input.causes.history) == ordered(&candidate.causes.history)
        })
    }
}
impl package::ClosureVerifier for Check {
    fn host_determination(&self, input: &package::CandidateInput) -> bool {
        self.candidates.iter().any(|candidate| input.closure == candidate.closure)
    }
}
impl crate::solve::ProcedureVerifier for Check {
    fn published_procedure(&self, procedure: &pn_records::solve::Procedure) -> bool {
        self.procedures.contains(procedure)
    }
}
impl publication::Verifier for Check {
    fn ridge_charge_profile(&self, _: u64) -> Option<&publication::RidgeReplayProfile> {
        self.ridge_profile.as_ref()
    }
    fn publication_profile(&self, carrier: &Carrier) -> bool {
        carrier.numeric == self.numeric
            && carrier.frames.iter().all(|f| {
                f.realization == realization()
                    && self.procedures.contains(&f.procedure.solve)
                    && f.procedure.arithmetic == Limits::default()
                    && f.procedure.maximum_products == 10_000_u64
            })
    }
    fn disclosure_profile(&self, carrier: &publication::disclosures::Disclosure) -> bool {
        carrier.numeric == self.numeric
            && carrier.frames.iter().all(|f| {
                f.realization == realization()
                    && self.procedures.contains(&f.procedure.solve)
                    && f.procedure.arithmetic == Limits::default()
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
fn raw_burn() -> pn_records::test_support::burn::BurnCase {
    let mut raw = pn_records::test_support::burn::generate(&[0]);
    let mut n = numeric();
    let amount = n.literal("30").unwrap();
    let amount = n.burn(&amount, "burn").unwrap();
    let mut record = raw.history.records[0].clone();
    record.address = burn::Address("a".into());
    record.amount = amount.clone();
    record.evidence = format!(
        "{}:{}:{}:{}",
        record.destruction,
        record.address.0,
        record.amount.exact(),
        record.amount.unit()
    )
    .into_bytes();
    raw.burn.read_addresses = BTreeSet::from([record.address.clone()]);
    raw.burn.amounts = std::collections::BTreeMap::from([(record.address.clone(), amount)]);
    raw.history.records = vec![record];
    raw.history.markers.truncate(2);
    let members = BTreeSet::from([raw.history.records[0].identity.clone()]);
    raw.history.markers[1].lineage.clone_from(&members);
    raw.history.markers[1].accepted = burn::AcceptedSet::CompleteList(members);
    raw
}
struct Prelude {
    raw: pn_records::test_support::burn::BurnCase,
    causes: publication::Causes,
    parameters: crate::ParameterInput,
    price: pn_records::numerics::ChargedPrice,
    candidate_input: package::CandidateInput,
}

fn append_ridge_declaration(declarations: &mut Vec<Declaration>, evidence: Option<&ChargeEvidence>) {
    if let Some(e) = evidence {
        declarations.push(Declaration {
            id: e.procedure.edition.clone(),
            announced_at: 0,
            effective_at: 1,
            content: DeclarationContent::Opaque,
        });
    }
}

fn prelude(evidence: Option<&ChargeEvidence>) -> Prelude {
    let raw = raw_burn();
    let mut n = numeric();
    let markers = pn_records::test_support::burn::recognize(raw.clone()).unwrap();
    let mut acts = positions(&self_acts());
    acts.sort_by_key(|a| a.id.sequence);
    let history = pn_records::validate_history(&acts, &[]).unwrap();
    let (declaration, mut edition, mut parameters) = constants_fixture();
    if evidence.is_some() {
        edition.floor = Floor::RidgeImage;
    }
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
    append_ridge_declaration(&mut declarations, evidence);
    // These distinct fixture namespaces determine their canonical structural order.
    declarations.sort_by_key(|row| (row.id.namespace.len(), row.id.namespace.clone()));
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let declared = pn_records::validate_record(&[], &empty, &declarations).unwrap();
    let constants = pn_records::constants::bind_constants(&declared, vec![edition.clone()]).unwrap();
    let input = crate::bind_inputs(&constants, parameters.clone(), Limits::default()).unwrap();
    let wall = n.literal("1/4").unwrap();
    let wall = n.computed(&wall).unwrap();
    let price = match evidence {
        Some(e) => n
            .charged_price_with_ridge(&wall, &edition.numeraire, e, &kernel::ChargeReplay)
            .unwrap(),
        None => n.charged_price(&wall, &edition.numeraire, edition.floor).unwrap(),
    };
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
    state: &crate::compiler::CompiledState,
    plan: &FinalProcedure,
    d: &admission::ScheduleDeclaration,
    ridge: &kernel::CheckedRidge,
) -> schedules::Record {
    let published = Published(plan.solve.clone());
    let bound = bind_procedure(state, plan.solve.clone(), &published, Limits::default()).unwrap();
    let search = crate::controller::InverseSearch {
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
        Some(ridge),
        Limits::default(),
    )
    .unwrap()
}
fn fixture(evidence: &ChargeEvidence) -> (ClosedBoundary, Carrier, Check, crate::compiler::CompiledState) {
    let Prelude {
        raw,
        causes: public_causes,
        parameters,
        price,
        candidate_input,
    } = prelude(Some(evidence));
    let causes = Causes(candidate_input.clone());
    let candidate = package::verify_candidate(candidate_input.clone(), &causes, &causes).unwrap();
    let plan = procedure(&candidate);
    let rational = prelude(None).candidate_input;
    let causes = Causes(rational.clone());
    let rational = package::verify_candidate(rational, &causes, &causes).unwrap();
    let mut declaration = schedule(&rational, "1/4").record().declaration.clone();
    declaration.initialization.floor = Some(Floor::RidgeImage);
    let ridge = kernel::replay(&evidence.procedure, &evidence.input, &evidence.record).unwrap();
    let d = admission::declare_schedule(declaration, Limits::default()).unwrap();
    let initial = schedules::evaluate(&d, &[], Some(&ridge), Limits::default()).unwrap();
    let led = schedules::replay(&d, &[], Some(&ridge), Limits::default(), &initial).unwrap();
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
    let state = crate::compiler::compile_admitted(
        &admitted,
        &RawVerifier,
        &mut numeric(),
        Limits::default(),
        plan.maximum_products,
    )
    .unwrap();
    let next = announce(&state, &plan, &d, &ridge);
    let numeric = NumericPolicy {
        arithmetic: Limits::default(),
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
    let check = Check {
        candidates: vec![candidate_input],
        procedures: vec![plan.solve],
        numeric,
        ridge_profile: Some(publication::RidgeReplayProfile {
            procedure: evidence.procedure.clone(),
            maximum_depth: evidence.input.maximum_depth,
            maximum_work: evidence.input.maximum_work,
            maximum_replay_work: evidence.input.maximum_replay_work,
        }),
    };
    (closed, carrier, check, state)
}
fn successor(
    carrier: &Carrier,
    check: &mut Check,
    closed: &ClosedBoundary,
    led: &schedules::CheckedSchedule,
    evidence: &ChargeEvidence,
) -> (Frame, ClosedBoundary, crate::compiler::CompiledState) {
    let mut frame = carrier.frames[0].clone();
    let mut marker = frame.marker_history.markers[1].clone();
    marker.predecessor = Some(marker.history_position);
    marker.history_position += 1;
    marker.index += 1;
    marker.name = "m2".into();
    frame.marker_history.markers.push(marker);
    let markers = pn_records::test_support::burn::recognize(pn_records::test_support::burn::BurnCase {
        burn: frame.burn.clone(),
        policy: frame.marker_policy.clone(),
        history: frame.marker_history.clone(),
    })
    .unwrap();
    let declarations = pn_records::validate_record(
        &[],
        &pn_records::validate_history(&[], &[]).unwrap(),
        &carrier.causes.declarations,
    )
    .unwrap();
    let constants = pn_records::constants::bind_constants(&declarations, carrier.causes.editions.clone()).unwrap();
    frame.parameters.boundary = 2;
    let inputs = crate::bind_inputs(&constants, frame.parameters.clone(), Limits::default()).unwrap();
    let mut context = numeric();
    let wall = context.literal(&led.record().publications[0].effective.wall).unwrap();
    let wall = context.computed(&wall).unwrap();
    let price = context
        .charged_price_with_ridge(&wall, &inputs.parameters().numeraire, evidence, &kernel::ChargeReplay)
        .unwrap();
    let mut input = check.candidates[0].clone();
    input.causes.markers = markers.clone();
    input.causes.inputs.push(inputs.clone());
    input.causes.prices.push(price.clone());
    input.causes.bindings.push(package::EpochBinding {
        marker: markers.markers()[2].identity().clone(),
        predecessor: markers.markers()[1].identity().clone(),
        inputs,
        price: price.clone(),
        sequence: vec![],
    });
    input.closure.opened_at = closed.record().statement.determined_at;
    input.closure.determined_at = input.closure.opened_at + input.closure.policy.maximum_ticks;
    let causes = Causes(input.clone());
    let candidate = package::verify_candidate(input.clone(), &causes, &causes).unwrap();
    frame.procedure = procedure(&candidate);
    let partition = closure::partition(&candidate).unwrap();
    let second = closure::close(
        &ClosureInput {
            candidate: &candidate,
            partition: &partition,
            schedule: led,
            previous: Some(closed),
        },
        &frame.procedure,
        &RawVerifier,
        &Published(frame.procedure.solve.clone()),
        numeric(),
    )
    .unwrap();
    let admitted = run(&candidate, &frame.procedure, led).unwrap();
    let state = crate::compiler::compile_admitted(
        &admitted,
        &RawVerifier,
        &mut numeric(),
        Limits::default(),
        frame.procedure.maximum_products,
    )
    .unwrap();
    check.candidates.push(input);
    check.procedures.push(frame.procedure.solve.clone());
    let published = Published(frame.procedure.solve.clone());
    let bound = bind_procedure(&state, frame.procedure.solve.clone(), &published, Limits::default()).unwrap();
    let fence = crate::fence::search(&bound, None).unwrap();
    frame.standing = crate::conserved::solve(&bound, &fence).unwrap();
    frame.price = price.disclosure();
    (frame, second, state)
}
pub(super) fn complete() -> (d::Disclosure, Check) {
    let evidence = proof();
    let ridge = kernel::replay(&evidence.procedure, &evidence.input, &evidence.record).unwrap();
    let (closed, mut carrier, mut check, first_state) = fixture(&evidence);
    let first_bound = bind_procedure(&first_state, check.procedures[0].clone(), &check, Limits::default()).unwrap();
    let old = &carrier.frames[0];
    let d = admission::declare_schedule(old.next.declaration.clone(), Limits::default()).unwrap();
    let search = old.next.publications[0].proposal.search.clone();
    let led = schedules::replay(
        &d,
        &[schedules::Boundary {
            completed: &first_bound,
            search: &search,
            announced_at: 1,
            effective_at: 2,
            policy_floor: None,
        }],
        Some(&ridge),
        Limits::default(),
        &old.next,
    )
    .unwrap();
    let (mut frame, second, state) = successor(&carrier, &mut check, &closed, &led, &evidence);
    let bound = bind_procedure(&state, frame.procedure.solve.clone(), &check, Limits::default()).unwrap();
    frame.next = schedules::evaluate(
        &d,
        &[
            schedules::Boundary {
                completed: &first_bound,
                search: &search,
                announced_at: 1,
                effective_at: 2,
                policy_floor: None,
            },
            schedules::Boundary {
                completed: &bound,
                search: &search,
                announced_at: 2,
                effective_at: 3,
                policy_floor: None,
            },
        ],
        Some(&ridge),
        Limits::default(),
    )
    .unwrap();
    frame.sequence.clear();
    frame.compiled = state.view().clone();
    frame.closure = second.record().clone();
    carrier.frames.push(frame);
    let disclosed = d::Disclosure {
        causes: carrier.causes.clone(),
        numeric: carrier.numeric.clone(),
        frames: carrier.frames.iter().map(d::fixture_frame).collect(),
    };
    (disclosed, check)
}

fn proof() -> ChargeEvidence {
    let input = prelude(None).candidate_input;
    let causes = Causes(input.clone());
    let candidate = package::verify_candidate(input, &causes, &causes).unwrap();
    let mut p = fence_procedure(&compiled(&candidate));
    // The charge's selected procedure is distinct from the standing procedure.
    p.edition = DeclarationId {
        namespace: "ridge".into(),
        name: "charge-evidence".into(),
        edition: 1,
    };
    // Existing epoch ridge fixture: num:numbers:solve-work-ceiling.
    p.maximum_work = 200_000_000;
    p.maximum_solve_work = 200_000_000;
    p.maximum_replay_work = 200_000_000;
    p.enclosure.as_mut().unwrap().store.work = 200_000_000;
    p.enclosure.as_mut().unwrap().operation.work = 200_000_000;
    p.precision = Precision::AbsoluteWidthBits(vec![21]);
    p.enclosure.as_mut().unwrap().refinement.precision = 21;
    let input = pn_records::ridge::Inputs {
        definition: pn_records::ridge::Definition {
            schema: "clean-elasticity-ridge-v1".into(),
            inverse_temperature: "2*ln(2)".into(),
            bleed_squared: "0".into(),
            core_power: "1".into(),
        },
        bracket: Range {
            lower: "679/10000".into(),
            upper: "17/250".into(),
        },
        maximum_depth: 8,
        maximum_work: 2_000_000_000,
        maximum_replay_work: 2_000_000_000,
    };
    let record = kernel::evaluate(&p, &input).unwrap();
    assert!(record.image.is_some());
    ChargeEvidence {
        analytic_premises: "clean-ridge-analytic-v1".into(),
        procedure: p,
        input,
        record,
    }
}
