use super::base::{
    BTreeSet, Carrier, Causes, ClosedBoundary, ClosureInput, Declaration, DeclarationContent, DeclarationId, FinalProcedure,
    Floor, Frame, Limits, NumericPolicy, OpeningKind, Position, Published, Range, RawVerifier, RegistrationVerifier,
    ValidatedAct, act, admission, bind_procedure, burn, closure, constants_fixture, numeric, package, positions, procedure,
    publication, run, schedule, schedules, self_acts,
};
#[derive(Debug)]
pub(super) struct Check {
    candidates: Vec<package::CandidateInput>,
    bytes: usize,
    procedures: Vec<pn_records::solve::Procedure>,
    numeric: NumericPolicy,
    pub(super) ridge_profile: Option<publication::RidgeReplayProfile>,
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
impl pn_epoch::solve::ProcedureVerifier for Check {
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
                f.realization == realization(self.bytes)
                    && self.procedures.contains(&f.procedure.solve)
                    && f.procedure.arithmetic == Limits::default()
                    && f.procedure.maximum_products == 10_000_u64
            })
    }
    fn disclosure_profile(&self, carrier: &publication::disclosures::Disclosure) -> bool {
        carrier.numeric == self.numeric
            && carrier.frames.iter().all(|f| {
                f.realization == realization(self.bytes)
                    && self.procedures.contains(&f.procedure.solve)
                    && f.procedure.arithmetic == Limits::default()
                    && f.procedure.maximum_products == 10_000_u64
            })
    }
}

fn realization(bytes: usize) -> publication::RealizationEvidence {
    publication::RealizationEvidence {
        edition: "fixture-audit".into(),
        provenance: (0..bytes).map(|i| u8::try_from(i % 251).unwrap()).collect(),
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
    let amount = n.literal("1000").unwrap();
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
    parameters: pn_epoch::ParameterInput,
    price: pn_records::numerics::ChargedPrice,
    candidate_input: package::CandidateInput,
}

fn prelude() -> Prelude {
    let raw = raw_burn();
    let mut n = numeric();
    let markers = pn_records::test_support::burn::recognize(raw.clone()).unwrap();
    let mut acts = positions(&self_acts());
    acts.sort_by_key(|a| a.id.sequence);
    let history = pn_records::validate_history(&acts, &[]).unwrap();
    let (declaration, edition, mut parameters) = constants_fixture();
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
    let input = pn_epoch::bind_inputs(&constants, parameters.clone(), Limits::default()).unwrap();
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
    let bound = bind_procedure(state, plan.solve.clone(), &published, Limits::default()).unwrap();
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
        Limits::default(),
    )
    .unwrap()
}
fn fixture(bytes: usize) -> (ClosedBoundary, Carrier, Check) {
    let Prelude {
        raw,
        causes: public_causes,
        parameters,
        price,
        candidate_input,
    } = prelude();
    let causes = Causes(candidate_input.clone());
    let candidate = package::verify_candidate(candidate_input.clone(), &causes, &causes).unwrap();
    let plan = procedure(&candidate);
    let declaration = schedule(&candidate, "1/4").record().declaration.clone();
    let d = admission::declare_schedule(declaration, Limits::default()).unwrap();
    let initial = schedules::evaluate(&d, &[], None, Limits::default()).unwrap();
    let led = schedules::replay(&d, &[], None, Limits::default(), &initial).unwrap();
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
    let state = pn_epoch::compiler::compile_admitted(
        &admitted,
        &RawVerifier,
        &mut numeric(),
        Limits::default(),
        plan.maximum_products,
    )
    .unwrap();
    let next = announce(&state, &plan, &d);
    let numeric = NumericPolicy {
        arithmetic: Limits::default(),
        comparison_attempts: 1000,
        comparison_work: 100_000_000_u64,
    };
    let carrier = Carrier {
        causes: public_causes,
        numeric: numeric.clone(),
        frames: vec![Frame {
            realization: realization(bytes),
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
        bytes,
        procedures: vec![plan.solve],
        numeric,
        ridge_profile: None,
    };
    (closed, carrier, check)
}
fn successor(
    carrier: &Carrier,
    check: &mut Check,
    closed: &ClosedBoundary,
    led: &schedules::CheckedSchedule,
) -> Result<(Frame, ClosedBoundary, pn_epoch::compiler::CompiledState), String> {
    let mut frame = carrier.frames.last().unwrap().clone();
    let index = carrier.frames.len() + 1;
    let boundary = u64::try_from(index).unwrap();
    let mut marker = frame.marker_history.markers.last().unwrap().clone();
    marker.predecessor = Some(marker.history_position);
    marker.history_position += 1;
    marker.index += 1;
    marker.name = format!("m{boundary}");
    frame.marker_history.markers.push(marker);
    let markers = pn_records::test_support::burn::recognize(pn_records::test_support::burn::BurnCase {
        burn: frame.burn.clone(),
        policy: frame.marker_policy.clone(),
        history: frame.marker_history.clone(),
    })
    .map_err(|error| format!("{error:?}"))?;
    let declarations = pn_records::validate_record(
        &[],
        &pn_records::validate_history(&[], &[]).map_err(|error| format!("{error:?}"))?,
        &carrier.causes.declarations,
    )
    .map_err(|error| format!("{error:?}"))?;
    let constants = pn_records::constants::bind_constants(&declarations, carrier.causes.editions.clone())
        .map_err(|error| format!("{error:?}"))?;
    frame.parameters.boundary = boundary;
    let inputs =
        pn_epoch::bind_inputs(&constants, frame.parameters.clone(), Limits::default()).map_err(|error| format!("{error:?}"))?;
    let mut context = numeric();
    let wall = context
        .literal(&led.record().publications.last().unwrap().effective.wall)
        .map_err(|error| format!("{error:?}"))?;
    let wall = context.computed(&wall).map_err(|error| format!("{error:?}"))?;
    let price = context
        .charged_price(&wall, &inputs.parameters().numeraire, Floor::RationalThreeThirtySevenths)
        .map_err(|error| format!("{error:?}"))?;
    let mut input = check.candidates.last().unwrap().clone();
    input.causes.history = pn_records::validate_history(&carrier.causes.acts, &[]).map_err(|error| format!("{error:?}"))?;
    input.causes.markers = markers.clone();
    input.causes.inputs.push(inputs.clone());
    input.causes.prices.push(price.clone());
    input.causes.bindings.push(package::EpochBinding {
        marker: markers.markers()[index].identity().clone(),
        predecessor: markers.markers()[index - 1].identity().clone(),
        inputs,
        price: price.clone(),
        sequence: input
            .causes
            .history
            .acts()
            .iter()
            .filter(|act| act.position().0 == boundary)
            .cloned()
            .collect(),
    });
    input.closure.opened_at = closed.record().statement.determined_at;
    input.closure.determined_at = input.closure.opened_at + input.closure.policy.maximum_ticks;
    let causes = Causes(input.clone());
    let candidate = package::verify_candidate(input.clone(), &causes, &causes).map_err(|error| format!("{error:?}"))?;
    frame.procedure = procedure(&candidate);
    let partition = closure::partition(&candidate).map_err(|error| format!("{error:?}"))?;
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
    .map_err(|error| format!("{error:?}"))?;
    let admitted = run(&candidate, &frame.procedure, led).map_err(|error| format!("{error:?}"))?;
    let state = pn_epoch::compiler::compile_admitted(
        &admitted,
        &RawVerifier,
        &mut numeric(),
        Limits::default(),
        frame.procedure.maximum_products,
    )
    .map_err(|error| format!("{error:?}"))?;
    frame.sequence = input
        .causes
        .bindings
        .last()
        .unwrap()
        .sequence
        .iter()
        .map(|act| act.id().clone())
        .collect();
    check.candidates.push(input);
    check.procedures.push(frame.procedure.solve.clone());
    let published = Published(frame.procedure.solve.clone());
    let bound = bind_procedure(&state, frame.procedure.solve.clone(), &published, Limits::default())
        .map_err(|error| format!("{error:?}"))?;
    let fence = pn_epoch::fence::search(&bound, None).map_err(|error| format!("{error:?}"))?;
    frame.standing = pn_epoch::conserved::solve(&bound, &fence).map_err(|error| format!("{error:?}"))?;
    frame.price = price.disclosure();
    Ok((frame, second, state))
}
pub(super) fn series(count: usize, bytes: usize) -> Result<(publication::AdmittedPackage, Check), String> {
    assert!(count > 0);
    let (mut closed, mut carrier, mut check) = fixture(bytes);
    let mut admitted = publication::assemble(&closed, carrier.clone(), &check).map_err(|error| format!("{error:?}"))?;
    let mut states = vec![];
    while carrier.frames.len() < count {
        states.push(
            pn_epoch::compiler::compile_admitted(admitted.boundary(), &check, &mut numeric(), Limits::default(), 10_000)
                .map_err(|error| format!("{error:?}"))?,
        );
        let bound: Vec<_> = states
            .iter()
            .zip(&check.procedures)
            .map(|(state, plan)| {
                bind_procedure(state, plan.clone(), &check, Limits::default()).map_err(|error| format!("{error:?}"))
            })
            .collect::<Result<_, _>>()?;
        let old = &carrier.frames.last().unwrap().next;
        let declaration =
            admission::declare_schedule(old.declaration.clone(), Limits::default()).map_err(|error| format!("{error:?}"))?;
        let search = old.publications[0].proposal.search.clone();
        let boundaries: Vec<_> = bound
            .iter()
            .enumerate()
            .map(|(i, completed)| schedules::Boundary {
                completed,
                search: &search,
                announced_at: u64::try_from(i + 1).unwrap(),
                effective_at: u64::try_from(i + 2).unwrap(),
                policy_floor: None,
            })
            .collect();
        let led =
            schedules::replay(&declaration, &boundaries, None, Limits::default(), old).map_err(|error| format!("{error:?}"))?;
        let boundary = u64::try_from(carrier.frames.len() + 1).unwrap();
        for position in 1..=2 {
            let mut next = act("Opinion", "a", (boundary - 1) * 2 + position, boundary);
            next.authoritative_position = position;
            carrier.causes.acts.push(next);
        }
        let (mut frame, next_closed, state) = successor(&carrier, &mut check, &closed, &led)?;
        let final_bound = bind_procedure(&state, frame.procedure.solve.clone(), &check, Limits::default())
            .map_err(|error| format!("{error:?}"))?;
        let mut boundaries = boundaries;
        let index = u64::try_from(count.min(carrier.frames.len() + 1)).unwrap();
        boundaries.push(schedules::Boundary {
            completed: &final_bound,
            search: &search,
            announced_at: index,
            effective_at: index + 1,
            policy_floor: None,
        });
        frame.next =
            schedules::evaluate(&declaration, &boundaries, None, Limits::default()).map_err(|error| format!("{error:?}"))?;
        frame.compiled = state.view().clone();
        frame.closure = next_closed.record().clone();
        carrier.frames.push(frame);
        closed = next_closed;
        admitted = publication::assemble(&closed, carrier.clone(), &check).map_err(|error| format!("{error:?}"))?;
    }
    assert_eq!(admitted.carrier().frames.len(), count);
    assert_eq!(admitted.carrier().causes.acts.len(), count * 2);
    Ok((admitted, check))
}
