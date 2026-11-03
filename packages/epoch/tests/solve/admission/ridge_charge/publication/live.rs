use super::*;
use pn_epoch::live_publication::{self, Error, Response, ResponseVerifier};
use pn_records::live_markers::{LiveVerifier, Status};

fn recognized(
    burn: &burn::BurnInput,
    policy: &burn::PolicyInput,
    history: &burn::HistoryInput,
    declarations: &[Declaration],
) -> burn::RecognizedMarkers {
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let record = pn_records::validate_record(&[], &empty, declarations).unwrap();
    let bound =
        pn_records::constants::bind_marker_policy(&record, policy.clone(), &burn::validate_burn(burn.clone()).unwrap()).unwrap();
    let history =
        burn::validate_marker_history(history.clone(), &bound, &pn_records::test_support::burn::FixtureVerifier).unwrap();
    let markers = burn::recognize_markers(&history);
    assert_eq!(markers.first_refusal(), None);
    markers
}

fn host_prelude(edition: u64) -> Prelude {
    let mut p = prelude(None);
    p.raw.policy.open_placement = false;
    p.raw.policy.placement_procedure = "declared fixture operator".into();
    p.raw.policy.edition = edition.to_string();
    p.raw.policy.sequence = format!("sequence-{edition}");
    p.raw.policy.initial_marker = format!("genesis-{edition}");
    p.raw.policy.published_at = edition - 1;
    p.raw.policy.genesis_at = edition;
    for marker in &mut p.raw.history.markers {
        marker.policy_edition.clone_from(&p.raw.policy.edition);
        marker.sequence.clone_from(&p.raw.policy.sequence);
        if marker.index == 0 {
            marker.name.clone_from(&p.raw.policy.initial_marker);
        }
    }
    for declaration in &mut p.causes.declarations {
        match &mut declaration.content {
            DeclarationContent::MarkerPolicy { recipe, digest } => {
                *recipe = pn_records::constants::HOST_MARKER_POLICY_RECIPE.into();
                *digest = pn_records::constants::marker_policy_digest(&p.raw.policy);
                declaration.id.edition = edition;
                declaration.announced_at = edition - 1;
                declaration.effective_at = edition - 1;
            }
            DeclarationContent::Deployment { genesis_at } => {
                *genesis_at = edition;
            }
            DeclarationContent::Opaque => {}
        }
    }
    let markers = recognized(&p.raw.burn, &p.raw.policy, &p.raw.history, &p.causes.declarations);
    p.candidate_input.causes.markers = markers.clone();
    p.candidate_input.causes.bindings[0].marker = markers.markers()[1].identity().clone();
    p.candidate_input.causes.bindings[0].predecessor = markers.markers()[0].identity().clone();
    p.raw.history.records.reverse();
    p.raw.history.markers.reverse();
    p.causes.declarations.reverse();
    p
}

#[derive(Debug)]
struct Live {
    frames: Vec<Frame>,
    status: Status,
}
impl burn::PublicVerifier for Live {
    fn profile(&self) -> &'static str {
        burn::PublicVerifier::profile(&pn_records::test_support::burn::FixtureVerifier)
    }
    fn destruction(&self, r: &burn::BurnRecord) -> bool {
        pn_records::test_support::burn::FixtureVerifier.destruction(r)
    }
    fn opening(&self, c: &[u8], o: &burn::Opening) -> bool {
        pn_records::test_support::burn::FixtureVerifier.opening(c, o)
    }
}
impl LiveVerifier for Live {
    fn settlement(&self, h: &burn::HistoryInput, p: &burn::PolicyInput, b: &burn::BurnInput, e: &[u8]) -> Status {
        if self.frames.iter().any(|f| {
            &f.marker_history == h && &f.marker_policy == p && &f.burn == b && f.realization.settlement_and_finality == e
        }) {
            self.status
        } else {
            Status::Pending
        }
    }
}
#[derive(Debug)]
struct ResponseCheck {
    old: Carrier,
    replacement: Carrier,
    response: Response,
}
impl live_publication::ResponseVerifier for ResponseCheck {
    fn published_response(&self, old: &Carrier, replacement: &Carrier, response: &Response) -> bool {
        old == &self.old && replacement == &self.replacement && response == &self.response
    }
}
fn live(carrier: &Carrier) -> Live {
    Live {
        frames: carrier.frames.clone(),
        status: Status::Final,
    }
}
fn settled_fixture(edition: u64) -> (ClosedBoundary, Carrier, Check) {
    let Prelude {
        raw,
        causes: public_causes,
        parameters,
        price,
        candidate_input,
    } = host_prelude(edition);
    let causes = Causes(candidate_input.clone());
    let candidate = package::verify_candidate(candidate_input.clone(), &causes, &causes).unwrap();
    let plan = procedure(&candidate);
    let rational = candidate_for_declaration();
    let mut declaration = schedule(&rational, NumberId::NumbersAdmissionWall.value())
        .record()
        .declaration
        .clone();
    declaration.initialization.floor = Some(public_causes.editions[0].floor);
    let d = admission::declare_schedule(declaration, Limits::default()).unwrap();
    let checked: Option<kernel::CheckedRidge> = None;
    let initial = schedules::evaluate(&d, &[], checked.as_ref(), Limits::default()).unwrap();
    let led = schedules::replay(&d, &[], checked.as_ref(), Limits::default(), &initial).unwrap();
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
        &joined::Verifier,
        &Published(plan.solve.clone()),
        joined::numeric(),
    )
    .unwrap();
    let state = pn_epoch::compiler::compile_admitted(
        &admitted,
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        plan.maximum_products,
    )
    .unwrap();
    let next = announce(&state, &plan, &d, checked.as_ref());
    let numeric = NumericPolicy {
        arithmetic: Limits::default(),
        comparison_attempts: u32::try_from(NumberId::PublicationComparisonAttemptCeiling.integer()).unwrap(),
        comparison_work: NumberId::PublicationComparisonWorkCeiling.integer(),
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
    };
    (closed, carrier, check)
}
fn live_successor(
    carrier: &Carrier,
    check: &mut Check,
    closed: &ClosedBoundary,
    led: &schedules::CheckedSchedule,
) -> (Frame, ClosedBoundary, pn_epoch::compiler::CompiledState) {
    let mut frame = carrier.frames[0].clone();
    let mut marker = frame.marker_history.markers.iter().max_by_key(|m| m.index).unwrap().clone();
    marker.predecessor = Some(marker.history_position);
    marker.history_position += 1;
    marker.index += 1;
    marker.name = "m2".into();
    frame.marker_history.markers.push(marker);
    let markers = recognized(
        &frame.burn,
        &frame.marker_policy,
        &frame.marker_history,
        &carrier.causes.declarations,
    );
    let declarations = pn_records::validate_record(
        &[],
        &pn_records::validate_history(&[], &[]).unwrap(),
        &carrier.causes.declarations,
    )
    .unwrap();
    let constants = pn_records::constants::bind_constants(&declarations, carrier.causes.editions.clone()).unwrap();
    frame.parameters.boundary = 2;
    let inputs = pn_epoch::bind_inputs(&constants, frame.parameters.clone(), Limits::default()).unwrap();
    let mut numeric = joined::numeric();
    let wall = numeric.literal(&led.record().publications[0].effective.wall).unwrap();
    let wall = numeric.computed(&wall).unwrap();
    let price = numeric
        .charged_price(&wall, &inputs.parameters().numeraire, Floor::RationalThreeThirtySevenths)
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
        &joined::Verifier,
        &Published(frame.procedure.solve.clone()),
        joined::numeric(),
    )
    .unwrap();
    let admitted = run(&candidate, &frame.procedure, led).unwrap();
    let state = pn_epoch::compiler::compile_admitted(
        &admitted,
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        frame.procedure.maximum_products,
    )
    .unwrap();
    check.candidates.push(input);
    check.procedures.push(frame.procedure.solve.clone());
    let published = Published(frame.procedure.solve.clone());
    let bound = bind_procedure(&state, frame.procedure.solve.clone(), &published, Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    frame.standing = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    frame.price = price.disclosure();
    (frame, second, state)
}

fn two_boundaries() -> (Carrier, Check) {
    let (closed, mut carrier, mut check) = settled_fixture(1);
    let first = publication::assemble(&closed, carrier.clone(), &check).unwrap();
    let first_state = pn_epoch::compiler::compile_admitted(
        first.boundary(),
        &check,
        &mut joined::numeric(),
        Limits::default(),
        NumberId::NumbersAdmissionProductCeiling.integer(),
    )
    .unwrap();
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
        None,
        Limits::default(),
        &old.next,
    )
    .unwrap();
    let (mut frame, second, state) = live_successor(&carrier, &mut check, &closed, &led);
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
        None,
        Limits::default(),
    )
    .unwrap();
    frame.sequence.clear();
    frame.compiled = state.view().clone();
    frame.closure = second.record().clone();
    carrier.frames.push(frame);
    (carrier, check)
}

/// Claim: The finite host-only complete prefix closes one marker once, retains original disclosures and empty-increment snapshots, and independently rechecks each live assessment and admission. Skipped, repeated, copied and pending proposals refuse under a declared verifier, not a real chain or offline authenticator.
/// ´claim:admission:live-publication-retains-marker-registration´
/// ´test:integration:live-publication-prefix´
#[test]
fn live_publication_prefix() {
    let (carrier, check) = two_boundaries();
    let service = live(&carrier);
    let mut prefix = carrier.clone();
    prefix.frames.pop();
    let mut pending_marker = prefix.clone();
    pending_marker.frames[0].marker_history = carrier.frames[1].marker_history.clone();
    let pending_frame = &mut pending_marker.frames[0];
    pending_frame.closure.markers = recognized(
        &pending_frame.burn,
        &pending_frame.marker_policy,
        &pending_frame.marker_history,
        &pending_marker.causes.declarations,
    );
    let pending_service = live(&pending_marker);
    let pending_epoch = live_publication::consume(pending_marker.clone(), &check, &pending_service).unwrap();
    assert_eq!(pending_epoch.closed().carrier().frames.len(), prefix.frames.len());
    assert_eq!(
        pending_epoch.closed().carrier().frames[0].closure.markers.markers().len(),
        prefix.frames[0].closure.markers.markers().len() + 1
    );
    assert_eq!(
        pending_epoch.closed().carrier().frames[0].closure.final_gates,
        prefix.frames[0].closure.final_gates
    );
    assert_eq!(
        pending_epoch.closed().carrier().frames[0].closure.bindings,
        prefix.frames[0].closure.bindings
    );
    let mut first = live_publication::consume(prefix.clone(), &check, &service).unwrap();
    let second = first.successor(carrier.clone(), &check, &service).unwrap();
    assert_eq!(second.closed().carrier(), &carrier);
    assert_eq!(first.closed().carrier(), &prefix);
    assert_eq!(
        carrier.frames[0].compiled.ledger.snapshots[0],
        carrier.frames[1].compiled.ledger.snapshots[0]
    );
    assert!(carrier.frames[1].compiled.ledger.snapshots[1].increment.is_empty());
    assert_eq!(
        carrier.frames[0].compiled.ledger.snapshots[0].gross,
        carrier.frames[1].compiled.ledger.snapshots[1].gross
    );
    assert!(matches!(
        first.successor(prefix.clone(), &check, &service),
        Err(Error::Prefix)
    ));
    let mut skip = carrier.clone();
    skip.frames.push(carrier.frames[1].clone());
    assert!(matches!(first.successor(skip, &check, &service), Err(Error::Prefix)));
    let mut changed = carrier.clone();
    changed.frames[0].marker_history.markers[0].name.push_str("-copy");
    assert!(matches!(first.successor(changed, &check, &service), Err(Error::Prefix)));
    let pending = Live {
        frames: carrier.frames.clone(),
        status: Status::Pending,
    };
    assert!(matches!(
        first.successor(carrier.clone(), &check, &pending),
        Err(Error::Live(pn_records::live_markers::Error::Pending))
    ));
    assert!(!first.halted());
    assert_eq!(first.closed().carrier(), &prefix);
    let mut doubled = carrier.clone();
    let gross = &mut doubled.frames[1].compiled.ledger.snapshots[1].gross;
    let amount = gross.values_mut().next().unwrap();
    let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    let value = nrz_cas::Rational::parse(amount.exact(), &mut budget).unwrap();
    let sum = value.add(&value, &mut budget).unwrap().exact_string(&mut budget).unwrap();
    let mut numeric = joined::numeric();
    let literal = numeric.literal(&sum).unwrap();
    *amount = numeric.burn(&literal, amount.unit()).unwrap();
    assert!(matches!(
        live_publication::consume(doubled, &check, &service),
        Err(Error::Publication(error)) if matches!(error.as_ref(), publication::Error::Structure("changed compiled section"))
    ));
    let mut missing = prefix;
    missing.frames[0].realization.settlement_and_finality.clear();
    assert!(matches!(
        live_publication::consume(missing, &check, &service),
        Err(Error::Live(pn_records::live_markers::Error::MissingEvidence))
    ));
}

fn check_response(state: &live_publication::LiveState, old: &Carrier, replacement: &Carrier, check: &Check, response: &Response) {
    let service = live(replacement);
    let verifier = ResponseCheck {
        old: old.clone(),
        replacement: replacement.clone(),
        response: response.clone(),
    };
    let restored = state
        .respond(replacement.clone(), response.clone(), check, &service, &verifier)
        .unwrap();
    assert_eq!(restored.closed().carrier(), replacement);
    assert_eq!(restored.response(), Some(response));
    assert!(!restored.halted());
}

fn response_policy_refusals(
    state: &live_publication::LiveState,
    carrier: &Carrier,
    replacement: &Carrier,
    replacement_check: &Check,
    response: &Response,
) {
    let mut old_initial = replacement.clone();
    old_initial.frames[0]
        .marker_policy
        .initial_marker
        .clone_from(&carrier.frames[0].marker_policy.initial_marker);
    let mut non_later = replacement.clone();
    non_later.frames[0].marker_policy.published_at = carrier.frames[0].marker_policy.published_at;
    let mut unchanged_sequence = replacement.clone();
    unchanged_sequence.frames[0]
        .marker_policy
        .sequence
        .clone_from(&carrier.frames[0].marker_policy.sequence);
    let late_divergence = Response::Follow {
        divergence: carrier.frames.len(),
        superseded: vec![],
        continuity: b"explicit ledger continuity".to_vec(),
        publication: b"published new policy".to_vec(),
    };
    for (invalid, response) in [
        (old_initial, response.clone()),
        (non_later, response.clone()),
        (unchanged_sequence, response.clone()),
        (replacement.clone(), late_divergence),
    ] {
        let permits = ResponseCheck {
            old: carrier.clone(),
            replacement: invalid.clone(),
            response: response.clone(),
        };
        assert!(permits.published_response(carrier, &invalid, &response));
        assert!(matches!(
            state.respond(invalid.clone(), response, replacement_check, &live(&invalid), &permits),
            Err(Error::Response)
        ));
    }
}

/// Claim: In the declared live fixture a lost final marker freezes the complete last closed package and prevents same-policy continuation. Re-anchor and follow are separate explicitly published new-policy responses, replaying replacement admission while preserving the old package and the exact supersession list; no real-chain finality or automatic Layer-1 repair is claimed.
/// ´claim:admission:finality-loss-freezes-live-publication´
/// ´test:integration:live-publication-breach´
#[test]
fn live_publication_breach() {
    let (_, carrier, check) = settled_fixture(1);
    let service = live(&carrier);
    let mut state = live_publication::consume(carrier.clone(), &check, &service).unwrap();
    let lost = Live {
        frames: carrier.frames.clone(),
        status: Status::Lost,
    };
    assert!(matches!(state.refresh(&lost), Err(Error::Halted)));
    assert!(state.halted());
    assert_eq!(state.closed().carrier(), &carrier);
    assert!(matches!(
        state.successor(carrier.clone(), &check, &service),
        Err(Error::Halted)
    ));
    assert!(matches!(state.refresh(&service), Err(Error::Halted)));
    let response = Response::Reanchor {
        continuity: b"explicit ledger continuity".to_vec(),
        publication: b"published new policy".to_vec(),
    };
    let same = ResponseCheck {
        old: carrier.clone(),
        replacement: carrier.clone(),
        response: response.clone(),
    };
    assert!(matches!(
        state.respond(carrier.clone(), response.clone(), &check, &service, &same),
        Err(Error::Response)
    ));
    let (_, replacement, replacement_check) = settled_fixture(2);
    let new_service = live(&replacement);
    check_response(&state, &carrier, &replacement, &replacement_check, &response);
    let follow = Response::Follow {
        divergence: 0,
        superseded: vec![carrier.frames[0].closure.clone()],
        continuity: b"explicit ledger continuity".to_vec(),
        publication: b"published new policy".to_vec(),
    };
    check_response(&state, &carrier, &replacement, &replacement_check, &follow);
    response_policy_refusals(&state, &carrier, &replacement, &replacement_check, &response);
    assert_eq!(state.closed().carrier(), &carrier);
    let Response::Follow {
        mut superseded,
        continuity,
        publication,
        ..
    } = follow
    else {
        unreachable!()
    };
    superseded.clear();
    for refused in [
        Response::Follow {
            divergence: 0,
            superseded,
            continuity,
            publication,
        },
        Response::Reanchor {
            continuity: vec![],
            publication: b"published new policy".to_vec(),
        },
    ] {
        let permits = ResponseCheck {
            old: carrier.clone(),
            replacement: replacement.clone(),
            response: refused.clone(),
        };
        assert!(permits.published_response(&carrier, &replacement, &refused));
        assert!(matches!(
            state.respond(replacement.clone(), refused, &replacement_check, &new_service, &permits),
            Err(Error::Response)
        ));
    }
}

/// Claim: In the finite delayed-acceptance fixture the ledger's snapshot sums each canonical destruction at its first accepted marker, including an older lineage member, and counts an alias only once. A later empty increment and changed read-time totals do not rewrite these gross snapshots. External destruction and finality remain verifier premises.
/// ´claim:admission:live-snapshots-use-first-accepted-increments´
/// ´test:integration:live-marker-snapshots´
#[test]
fn live_marker_snapshots() {
    let p = prelude(None);
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let records = pn_records::validate_record(&[], &empty, &p.causes.declarations).unwrap();
    let constants = pn_records::constants::bind_constants(&records, p.causes.editions).unwrap();
    let mut inputs = vec![];
    for boundary in 1..=3 {
        let mut parameters = p.parameters.clone();
        parameters.boundary = boundary;
        inputs.push(pn_epoch::bind_inputs(&constants, parameters, Limits::default()).unwrap());
    }
    let mut raw = pn_records::test_support::burn::generate(&[]);
    let address = raw.history.records[0].address.clone();
    let amount = raw.history.records[0].amount.clone();
    let mut last = raw.history.markers[2].clone();
    last.name = "empty-increment".into();
    last.predecessor = Some(last.history_position);
    last.history_position += 1;
    last.index += 1;
    raw.history.markers.push(last);
    raw.history.markers.reverse();
    raw.history.records.reverse();
    let markers = pn_records::test_support::burn::recognize(raw.clone()).unwrap();
    let compile = |markers: &burn::RecognizedMarkers| {
        pn_epoch::ledger::compile_ledger(
            &inputs,
            &vec![p.price.clone(); inputs.len()],
            markers,
            &empty,
            &joined::Verifier,
            &mut joined::numeric(),
            Limits::default(),
        )
        .unwrap()
    };
    let ledger = compile(&markers);
    assert_eq!(ledger.snapshots[0].increment[&address], amount);
    assert_eq!(ledger.snapshots[1].increment[&address], amount);
    let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    let one = nrz_cas::Rational::parse(amount.exact(), &mut budget).unwrap();
    let sum = one.add(&one, &mut budget).unwrap().exact_string(&mut budget).unwrap();
    assert_eq!(ledger.snapshots[1].gross[&address].exact(), sum);
    assert!(ledger.snapshots[2].increment.is_empty());
    assert_eq!(ledger.snapshots[2].gross, ledger.snapshots[1].gross);
    assert!(ledger.debits.is_empty());
    assert_ne!(raw.burn.amounts[&address], p.raw.burn.amounts[&burn::Address("a".into())]);
    raw.burn
        .amounts
        .insert(address, p.raw.burn.amounts[&burn::Address("a".into())].clone());
    let changed = pn_records::test_support::burn::recognize(raw).unwrap();
    assert_eq!(compile(&changed), ledger);
}
