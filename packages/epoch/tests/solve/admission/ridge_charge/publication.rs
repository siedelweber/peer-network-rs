use super::*;
use pn_epoch::publication::{self, Carrier, Frame, NumericPolicy};
use pn_graph::registration::{OpeningKind, RegistrationVerifier};
use pn_records::{Declaration, DeclarationContent, DeclarationId, Position, ValidatedAct, burn};
use std::collections::BTreeSet;

#[derive(Debug)]
struct Check {
    candidates: Vec<package::CandidateInput>,
    procedures: Vec<pn_records::solve::Procedure>,
    numeric: NumericPolicy,
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
        joined::Verifier.approval(act)
    }
    fn removal(&self, act: &ValidatedAct, kind: OpeningKind, position: Position) -> bool {
        joined::Verifier.removal(act, kind, position)
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
    fn publication_profile(&self, carrier: &Carrier) -> bool {
        carrier.numeric == self.numeric
            && carrier.frames.iter().all(|f| {
                f.realization == realization()
                    && self.procedures.contains(&f.procedure.solve)
                    && f.procedure.arithmetic == Limits::default()
                    && f.procedure.maximum_products == NumberId::NumbersAdmissionProductCeiling.integer()
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
    let mut n = joined::numeric();
    let amount = n.literal(NumberId::NumbersAdmissionRepeatedBurn.value()).unwrap();
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

fn prelude(evidence: Option<&ChargeEvidence>) -> Prelude {
    let raw = raw_burn();
    let mut n = joined::numeric();
    let markers = pn_records::test_support::burn::recognize(raw.clone()).unwrap();
    let acts = joined::positions(&self_acts());
    let history = pn_records::validate_history(&acts, &[]).unwrap();
    let (declaration, mut edition, mut parameters) = common::fixture();
    for name in parameters.domain_weights.values_mut() {
        *name = "one".into();
    }
    parameters.depth_mass = vec!["one".into()];
    if evidence.is_some() {
        edition.floor = Floor::RidgeImage;
    }
    let declarations = vec![
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
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let declared = pn_records::validate_record(&[], &empty, &declarations).unwrap();
    let constants = pn_records::constants::bind_constants(&declared, vec![edition.clone()]).unwrap();
    let input = pn_epoch::bind_inputs(&constants, parameters.clone(), Limits::default()).unwrap();
    let price = if let Some(e) = evidence {
        charge(e, NumberId::NumbersAdmissionWall.value()).unwrap()
    } else {
        let wall = n.literal(NumberId::NumbersAdmissionWall.value()).unwrap();
        let wall = n.computed(&wall).unwrap();
        n.charged_price(&wall, &edition.numeraire, edition.floor).unwrap()
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
        closure: candidate(&self_acts(), 1, &[("a", NumberId::NumbersAdmissionRepeatedBurn.value())])
            .input()
            .closure
            .clone(),
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
    checked: Option<&kernel::CheckedRidge>,
) -> schedules::Record {
    let published = Published(plan.solve.clone());
    let bound = bind_procedure(state, plan.solve.clone(), &published, Limits::default()).unwrap();
    let search = pn_epoch::controller::InverseSearch {
        bracket: Range {
            lower: NumberId::NumbersControllerTestBracketLower.value().into(),
            upper: NumberId::NumbersControllerTestBracketUpper.value().into(),
        },
        stopping_width: NumberId::NumbersControllerTestStoppingWidth.value().into(),
        maximum_steps: NumberId::NumbersControllerTestSteps.integer(),
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
        checked,
        Limits::default(),
    )
    .unwrap()
}

fn fixture(evidence: Option<&ChargeEvidence>) -> (ClosedBoundary, Carrier, Check) {
    let Prelude {
        raw,
        causes: public_causes,
        parameters,
        price,
        candidate_input,
    } = prelude(evidence);
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
    let checked = evidence.map(|e| kernel::replay(&e.procedure, &e.input, &e.record).unwrap());
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
fn candidate_for_declaration() -> package::CandidateContext {
    candidate(&self_acts(), 1, &[("a", NumberId::NumbersAdmissionRepeatedBurn.value())])
}

/// Claim: The finite reversed self-supported complete history forms an immutable semantic package only through admission and independent restoration under each chartered floor; restored compilation, final gates and the next announcement retain their complete records. No encoding, persistence or deployment authentication is inferred.
/// ´claim:admission:restored-packages-retain-complete-admission´
/// ´test:integration:publication-roundtrip´
#[test]
fn publication_roundtrip() {
    let ridge = proof(NumberId::NumbersRidgeCertificatePrecision);
    let mut previous = None;
    for evidence in [None, Some(&ridge)] {
        let (closed, carrier, check) = fixture(evidence);
        assert!(carrier.causes.acts[0].authoritative_position > carrier.causes.acts[1].authoritative_position);
        let admitted = publication::assemble(&closed, carrier.clone(), &check).unwrap();
        let restored = publication::consume(admitted.carrier().clone(), &check).unwrap();
        assert_eq!(restored.carrier().frames[0].compiled, carrier.frames[0].compiled);
        assert_eq!(restored.carrier().frames[0].closure, *closed.record());
        assert_eq!(restored.carrier().frames[0].next, carrier.frames[0].next);
        assert_eq!(restored.carrier().frames[0].price, carrier.frames[0].price);
        if let Some(other) = &previous {
            assert!(matches!(
                publication::assemble(other, carrier.clone(), &check),
                Err(publication::Error::Structure("mixed admitted close"))
            ));
        }
        let mut reordered = carrier;
        reordered.causes.declarations.reverse();
        reordered.causes.acts.reverse();
        // Set presentation may change; authoritative sequence remains fixed.
        let restored = publication::consume(reordered, &check).unwrap();
        assert_eq!(restored.carrier().frames[0].closure, *closed.record());
        previous = Some(closed);
    }
}

fn audit_refusals(carrier: &Carrier, check: &Check) {
    let mut missing = carrier.clone();
    missing.frames[0].realization.capacity_bound.clear();
    assert!(matches!(
        publication::consume(missing, check),
        Err(publication::Error::Structure("missing realization disclosure"))
    ));
    let mut altered = carrier.clone();
    altered.frames[0].realization.dimensioned_unit_cost.push(b'!');
    assert!(matches!(
        publication::consume(altered, check),
        Err(publication::Error::Structure("publication profile"))
    ));
    let mut omitted = carrier.clone();
    omitted.causes.editions.clear();
    assert!(matches!(
        publication::consume(omitted, check),
        Err(publication::Error::Constants(_))
    ));
}

/// Claim: The finite semantic restoration controls refuse omitted and mixed public causes, changed sequence, compilation, final gates, next-announcement prefix and profile; a restored record alone never supplies admission authority.
/// ´claim:admission:mixed-semantic-sections-are-refused´
/// ´test:integration:publication-refusals´
#[test]
fn publication_refusals() {
    let (closed, carrier, check) = fixture(None);
    audit_refusals(&carrier, &check);
    let mut changed = carrier.clone();
    changed.causes.acts.pop();
    assert!(publication::consume(changed, &check).is_err());
    changed = carrier.clone();
    changed.frames[0].marker_history.records[0].evidence.clear();
    assert!(publication::consume(changed, &check).is_err());
    changed = carrier.clone();
    changed.frames[0].sequence.reverse();
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::Candidate(_))
    ));
    let mutations: [fn(&mut pn_epoch::compiler::CompiledView); 7] = [
        |view| view.cells.clear(),
        |view| view.coefficients.clear(),
        |view| view.recipients.clear(),
        |view| view.base.rows.clear(),
        |view| view.support.sources.clear(),
        |view| view.ledger.debits.clear(),
        |view| view.title.epoch = 0,
    ];
    for mutate in mutations {
        changed = carrier.clone();
        mutate(&mut changed.frames[0].compiled);
        assert!(matches!(
            publication::consume(changed, &check),
            Err(publication::Error::Structure("changed compiled section"))
        ));
    }
    changed = carrier.clone();
    changed.frames[0].closure.final_gates.rounds.clear();
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::Closure(closure::ClosureError::Evidence))
    ));
    changed = carrier.clone();
    changed.frames[0].next.initial.wall = "0".into();
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::Structure("changed announcement prefix"))
    ));
    changed = carrier.clone();
    changed.numeric.comparison_work = 0;
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::Structure("publication profile"))
    ));
    changed = carrier.clone();
    changed.frames[0].price.price = "0".into();
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::Numeric(NumericError::RidgeEvidence))
    ));
    changed = carrier;
    changed.frames[0].closure.statement.attestation.push('!');
    assert!(publication::assemble(&closed, changed, &check).is_err());
}

/// Claim: The finite ridge semantic disclosure controls reselect the admitted graph verifier at consumption and refuse changed defining bleed, query precision and transcript image; an unresolved ridge never becomes a restored charge. Neither a stored digest nor a different verifier supplies checked authority.
/// ´claim:admission:restored-ridge-prices-reselect-replay´
/// ´test:integration:publication-ridge-refusals´
#[test]
fn publication_ridge_refusals() {
    let evidence = proof(NumberId::NumbersRidgeCertificatePrecision);
    let (_, carrier, check) = fixture(Some(&evidence));
    let mut changed = carrier.clone();
    changed.frames[0].price.ridge.as_mut().unwrap().input.definition.bleed_squared =
        NumberId::NumbersReferenceSquaredBleed.value().into();
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::Ridge(kernel::Error::Definition))
    ));
    changed = carrier.clone();
    changed.frames[0].price.ridge.as_mut().unwrap().record.queries[0].precision += 1;
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::Ridge(kernel::Error::Query))
    ));
    changed = carrier.clone();
    changed.frames[0]
        .price
        .ridge
        .as_mut()
        .unwrap()
        .record
        .image
        .as_mut()
        .unwrap()
        .upper = "1".into();
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::Ridge(kernel::Error::Record))
    ));
    changed = carrier;
    changed.frames[0].price.ridge = Some(Box::new(proof(NumberId::NumbersRidgeCertificateFailedPrecision)));
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::Schedule(schedules::Error::Refused(
            AdmissionRefusal::Indecisive(admission::Comparison::Floor)
        )))
    ));
}

fn successor(
    carrier: &Carrier,
    check: &mut Check,
    closed: &ClosedBoundary,
    led: &schedules::CheckedSchedule,
) -> (Frame, ClosedBoundary, pn_epoch::compiler::CompiledState) {
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

/// Complete-prefix restoration retains an earlier marker disclosure and debit vintage.
/// (´claim:admission:restored-packages-retain-complete-admission´)
/// ´test:integration:publication-prefix´
#[test]
fn publication_prefix() {
    let (closed, mut carrier, mut check) = fixture(None);
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
    let (mut frame, second, state) = successor(&carrier, &mut check, &closed, &led);
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
    let restored = publication::assemble(&second, carrier.clone(), &check).unwrap();
    assert_eq!(restored.carrier().frames[0].closure, *closed.record());
    assert_eq!(restored.carrier().frames[1].closure, *second.record());
    assert_eq!(
        restored.carrier().frames[0].compiled.ledger.debits,
        restored.carrier().frames[1].compiled.ledger.debits
    );
    assert!(restored.carrier().frames[1].closure.final_gates.standing.is_none());
    assert_ne!(restored.carrier().frames[1].standing.rounds.as_slice(), &[]);
    let mut missing = carrier.clone();
    missing.frames[1].standing.rounds.clear();
    assert!(matches!(
        publication::consume(missing, &check),
        Err(publication::Error::Standing(_))
    ));
    let mut missing = carrier.clone();
    missing.frames.remove(0);
    assert!(publication::consume(missing, &check).is_err());
    carrier.frames[1].price = carrier.frames[0].price.clone();
    assert!(publication::consume(carrier, &check).is_err());
}

#[path = "publication/live.rs"]
mod live;

#[path = "publication/disclosures.rs"]
mod disclosures;
