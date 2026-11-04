use super::*;
#[path = "disclosures/profile.rs"]
mod profile;
use pn_epoch::publication::disclosures::{self, Section};

fn ridge_successor(
    carrier: &Carrier,
    check: &mut Check,
    closed: &ClosedBoundary,
    led: &schedules::CheckedSchedule,
    evidence: &ChargeEvidence,
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

fn ridge_prefix(evidence: &ChargeEvidence) -> (ClosedBoundary, Carrier, Check) {
    let (closed, mut carrier, mut check) = fixture(Some(evidence));
    let first = publication::assemble(&closed, carrier.clone(), &check).unwrap();
    let checked = kernel::replay(&evidence.procedure, &evidence.input, &evidence.record).unwrap();
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
        Some(&checked),
        Limits::default(),
        &old.next,
    )
    .unwrap();
    let mut alternative = evidence.clone();
    alternative.input.maximum_replay_work += 1;
    alternative.record.input = alternative.input.clone();
    kernel::replay(&alternative.procedure, &alternative.input, &alternative.record).unwrap();
    let (mut frame, second, state) = ridge_successor(&carrier, &mut check, &closed, &led, &alternative);
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
        Some(&checked),
        Limits::default(),
    )
    .unwrap();
    frame.sequence.clear();
    frame.compiled = state.view().clone();
    frame.closure = second.record().clone();
    carrier.frames.push(frame);
    (second, carrier, check)
}

/// Claim: The finite complete publication disclosures reconstruct an equal admitted package under declared fixture verifiers, retaining every asserted compilation and closure section. This is a semantic restoration witness, not byte decoding or settlement authenticity.
/// ´claim:admission:disclosures-rebuild-checked-package-authority´
/// ´test:integration:disclosure-roundtrip´
#[test]
fn disclosure_roundtrip() {
    let (closed, carrier, check) = fixture(None);
    let admitted = publication::assemble(&closed, carrier, &check).unwrap();
    let raw = admitted.disclosures();
    let restored = disclosures::restore(raw.clone(), &check).unwrap();
    assert_eq!(restored.carrier(), admitted.carrier());
    assert_eq!(restored.disclosures(), raw);
    assert_eq!(restored.boundary().evidence(), admitted.boundary().evidence());
    let metadata = disclosures::Metadata {
        position: (1, 1),
        logical_time: 1,
    };
    assert_eq!(metadata.position, (1, 1));
    assert_eq!(metadata.logical_time, 1);
}

fn compiled_refusals(raw: &disclosures::Disclosure, check: &Check) {
    type Mutation = (Section, fn(&mut disclosures::Compiled));
    let mutations: &[Mutation] = &[
        (Section::Title, |c| c.title.epoch += 1),
        (Section::Ledger, |c| c.ledger.counts.clear()),
        (Section::Cells, |c| c.cells.clear()),
        (Section::Coefficients, |c| c.coefficients.clear()),
        (Section::Recipients, |c| c.recipients.clear()),
        (Section::Base, |c| c.base.boundary += 1),
        (Section::Support, |c| c.support.boundary += 1),
    ];
    for (section, mutate) in mutations {
        let mut changed = raw.clone();
        mutate(&mut changed.frames[0].compiled);
        assert!(matches!(disclosures::restore(changed, check), Err(publication::Error::Disclosure(found)) if &found == section));
    }
}

/// Claim: The finite disclosure matrix refuses mutated recognition, effective constants, sequence references, charges, debit results, compiled sections, final gates, standing, schedules, realization and omitted causes under its declared fixture verifier. It establishes no byte codec or settlement authenticity.
/// ´claim:admission:disclosure-sections-refuse-substitution´
/// ´test:integration:disclosure-refusals´
#[test]
fn disclosure_refusals() {
    let (closed, carrier, check) = fixture(None);
    let admitted = publication::assemble(&closed, carrier, &check).unwrap();
    let raw = admitted.disclosures();
    let mut changed = raw.clone();
    changed.frames[0].closure.markers.markers[1].accepted.clear();
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Disclosure(Section::Recognition))
    ));
    changed = raw.clone();
    changed.frames[0].closure.bindings[0].inputs.constants.floor = Floor::RidgeImage;
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Disclosure(Section::Inputs))
    ));
    changed = raw.clone();
    changed.frames[0].closure.bindings[0].sequence[0].author.push('!');
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Disclosure(Section::Sequence))
    ));
    changed = raw.clone();
    changed.frames[0].closure.bindings[0].price.price = "0".into();
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Numeric(NumericError::RidgeEvidence))
    ));
    changed = raw.clone();
    let mut numeric = joined::numeric();
    let zero = numeric.literal("0").unwrap();
    changed.frames[0].compiled.ledger.debits.values_mut().next().unwrap().charged = numeric.burn(&zero, "burn").unwrap();
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Disclosure(Section::Debit))
    ));
    compiled_refusals(&raw, &check);
    changed = raw.clone();
    changed.frames[0].closure.final_gates.rounds.clear();
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Closure(closure::ClosureError::Evidence))
    ));
    changed = raw.clone();
    changed.frames[0].standing.rounds.clear();
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Standing(_))
    ));
    changed = raw.clone();
    changed.frames[0].next.initial.wall = "0".into();
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Structure("changed announcement prefix"))
    ));
    changed = raw.clone();
    changed.frames[0].realization.provenance.clear();
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Structure("missing realization disclosure"))
    ));
    changed = raw.clone();
    changed.frames[0].closure.bindings[0].marker.name.push('!');
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Closure(closure::ClosureError::Context))
    ));
    changed = raw.clone();
    changed.frames[0].parameters.self_base = "absent".into();
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Inputs(pn_epoch::InputError::Constant))
    ));
    changed = raw.clone();
    changed.frames[0].price.price = "0".into();
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Numeric(NumericError::RidgeEvidence))
    ));
    changed = raw.clone();
    changed.numeric.comparison_work = 0;
    assert!(matches!(
        disclosures::restore(changed.clone(), &check),
        Err(publication::Error::Structure("publication profile"))
    ));
    // Retain the numerical exhaustion control under an explicitly admitted test profile.
    let exhausted = Check {
        candidates: check.candidates.clone(),
        procedures: check.procedures.clone(),
        numeric: changed.numeric.clone(),
    };
    assert!(matches!(
        disclosures::restore(changed, &exhausted),
        Err(publication::Error::Numeric(_))
    ));
    changed = raw;
    changed.causes.acts.clear();
    assert!(matches!(
        disclosures::restore(changed, &check),
        Err(publication::Error::Disclosure(Section::Sequence))
    ));
}

/// Claim: The finite two-boundary ridge carrier independently restores its later price under `ChargeReplay`: a changed second-frame query refuses as Numeric while the unchanged initial schedule proof passes. Separate valid certificates for the same defining ridge are accepted; no transcript identity is a floor or charge.
/// ´claim:admission:later-ridge-frames-require-charge-replay´
/// ´test:integration:disclosure-ridge-prefix´
#[test]
fn disclosure_ridge_prefix() {
    let evidence = proof(NumberId::NumbersRidgeCertificatePrecision);
    let (closed, carrier, check) = ridge_prefix(&evidence);
    assert_ne!(carrier.frames[0].price.ridge, carrier.frames[1].price.ridge);
    let admitted = publication::assemble(&closed, carrier.clone(), &check).unwrap();
    assert_eq!(
        disclosures::restore(admitted.disclosures(), &check).unwrap().carrier(),
        admitted.carrier()
    );
    let mut changed = carrier.clone();
    changed.frames[1].price.ridge.as_mut().unwrap().record.queries[0].precision += 1;
    let mut raw = admitted.disclosures();
    raw.frames[1].price = changed.frames[1].price.clone();
    assert!(matches!(
        disclosures::restore(raw, &check),
        Err(publication::Error::Numeric(NumericError::RidgeEvidence))
    ));
    assert_eq!(changed.frames[0], carrier.frames[0]);
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::Numeric(NumericError::RidgeEvidence))
    ));
}
