#[path = "common/allocation.rs"]
mod allocation;
mod common;
pub use common::pins;

#[path = "common/package.rs"]
mod package_inputs;
use package_inputs::{Published, fixture};
use pn_epoch::package::{PackageError, verify_package};
use pn_records::numerics::{ComparisonLimits, ExactLimits, NumericContext};

fn other_inputs(boundary: u64, edition_number: u64) -> pn_epoch::CompilerInputs {
    let (mut declaration, mut edition, mut parameters) = common::fixture();
    declaration.id.edition = edition_number;
    edition.id = declaration.id.clone();
    parameters.edition = declaration.id.clone();
    parameters.boundary = boundary;
    for profile in &mut parameters.profiles {
        profile.edition = declaration.id.clone();
    }
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let records = pn_records::validate_record(&[], &history, &[declaration]).unwrap();
    let constants = pn_records::constants::bind_constants(&records, vec![edition]).unwrap();
    pn_epoch::bind_inputs(&constants, parameters, ExactLimits::default()).unwrap()
}

fn predecessor_cases(mut input: pn_epoch::package::PackageInput) {
    let second_inputs = other_inputs(2, 1);
    let second_price = input.prices[0].clone();
    input.bindings.push(pn_epoch::package::EpochBinding {
        marker: input.markers.markers()[2].identity().clone(),
        predecessor: input.markers.markers()[1].identity().clone(),
        inputs: second_inputs.clone(),
        price: second_price.clone(),
        sequence: vec![],
    });
    input.inputs.push(second_inputs);
    input.prices.push(second_price);
    let published = Published(input.bindings.clone());
    verify_package(input.clone(), &published).unwrap();
    input.bindings[1].predecessor.accepted = pn_records::burn::AcceptedSet::CompleteList(std::collections::BTreeSet::new());
    assert_eq!(verify_package(input, &published).unwrap_err(), PackageError::Predecessor);
}

/// Claim: Structural package verification separates burn-marker acceptance from complete act sequences and refuses mismatched histories, policies, predecessor markers, constants, writing prices, sequences and epoch alignment before public binding verification; matching epoch numbers alone do not establish a package.
/// ´claim:compiler:completed-packages-require-explicit-coherent-bindings´
/// ´test:integration:package-bindings´
#[test]
fn package_bindings() {
    let original = fixture();
    let verifier = Published(original.bindings.clone());
    let accepted = verify_package(original.clone(), &verifier).unwrap();
    assert_eq!(accepted.input().bindings, original.bindings);
    pn_graph::formation::reconstruct_replay(&accepted.input().history, &allocation::Verifier).unwrap();
    for (case, expected) in [
        (0, PackageError::History),
        (1, PackageError::Policy),
        (2, PackageError::Predecessor),
        (3, PackageError::Constants),
        (4, PackageError::Sequence),
        (5, PackageError::Sequence),
        (6, PackageError::Alignment),
        (7, PackageError::Alignment),
        (8, PackageError::Vintage),
        (9, PackageError::Policy),
        (10, PackageError::Constants),
        (11, PackageError::Sequence),
    ] {
        let mut input = original.clone();
        match case {
            0 => input.bindings[0].marker.history.push_str("-foreign"),
            1 => input.bindings[0].marker.policy_edition.push_str("-foreign"),
            2 => input.bindings[0].predecessor = input.bindings[0].marker.clone(),
            3 => input.bindings[0].inputs = allocation::inputs_for_depth(&["one"]),
            4 => {
                input.bindings[0].sequence.pop();
            }
            5 => input.bindings[0].sequence.swap(0, 1),
            6 => input.bindings[0].marker.index = 2,
            7 => input.bindings.clear(),
            8 => {
                let mut numeric = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(1000, 1000)).unwrap();
                let literal = numeric.literal("3").unwrap();
                let wall = numeric.computed(&literal).unwrap();
                input.bindings[0].price = numeric
                    .charged_price(
                        &wall,
                        &input.inputs[0].parameters().numeraire,
                        input.inputs[0].constants().content().floor,
                    )
                    .unwrap();
            }
            9 => input.bindings[0].predecessor.policy_identity.push_str("-foreign"),
            10 => input.bindings[0].inputs = other_inputs(1, 2),
            _ => {
                let mut acts = allocation::acts();
                acts[3].body.quantities[0].1.value = 0;
                input.history = allocation::history(&acts);
            }
        }
        assert_eq!(verify_package(input, &verifier).unwrap_err(), expected);
    }
    assert_eq!(
        verify_package(original.clone(), &Published(vec![])).unwrap_err(),
        PackageError::Binding
    );
    predecessor_cases(original);
}

fn schedule_fixture() -> pn_epoch::admission::ScheduleInput {
    use pins::NumberId;
    use pn_epoch::admission::{ControllerParameters, Delivery, InitializationInput, Refinement, ScheduleInput};
    ScheduleInput {
        controller: "canonical-interim-v1".into(),
        announced_at: 0,
        initialization: InitializationInput {
            floor: Some(pn_records::numerics::Floor::RationalThreeThirtySevenths),
            wall: Some(NumberId::NumbersScheduleFixtureInitialWall.value().into()),
            policy_floor: Some(NumberId::NumbersScheduleFixturePolicyFloor.value().into()),
            effective_boundary: Some(1),
            parameters: Some(ControllerParameters {
                absolute_cap: NumberId::NumbersScheduleFixtureAbsoluteCap.value().into(),
                relative_cap: NumberId::NumbersScheduleFixtureRelativeCap.value().into(),
                deadband: NumberId::NumbersScheduleFixtureDeadband.value().into(),
                margin: NumberId::NumbersScheduleFixtureMargin.value().into(),
            }),
        },
        numeraire: common::fixture().2.numeraire,
        delivery: Delivery::Grid {
            quantum: NumberId::NumbersScheduleFixtureGridQuantum.value().into(),
            maximum_error: NumberId::NumbersScheduleFixtureDeliveryError.value().into(),
        },
        refinement: Refinement {
            precision_bits: vec![
                u32::try_from(NumberId::NumbersScheduleFixtureInitialPrecision.integer()).unwrap(),
                u32::try_from(NumberId::NumbersScheduleFixtureFinalPrecision.integer()).unwrap(),
            ],
            maximum_work: NumberId::NumbersScheduleFixtureProductionWork.integer(),
            maximum_replay_work: NumberId::NumbersScheduleFixtureReplayWork.integer(),
        },
    }
}

/// Claim: Schedule declaration validation retains explicit initialization and a closed canonical-controller edition, refusing missing fields, unknown editions, late activation, invalid rational parameter ranges, grid placement and refinement declarations on the declared finite controls; validation produces neither a delivered schedule nor admission evidence.
/// ´claim:admission:schedule-declarations-refuse-incomplete-or-invalid-inputs´
/// ´test:integration:schedule-declarations´
#[test]
fn schedule_declarations() {
    use pn_epoch::admission::{ControllerEdition, DeclarationError, Delivery, InitializationField, declare_schedule};
    let original = schedule_fixture();
    let checked = declare_schedule(original.clone(), ExactLimits::default()).unwrap();
    assert_eq!(checked.controller(), ControllerEdition::CanonicalInterim);
    assert_eq!(checked.input(), &original);
    for missing in [
        InitializationField::PolicyFloor,
        InitializationField::Floor,
        InitializationField::EffectiveBoundary,
        InitializationField::Wall,
        InitializationField::Parameters,
    ] {
        let mut input = original.clone();
        match missing {
            InitializationField::Floor => input.initialization.floor = None,
            InitializationField::Wall => input.initialization.wall = None,
            InitializationField::Parameters => input.initialization.parameters = None,
            InitializationField::PolicyFloor => input.initialization.policy_floor = None,
            InitializationField::EffectiveBoundary => input.initialization.effective_boundary = None,
        }
        assert_eq!(
            declare_schedule(input, ExactLimits::default()).unwrap_err(),
            DeclarationError::Missing(missing)
        );
    }
    for (case, expected) in [
        (0, DeclarationError::Controller),
        (1, DeclarationError::Late),
        (2, DeclarationError::InitialWall),
        (3, DeclarationError::InitialWall),
        (4, DeclarationError::Parameters),
        (5, DeclarationError::Parameters),
        (6, DeclarationError::Parameters),
        (7, DeclarationError::Parameters),
        (8, DeclarationError::Delivery),
        (9, DeclarationError::Delivery),
        (10, DeclarationError::Delivery),
        (11, DeclarationError::Refinement),
        (12, DeclarationError::Refinement),
        (13, DeclarationError::Refinement),
        (14, DeclarationError::Refinement),
        (15, DeclarationError::Refinement),
        (16, DeclarationError::Late),
    ]
    .into_iter()
    .rev()
    {
        let mut input = original.clone();
        match case {
            0 => input.controller = "unknown-controller".into(),
            1 => input.announced_at = input.initialization.effective_boundary.unwrap(),
            2 => input.initialization.wall = Some("0".into()),
            3 => input.initialization.policy_floor = Some("0".into()),
            4 => input.initialization.parameters.as_mut().unwrap().absolute_cap = "0".into(),
            5 => input.initialization.parameters.as_mut().unwrap().relative_cap = "1".into(),
            6 => input.initialization.parameters.as_mut().unwrap().deadband = "1".into(),
            7 => input.initialization.parameters.as_mut().unwrap().margin = "1".into(),
            8 => {
                input.delivery = Delivery::Grid {
                    quantum: "0".into(),
                    maximum_error: pins::NumberId::NumbersScheduleFixtureDeliveryError.value().into(),
                }
            }
            9 => {
                input.delivery = Delivery::Grid {
                    quantum: pins::NumberId::NumbersScheduleFixtureGridQuantum.value().into(),
                    maximum_error: "0".into(),
                }
            }
            10 => input.initialization.wall = Some(pins::NumberId::NumbersScheduleFixtureOffGridWall.value().into()),
            11 => input.refinement.precision_bits.clear(),
            12 => input.refinement.precision_bits.reverse(),
            13 => input.refinement.precision_bits[0] = 0,
            14 => input.refinement.maximum_work = 0,
            15 => input.refinement.maximum_replay_work = 0,
            _ => input.initialization.effective_boundary = Some(input.announced_at + 2),
        }
        assert_eq!(declare_schedule(input, ExactLimits::default()).unwrap_err(), expected);
    }
    let mut exact = original;
    exact.delivery = Delivery::ExactRational;
    declare_schedule(exact.clone(), ExactLimits::default()).unwrap();
    exact.initialization.floor = Some(pn_records::numerics::Floor::RidgeImage);
    // The declaration retains the defining floor; it does not certify its comparison.
    assert_eq!(
        declare_schedule(exact, ExactLimits::default())
            .unwrap()
            .input()
            .initialization
            .floor,
        Some(pn_records::numerics::Floor::RidgeImage)
    );
}

#[derive(Debug)]
struct Proposed(Vec<pn_epoch::package::EpochBinding>);
impl pn_epoch::package::CandidateVerifier for Proposed {
    fn candidate_causes(&self, input: &pn_epoch::package::CandidateInput) -> bool {
        // Fixture authority is a retained complete proposed cause set, not publication.
        input.causes.bindings == self.0
    }
}

#[derive(Debug)]
struct Attested(pn_epoch::package::ClosureStatement);
impl pn_epoch::package::ClosureVerifier for Attested {
    fn host_determination(&self, input: &pn_epoch::package::CandidateInput) -> bool {
        // The fixture models an independently supplied attestation for this statement.
        input.closure == self.0
    }
}

/// Claim: Candidate verification shares published-package cause coherence while requiring separate proposed-cause and closure verifiers; the finite controls refuse cause substitution, invalid closure conditions, changed attestations and publication without its own evidence, and expose no admitted-result constructor.
/// ´claim:admission:candidate-context-retains-separate-authority´
/// ´test:integration:candidate-boundaries´
#[test]
fn candidate_boundaries() {
    use pn_epoch::package::{CandidateInput, ClosureCause, ClosurePolicy, ClosureStatement, verify_candidate};
    let original = fixture();
    let proposed = Proposed(original.bindings.clone());
    let ticks = pins::NumberId::NumbersCandidateFixtureMaximumTicks.integer();
    let statement = ClosureStatement {
        policy: ClosurePolicy {
            target: u64::try_from(original.bindings.last().unwrap().sequence.len()).unwrap(),
            minimum_ticks: pins::NumberId::NumbersCandidateFixtureMinimumTicks.integer(),
            maximum_ticks: ticks,
            clock: "fixture-attested-clock".into(),
        },
        opened_at: 0,
        determined_at: ticks,
        cause: ClosureCause::MaximumDuration,
        attestation: "fixture-maximum-attestation".into(),
    };
    let input = CandidateInput {
        causes: original.clone(),
        closure: statement.clone(),
    };
    let candidate = verify_candidate(input.clone(), &proposed, &Attested(statement.clone())).unwrap();
    assert_eq!(candidate.input().causes.bindings, original.bindings);
    // There is no publication in the fixture's published registry.
    assert_eq!(
        verify_package(candidate.input().causes.clone(), &Published(vec![])).unwrap_err(),
        PackageError::Binding
    );
    assert_eq!(
        verify_candidate(input.clone(), &Proposed(vec![]), &Attested(statement.clone())).unwrap_err(),
        PackageError::CandidateBinding
    );
    let mut changed = input.clone();
    changed.causes.bindings[0].sequence.pop();
    assert_eq!(
        verify_candidate(changed.clone(), &proposed, &Attested(statement.clone())).unwrap_err(),
        PackageError::Sequence
    );
    assert_eq!(
        verify_package(changed.causes, &Published(original.bindings)).unwrap_err(),
        PackageError::Sequence
    );
    for case in (0..7).rev() {
        let mut changed = input.clone();
        match case {
            0 => changed.closure.policy.target = 0,
            1 => changed.closure.policy.minimum_ticks = ticks + 1,
            2 => changed.closure.determined_at = ticks - 1,
            3 => changed.closure.opened_at = ticks + 1,
            4 => changed.closure.policy.clock.clear(),
            5 => changed.closure.attestation.clear(),
            _ => changed.closure.attestation.push_str("-substituted"),
        }
        assert_eq!(
            verify_candidate(changed, &proposed, &Attested(statement.clone())).unwrap_err(),
            PackageError::Closure
        );
    }
    let mut target = input;
    target.closure.cause = ClosureCause::TargetAfterMinimum;
    target.closure.determined_at = target.closure.policy.minimum_ticks;
    target.closure.attestation = "fixture-target-attestation".into();
    verify_candidate(target.clone(), &proposed, &Attested(target.closure.clone())).unwrap();
    target.closure.determined_at -= 1;
    assert_eq!(
        verify_candidate(target.clone(), &proposed, &Attested(target.closure.clone())).unwrap_err(),
        PackageError::Closure
    );
}
