pub use common::pins;
use pins::NumberId;

mod common;
#[path = "common/joined.rs"]
mod joined;
#[path = "solve/partitions.rs"]
mod partitions;

fn burn_reference(acts: &mut Vec<pn_records::CandidateAct>, source: &str, target: &str, count: u64) {
    for _ in 0..count {
        let sequence = u64::try_from(acts.len()).unwrap() + 1;
        let mut act = joined::act("Reference", source, sequence, 1);
        let middle = joined::named("name", &format!("object-{sequence}"));
        act.legs[0].target = middle.clone();
        act.legs[1].source = middle;
        act.legs[1].target = joined::named("prof", target);
        acts.push(act);
    }
}

fn burn_padding(acts: &mut Vec<pn_records::CandidateAct>, source: &str, count: u64) {
    while u64::try_from(acts.iter().filter(|act| act.id.author == source).count()).unwrap() < count {
        let sequence = u64::try_from(acts.len()).unwrap() + 1;
        let mut act = joined::act("Publish", source, sequence, 1);
        joined::coordinates(
            &mut act,
            &["attachment"],
            i64::try_from(NumberId::NumbersBurnZeroCoefficient.integer()).unwrap(),
        );
        acts.push(act);
    }
}

fn burn_acts(case: &str) -> Vec<pn_records::CandidateAct> {
    use NumberId as N;
    let actors: &[&str] = if case == "own" {
        &["j", "d", "u", "b", "a", "v", "c"]
    } else {
        &["i", "b", "u"]
    };
    let mut acts: Vec<_> = actors
        .iter()
        .enumerate()
        .map(|(i, name)| joined::act("Registration", name, u64::try_from(i).unwrap() + 1, 1))
        .collect();
    if case == "own" {
        for (source, target) in [("u", "a"), ("v", "a"), ("a", "c"), ("c", "d"), ("d", "b")] {
            burn_reference(&mut acts, source, target, N::NumbersBurnOwnPathMultiplicity.integer());
        }
        burn_reference(&mut acts, "u", "j", N::NumbersBurnOwnSideMultiplicity.integer());
        burn_reference(&mut acts, "b", "j", N::NumbersBurnOwnExportMultiplicity.integer());
        for source in ["v", "u"] {
            burn_padding(&mut acts, source, N::NumbersBurnOwnUpstreamCount.integer());
        }
    } else if case == "depleted" {
        burn_reference(&mut acts, "u", "b", 1);
        burn_reference(&mut acts, "b", "i", 1);
        burn_padding(&mut acts, "u", N::NumbersBurnDepletedUpstreamCount.integer());
    } else if case != "monotone" {
        burn_reference(&mut acts, "u", "b", 1);
        burn_reference(&mut acts, "u", "i", 1);
        let sequence = u64::try_from(acts.len()).unwrap() + 1;
        let mut act = joined::act("Opinion", "b", sequence, 1);
        act.legs[0].target = joined::named("prof", "i");
        let denominator = if case == "switch" {
            N::NumbersBurnSwitchWeakDenominator
        } else {
            N::NumbersBurnSiblingWeakDenominator
        };
        for (name, quantity) in &mut act.body.quantities {
            if name.ends_with("denominator") {
                quantity.value = i64::try_from(denominator.integer()).unwrap();
            }
        }
        acts.push(act);
    }
    acts.reverse();
    acts
}

fn burn_state(case: &str, after: bool) -> pn_epoch::compiler::CompiledState {
    use NumberId as N;
    let acts = burn_acts(case);
    let mut counts = BTreeMap::<String, u64>::new();
    for act in &acts {
        *counts.entry(act.id.author.clone()).or_default() += 1;
    }
    let wall = Fraction::parse(N::NumbersBurnWall.value());
    let amounts: Vec<_> = counts
        .iter()
        .rev()
        .map(|(name, count)| {
            let rate = if name == "b" {
                match (case, after) {
                    ("depleted", false) => N::NumbersBurnDepletedRateBefore,
                    ("depleted", true) => N::NumbersBurnDepletedRateAfter,
                    ("switch", false) => N::NumbersBurnSwitchRateBefore,
                    ("switch", true) => N::NumbersBurnSwitchRateAfter,
                    (_, true) => N::NumbersBurnRaisedRate,
                    (_, false) => N::NumbersBurnLowRate,
                }
            } else if name == "u" || case == "depleted" {
                N::NumbersBurnHighRate
            } else {
                N::NumbersBurnLowRate
            };
            let amount = Fraction::parse(rate.value())
                .plus(wall)
                .times(Fraction(i128::from(*count), 1));
            (name.clone(), format!("{}/{}", amount.0, amount.1))
        })
        .collect();
    let amounts: Vec<_> = amounts.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let original = joined::package_at_wall(&acts, 1, &amounts, N::NumbersBurnWall.value());
    let (declaration, mut edition, _) = common::fixture();
    let mut numeric = pn_records::numerics::NumericContext::new(
        Limits {
            work: N::NumbersBurnCompilerWorkCeiling.integer(),
            arithmetic_steps: N::NumbersBurnArithmeticCeiling.integer(),
            ..Limits::default()
        },
        pn_records::numerics::ComparisonLimits::new(
            u32::try_from(N::NumbersBurnProductCeiling.integer()).unwrap(),
            N::NumbersBurnProductCeiling.integer(),
        ),
    )
    .unwrap();
    for (name, value) in [
        ("burn-shape-first", N::NumbersPublishedShapeFirst),
        ("burn-shape-second", N::NumbersPublishedShapeSecond),
        ("burn-shape-third", N::NumbersPublishedShapeThird),
        ("burn-shape-fourth", N::NumbersPublishedShapeFourth),
        ("burn-mass-first", N::NumbersPublishedMassFirst),
        ("burn-mass-second", N::NumbersPublishedMassSecond),
        ("burn-mass-third", N::NumbersPublishedMassThird),
        ("burn-mass-fourth", N::NumbersPublishedMassFourth),
    ] {
        edition.constants.push(pn_records::constants::ConstantDefinition::Literal {
            name: name.into(),
            value: numeric.literal(value.value()).unwrap(),
        });
    }
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let record = pn_records::validate_record(&[], &history, &[declaration]).unwrap();
    let constants = pn_records::constants::bind_constants(&record, vec![edition]).unwrap();
    let mut package = original.input().clone();
    let mut parameters = package.inputs[0].parameters().clone();
    parameters.depth_mass = ["burn-mass-first", "burn-mass-second", "burn-mass-third", "burn-mass-fourth"]
        .map(str::to_owned)
        .to_vec();
    let limits = Limits {
        work: N::NumbersBurnCompilerWorkCeiling.integer(),
        arithmetic_steps: N::NumbersBurnArithmeticCeiling.integer(),
        ..Limits::default()
    };
    let input = pn_epoch::bind_inputs(&constants, parameters, limits.clone()).unwrap();
    package.inputs[0] = input.clone();
    package.bindings[0].inputs = input;
    let publication = FencePublication(package.bindings.clone());
    let verified = pn_epoch::package::verify_package(package, &publication).unwrap();
    compile_final_state(
        &verified,
        &joined::Verifier,
        &mut numeric,
        limits,
        N::NumbersBurnProductCeiling.integer(),
    )
    .unwrap()
}

fn burn_policy(state: &pn_epoch::compiler::CompiledState, case: &str) -> Procedure {
    use NumberId as N;
    let mut p = fence_procedure(state);
    let precision = if matches!(case, "depleted" | "monotone") {
        N::NumbersBurnAnchorPrecision
    } else if case == "own" {
        N::NumbersBurnOwnPrecision
    } else {
        N::NumbersBurnSaturatedPrecision
    };
    p.precision = Precision::AbsoluteWidthBits(vec![u32::try_from(precision.integer()).unwrap()]);
    p.grid = vec!["1".into(), "0".into()];
    p.endpoint_grid = N::NumbersBurnEndpointGrid.value().into();
    p.maximum_iterations = N::NumbersBurnProposalCap.integer();
    p.maximum_work = N::NumbersBurnWorkCeiling.integer();
    p.maximum_solve_work = p.maximum_work;
    p.maximum_replay_work = p.maximum_work;
    let e = p.enclosure.as_mut().unwrap();
    e.operation.work = p.maximum_work;
    e.operation.arithmetic_steps = N::NumbersBurnArithmeticCeiling.integer();
    e.operation.literal_bytes = N::NumbersBurnLiteralBytes.integer();
    e.operation.output_bytes = N::NumbersBurnOutputBytes.integer();
    e.store = e.operation.clone();
    e.refinement.precision = u32::try_from(precision.integer()).unwrap();
    e.refinement.reduction_ceiling = u32::try_from(N::NumbersReferenceReductionCeiling.integer()).unwrap();
    p.fence.as_mut().unwrap().shape = [
        "burn-shape-first",
        "burn-shape-second",
        "burn-shape-third",
        "burn-shape-fourth",
    ]
    .map(str::to_owned)
    .to_vec();
    p
}

fn burn_range(value: &Bounds, budget: &mut nrz_cas::limits::Budget) -> nrz_cas::enclosure::Interval {
    nrz_cas::enclosure::Interval::new(
        nrz_cas::Rational::parse(&value.lower, budget).unwrap(),
        nrz_cas::Rational::parse(&value.upper, budget).unwrap(),
        budget,
    )
    .unwrap()
}

fn burn_sub(
    a: &nrz_cas::enclosure::Interval,
    b: &nrz_cas::enclosure::Interval,
    budget: &mut nrz_cas::limits::Budget,
) -> nrz_cas::enclosure::Interval {
    let bits = u32::try_from(NumberId::NumbersBurnSaturatedPrecision.integer()).unwrap();
    let a = a.coarsen(bits, budget).unwrap();
    let b = b.coarsen(bits, budget).unwrap();
    nrz_cas::enclosure::Interval::new(
        a.lower().sub(b.upper(), budget).unwrap(),
        a.upper().sub(b.lower(), budget).unwrap(),
        budget,
    )
    .unwrap()
}

fn burn_pin_upper(value: &nrz_cas::Rational, pin: NumberId, budget: &mut nrz_cas::limits::Budget) {
    assert!(
        !value
            .compare(&nrz_cas::Rational::parse(pin.value(), budget).unwrap(), budget)
            .unwrap()
            .is_gt()
    );
}

fn burn_pin_interval(
    value: &nrz_cas::enclosure::Interval,
    lower: NumberId,
    upper: NumberId,
    budget: &mut nrz_cas::limits::Budget,
) {
    assert!(
        !value
            .lower()
            .compare(&nrz_cas::Rational::parse(lower.value(), budget).unwrap(), budget)
            .unwrap()
            .is_lt()
    );
    burn_pin_upper(value.upper(), upper, budget);
}

type BurnActivationPair = (
    pn_graph::numeric::activation::Evaluation,
    pn_graph::numeric::activation::Evaluation,
);

struct BurnActivations {
    policy: Procedure,
    results: Vec<(pn_graph::numeric::activation::Request, BurnActivationPair)>,
}

fn burn_activation(
    policy: &Procedure,
    request: &pn_graph::numeric::activation::Request,
    cache: Option<&mut BurnActivations>,
) -> BurnActivationPair {
    use pn_graph::numeric::activation;
    if let Some(cached) = cache.as_ref() {
        assert_eq!(policy, &cached.policy);
        if let Some((_, result)) = cached.results.iter().find(|(key, _)| key == request) {
            return result.clone();
        }
    }
    let result = activation::evaluate(policy, request, None).unwrap();
    let replay = activation::replay(policy, request, result.primitive.evidence.attachment.as_ref().unwrap(), None).unwrap();
    let pair = (result, replay);
    if let Some(cached) = cache {
        cached.results.push((request.clone(), pair.clone()));
    }
    pair
}

fn burn_box_transport(
    state: &pn_epoch::compiler::CompiledState,
    policy: &Procedure,
    template: &pn_records::conserved::MapRecord,
    coordinates: &BTreeMap<String, Bounds>,
    budget: &mut nrz_cas::limits::Budget,
) -> pn_records::transport::TransportOutput<nrz_cas::enclosure::Interval> {
    burn_box_transport_with_activations(state, policy, template, coordinates, budget, None)
}

fn burn_box_transport_with_activations(
    state: &pn_epoch::compiler::CompiledState,
    policy: &Procedure,
    template: &pn_records::conserved::MapRecord,
    coordinates: &BTreeMap<String, Bounds>,
    budget: &mut nrz_cas::limits::Budget,
    mut activations: Option<&mut BurnActivations>,
) -> pn_records::transport::TransportOutput<nrz_cas::enclosure::Interval> {
    use nrz_cas::{Rational, enclosure::Interval};
    use pn_graph::numeric::activation::{Quantity, Request};
    use pn_records::primitive::Range;
    let names: Vec<_> = state.view().base.rows.keys().collect();
    let mut input = template.transport_input.clone();
    for (hop, shape) in input.hops.iter_mut().zip([
        NumberId::NumbersPublishedShapeFirst,
        NumberId::NumbersPublishedShapeSecond,
        NumberId::NumbersPublishedShapeThird,
        NumberId::NumbersPublishedShapeFourth,
    ]) {
        let factors: Vec<_> = names
            .iter()
            .map(|name| {
                let coordinate = burn_range(&coordinates[*name], budget)
                    .coarsen(
                        u32::try_from(NumberId::NumbersBurnSaturatedPrecision.integer()).unwrap(),
                        budget,
                    )
                    .unwrap();
                let request = Request {
                    standing: Range {
                        lower: coordinate.lower().exact_string(budget).unwrap(),
                        upper: coordinate.upper().exact_string(budget).unwrap(),
                    },
                    bleed_squared: NumberId::NumbersReferenceSquaredBleed.value().into(),
                    wall: Some(NumberId::NumbersBurnWall.value().into()),
                    wall_enclosure: None,
                    quantity: Quantity::Hop {
                        strength: template.rung.clone(),
                        shape: shape.value().into(),
                    },
                };
                let (result, replay) = burn_activation(policy, &request, activations.as_deref_mut());
                let evidence = &result.primitive.evidence;
                assert_eq!(evidence.bounds, replay.primitive.evidence.bounds);
                evidence
                    .bounds
                    .as_ref()
                    .unwrap()
                    .coarsen(
                        u32::try_from(NumberId::NumbersBurnSaturatedPrecision.integer()).unwrap(),
                        budget,
                    )
                    .unwrap()
            })
            .collect();
        for (i, row) in hop.iter_mut().enumerate() {
            for (j, entry) in row {
                let pn_epoch::base::BaseScore::Exact(score) = &state.view().base.rows[names[i]][names[*j]].score else {
                    panic!("rational burn base");
                };
                let score = Rational::parse(score, budget).unwrap();
                *entry = if i == *j {
                    Interval::singleton(&score, budget).unwrap()
                } else {
                    Interval::new(
                        score.mul(factors[*j].lower(), budget).unwrap(),
                        score.mul(factors[*j].upper(), budget).unwrap(),
                        budget,
                    )
                    .unwrap()
                };
            }
        }
    }
    pn_graph::transport::enclosed::evaluate(
        &input,
        budget,
        usize::try_from(NumberId::NumbersBurnProductCeiling.integer()).unwrap(),
    )
    .unwrap()
}

fn burn_magnitude(value: &nrz_cas::enclosure::Interval, budget: &mut nrz_cas::limits::Budget) -> nrz_cas::Rational {
    let lo = if value.lower().is_negative() {
        value.lower().negated(budget).unwrap()
    } else {
        value.lower().clone()
    };
    let hi = if value.upper().is_negative() {
        value.upper().negated(budget).unwrap()
    } else {
        value.upper().clone()
    };
    if lo.compare(&hi, budget).unwrap().is_gt() { lo } else { hi }
}

fn burn_maximum(values: &[nrz_cas::enclosure::Interval], budget: &mut nrz_cas::limits::Budget) -> nrz_cas::Rational {
    values
        .iter()
        .fold(nrz_cas::Rational::parse("0", budget).unwrap(), |old, value| {
            let next = burn_magnitude(value, budget);
            if next.compare(&old, budget).unwrap().is_gt() {
                next
            } else {
                old
            }
        })
}

fn burn_premises(before: &pn_epoch::compiler::CompiledState, after: &pn_epoch::compiler::CompiledState, case: &str) {
    use NumberId as N;
    assert_eq!(
        before.package().input().history.acts(),
        after.package().input().history.acts()
    );
    assert_eq!(before.package().input().prices, after.package().input().prices);
    assert_eq!(
        before.package().input().inputs[0].parameters(),
        after.package().input().inputs[0].parameters()
    );
    assert_eq!(before.view().base, after.view().base);
    assert_eq!(before.view().ledger.counts, after.view().ledger.counts);
    for (address, amount) in &before.view().ledger.balances {
        let next = &after.view().ledger.balances[address];
        if address.0 == "b" {
            assert!(Fraction::parse(next.exact()).order(Fraction::parse(amount.exact())).is_gt());
        } else {
            assert_eq!(amount, next);
        }
    }
    for state in [before, after] {
        assert_eq!(
            state.package().input().inputs[0].parameters().numeraire.amount().exact(),
            N::NumbersBurnNumeraire.value()
        );
        for (name, source) in &state.view().support.sources {
            let rate = Fraction::parse(&source.reduced_rate);
            let wall = Fraction::parse(N::NumbersBurnWall.value());
            if case == "depleted" && name == "b" {
                assert!(rate.order(wall).is_lt());
                assert_eq!(Fraction::parse(&source.emission), rate.over(wall));
            } else {
                assert!(rate.order(wall).is_gt());
                assert_eq!(source.emission, "1");
            }
        }
        if case == "monotone" {
            // The support identity and affine rate interval prove the premise
            // on the entire burn segment, not just at sampled interior points.
            for (name, sources) in &state.view().support.contributors {
                assert_eq!(sources, &std::collections::BTreeSet::from([name.clone()]));
                assert_eq!(state.view().support.ranges[name].width, "0");
                assert_eq!(state.view().base.rows[name].len(), 1);
            }
        }
    }
    if matches!(case, "sibling" | "depleted") {
        assert!(before.view().support.contributors["i"].contains("b"));
    }
    if case == "depleted" {
        assert_ne!(
            before.view().support.sources["b"].emission,
            after.view().support.sources["b"].emission
        );
        let incoming = before
            .package()
            .input()
            .history
            .acts()
            .iter()
            .find(|a| a.id().family == "Reference" && a.id().author == "u")
            .unwrap();
        let debit = before
            .package()
            .input()
            .history
            .acts()
            .iter()
            .find(|a| a.id().family == "Reference" && a.id().author == "b")
            .unwrap();
        assert!(incoming.id().sequence < debit.id().sequence);
    }
}

fn burn_rungs(search: &pn_epoch::fence::Search, anchor: bool) {
    use pn_records::solve::Completion;
    let expected = if anchor {
        vec![Completion::Fail, Completion::Pass]
    } else {
        vec![Completion::Pass]
    };
    assert_eq!(
        search
            .evidence
            .attempts
            .iter()
            .map(|a| a.completion.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(search.selected.as_deref(), Some(if anchor { "0" } else { "1" }));
    assert_eq!(search.operational_stop, None);
}

fn burn_pins(case: &str) -> ([NumberId; 9], Option<NumberId>) {
    let values = match case {
        "depleted" => [
            NumberId::NumbersBurnDepletedStandingBeforeLower,
            NumberId::NumbersBurnDepletedStandingBeforeUpper,
            NumberId::NumbersBurnDepletedStandingAfterLower,
            NumberId::NumbersBurnDepletedStandingAfterUpper,
            NumberId::NumbersBurnDepletedResponseLower,
            NumberId::NumbersBurnDepletedResponseUpper,
            NumberId::NumbersBurnDepletedSolveBeforeWork,
            NumberId::NumbersBurnDepletedSolveAfterWork,
            NumberId::NumbersBurnDepletedDisplacementUpper,
        ],
        "monotone" => [
            NumberId::NumbersBurnMonotoneStandingBeforeLower,
            NumberId::NumbersBurnMonotoneStandingBeforeUpper,
            NumberId::NumbersBurnMonotoneStandingAfterLower,
            NumberId::NumbersBurnMonotoneStandingAfterUpper,
            NumberId::NumbersBurnMonotoneResponseLower,
            NumberId::NumbersBurnMonotoneResponseUpper,
            NumberId::NumbersBurnMonotoneSolveBeforeWork,
            NumberId::NumbersBurnMonotoneSolveAfterWork,
            NumberId::NumbersBurnMonotoneDisplacementUpper,
        ],
        "own" => [
            NumberId::NumbersBurnOwnStandingBeforeLower,
            NumberId::NumbersBurnOwnStandingBeforeUpper,
            NumberId::NumbersBurnOwnStandingAfterLower,
            NumberId::NumbersBurnOwnStandingAfterUpper,
            NumberId::NumbersBurnOwnResponseLower,
            NumberId::NumbersBurnOwnResponseUpper,
            NumberId::NumbersBurnOwnSolveBeforeWork,
            NumberId::NumbersBurnOwnSolveAfterWork,
            NumberId::NumbersBurnOwnDisplacementUpper,
        ],
        "sibling" => [
            NumberId::NumbersBurnSiblingStandingBeforeLower,
            NumberId::NumbersBurnSiblingStandingBeforeUpper,
            NumberId::NumbersBurnSiblingStandingAfterLower,
            NumberId::NumbersBurnSiblingStandingAfterUpper,
            NumberId::NumbersBurnSiblingResponseLower,
            NumberId::NumbersBurnSiblingResponseUpper,
            NumberId::NumbersBurnSiblingSolveBeforeWork,
            NumberId::NumbersBurnSiblingSolveAfterWork,
            NumberId::NumbersBurnSiblingDisplacementUpper,
        ],
        "switch" => [
            NumberId::NumbersBurnSwitchStandingBeforeLower,
            NumberId::NumbersBurnSwitchStandingBeforeUpper,
            NumberId::NumbersBurnSwitchStandingAfterLower,
            NumberId::NumbersBurnSwitchStandingAfterUpper,
            NumberId::NumbersBurnSwitchResponseLower,
            NumberId::NumbersBurnSwitchResponseUpper,
            NumberId::NumbersBurnSwitchSolveBeforeWork,
            NumberId::NumbersBurnSwitchSolveAfterWork,
            NumberId::NumbersBurnSwitchDisplacementUpper,
        ],
        _ => panic!("unknown burn fixture"),
    };
    let loss = match case {
        "depleted" => Some(NumberId::NumbersBurnDepletedTargetLossUpper),
        "own" => Some(NumberId::NumbersBurnOwnTargetLossUpper),
        "sibling" => Some(NumberId::NumbersBurnSiblingTargetLossUpper),
        "switch" => Some(NumberId::NumbersBurnSwitchTargetLossUpper),
        _ => None,
    };
    (values, loss)
}

fn burn_finite_bounds(
    p: &Procedure,
    fb: &pn_epoch::fence::Search,
    names: &[&String],
    rounds: (&pn_records::conserved::ResidualRound, &pn_records::conserved::ResidualRound),
    shock: &[nrz_cas::enclosure::Interval],
    budget: &mut nrz_cas::limits::Budget,
) -> (
    nrz_cas::Rational,
    nrz_cas::Rational,
    nrz_cas::Rational,
    Vec<nrz_cas::Rational>,
) {
    let (old, new) = rounds;
    let one = nrz_cas::Rational::parse("1", budget).unwrap();
    let two = one.add(&one, budget).unwrap();
    let margin = nrz_cas::Rational::parse(&p.margin, budget).unwrap();
    let q = nrz_cas::Rational::parse(&fb.evidence.attempts.last().unwrap().margined_fence.upper, budget)
        .unwrap()
        .div(&margin, budget)
        .unwrap()
        .div(&two, budget)
        .unwrap();
    let remaining = one.sub(&q, budget).unwrap();
    let factor = q.div(&remaining, budget).unwrap();
    let cap = nrz_cas::Rational::parse(NumberId::NumbersBurnFeedbackCap.value(), budget).unwrap();
    assert!(!factor.compare(&cap, budget).unwrap().is_gt());
    let norm = burn_maximum(shock, budget);
    let displacement = norm.div(&remaining, budget).unwrap();
    let mut loss_bounds = Vec::new();
    for (name, forcing) in names.iter().zip(shock) {
        let delta = burn_sub(
            &burn_range(&new.standing[*name], budget),
            &burn_range(&old.standing[*name], budget),
            budget,
        );
        assert!(!burn_magnitude(&delta, budget).compare(&displacement, budget).unwrap().is_gt());
        let loss = factor.mul(&norm, budget).unwrap().sub(forcing.lower(), budget).unwrap();
        let loss = if loss.is_negative() {
            nrz_cas::Rational::parse("0", budget).unwrap()
        } else {
            loss
        };
        if delta.lower().is_negative() {
            assert!(!delta.lower().negated(budget).unwrap().compare(&loss, budget).unwrap().is_gt());
        }
        loss_bounds.push(loss);
    }
    (q, factor, displacement, loss_bounds)
}

fn burn_direct_forcing(
    before: &pn_epoch::compiler::CompiledState,
    p: &Procedure,
    old: &pn_records::conserved::ResidualRound,
    budget: &mut nrz_cas::limits::Budget,
    activations: Option<&mut BurnActivations>,
) -> Vec<nrz_cas::enclosure::Interval> {
    let names: Vec<_> = before.view().base.rows.keys().collect();
    let old_transport = burn_box_transport_with_activations(before, p, &old.certified, &old.standing, budget, activations);
    let burner = names.iter().position(|v| v.as_str() == "b").unwrap();
    names
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let zero = nrz_cas::Rational::parse("0", budget).unwrap();
            let zero = nrz_cas::enclosure::Interval::singleton(&zero, budget).unwrap();
            let numerator = old_transport.emitted[burner].get(&i).unwrap_or(&zero);
            let denominator = &old_transport.denominator[i];
            nrz_cas::enclosure::Interval::new(
                numerator.lower().div(denominator.upper(), budget).unwrap(),
                numerator.upper().div(denominator.lower(), budget).unwrap(),
                budget,
            )
            .unwrap()
        })
        .collect()
}

fn burn_feedback_cap(
    case: &str,
    before: &pn_epoch::compiler::CompiledState,
    direct: &[nrz_cas::enclosure::Interval],
    factor: &nrz_cas::Rational,
    budget: &mut nrz_cas::limits::Budget,
) {
    use NumberId as N;
    let names: Vec<_> = before.view().base.rows.keys().collect();
    let one = nrz_cas::Rational::parse("1", budget).unwrap();
    let cap = nrz_cas::Rational::parse(N::NumbersBurnFeedbackCap.value(), budget).unwrap();
    let burner = names.iter().position(|v| v.as_str() == "b").unwrap();
    let largest = if case == "own" { "j" } else { "b" };
    let largest = names.iter().position(|v| v.as_str() == largest).unwrap();
    for (i, forcing) in direct.iter().enumerate() {
        assert!(!forcing.lower().is_negative());
        if i != largest {
            assert!(direct[largest].lower().compare(forcing.upper(), budget).unwrap().is_gt());
        }
    }
    assert!(!direct[burner].lower().is_zero());
    let maximum = burn_maximum(direct, budget);
    let feedback_upper = factor.mul(&maximum, budget).unwrap();
    assert!(
        !feedback_upper
            .compare(&cap.mul(&maximum, budget).unwrap(), budget)
            .unwrap()
            .is_gt()
    );
    let count = nrz_cas::Rational::parse(
        &before.view().ledger.counts[&pn_records::burn::Address("b".into())]
            .0
            .to_string(),
        budget,
    )
    .unwrap();
    assert!(!maximum.compare(&one.div(&count, budget).unwrap(), budget).unwrap().is_gt());
    let pins = if case == "own" {
        [
            N::NumbersBurnOwnDirectOwnLower,
            N::NumbersBurnOwnDirectOwnUpper,
            N::NumbersBurnOwnDirectMaximumLower,
            N::NumbersBurnOwnDirectMaximumUpper,
            N::NumbersBurnOwnFeedbackUpper,
        ]
    } else {
        [
            N::NumbersBurnSiblingDirectOwnLower,
            N::NumbersBurnSiblingDirectOwnUpper,
            N::NumbersBurnSiblingDirectMaximumLower,
            N::NumbersBurnSiblingDirectMaximumUpper,
            N::NumbersBurnSiblingFeedbackUpper,
        ]
    };
    burn_pin_interval(&direct[burner], pins[0], pins[1], budget);
    burn_pin_interval(&direct[largest], pins[2], pins[3], budget);
    burn_pin_upper(&feedback_upper, pins[4], budget);
}

fn burn_history_size(before: &pn_epoch::compiler::CompiledState, case: &str) {
    use NumberId as N;
    let count_pin = match case {
        "own" => N::NumbersBurnOwnActCount,
        "sibling" => N::NumbersBurnSiblingActCount,
        "switch" => N::NumbersBurnSwitchActCount,
        "depleted" => N::NumbersBurnDepletedActCount,
        "monotone" => N::NumbersBurnMonotoneActCount,
        _ => unreachable!(),
    };
    assert_eq!(
        u64::try_from(before.package().input().history.acts().len()).unwrap(),
        count_pin.integer()
    );
}

fn burn_case(case: &str) {
    use NumberId as N;
    let (
        [
            old_lo,
            old_hi,
            new_lo,
            new_hi,
            delta_lo,
            delta_hi,
            old_work,
            new_work,
            displacement_pin,
        ],
        loss_pin,
    ) = burn_pins(case);
    let before = burn_state(case, false);
    let after = burn_state(case, true);
    burn_premises(&before, &after, case);
    let p = burn_policy(&before, case);
    let a = bind_procedure(&before, p.clone(), &Published(p.clone()), Limits::default()).unwrap();
    let b = bind_procedure(&after, p.clone(), &Published(p), Limits::default()).unwrap();
    let fa = pn_epoch::fence::search(&a, None).unwrap();
    let fb = pn_epoch::fence::search(&b, None).unwrap();
    burn_rungs(&fa, case == "depleted");
    burn_rungs(&fb, matches!(case, "depleted" | "switch"));
    let ra = pn_epoch::conserved::solve(&a, &fa).unwrap();
    let rb = pn_epoch::conserved::solve(&b, &fb).unwrap();
    let target = if case == "sibling" || case == "depleted" { "i" } else { "b" };
    let old = ra.rounds.last().unwrap();
    let new = rb.rounds.last().unwrap();
    let mut budget = nrz_cas::limits::Budget::new(a.inputs().1.enclosure.as_ref().unwrap().operation.clone()).unwrap();
    let old_value = burn_range(&old.standing[target], &mut budget);
    let new_value = burn_range(&new.standing[target], &mut budget);
    let response = burn_sub(&new_value, &old_value, &mut budget);
    if case == "monotone" {
        assert!(!response.lower().is_negative() && !response.lower().is_zero());
        assert_eq!(old.standing[target].lower, before.view().support.sources[target].reduced_rate);
        assert_eq!(new.standing[target].lower, after.view().support.sources[target].reduced_rate);
        assert_eq!(old.standing[target].lower, old.standing[target].upper);
        assert_eq!(new.standing[target].lower, new.standing[target].upper);
    } else {
        // Counterexamples refuse an unconditional monotonicity or recovery claim.
        assert!(response.upper().is_negative());
    }
    let mut activations = (case == "own").then(|| BurnActivations {
        policy: a.inputs().1.clone(),
        results: Vec::new(),
    });
    let transported = burn_box_transport_with_activations(
        &after,
        b.inputs().1,
        &new.certified,
        &old.standing,
        &mut budget,
        activations.as_mut(),
    );
    let names: Vec<_> = after.view().base.rows.keys().collect();
    let shock: Vec<_> = names
        .iter()
        .zip(&transported.standing)
        .map(|(name, image)| burn_sub(image, &burn_range(&old.standing[*name], &mut budget), &mut budget))
        .collect();
    let (q, factor, displacement, loss_bounds) = burn_finite_bounds(a.inputs().1, &fb, &names, (old, new), &shock, &mut budget);
    if matches!(case, "own" | "sibling") {
        assert_eq!(
            fa.evidence.attempts.last().unwrap().margined_fence,
            fb.evidence.attempts.last().unwrap().margined_fence
        );
        assert_eq!(
            q.exact_string(&mut budget).unwrap(),
            if case == "own" {
                N::NumbersBurnOwnContractionUpper
            } else {
                N::NumbersBurnSaturatedContractionUpper
            }
            .value()
        );
        assert_eq!(
            factor.exact_string(&mut budget).unwrap(),
            if case == "own" {
                N::NumbersBurnOwnFeedbackFactorUpper
            } else {
                N::NumbersBurnSaturatedFeedbackFactorUpper
            }
            .value()
        );
        let direct = burn_direct_forcing(&before, a.inputs().1, old, &mut budget, activations.as_mut());
        burn_feedback_cap(case, &before, &direct, &factor, &mut budget);
    }
    burn_pin_interval(&old_value, old_lo, old_hi, &mut budget);
    burn_pin_interval(&new_value, new_lo, new_hi, &mut budget);
    burn_pin_interval(&response, delta_lo, delta_hi, &mut budget);
    assert_eq!((ra.work, rb.work), (old_work.integer(), new_work.integer()));
    burn_pin_upper(&displacement, displacement_pin, &mut budget);
    let target_index = names.iter().position(|name| name.as_str() == target).unwrap();
    if let Some(pin) = loss_pin {
        burn_pin_upper(&loss_bounds[target_index], pin, &mut budget);
    } else {
        assert!(loss_bounds[target_index].is_zero());
    }
    burn_history_size(&before, case);
}

/// Claim: The unsorted complete-history own-burn pair preserves counts, base, publication and full emission at the same positive passing rung, yet certified standing decreases. Replayed box transport bounds its finite shock and displacement; the declared smooth-regime feedback majorant uses the certified largest direct forcing at another Actor, not the own forcing.
/// ´claim:standing:saturated-burn-can-lower-own-standing´
/// ´test:integration:burn-own´
#[test]
fn burn_own() {
    burn_case("own");
}
/// Claim: The unsorted complete-history sibling pair changes only one accepted burn and preserves counts, base, publication and saturated emission at the same positive passing rung. Certified reached standing decreases; replayed box transport checks the finite response bounds and the largest-direct-forcing feedback majorant.
/// ´claim:standing:saturated-burn-can-lower-reached-standing´
/// ´test:integration:burn-sibling´
#[test]
fn burn_sibling() {
    burn_case("sibling");
}
/// Claim: The unsorted complete-history depleted-source pair changes only one accepted burn. Both full rungs fail and both anchors pass; emission changes and the certified reached recipient decreases. The complete signed shock, not fixed-emission direct forcing, bounds the finite response.
/// ´claim:standing:depleted-burn-can-lower-anchor-recipient´
/// ´test:integration:burn-depleted´
#[test]
fn burn_depleted() {
    burn_case("depleted");
}
/// Claim: The unsorted complete-history positive-burn pair preserves counts, base and saturated emission but changes the selected rung from a passing full rung to a passing anchor after a full-rung failure. Certified own standing decreases, and replayed transport checks the complete shock and finite response bound.
/// ´claim:standing:burn-rung-switch-retains-finite-loss-bound´
/// ´test:integration:burn-switch´
#[test]
fn burn_switch() {
    burn_case("switch");
}
/// Claim: The unsorted complete-history sole-contributor pair changes only one accepted burn. Fixed self-only support and an affine source-rate segment strictly above the wall establish the premise throughout the path; both full rungs pass and exact own standing increases with its rate. No positive direction is asserted outside that regime.
/// ´claim:standing:sole-contributor-burn-increases-throughout-path´
/// ´test:integration:burn-monotone´
#[test]
fn burn_monotone() {
    burn_case("monotone");
}

fn split_state(refined: bool, exporting: bool) -> pn_epoch::compiler::CompiledState {
    use NumberId as N;
    let member = if refined { "third" } else { "seller" };
    let last_family = if exporting { "Opinion" } else { "Registration" };
    // Presentation is deliberately not authoritative or Actor order.
    let acts = [
        joined::act(last_family, member, 5, 1),
        joined::act("Registration", "buyer", 3, 1),
        joined::act("Registration", "seller", 1, 1),
        joined::act(last_family, "seller", 4, 1),
        joined::act("Registration", member, 2, 1),
    ];
    let mut burns = vec![("buyer", N::NumbersSplitOutsiderBurn.value())];
    if refined {
        burns.extend([
            ("third", N::NumbersSplitMemberBurn.value()),
            ("seller", N::NumbersSplitMemberBurn.value()),
        ]);
    } else {
        burns.push(("seller", N::NumbersSplitCoarseBurn.value()));
    }
    let package = joined::package_at_wall(&acts, 1, &burns, N::NumbersSplitWritingWall.value());
    compile_final_state(
        &package,
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        N::NumbersSplitCompilerProductCeiling.integer(),
    )
    .unwrap()
}

fn split_policy(state: &pn_epoch::compiler::CompiledState) -> Procedure {
    use NumberId as N;
    let mut p = conserved_policy(state, N::NumbersSplitEndpointGrid.value());
    p.grid = vec!["1".into(), "0".into()];
    p.maximum_iterations = N::NumbersSplitProposalCap.integer();
    p.precision = Precision::AbsoluteWidthBits(vec![u32::try_from(N::NumbersSplitPrecision.integer()).unwrap()]);
    p
}

fn split_premises(coarse: &pn_epoch::compiler::CompiledState, refined: &pn_epoch::compiler::CompiledState) {
    use NumberId as N;
    use pn_records::burn::Address;
    let old = coarse.package().input();
    let new = refined.package().input();
    assert_eq!(old.prices, new.prices);
    assert_eq!(old.inputs[0].parameters(), new.inputs[0].parameters());
    assert_eq!(old.history.acts().len(), new.history.acts().len());
    for original in old.history.acts() {
        let counterpart = new
            .history
            .acts()
            .iter()
            .find(|act| act.id().sequence == original.id().sequence)
            .unwrap();
        assert_eq!(original.id().family, counterpart.id().family);
        if original.id().author == "buyer" {
            assert_eq!(original, counterpart);
        }
        // Only the participant author and its own Registration profile change.
        assert_eq!(original.body(), counterpart.body());
        if original.id().family == "Opinion" {
            assert_eq!(original.legs()[0].target(), counterpart.legs()[0].target());
        }
    }
    for (state, actor, count, balance, rate) in [
        (
            coarse,
            "seller",
            N::NumbersSplitCoarseCount,
            N::NumbersSplitCoarseBalance,
            N::NumbersSplitSourceRate,
        ),
        (
            refined,
            "third",
            N::NumbersSplitMemberCount,
            N::NumbersSplitMemberBalance,
            N::NumbersSplitSourceRate,
        ),
        (
            refined,
            "seller",
            N::NumbersSplitMemberCount,
            N::NumbersSplitMemberBalance,
            N::NumbersSplitSourceRate,
        ),
        (
            coarse,
            "buyer",
            N::NumbersSplitOutsiderCount,
            N::NumbersSplitOutsiderBalance,
            N::NumbersSplitOutsiderRate,
        ),
        (
            refined,
            "buyer",
            N::NumbersSplitOutsiderCount,
            N::NumbersSplitOutsiderBalance,
            N::NumbersSplitOutsiderRate,
        ),
    ] {
        let address = Address(actor.into());
        assert_eq!(state.view().ledger.counts[&address].0, count.integer());
        assert_eq!(state.view().ledger.balances[&address].exact(), balance.value());
        assert_eq!(state.view().support.sources[actor].reduced_rate, rate.value());
        assert!(
            Fraction::parse(rate.value())
                .order(Fraction::parse(N::NumbersSplitWritingWall.value()))
                .is_gt()
        );
    }
    let proportion = Fraction::parse(N::NumbersSplitMemberProportion.value());
    assert_eq!(proportion.plus(proportion), Fraction(1, 1));
    assert_eq!(
        Fraction::parse(N::NumbersSplitCoarseCount.value()).times(proportion),
        Fraction::parse(N::NumbersSplitMemberCount.value())
    );
    assert_eq!(
        Fraction::parse(N::NumbersSplitCoarseBalance.value()).times(proportion),
        Fraction::parse(N::NumbersSplitMemberBalance.value())
    );
}

fn split_exact(value: &nrz_cas::enclosure::Interval) -> Fraction {
    let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    assert_eq!(value.lower(), value.upper());
    Fraction::parse(&value.lower().exact_string(&mut budget).unwrap())
}

fn split_hops(state: &pn_epoch::compiler::CompiledState, record: &pn_records::conserved::MapRecord) -> Vec<Vec<Fraction>> {
    let names: Vec<_> = state.view().base.rows.keys().collect();
    assert_eq!(record.transport.normalized.len(), 1);
    // Either the accepted anchor makes all off-diagonal powers zero, or every
    // row is self-only. These structural premises make the matrix state-independent.
    assert!(
        record.rung == "0"
            || state
                .view()
                .base
                .rows
                .iter()
                .all(|(source, row)| row.keys().all(|target| target == source))
    );
    names
        .iter()
        .enumerate()
        .map(|(i, source)| {
            let base: Vec<_> = names
                .iter()
                .map(|target| {
                    state.view().base.rows[*source].get(*target).map_or(Fraction(0, 1), |entry| {
                        let pn_epoch::base::BaseScore::Exact(value) = &entry.score else {
                            panic!("exact split base");
                        };
                        Fraction::parse(value)
                    })
                })
                .collect();
            let sum = base.iter().copied().fold(Fraction(0, 1), Fraction::plus);
            base.iter()
                .enumerate()
                .map(|(j, value)| {
                    let expected = value.over(sum);
                    let actual = record.transport.normalized[0][i].get(&j).map_or(Fraction(0, 1), split_exact);
                    assert_eq!(actual, expected);
                    actual
                })
                .collect()
        })
        .collect()
}

fn split_intertwines(coarse: &[Vec<Fraction>], refined: &[Vec<Fraction>]) -> bool {
    let zero = Fraction(0, 1);
    let half = Fraction::parse(NumberId::NumbersSplitMemberProportion.value());
    // Sorted compiled order is buyer, seller, then third in the refinement.
    let refinement = [vec![Fraction(1, 1), zero, zero], vec![zero, half, half]];
    refinement.iter().enumerate().all(|(u, row)| {
        refined.iter().enumerate().all(|(a, _)| {
            let left = row.iter().zip(refined).map(|(r, p)| r.times(p[a])).fold(zero, Fraction::plus);
            let right = coarse[u]
                .iter()
                .zip(&refinement)
                .map(|(p, r)| p.times(r[a]))
                .fold(zero, Fraction::plus);
            left == right
        })
    })
}

fn split_pair_bound(old: &pn_records::conserved::MapRecord, new: &pn_records::conserved::MapRecord) {
    use NumberId as N;
    let zero = Fraction(0, 1);
    let old_count = split_exact(&old.transport.denominator[0]);
    let new_count = split_exact(&new.transport.denominator[0]);
    let old_amount = split_exact(&old.transport.numerator[0]);
    let new_amount = split_exact(&new.transport.numerator[0]);
    let old_standing = old_amount.over(old_count);
    let delta_count = new_count.minus(old_count);
    let delta_amount = new_amount.minus(old_amount);
    let displacement = new_amount.over(new_count).minus(old_standing);
    assert_eq!(
        displacement,
        delta_amount.minus(old_standing.times(delta_count)).over(new_count)
    );
    let counts = [
        N::NumbersSplitOutsiderCount,
        N::NumbersSplitMemberCount,
        N::NumbersSplitMemberCount,
    ];
    let rates = [
        N::NumbersSplitOutsiderRate,
        N::NumbersSplitSourceRate,
        N::NumbersSplitSourceRate,
    ];
    let weights: Vec<_> = counts
        .iter()
        .enumerate()
        .map(|(a, count)| {
            let old_source = usize::from(a != 0);
            let p = old.transport.normalized[0][old_source].get(&0).map_or(zero, split_exact);
            let next = new.transport.normalized[0][a].get(&0).map_or(zero, split_exact);
            (
                Fraction::parse(count.value()).times(p),
                Fraction::parse(count.value()).times(next),
            )
        })
        .collect();
    let old_oracle = weights
        .iter()
        .zip(rates)
        .map(|((w, _), rate)| w.times(Fraction::parse(rate.value())))
        .fold(zero, Fraction::plus);
    let new_oracle = weights
        .iter()
        .zip(rates)
        .map(|((_, w), rate)| w.times(Fraction::parse(rate.value())))
        .fold(zero, Fraction::plus);
    assert_eq!(old_amount, old_oracle);
    assert_eq!(new_amount, new_oracle);
    assert_eq!(old_count, weights.iter().map(|(w, _)| *w).fold(zero, Fraction::plus));
    assert_eq!(new_count, weights.iter().map(|(_, w)| *w).fold(zero, Fraction::plus));
    let variation = weights
        .iter()
        .map(|(w, next)| {
            let difference = next.over(new_count).minus(w.over(old_count));
            Fraction::new(difference.0.abs(), difference.1)
        })
        .fold(zero, Fraction::plus)
        .over(Fraction(2, 1));
    assert_eq!(variation, Fraction::parse(N::NumbersSplitReceivingVariation.value()));
    let bound = Fraction::parse(N::NumbersSplitContributingWidth.value()).times(variation);
    assert_eq!(Fraction::new(displacement.0.abs(), displacement.1), bound);
    let outside_count = Fraction::parse(N::NumbersSplitOutsiderCount.value());
    assert_eq!(
        old_count.minus(outside_count),
        Fraction::parse(N::NumbersSplitCoarseExport.value())
    );
    assert_eq!(
        new_count.minus(outside_count),
        Fraction::parse(N::NumbersSplitRefinedExport.value())
    );
    assert_eq!(
        split_exact(&old.transport.normalized[0][1][&1]),
        Fraction::parse(N::NumbersSplitCoarseSelfHop.value())
    );
    assert_eq!(
        split_exact(&new.transport.normalized[0][1][&1]),
        Fraction::parse(N::NumbersSplitRefinedSelfHop.value())
    );
}

fn split_projected_bound(
    bound: &pn_epoch::solve::BoundProcedure<'_>,
    old: &pn_records::conserved::ResidualRound,
    new: &pn_records::conserved::ResidualRound,
    exporting: bool,
) {
    use NumberId as N;
    let zero = Fraction(0, 1);
    let lifted: BTreeMap<_, _> = new
        .standing
        .keys()
        .map(|name| {
            let source = if name == "third" { "seller" } else { name };
            let value = &old.standing[source];
            assert_eq!(value.lower, value.upper);
            (name.clone(), value.lower.clone())
        })
        .collect();
    // In these two cases the lifted point is already in every refined hull.
    for (name, value) in &lifted {
        let hull = &bound.inputs().0.view().support.ranges[name];
        assert!(!Fraction::parse(value).order(Fraction::parse(&hull.minimum)).is_lt());
        assert!(!Fraction::parse(value).order(Fraction::parse(&hull.maximum)).is_gt());
    }
    let trial = pn_epoch::conserved::evaluate_map(bound, &new.certified.rung, &lifted, new.certified.precision).unwrap();
    pn_epoch::conserved::replay_map(bound, &trial).unwrap();
    let residuals: BTreeMap<_, _> = lifted
        .iter()
        .map(|(name, y)| {
            let image = &trial.image[name];
            assert_eq!(image.lower, image.upper);
            let delta = Fraction::parse(&image.lower).minus(Fraction::parse(y));
            (name, Fraction::new(delta.0.abs(), delta.1))
        })
        .collect();
    let delta = residuals.values().copied().max_by(|a, b| a.order(*b)).unwrap();
    let q = Fraction::parse(&new.contraction);
    assert_eq!(q, zero);
    let radius = delta.over(Fraction(1, 1).minus(q));
    let expected = if exporting {
        N::NumbersSplitReceivingDisplacement.value()
    } else {
        "0"
    };
    assert_eq!(radius, Fraction::parse(expected));
    for (name, y) in &lifted {
        let current = &new.standing[name];
        assert_eq!(current.lower, current.upper);
        let difference = Fraction::parse(&current.lower).minus(Fraction::parse(y));
        let displacement = Fraction::new(difference.0.abs(), difference.1);
        assert!(!displacement.order(radius).is_gt());
        assert!(!displacement.order(residuals[name].plus(q.times(radius))).is_gt());
        if exporting && name == "buyer" {
            assert!(difference.0 < 0);
            assert_eq!(
                displacement,
                Fraction::parse(N::NumbersSplitContributingWidth.value())
                    .times(Fraction::parse(N::NumbersSplitReceivingVariation.value()))
            );
        } else {
            assert_eq!(displacement, zero);
        }
    }
}

/// Claim: Two unsorted proportional complete-history splits are certified and replayed under a common declared policy per comparison. The self-only pair selects full strength and satisfies the all-state compiled hop refinement, preserving each member and the outside coordinate. The fold/export pair selects the anchor, fails that identity and strictly lowers the outside coordinate. Independent exact hop normalization and projected residual bounds retain their premises; unconditional split equality is rejected. These finite cases establish no burn, annotation or general funded-partition guarantee.
/// ´claim:standing:certified-splits-retain-hop-premises-and-displacement´
/// ´test:integration:certified-splits´
#[test]
fn certified_splits() {
    use NumberId as N;
    for exporting in [true, false] {
        let coarse = split_state(false, exporting);
        let refined = split_state(true, exporting);
        split_premises(&coarse, &refined);
        let p = split_policy(&coarse);
        let p_refined = split_policy(&refined);
        assert_eq!(p, p_refined);
        let bound = bind_procedure(&coarse, p.clone(), &Published(p.clone()), Limits::default()).unwrap();
        let bound_refined = bind_procedure(&refined, p_refined.clone(), &Published(p_refined), Limits::default()).unwrap();
        let accepted = pn_epoch::fence::search(&bound, None).unwrap();
        let accepted_refined = pn_epoch::fence::search(&bound_refined, None).unwrap();
        let expected_rung = if exporting { "0" } else { "1" };
        assert_eq!(accepted.selected.as_deref(), Some(expected_rung));
        assert_eq!(accepted.selected, accepted_refined.selected);
        for evidence in [&accepted.evidence, &accepted_refined.evidence] {
            validate_evidence(&p, evidence, Limits::default()).unwrap();
            assert_eq!(evidence.attempts.last().unwrap().completion, Completion::Pass);
            if exporting {
                assert_eq!(evidence.attempts[0].completion, Completion::Fail);
            } else {
                assert_eq!(evidence.attempts.len(), 1);
            }
        }
        let old = pn_epoch::conserved::solve(&bound, &accepted).unwrap();
        let new = pn_epoch::conserved::solve(&bound_refined, &accepted_refined).unwrap();
        pn_epoch::conserved::replay(&bound, &old).unwrap();
        pn_epoch::conserved::replay(&bound_refined, &new).unwrap();
        let old = old.rounds.last().unwrap();
        let new = new.rounds.last().unwrap();
        assert_eq!(
            split_intertwines(&split_hops(&coarse, &old.certified), &split_hops(&refined, &new.certified)),
            !exporting
        );
        let old_outside = if exporting {
            N::NumbersSplitCoarseReceivingStanding
        } else {
            N::NumbersSplitOutsiderRate
        };
        let new_outside = if exporting {
            N::NumbersSplitRefinedReceivingStanding
        } else {
            N::NumbersSplitOutsiderRate
        };
        assert_eq!(old.standing["buyer"].lower, old_outside.value());
        assert_eq!(new.standing["buyer"].lower, new_outside.value());
        split_projected_bound(&bound_refined, old, new, exporting);
        if exporting {
            split_pair_bound(&old.certified, &new.certified);
        }
        // The positive residual counterexample refuses an unconditional equality claim.
        assert_eq!(old.standing["buyer"] == new.standing["buyer"], !exporting);
    }
}

use nrz_cas::limits::Limits;
use pn_epoch::{
    compiler::compile_final_state,
    solve::{ProcedureError, ProcedureVerifier, bind_procedure},
};
use pn_records::solve::{
    Attempt, AttemptStop, Bounds, Completion, Equality, Evidence, Precision, Primitive, Procedure, RecordError, Residual,
    validate_evidence, validate_procedure,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
struct Published(Procedure);

#[derive(Debug)]
struct PublishedReference(pn_records::wall::Inputs);
impl pn_epoch::wall::ReferenceVerifier for PublishedReference {
    fn published_reference(&self, _: &Procedure, input: &pn_records::wall::Inputs) -> bool {
        input == &self.0
    }
}

fn enclosed_state() -> pn_epoch::compiler::CompiledState {
    let actors = ["third", "fifth", "seller", "buyer", "fourth"];
    let mut acts = Vec::new();
    for (i, actor) in actors.iter().enumerate() {
        acts.push(joined::act("Registration", actor, u64::try_from(i + 1).unwrap(), 1));
        let mut opinion = joined::act("Opinion", actor, u64::try_from(i + 6).unwrap(), 1);
        opinion.legs[0].target = joined::named("prof", actors[(i + 1) % actors.len()]);
        acts.push(opinion);
    }
    let original = joined::package(
        &acts,
        1,
        &[
            ("third", "6"),
            ("fifth", "5"),
            ("seller", "7"),
            ("buyer", "11/2"),
            ("fourth", "13/2"),
        ],
    );
    let (declaration, mut edition, _) = common::fixture();
    let mut numeric = joined::numeric();
    for (name, value) in [("half", "1/2"), ("quarter", "1/4"), ("eighth", "1/8")] {
        edition.constants.push(pn_records::constants::ConstantDefinition::Literal {
            name: name.into(),
            value: numeric.literal(value).unwrap(),
        });
    }
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let record = pn_records::validate_record(&[], &history, &[declaration]).unwrap();
    let constants = pn_records::constants::bind_constants(&record, vec![edition]).unwrap();
    let mut package = original.input().clone();
    let mut parameters = package.inputs[0].parameters().clone();
    parameters.depth_mass = vec!["quarter".into(); usize::try_from(NumberId::NumbersEnclosedDepthMassCount.integer()).unwrap()];
    let input = pn_epoch::bind_inputs(&constants, parameters, Limits::default()).unwrap();
    package.inputs[0] = input.clone();
    package.bindings[0].inputs = input;
    let publication = FencePublication(package.bindings.clone());
    let verified = pn_epoch::package::verify_package(package, &publication).unwrap();
    let state = compile_final_state(&verified, &joined::Verifier, &mut numeric, Limits::default(), 10000).unwrap();
    assert_eq!(
        state.view().support.by_depth.keys().next_back(),
        Some(&usize::try_from(NumberId::NumbersEnclosedDepthMassCount.integer()).unwrap())
    );
    assert!(state.view().support.ranges.values().all(|r| r.width == "1"));
    state
}

fn enclosed_policy(state: &pn_epoch::compiler::CompiledState, inverse: bool) -> Procedure {
    let mut p = fence_procedure(state);
    p.precision = Precision::AbsoluteWidthBits(vec![8, 16, 24]);
    p.grid = vec!["1".into(), "1/2".into(), "0".into()];
    p.endpoint_grid = "1/128".into();
    p.maximum_iterations = 2;
    p.maximum_work = NumberId::NumbersEnclosedWorkCeiling.integer();
    p.maximum_solve_work = p.maximum_work;
    p.maximum_replay_work = p.maximum_work;
    let policy = p.enclosure.as_mut().unwrap();
    policy.operation.work = p.maximum_work;
    policy.operation.arithmetic_steps = 100_000_000;
    policy.operation.literal_bytes = 4096;
    policy.store = policy.operation.clone();
    policy.refinement.precision = 8;
    policy.refinement.reduction_ceiling = 2;
    policy.refinement.rounds = 2;
    let profile = p.fence.as_mut().unwrap();
    profile.shape = vec!["one".into(), "half".into(), "quarter".into(), "eighth".into()];
    profile.inverse_wall = inverse;
    p
}

fn enclosed_definition() -> pn_records::wall::Inputs {
    pn_records::wall::Inputs {
        width: "1".into(),
        cumulative_tilt: "15/8".into(),
        bracket: pn_records::primitive::Range {
            lower: "1/2".into(),
            upper: "1".into(),
        },
        stopping_width: "1/128".into(),
        maximum_steps: 64,
        maximum_work: NumberId::NumbersReferenceWorkCeiling.integer(),
        maximum_replay_work: NumberId::NumbersReferenceWorkCeiling.integer(),
        floor: pn_records::wall::Floor::Rational,
        previous: pn_records::wall::Previous::Target,
        door: "1".into(),
        absolute_cap: "1/10".into(),
        relative_cap: "1/4".into(),
        deadband: "1/20".into(),
    }
}

/// Claim: A five-Actor reference declaration consumes a replayed inverse-wall enclosure through the lower-endpoint fence and independent-coordinate map, completes its declared solve and residual replay without changing charged prices, and refuses an altered wall scope. Literal N/N-minus-one controls pin production and replay separately beside the rational-wall solve; insufficient replay allowance also refuses production publication. Wrong frozen width, tilt or bleed, changed inverse evidence and a delivered wall below the binding range refuse. The rational-wall comparison retains its separate path.
/// ´claim:compiler:enclosed-wall-solve-binds-fence-map-and-residual´
/// ´test:integration:enclosed-wall-solve´
#[test]
fn enclosed_wall_solve() {
    let state = enclosed_state();
    let before = state.view().clone();
    let price = state.package().input().prices.last().unwrap().clone();
    for inverse in [true, false] {
        let p = enclosed_policy(&state, inverse);
        let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
        let definition = enclosed_definition();
        let reference = pn_epoch::wall::bind(&bound, definition.clone(), &PublishedReference(definition)).unwrap();
        let wall = reference.evaluate().unwrap();
        assert_eq!(wall.target.as_ref().unwrap().lower, "1/2");
        assert_eq!(wall.target.as_ref().unwrap().upper, "65/128");
        let consumed = if inverse {
            Some(reference.consume(&bound, &wall).unwrap())
        } else {
            None
        };
        let active = consumed.as_ref().unwrap_or(&bound);
        let fence = pn_epoch::fence::search(active, None).unwrap();
        assert_eq!(fence.selected.as_deref(), Some(if inverse { "1/2" } else { "1" }));
        if inverse {
            enclosed_fence(&bound, &fence);
        }
        let solved = pn_epoch::conserved::solve(active, &fence).unwrap();
        let checked = pn_epoch::conserved::replay(active, &solved).unwrap();
        assert_eq!(solved.rounds.len(), 3);
        assert_eq!(
            solved.rounds.last().unwrap().standing,
            checked.rounds.last().unwrap().standing
        );
        if inverse {
            for round in &solved.rounds {
                let map = &round.certified;
                let activations = &map.primitives[2..2 + map.point.len()];
                assert_eq!(activations.len(), 5);
                for activation in activations {
                    use pn_records::primitive::Node;
                    let query = &activation.query;
                    assert_eq!(query.coordinates[3], *wall.target.as_ref().unwrap());
                    assert!(query.nodes.iter().any(|node| matches!(node,
                        Node::Clamp(0, wall) if query.nodes[*wall] == Node::Coordinate(3)
                    )));
                }
            }
            let mut changed = solved.clone();
            changed.rounds[0].certified.wall_enclosure.as_mut().unwrap().upper = "1".into();
            assert!(matches!(
                pn_epoch::conserved::replay(active, &changed),
                Err(pn_epoch::conserved::Error::Scope)
            ));
        }
        let (production, replay, residuals) = if inverse {
            (
                NumberId::NumbersEnclosedWallProductionWork.integer(),
                NumberId::NumbersEnclosedWallReplayWork.integer(),
                [
                    "5670141826438649515891619368601199708332953414052388146919623/981010981479406899837363992476113976808150623333565068647018368",
                    "158459167044379273832471725989253443784384870325214392084444336722433273594407277236757607522198685041639631556016670729113/41698426653304478132274004120036559947438140753445930447086199182362541242148577432681496137945158911327465068169836485201280",
                    "154384356534326173951113198299405577634554285670260280189045521572196148144100982293584088608415339639816313833558425587755955994232765063577225262164976701288127670987487175037028274684088163898954996761/40677082559805512101152199789879933607564018006795460058126514322933456888137157109515011992513424507201615092650143047085721624065839183451394697839601295923799011604521478146473911063886593048570925736576",
                ],
            )
        } else {
            (
                NumberId::NumbersRationalWallProductionWork.integer(),
                NumberId::NumbersRationalWallReplayWork.integer(),
                [
                    "95835251845316451407327/17577709914569017269853056",
                    "1342422069073379924110811894088156726642243/372794307304807277232275496297520517193064960",
                    "173939885486187734702589247281184449958500746197177318821128591607/48412748022768835731083442280110380961561562754342471004276514293632",
                ],
            )
        };
        assert_eq!((solved.work, checked.work), (production, replay));
        assert_eq!(
            solved.rounds.iter().map(|r| r.residual.as_str()).collect::<Vec<_>>(),
            residuals
        );
        enclosed_work(&state, active.inputs().1, &wall, &fence, &solved, (production, replay));
        if inverse {
            enclosed_refusals(&bound, &wall, &solved);
        }
    }
    assert_eq!(state.view(), &before);
    assert_eq!(state.package().input().prices.last().unwrap(), &price);
}

fn enclosed_work(
    state: &pn_epoch::compiler::CompiledState,
    p: &Procedure,
    wall: &pn_records::wall::Record,
    fence: &pn_epoch::fence::Search,
    solved: &pn_records::conserved::SolveRecord,
    costs: (u64, u64),
) {
    let (production, replay) = costs;
    for (n, r, passes) in [
        (production - 1, replay, false),
        (production, replay, true),
        (production, replay - 1, false),
    ] {
        let mut policy = p.clone();
        policy.maximum_solve_work = n;
        policy.maximum_replay_work = r;
        let bound = bind_procedure(state, policy.clone(), &Published(policy), Limits::default()).unwrap();
        let definition = enclosed_definition();
        let reference = pn_epoch::wall::bind(&bound, definition.clone(), &PublishedReference(definition)).unwrap();
        let consumed = if p.fence.as_ref().unwrap().inverse_wall {
            Some(reference.consume(&bound, wall).unwrap())
        } else {
            None
        };
        let active = consumed.as_ref().unwrap_or(&bound);
        assert_eq!(
            pn_epoch::conserved::solve(active, fence).is_ok(),
            passes,
            "production={n} replay={r}"
        );
        assert_eq!(pn_epoch::conserved::replay(active, solved).is_ok(), r == replay);
    }
}

fn enclosed_refusals(
    bound: &pn_epoch::solve::BoundProcedure<'_>,
    wall: &pn_records::wall::Record,
    solved: &pn_records::conserved::SolveRecord,
) {
    use pn_epoch::wall::{self as reference, Error};
    let mut wrong_bleed = bound.inputs().1.clone();
    wrong_bleed.fence.as_mut().unwrap().bleed_squared = "one".into();
    let changed = bind_procedure(
        bound.inputs().0,
        wrong_bleed.clone(),
        &Published(wrong_bleed),
        Limits::default(),
    )
    .unwrap();
    let input = enclosed_definition();
    let checked = reference::bind(&changed, input.clone(), &PublishedReference(input)).unwrap();
    assert!(matches!(
        checked.consume(&changed, wall),
        Err(Error::Fence(pn_epoch::fence::Error::Profile))
    ));
    for field in [1, 0] {
        let mut input = enclosed_definition();
        if field == 0 {
            input.width = "2".into();
        } else {
            input.cumulative_tilt = "1".into();
        }
        let checked = reference::bind(bound, input.clone(), &PublishedReference(input)).unwrap();
        assert!(matches!(checked.consume(bound, wall), Err(Error::Scope)));
    }
    let input = enclosed_definition();
    let checked = reference::bind(bound, input.clone(), &PublishedReference(input)).unwrap();
    let mut changed = wall.clone();
    changed.target.as_mut().unwrap().upper = "1".into();
    assert!(matches!(
        checked.consume(bound, &changed),
        Err(Error::Wall(pn_graph::numeric::wall::Error::Record))
    ));
    let active = checked.consume(bound, wall).unwrap();
    let mut zero = pn_epoch::conserved::evaluate_map(&active, "0", &solved.rounds[0].certified.point, 8).unwrap();
    assert_eq!(zero.primitives, Vec::new());
    zero.wall_enclosure.as_mut().unwrap().upper = "1".into();
    assert!(matches!(
        pn_epoch::conserved::replay_map(&active, &zero),
        Err(pn_epoch::conserved::Error::Scope)
    ));
    let mut input = enclosed_definition();
    input.previous = pn_records::wall::Previous::Rational("3/37".into());
    let checked = reference::bind(bound, input.clone(), &PublishedReference(input)).unwrap();
    let capped = checked.evaluate().unwrap();
    assert!(matches!(
        checked.consume(bound, &capped),
        Err(Error::Procedure(ProcedureError::WallRange))
    ));
}

fn enclosed_fence(bound: &pn_epoch::solve::BoundProcedure<'_>, fence: &pn_epoch::fence::Search) {
    let p = bound.inputs().1;
    assert_eq!(fence.evidence.attempts[0].completion, Completion::Fail);
    for attempt in &fence.evidence.attempts {
        for index in &attempt.primitives {
            let record = &fence.evidence.primitives[*index];
            let input = pn_graph::numeric::activation::fence::Inputs {
                wall: "1/2".into(),
                bleed_squared: NumberId::NumbersReferenceSquaredBleed.value().into(),
                width: "1".into(),
                margin: "5/4".into(),
                cumulative_tilt: if attempt.rung == "1" { "15/8" } else { "15/16" }.into(),
            };
            let query = pn_graph::numeric::activation::fence::query(p, &input).unwrap();
            assert_eq!(record.query, query);
            let mut policy = p.clone();
            policy.enclosure.as_mut().unwrap().refinement.precision = record.precision;
            let endpoint = pn_graph::numeric::evaluate(&policy, &query, None).unwrap();
            assert_eq!(endpoint.bounds, record.evidence.bounds);
        }
    }
    let left = independent_activation(Q(1, 2), false, true);
    let right = independent_activation(Q(65, 128), false, true);
    assert!(!left.0.le(Q(16, 75)));
    assert!(!Q(16, 75).le(right.1));
}

/// Claim: A separately published reference definition binds through the frozen procedure, refuses a changed declaration and unsupported lower endpoint, and evaluates and replays zero width without changing the rational charged price.
/// ´claim:compiler:reference-wall-binding-preserves-charged-price´
/// ´test:integration:reference-wall-binding´
#[test]
fn reference_wall_binding() {
    use pn_epoch::wall;
    use pn_records::{
        primitive::Range,
        wall::{Floor, Inputs, Previous},
    };
    let state = state();
    let p = base_procedure(&state);
    let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
    let input = Inputs {
        width: "0".into(),
        cumulative_tilt: "15/8".into(),
        bracket: Range {
            lower: "1/2".into(),
            upper: "1".into(),
        },
        stopping_width: "1/128".into(),
        maximum_steps: 64,
        maximum_work: NumberId::NumbersZeroWidthReferenceWorkCeiling.integer(),
        maximum_replay_work: NumberId::NumbersZeroWidthReferenceWorkCeiling.integer(),
        floor: Floor::Rational,
        previous: Previous::Rational("3/37".into()),
        door: "1".into(),
        absolute_cap: "1/4".into(),
        relative_cap: "1/2".into(),
        deadband: "1/16".into(),
    };
    let published = PublishedReference(input.clone());
    let price = state.package().input().prices.last().unwrap().clone();
    let reference = wall::bind(&bound, input.clone(), &published).unwrap();
    let record = reference.evaluate().unwrap();
    assert_eq!(record.steps, Vec::new());
    assert_eq!(reference.replay(&record).unwrap(), record);
    assert_eq!(state.package().input().prices.last().unwrap(), &price);
    let mut changed = input.clone();
    changed.door = "2".into();
    assert!(matches!(
        wall::bind(&bound, changed, &published),
        Err(wall::Error::Publication)
    ));
    let mut changed = input;
    changed.bracket.lower = "1/1000".into();
    assert!(matches!(
        wall::bind(&bound, changed, &published),
        Err(wall::Error::Wall(pn_graph::numeric::wall::Error::Binding))
    ));
}
impl ProcedureVerifier for Published {
    fn published_procedure(&self, input: &Procedure) -> bool {
        input == &self.0
    }
}

fn declaration(state: &pn_epoch::compiler::CompiledState) -> Procedure {
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

fn state() -> pn_epoch::compiler::CompiledState {
    compile_final_state(
        &joined::package(
            &joined::anchors(),
            1,
            &[("seller", "100"), ("buyer", "100"), ("third", "100")],
        ),
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        1000,
    )
    .unwrap()
}

/// Claim: A solve declaration is retained with the frozen compiled package only after its boundary, constants edition, declared name and full public payload agree; wrong bindings and same-name payload substitution refuse, and only an explicit absolute-width policy and the admitted scalar inventory pass preflight; binary-format requests and held compositions refuse.
/// ´claim:compiler:solve-declarations-bind-to-admitted-primitives´
/// ´test:integration:procedure-binding´
#[test]
fn procedure_binding() {
    let state = state();
    let procedure = declaration(&state);
    let verifier = Published(procedure.clone());
    let bound = bind_procedure(&state, procedure.clone(), &verifier, Limits::default()).unwrap();
    assert!(std::ptr::eq(bound.inputs().0, &raw const state));
    assert_eq!(bound.inputs().1, &procedure);
    assert_eq!(bound.preflight(), Err(ProcedureError::Unsupported));
    let acts = joined::settlement();
    let burns = [("seller", "100"), ("buyer", "100"), ("third", "100")];
    for package in [joined::package(&acts, 2, &burns), joined::reordered_package(&acts, 2, &burns)] {
        let other = compile_final_state(&package, &joined::Verifier, &mut joined::numeric(), Limits::default(), 1000).unwrap();
        let input = declaration(&other);
        let published = Published(input.clone());
        let attached = bind_procedure(&other, input, &published, Limits::default()).unwrap();
        assert!(std::ptr::eq(attached.inputs().0, &raw const other));
    }
    for case in 0..3 {
        let mut bad = procedure.clone();
        match case {
            0 => bad.edition.edition += 1,
            1 => bad.boundary += 1,
            _ => bad.name.push_str("-other"),
        }
        assert_eq!(
            bind_procedure(&state, bad, &verifier, Limits::default()).unwrap_err(),
            ProcedureError::Binding
        );
    }
    let mut bad = procedure.clone();
    bad.maximum_work += 1;
    assert_eq!(
        bind_procedure(&state, bad, &verifier, Limits::default()).unwrap_err(),
        ProcedureError::Publication
    );
    for precision in [Precision::ExactRational, Precision::BinaryBits(vec![128, 256])] {
        let mut declared = procedure.clone();
        declared.precision = precision;
        let public = Published(declared.clone());
        assert_eq!(
            bind_procedure(&state, declared, &public, Limits::default())
                .unwrap()
                .preflight(),
            Err(ProcedureError::Unsupported)
        );
    }
    let mut admitted = procedure.clone();
    admitted.backend = "nrz-cas".into();
    admitted.precision = Precision::AbsoluteWidthBits(vec![4]);
    admitted.maximum_work = 3_000_000;
    let limits = Limits {
        work: 3_000_000,
        ..Limits::default()
    };
    admitted.enclosure = Some(pn_records::primitive::EnclosurePolicy {
        store: limits.clone(),
        operation: limits,
        refinement: nrz_cas::enclosure::RefinementPolicy {
            version: 1,
            precision: 4,
            grid_ceiling: 64,
            rounds: 2,
            reduction_ceiling: 4,
            term_ceiling: 64,
            checking_work: 100_000,
        },
    });
    let published = Published(admitted.clone());
    assert!(
        bind_procedure(&state, admitted.clone(), &published, Limits::default())
            .unwrap()
            .preflight()
            .is_ok()
    );
    for primitive in [Primitive::Matrix, Primitive::Krawczyk, Primitive::InverseGain] {
        let mut held = admitted.clone();
        held.primitives.insert(primitive);
        let published = Published(held.clone());
        assert!(
            bind_procedure(&state, held, &published, Limits::default())
                .unwrap()
                .preflight()
                .is_err()
        );
    }
}

/// Claim: Procedure records require finite positive limits and precision requests, a positive endpoint grid and margin above one, and a strictly descending nonnegative rung grid ending in zero; malformed declarations never enable numerical work.
/// ´claim:compiler:solve-records-refuse-malformed-procedures´
/// ´test:integration:procedure-records´
#[test]
fn procedure_records() {
    let procedure = declaration(&state());
    validate_procedure(&procedure, Limits::default()).unwrap();
    for grid in [vec![], vec!["1"], vec!["0", "1"], vec!["1", "1/1", "0"], vec!["-1", "0"]] {
        let mut bad = procedure.clone();
        bad.grid = grid.iter().map(ToString::to_string).collect();
        assert!(validate_procedure(&bad, Limits::default()).is_err());
    }
    for case in 0..10 {
        let mut bad = procedure.clone();
        match case {
            0 => bad.maximum_work = 0,
            1 => bad.maximum_iterations = 0,
            2 => bad.margin = "1".into(),
            3 => bad.endpoint_grid = "0".into(),
            4 => bad.precision = Precision::BinaryBits(vec![]),
            5 => bad.precision = Precision::BinaryBits(vec![64, 32]),
            6 => bad.primitives.clear(),
            7 => bad.maximum_solve_work = 0,
            8 => bad.maximum_replay_work = 0,
            _ => bad.backend.clear(),
        }
        assert_eq!(validate_procedure(&bad, Limits::default()), Err(RecordError::Procedure));
    }
}

fn interval(lower: &str, upper: &str) -> Bounds {
    Bounds {
        lower: lower.into(),
        upper: upper.into(),
    }
}
fn attempt(rung: &str, range: Bounds, completion: Completion) -> Attempt {
    let stop = match completion {
        Completion::Pass | Completion::Fail => AttemptStop::ComparisonSeparated,
        Completion::Indecisive => AttemptStop::PrecisionSequenceExhausted,
        Completion::Interrupted => AttemptStop::Interrupted,
    };
    Attempt {
        rung: rung.into(),
        margined_fence: range,
        work: 10,
        completion,
        stop,
        primitives: Vec::new(),
    }
}

/// Claim: Supplied evidence records require compatible verdict and stopping categories and a joined Work-exhaustion fault for a Work-limited straddle, with actual consumed Work never padded. An actual completed primitive straddle stopped before its next charge fits is recorded as INDECISIVE and passed over; missing or mismatched joins refuse. Precision-sequence completion remains declared, and interrupted transcripts carry no residual. These are structural consistency checks, not certification of the supplied map evaluations or sequence execution.
/// ´claim:compiler:solve-transcripts-separate-verdicts-from-interruption´
/// ´test:integration:evidence-records´
#[test]
fn evidence_records() {
    let procedure = declaration(&state());
    let evidence = Evidence {
        primitives: Vec::new(),
        hull: BTreeMap::from([("a".into(), interval("0", "2"))]),
        attempts: vec![
            attempt("1", interval("9/10", "11/10"), Completion::Indecisive),
            attempt("1/2", interval("0", "1"), Completion::Pass),
        ],
        residual: Some(Residual {
            candidate: BTreeMap::from([("a".into(), "1".into())]),
            residual_upper: "1/10".into(),
            contraction_upper: "1/2".into(),
            radius: "1/5".into(),
        }),
    };
    validate_evidence(&procedure, &evidence, Limits::default()).unwrap();
    let mut partial_work = evidence.clone();
    partial_work.attempts[0].work = 9;
    validate_evidence(&procedure, &partial_work, Limits::default()).unwrap();
    partial_work.attempts[0].stop = AttemptStop::WorkLimit;
    assert_eq!(
        validate_evidence(&procedure, &partial_work, Limits::default()),
        Err(RecordError::Attempt)
    );
    work_limited_record();
    for stop in [AttemptStop::ComparisonSeparated, AttemptStop::Interrupted] {
        partial_work.attempts[0].stop = stop;
        assert_eq!(
            validate_evidence(&procedure, &partial_work, Limits::default()),
            Err(RecordError::Attempt)
        );
    }
    let mut failed = evidence.clone();
    failed.attempts[0] = attempt("1", interval("11/10", "6/5"), Completion::Fail);
    validate_evidence(&procedure, &failed, Limits::default()).unwrap();
    let mut interrupted = evidence.clone();
    interrupted.attempts = vec![attempt("1", interval("9/10", "11/10"), Completion::Interrupted)];
    assert_eq!(
        validate_evidence(&procedure, &interrupted, Limits::default()),
        Err(RecordError::Residual)
    );
    interrupted.residual = None;
    validate_evidence(&procedure, &interrupted, Limits::default()).unwrap();
    assert_eq!(interrupted.attempts[0].completion, Completion::Interrupted);
    for case in 0..10 {
        let mut bad = evidence.clone();
        match case {
            0 => bad.hull.insert("a".into(), interval("2", "1")).map(|_| ()).unwrap(),
            1 => {
                bad.attempts[0].completion = Completion::Fail;
                bad.attempts[0].stop = AttemptStop::ComparisonSeparated;
            }
            2 => {
                bad.attempts[0].completion = Completion::Pass;
                bad.attempts[0].stop = AttemptStop::ComparisonSeparated;
            }
            3 => bad.attempts[0].work = 11,
            4 => bad.attempts[0].rung = "0".into(),
            5 => bad.attempts.push(attempt("0", interval("0", "0"), Completion::Pass)),
            6 => bad.residual.as_mut().unwrap().radius = "1/6".into(),
            7 => bad.residual.as_mut().unwrap().contraction_upper = "1".into(),
            8 => {
                bad.residual.as_mut().unwrap().candidate.insert("a".into(), "3".into());
            }
            _ => bad.residual.as_mut().unwrap().candidate.clear(),
        }
        assert!(validate_evidence(&procedure, &bad, Limits::default()).is_err(), "case {case}");
    }
}

// A restricted dense rational oracle: fixed small i128 inputs, no production
// normalization, transport, support or arbitrary-precision arithmetic calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fraction(i128, i128);
impl Fraction {
    fn new(n: i128, d: i128) -> Self {
        assert_ne!(d, 0);
        let (mut a, mut b) = (n.abs(), d.abs());
        while b != 0 {
            (a, b) = (b, a % b);
        }
        let sign = if d < 0 { -1 } else { 1 };
        Self(sign * n / a, d.abs() / a)
    }
    fn parse(s: &str) -> Self {
        let parts: Vec<_> = s.split('/').collect();
        Self::new(
            parts[0].parse().unwrap(),
            if parts.len() == 2 { parts[1].parse().unwrap() } else { 1 },
        )
    }
    fn plus(self, b: Self) -> Self {
        Self::new(self.0 * b.1 + b.0 * self.1, self.1 * b.1)
    }
    fn minus(self, b: Self) -> Self {
        Self::new(self.0 * b.1 - b.0 * self.1, self.1 * b.1)
    }
    fn times(self, b: Self) -> Self {
        Self::new(self.0 * b.0, self.1 * b.1)
    }
    fn over(self, b: Self) -> Self {
        Self::new(self.0 * b.1, self.1 * b.0)
    }
    fn order(self, b: Self) -> std::cmp::Ordering {
        (self.0 * b.1).cmp(&(b.0 * self.1))
    }
}
#[derive(Debug)]
struct FixtureArithmetic;
impl pn_records::transport::ExactArithmetic for FixtureArithmetic {
    type Number = Fraction;
    fn zero(&self) -> Fraction {
        Fraction(0, 1)
    }
    fn one(&self) -> Fraction {
        Fraction(1, 1)
    }
    fn add(&mut self, a: &Fraction, b: &Fraction) -> Result<Fraction, pn_records::transport::KernelError> {
        Ok(a.plus(*b))
    }
    fn sub(&mut self, a: &Fraction, b: &Fraction) -> Result<Fraction, pn_records::transport::KernelError> {
        Ok(a.minus(*b))
    }
    fn mul(&mut self, a: &Fraction, b: &Fraction) -> Result<Fraction, pn_records::transport::KernelError> {
        Ok(a.times(*b))
    }
    fn div(&mut self, a: &Fraction, b: &Fraction) -> Result<Fraction, pn_records::transport::KernelError> {
        Ok(a.over(*b))
    }
    fn compare(&mut self, a: &Fraction, b: &Fraction) -> Result<std::cmp::Ordering, pn_records::transport::KernelError> {
        Ok(a.order(*b))
    }
}

trait DenseNumber: Copy {
    fn zero() -> Self;
    fn one() -> Self;
    fn plus(self, other: Self) -> Self;
    fn minus(self, other: Self) -> Self;
    fn times(self, other: Self) -> Self;
    fn over(self, other: Self) -> Self;
}
impl DenseNumber for Fraction {
    fn zero() -> Self {
        Self(0, 1)
    }
    fn one() -> Self {
        Self(1, 1)
    }
    fn plus(self, b: Self) -> Self {
        self.plus(b)
    }
    fn minus(self, b: Self) -> Self {
        self.minus(b)
    }
    fn times(self, b: Self) -> Self {
        self.times(b)
    }
    fn over(self, b: Self) -> Self {
        self.over(b)
    }
}
fn dense_operator<T: DenseNumber>(hops: &[Vec<Vec<T>>], mass: &[T], emission: &[T]) -> Vec<Vec<T>> {
    let n = emission.len();
    let z = T::zero();
    let one = T::one();
    let mut current: Vec<Vec<_>> = (0..n)
        .map(|i| (0..n).map(|j| if i == j { one } else { z }).collect())
        .collect();
    let mut answer = vec![vec![z; n]; n];
    for (hop, mass) in hops.iter().zip(mass) {
        let normalized: Vec<Vec<_>> = hop
            .iter()
            .map(|row| {
                let sum = row.iter().copied().fold(z, T::plus);
                row.iter().map(|v| v.over(sum)).collect()
            })
            .collect();
        current = current
            .iter()
            .map(|row| {
                (0..n)
                    .map(|target| {
                        row.iter()
                            .zip(&normalized)
                            .map(|(left, right)| left.times(right[target]))
                            .fold(z, T::plus)
                    })
                    .collect()
            })
            .collect();
        for (result, row) in answer.iter_mut().zip(&current) {
            for (value, path) in result.iter_mut().zip(row) {
                *value = value.plus(mass.times(*path));
            }
        }
    }
    for (i, row) in answer.iter_mut().enumerate() {
        for value in row.iter_mut() {
            *value = emission[i].times(*value);
        }
        row[i] = row[i].plus(one.minus(emission[i]));
    }
    answer
}
fn sparse(rows: &[Vec<Fraction>]) -> pn_records::transport::Matrix<Fraction> {
    rows.iter().map(|row| row.iter().copied().enumerate().collect()).collect()
}

/// Claim: Exact sparse transport agrees with an independent dense rational operator on noncommuting source-adjacent hops, applies emission once, retains zero-balance identity rows and conserves each closed cluster's paired sums and equal rates; malformed premises and finite cell exhaustion refuse without a mathematical verdict.
/// ´claim:transport:transport-preserves-balance-and-count-mass´
/// ´test:integration:transport-oracle´
#[test]
fn transport_oracle() {
    use pn_graph::transport::exact_transport;
    use pn_records::transport::{KernelError, TransportInput};
    let z = Fraction(0, 1);
    let o = Fraction(1, 1);
    let half = Fraction(1, 2);
    let h1 = vec![vec![o, o, z], vec![z, o, z], vec![z, z, o]];
    let h2 = vec![vec![o, z, z], vec![o, o, z], vec![z, z, o]];
    let hops = vec![h1, h2];
    let mass = vec![half, half];
    let emission = vec![half, Fraction(0, 1), o];
    let expected = dense_operator(&hops, &mass, &emission);
    assert_ne!(
        expected,
        dense_operator(&[hops[1].clone(), hops[0].clone()], &mass, &emission)
    );
    let input = TransportInput {
        hops: hops.iter().map(|h| sparse(h)).collect(),
        depth_mass: mass,
        emission,
        counts: vec![o, Fraction(2, 1), Fraction(3, 1)],
        rates: vec![Fraction(4, 1); 3],
    };
    let result = exact_transport(&input, &mut FixtureArithmetic, 100).unwrap();
    for (row, expected) in result.emitted.iter().zip(&expected) {
        for (j, value) in expected.iter().enumerate() {
            assert_eq!(row.get(&j).copied().unwrap_or(z), *value);
        }
    }
    assert_eq!(result.emitted[1].get(&0).copied().unwrap_or(z), z);
    assert_eq!(result.emitted[1][&1], o);
    assert_eq!(result.standing, vec![Fraction(4, 1); 3]);
    for cluster in [vec![0, 1], vec![2]] {
        let counts = cluster.iter().map(|i| input.counts[*i]).fold(z, Fraction::plus);
        let after = cluster.iter().map(|i| result.denominator[*i]).fold(z, Fraction::plus);
        let amount = cluster.iter().map(|i| result.numerator[*i]).fold(z, Fraction::plus);
        assert_eq!(counts, after);
        assert_eq!(amount, counts.times(Fraction(4, 1)));
    }
    for case in 0..7 {
        let mut bad = input.clone();
        match case {
            0 => {
                bad.hops[0][0].insert(3, o);
            }
            1 => {
                bad.hops[0][0].insert(0, z);
            }
            2 => {
                bad.hops[0][0].insert(1, Fraction(-1, 1));
            }
            3 => bad.depth_mass[0] = o,
            4 => bad.emission[0] = Fraction(2, 1),
            5 => bad.counts[0] = z,
            _ => {
                bad.rates.pop();
            }
        }
        assert!(matches!(
            exact_transport(&bad, &mut FixtureArithmetic, 100),
            Err(KernelError::Input)
        ));
    }
    assert!(matches!(
        exact_transport(&input, &mut FixtureArithmetic, 1),
        Err(KernelError::Limit)
    ));
}

fn check_pairs(
    actual: &pn_epoch::anchor::ExactAnchor,
    actors: &[&String],
    expected: &[Vec<Fraction>],
    counts: &[Fraction],
    rates: &[Fraction],
) {
    let z = Fraction(0, 1);
    for (target, actor) in actors.iter().enumerate() {
        let denominator = expected
            .iter()
            .zip(counts)
            .map(|(row, n)| row[target].times(*n))
            .fold(z, Fraction::plus);
        let numerator = expected
            .iter()
            .zip(counts)
            .zip(rates)
            .map(|((row, n), r)| row[target].times(*n).times(*r))
            .fold(z, Fraction::plus);
        let standing = numerator.over(denominator);
        assert_eq!(Fraction::parse(&actual.denominator[*actor]), denominator);
        assert_eq!(Fraction::parse(&actual.numerator[*actor]), numerator);
        assert_eq!(Fraction::parse(&actual.standing[*actor]), standing);
        let mut contributors: Vec<_> = expected
            .iter()
            .zip(rates)
            .filter(|(row, _)| row[target] != z)
            .map(|(_, rate)| *rate)
            .collect();
        contributors.sort_by(|a, b| a.order(*b));
        assert_eq!(Fraction::parse(&actual.hull[*actor].lower), *contributors.first().unwrap());
        assert_eq!(Fraction::parse(&actual.hull[*actor].upper), *contributors.last().unwrap());
        assert!(!standing.order(Fraction::parse(&actual.hull[*actor].lower)).is_lt());
        assert!(!standing.order(Fraction::parse(&actual.hull[*actor].upper)).is_gt());
    }
    let expected_count = counts.iter().copied().fold(z, Fraction::plus);
    let actual_count = actual
        .denominator
        .values()
        .map(|s| Fraction::parse(s))
        .fold(z, Fraction::plus);
    assert_eq!(expected_count, actual_count);
}

fn check_anchor(compiled: &pn_epoch::compiler::CompiledState) {
    use pn_epoch::anchor::{AnchorOutcome, exact_anchor};
    let before = compiled.view().clone();
    let AnchorOutcome::Exact(actual) = exact_anchor(compiled, Limits::default(), 10000).unwrap() else {
        panic!("fixture requires exact base");
    };
    assert_eq!(compiled.view(), &before);
    let actors: Vec<_> = before.base.rows.keys().collect();
    let z = Fraction(0, 1);
    let one = Fraction(1, 1);
    let inputs = compiled.package().input().inputs.last().unwrap();
    let nu = Fraction::parse(inputs.parameters().numeraire.amount().exact());
    let threshold = Fraction::parse(compiled.package().input().prices.last().unwrap().price().exact());
    let counts: Vec<_> = actors
        .iter()
        .map(|a| {
            Fraction(
                i128::from(before.ledger.counts[&pn_records::burn::Address((*a).clone())].0),
                1,
            )
        })
        .collect();
    let balance: Vec<_> = actors
        .iter()
        .map(|a| Fraction::parse(before.ledger.balances[&pn_records::burn::Address((*a).clone())].exact()))
        .collect();
    let rates: Vec<_> = balance.iter().zip(&counts).map(|(b, n)| b.over(nu.times(*n))).collect();
    let emission: Vec<_> = balance
        .iter()
        .zip(&counts)
        .map(|(b, n)| {
            let e = b.over(threshold.times(*n));
            if e.order(one).is_gt() { one } else { e }
        })
        .collect();
    let base: Vec<Vec<_>> = actors
        .iter()
        .map(|a| {
            actors
                .iter()
                .map(|b| match before.base.rows[*a].get(*b).map(|entry| &entry.score) {
                    None => z,
                    Some(pn_epoch::base::BaseScore::Exact(s)) => Fraction::parse(s),
                    _ => panic!("held base not an exact oracle input"),
                })
                .collect()
        })
        .collect();
    // Joined fixture declares a one-hop unit mass independently of production transport.
    assert_eq!(inputs.parameters().depth_mass, vec!["one"]);
    let raw = dense_operator(std::slice::from_ref(&base), &[one], &vec![one; actors.len()]);
    let expected = dense_operator(&[base], &[one], &emission);
    for (source, row) in expected.iter().enumerate() {
        let actor = actors[source];
        let mut exported = z;
        for (target, value) in row.iter().enumerate() {
            assert_eq!(
                Fraction::parse(actual.emitted[actor].get(actors[target]).map_or("0", String::as_str)),
                *value
            );
            assert_eq!(
                Fraction::parse(actual.raw[actor].get(actors[target]).map_or("0", String::as_str)),
                raw[source][target]
            );
            assert_eq!(
                Fraction::parse(actual.normalized[actor].get(actors[target]).map_or("0", String::as_str)),
                raw[source][target]
            );
            if source != target {
                exported = exported.plus(value.times(counts[source]));
            }
        }
        assert!(!exported.order(balance[source].over(threshold)).is_gt());
    }
    check_pairs(&actual, &actors, &expected, &counts, &rates);
}

/// # Panics
/// Panics only if a controlled rational fixture unexpectedly returns held evidence.
///
/// Claim: The zero-tilt anchor consumes only the frozen exact base, final ledger and bound depth masses; an independent rational oracle checks paired transport, export ceilings, direct mediants and hull inclusion without changing the ledger, including zero balance, equal-rate and empty domains. Irrational base terms remain named holds rather than approximate standings.
/// ´claim:compiler:zero-tilt-anchor-keeps-ledger-and-irrational-holds´
/// ´test:integration:anchor-tables´
#[test]
fn anchor_tables() {
    let compile = |acts: &[pn_records::CandidateAct], burns: &[(&str, &str)]| {
        compile_final_state(
            &joined::package(acts, acts.iter().map(|act| act.finalization_epoch).max().unwrap_or(1), burns),
            &joined::Verifier,
            &mut joined::numeric(),
            Limits::default(),
            10000,
        )
        .unwrap()
    };
    check_anchor(&compile(
        &joined::anchors(),
        &[("seller", "5"), ("buyer", "5"), ("third", "5")],
    ));
    let mut acts = joined::anchors();
    acts.push(joined::act("Opinion", "seller", 2, 1));
    check_anchor(&compile(&acts, &[("seller", "4"), ("buyer", "5"), ("third", "5")]));
    check_anchor(&compile(&acts, &[("seller", "5"), ("buyer", "100"), ("third", "5")]));
    check_anchor(&compile(
        &joined::settlement(),
        &[("seller", "100"), ("buyer", "100"), ("third", "100")],
    ));
    check_anchor(&compile(&[], &[]));
    acts.last_mut()
        .unwrap()
        .body
        .quantities
        .iter_mut()
        .find(|(name, _)| name == "reaction.denominator")
        .unwrap()
        .1
        .value = 2;
    let held = compile(&acts, &[("seller", "100"), ("buyer", "100"), ("third", "100")]);
    let pn_epoch::anchor::AnchorOutcome::Held { entries } =
        pn_epoch::anchor::exact_anchor(&held, Limits::default(), 10000).unwrap()
    else {
        panic!("irrational fixture must remain held");
    };
    assert_eq!(entries.len(), 1);
    for ((source, target), score) in &entries {
        assert_eq!(score, &held.view().base.rows[source][target].score);
        let pn_epoch::base::BaseScore::Held { terms, .. } = score else {
            panic!("held entry requires retained terms");
        };
        assert!(terms.iter().all(|term| term.radicand == "1/2"));
    }
}

fn base_procedure(state: &pn_epoch::compiler::CompiledState) -> Procedure {
    let mut input = declaration(state);
    input.backend = "nrz-cas".into();
    input.precision = Precision::AbsoluteWidthBits(vec![4]);
    input.maximum_work = 10_000_000;
    let limits = Limits {
        work: input.maximum_work,
        ..Limits::default()
    };
    input.enclosure = Some(pn_records::primitive::EnclosurePolicy {
        store: limits.clone(),
        operation: limits,
        refinement: nrz_cas::enclosure::RefinementPolicy {
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

fn work_limited_record() {
    use pn_records::primitive::{Goal, Node, Outcome, PrimitiveRecord, Query, Range};
    let query = Query {
        coordinates: vec![Range {
            lower: "9/10".into(),
            upper: "11/10".into(),
        }],
        nodes: vec![Node::Coordinate(0)],
        target: 0,
        goal: Goal::AtMost("1".into()),
    };
    let mut p = base_procedure(&state());
    let policy = p.enclosure.as_mut().unwrap();
    policy.refinement.checking_work = 0;
    policy.refinement.rounds = 1;
    let first = pn_graph::numeric::evaluate(&p, &query, None).unwrap();
    p.maximum_work = first.work + 1;
    let policy = p.enclosure.as_mut().unwrap();
    policy.store.work = p.maximum_work;
    policy.operation.work = p.maximum_work;
    policy.refinement.rounds = 2;
    let stopped = pn_graph::numeric::evaluate(&p, &query, None).unwrap();
    assert_eq!(
        stopped.outcome,
        Outcome::Indecisive(nrz_cas::enclosure::UndecidedReason::WorkExhausted)
    );
    assert!(stopped.work < p.maximum_work);
    let mut first_attempt = attempt("1", interval("9/10", "11/10"), Completion::Indecisive);
    first_attempt.stop = AttemptStop::WorkLimit;
    first_attempt.work = stopped.work;
    first_attempt.primitives = vec![0];
    let evidence = Evidence {
        hull: BTreeMap::new(),
        attempts: vec![first_attempt, attempt("1/2", interval("0", "1"), Completion::Pass)],
        residual: None,
        primitives: vec![PrimitiveRecord {
            query,
            precision: 4,
            evidence: stopped,
        }],
    };
    validate_evidence(&p, &evidence, Limits::default()).unwrap();
    for case in 0..5 {
        let mut bad = evidence.clone();
        match case {
            0 => bad.attempts[0].primitives.clear(),
            1 => bad.attempts[0].primitives.push(0),
            2 => bad.attempts[0].work += 1,
            3 => bad.primitives[0].evidence.resource_fault = None,
            _ => bad.primitives[0].evidence.outcome = Outcome::Interrupted,
        }
        assert_eq!(validate_evidence(&p, &bad, Limits::default()), Err(RecordError::Attempt));
    }
}

fn base_root_bracket(x: Fraction) -> (Fraction, Fraction) {
    assert!(x.0 >= 0 && x.0 < 4 * x.1);
    let grid = 1_i128 << 16;
    let (mut low, mut high) = (0_i128, 2 * grid);
    while high - low > 1 {
        let middle = low.midpoint(high);
        if middle * middle * x.1 <= x.0 * grid * grid {
            low = middle;
        } else {
            high = middle;
        }
    }
    (Fraction::new(low, grid), Fraction::new(high, grid))
}

fn check_real_base(bound: &pn_epoch::solve::BoundProcedure<'_>) -> (usize, usize) {
    use pn_epoch::base::BaseScore;
    let (state, procedure) = bound.inputs();
    let (mut exact, mut held) = (0, 0);
    for (source, row) in &state.view().base.rows {
        for (target, original) in row {
            let result = pn_epoch::real_base::evaluate(bound, source, target, None).unwrap();
            assert_eq!(result.original, *original);
            match &original.score {
                BaseScore::Exact(_) => {
                    exact += 1;
                    assert!(result.primitive.is_none());
                }
                BaseScore::Held { exact_part, terms } => {
                    held += 1;
                    let record = result.primitive.unwrap();
                    assert_eq!(record.evidence.outcome, pn_records::primitive::Outcome::Bound);
                    let replayed =
                        pn_epoch::real_base::replay(bound, source, target, record.evidence.attachment.as_ref().unwrap(), None)
                            .unwrap();
                    assert_eq!(replayed.primitive.unwrap().evidence.bounds, record.evidence.bounds);
                    for index in [1, 3] {
                        let mut changed = record.query.clone();
                        changed.nodes[index] = pn_records::primitive::Node::Rational("2".into());
                        let substituted = pn_graph::numeric::evaluate(procedure, &changed, None).unwrap();
                        assert!(
                            pn_epoch::real_base::replay(bound, source, target, substituted.attachment.as_ref().unwrap(), None)
                                .is_err()
                        );
                    }
                    let mut oracle = (Fraction::parse(exact_part), Fraction::parse(exact_part));
                    for term in terms {
                        assert!(original.cells.contains(&term.cell));
                        let (a, b) = base_root_bracket(Fraction::parse(&term.radicand));
                        let factor = Fraction::parse(&term.domain_factor);
                        oracle = (oracle.0.plus(a.times(factor)), oracle.1.plus(b.times(factor)));
                    }
                    let bounds = record.evidence.bounds.unwrap();
                    let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
                    let lower = Fraction::parse(&bounds.lower().exact_string(&mut budget).unwrap());
                    let upper = Fraction::parse(&bounds.upper().exact_string(&mut budget).unwrap());
                    assert!(!lower.order(oracle.0).is_gt() && !oracle.1.order(upper).is_gt());
                    assert!(lower.0 > 0);
                }
            }
        }
    }
    (exact, held)
}

/// Claim: Six unsorted reaction denominators preserve every frozen base entry and its cells, radicands and domain factors while attaching replayable enclosures to irrational terms. Independent integer-square brackets lie inside those bounds; rational-root entries stay exact, and ledger, support and compiler output remain unchanged. No standing or rung is computed.
/// ´claim:compiler:real-base-enclosures-retain-frozen-provenance´
/// ´test:integration:real-base´
#[test]
fn real_base() {
    let (mut exact, mut held) = (0, 0);
    let denominators = [2, 9, 3, 4, 5, 1];
    assert_eq!(
        denominators.len(),
        usize::try_from(NumberId::NumbersEpochRealBaseDenominatorCount.integer()).unwrap()
    );
    for denominator in denominators {
        let mut acts = joined::anchors();
        let mut opinion = joined::act("Opinion", "seller", 2, 1);
        opinion
            .body
            .quantities
            .iter_mut()
            .find(|(name, _)| name == "reaction.denominator")
            .unwrap()
            .1
            .value = denominator;
        acts.push(opinion);
        let state = compile_final_state(
            &joined::package(&acts, 2, &[("seller", "100"), ("buyer", "100"), ("third", "100")]),
            &joined::Verifier,
            &mut joined::numeric(),
            Limits::default(),
            10000,
        )
        .unwrap();
        let before = state.view().clone();
        let procedure = base_procedure(&state);
        let bound = bind_procedure(&state, procedure.clone(), &Published(procedure), Limits::default()).unwrap();
        let counts = check_real_base(&bound);
        exact += counts.0;
        held += counts.1;
        assert_eq!(state.view(), &before);
        assert_eq!(
            pn_epoch::real_base::evaluate(&bound, "absent", "buyer", None),
            Err(ProcedureError::BaseEntry)
        );
    }
    assert_eq!((exact, held), (21, 3));
}

fn fence_procedure(state: &pn_epoch::compiler::CompiledState) -> Procedure {
    let mut p = base_procedure(state);
    p.maximum_work = NumberId::NumbersSolveWorkCeiling.integer();
    p.maximum_solve_work = NumberId::NumbersSolveWorkCeiling.integer();
    p.maximum_replay_work = NumberId::NumbersSolveWorkCeiling.integer();
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

fn fence_state(reaction: i64, buyer: &str) -> pn_epoch::compiler::CompiledState {
    let mut acts = joined::anchors();
    let mut opinion = joined::act("Opinion", "seller", 2, 1);
    opinion
        .body
        .quantities
        .iter_mut()
        .find(|(name, _)| name == "reaction.denominator")
        .unwrap()
        .1
        .value = reaction;
    acts.push(opinion);
    compile_final_state(
        &joined::package(&acts, 1, &[("seller", "50"), ("buyer", buyer), ("third", "100")]),
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        10000,
    )
    .unwrap()
}

fn search(state: &pn_epoch::compiler::CompiledState, p: &Procedure) -> pn_epoch::fence::Search {
    let bound = bind_procedure(state, p.clone(), &Published(p.clone()), Limits::default()).unwrap();
    pn_epoch::fence::search(&bound, None).unwrap()
}

/// Claim: The rung driver uses the frozen contributing width and cumulative shape through the deepest supported depth, evaluates the deployed wall gain independently at each attempted rung, and selects the first proved pass in the descending published grid; exact zero-width and empty-domain cases preserve the frozen state, and equal-width weighted graphs give identical fence transcripts. Replay rebuilds each retained question from the frozen package and refuses substituted width, tilt and wall queries or their attachments.
/// ´claim:compiler:width-fence-retains-frozen-support-and-anchor´
/// ´test:integration:fence-shapes´
#[test]
fn fence_shapes() {
    let left = fence_state(4, "100");
    let right = fence_state(1, "100");
    let third = fence_state(9, "100");
    assert_ne!(left.view().base, right.view().base);
    assert_eq!(left.view().support.ranges, right.view().support.ranges);
    let p = fence_procedure(&left);
    check_depth_fence(&left);
    check_fence_comparison(&p);
    let a = search(&left, &p);
    let b = search(&right, &fence_procedure(&right));
    assert_eq!(a, b);
    assert_eq!(a, search(&third, &fence_procedure(&third)));
    check_width_factor(&left, &a);
    check_fence_replay(&left, &p, &a);
    assert!(a.evidence.attempts.iter().any(|v| v.completion == Completion::Fail));
    assert!(a.selected.is_some());
    validate_evidence(&p, &a.evidence, Limits::default()).unwrap();
    for record in &a.evidence.primitives {
        let mut replay_policy = p.clone();
        replay_policy.enclosure.as_mut().unwrap().refinement.precision = record.precision;
        let replay = pn_graph::numeric::replay(
            &replay_policy,
            &record.query,
            record.evidence.attachment.as_ref().unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(replay.bounds, record.evidence.bounds);
    }
    assert!(
        pn_graph::numeric::replay(
            &p,
            &a.evidence.primitives[1].query,
            a.evidence.primitives[0].evidence.attachment.as_ref().unwrap(),
            None
        )
        .is_err()
    );
    for state in [
        state(),
        compile_final_state(
            &joined::package(&[], 1, &[]),
            &joined::Verifier,
            &mut joined::numeric(),
            Limits::default(),
            1000,
        )
        .unwrap(),
    ] {
        let before = state.view().clone();
        let p = fence_procedure(&state);
        let got = search(&state, &p);
        assert_eq!(got.selected, Some("1".into()));
        assert_eq!(got.evidence.attempts[0].work, 0);
        assert_eq!(got.evidence.attempts[0].margined_fence, interval("0", "0"));
        assert_eq!(state.view(), &before);
    }
    let mut anchor = p.clone();
    anchor.grid = vec!["0".into()];
    let got = search(&left, &anchor);
    assert_eq!(got.selected, Some("0".into()));
    assert_eq!(got.evidence.primitives.len(), 0);
    for case in 0..3 {
        let mut bad = p.clone();
        let profile = bad.fence.as_mut().unwrap();
        match case {
            0 => profile.inverse_wall = true,
            1 => profile.shape.swap(0, 3),
            _ => profile.bleed_squared = "zero".into(),
        }
        let bound = bind_procedure(&left, bad.clone(), &Published(bad), Limits::default()).unwrap();
        assert!(pn_epoch::fence::search(&bound, None).is_err());
    }
}

fn check_fence_replay(state: &pn_epoch::compiler::CompiledState, p: &Procedure, result: &pn_epoch::fence::Search) {
    let bound = bind_procedure(state, p.clone(), &Published(p.clone()), Limits::default()).unwrap();
    for attempt in &result.evidence.attempts {
        for index in &attempt.primitives {
            let record = &result.evidence.primitives[*index];
            let checked = pn_epoch::fence::replay(&bound, &attempt.rung, record).unwrap();
            assert_eq!(checked.bounds, record.evidence.bounds);
        }
    }
    let record = &result.evidence.primitives[0];
    for case in [2, 0, 1] {
        let mut changed = record.clone();
        match case {
            0 => changed.query.nodes[record.query.target - 3] = pn_records::primitive::Node::Rational("7".into()),
            1 => changed.query.nodes[record.query.target - 1] = pn_records::primitive::Node::Rational("7".into()),
            _ => {
                changed.query.coordinates[0] = pn_records::primitive::Range {
                    lower: "3".into(),
                    upper: "3".into(),
                }
            }
        }
        assert_ne!(changed.query, record.query, "mutation {case} must change the scope");
        let mut policy = p.clone();
        policy.enclosure.as_mut().unwrap().refinement.precision = record.precision;
        changed.evidence = pn_graph::numeric::evaluate(&policy, &changed.query, None).unwrap();
        assert!(changed.evidence.attachment.is_some());
        assert!(matches!(
            pn_epoch::fence::replay(&bound, &result.evidence.attempts[0].rung, &changed),
            Err(pn_epoch::fence::Error::Profile)
        ));
        changed.query = record.query.clone();
        let replay = pn_epoch::fence::replay(&bound, &result.evidence.attempts[0].rung, &changed);
        assert!(
            matches!(replay, Err(pn_epoch::fence::Error::Numeric(_))),
            "case {case}: {replay:?}"
        );
    }
}

/// Claim: A rung's fixed precision sequence uses fresh stores and retains actual Work and original queries; a straddle at sequence exhaustion and a straddle stopped before the next unaffordable operation are INDECISIVE and passed over, while interruption supplies no selected rung. A private starting precision cannot replace the declared sequence or alter its choice.
/// ´claim:rungs:rung-selection-respects-certified-verdicts´
/// ´test:integration:fence-refinement´
#[test]
fn fence_refinement() {
    let state = fence_state(1, "100");
    let mut p = fence_procedure(&state);
    // Tune an exact declared rung from a checked gain bracket, not from a point estimate.
    // The retained original query still checks the resulting fence independently.
    let preliminary = search(&state, &p);
    let first = &preliminary.evidence.primitives[0];
    let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    let b = first.evidence.bounds.as_ref().unwrap();
    let middle = b
        .lower()
        .add(b.upper(), &mut budget)
        .unwrap()
        .div(&nrz_cas::Rational::parse("2", &mut budget).unwrap(), &mut budget)
        .unwrap();
    let rung = nrz_cas::Rational::parse("1", &mut budget)
        .unwrap()
        .div(&middle, &mut budget)
        .unwrap()
        .exact_string(&mut budget)
        .unwrap();
    p.grid = vec![rung, "0".into()];
    p.precision = Precision::AbsoluteWidthBits(vec![4]);
    let first = search(&state, &p);
    assert_eq!(first.evidence.attempts[0].completion, Completion::Indecisive);
    assert_eq!(first.evidence.attempts[0].stop, AttemptStop::PrecisionSequenceExhausted);
    assert_eq!(first.selected, Some("0".into()));
    validate_evidence(&p, &first.evidence, Limits::default()).unwrap();
    let mut capped = p.clone();
    capped.precision = Precision::AbsoluteWidthBits(vec![4, 8]);
    capped.maximum_work = first.evidence.attempts[0].work + 1_000_000;
    let cap = capped.maximum_work;
    let policy = capped.enclosure.as_mut().unwrap();
    policy.store.work = cap;
    policy.operation.work = cap;
    let limited = search(&state, &capped);
    assert_eq!(limited.evidence.attempts[0].stop, AttemptStop::WorkLimit);
    assert!(limited.evidence.attempts[0].work < cap);
    assert_eq!(limited.selected, Some("0".into()));
    validate_evidence(&capped, &limited.evidence, Limits::default()).unwrap();
    let mut alternate = capped.clone();
    alternate.enclosure.as_mut().unwrap().refinement.precision = 8;
    assert_eq!(search(&state, &alternate), limited);
    let bound = bind_procedure(&state, capped.clone(), &Published(capped.clone()), Limits::default()).unwrap();
    let interrupted = pn_epoch::fence::search(&bound, Some(0)).unwrap();
    assert_eq!(
        interrupted.operational_stop,
        Some(pn_records::primitive::Outcome::Interrupted)
    );
    assert!(interrupted.selected.is_none());
    assert!(bind_procedure(&state, alternate, &Published(capped), Limits::default()).is_err());
}

#[derive(Debug)]
struct FencePublication(Vec<pn_epoch::package::EpochBinding>);
impl pn_epoch::package::PackageVerifier for FencePublication {
    fn published_package(&self, input: &pn_epoch::package::PackageInput) -> bool {
        input.bindings == self.0
    }
}

fn depths(state: &pn_epoch::compiler::CompiledState, names: &[&str]) -> pn_epoch::compiler::CompiledState {
    let (declaration, edition, _) = common::fixture();
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let record = pn_records::validate_record(&[], &history, &[declaration]).unwrap();
    let constants = pn_records::constants::bind_constants(&record, vec![edition]).unwrap();
    let mut package = state.package().input().clone();
    let mut parameters = package.inputs[0].parameters().clone();
    parameters.depth_mass = names.iter().map(|s| (*s).into()).collect();
    let input = pn_epoch::bind_inputs(&constants, parameters, Limits::default()).unwrap();
    package.inputs[0] = input.clone();
    package.bindings[0].inputs = input;
    let publication = FencePublication(package.bindings.clone());
    let verified = pn_epoch::package::verify_package(package, &publication).unwrap();
    compile_final_state(&verified, &joined::Verifier, &mut joined::numeric(), Limits::default(), 10000).unwrap()
}

fn check_depth_fence(state: &pn_epoch::compiler::CompiledState) {
    use pn_records::primitive::Node;
    for (mass, expected) in [(["third", "rest"], "5/3"), (["one", "zero"], "1")] {
        let state = depths(state, &mass);
        let p = fence_procedure(&state);
        let result = search(&state, &p);
        let first = &result.evidence.primitives[0].query;
        assert_eq!(first.nodes[first.target - 1], Node::Rational(expected.into()));
        validate_evidence(&p, &result.evidence, Limits::default()).unwrap();
    }
}

fn check_width_factor(state: &pn_epoch::compiler::CompiledState, result: &pn_epoch::fence::Search) {
    let expected = state.view().support.ranges.values().fold(Fraction(0, 1), |old, range| {
        let width = Fraction::parse(&range.maximum).minus(Fraction::parse(&range.minimum));
        if width.order(old).is_gt() { width } else { old }
    });
    for record in &result.evidence.primitives {
        let pn_records::primitive::Node::Rational(width) = &record.query.nodes[record.query.target - 3] else {
            panic!("fence must retain its width factor");
        };
        assert_eq!(Fraction::parse(width), expected);
    }
}

fn check_fence_comparison(p: &Procedure) {
    use pn_records::primitive::{Goal, Node, Outcome, Query};
    // Exact arithmetic controls for the same <= comparison used by the fence.
    for (value, expected) in [("1", Outcome::Pass), ("0", Outcome::Pass), ("2", Outcome::Fail)] {
        let query = Query {
            coordinates: vec![],
            nodes: vec![Node::Rational(value.into())],
            target: 0,
            goal: Goal::AtMost("1".into()),
        };
        let result = pn_graph::numeric::evaluate(p, &query, None).unwrap();
        assert_eq!(result.outcome, expected);
        let replay = pn_graph::numeric::replay(p, &query, result.attachment.as_ref().unwrap(), None).unwrap();
        assert_eq!(result.bounds, replay.bounds);
    }
}

fn conserved_state() -> pn_epoch::compiler::CompiledState {
    let actors = ["third", "fourth", "seller", "buyer"];
    let mut acts = Vec::new();
    for (index, actor) in actors.iter().enumerate() {
        acts.push(joined::act("Registration", actor, u64::try_from(index + 1).unwrap(), 1));
        let mut opinion = joined::act("Opinion", actor, u64::try_from(index + 5).unwrap(), 1);
        opinion.legs[0].target = joined::named("prof", actors[(index + 1) % actors.len()]);
        acts.push(opinion);
    }
    let state = compile_final_state(
        &joined::package(
            &acts,
            1,
            &[("third", "120"), ("fourth", "80"), ("seller", "100"), ("buyer", "60")],
        ),
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        10000,
    )
    .unwrap();
    let masses = ["third", "third", "third", "zero"];
    assert_eq!(
        masses.len(),
        usize::try_from(NumberId::NumbersFrozenDeclaredDepthCount.integer()).unwrap()
    );
    let state = depths(&state, &masses);
    assert_eq!(
        state.view().support.by_depth.len(),
        usize::try_from(NumberId::NumbersFrozenSupportedDepthCount.integer()).unwrap()
    );
    state
}

/// Claim: The separate full-emission box verification of the four-Actor frozen fixture independently replays two maps and their image-first residual. The finite witness pins point and box Work and both residual radii, including success and refusal at adjacent box Work allowances.
/// ´claim:compiler:two-map-verification-retains-frozen-fixture´
/// ´test:integration:two-map-box´
#[test]
fn two_map_box() {
    use pn_graph::numeric::verification;
    let state = conserved_state();
    let mut p = fence_procedure(&state);
    p.precision = Precision::AbsoluteWidthBits(vec![16]);
    p.grid = vec!["1/4".into(), "0".into()];
    p.maximum_iterations = 2;
    p.maximum_work = NumberId::NumbersVerificationTrialWorkCeiling.integer();
    p.maximum_solve_work = p.maximum_work;
    p.maximum_replay_work = p.maximum_work;
    let policy = p.enclosure.as_mut().unwrap();
    policy.refinement.precision = 16;
    policy.refinement.reduction_ceiling = 2;
    policy.operation.work = p.maximum_work;
    policy.operation.arithmetic_steps = 1_000_000_000;
    policy.operation.literal_bytes = 4096;
    policy.store = policy.operation.clone();
    let bound = bind_procedure(&state, p.clone(), &Published(p.clone()), Limits::default()).unwrap();
    let input = pn_epoch::conserved::verification_declaration(&bound, "1/4", 32).unwrap();
    let candidate = vec![
        pn_records::primitive::Range {
            lower: "43".into(),
            upper: "43".into()
        };
        4
    ];
    let result = verification::two_map(&p, &input, &candidate).unwrap();
    let checked = verification::replay_two_map(&p, &input, &candidate, &result).unwrap();
    assert_eq!(result.enclosure, checked.enclosure);
    assert_eq!(
        (
            result.first.work,
            result.second.work,
            result.one_map_radius.as_str(),
            result.radius.as_str()
        ),
        (
            NumberId::NumbersFrozenPointMapWork.integer(),
            NumberId::NumbersFrozenBoxMapWork.integer(),
            NumberId::NumbersFrozenOneMapRadius.value(),
            NumberId::NumbersFrozenImageFirstRadius.value()
        )
    );
    for cap in [
        NumberId::NumbersFrozenBoxMapWork.integer() - 1,
        NumberId::NumbersFrozenBoxMapWork.integer(),
    ] {
        let mut limited = p.clone();
        limited.maximum_work = cap;
        limited.enclosure.as_mut().unwrap().operation.work = cap;
        assert_eq!(
            verification::evaluate_box(&limited, &input, &result.first.image).is_ok(),
            cap == NumberId::NumbersFrozenBoxMapWork.integer()
        );
    }
}

fn endpoint_pair(a: Fraction, b: Fraction, budget: &mut nrz_cas::limits::Budget) -> nrz_cas::enclosure::Interval {
    nrz_cas::enclosure::Interval::new(
        nrz_cas::Rational::parse(&format!("{}/{}", a.0, a.1), budget).unwrap(),
        nrz_cas::Rational::parse(&format!("{}/{}", b.0, b.1), budget).unwrap(),
        budget,
    )
    .unwrap()
}

fn contains_fraction(value: &nrz_cas::enclosure::Interval, expected: Fraction, budget: &mut nrz_cas::limits::Budget) {
    let expected = nrz_cas::Rational::parse(&format!("{}/{}", expected.0, expected.1), budget).unwrap();
    assert!(!value.lower().compare(&expected, budget).unwrap().is_gt());
    assert!(!value.upper().compare(&expected, budget).unwrap().is_lt());
}

/// Claim: Twelve unsorted positive endpoint transports and a three-Actor, three-hop case with missing entries and a zero-emission source contain an independent dense rational operator and its pair mediants, including exact singleton inputs; factor order, emission and source counts are retained rather than inferred from interval row sums.
/// ´claim:compiler:endpoint-transport-contains-dense-rational-oracle´
/// ´test:integration:endpoint-transport´
#[test]
fn endpoint_transport() {
    check_sparse_three_actor_oracle();
    let z = Fraction(0, 1);
    let one = Fraction(1, 1);
    let counts = [Fraction(3, 1), Fraction(5, 1)];
    let rates = [Fraction(1, 1), Fraction(7, 4)];
    let mass = [Fraction(3, 4), Fraction(1, 4)];
    let emission = [Fraction(1, 2), Fraction(2, 3)];
    let mut distinct = BTreeSet::new();
    for seed in [5, 1, 4, 2, 6, 3] {
        for width in [Fraction(1, 16), z] {
            distinct.insert((seed, width.0));
            let hops = vec![
                vec![vec![one, Fraction(seed, 3)], vec![Fraction(2, 3), one]],
                vec![vec![one, Fraction(1, 3)], vec![Fraction(seed, 5), one]],
            ];
            let expected = dense_operator(&hops, &mass, &emission);
            let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
            let input = pn_records::transport::TransportInput {
                hops: hops
                    .iter()
                    .map(|h| {
                        h.iter()
                            .map(|row| {
                                row.iter()
                                    .enumerate()
                                    .map(|(j, v)| (j, endpoint_pair(v.minus(width), v.plus(width), &mut budget)))
                                    .collect()
                            })
                            .collect()
                    })
                    .collect(),
                depth_mass: mass.iter().map(|v| endpoint_pair(*v, *v, &mut budget)).collect(),
                emission: emission.iter().map(|v| endpoint_pair(*v, *v, &mut budget)).collect(),
                counts: counts.iter().map(|v| endpoint_pair(*v, *v, &mut budget)).collect(),
                rates: rates.iter().map(|v| endpoint_pair(*v, *v, &mut budget)).collect(),
            };
            let result = pn_graph::transport::enclosed::evaluate(&input, &mut budget, 100).unwrap();
            for (row, oracle) in result.emitted.iter().zip(&expected) {
                for (j, value) in oracle.iter().enumerate() {
                    contains_fraction(&row[&j], *value, &mut budget);
                }
            }
            for (target, value) in result.standing.iter().enumerate() {
                let denominator = expected
                    .iter()
                    .zip(counts)
                    .map(|(row, count)| row[target].times(count))
                    .fold(z, Fraction::plus);
                let numerator = expected
                    .iter()
                    .zip(counts)
                    .zip(rates)
                    .map(|((row, count), rate)| row[target].times(count).times(rate))
                    .fold(z, Fraction::plus);
                contains_fraction(value, numerator.over(denominator), &mut budget);
                if width == z {
                    assert_eq!(value.lower(), value.upper());
                }
            }
        }
    }
    assert_eq!(distinct.len(), 12);
}

/// Claim: Four unsorted positive standing inputs retain Actor-key scalar order, target-owned hop powers and unmodulated self scores in the frozen map; replay reconstructs the original scope and refuses a changed transported image. Independently computed activation and root brackets flow through the dense directed operator and pair mediants inside every image coordinate.
/// ´claim:compiler:conserved-map-replays-frozen-point-scopes´
/// ´test:integration:conserved-map´
#[test]
fn conserved_map() {
    let state = conserved_state();
    let mut p = fence_procedure(&state);
    p.precision = Precision::AbsoluteWidthBits(vec![4]);
    p.grid = vec!["1/4".into(), "0".into()];
    p.endpoint_grid = "1/16".into();
    p.maximum_iterations = 2;
    let limits = p.enclosure.as_mut().unwrap();
    limits.refinement.precision = 4;
    limits.refinement.reduction_ceiling = 2;
    let point = BTreeMap::from([
        ("third".into(), "3".into()),
        ("fourth".into(), "5/2".into()),
        ("seller".into(), "7/2".into()),
        ("buyer".into(), "4".into()),
    ]);
    let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
    let result = pn_epoch::conserved::evaluate_map(&bound, "1/4", &point, 4).unwrap();
    let checked = pn_epoch::conserved::replay_map(&bound, &result).unwrap();
    assert_eq!(checked.image, result.image);
    check_map_joins(&state, &result);
    check_independent_map(&state, &result);
    let mut changed = result.clone();
    changed.image.values_mut().next().unwrap().upper = "100".into();
    assert!(pn_epoch::conserved::replay_map(&bound, &changed).is_err());
}

fn check_map_joins(state: &pn_epoch::compiler::CompiledState, map: &pn_records::conserved::MapRecord) {
    let actors: Vec<_> = map.point.keys().collect();
    let mut budget = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    for (i, actor) in actors.iter().enumerate() {
        let request = &map.primitives[2 + i].query;
        assert_eq!(request.coordinates[0].lower, map.point[*actor]);
        assert_eq!(request.coordinates[0].upper, map.point[*actor]);
    }
    for (h, hop) in map.transport_input.hops.iter().enumerate() {
        for (source, row) in hop.iter().enumerate() {
            for (target, score) in row {
                let entry = &state.view().base.rows[actors[source]][actors[*target]];
                let pn_epoch::base::BaseScore::Exact(value) = &entry.score else {
                    panic!("literal fixture has rational bases");
                };
                let base = nrz_cas::Rational::parse(value, &mut budget).unwrap();
                if source == *target {
                    assert_eq!((score.lower(), score.upper()), (&base, &base));
                } else {
                    let index = 2 + actors.len() + 2 * (h * actors.len() + target);
                    let lower = map.primitives[index].evidence.bounds.as_ref().unwrap().lower();
                    let upper = map.primitives[index + 1].evidence.bounds.as_ref().unwrap().upper();
                    assert_eq!(score.lower(), &base.mul(lower, &mut budget).unwrap());
                    assert_eq!(score.upper(), &base.mul(upper, &mut budget).unwrap());
                }
            }
        }
    }
}

/// Claim: The declared rational proposal sequence is followed by one certified map per declared precision, and frozen-package replay reconstructs the residual intersection while rejecting changed residual and radius fields. Four denominator/cap declarations pin residuals, radii and each published width within the hull; their two-grid standings intersect, changed standing refuses, and a separate solve exhaustion cannot alter fence selection. The equal-hull four-Actor first proposal replays within its production allowance, and insufficient replay Work refuses solve publication. The compiler view and ledger remain immutable.
/// ´claim:compiler:projected-residual-replays-conserved-map´
/// ´test:integration:conserved-residual´
#[test]
fn conserved_residual() {
    check_solve_accuracy();
    check_prefix_pins();
    let state = conserved_state();
    let before = state.view().clone();
    let mut p = fence_procedure(&state);
    p.precision = Precision::AbsoluteWidthBits(vec![4]);
    p.grid = vec!["1/4".into(), "0".into()];
    p.endpoint_grid = "1/16".into();
    p.maximum_iterations = 2;
    // The existing explicit allowance covers candidate and residual work cumulatively.
    let limits = p.enclosure.as_mut().unwrap();
    limits.refinement.precision = 4;
    limits.refinement.reduction_ceiling = 2;
    let bound = bind_procedure(&state, p.clone(), &Published(p.clone()), Limits::default()).unwrap();
    let fence = pn_epoch::fence::search(&bound, None).unwrap();
    assert_eq!(fence.selected.as_deref(), Some("1/4"));
    let result = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    assert_eq!(result.work, NumberId::NumbersSolveSixteenthTwoWork.integer());
    let checked = pn_epoch::conserved::replay(&bound, &result).unwrap();
    assert_eq!(
        checked.rounds.last().unwrap().standing,
        result.rounds.last().unwrap().standing
    );
    for case in [1, 0] {
        let mut bad = result.clone();
        if case == 0 {
            bad.rounds[0].residual = "0".into();
        } else {
            bad.rounds[0].radius = "0".into();
        }
        let refused = pn_epoch::conserved::replay(&bound, &bad);
        assert!(if case == 0 {
            matches!(refused, Err(pn_epoch::conserved::Error::Residual))
        } else {
            matches!(refused, Err(pn_epoch::conserved::Error::Radius))
        });
    }
    assert_eq!(state.view(), &before);
    for case in [2, 0, 1] {
        let mut bad = result.clone();
        match case {
            0 => {
                bad.rounds[0].proposals.pop();
            }
            1 => {
                bad.rounds[0].certified.precision = 3;
            }
            _ => {
                bad.rounds.clear();
            }
        }
        assert!(matches!(
            pn_epoch::conserved::replay(&bound, &bad),
            Err(pn_epoch::conserved::Error::Scope)
        ));
    }
    check_solve_work(&state, &p, &fence, &result);
    let mut alternate = p.clone();
    alternate.endpoint_grid = "1/4".into();
    let bound = bind_procedure(&state, alternate.clone(), &Published(alternate.clone()), Limits::default()).unwrap();
    let comparison = pn_epoch::conserved::solve(&bound, &fence).unwrap();
    assert_eq!(comparison.work, NumberId::NumbersSolveQuarterTwoWork.integer());
    for cap in [
        NumberId::NumbersSolveQuarterTwoWork.integer(),
        NumberId::NumbersSolveQuarterTwoWork.integer() - 1,
    ] {
        let limited = work_policy(&alternate, cap);
        let bound = bind_procedure(&state, limited.clone(), &Published(limited), Limits::default()).unwrap();
        assert_eq!(
            pn_epoch::conserved::solve(&bound, &fence).is_ok(),
            cap == NumberId::NumbersSolveQuarterTwoWork.integer()
        );
    }
}

fn work_policy(p: &Procedure, cap: u64) -> Procedure {
    let mut result = p.clone();
    result.maximum_work = cap;
    result.maximum_solve_work = cap;
    let policy = result.enclosure.as_mut().unwrap();
    policy.operation.work = policy.operation.work.min(cap);
    result
}

fn check_solve_work(
    state: &pn_epoch::compiler::CompiledState,
    p: &Procedure,
    fence: &pn_epoch::fence::Search,
    result: &pn_records::conserved::SolveRecord,
) {
    for cap in [
        NumberId::NumbersSolveSixteenthTwoWork.integer(),
        NumberId::NumbersSolveSixteenthTwoWork.integer() - 1,
    ] {
        let limited = work_policy(p, cap);
        let bound = bind_procedure(state, limited.clone(), &Published(limited), Limits::default()).unwrap();
        assert_eq!(
            pn_epoch::conserved::solve(&bound, fence).is_ok(),
            cap == NumberId::NumbersSolveSixteenthTwoWork.integer()
        );
    }
    let round = &result.rounds[0];
    assert_eq!(round.candidate_work, NumberId::NumbersCandidateTotalWork.integer());
    assert_eq!(round.proposals.len(), 2);
    let repeated = &round.proposals[0];
    assert_eq!(repeated.point.len(), 4);
    assert!(
        repeated
            .point
            .values()
            .all(|value| value == repeated.point.values().next().unwrap())
    );
    assert!(repeated.primitives[2..6].windows(2).all(|pair| pair[0] == pair[1]));
    let mut replay_policy = p.clone();
    replay_policy.maximum_replay_work = repeated.work;
    let replay_bound = bind_procedure(state, replay_policy.clone(), &Published(replay_policy), Limits::default()).unwrap();
    let checked = pn_epoch::conserved::replay_map(&replay_bound, repeated).unwrap();
    assert_eq!(checked.image, repeated.image);
    assert!(checked.work <= repeated.work);
    for (map, expected) in [
        (&round.proposals[1], NumberId::NumbersSecondProposalWork.integer()),
        (&round.certified, NumberId::NumbersCertifiedMapWork.integer()),
        (&round.proposals[0], NumberId::NumbersFirstProposalWork.integer()),
    ] {
        assert_eq!(map.work, expected);
        for cap in [expected, expected - 1] {
            let limited = work_policy(p, cap);
            let bound = bind_procedure(state, limited.clone(), &Published(limited), Limits::default()).unwrap();
            let checked = pn_epoch::conserved::evaluate_map(&bound, &map.rung, &map.point, map.precision);
            assert_eq!(checked.is_ok(), cap == expected, "cap={cap}");
        }
    }
    check_kernel_work(p, &round.certified);
    check_activation_work(p, &round.certified);
}

fn check_kernel_work(p: &Procedure, map: &pn_records::conserved::MapRecord) {
    for cap in [
        NumberId::NumbersCertifiedTransportWork.integer(),
        NumberId::NumbersCertifiedTransportWork.integer() - 1,
    ] {
        let mut limits = p.enclosure.as_ref().unwrap().operation.clone();
        limits.work = cap;
        let mut budget = nrz_cas::limits::Budget::new(limits).unwrap();
        let output = pn_graph::transport::enclosed::evaluate(&map.transport_input, &mut budget, 10000);
        assert_eq!(output.is_ok(), cap == NumberId::NumbersCertifiedTransportWork.integer());
        if let Ok(output) = output {
            assert_eq!(output, map.transport);
            assert_eq!(budget.usage().work, cap);
        }
    }
}

fn check_activation_work(p: &Procedure, map: &pn_records::conserved::MapRecord) {
    let mut session =
        pn_graph::numeric::activation::sharing::Session::new(p, NumberId::NumbersReferenceSquaredBleed.value()).unwrap();
    let prefix = session.work();
    let value = map.point.values().next().unwrap().clone();
    let request = pn_graph::numeric::activation::Request {
        standing: pn_records::primitive::Range {
            lower: value.clone(),
            upper: value.clone(),
        },
        bleed_squared: NumberId::NumbersReferenceSquaredBleed.value().into(),
        wall: Some("2".into()),
        wall_enclosure: None,
        quantity: pn_graph::numeric::activation::Quantity::Clamped,
    };
    let index = session.evaluate(&request).unwrap();
    assert_eq!(session.evidence(index).unwrap().primitive.evidence.work, 8_961_551);
    assert_eq!(
        (prefix, session.work()),
        (NumberId::NumbersSolveCertifyingPrefixWork.integer(), 13_888_467)
    );
    for cap in [13_888_467, 13_888_466] {
        let policy = work_policy(p, cap);
        let mut session =
            pn_graph::numeric::activation::sharing::Session::new(&policy, NumberId::NumbersReferenceSquaredBleed.value())
                .unwrap();
        assert_eq!(session.evaluate(&request).is_ok(), cap == 13_888_467);
    }
}

fn singleton_hull_state() -> pn_epoch::compiler::CompiledState {
    let actors = ["third", "fourth", "seller", "buyer"];
    let acts: Vec<_> = actors
        .iter()
        .enumerate()
        .map(|(i, actor)| joined::act("Registration", actor, u64::try_from(i + 1).unwrap(), 1))
        .collect();
    // Registration pays the exact charge two, leaving reduced rate one third.
    let burns: Vec<_> = actors.iter().map(|actor| (*actor, "7/3")).collect();
    let state = compile_final_state(
        &joined::package(&acts, 1, &burns),
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        10000,
    )
    .unwrap();
    let masses = ["third", "third", "third", "zero"];
    assert_eq!(
        masses.len(),
        usize::try_from(NumberId::NumbersFrozenDeclaredDepthCount.integer()).unwrap()
    );
    let state = depths(&state, &masses);
    assert_eq!(
        state.view().support.by_depth.len(),
        usize::try_from(NumberId::NumbersFrozenSupportedDepthCount.integer()).unwrap()
    );
    state
}

fn conserved_policy(state: &pn_epoch::compiler::CompiledState, grid: &str) -> Procedure {
    let mut p = fence_procedure(state);
    p.precision = Precision::AbsoluteWidthBits(vec![4]);
    p.grid = vec!["1/4".into(), "0".into()];
    p.endpoint_grid = grid.into();
    p.maximum_iterations = 2;
    let limits = p.enclosure.as_mut().unwrap();
    limits.refinement.precision = 4;
    limits.refinement.reduction_ceiling = 2;
    p
}

/// Claim: Two declared dyadic grids produce different rational proposals outside a singleton non-dyadic hull, yet final projection and replay certify the same exact self-only standing. Changed starting points, contraction fields and non-dyadic proposal grids refuse; no private start enters the declared solve. On a non-singleton hull the replayed zero fence publishes the certified image exactly; a positive rung below the edge uses its evaluated contraction bound and a strictly smaller radius than the margin-only bound. Eight wall/ceiling bindings admit supported and refuse unsupported argument ranges at binding.
/// ´claim:compiler:projected-proposals-keep-hull-and-start-binding´
/// ´test:integration:conserved-projection´
#[test]
fn conserved_projection() {
    check_evaluated_contraction();
    check_wall_binding();
    let state = singleton_hull_state();
    let mut starts = BTreeSet::new();
    for grid in ["1/16", "1/4"] {
        let p = conserved_policy(&state, grid);
        let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
        let accepted = pn_epoch::fence::search(&bound, None).unwrap();
        let result = pn_epoch::conserved::solve(&bound, &accepted).unwrap();
        let round = &result.rounds[0];
        let start = round.proposals[0].point.values().next().unwrap();
        starts.insert(start.clone());
        assert!(Fraction::parse(start).order(Fraction(1, 3)).is_lt());
        assert!(round.certified.point.values().all(|p| p == "1/3"));
        assert!(round.standing.values().all(|r| r.lower == "1/3" && r.upper == "1/3"));
        assert_eq!(round.residual, "0");
        pn_epoch::conserved::replay(&bound, &result).unwrap();
        for case in [1, 0] {
            let mut changed = result.clone();
            if case == 0 {
                *changed.rounds[0].proposals[0].point.values_mut().next().unwrap() = "9".into();
            } else {
                changed.rounds[0].contraction = "1".into();
            }
            let refused = pn_epoch::conserved::replay(&bound, &changed);
            assert!(if case == 0 {
                matches!(refused, Err(pn_epoch::conserved::Error::Scope))
            } else {
                matches!(refused, Err(pn_epoch::conserved::Error::Residual))
            });
        }
    }
    assert_eq!(starts.len(), 2);
    let p = conserved_policy(&state, "1/3");
    let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
    let accepted = pn_epoch::fence::search(&bound, None).unwrap();
    assert!(matches!(
        pn_epoch::conserved::solve(&bound, &accepted),
        Err(pn_epoch::conserved::Error::Scope)
    ));
}

fn check_evaluated_contraction() {
    let state = conserved_state();
    for rung in ["1/8", "0"] {
        let mut p = conserved_policy(&state, "1/16");
        p.grid = if rung == "0" {
            vec!["0".into()]
        } else {
            vec![rung.into(), "0".into()]
        };
        let bound = bind_procedure(&state, p.clone(), &Published(p), Limits::default()).unwrap();
        let accepted = pn_epoch::fence::search(&bound, None).unwrap();
        assert_eq!(accepted.selected.as_deref(), Some(rung));
        let result = pn_epoch::conserved::solve(&bound, &accepted).unwrap();
        let round = &result.rounds[0];
        let mut b = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
        let c = nrz_cas::Rational::parse(&round.contraction, &mut b).unwrap();
        let upper = nrz_cas::Rational::parse(&accepted.evidence.attempts.last().unwrap().margined_fence.upper, &mut b).unwrap();
        let margin = nrz_cas::Rational::parse("5/4", &mut b).unwrap();
        assert_eq!(c, upper.div(&margin, &mut b).unwrap());
        assert!(accepted.evidence.hull.values().all(|h| h.lower != h.upper));
        if rung == "0" {
            assert!(c.is_zero());
            assert_eq!(round.standing, round.certified.image);
        } else {
            let old = nrz_cas::Rational::parse("4/5", &mut b).unwrap();
            assert!(c.compare(&old, &mut b).unwrap().is_lt());
            let r = nrz_cas::Rational::parse(&round.residual, &mut b).unwrap();
            let radius = nrz_cas::Rational::parse(&round.radius, &mut b).unwrap();
            let old_radius = r.mul(&nrz_cas::Rational::parse("5", &mut b).unwrap(), &mut b).unwrap();
            assert!(radius.compare(&old_radius, &mut b).unwrap().is_lt());
        }
        pn_epoch::conserved::replay(&bound, &result).unwrap();
        if rung == "0" {
            let mut bad = accepted.clone();
            bad.evidence.attempts.last_mut().unwrap().margined_fence.upper = "1/2".into();
            assert!(pn_epoch::conserved::solve(&bound, &bad).is_err());
        }
    }
}

// Independent small-integer oracle. No nrz numbers, producer, interval or checker calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Q(i128, i128);
impl Q {
    fn new(n: i128, d: i128) -> Self {
        assert_ne!(d, 0);
        let (mut a, mut b) = (n.abs(), d.abs());
        while b != 0 {
            (a, b) = (b, a % b);
        }
        Self(n / a * d.signum(), d.abs() / a)
    }
    fn parse(s: &str) -> Self {
        let (n, d) = s.split_once('/').unwrap_or((s, "1"));
        Self::new(n.parse().unwrap(), d.parse().unwrap())
    }
    fn add(self, b: Self) -> Self {
        Self::new(self.0 * b.1 + b.0 * self.1, self.1 * b.1)
    }
    fn neg(self) -> Self {
        Self(-self.0, self.1)
    }
    fn mul(self, b: Self) -> Self {
        Self::new(self.0 * b.0, self.1 * b.1)
    }
    fn div(self, b: Self) -> Self {
        Self::new(self.0 * b.1, self.1 * b.0)
    }
    fn le(self, b: Self) -> bool {
        self.0 * b.1 <= b.0 * self.1
    }
    fn round(self, bits: u32, upper: bool) -> Self {
        let scale = 1_i128 << bits;
        let n = self.0 * scale;
        Self::new(n.div_euclid(self.1) + i128::from(upper && n.rem_euclid(self.1) != 0), scale)
    }
}
// Directed integer rounding on a fixed grid bounds every product in the
// independent binomial oracle; it shares no analytic series with the backend.
fn rounded_power(mut base: Q, mut exponent: u32, upper: bool) -> Q {
    let mut result = Q(1, 1);
    while exponent != 0 {
        if exponent % 2 == 1 {
            result = result.mul(base).round(32, upper);
        }
        exponent /= 2;
        if exponent != 0 {
            base = base.mul(base).round(32, upper);
        }
    }
    result
}

fn tight_exp(x: Q) -> (Q, Q) {
    let one = Q(1, 1);
    if x.0 < 0 {
        let (a, b) = tight_exp(x.neg());
        return (one.div(b), one.div(a));
    }
    let h = x.div(Q(4096, 1));
    (
        rounded_power(one.add(h), 4096, false),
        one.div(rounded_power(one.add(h.neg()), 4096, false)),
    )
}

fn tight_log(x: Q) -> (Q, Q) {
    if x.le(Q(1, 1)) {
        if x == Q(1, 1) {
            return (Q(0, 1), Q(0, 1));
        }
        let (a, b) = tight_log(Q(1, 1).div(x));
        return (b.neg(), a.neg());
    }
    let h = x.add(Q(-1, 1)).div(Q(4096, 1));
    let (mut lower, mut upper) = (Q(0, 1), Q(0, 1));
    for i in 0..4096 {
        lower = lower.add(h.div(Q(1, 1).add(h.mul(Q(i + 1, 1)))).round(32, false));
        upper = upper.add(h.div(Q(1, 1).add(h.mul(Q(i, 1)))).round(32, true));
    }
    (lower, upper)
}
// Independent directed fixed-grid computation, using integral/binomial brackets
// and integer root comparisons rather than the backend's analytic series.
#[derive(Clone, Copy, Debug)]
struct I(Q, Q);
impl I {
    fn point(value: Q) -> Self {
        Self(value, value)
    }
    fn rounded(a: Q, b: Q) -> Self {
        Self(a.round(24, false), b.round(24, true))
    }
    fn add(self, b: Self) -> Self {
        Self::rounded(self.0.add(b.0), self.1.add(b.1))
    }
    fn sub(self, b: Self) -> Self {
        Self::rounded(self.0.add(b.1.neg()), self.1.add(b.0.neg()))
    }
    fn mul(self, b: Self) -> Self {
        let values = [self.0.mul(b.0), self.0.mul(b.1), self.1.mul(b.0), self.1.mul(b.1)];
        let (mut low, mut high) = (values[0], values[0]);
        for value in values {
            if value.le(low) {
                low = value;
            }
            if high.le(value) {
                high = value;
            }
        }
        Self::rounded(low, high)
    }
    fn div(self, b: Self) -> Self {
        assert!(b.0.0 > 0);
        self.mul(Self::rounded(Q(1, 1).div(b.1), Q(1, 1).div(b.0)))
    }
    fn root(self, degree: u32) -> Self {
        fn endpoint(x: Q, degree: u32, upper: bool) -> Q {
            assert!(x.0 >= 0 && x.0 < 8_i128.pow(degree) * x.1);
            let scale = 1_i128 << 24;
            let target = x.0 * scale.pow(degree);
            let (mut low, mut high) = (0_i128, 8 * scale);
            while high - low > 1 {
                let middle = high.midpoint(low);
                if middle.pow(degree) * x.1 <= target {
                    low = middle;
                } else {
                    high = middle;
                }
            }
            Q::new(low + i128::from(upper && low.pow(degree) * x.1 != target), scale)
        }
        Self(endpoint(self.0, degree, false), endpoint(self.1, degree, true))
    }
    fn sigmoid(self) -> Self {
        let one = Q(1, 1);
        let (a, _) = tight_exp(self.0);
        let (_, b) = tight_exp(self.1);
        Self::rounded(a.div(one.add(a)), b.div(one.add(b)))
    }
    fn tanh(self) -> Self {
        let one = Q(1, 1);
        let (a, _) = tight_exp(self.0.mul(Q(2, 1)));
        let (_, b) = tight_exp(self.1.mul(Q(2, 1)));
        Self::rounded(a.add(one.neg()).div(a.add(one)), b.add(one.neg()).div(b.add(one)))
    }
}

fn independent_activation(x: Q, clean: bool, gain: bool) -> I {
    let one = I::point(Q(1, 1));
    let (log_lower, log_upper) = tight_log(Q(2, 1));
    let beta = I::rounded(log_lower.mul(Q(2, 1)), log_upper.mul(Q(2, 1)));
    let eta = I::point(if clean { Q(0, 1) } else { Q(1, 400) });
    let denominator = I::point(Q(1, 1).add(x));
    let p = I::point(x.div(Q(1, 1).add(x)));
    let core = |p: I| {
        let t = p.tanh();
        beta.mul(p).sigmoid().mul(t.mul(one.sub(eta.mul(t))).root(2))
    };
    if gain {
        let t = p.tanh();
        let slope = one.sub(t.mul(t));
        let kernel = beta
            .mul(one.sub(beta.mul(p).sigmoid()))
            .add(slope.div(I::point(Q(2, 1)).mul(t)))
            .sub(eta.mul(slope).div(I::point(Q(2, 1)).mul(one.sub(eta.mul(t)))));
        let gain = kernel.div(denominator.mul(denominator));
        if clean { gain } else { gain.mul(I::point(Q(1, 4))) }
    } else {
        core(p).div(core(one)).root(2).root(2)
    }
}

impl DenseNumber for I {
    fn zero() -> Self {
        Self::point(Q(0, 1))
    }
    fn one() -> Self {
        Self::point(Q(1, 1))
    }
    fn plus(self, b: Self) -> Self {
        self.add(b)
    }
    fn minus(self, b: Self) -> Self {
        self.sub(b)
    }
    fn times(self, b: Self) -> Self {
        self.mul(b)
    }
    fn over(self, b: Self) -> Self {
        self.div(b)
    }
}

fn check_independent_map(state: &pn_epoch::compiler::CompiledState, map: &pn_records::conserved::MapRecord) {
    let actors: Vec<_> = map.point.keys().collect();
    let powers: Vec<_> = map
        .point
        .values()
        .map(|x| {
            let a = independent_activation(Q::parse(x), false, false);
            [a.root(2).root(2), a.root(2).root(3), a.root(2).root(2).root(3)]
        })
        .collect();
    let hops: Vec<Vec<Vec<I>>> = (0..3)
        .map(|hop| {
            actors
                .iter()
                .enumerate()
                .map(|(source, actor)| {
                    actors
                        .iter()
                        .enumerate()
                        .map(|(target, recipient)| {
                            let Some(entry) = state.view().base.rows[*actor].get(*recipient) else {
                                return I::zero();
                            };
                            let pn_epoch::base::BaseScore::Exact(value) = &entry.score else {
                                panic!("rational fixture")
                            };
                            let base = I::point(Q::parse(value));
                            if source == target {
                                base
                            } else {
                                base.mul(powers[target][hop])
                            }
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    let sources = &state.view().support.sources;
    let emissions: Vec<_> = actors.iter().map(|a| I::point(Q::parse(&sources[*a].emission))).collect();
    let counts: Vec<_> = actors
        .iter()
        .map(|a| {
            I::point(Q(
                i128::from(state.view().ledger.counts[&pn_records::burn::Address((*a).clone())].0),
                1,
            ))
        })
        .collect();
    let rates: Vec<_> = actors.iter().map(|a| I::point(Q::parse(&sources[*a].reduced_rate))).collect();
    let operator = dense_operator(&hops, &[I::point(Q(1, 3)); 3], &emissions);
    let mut b = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    for (target, actor) in actors.iter().enumerate() {
        let denominator = operator
            .iter()
            .zip(&counts)
            .map(|(row, count)| row[target].mul(*count))
            .fold(I::zero(), I::add);
        let numerator = operator
            .iter()
            .zip(&counts)
            .zip(&rates)
            .map(|((row, count), rate)| row[target].mul(*count).mul(*rate))
            .fold(I::zero(), I::add);
        let oracle = numerator.div(denominator);
        let value = &map.image[*actor];
        let lo = nrz_cas::Rational::parse(&value.lower, &mut b).unwrap();
        let hi = nrz_cas::Rational::parse(&value.upper, &mut b).unwrap();
        let a = nrz_cas::Rational::parse(&format!("{}/{}", oracle.0.0, oracle.0.1), &mut b).unwrap();
        let z = nrz_cas::Rational::parse(&format!("{}/{}", oracle.1.0, oracle.1.1), &mut b).unwrap();
        assert!(!lo.compare(&a, &mut b).unwrap().is_gt());
        assert!(!hi.compare(&z, &mut b).unwrap().is_lt());
    }
}

fn check_sparse_three_actor_oracle() {
    let z = Fraction(0, 1);
    let o = Fraction(1, 1);
    let hops = vec![
        vec![vec![o, z, o], vec![o, o, z], vec![z, o, o]],
        vec![vec![o, o, z], vec![z, o, o], vec![o, z, o]],
        vec![vec![o, z, o], vec![z, o, z], vec![o, o, o]],
    ];
    let mass = [Fraction(1, 2), Fraction(1, 3), Fraction(1, 6)];
    let emission = [o, z, Fraction(2, 3)];
    let counts = [Fraction(3, 1), Fraction(2, 1), o];
    let rates = [Fraction(7, 1), o, Fraction(3, 1)];
    let expected = dense_operator(&hops, &mass, &emission);
    let mut b = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    let input = pn_records::transport::TransportInput {
        hops: hops
            .iter()
            .map(|h| {
                h.iter()
                    .map(|row| {
                        row.iter()
                            .enumerate()
                            .filter(|(_, v)| **v != z)
                            .map(|(i, v)| (i, endpoint_pair(*v, *v, &mut b)))
                            .collect()
                    })
                    .collect()
            })
            .collect(),
        depth_mass: mass.iter().map(|v| endpoint_pair(*v, *v, &mut b)).collect(),
        emission: emission.iter().map(|v| endpoint_pair(*v, *v, &mut b)).collect(),
        counts: counts.iter().map(|v| endpoint_pair(*v, *v, &mut b)).collect(),
        rates: rates.iter().map(|v| endpoint_pair(*v, *v, &mut b)).collect(),
    };
    let result = pn_graph::transport::enclosed::evaluate(&input, &mut b, 100).unwrap();
    for (i, row) in expected.iter().enumerate() {
        for (j, value) in row.iter().enumerate() {
            if let Some(got) = result.emitted[i].get(&j) {
                contains_fraction(got, *value, &mut b);
            } else {
                assert_eq!(*value, z);
            }
        }
    }
    for (target, got) in result.standing.iter().enumerate() {
        let denominator = expected
            .iter()
            .zip(counts)
            .map(|(row, n)| row[target].times(n))
            .fold(z, Fraction::plus);
        let numerator = expected
            .iter()
            .zip(counts)
            .zip(rates)
            .map(|((row, n), r)| row[target].times(n).times(r))
            .fold(z, Fraction::plus);
        contains_fraction(got, numerator.over(denominator), &mut b);
        assert_eq!(got.lower(), got.upper());
    }
}

fn check_solve_accuracy() {
    let state = conserved_state();
    let mut results = Vec::new();
    for (grid, cap) in [("1/16", 2), ("1/4", 1), ("1/16", 1), ("1/4", 2)] {
        results.push((grid, cap, accuracy_case(&state, grid, cap)));
    }
    for cap in [2, 1] {
        let a = &results.iter().find(|(d, c, _)| *d == "1/16" && *c == cap).unwrap().2;
        let z = &results.iter().find(|(d, c, _)| *d == "1/4" && *c == cap).unwrap().2;
        let mut b = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
        for (actor, range) in a {
            let other = &z[actor];
            assert!(
                !nrz_cas::Rational::parse(&range.lower, &mut b)
                    .unwrap()
                    .compare(&nrz_cas::Rational::parse(&other.upper, &mut b).unwrap(), &mut b)
                    .unwrap()
                    .is_gt()
            );
            assert!(
                !nrz_cas::Rational::parse(&other.lower, &mut b)
                    .unwrap()
                    .compare(&nrz_cas::Rational::parse(&range.upper, &mut b).unwrap(), &mut b)
                    .unwrap()
                    .is_gt()
            );
        }
    }
}

fn accuracy_case(state: &pn_epoch::compiler::CompiledState, grid: &str, cap: u64) -> BTreeMap<String, Bounds> {
    let mut p = conserved_policy(state, grid);
    p.maximum_iterations = cap;
    let bound = bind_procedure(state, p.clone(), &Published(p.clone()), Limits::default()).unwrap();
    let accepted = pn_epoch::fence::search(&bound, None).unwrap();
    let result = pn_epoch::conserved::solve(&bound, &accepted).unwrap();
    let round = &result.rounds[0];
    let expected = match (grid, cap) {
        ("1/16", 2) => NumberId::NumbersSolveSixteenthTwoWork.integer(),
        ("1/4", 1) => NumberId::NumbersSolveQuarterOneWork.integer(),
        ("1/16", 1) => NumberId::NumbersSolveSixteenthOneWork.integer(),
        ("1/4", 2) => NumberId::NumbersSolveQuarterTwoWork.integer(),
        _ => unreachable!(),
    };
    assert_eq!(result.work, expected);
    for work in [expected, expected - 1] {
        let mut limited = p.clone();
        limited.maximum_solve_work = work;
        limited.maximum_replay_work = work;
        let bounded = bind_procedure(state, limited.clone(), &Published(limited), Limits::default()).unwrap();
        assert_eq!(pn_epoch::conserved::solve(&bounded, &accepted).is_ok(), work == expected);
        if work == expected {
            let replayed = pn_epoch::conserved::replay(&bounded, &result).unwrap();
            assert!(
                replayed.work <= result.work,
                "replay {} producer {}",
                replayed.work,
                result.work
            );
            assert_eq!(replayed.rounds[0].standing, round.standing);
        }
    }
    assert_accuracy(round, &accepted.evidence.hull, grid);
    let mut no_solve = p.clone();
    no_solve.maximum_solve_work = 1;
    let limited = bind_procedure(state, no_solve.clone(), &Published(no_solve), Limits::default()).unwrap();
    assert_eq!(pn_epoch::fence::search(&limited, None).unwrap(), accepted);
    assert!(pn_epoch::conserved::solve(&limited, &accepted).is_err());
    let mut no_replay = p.clone();
    no_replay.maximum_replay_work = 1;
    let limited = bind_procedure(state, no_replay.clone(), &Published(no_replay), Limits::default()).unwrap();
    assert!(pn_epoch::conserved::replay(&limited, &result).is_err());
    assert!(pn_epoch::conserved::solve(&limited, &accepted).is_err());
    let mut altered = result.clone();
    altered.rounds[0].standing.values_mut().next().unwrap().upper = "999".into();
    assert!(matches!(
        pn_epoch::conserved::replay(&bound, &altered),
        Err(pn_epoch::conserved::Error::Residual)
    ));
    round.standing.clone()
}

fn assert_accuracy(round: &pn_records::conserved::ResidualRound, hull: &BTreeMap<String, Bounds>, grid: &str) {
    let (residual, radius, widths) = match grid {
        "1/16" => (
            NumberId::NumbersSolveSixteenthResidual.value(),
            NumberId::NumbersSolveSixteenthRadius.value(),
            [
                NumberId::NumbersSolveSixteenthAliceWidth.value(),
                NumberId::NumbersSolveSixteenthBobWidth.value(),
                NumberId::NumbersSolveSixteenthCarolWidth.value(),
                NumberId::NumbersSolveSixteenthDaveWidth.value(),
            ],
        ),
        "1/4" => (
            NumberId::NumbersSolveQuarterResidual.value(),
            NumberId::NumbersSolveQuarterRadius.value(),
            [
                NumberId::NumbersSolveQuarterAliceWidth.value(),
                NumberId::NumbersSolveQuarterBobWidth.value(),
                NumberId::NumbersSolveQuarterCarolWidth.value(),
                NumberId::NumbersSolveQuarterDaveWidth.value(),
            ],
        ),
        _ => unreachable!(),
    };
    assert_eq!(round.residual, residual);
    assert_eq!(round.radius, radius);
    let mut b = nrz_cas::limits::Budget::new(Limits::default()).unwrap();
    for ((actor, value), width) in round.standing.iter().zip(widths) {
        let h = &hull[actor];
        let lo = nrz_cas::Rational::parse(&value.lower, &mut b).unwrap();
        let hi = nrz_cas::Rational::parse(&value.upper, &mut b).unwrap();
        assert!(
            !lo.compare(&nrz_cas::Rational::parse(&h.lower, &mut b).unwrap(), &mut b)
                .unwrap()
                .is_lt()
        );
        assert!(
            !hi.compare(&nrz_cas::Rational::parse(&h.upper, &mut b).unwrap(), &mut b)
                .unwrap()
                .is_gt()
        );
        assert_eq!(hi.sub(&lo, &mut b).unwrap().exact_string(&mut b).unwrap(), width);
    }
}

fn check_wall_binding() {
    for wall in ["2", "1/8"] {
        let state = compile_final_state(
            &joined::package_at_wall(
                &joined::anchors(),
                1,
                &[("seller", "50"), ("buyer", "60"), ("third", "100")],
                wall,
            ),
            &joined::Verifier,
            &mut joined::numeric(),
            Limits::default(),
            10000,
        )
        .unwrap();
        for k in [3, 1, 4, 2] {
            let mut p = conserved_policy(&state, "1/16");
            p.enclosure.as_mut().unwrap().refinement.reduction_ceiling = k;
            let got = bind_procedure(&state, p.clone(), &Published(p), Limits::default());
            if k < 2 || (wall == "1/8" && k < 4) {
                assert!(matches!(got, Err(ProcedureError::WallRange)));
            } else {
                assert!(got.is_ok());
            }
        }
    }
}

fn check_prefix_pins() {
    let state = conserved_state();
    for (precision, expected) in [
        (2, NumberId::NumbersProposalPrefixWork.integer()),
        (4, NumberId::NumbersSolveCertifyingPrefixWork.integer()),
    ] {
        for cap in [expected, expected - 1] {
            let mut p = conserved_policy(&state, "1/16");
            p.precision = Precision::AbsoluteWidthBits(vec![precision]);
            p.enclosure.as_mut().unwrap().refinement.precision = precision;
            p.maximum_work = cap;
            p.enclosure.as_mut().unwrap().operation.work = cap;
            let result = pn_graph::numeric::activation::sharing::Session::new(&p, NumberId::NumbersReferenceSquaredBleed.value());
            assert_eq!(result.is_ok(), cap == expected);
            if let Ok(session) = result {
                assert_eq!(session.work(), expected);
            }
        }
    }
}

fn act_response_state(case: &str, after: bool) -> pn_epoch::compiler::CompiledState {
    use NumberId as N;
    let names: &[&str] = if case == "emission" { &["b", "u"] } else { &["i", "b"] };
    let mut acts: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, name)| joined::act("Registration", name, u64::try_from(i).unwrap() + 1, 1))
        .collect();
    if case == "emission" {
        burn_reference(&mut acts, "u", "b", 1);
        burn_reference(&mut acts, "b", "u", 1);
    }
    if after {
        if case == "emission" {
            acts.push(joined::act("Registration", "b", u64::try_from(acts.len()).unwrap() + 1, 1));
        } else {
            burn_reference(&mut acts, "b", "i", 1);
        }
    }
    acts.reverse();
    let source_burn = match case {
        "raise" => N::NumbersActResponseRaiseBurn,
        "lower" => N::NumbersActResponseLowerBurn,
        "emission" => N::NumbersActResponseEmissionBurn,
        "switch" => N::NumbersActResponseSwitchBurn,
        _ => unreachable!(),
    };
    let target_burn = if case == "raise" {
        N::NumbersActResponseRaisedTargetBurn
    } else {
        N::NumbersActResponseTargetBurn
    };
    let mut amounts = vec![("b", source_burn.value())];
    if case != "emission" {
        amounts.push(("i", target_burn.value()));
    }
    if case == "emission" {
        amounts.push(("u", N::NumbersActResponseUpstreamBurn.value()));
    }
    compile_final_state(
        &joined::package_at_wall(&acts, 1, &amounts, N::NumbersActResponseWall.value()),
        &joined::Verifier,
        &mut joined::numeric(),
        Limits::default(),
        N::NumbersActResponseProductCeiling.integer(),
    )
    .unwrap()
}

fn act_response_policy(state: &pn_epoch::compiler::CompiledState) -> Procedure {
    use NumberId as N;
    let mut p = fence_procedure(state);
    let bits = u32::try_from(N::NumbersActResponsePrecision.integer()).unwrap();
    p.precision = Precision::AbsoluteWidthBits(vec![bits]);
    p.grid = vec!["1".into(), "0".into()];
    p.endpoint_grid = N::NumbersActResponseEndpointGrid.value().into();
    p.maximum_iterations = N::NumbersActResponseProposalCap.integer();
    p.maximum_work = N::NumbersActResponseWorkCeiling.integer();
    p.maximum_solve_work = p.maximum_work;
    p.maximum_replay_work = p.maximum_work;
    let e = p.enclosure.as_mut().unwrap();
    e.operation.work = p.maximum_work;
    e.operation.arithmetic_steps = N::NumbersActResponseArithmeticCeiling.integer();
    e.store = e.operation.clone();
    e.refinement.precision = bits;
    p
}

fn act_response_premises(before: &pn_epoch::compiler::CompiledState, after: &pn_epoch::compiler::CompiledState, case: &str) {
    let old = before.package().input();
    let new = after.package().input();
    assert_eq!(
        u64::try_from(old.inputs[0].parameters().depth_mass.len()).unwrap(),
        NumberId::NumbersActResponseSupportedDepthCount.integer()
    );
    assert_eq!(old.markers, new.markers);
    assert_eq!(old.prices, new.prices);
    assert_eq!(old.inputs[0].parameters(), new.inputs[0].parameters());
    assert_eq!(new.history.acts().len(), old.history.acts().len() + 1);
    for act in old.history.acts() {
        assert!(new.history.acts().contains(act));
    }
    let added: Vec<_> = new
        .history
        .acts()
        .iter()
        .filter(|act| !old.history.acts().contains(act))
        .collect();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].id().author, "b");
    assert_eq!(
        u64::try_from(before.view().base.rows.len()).unwrap(),
        NumberId::NumbersActResponseActorCount.integer()
    );
    let (old_count, new_count) = if case == "emission" {
        (
            NumberId::NumbersActResponseEmissionActsBefore,
            NumberId::NumbersActResponseEmissionActsAfter,
        )
    } else {
        (
            NumberId::NumbersActResponseReferenceActsBefore,
            NumberId::NumbersActResponseReferenceActsAfter,
        )
    };
    assert_eq!(u64::try_from(old.history.acts().len()).unwrap(), old_count.integer());
    assert_eq!(u64::try_from(new.history.acts().len()).unwrap(), new_count.integer());
    let wall = Fraction::parse(NumberId::NumbersActResponseWall.value());
    for (address, count) in &before.view().ledger.counts {
        let next = after.view().ledger.counts[address].0;
        let balance = Fraction::parse(before.view().ledger.balances[address].exact());
        let next_balance = Fraction::parse(after.view().ledger.balances[address].exact());
        if address.0 == "b" {
            assert_eq!(next, count.0 + 1);
            assert_eq!(balance.minus(next_balance), wall);
        } else {
            assert_eq!(next, count.0);
            assert_eq!(balance, next_balance);
        }
    }
    assert_ne!(before.view().base, after.view().base);
    assert_eq!(
        before.view().base.rows.keys().collect::<Vec<_>>(),
        after.view().base.rows.keys().collect::<Vec<_>>()
    );
    if case == "emission" {
        assert_eq!(before.view().support.sources["b"].emission, "1");
        assert!(
            Fraction::parse(&after.view().support.sources["b"].emission)
                .order(Fraction(1, 1))
                .is_lt()
        );
        assert!(after.view().support.contributors["b"].contains("u"));
    } else {
        assert!(after.view().support.contributors["i"].contains("b"));
        for state in [before, after] {
            assert!(state.view().support.sources.values().all(|s| s.emission == "1"));
        }
    }
}

fn act_response_case(case: &str) -> String {
    let before = act_response_state(case, false);
    let after = act_response_state(case, true);
    act_response_premises(&before, &after, case);
    let p = act_response_policy(&before);
    let a = bind_procedure(&before, p.clone(), &Published(p.clone()), Limits::default()).unwrap();
    let b = bind_procedure(&after, p.clone(), &Published(p), Limits::default()).unwrap();
    let fa = pn_epoch::fence::search(&a, None).unwrap();
    let fb = pn_epoch::fence::search(&b, None).unwrap();
    burn_rungs(&fa, false);
    burn_rungs(&fb, case == "switch");
    let ra = pn_epoch::conserved::solve(&a, &fa).unwrap();
    let rb = pn_epoch::conserved::solve(&b, &fb).unwrap();
    let old = ra.rounds.last().unwrap();
    let new = rb.rounds.last().unwrap();
    let target = if case == "emission" { "b" } else { "i" };
    let mut budget = nrz_cas::limits::Budget::new(a.inputs().1.enclosure.as_ref().unwrap().operation.clone()).unwrap();
    let response = burn_sub(
        &burn_range(&new.standing[target], &mut budget),
        &burn_range(&old.standing[target], &mut budget),
        &mut budget,
    );
    if matches!(case, "raise" | "switch") {
        assert!(!response.lower().is_negative() && !response.lower().is_zero());
    } else {
        assert!(response.upper().is_negative());
    }
    let transported = burn_box_transport(&after, b.inputs().1, &new.certified, &old.standing, &mut budget);
    let names: Vec<_> = after.view().base.rows.keys().collect();
    let shock: Vec<_> = names
        .iter()
        .zip(&transported.standing)
        .map(|(name, image)| burn_sub(image, &burn_range(&old.standing[*name], &mut budget), &mut budget))
        .collect();
    let (q, _, displacement, losses) = burn_finite_bounds(b.inputs().1, &fb, &names, (old, new), &shock, &mut budget);
    let index = names.iter().position(|name| name.as_str() == target).unwrap();
    if case == "emission" {
        let source = names.iter().position(|name| name.as_str() == "b").unwrap();
        let recipient = names.iter().position(|name| name.as_str() == "u").unwrap();
        assert!(
            transported.emitted[source][&recipient]
                .upper()
                .compare(transported.raw[source][&recipient].lower(), &mut budget)
                .unwrap()
                .is_lt()
        );
    }
    let [old_lo, old_hi, new_lo, new_hi, delta_lo, delta_hi, bound, old_work, new_work] = act_response_pins(case);
    burn_pin_interval(&burn_range(&old.standing[target], &mut budget), old_lo, old_hi, &mut budget);
    burn_pin_interval(&burn_range(&new.standing[target], &mut budget), new_lo, new_hi, &mut budget);
    burn_pin_interval(&response, delta_lo, delta_hi, &mut budget);
    burn_pin_upper(&displacement, bound, &mut budget);
    if case == "emission" {
        burn_pin_upper(
            &losses[index],
            NumberId::NumbersActResponseEmissionTargetLossUpper,
            &mut budget,
        );
    } else if case == "lower" {
        burn_pin_upper(&losses[index], NumberId::NumbersActResponseLowerTargetLossUpper, &mut budget);
    } else {
        assert!(losses[index].is_zero());
    }
    assert_eq!((ra.work, rb.work), (old_work.integer(), new_work.integer()));
    let q = q.exact_string(&mut budget).unwrap();
    assert_eq!(
        q,
        if case == "switch" {
            "0"
        } else if case == "emission" {
            NumberId::NumbersActResponseEmissionContractionUpper.value()
        } else {
            NumberId::NumbersActResponseDirectionsContractionUpper.value()
        }
    );
    let wall = nrz_cas::Rational::parse(NumberId::NumbersActResponseWall.value(), &mut budget).unwrap();
    for round in [old, new] {
        for standing in round.standing.values() {
            assert!(
                burn_range(standing, &mut budget)
                    .lower()
                    .compare(&wall, &mut budget)
                    .unwrap()
                    .is_gt()
            );
        }
    }
    q
}

fn act_response_pins(case: &str) -> [NumberId; 9] {
    match case {
        "emission" => [
            NumberId::NumbersActResponseEmissionStandingBeforeLower,
            NumberId::NumbersActResponseEmissionStandingBeforeUpper,
            NumberId::NumbersActResponseEmissionStandingAfterLower,
            NumberId::NumbersActResponseEmissionStandingAfterUpper,
            NumberId::NumbersActResponseEmissionResponseLower,
            NumberId::NumbersActResponseEmissionResponseUpper,
            NumberId::NumbersActResponseEmissionDisplacementUpper,
            NumberId::NumbersActResponseEmissionSolveBeforeWork,
            NumberId::NumbersActResponseEmissionSolveAfterWork,
        ],
        "lower" => [
            NumberId::NumbersActResponseLowerStandingBeforeLower,
            NumberId::NumbersActResponseLowerStandingBeforeUpper,
            NumberId::NumbersActResponseLowerStandingAfterLower,
            NumberId::NumbersActResponseLowerStandingAfterUpper,
            NumberId::NumbersActResponseLowerResponseLower,
            NumberId::NumbersActResponseLowerResponseUpper,
            NumberId::NumbersActResponseLowerDisplacementUpper,
            NumberId::NumbersActResponseLowerSolveBeforeWork,
            NumberId::NumbersActResponseLowerSolveAfterWork,
        ],
        "raise" => [
            NumberId::NumbersActResponseRaiseStandingBeforeLower,
            NumberId::NumbersActResponseRaiseStandingBeforeUpper,
            NumberId::NumbersActResponseRaiseStandingAfterLower,
            NumberId::NumbersActResponseRaiseStandingAfterUpper,
            NumberId::NumbersActResponseRaiseResponseLower,
            NumberId::NumbersActResponseRaiseResponseUpper,
            NumberId::NumbersActResponseRaiseDisplacementUpper,
            NumberId::NumbersActResponseRaiseSolveBeforeWork,
            NumberId::NumbersActResponseRaiseSolveAfterWork,
        ],
        "switch" => [
            NumberId::NumbersActResponseSwitchStandingBeforeLower,
            NumberId::NumbersActResponseSwitchStandingBeforeUpper,
            NumberId::NumbersActResponseSwitchStandingAfterLower,
            NumberId::NumbersActResponseSwitchStandingAfterUpper,
            NumberId::NumbersActResponseSwitchResponseLower,
            NumberId::NumbersActResponseSwitchResponseUpper,
            NumberId::NumbersActResponseSwitchDisplacementUpper,
            NumberId::NumbersActResponseSwitchSolveBeforeWork,
            NumberId::NumbersActResponseSwitchSolveAfterWork,
        ],
        _ => unreachable!(),
    }
}

/// Claim: Matched unsorted complete histories with fixed burn and one added Reference give opposite certified reached-standing responses. The two comparisons have identical evaluated contraction bounds but different signs; counts, debits, base allocation, saturated emission and common passing full rungs are checked. Replayed box transport bounds each complete finite shock. No universal act direction follows from contraction.
/// ´claim:standing:accepted-acts-have-opposite-certified-responses´
/// ´test:integration:act-directions´
#[test]
fn act_directions() {
    assert_eq!(act_response_case("raise"), act_response_case("lower"));
}

/// Claim: An unsorted complete-history pair with fixed burn differs by one accepted Registration. Its count and debit change the source emission; both histories select the full passing rung and certified standing decreases. The complete new map at the old equilibrium enclosure supplies the finite response and loss bounds, without a fixed-emission forcing substitution.
/// ´claim:standing:accepted-act-emission-change-retains-finite-response´
/// ´test:integration:act-emission´
#[test]
fn act_emission() {
    act_response_case("emission");
}

/// Claim: An unsorted complete-history pair with fixed burn differs by one accepted Reference. The new base, debit and count change the contributing width and selected rung from full strength to the anchor after a full-rung failure. Certified reached standing increases, with the complete signed shock enclosing the finite response. No response sign is inferred from the rung switch alone.
/// ´claim:standing:accepted-act-rung-switch-retains-finite-response´
/// ´test:integration:act-switch´
#[test]
fn act_switch() {
    act_response_case("switch");
}
