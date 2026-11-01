use super::*;
use NumberId as N;
use pn_epoch::compiler::CompiledState;
use pn_records::{CandidateAct, burn::Address, conserved::SolveRecord};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purpose {
    SeparateRoles,
    ConcentrateStanding,
}

// A semantic annotation is deliberately not part of PackageInput or Procedure.
struct CompletionNote<'a> {
    purpose: Purpose,
    public: &'a [CandidateAct],
}

#[derive(Clone, Copy)]
struct Receiving {
    registrations: NumberId,
    retained: NumberId,
    donors: NumberId,
    old: NumberId,
    new: NumberId,
    incoming: NumberId,
    gain: NumberId,
}

fn receiving_fixture(showcase: bool) -> Receiving {
    if showcase {
        Receiving {
            registrations: N::NumbersReceivingShowcaseRegistrations,
            retained: N::NumbersReceivingShowcaseRetainedCount,
            donors: N::NumbersReceivingShowcaseDonors,
            old: N::NumbersReceivingShowcaseStandingOld,
            new: N::NumbersReceivingShowcaseStandingNew,
            incoming: N::NumbersReceivingShowcaseIncomingCount,
            gain: N::NumbersReceivingShowcaseGain,
        }
    } else {
        Receiving {
            registrations: N::NumbersReceivingSmallRegistrations,
            retained: N::NumbersReceivingSmallRetainedCount,
            donors: N::NumbersReceivingSmallDonors,
            old: N::NumbersReceivingSmallStandingOld,
            new: N::NumbersReceivingSmallStandingNew,
            incoming: N::NumbersReceivingSmallIncomingCount,
            gain: N::NumbersReceivingSmallGain,
        }
    }
}

fn append(acts: &mut Vec<CandidateAct>, family: &str, author: &str, target: &str) {
    let mut act = joined::act(family, author, u64::try_from(acts.len()).unwrap() + 1, 1);
    act.legs[0].target = joined::named("prof", target);
    acts.push(act);
}

fn receiving_acts(f: Receiving, refined: bool) -> Vec<CandidateAct> {
    let mut acts = Vec::new();
    for index in 0..f.registrations.integer() {
        let author = if refined && index >= f.retained.integer() {
            "moved"
        } else {
            "retained"
        };
        append(&mut acts, "Registration", author, author);
    }
    for index in 0..f.donors.integer() {
        let donor = format!("donor-{index}");
        append(&mut acts, "Registration", &donor, &donor);
        append(&mut acts, "Opinion", &donor, "retained");
    }
    acts.reverse();
    acts
}

fn limits() -> Limits {
    Limits {
        work: N::NumbersPartitionWorkCeiling.integer(),
        arithmetic_steps: N::NumbersPartitionArithmeticCeiling.integer(),
        output_bytes: N::NumbersPartitionOutputCeiling.integer(),
        proof_nodes: N::NumbersPartitionProofNodeCeiling.integer(),
        ..Limits::default()
    }
}

fn numeric() -> pn_records::numerics::NumericContext {
    pn_records::numerics::NumericContext::new(
        limits(),
        pn_records::numerics::ComparisonLimits::new(
            u32::try_from(N::NumbersPartitionProductCeiling.integer()).unwrap(),
            N::NumbersPartitionProductCeiling.integer(),
        ),
    )
    .unwrap()
}

fn compile(acts: &[CandidateAct], rates: &BTreeMap<String, Fraction>) -> CompiledState {
    let mut counts = BTreeMap::<String, u64>::new();
    for act in acts {
        *counts.entry(act.id.author.clone()).or_default() += 1;
    }
    let nu = Fraction::parse(N::NumbersPartitionNumeraire.value());
    // This is the tagged structural floor, not a fixture-selected wall.
    let wall = Fraction::parse("3/37");
    let burns: Vec<_> = counts
        .iter()
        .rev()
        .map(|(name, count)| {
            let amount = rates[name].plus(wall).times(nu).times(Fraction(i128::from(*count), 1));
            (name.as_str(), format!("{}/{}", amount.0, amount.1))
        })
        .collect();
    let borrowed: Vec<_> = burns.iter().map(|(name, amount)| (*name, amount.as_str())).collect();
    let original = joined::package_at_wall(acts, 1, &borrowed, "3/37");
    let (declaration, mut edition, mut parameters) = common::fixture();
    let mut n = numeric();
    let literal = n.literal(N::NumbersPartitionNumeraire.value()).unwrap();
    let unit = n.burn_per_action(&literal, "burn").unwrap();
    let numeraire = n.numeraire("nu", &unit).unwrap();
    edition.numeraire = numeraire.clone();
    parameters.numeraire = numeraire;
    for (name, id) in [
        ("partition-shape-first", N::NumbersPublishedShapeFirst),
        ("partition-shape-second", N::NumbersPublishedShapeSecond),
        ("partition-shape-third", N::NumbersPublishedShapeThird),
        ("partition-shape-fourth", N::NumbersPublishedShapeFourth),
        ("partition-mass-first", N::NumbersPublishedMassFirst),
        ("partition-mass-second", N::NumbersPublishedMassSecond),
        ("partition-mass-third", N::NumbersPublishedMassThird),
        ("partition-mass-fourth", N::NumbersPublishedMassFourth),
    ] {
        edition.constants.push(pn_records::constants::ConstantDefinition::Literal {
            name: name.into(),
            value: n.literal(id.value()).unwrap(),
        });
    }
    for value in parameters.domain_weights.values_mut() {
        *value = "one".into();
    }
    parameters.depth_mass = [
        "partition-mass-first",
        "partition-mass-second",
        "partition-mass-third",
        "partition-mass-fourth",
    ]
    .map(str::to_owned)
    .to_vec();
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let declaration = pn_records::validate_record(&[], &empty, &[declaration]).unwrap();
    let constants = pn_records::constants::bind_constants(&declaration, vec![edition]).unwrap();
    let input = pn_epoch::bind_inputs(&constants, parameters, limits()).unwrap();
    let literal = n.literal("3/37").unwrap();
    let wall = n.computed(&literal).unwrap();
    let price = n
        .charged_price(&wall, &input.parameters().numeraire, input.constants().content().floor)
        .unwrap();
    let mut package = original.input().clone();
    package.inputs[0] = input.clone();
    package.prices[0] = price.clone();
    package.bindings[0].inputs = input;
    package.bindings[0].price = price;
    let publication = FencePublication(package.bindings.clone());
    let verified = pn_epoch::package::verify_package(package, &publication).unwrap();
    compile_final_state(
        &verified,
        &joined::Verifier,
        &mut n,
        limits(),
        N::NumbersPartitionProductCeiling.integer(),
    )
    .unwrap()
}

fn policy(state: &CompiledState) -> Procedure {
    let mut p = fence_procedure(state);
    p.grid = vec![
        "1".into(),
        N::NumbersPartitionHalfRung.value().into(),
        N::NumbersPartitionQuarterRung.value().into(),
        "0".into(),
    ];
    p.precision = Precision::AbsoluteWidthBits(vec![u32::try_from(N::NumbersPartitionPrecision.integer()).unwrap()]);
    p.endpoint_grid = N::NumbersPartitionEndpointGrid.value().into();
    p.maximum_iterations = N::NumbersPartitionProposalCap.integer();
    p.maximum_work = N::NumbersPartitionWorkCeiling.integer();
    p.maximum_solve_work = p.maximum_work;
    p.maximum_replay_work = p.maximum_work;
    let e = p.enclosure.as_mut().unwrap();
    e.store = limits();
    e.operation = limits();
    e.refinement.precision = u32::try_from(N::NumbersPartitionPrecision.integer()).unwrap();
    e.refinement.reduction_ceiling = u32::try_from(N::NumbersPartitionReductionCeiling.integer()).unwrap();
    p.fence.as_mut().unwrap().shape = [
        "partition-shape-first",
        "partition-shape-second",
        "partition-shape-third",
        "partition-shape-fourth",
    ]
    .map(str::to_owned)
    .to_vec();
    p
}

fn solve(state: &CompiledState, anchor: bool) -> SolveRecord {
    let p = policy(state);
    let bound = bind_procedure(state, p.clone(), &Published(p.clone()), limits()).unwrap();
    let accepted = pn_epoch::fence::search(&bound, None).unwrap();
    let expected = if anchor {
        vec![Completion::Fail, Completion::Fail, Completion::Fail, Completion::Pass]
    } else {
        vec![Completion::Pass]
    };
    assert_eq!(
        accepted
            .evidence
            .attempts
            .iter()
            .map(|a| a.completion.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(accepted.selected.as_deref(), Some(if anchor { "0" } else { "1" }));
    assert_eq!(accepted.operational_stop, None);
    validate_evidence(&p, &accepted.evidence, limits()).unwrap();
    let record = pn_epoch::conserved::solve(&bound, &accepted).unwrap();
    pn_epoch::conserved::replay(&bound, &record).unwrap();
    record
}

fn receiving_rates(acts: &[CandidateAct]) -> BTreeMap<String, Fraction> {
    acts.iter()
        .map(|act| {
            (
                act.id.author.clone(),
                Fraction::parse(if act.id.author.starts_with("donor-") {
                    N::NumbersPartitionHighRate.value()
                } else {
                    N::NumbersPartitionLowRate.value()
                }),
            )
        })
        .collect()
}

fn identical_public(a: &CompiledState, b: &CompiledState) {
    let x = a.package().input();
    let y = b.package().input();
    assert_eq!(x.history.acts(), y.history.acts());
    assert_eq!(x.markers, y.markers);
    assert_eq!(x.inputs, y.inputs);
    assert_eq!(x.prices, y.prices);
    assert_eq!(x.bindings, y.bindings);
    assert_eq!(a.view(), b.view());
}

fn annotation_run(acts: &[CandidateAct]) -> (CompiledState, SolveRecord) {
    let legitimate = CompletionNote {
        purpose: Purpose::SeparateRoles,
        public: acts,
    };
    let strategic = CompletionNote {
        purpose: Purpose::ConcentrateStanding,
        public: acts,
    };
    assert_ne!(legitimate.purpose, strategic.purpose);
    let a = compile(legitimate.public, &receiving_rates(legitimate.public));
    let b = compile(strategic.public, &receiving_rates(strategic.public));
    identical_public(&a, &b);
    let old = solve(&a, true);
    let new = solve(&b, true);
    assert_eq!(old, new);
    // Independent replay under the other completion has exactly the same result.
    let p = policy(&b);
    let bound = bind_procedure(&b, p.clone(), &Published(p), limits()).unwrap();
    pn_epoch::conserved::replay(&bound, &old).unwrap();
    (a, old)
}

fn receiving_premises(f: Receiving, old: &CompiledState, new: &CompiledState) {
    let n = f.retained.integer();
    let total = f.registrations.integer();
    assert!(n > 0 && n < total);
    assert!(f.donors.integer() > 0);
    assert!(
        Fraction::parse(N::NumbersPartitionLowRate.value())
            .order(Fraction::parse(N::NumbersPartitionHighRate.value()))
            .is_le()
    );
    let a = old.package().input();
    let b = new.package().input();
    assert_eq!(a.inputs, b.inputs);
    assert_eq!(a.prices, b.prices);
    assert_eq!(a.history.acts().len(), b.history.acts().len());
    let by_sequence: BTreeMap<_, _> = b.history.acts().iter().map(|act| (act.id().sequence, act)).collect();
    assert_eq!(by_sequence.len(), b.history.acts().len());
    for original in a.history.acts() {
        let counterpart = by_sequence[&original.id().sequence];
        assert_eq!(original.body(), counterpart.body());
        if original.id().author.starts_with("donor-") {
            assert_eq!(original, counterpart);
        } else {
            assert_eq!(original.id().family, "Registration");
        }
    }
    for state in [old, new] {
        assert_eq!(state.view().title.certificate.len(), 0);
        assert_eq!(state.view().title.events.len(), 0);
        for act in state.package().input().history.acts() {
            // No aggregate-scope claim, identity attestation or title-bearing act.
            assert_eq!(act.protocol_references(), []);
            assert_eq!(act.body().asserted_parents, []);
            assert!(act.body().license.is_none() && act.body().settlement.is_none());
            if act.id().family == "Opinion" {
                assert_eq!(act.legs()[0].target(), &joined::named("prof", "retained"));
                assert!(act.body().quantities.iter().all(|(_, q)| q.value == 1));
            } else {
                assert_eq!(act.id().family, "Registration");
            }
        }
        for (name, source) in &state.view().support.sources {
            assert_eq!(source.emission, "1");
            if name.starts_with("donor-") {
                assert_eq!(source.reduced_rate, N::NumbersPartitionHighRate.value());
                assert_eq!(state.view().ledger.counts[&Address(name.clone())].0, 2);
            } else {
                assert_eq!(source.reduced_rate, N::NumbersPartitionLowRate.value());
                assert_eq!(state.view().base.rows[name].keys().collect::<Vec<_>>(), vec![name]);
            }
        }
    }
    let count = |s: &CompiledState, name: &str| s.view().ledger.counts[&Address(name.into())].0;
    assert_eq!(count(old, "retained"), total);
    assert_eq!(count(new, "retained"), n);
    assert_eq!(count(new, "moved"), total - n);
    let balance = |s: &CompiledState, name: &str| Fraction::parse(s.view().ledger.balances[&Address(name.into())].exact());
    assert_eq!(balance(old, "retained"), balance(new, "retained").plus(balance(new, "moved")));
}

fn admitted(state: &CompiledState, record: &SolveRecord) {
    let result = record.rounds.last().unwrap();
    let acts = state.package().input().history.acts();
    assert!(u64::try_from(acts.len()).unwrap() <= N::NumbersPartitionActCapacity.integer());
    let mut sum = Fraction(0, 1);
    for act in acts {
        let lower = Fraction::parse(&result.standing[&act.id().author].lower);
        assert!(lower.order(Fraction::parse("3/37")).is_ge());
        sum = sum.plus(lower);
    }
    assert!(
        sum.over(Fraction(i128::try_from(acts.len()).unwrap(), 1))
            .order(Fraction::parse(N::NumbersPartitionPolicyFloor.value()))
            .is_ge()
    );
    // Compilation already debited each act from its author's recognized burn.
    assert!(
        state
            .view()
            .ledger
            .balances
            .values()
            .all(|v| Fraction::parse(v.exact()).0 >= 0)
    );
}

fn receiving_result(f: Receiving, old: &SolveRecord, new: &SolveRecord) {
    let a = old.rounds.last().unwrap();
    let b = new.rounds.last().unwrap();
    assert_eq!(
        a.standing["retained"],
        Bounds {
            lower: f.old.value().into(),
            upper: f.old.value().into()
        }
    );
    assert_eq!(
        b.standing["retained"],
        Bounds {
            lower: f.new.value().into(),
            upper: f.new.value().into()
        }
    );
    assert_eq!(b.standing["moved"].lower, N::NumbersPartitionLowRate.value());
    let low_rate = Fraction::parse(N::NumbersPartitionLowRate.value());
    let high_rate = Fraction::parse(N::NumbersPartitionHighRate.value());
    let total = Fraction::parse(f.registrations.value());
    let retained_count = Fraction::parse(f.retained.value());
    let incoming = Fraction::parse(f.incoming.value());
    let gain = Fraction::parse(f.new.value()).minus(Fraction::parse(f.old.value()));
    assert_eq!(gain, Fraction::parse(f.gain.value()));
    assert_eq!(
        gain,
        high_rate
            .minus(low_rate)
            .times(incoming)
            .times(total.minus(retained_count))
            .over(retained_count.plus(incoming).times(total.plus(incoming)))
    );
    assert!(gain.0 > 0 && gain.order(high_rate.minus(low_rate)).is_lt());
    // Squaring this nonnegative rational proves the continuous square-root bound.
    let root_ceiling = total
        .plus(retained_count)
        .minus(gain.over(high_rate.minus(low_rate)).times(total.minus(retained_count)))
        .over(Fraction(2, 1));
    assert!(root_ceiling.0 >= 0);
    assert!(root_ceiling.times(root_ceiling).order(retained_count.times(total)).is_ge());
    for record in [a, b] {
        assert_eq!(record.contraction, "0");
        assert_eq!(record.radius, record.residual);
    }
}

fn receiving_pairs(f: Receiving, state: &CompiledState, record: &SolveRecord, refined: bool) {
    let map = &record.rounds.last().unwrap().certified;
    let names: Vec<_> = map.point.keys().collect();
    let retained = names.iter().position(|name| *name == "retained").unwrap();
    let own_count = if refined { f.retained } else { f.registrations };
    let incoming = split_exact(&map.transport.denominator[retained]).minus(Fraction::parse(own_count.value()));
    assert_eq!(incoming, Fraction::parse(f.incoming.value()));
    let mut donor_sum = Fraction(0, 1);
    for (i, name) in names.iter().enumerate() {
        let count = Fraction(i128::from(state.view().ledger.counts[&Address((*name).clone())].0), 1);
        let exported = map.transport.emitted[i]
            .iter()
            .filter(|(j, _)| names[**j].starts_with("donor-") != name.starts_with("donor-"))
            .map(|(_, probability)| split_exact(probability))
            .fold(Fraction(0, 1), Fraction::plus)
            .times(count);
        let balance = Fraction::parse(state.view().ledger.balances[&Address((*name).clone())].exact());
        let price = Fraction::parse("3/37").times(Fraction::parse(N::NumbersPartitionNumeraire.value()));
        let capacity = if count.order(balance.over(price)).is_lt() {
            count
        } else {
            balance.over(price)
        };
        assert!(exported.0 >= 0 && exported.order(capacity).is_le());
        assert_eq!(capacity, count);
        if name.starts_with("donor-") {
            donor_sum = donor_sum.plus(exported);
        } else {
            assert_eq!(exported, Fraction(0, 1));
        }
    }
    assert_eq!(donor_sum, incoming);
}

// A sufficient fixture-local review, not a general private-intent recognizer.
fn role_completion_allowed(acts: &[CandidateAct], roles_independent: bool, donors_can_intend_role: bool) -> bool {
    roles_independent
        && donors_can_intend_role
        && acts.iter().all(|act| {
            act.protocol_references.is_empty()
                && act.body.license.is_none()
                && act.body.settlement.is_none()
                && act.body.asserted_parents.is_empty()
                && match act.id.family.as_str() {
                    "Registration" => act.body.quantities.is_empty(),
                    "Opinion" => {
                        act.id.author.starts_with("donor-")
                            && act.legs[0].target == joined::named("prof", "retained")
                            && act.body.quantities.iter().all(|(_, q)| q.value == 1)
                    }
                    _ => false,
                }
        })
}

fn completion_probes() {
    let acts = receiving_acts(receiving_fixture(false), true);
    assert!(role_completion_allowed(&acts, true, true));
    assert!(!role_completion_allowed(&acts, false, true));
    assert!(!role_completion_allowed(&acts, true, false));
    let mut contradictory = acts.clone();
    contradictory[0]
        .protocol_references
        .push(joined::named("scope", "aggregate-role-attestation"));
    assert!(!role_completion_allowed(&contradictory, true, true));
    let mut outside_family = acts;
    outside_family[0].legs[0].target = joined::named("prof", "moved");
    assert!(!role_completion_allowed(&outside_family, true, true));
    // The countermodels with identical public observations have distinct purposes.
    // Hence a unique actual-purpose inference is not supported by these inputs.
    assert_eq!(
        BTreeSet::from([
            format!("{:?}", Purpose::SeparateRoles),
            format!("{:?}", Purpose::ConcentrateStanding)
        ])
        .len(),
        2
    );
}

fn receiving(showcase: bool) {
    let f = receiving_fixture(showcase);
    let pooled = receiving_acts(f, false);
    let partitioned = receiving_acts(f, true);
    assert!(role_completion_allowed(&pooled, true, true));
    assert!(role_completion_allowed(&partitioned, true, true));
    assert_ne!(pooled, partitioned);
    let (a, old) = annotation_run(&pooled);
    let (b, new) = annotation_run(&partitioned);
    receiving_premises(f, &a, &b);
    admitted(&a, &old);
    admitted(&b, &new);
    receiving_pairs(f, &a, &old, false);
    receiving_pairs(f, &b, &new, true);
    receiving_result(f, &old, &new);
    assert_ne!(old.rounds.last().unwrap().standing, new.rounds.last().unwrap().standing);
}

/// Claim: The tagged small receiving comparison is compiled, certified and replayed with unchanged donor acts and proportional participant pairs. Legitimate-role and strategic-purpose annotations of each identical public record give identical compiled views and solve records. The different pooled and partitioned records strictly increase retained standing under the checked receiving premises; annotation equality supplies no equality of those records or inference of actual intent.
/// ´claim:standing:small-receiving-annotations-preserve-public-evidence´
/// ´test:integration:receiving-small´
#[test]
fn receiving_small() {
    receiving(false);
    completion_probes();
}

/// Claim: The tagged showcase receiving comparison retains its full Registration and donor multiplicities. Both annotation readings independently compile, certify and replay identically for each public record; the pooled and partitioned records differ and the retained gain satisfies the receiving concentration formula under absorbing participant rows and fixed incoming acts. This finite reproduction establishes no intent classifier or unrestricted strategic-history completion.
/// ´claim:standing:showcase-receiving-retains-scoped-concentration´
/// ´test:integration:receiving-showcase´
#[test]
fn receiving_showcase() {
    receiving(true);
}
