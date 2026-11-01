use super::*;
use NumberId as N;
use nrz_cas::{Rational, limits::Budget};
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
        literal_bytes: N::NumbersPartitionLiteralByteCeiling.integer(),
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
    let ratio = Fraction::parse(N::NumbersPartitionBackoffRatio.value());
    let squared = ratio.times(ratio);
    p.grid = vec![
        "1".into(),
        N::NumbersPartitionBackoffRatio.value().into(),
        format!("{}/{}", squared.0, squared.1),
        "0".into(),
    ];
    p.precision = Precision::AbsoluteWidthBits(vec![u32::try_from(N::NumbersPartitionPrecision.integer()).unwrap()]);
    p.endpoint_grid = N::NumbersPartitionEndpointGrid.value().into();
    p.maximum_iterations = if state
        .view()
        .support
        .sources
        .values()
        .any(|source| source.reduced_rate == N::NumbersPartitionHighRate.value())
    {
        N::NumbersPartitionProposalCap.integer()
    } else {
        N::NumbersPartitionPositiveProposalCap.integer()
    };
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
    let mut budget = Budget::new(limits()).unwrap();
    let mut sum = Rational::parse("0", &mut budget).unwrap();
    let wall = Rational::parse("3/37", &mut budget).unwrap();
    for act in acts {
        let lower = Rational::parse(&result.standing[&act.id().author].lower, &mut budget).unwrap();
        assert!(lower.compare(&wall, &mut budget).unwrap().is_ge());
        sum = sum.add(&lower, &mut budget).unwrap();
    }
    let count = Rational::parse(&acts.len().to_string(), &mut budget).unwrap();
    let policy = Rational::parse(N::NumbersPartitionPolicyFloor.value(), &mut budget).unwrap();
    assert!(
        sum.div(&count, &mut budget)
            .unwrap()
            .compare(&policy, &mut budget)
            .unwrap()
            .is_ge()
    );
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

#[derive(Clone, Copy, Debug)]
enum ExportCase {
    Distinct,
    Lower,
    Raise,
    Matched,
}

fn exporting_acts(case: ExportCase, refined: bool) -> Vec<CandidateAct> {
    let mut acts = Vec::new();
    for index in 0..N::NumbersPartitionExportRegistrations.integer() {
        let author = if refined && index != 0 { "moved" } else { "retained" };
        append(&mut acts, "Registration", author, author);
    }
    for index in 0..N::NumbersPartitionExportOpinions.integer() {
        let author = if refined && index != 0 { "moved" } else { "retained" };
        let target = if matches!(case, ExportCase::Distinct) && index != 0 {
            "target-other"
        } else {
            "target"
        };
        append(&mut acts, "Opinion", author, target);
        if matches!(case, ExportCase::Matched) {
            let coordinate = Fraction::parse(N::NumbersPartitionMatchedCoordinate.value());
            for (name, quantity) in &mut acts.last_mut().unwrap().body.quantities {
                quantity.value = i64::try_from(if name.ends_with("numerator") {
                    coordinate.0
                } else {
                    coordinate.1
                })
                .unwrap();
            }
        }
    }
    // Each external recipient is anchored by its own Registration.
    append(&mut acts, "Registration", "target", "target");
    if matches!(case, ExportCase::Distinct) {
        append(&mut acts, "Registration", "target-other", "target-other");
    }
    acts.reverse();
    acts
}

fn exporting_rates(acts: &[CandidateAct], case: ExportCase) -> BTreeMap<String, Fraction> {
    acts.iter()
        .map(|act| {
            let target = act.id.author.starts_with("target");
            let id = match (case, target) {
                (ExportCase::Distinct, true) => N::NumbersPartitionHighRate,
                (ExportCase::Raise, false) | (ExportCase::Lower | ExportCase::Matched, true) => N::NumbersPartitionCloseRate,
                _ => N::NumbersPartitionLowRate,
            };
            (act.id.author.clone(), Fraction::parse(id.value()))
        })
        .collect()
}

fn exporting_premises(old: &CompiledState, new: &CompiledState) {
    assert_eq!(old.package().input().inputs, new.package().input().inputs);
    assert_eq!(old.package().input().prices, new.package().input().prices);
    let before = old.package().input().history.acts();
    let after = new.package().input().history.acts();
    assert_eq!(before.len(), after.len());
    let by_sequence: BTreeMap<_, _> = after.iter().map(|act| (act.id().sequence, act)).collect();
    assert_eq!(by_sequence.len(), after.len());
    for act in before {
        let next = by_sequence[&act.id().sequence];
        assert_eq!(act.body(), next.body());
        if act.id().author.starts_with("target") {
            assert_eq!(act, next);
        } else {
            assert!(next.id().author == "retained" || next.id().author == "moved");
            assert_eq!(act.id().family, next.id().family);
            assert_eq!(act.legs()[0].source(), &joined::named("addr", &act.id().author));
            assert_eq!(next.legs()[0].source(), &joined::named("addr", &next.id().author));
            if act.id().family == "Opinion" {
                assert_eq!(act.legs()[0].target(), next.legs()[0].target());
            } else {
                assert_eq!(next.legs()[0].target(), &joined::named("prof", &next.id().author));
            }
        }
    }
    let count = |state: &CompiledState, name: &str| state.view().ledger.counts[&Address(name.into())].0;
    assert_eq!(count(old, "retained"), count(new, "retained") + count(new, "moved"));
    let balance =
        |state: &CompiledState, name: &str| Fraction::parse(state.view().ledger.balances[&Address(name.into())].exact());
    assert_eq!(balance(old, "retained"), balance(new, "retained").plus(balance(new, "moved")));
    for (name, source) in &new.view().support.sources {
        let original = if name == "moved" { "retained" } else { name };
        assert_eq!(source.reduced_rate, old.view().support.sources[original].reduced_rate);
        assert_eq!(source.emission, "1");
        if name.starts_with("target") {
            assert_eq!(count(old, name), count(new, name));
            assert_eq!(balance(old, name), balance(new, name));
            assert_eq!(old.view().base.rows[name].keys().collect::<Vec<_>>(), vec![name]);
            assert_eq!(new.view().base.rows[name].keys().collect::<Vec<_>>(), vec![name]);
        }
    }
    for state in [old, new] {
        assert_eq!(state.view().title.events.len(), 0);
        assert!(state.view().support.sources.values().all(|s| s.emission == "1"));
    }
}

fn exported(state: &CompiledState, map: &pn_records::conserved::MapRecord) -> Fraction {
    let names: Vec<_> = map.point.keys().collect();
    names
        .iter()
        .enumerate()
        .filter(|(_, name)| !name.starts_with("target"))
        .map(|(i, name)| {
            let count = Fraction(i128::from(state.view().ledger.counts[&Address((*name).clone())].0), 1);
            map.transport.emitted[i]
                .iter()
                .filter(|(j, _)| names[**j].starts_with("target"))
                .map(|(_, v)| split_exact(v))
                .fold(Fraction(0, 1), Fraction::plus)
                .times(count)
        })
        .fold(Fraction(0, 1), Fraction::plus)
}

fn distinct_bound(old_state: &CompiledState, new_state: &CompiledState, old: &SolveRecord, new: &SolveRecord) {
    let before = &old.rounds.last().unwrap().certified;
    let after = &new.rounds.last().unwrap().certified;
    let old_names: Vec<_> = before.point.keys().collect();
    let new_names: Vec<_> = after.point.keys().collect();
    let old_target = old_names.iter().position(|name| *name == "target").unwrap();
    let new_target = new_names.iter().position(|name| *name == "target").unwrap();
    let old_count = split_exact(&before.transport.denominator[old_target]);
    let new_count = split_exact(&after.transport.denominator[new_target]);
    let old_amount = split_exact(&before.transport.numerator[old_target]);
    let new_amount = split_exact(&after.transport.numerator[new_target]);
    let old_value = old_amount.over(old_count);
    let new_value = new_amount.over(new_count);
    assert_eq!(old_value, Fraction::parse(N::NumbersPartitionDistinctStandingOld.value()));
    assert_eq!(new_value, Fraction::parse(N::NumbersPartitionDistinctStandingNew.value()));
    let response = new_value.minus(old_value);
    assert_eq!(response, Fraction::parse(N::NumbersPartitionDistinctGain.value()));
    assert_eq!(
        response,
        new_amount
            .minus(old_amount)
            .minus(old_value.times(new_count.minus(old_count)))
            .over(new_count)
    );
    let zero = Fraction(0, 1);
    let weights: Vec<_> = new_names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let original = if *name == "moved" { "retained" } else { name };
            let old_index = old_names.iter().position(|n| *n == original).unwrap();
            let count = Fraction(i128::from(new_state.view().ledger.counts[&Address((*name).clone())].0), 1);
            (
                count.times(before.transport.emitted[old_index].get(&old_target).map_or(zero, split_exact)),
                count.times(after.transport.emitted[i].get(&new_target).map_or(zero, split_exact)),
            )
        })
        .collect();
    assert_eq!(weights.iter().map(|(a, _)| *a).fold(zero, Fraction::plus), old_count);
    assert_eq!(weights.iter().map(|(_, b)| *b).fold(zero, Fraction::plus), new_count);
    let variation = weights
        .iter()
        .map(|(a, b)| {
            let delta = b.over(new_count).minus(a.over(old_count));
            Fraction::new(delta.0.abs(), delta.1)
        })
        .fold(zero, Fraction::plus)
        .over(Fraction(2, 1));
    assert!(variation.order(Fraction(1, 1)).is_le());
    let width = Fraction::parse(N::NumbersPartitionHighRate.value()).minus(Fraction::parse(N::NumbersPartitionLowRate.value()));
    let ungrouped_bound = width.times(variation);
    assert!(response.order(ungrouped_bound).is_le());
    assert_eq!(
        ungrouped_bound,
        Fraction::parse(N::NumbersPartitionDistinctUngroupedBound.value())
    );
    let grouped = new_names
        .iter()
        .zip(&weights)
        .filter(|(name, _)| !name.starts_with("target"))
        .map(|(_, pair)| *pair)
        .fold((zero, zero), |(a, b), (c, d)| (a.plus(c), b.plus(d)));
    let grouped_delta = grouped.1.over(new_count).minus(grouped.0.over(old_count));
    let grouped_variation = Fraction::new(grouped_delta.0.abs(), grouped_delta.1);
    assert_eq!(response, width.times(grouped_variation));
    let old_export = exported(old_state, before);
    let new_export = exported(new_state, after);
    assert_eq!(old_export, Fraction::parse(N::NumbersPartitionDistinctExportOld.value()));
    assert_eq!(new_export, Fraction::parse(N::NumbersPartitionDistinctExportNew.value()));
    let capacity = Fraction(i128::from(old_state.view().ledger.counts[&Address("retained".into())].0), 1);
    assert!(new_export.order(old_export).is_lt());
    assert!(old_export.order(capacity).is_le() && new_export.0 >= 0);
    assert!(old_export.minus(new_export).order(capacity).is_le());
}

fn exporting(case: ExportCase) -> (CompiledState, CompiledState, SolveRecord, SolveRecord) {
    let before = exporting_acts(case, false);
    let after = exporting_acts(case, true);
    let old_state = compile(&before, &exporting_rates(&before, case));
    let new_state = compile(&after, &exporting_rates(&after, case));
    exporting_premises(&old_state, &new_state);
    let old = solve(&old_state, matches!(case, ExportCase::Distinct));
    let new = solve(&new_state, matches!(case, ExportCase::Distinct));
    admitted(&old_state, &old);
    admitted(&new_state, &new);
    (old_state, new_state, old, new)
}

/// Claim: A complete proportional split with unchanged distinct external recipients passes the anchor after all positive declared rungs fail. Replayed exact transport reproduces the published target gain, satisfies the pair displacement identity, satisfies the common-source total-variation bound and attains its equal-rate grouped refinement and decreases export within the unchanged fibre capacity. A changed count or split alone does not supply coordinate equality.
/// ´claim:standing:distinct-target-split-retains-pair-displacement´
/// ´test:integration:distinct-target-split´
#[test]
fn distinct_target_split() {
    let (before, after, old, new) = exporting(ExportCase::Distinct);
    distinct_bound(&before, &after, &old, &new);
}

fn partition_box_transport(
    state: &pn_epoch::compiler::CompiledState,
    policy: &Procedure,
    template: &pn_records::conserved::MapRecord,
    coordinates: &BTreeMap<String, Bounds>,
    budget: &mut nrz_cas::limits::Budget,
) -> pn_records::transport::TransportOutput<nrz_cas::enclosure::Interval> {
    use nrz_cas::{Rational, enclosure::Interval};
    use pn_graph::numeric::activation::{self, Quantity, Request};
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
                    .coarsen(u32::try_from(N::NumbersPartitionPrecision.integer()).unwrap(), budget)
                    .unwrap();
                let request = Request {
                    standing: Range {
                        lower: coordinate.lower().exact_string(budget).unwrap(),
                        upper: coordinate.upper().exact_string(budget).unwrap(),
                    },
                    bleed_squared: NumberId::NumbersReferenceSquaredBleed.value().into(),
                    wall: Some("3/37".into()),
                    wall_enclosure: None,
                    quantity: Quantity::Hop {
                        strength: template.rung.clone(),
                        shape: shape.value().into(),
                    },
                };
                let result = activation::evaluate(policy, &request, None).unwrap();
                let evidence = &result.primitive.evidence;
                let replay = activation::replay(policy, &request, evidence.attachment.as_ref().unwrap(), None).unwrap();
                assert_eq!(evidence.bounds, replay.primitive.evidence.bounds);
                evidence
                    .bounds
                    .as_ref()
                    .unwrap()
                    .coarsen(u32::try_from(N::NumbersPartitionPrecision.integer()).unwrap(), budget)
                    .unwrap()
            })
            .collect();
        for (i, row) in hop.iter_mut().enumerate() {
            for (j, entry) in row {
                let pn_epoch::base::BaseScore::Exact(score) = &state.view().base.rows[names[i]][names[*j]].score else {
                    panic!("rational partition base");
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
        usize::try_from(N::NumbersPartitionProofNodeCeiling.integer()).unwrap(),
    )
    .unwrap()
}

fn partition_difference(
    a: &nrz_cas::enclosure::Interval,
    b: &nrz_cas::enclosure::Interval,
    budget: &mut Budget,
) -> nrz_cas::enclosure::Interval {
    use nrz_cas::enclosure::Interval;
    let bits = u32::try_from(N::NumbersPartitionPrecision.integer()).unwrap();
    let a = a.coarsen(bits, budget).unwrap();
    let b = b.coarsen(bits, budget).unwrap();
    Interval::new(
        a.lower().sub(b.upper(), budget).unwrap(),
        a.upper().sub(b.lower(), budget).unwrap(),
        budget,
    )
    .unwrap()
}

fn partition_projected_bound(
    after: &CompiledState,
    old: &pn_records::conserved::ResidualRound,
    new: &pn_records::conserved::ResidualRound,
    budget: &mut Budget,
) -> Rational {
    let one = Rational::parse("1", budget).unwrap();
    let new_names: Vec<_> = new.standing.keys().collect();
    // The lifted coarse equilibrium box is already in every refined hull.
    let lifted: BTreeMap<_, _> = new
        .standing
        .keys()
        .map(|name| {
            let original = if name == "moved" { "retained" } else { name };
            (name.clone(), old.standing[original].clone())
        })
        .collect();
    for (name, range) in &lifted {
        let hull = &after.view().support.ranges[name];
        let range = burn_range(range, budget);
        assert!(
            range
                .lower()
                .compare(&Rational::parse(&hull.minimum, budget).unwrap(), budget)
                .unwrap()
                .is_ge()
        );
        assert!(
            range
                .upper()
                .compare(&Rational::parse(&hull.maximum, budget).unwrap(), budget)
                .unwrap()
                .is_le()
        );
    }
    let trial = partition_box_transport(after, &policy(after), &new.certified, &lifted, budget);
    let shocks: Vec<_> = new_names
        .iter()
        .zip(&trial.standing)
        .map(|(name, image)| partition_difference(image, &burn_range(&lifted[*name], budget), budget))
        .collect();
    let norm = burn_maximum(&shocks, budget);
    let contraction = Rational::parse(&new.contraction, budget).unwrap();
    let residual_bound = norm.div(&one.sub(&contraction, budget).unwrap(), budget).unwrap();
    for name in new_names {
        let displacement = partition_difference(
            &burn_range(&new.standing[name], budget),
            &burn_range(&lifted[name], budget),
            budget,
        );
        assert!(
            burn_magnitude(&displacement, budget)
                .compare(&residual_bound, budget)
                .unwrap()
                .is_le()
        );
    }
    residual_bound
}

fn positive_displacement(before: &CompiledState, after: &CompiledState, old: &SolveRecord, new: &SolveRecord, raise: bool) {
    use nrz_cas::{Rational, enclosure::Interval};
    let mut budget = Budget::new(limits()).unwrap();
    let old = old.rounds.last().unwrap();
    let new = new.rounds.last().unwrap();
    let old_transport = partition_box_transport(before, &policy(before), &old.certified, &old.standing, &mut budget);
    let new_transport = partition_box_transport(after, &policy(after), &new.certified, &new.standing, &mut budget);
    let old_names: Vec<_> = old.standing.keys().collect();
    let new_names: Vec<_> = new.standing.keys().collect();
    let old_target = old_names.iter().position(|name| *name == "target").unwrap();
    let new_target = new_names.iter().position(|name| *name == "target").unwrap();
    let delta = partition_difference(
        &burn_range(&new.standing["target"], &mut budget),
        &burn_range(&old.standing["target"], &mut budget),
        &mut budget,
    );
    if raise {
        assert!(!delta.lower().is_negative() && !delta.lower().is_zero());
    } else {
        assert!(delta.upper().is_negative());
    }
    let zero = Rational::parse("0", &mut budget).unwrap();
    let mut variation = zero.clone();
    let mut old_weights = Interval::singleton(&zero, &mut budget).unwrap();
    let mut new_weights = old_weights.clone();
    for (i, name) in new_names.iter().enumerate() {
        let original = if *name == "moved" { "retained" } else { name };
        let old_index = old_names.iter().position(|n| *n == original).unwrap();
        let count = Rational::parse(
            &after.view().ledger.counts[&Address((*name).clone())].0.to_string(),
            &mut budget,
        )
        .unwrap();
        let count = Interval::singleton(&count, &mut budget).unwrap();
        let empty = Interval::singleton(&zero, &mut budget).unwrap();
        let weight = partition_product(
            old_transport.emitted[old_index].get(&old_target).unwrap_or(&empty),
            &count,
            &mut budget,
        );
        let next = partition_product(
            new_transport.emitted[i].get(&new_target).unwrap_or(&empty),
            &count,
            &mut budget,
        );
        old_weights = partition_sum(&old_weights, &weight, &mut budget);
        new_weights = partition_sum(&new_weights, &next, &mut budget);
        let normalized = partition_quotient(&weight, &old_transport.denominator[old_target], &mut budget);
        let normalized_next = partition_quotient(&next, &new_transport.denominator[new_target], &mut budget);
        let difference = partition_difference(&normalized_next, &normalized, &mut budget);
        variation = variation.add(&burn_magnitude(&difference, &mut budget), &mut budget).unwrap();
    }
    assert_eq!(old_weights, old_transport.denominator[old_target]);
    assert_eq!(new_weights, new_transport.denominator[new_target]);
    let two = Rational::parse("2", &mut budget).unwrap();
    let width = Rational::parse(N::NumbersPartitionCloseRate.value(), &mut budget)
        .unwrap()
        .sub(
            &Rational::parse(N::NumbersPartitionLowRate.value(), &mut budget).unwrap(),
            &mut budget,
        )
        .unwrap();
    let variation = variation.div(&two, &mut budget).unwrap();
    let one = Rational::parse("1", &mut budget).unwrap();
    assert!(variation.compare(&one, &mut budget).unwrap().is_lt());
    let bound = variation.mul(&width, &mut budget).unwrap();
    // Both enclose the true response; the difference of outer boxes may be wider.
    let pair_box = Interval::new(bound.negated(&mut budget).unwrap(), bound.clone(), &mut budget).unwrap();
    let scoped_delta = delta.intersection(&pair_box, &mut budget).unwrap();
    let residual_bound = partition_projected_bound(after, old, new, &mut budget);
    let pins = if raise {
        [
            N::NumbersPartitionPositiveRaiseResponseLower,
            N::NumbersPartitionPositiveRaiseResponseUpper,
            N::NumbersPartitionPositiveRaisePairUpper,
            N::NumbersPartitionPositiveRaiseProjectedUpper,
            N::NumbersPartitionPositiveRaiseOldRoundWork,
            N::NumbersPartitionPositiveRaiseNewRoundWork,
        ]
    } else {
        [
            N::NumbersPartitionPositiveLowerResponseLower,
            N::NumbersPartitionPositiveLowerResponseUpper,
            N::NumbersPartitionPositiveLowerPairUpper,
            N::NumbersPartitionPositiveLowerProjectedUpper,
            N::NumbersPartitionPositiveLowerOldRoundWork,
            N::NumbersPartitionPositiveLowerNewRoundWork,
        ]
    };
    burn_pin_interval(&scoped_delta, pins[0], pins[1], &mut budget);
    assert_eq!(partition_upper(&bound, &mut budget), pins[2].value());
    assert_eq!(partition_upper(&residual_bound, &mut budget), pins[3].value());
    assert_eq!(old.work, pins[4].integer());
    assert_eq!(new.work, pins[5].integer());
}

/// Claim: The complete fold-and-export split with close heterogeneous source rates passes the full rung in both orientations and both histories. Certified target responses have opposite signs; replayed transport over equilibrium boxes bounds common-source total variation and projected residual displacement under matched source pairs, fixed recipients, saturated emission and absorbing targets. No unconditional split equality or response direction is inferred.
/// ´claim:standing:positive-rung-splits-retain-displacement-premises´
/// ´test:integration:positive-rung-split´
#[test]
fn positive_rung_split() {
    for case in [ExportCase::Raise, ExportCase::Lower] {
        let (before, after, old, new) = exporting(case);
        positive_displacement(&before, &after, &old, &new, matches!(case, ExportCase::Raise));
    }
}
fn partition_sum(
    a: &nrz_cas::enclosure::Interval,
    b: &nrz_cas::enclosure::Interval,
    budget: &mut Budget,
) -> nrz_cas::enclosure::Interval {
    nrz_cas::enclosure::Interval::new(
        a.lower().add(b.lower(), budget).unwrap(),
        a.upper().add(b.upper(), budget).unwrap(),
        budget,
    )
    .unwrap()
}
fn partition_product(
    a: &nrz_cas::enclosure::Interval,
    b: &nrz_cas::enclosure::Interval,
    budget: &mut Budget,
) -> nrz_cas::enclosure::Interval {
    assert!(!a.lower().is_negative() && !b.lower().is_negative());
    nrz_cas::enclosure::Interval::new(
        a.lower().mul(b.lower(), budget).unwrap(),
        a.upper().mul(b.upper(), budget).unwrap(),
        budget,
    )
    .unwrap()
}
fn partition_quotient(
    a: &nrz_cas::enclosure::Interval,
    b: &nrz_cas::enclosure::Interval,
    budget: &mut Budget,
) -> nrz_cas::enclosure::Interval {
    assert!(!a.lower().is_negative() && !b.lower().is_negative() && !b.lower().is_zero());
    nrz_cas::enclosure::Interval::new(
        a.lower().div(b.upper(), budget).unwrap(),
        a.upper().div(b.lower(), budget).unwrap(),
        budget,
    )
    .unwrap()
}

fn matched_coefficients(before: &CompiledState, after: &CompiledState) {
    let score = |state: &CompiledState, source: &str, target: &str| {
        let pn_epoch::base::BaseScore::Exact(value) = &state.view().base.rows[source][target].score else {
            panic!("exact matched base")
        };
        Fraction::parse(value)
    };
    let old_diagonal = score(before, "retained", "retained");
    let old_edge = score(before, "retained", "target");
    assert_eq!(old_edge, Fraction(1, 1)); // The coarse Opinion cell reaches its cap.
    for member in ["moved", "retained"] {
        let diagonal = score(after, member, member);
        let edge = score(after, member, "target");
        assert_eq!(edge, Fraction::parse(N::NumbersPartitionMatchedCoordinate.value()));
        assert_eq!(old_edge.times(diagonal), edge.times(old_diagonal));
        assert_eq!(after.view().base.rows[member].len(), 2);
    }
    assert_eq!(before.view().base.rows["retained"].len(), 2);
    // For every positive target factor t the row is (d, e*t)/(d+e*t).
    // The exact cross products above prove equality for every t, at every hop;
    // the outside row is absorbing, and the matched rates give equal emission.
    assert_ne!(
        before.view().support.sources["retained"].reduced_rate,
        before.view().support.sources["target"].reduced_rate
    );
}

/// Claim: The declared complete proportional split with capped parallel Opinion cells has exact base-score ratios that intertwine every target activation factor at every hop, matched rates and saturated emission. Both certified histories select the full rung. Independently replayed endpoint maps are nonconstant, and the certified equilibrium enclosures intersect at every lifted coordinate. Equality follows under the checked hop-refinement premises, not from finite numerical overlap alone.
/// ´claim:standing:nonconstant-matched-split-retains-hop-refinement´
/// ´test:integration:nonconstant-matched-split´
#[test]
fn nonconstant_matched_split() {
    let (before, after, old, new) = exporting(ExportCase::Matched);
    matched_coefficients(&before, &after);
    let old = old.rounds.last().unwrap();
    let new = new.rounds.last().unwrap();
    let mut budget = Budget::new(limits()).unwrap();
    for (name, range) in &new.standing {
        let original = if name == "moved" { "retained" } else { name };
        let left = burn_range(&old.standing[original], &mut budget);
        let right = burn_range(range, &mut budget);
        left.intersection(&right, &mut budget).unwrap();
    }
    let p = policy(&before);
    let bound = bind_procedure(&before, p.clone(), &Published(p), limits()).unwrap();
    let endpoint = |upper: bool| {
        before
            .view()
            .support
            .ranges
            .iter()
            .map(|(name, range)| {
                (
                    name.clone(),
                    if upper { range.maximum.clone() } else { range.minimum.clone() },
                )
            })
            .collect()
    };
    let low = pn_epoch::conserved::evaluate_map(&bound, "1", &endpoint(false), old.certified.precision).unwrap();
    let high = pn_epoch::conserved::evaluate_map(&bound, "1", &endpoint(true), old.certified.precision).unwrap();
    pn_epoch::conserved::replay_map(&bound, &low).unwrap();
    pn_epoch::conserved::replay_map(&bound, &high).unwrap();
    let next_policy = policy(&after);
    let next_bound = bind_procedure(&after, next_policy.clone(), &Published(next_policy), limits()).unwrap();
    for original in [&low, &high] {
        let lifted = new
            .standing
            .keys()
            .map(|name| {
                let source = if name == "moved" { "retained" } else { name };
                (name.clone(), original.point[source].clone())
            })
            .collect();
        let refined = pn_epoch::conserved::evaluate_map(&next_bound, "1", &lifted, original.precision).unwrap();
        pn_epoch::conserved::replay_map(&next_bound, &refined).unwrap();
        let coarse_names: Vec<_> = original.point.keys().collect();
        let refined_names: Vec<_> = refined.point.keys().collect();
        let coarse_source = coarse_names.iter().position(|name| *name == "retained").unwrap();
        let coarse_target = coarse_names.iter().position(|name| *name == "target").unwrap();
        let refined_target = refined_names.iter().position(|name| *name == "target").unwrap();
        assert_eq!(original.transport.normalized.len(), refined.transport.normalized.len());
        for (old_hop, new_hop) in original.transport.normalized.iter().zip(&refined.transport.normalized) {
            for member in ["moved", "retained"] {
                let source = refined_names.iter().position(|name| *name == member).unwrap();
                assert_eq!(old_hop[coarse_source][&coarse_source], new_hop[source][&source]);
                assert_eq!(old_hop[coarse_source][&coarse_target], new_hop[source][&refined_target]);
            }
            assert_eq!(
                old_hop[coarse_target][&coarse_target],
                new_hop[refined_target][&refined_target]
            );
        }
    }
    let low = burn_range(&low.image["target"], &mut budget);
    let high = burn_range(&high.image["target"], &mut budget);
    assert!(
        low.upper().compare(high.lower(), &mut budget).unwrap().is_lt()
            || high.upper().compare(low.lower(), &mut budget).unwrap().is_lt()
    );
    assert_eq!(old.work, N::NumbersPartitionMatchedOldRoundWork.integer());
    assert_eq!(new.work, N::NumbersPartitionMatchedNewRoundWork.integer());
    burn_pin_upper(
        &Rational::parse(&old.radius, &mut budget).unwrap(),
        N::NumbersPartitionMatchedOldRadiusUpper,
        &mut budget,
    );
    burn_pin_upper(
        &Rational::parse(&new.radius, &mut budget).unwrap(),
        N::NumbersPartitionMatchedNewRadiusUpper,
        &mut budget,
    );
}

fn partition_upper(value: &nrz_cas::Rational, budget: &mut Budget) -> String {
    nrz_cas::enclosure::Interval::singleton(value, budget)
        .unwrap()
        .coarsen(u32::try_from(N::NumbersPartitionPrecision.integer()).unwrap(), budget)
        .unwrap()
        .upper()
        .exact_string(budget)
        .unwrap()
}
