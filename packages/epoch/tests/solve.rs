mod common;
#[path = "common/joined.rs"]
mod joined;

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
    for case in 0..8 {
        let mut bad = procedure.clone();
        match case {
            0 => bad.maximum_work = 0,
            1 => bad.maximum_iterations = 0,
            2 => bad.margin = "1".into(),
            3 => bad.endpoint_grid = "0".into(),
            4 => bad.precision = Precision::BinaryBits(vec![]),
            5 => bad.precision = Precision::BinaryBits(vec![64, 32]),
            6 => bad.primitives.clear(),
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

fn dense_operator(hops: &[Vec<Vec<Fraction>>], mass: &[Fraction], emission: &[Fraction]) -> Vec<Vec<Fraction>> {
    let n = emission.len();
    let z = Fraction(0, 1);
    let one = Fraction(1, 1);
    let mut current: Vec<Vec<_>> = (0..n)
        .map(|i| (0..n).map(|j| if i == j { one } else { z }).collect())
        .collect();
    let mut answer = vec![vec![z; n]; n];
    for (hop, mass) in hops.iter().zip(mass) {
        let normalized: Vec<Vec<_>> = hop
            .iter()
            .map(|row| {
                let sum = row.iter().copied().fold(z, Fraction::plus);
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
                            .fold(z, Fraction::plus)
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
/// ´claim:compiler:exact-transport-agrees-with-dense-rational-oracle´
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
    let emission = vec![half, z, o];
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
    for denominator in [2, 9, 3, 4, 5, 1] {
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
    p.maximum_work = 200_000_000;
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

/// Claim: The rung driver uses the frozen contributing width and cumulative shape through the deepest supported depth, evaluates the deployed wall gain independently at each attempted rung, and selects the first proved pass in the descending published grid; exact zero-width and empty-domain cases preserve the frozen state, and equal-width weighted graphs give identical fence transcripts.
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

/// Claim: A rung's fixed precision sequence uses fresh stores and retains actual Work and original queries; a straddle at sequence exhaustion and a straddle stopped before the next unaffordable operation are INDECISIVE and passed over, while interruption supplies no selected rung. A private starting precision cannot replace the declared sequence or alter its choice.
/// ´claim:compiler:rung-search-keeps-declared-stops-and-precision´
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
