pub use constants::pins;
mod causes;
mod constants;
mod history;
pub mod scalar;
use causes::{Approval, act, named};
pub use history::numeric;
use nrz_cas::limits::Limits;
use pn_epoch::{compiler, package, solve::ProcedureVerifier};
use pn_records::solve::{Equality, Precision, Primitive, Procedure};
use std::collections::{BTreeMap, BTreeSet};
pub const PRODUCTS: u64 = 100_000;
pub const SEED: u64 = 0;

#[derive(Debug)]
struct Causes(package::CandidateInput);
impl package::CandidateVerifier for Causes {
    fn candidate_causes(&self, i: &package::CandidateInput) -> bool {
        i.causes.bindings == self.0.causes.bindings
            && i.causes.inputs == self.0.causes.inputs
            && i.causes.prices == self.0.causes.prices
            && i.causes.history.acts() == self.0.causes.history.acts()
    }
}
impl package::ClosureVerifier for Causes {
    fn host_determination(&self, i: &package::CandidateInput) -> bool {
        i.closure == self.0.closure
    }
}
#[derive(Debug)]
pub struct Published(pub Procedure);
impl ProcedureVerifier for Published {
    fn published_procedure(&self, p: &Procedure) -> bool {
        p == &self.0
    }
}
pub struct Candidate {
    pub context: package::CandidateContext,
    pub approval: Approval,
    pub n: usize,
    pub m: usize,
}

// shape ring/dense use one current registration per Actor and complete Reference acts.
// parallel/mixed retain exactly M current complete acts, including registrations.
pub fn candidate(seed: u64, n: usize, m: Option<usize>, shape: &str, outcome: &str) -> Candidate {
    assert!(n >= 2);
    let actors: Vec<_> = (0..n).map(|i| format!("actor-{seed}-{i}")).collect();
    let mut raw: Vec<_> = actors
        .iter()
        .enumerate()
        .map(|(i, a)| act("Registration", a, u64::try_from(i + 1).unwrap(), 1))
        .collect();
    let extra = m.map_or(if shape == "dense" { n * (n - 1) } else { n }, |m| m.checked_sub(n).unwrap());
    for k in 0..extra {
        let source = k % n;
        let target = if shape == "dense" {
            (source + 1 + (k / n) % (n - 1)) % n
        } else {
            (source + 1) % n
        };
        let family = if shape == "mixed" {
            if k % 2 == 0 { "Opinion" } else { "Reference" }
        } else if shape == "self" || shape == "trials" || shape == "parallel" {
            "Opinion"
        } else {
            "Reference"
        };
        let mut a = act(family, &actors[source], u64::try_from(raw.len() + 1).unwrap(), 1);
        let target = if shape == "self" || shape == "trials" {
            source
        } else {
            target
        };
        if family == "Reference" {
            let middle = named("name", &format!("object-{seed}-{k}"));
            a.legs[0].target = middle.clone();
            a.legs[1].source = middle;
            a.legs[1].target = named("prof", &actors[target]);
        } else {
            a.legs[0].target = named("prof", &actors[target]);
        }
        raw.push(a);
    }
    if shape == "trials" {
        for index in 1..raw.len() {
            let parent = raw[index - 1].id.clone();
            raw[index].body.asserted_parents.push(parent.clone());
            raw[index].projections.dependency = pn_records::DependencyProjection::Full(vec![parent]);
        }
    }
    causes::stamp(&mut raw);
    raw.reverse();
    let mut counts = BTreeMap::<String, u64>::new();
    for a in &raw {
        *counts.entry(a.id.author.clone()).or_default() += 1;
    }
    let amounts: Vec<_> = actors
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let rate = if outcome == "individual" && i == 0 {
                1
            } else if outcome == "late" {
                10 + 90 * i as u64
            } else if outcome == "equal" || (shape == "self" || shape == "trials") {
                10
            } else {
                10 + i as u64
            };
            let amount = if outcome == "own" && i == 0 {
                1
            } else {
                counts[a] * (2 + rate)
            };
            (a.clone(), amount.to_string())
        })
        .collect();
    let borrowed: Vec<_> = amounts.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let causes = history::package_at_prices(&raw, 1, &borrowed, &["2"], &[]);
    let approval = Approval(causes.history.acts().to_vec());
    let input = package::CandidateInput {
        causes,
        closure: package::ClosureStatement {
            policy: package::ClosurePolicy {
                target: u64::try_from(raw.len()).unwrap(),
                minimum_ticks: 0,
                maximum_ticks: 1,
                clock: "benchmark-clock".into(),
            },
            opened_at: 0,
            determined_at: 1,
            cause: package::ClosureCause::MaximumDuration,
            attestation: format!("benchmark-determination-{seed}"),
        },
    };
    let verifier = Causes(input.clone());
    let context = package::verify_candidate(input, &verifier, &verifier).unwrap();
    Candidate {
        context,
        approval,
        n,
        m: raw.len(),
    }
}
pub fn compile(c: &Candidate) -> Result<compiler::CompiledState, Box<compiler::CompileError>> {
    compiler::compile_candidate(&c.context, &c.approval, &mut numeric(), Limits::default(), PRODUCTS).map_err(Box::new)
}
pub fn check_compilation(c: &Candidate, s: &compiler::CompiledState) {
    let v = s.view();
    assert_eq!(v.ledger.counts.len(), c.n);
    assert_eq!(v.ledger.debits.len(), c.m);
    assert_eq!(v.base.rows.len(), c.n);
    let total: u64 = v.ledger.counts.values().map(|n| n.0).sum();
    assert_eq!(total, u64::try_from(c.m).unwrap());
    for (a, n) in &v.ledger.counts {
        assert_eq!(
            n.0.to_string(),
            c.context
                .input()
                .causes
                .history
                .acts()
                .iter()
                .filter(|x| x.id().author == a.0)
                .count()
                .to_string()
        );
    }
}
pub fn dimensions(c: &Candidate, s: &compiler::CompiledState) -> String {
    format!(
        "N={} M={} Z={} H={} cells={} products={} S=1",
        c.n,
        c.m,
        s.view().base.rows.values().map(BTreeMap::len).sum::<usize>(),
        s.view().support.by_depth.keys().next_back().copied().unwrap_or(0),
        s.view().cells.len(),
        s.view().support.products
    )
}
pub fn procedure(s: &compiler::CompiledState, bits: u32) -> Procedure {
    let inputs = s.package().input().inputs.last().unwrap();
    let work = constants::pins::NumberId::NumbersSolveWorkCeiling.integer();
    let limits = Limits {
        work,
        output_bytes: 32 * 1024 * 1024,
        arithmetic_steps: 5_000_000,
        ..Limits::default()
    };
    Procedure {
        edition: inputs.parameters().edition.clone(),
        boundary: inputs.parameters().boundary,
        name: inputs.constants().content().numerical_procedure.clone(),
        backend: "nrz-cas".into(),
        primitives: BTreeSet::from([
            Primitive::Rational,
            Primitive::Root,
            Primitive::Exponential,
            Primitive::Logarithm,
            Primitive::Power,
            Primitive::Sigmoid,
            Primitive::Tanh,
            Primitive::SmoothDerivative,
            Primitive::ClampGeneralized,
        ]),
        precision: Precision::AbsoluteWidthBits(vec![bits]),
        equality: Equality::ExactRationalOnly,
        grid: vec!["1".into(), "1/2".into(), "0".into()],
        margin: "5/4".into(),
        maximum_work: work,
        maximum_solve_work: work,
        maximum_replay_work: work,
        maximum_iterations: 4,
        endpoint_grid: "1/1024".into(),
        fence: Some(pn_records::solve::FenceProfile {
            bleed_squared: "bleed".into(),
            shape: vec!["one".into(), "rest".into(), "third".into(), "zero".into()],
            inverse_wall: false,
        }),
        enclosure: Some(pn_records::primitive::EnclosurePolicy {
            store: limits.clone(),
            operation: limits,
            refinement: nrz_cas::enclosure::RefinementPolicy {
                version: 1,
                precision: bits,
                grid_ceiling: 96,
                rounds: 1,
                reduction_ceiling: 4,
                term_ceiling: 64,
                checking_work: 0,
            },
        }),
    }
}
pub fn solve_counters(r: &pn_records::conserved::SolveRecord) -> String {
    let k: usize = r.rounds.iter().map(|r| r.proposals.len()).sum();
    let primitive_count: usize = r
        .rounds
        .iter()
        .map(|r| r.certified.primitives.len() + r.proposals.iter().map(|p| p.primitives.len()).sum::<usize>())
        .sum();
    let transcript = format!("{r:?}");
    format!(
        "K={k} precision_rounds={} primitive_count={primitive_count} solve_work={} replay_work={} diagnostic_transcript_bytes={} retained_heap_bytes=unavailable-no-allocator-counter residuals={:?}",
        r.rounds.len(),
        r.work,
        r.replay_work,
        transcript.len(),
        r.rounds.iter().map(|r| &r.residual).collect::<Vec<_>>()
    )
}
pub fn schedule(c: &Candidate, policy: &str) -> pn_epoch::schedules::CheckedSchedule {
    use pn_epoch::admission::{ControllerParameters, Delivery, InitializationInput, Refinement, ScheduleInput, declare_schedule};
    let binding = c.context.input().causes.bindings.last().unwrap();
    let d = declare_schedule(
        ScheduleInput {
            controller: "canonical-interim-v1".into(),
            announced_at: 0,
            initialization: InitializationInput {
                floor: Some(binding.inputs.constants().content().floor),
                wall: Some(binding.price.wall().exact().into()),
                policy_floor: Some(policy.into()),
                effective_boundary: Some(1),
                parameters: Some(ControllerParameters {
                    absolute_cap: "1/4".into(),
                    relative_cap: "1/4".into(),
                    deadband: "0".into(),
                    margin: "5/4".into(),
                }),
            },
            numeraire: binding.price.numeraire().clone(),
            delivery: Delivery::ExactRational,
            refinement: Refinement {
                precision_bits: vec![8],
                maximum_work: constants::pins::NumberId::NumbersControllerTestWork.integer(),
                maximum_replay_work: constants::pins::NumberId::NumbersControllerTestWork.integer(),
            },
        },
        Limits::default(),
    )
    .unwrap();
    let r = pn_epoch::schedules::evaluate(&d, &[], None, Limits::default()).unwrap();
    pn_epoch::schedules::replay(&d, &[], None, Limits::default(), &r).unwrap()
}

// Workload fixture only: 100 times the old 200-million allowance permits the
// denser N=2..8 series; the runner's per-point wall deadline remains independent.
pub fn scaling_procedure(state: &compiler::CompiledState, bits: u32) -> Procedure {
    let mut p = procedure(state, bits);
    let work = 20_000_000_000;
    p.maximum_work = work;
    p.maximum_solve_work = work;
    p.maximum_replay_work = work;
    let e = p.enclosure.as_mut().unwrap();
    e.operation.work = work;
    e.operation.arithmetic_steps = 1_000_000_000;
    e.store = e.operation.clone();
    p
}
