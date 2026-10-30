mod common;
#[path = "common/joined.rs"]
mod joined;

use nrz_cas::limits::Limits;
use pn_epoch::{
    compiler::compile_final_state,
    solve::{ProcedureError, ProcedureVerifier, bind_procedure},
};
use pn_records::solve::{
    Attempt, Bounds, Completion, Equality, Evidence, Precision, Primitive, Procedure, RecordError, Residual, validate_evidence,
    validate_procedure,
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

/// Claim: A solve declaration is retained with the frozen compiled package only after its boundary, constants edition, declared name and full public payload agree; wrong bindings and same-name payload substitution refuse, and every declared nonlinear backend remains unsupported at preflight.
/// ´claim:compiler:solve-declarations-bind-without-enabling-evaluation´
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
    Attempt {
        rung: rung.into(),
        margined_fence: range,
        work: 10,
        completion,
    }
}

/// Claim: Supplied evidence records distinguish proved bound separation, exhausted straddling and interruption; reject malformed hulls, out-of-order or post-completion attempts and inconsistent residual radii; and never attach a residual result to an interrupted attempt. These are consistency checks, not validation of the supplied map evaluations.
/// ´claim:compiler:solve-transcripts-separate-verdicts-from-interruption´
/// ´test:integration:evidence-records´
#[test]
fn evidence_records() {
    let procedure = declaration(&state());
    let evidence = Evidence {
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
            1 => bad.attempts[0].completion = Completion::Fail,
            2 => bad.attempts[0].completion = Completion::Pass,
            3 => bad.attempts[0].work = 9,
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
