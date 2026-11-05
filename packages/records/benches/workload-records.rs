#[path = "../tests/common/workload_inputs.rs"]
mod workloads;

use criterion::{BatchSize, Criterion, SamplingMode};
use pn_records::burn::{recognize_markers, validate_marker_history};
use std::hint::black_box;
use std::time::{Duration, Instant};

fn main() {
    let name = std::env::var("PN_BENCH_POINT").unwrap();
    let size: usize = std::env::var("PN_BENCH_SIZE").unwrap().parse().unwrap();
    let variant = std::env::var("PN_BENCH_VARIANT").unwrap();
    let mode = std::env::var("PN_BENCH_MODE").unwrap();
    let output = std::env::var_os("PN_BENCH_OUTPUT").unwrap();
    let setup = Instant::now();
    let history = (variant == "parallel" || variant == "mixed").then(|| workloads::history(size, variant == "mixed"));
    let markers = (variant == "list" || variant == "commitment").then(|| {
        let case = workloads::marker_case(size, variant == "commitment");
        let policy = workloads::marker_policy(&case);
        (case.history, policy)
    });
    assert_ne!(history.is_some(), markers.is_some());
    let setup_s = setup.elapsed().as_secs_f64();
    let mut criterion = Criterion::default()
        .output_directory(std::path::Path::new(&output))
        .sample_size(10)
        .warm_up_time(Duration::from_millis(if mode == "full" { 100 } else { 10 }))
        .measurement_time(Duration::from_millis(if mode == "full" { 1000 } else { 30 }))
        .nresamples(1000)
        .configure_from_args();
    let mut group = criterion.benchmark_group("workload-records");
    group.sampling_mode(SamplingMode::Flat);
    if let Some((acts, names)) = &history {
        group.bench_function(&name, |bench| {
            bench.iter(|| {
                drop(black_box(
                    pn_records::validate_history(black_box(acts), black_box(names)).unwrap(),
                ));
            });
        });
        assert_eq!(pn_records::validate_history(acts, names).unwrap().acts().len(), size);
    }
    if let Some((input, policy)) = &markers {
        group.bench_function(&name, |bench| {
            bench.iter_batched(
                || input.clone(),
                |input| {
                    let checked =
                        validate_marker_history(input, policy, &pn_records::test_support::burn::FixtureVerifier).unwrap();
                    drop(black_box(recognize_markers(&checked)));
                },
                BatchSize::PerIteration,
            );
        });
        let checked = validate_marker_history(input.clone(), policy, &pn_records::test_support::burn::FixtureVerifier).unwrap();
        assert!(recognize_markers(&checked).first_refusal().is_none());
    }
    group.finish();
    criterion.final_summary();
    let dimensions = if let Some((acts, _)) = &history {
        let actors: std::collections::BTreeSet<_> = acts.iter().map(|act| &act.id.author).collect();
        serde_json::json!({"actors": actors.len(), "acts": acts.len(), "legs": acts.iter().map(|act| act.legs.len()).sum::<usize>(),
            "markers": 0, "logical_work": "unavailable: structural validator exposes no work counter"})
    } else {
        let (input, _) = markers.as_ref().unwrap();
        let memberships: usize = input
            .markers
            .iter()
            .map(|marker| match &marker.accepted {
                pn_records::burn::AcceptedSet::CompleteList(members) => members.len(),
                pn_records::burn::AcceptedSet::Commitment { openings, .. } => {
                    openings.iter().map(|opening| opening.members.len()).sum()
                }
                pn_records::burn::AcceptedSet::WholePrefix => 0,
            })
            .sum();
        serde_json::json!({"markers": input.markers.len(), "burn_records": input.records.len(), "memberships": memberships,
            "destruction_checks": input.records.len(), "opening_checks": if variant == "commitment" { input.markers.len() } else { 0 },
            "logical_work": "unavailable: recognition exposes no work counter"})
    };
    let receipt = serde_json::json!({"name": name, "size": size, "variant": variant, "mode": mode,
        "run": std::env::var("PN_BENCH_RUN").unwrap(), "setup_s": setup_s, "correctness": "passed", "dimensions": dimensions});
    std::fs::write(
        std::env::var_os("PN_BENCH_RECEIPT").unwrap(),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
}
