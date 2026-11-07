#[path = "support/base.rs"]
mod base;
#[path = "support/control.rs"]
mod control;
#[path = "support/publication.rs"]
mod fixture;

use criterion::{BatchSize, Criterion, SamplingMode};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

fn dimensions(name: &str, size: usize) -> (usize, usize) {
    if name.starts_with("publication-bytes-") {
        (1, size)
    } else {
        assert!(name.starts_with("publication-"));
        (size, 32)
    }
}

const RECIPE: &str = "publication-workloads/typed-refusals-v2";

fn refused(phase: &str, cause: &str, setup: Instant) {
    let receipt = serde_json::json!({
        "name": std::env::var("PN_BENCH_POINT").unwrap(),
        "size": std::env::var("PN_BENCH_SIZE").unwrap().parse::<usize>().unwrap(),
        "variant": std::env::var("PN_BENCH_VARIANT").unwrap(),
        "mode": std::env::var("PN_BENCH_MODE").unwrap(),
        "run": std::env::var("PN_BENCH_RUN").unwrap(),
        "recipe_edition": RECIPE, "correctness": "passed", "outcome": "refused",
        "phase": phase, "reason": format!("{phase}: {cause}"), "cause": cause,
        "setup_s": setup.elapsed().as_secs_f64(),
        "count_scope": "no completed operation; no fitted samples or unavailable work totals represented as zero"
    });
    std::fs::write(
        std::env::var_os("PN_BENCH_RECEIPT").unwrap(),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
}

fn main() {
    let name = std::env::var("PN_BENCH_POINT").unwrap();
    let size: usize = std::env::var("PN_BENCH_SIZE").unwrap().parse().unwrap();
    let variant = std::env::var("PN_BENCH_VARIANT").unwrap();
    let mode = std::env::var("PN_BENCH_MODE").unwrap();
    let setup = Instant::now();
    assert_eq!(dimensions("publication-bytes-encode-256", 256), (1, 256));
    assert_eq!(dimensions("publication-restore-2", 2), (2, 32));
    let (boundaries, padding) = dimensions(&name, size);
    let (admitted, verifier) = match fixture::series(boundaries, padding) {
        Ok(value) => value,
        Err(error) => {
            refused("construction", &error, setup);
            return;
        }
    };
    let disclosure = admitted.disclosures();
    let limits = base::Limits {
        work: 100_000_000,
        arithmetic_steps: 5_000_000,
        ..base::Limits::default()
    };
    let bytes = match pn_host::publication::encode(&disclosure, &mut base::numeric(), limits.clone()) {
        Ok(value) => value,
        Err(error) => {
            refused("encode-control", &format!("{error:?}"), setup);
            return;
        }
    };
    let control = || -> Result<(), String> {
        let decoded = control::decode_control(&bytes, &disclosure, &mut base::numeric(), limits.clone())
            .map_err(|error| format!("decode-control: {error:?}"))?;
        assert_eq!(decoded, disclosure);
        assert_eq!(
            pn_host::publication::encode(&decoded, &mut base::numeric(), limits.clone())
                .map_err(|error| format!("reencode-control: {error:?}"))?,
            bytes
        );
        let restored = base::d::restore(decoded, &verifier).map_err(|error| format!("restore-control: {error:?}"))?;
        assert_eq!(restored.carrier(), admitted.carrier());
        assert_eq!(restored.boundary().evidence(), admitted.boundary().evidence());
        Ok(())
    };
    if let Err(error) = control() {
        refused("untimed-control", &error, setup);
        return;
    }
    let setup_s = setup.elapsed().as_secs_f64();
    let mut criterion = Criterion::default()
        .output_directory(std::path::Path::new(&std::env::var_os("PN_BENCH_OUTPUT").unwrap()))
        .sample_size(10)
        .nresamples(1000)
        .warm_up_time(Duration::from_millis(if mode == "full" { 100 } else { 10 }))
        .measurement_time(Duration::from_millis(if mode == "full" { 1000 } else { 30 }))
        .configure_from_args();
    let mut group = criterion.benchmark_group("workload-publication");
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(&name, |bench| match variant.as_str() {
        "encode" => bench.iter_batched(
            base::numeric,
            |mut numeric| {
                drop(black_box(
                    pn_host::publication::encode(black_box(&disclosure), &mut numeric, limits.clone()).unwrap(),
                ));
            },
            BatchSize::PerIteration,
        ),
        "decode" => bench.iter_batched(
            base::numeric,
            |mut numeric| {
                drop(black_box(
                    pn_host::publication::decode(black_box(&bytes), &mut numeric, limits.clone()).unwrap(),
                ));
            },
            BatchSize::PerIteration,
        ),
        "restore" => bench.iter_batched(
            base::numeric,
            |mut numeric| {
                let decoded = pn_host::publication::decode(black_box(&bytes), &mut numeric, limits.clone()).unwrap();
                drop(black_box(base::d::restore(decoded, &verifier).unwrap()));
            },
            BatchSize::PerIteration,
        ),
        _ => panic!("undeclared publication operation"),
    });
    group.finish();
    criterion.final_summary();
    control().expect("previously passing deterministic control changed after measurement");
    let standing_replay_work: u64 = disclosure.frames.iter().map(|frame| frame.standing.replay_work).sum();
    let receipt = serde_json::json!({"name": name, "size": size, "variant": variant, "mode": mode,
        "recipe_edition": RECIPE, "run": std::env::var("PN_BENCH_RUN").unwrap(), "correctness": "passed", "setup_s": setup_s,
        "dimensions": {"boundaries": boundaries, "acts": disclosure.causes.acts.len(), "provenance_bytes_per_boundary": padding,
            "canonical_bytes": bytes.len(), "retained_standing_replay_work": standing_replay_work},
        "count_scope": "canonical_bytes is the complete codec input/output length; retained_standing_replay_work sums one published standing replay ledger per boundary, not all restore work or repeated schedule work",
        "unavailable": "codec arithmetic usage, NumericContext usage and complete restore execution work are not exposed publicly"});
    std::fs::write(
        std::env::var_os("PN_BENCH_RECEIPT").unwrap(),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
}
