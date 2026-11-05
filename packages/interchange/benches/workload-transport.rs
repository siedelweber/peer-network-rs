#[path = "../tests/support/transport_workloads.rs"]
mod workloads;

use criterion::{Criterion, SamplingMode};
use pn_interchange::{TransportUsage, Value};
use std::hint::black_box;
use std::time::{Duration, Instant};

fn main() {
    let name = std::env::var("PN_BENCH_POINT").unwrap();
    let size: usize = std::env::var("PN_BENCH_SIZE").unwrap().parse().unwrap();
    let variant = std::env::var("PN_BENCH_VARIANT").unwrap();
    assert!(variant == "strict" || variant == "chunked");
    let mode = std::env::var("PN_BENCH_MODE").unwrap();
    let setup = Instant::now();
    let (value, bytes, limits) = workloads::input(size, variant == "chunked");
    let setup_s = setup.elapsed().as_secs_f64();
    let mut criterion = Criterion::default()
        .output_directory(std::path::Path::new(&std::env::var_os("PN_BENCH_OUTPUT").unwrap()))
        .sample_size(10)
        .warm_up_time(Duration::from_millis(if mode == "full" { 100 } else { 10 }))
        .measurement_time(Duration::from_millis(if mode == "full" { 1000 } else { 30 }))
        .nresamples(1000)
        .configure_from_args();
    let mut group = criterion.benchmark_group("workload-transport");
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(&name, |bench| {
        bench.iter(|| {
            let result = if variant == "strict" {
                Value::from_canonical_bytes(black_box(&bytes))
            } else {
                Value::from_transport_bytes(black_box(&bytes), limits, &mut TransportUsage::default())
            };
            drop(black_box(result.unwrap()));
        });
    });
    group.finish();
    criterion.final_summary();
    let mut usage = TransportUsage::default();
    assert_eq!(Value::from_transport_bytes(&bytes, limits, &mut usage).unwrap(), value);
    let receipt = serde_json::json!({"name": name, "size": size, "variant": variant, "mode": mode,
        "run": std::env::var("PN_BENCH_RUN").unwrap(), "setup_s": setup_s, "correctness": "passed",
        "input_bytes": bytes.len(), "allocation_calls": usage.allocation_calls,
        "allocation_bytes": usage.allocation_bytes, "items": usage.items, "work": usage.work,
        "usage_scope": "separate identical transport read, including for strict control"});
    std::fs::write(
        std::env::var_os("PN_BENCH_RECEIPT").unwrap(),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
}
