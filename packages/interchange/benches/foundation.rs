#[path = "../tests/support/benchmark_workloads.rs"]
mod workloads;

use criterion::Criterion;
use pn_interchange::Value;
use std::hint::black_box;
use std::time::Duration;

fn main() {
    let value = workloads::value();
    let output = std::env::var_os("PN_BENCH_OUTPUT").expect("owned benchmark output directory");
    // Correctness is checked before sampling; a panic remains a failing command.
    assert_eq!(value.to_canonical_bytes(), workloads::BYTES);
    assert_eq!(
        Value::from_canonical_bytes(workloads::BYTES).expect("canonical workload"),
        value
    );
    let mut criterion = Criterion::default()
        .output_directory(std::path::Path::new(&output))
        .sample_size(10)
        .warm_up_time(Duration::from_millis(10))
        .measurement_time(Duration::from_millis(30))
        .configure_from_args();
    criterion.bench_function("canonical-encode", |bench| {
        bench.iter(|| black_box(value.to_canonical_bytes()));
    });
    criterion.bench_function("canonical-decode", |bench| {
        bench.iter(|| black_box(Value::from_canonical_bytes(workloads::BYTES)));
    });
    criterion.final_summary();
}
