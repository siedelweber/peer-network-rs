use criterion::{Criterion, SamplingMode};
use pn_host::{
    Configuration, Session,
    storage::{Family, Payload, PostgresStore, Predecessor, Version},
};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

fn main() {
    let name = std::env::var("PN_BENCH_POINT").unwrap();
    let size: u64 = std::env::var("PN_BENCH_SIZE").unwrap().parse().unwrap();
    assert!([1, 2, 4, 8, 16, 32, 64, 128, 256].contains(&size));
    let variant = std::env::var("PN_BENCH_VARIANT").unwrap();
    let mode = std::env::var("PN_BENCH_MODE").unwrap();
    let setup = Instant::now();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let root = std::env::var_os("PN_HOST_TEST_ROOT").unwrap();
    let mut file = std::fs::File::open(std::path::Path::new(&root).join(format!("workload-storage-{size}.json"))).unwrap();
    let config = Configuration::acquire(Some("host-secured"), &mut file).unwrap();
    let mut store = runtime.block_on(async {
        PostgresStore::open_store(Session::connect(config).await.unwrap())
            .await
            .unwrap()
    });
    let schema_s = setup.elapsed().as_secs_f64();
    let population = Instant::now();
    let mut appended = 0_u64;
    for at in 0..size {
        let input = Version {
            family: Family::Rule,
            key: "benchmark-rule".into(),
            edition: format!("edition-{at}"),
            announced_at: at,
            opens_at: at,
            payload: Some(Payload::rule(&pn_interchange::Value::Unsigned(0)).unwrap()),
        };
        let previous = (at > 0).then(|| Predecessor {
            edition: format!("edition-{}", at - 1),
            closes_at: at,
        });
        if runtime
            .block_on(store.append_effective_successor(input, previous.as_ref()))
            .unwrap()
        {
            appended += 1;
        }
    }
    let population_s = population.elapsed().as_secs_f64();
    let required = vec![(Family::Rule, "benchmark-rule".into())];
    let expected = runtime.block_on(store.load_boundary(size - 1, &required)).unwrap();
    assert_eq!(expected.rows.len(), 1);
    assert_eq!(expected.rows[0].version.edition, format!("edition-{}", size - 1));
    runtime.block_on(store.audit_history()).unwrap();
    let setup_s = setup.elapsed().as_secs_f64();
    let mut criterion = Criterion::default()
        .output_directory(std::path::Path::new(&std::env::var_os("PN_BENCH_OUTPUT").unwrap()))
        .sample_size(10)
        .nresamples(1000)
        .warm_up_time(Duration::from_millis(if mode == "full" { 100 } else { 10 }))
        .measurement_time(Duration::from_millis(if mode == "full" { 1000 } else { 30 }))
        .configure_from_args();
    let mut group = criterion.benchmark_group("workload-storage");
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(&name, |bench| match variant.as_str() {
        "load" => bench.iter(|| {
            drop(black_box(runtime.block_on(store.load_boundary(size - 1, &required)).unwrap()));
        }),
        "audit" => bench.iter(|| {
            runtime.block_on(store.audit_history()).unwrap();
        }),
        _ => panic!("undeclared storage operation"),
    });
    group.finish();
    criterion.final_summary();
    assert_eq!(runtime.block_on(store.load_boundary(size - 1, &required)).unwrap(), expected);
    runtime.block_on(store.audit_history()).unwrap();
    let receipt = serde_json::json!({"name": name, "size": size, "variant": variant, "mode": mode,
        "run": std::env::var("PN_BENCH_RUN").unwrap(), "correctness": "passed", "setup_s": setup_s, "schema_s": schema_s, "population_s": population_s,
        "dimensions": {"versions_per_key": size, "keys": 1, "successful_setup_appends": appended, "boundary_result_rows": expected.rows.len(),
            "effective_payload_bytes": expected.rows[0].version.payload.as_ref().unwrap().bytes().len()},
        "count_scope": "successful_setup_appends counts public append operations, not physical SQL rows; boundary_result_rows counts returned effective rows, not history rows scanned",
        "unavailable": "physical database rows read/written and audit work are not exposed; admitted-epoch persistence remains held"});
    std::fs::write(
        std::env::var_os("PN_BENCH_RECEIPT").unwrap(),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
}
