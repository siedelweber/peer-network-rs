#[path = "support/receipt.rs"]
mod receipt;
mod support;
use criterion::{BatchSize, Criterion, SamplingMode};
use nrz_cas::limits::Budget;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};
use support as inputs;
type Bench<'a> = criterion::BenchmarkGroup<'a, criterion::measurement::WallTime>;

fn selected(name: &str) -> bool {
    receipt::internal() == name
}

fn main() {
    let output = std::path::PathBuf::from(std::env::var_os("PN_BENCH_OUTPUT").expect("owned benchmark output directory"));
    std::fs::create_dir_all(&output).unwrap();
    let mode = std::env::var("PN_BENCH_MODE").unwrap();
    assert!(["full", "smoke", "pilot"].contains(&mode.as_str()));
    let seed = inputs::SEED;
    let mut criterion = Criterion::default()
        .output_directory(&output)
        .sample_size(10)
        .nresamples(1000)
        .warm_up_time(Duration::from_millis(if mode == "smoke" { 10 } else { 100 }))
        .measurement_time(Duration::from_millis(if mode == "smoke" { 30 } else { 1000 }))
        .configure_from_args();
    let mut group = criterion.benchmark_group("workload-graph");
    group.sampling_mode(SamplingMode::Flat);
    partitions(&mut group, &output, &mode, seed);
    transports(&mut group, &output, &mode, seed);
    titles(&mut group, &output, &mode, seed);
    group.finish();
    criterion.final_summary();
    receipt::finish(&output, &mode);
}

fn partitions(group: &mut Bench<'_>, output: &std::path::Path, mode: &str, seed: u64) {
    for m in if mode == "smoke" {
        vec![8]
    } else {
        vec![8, 16, 32, 64, 128, 256, 512, 1024]
    } {
        for shape in 0..if mode == "smoke" { 1 } else { 3 } {
            let name = format!("B2-partition-m{m}-shape{shape}");
            if !selected(&name) {
                continue;
            }
            let setup = Instant::now();
            inputs::check_partition(seed, m, shape);
            let record = inputs::partition(seed, m, shape);
            let input = pn_records::assemble_boundary_inputs(&record, (1, 1)).unwrap();
            let setup = setup.elapsed();
            let start = Instant::now();
            let result = pn_graph::partition_dependencies(&input).unwrap();
            let elapsed = start.elapsed();
            std::fs::write(
                output.join(format!("{name}.txt")),
                format!(
                    "recipe=scaling-workloads/v2 seed={seed} M={m} S=1 blocks={} setup_s={} pilot_operation_s={} outcome=PASS\n",
                    result.1.len(),
                    setup.as_secs_f64(),
                    elapsed.as_secs_f64()
                ),
            )
            .unwrap();
            if mode != "pilot" {
                group.bench_function(receipt::name(), |b| {
                    b.iter(|| drop(black_box(pn_graph::partition_dependencies(black_box(&input)).unwrap())));
                });
            }
            assert_eq!(pn_graph::partition_dependencies(&input).unwrap().1, result.1);
        }
    }
}

fn transports(group: &mut Bench<'_>, output: &std::path::Path, mode: &str, seed: u64) {
    for n in if mode == "smoke" {
        vec![2]
    } else {
        vec![2, 4, 8, 16, 32, 64, 128, 256]
    } {
        for dense in if mode == "smoke" { vec![false] } else { vec![false, true] } {
            if ![false, true]
                .iter()
                .any(|interval| selected(&format!("B4-transport-n{n}-dense{dense}-enclosed{interval}")))
            {
                continue;
            }
            let setup = Instant::now();
            let oracle = inputs::check_transport(seed, n, dense);
            let prepared =
                inputs::transport(seed, n, dense).and_then(|input| inputs::enclosed(&input).map(|enclosed| (input, enclosed)));
            let (input, enclosed) = match prepared {
                Ok(values) => values,
                Err(error) => {
                    for interval in [false, true] {
                        let name = format!("B4-transport-n{n}-dense{dense}-enclosed{interval}");
                        if selected(&name) {
                            std::fs::write(output.join(format!("{name}.txt")), format!("recipe=scaling-workloads/transport-construction-v3 seed={seed} N={n} outcome=REFUSED phase=construction refusal={error:?} setup_s={}\n", setup.elapsed().as_secs_f64())).unwrap();
                        }
                    }
                    continue;
                }
            };
            let setup = setup.elapsed();
            for interval in if mode == "smoke" { vec![false] } else { vec![false, true] } {
                let name = format!("B4-transport-n{n}-dense{dense}-enclosed{interval}");
                if !selected(&name) {
                    continue;
                }
                if let Err(error) = &oracle {
                    std::fs::write(output.join(format!("{name}.txt")),format!("recipe=scaling-workloads/transport-construction-v3 seed={seed} N={n} Z={} H=1 outcome=REFUSED phase=untimed-cross-oracle refusal={error:?} setup_s={}\n",if dense {n*n}else{2*n},setup.as_secs_f64())).unwrap();
                    continue;
                }
                let (elapsed, expected, work) = if interval {
                    let mut budget = Budget::new(inputs::operation_limits()).unwrap();
                    let start = Instant::now();
                    let result = pn_graph::transport::enclosed::evaluate(&enclosed, &mut budget, inputs::CELLS);
                    let elapsed = start.elapsed();
                    (elapsed, format!("{result:?}"), budget.usage().work)
                } else {
                    let mut arithmetic = inputs::Arithmetic::new();
                    let before = arithmetic.budget.usage().work;
                    let start = Instant::now();
                    let result = pn_graph::transport::exact_transport(&input, &mut arithmetic, inputs::CELLS);
                    let elapsed = start.elapsed();
                    (elapsed, format!("{result:?}"), arithmetic.budget.usage().work - before)
                };
                std::fs::write(output.join(format!("{name}.txt")),format!("recipe=scaling-workloads/transport-construction-v3 seed={seed} N={n} Z={} H=1 maximum_cells={} work={work} oracle_work_limit={} setup_s={} pilot_operation_s={} outcome={expected}\n",if dense {n*n}else{2*n},inputs::CELLS,inputs::ORACLE_WORK,setup.as_secs_f64(),elapsed.as_secs_f64())).unwrap();
                if mode != "pilot" {
                    if interval {
                        group.bench_function(receipt::name(), |b| {
                            b.iter_batched(
                                || Budget::new(inputs::operation_limits()).unwrap(),
                                |mut budget| {
                                    drop(black_box(pn_graph::transport::enclosed::evaluate(
                                        black_box(&enclosed),
                                        &mut budget,
                                        inputs::CELLS,
                                    )));
                                },
                                BatchSize::SmallInput,
                            );
                        });
                    } else {
                        group.bench_function(receipt::name(), |b| {
                            b.iter_batched(
                                inputs::Arithmetic::new,
                                |mut a| {
                                    drop(black_box(pn_graph::transport::exact_transport(
                                        black_box(&input),
                                        &mut a,
                                        inputs::CELLS,
                                    )));
                                },
                                BatchSize::SmallInput,
                            );
                        });
                    }
                }
                inputs::check_transport(seed, n, dense).unwrap();
            }
        }
    }
}

fn titles(group: &mut Bench<'_>, output: &std::path::Path, mode: &str, seed: u64) {
    if mode != "smoke" {
        for m in [4, 7, 16, 31, 64, 127, 256, 511] {
            let name = format!("B16-title-m{m}");
            if !selected(&name) {
                continue;
            }
            let setup = Instant::now();
            inputs::check_title(seed, m);
            let input = inputs::title(seed, m, false);
            let setup = setup.elapsed();
            let start = Instant::now();
            let expected = pn_graph::title::replay_title(&input.graph, &input.history, &input.approval, input.epoch).unwrap();
            let elapsed = start.elapsed();
            std::fs::write(
                output.join(format!("{name}.txt")),
                format!(
                    "recipe=scaling-workloads/v2 seed={seed} M={m} B={} setup_s={} pilot_operation_s={} outcome=PASS\n",
                    input.epoch,
                    setup.as_secs_f64(),
                    elapsed.as_secs_f64()
                ),
            )
            .unwrap();
            if mode != "pilot" {
                group.bench_function(receipt::name(), |b| {
                    b.iter(|| {
                        drop(black_box(
                            pn_graph::title::replay_title(black_box(&input.graph), &input.history, &input.approval, input.epoch)
                                .unwrap(),
                        ));
                    });
                });
            }
            assert_eq!(
                pn_graph::title::replay_title(&input.graph, &input.history, &input.approval, input.epoch).unwrap(),
                expected
            );
        }
    }
}
