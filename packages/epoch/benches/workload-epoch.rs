#[path = "support/receipt.rs"]
mod receipt;
pub use support::{pins, scalar::pins as graph_pins};
mod support;
use criterion::{BatchSize, Criterion, SamplingMode};
use inputs::Published;
use nrz_cas::limits::Limits;
use pn_epoch::{admission, conserved, fence, solve::bind_procedure};
use std::{
    fmt::Debug,
    hint::black_box,
    path::Path,
    time::{Duration, Instant},
};
use support as inputs;
type Bench<'a> = criterion::BenchmarkGroup<'a, criterion::measurement::WallTime>;

trait Accepted {
    fn work_fields(&self, _name: &str) -> String {
        "work_unavailable=internal-ledgers-not-exposed".into()
    }
    fn accepted(&self) -> bool;
}
impl Accepted for pn_epoch::compiler::CompiledState {
    fn accepted(&self) -> bool {
        true
    }
}
impl Accepted for conserved::bounded::records::SolveRecord {
    fn work_fields(&self, name: &str) -> String {
        if name.starts_with("B7-") {
            format!("work={} replay_work={}", self.work, self.work)
        } else {
            format!(
                "work={} solve_work={} replay_work={}",
                self.work.checked_add(self.replay_work).unwrap(),
                self.work,
                self.replay_work
            )
        }
    }
    fn accepted(&self) -> bool {
        true
    }
}
impl Accepted for conserved::bounded::Record {
    fn accepted(&self) -> bool {
        true
    }
    fn work_fields(&self, name: &str) -> String {
        let a = if name.starts_with("B7-") {
            &self.mandatory_replay
        } else {
            &self.production
        };
        format!(
            "{} setup_work={} map_work={} final_check_work={} driver_work={} procedure_revision=bounded-activation-v3",
            self.solve.work_fields(name),
            a.setup,
            a.map_passes.iter().sum::<u64>(),
            a.final_checks.iter().sum::<u64>(),
            a.driver_work
        )
    }
}
impl Accepted for pn_epoch::fence::Search {
    fn work_fields(&self, _name: &str) -> String {
        format!(
            "primitive_work={} work_unavailable=preparation-ledger-not-exposed",
            self.evidence.primitives.iter().map(|p| p.evidence.work).sum::<u64>()
        )
    }
    fn accepted(&self) -> bool {
        self.selected.is_some() && self.operational_stop.is_none()
    }
}
impl Accepted for pn_epoch::package::AdmittedBoundary {
    fn accepted(&self) -> bool {
        true
    }
}
impl Accepted for Vec<pn_epoch::package::AdmittedBoundary> {
    fn accepted(&self) -> bool {
        true
    }
}
impl Accepted for pn_graph::numeric::ridge::CheckedRidge {
    fn work_fields(&self, _name: &str) -> String {
        format!("work={} replay_work={}", self.replay_work(), self.replay_work())
    }
    fn accepted(&self) -> bool {
        self.image().is_some()
    }
}
impl Accepted for pn_records::controller::Record {
    fn accepted(&self) -> bool {
        self.verdict == pn_records::controller::Verdict::Delivered
    }
}
impl Accepted for (pn_records::controller::Record, u64) {
    fn accepted(&self) -> bool {
        self.0.verdict == pn_records::controller::Verdict::Delivered
    }
    fn work_fields(&self, _name: &str) -> String {
        format!("work={} replay_work={}", self.1, self.1)
    }
}
fn own_ticks() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let fields: Vec<_> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    fields
        .get(11)?
        .parse::<u64>()
        .ok()?
        .checked_add(fields.get(12)?.parse::<u64>().ok()?)
}

struct Measurement<T, E>(Result<T, E>);

fn selected(name: &str) -> bool {
    receipt::internal() == name
}

fn measure<S, T: Debug + Accepted, E: Debug>(
    c: &mut Bench<'_>,
    output: &Path,
    mode: &str,
    name: &str,
    metadata: &str,
    mut setup: impl FnMut() -> S,
    mut run: impl FnMut(S) -> Result<T, E>,
) -> Measurement<T, E> {
    let begin = Instant::now();
    let input = setup();
    let setup_time = begin.elapsed();
    let cpu_start = own_ticks();
    let start = Instant::now();
    let expected = run(input);
    let operation = start.elapsed();
    let cpu = own_ticks().zip(cpu_start).map(|(after, before)| after - before);
    let accepted = expected.as_ref().is_ok_and(Accepted::accepted);
    let signature = format!("{expected:?}");
    let work = expected
        .as_ref()
        .map_or_else(|_| "work_unavailable=no-completed-operation".into(), |r| r.work_fields(name));
    std::fs::write(
        output.join(format!("{name}.txt")),
        format!(
            "{work} {metadata} fresh_setup_s={} pilot_operation_s={} outcome={} own_cpu_ticks={cpu:?} diagnostic_bytes={}\n{signature}\n",
            setup_time.as_secs_f64(),
            operation.as_secs_f64(),
            if accepted { "PASS" } else { "REFUSED_OR_INDECISIVE" },
            signature.len()
        ),
    )
    .unwrap();
    if accepted && mode != "pilot" {
        c.bench_function(receipt::name(), |b| {
            b.iter_batched(
                &mut setup,
                |input| drop(black_box(run(black_box(input)).expect("accepted workload changed verdict"))),
                BatchSize::SmallInput,
            );
        });
    }
    let again = run(setup());
    assert_eq!(format!("{again:?}"), signature);
    Measurement(expected)
}
fn main() {
    let output = std::path::PathBuf::from(std::env::var_os("PN_BENCH_OUTPUT").expect("owned benchmark output directory"));
    std::fs::create_dir_all(&output).unwrap();
    let mode = std::env::var("PN_BENCH_MODE").unwrap();
    assert!(["full", "pilot"].contains(&mode.as_str()), "epoch has no smoke solve");
    let seed = inputs::SEED;
    let mut c = Criterion::default()
        .output_directory(&output)
        .sample_size(10)
        .nresamples(1000)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_secs(1))
        .configure_from_args();
    let mut group = c.benchmark_group("workload-epoch");
    group.sampling_mode(SamplingMode::Flat);
    compact_actors(&mut group, &output, &mode, seed);
    actors(&mut group, &output, &mode, seed);
    acts(&mut group, &output, &mode, seed);
    fences(&mut group, &output, &mode, seed);
    admissions(&mut group, &output, &mode, seed);
    trials(&mut group, &output, &mode, seed);
    scalars(&mut group, &output, &mode, seed);
    group.finish();
    c.final_summary();
    receipt::finish(&output, &mode);
}

fn append_metadata(output: &std::path::Path, name: &str, metadata: &str) {
    use std::io::Write;
    let mut artifact = std::fs::OpenOptions::new()
        .append(true)
        .open(output.join(format!("{name}.txt")))
        .unwrap();
    writeln!(artifact, "{metadata}").unwrap();
}

fn actors(group: &mut Bench<'_>, output: &std::path::Path, mode: &str, seed: u64) {
    let ns = vec![2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256];
    for n in ns {
        for shape in ["ring", "dense"] {
            let names = [format!("B3-compile-n{n}-{shape}")];
            if !names.iter().any(|n| selected(n)) {
                continue;
            }
            let start = Instant::now();
            let input = inputs::candidate(seed, n, None, shape, "pass");
            let state = match inputs::compile(&input) {
                Ok(state) => state,
                Err(error) => {
                    for name in &names {
                        if selected(name) {
                            std::fs::write(output.join(format!("{name}.txt")), format!("recipe=scaling-workloads/v2 seed={seed} N={n} outcome=REFUSED phase=construction refusal={error:?} setup_s={}\n", start.elapsed().as_secs_f64())).unwrap();
                        }
                    }
                    continue;
                }
            };
            inputs::check_compilation(&input, &state);
            let metadata = format!(
                "recipe=scaling-workloads/v2 seed={seed} {} construction_s={}",
                inputs::dimensions(&input, &state),
                start.elapsed().as_secs_f64()
            );
            if selected(&names[0]) {
                measure(group, output, mode, &names[0], &metadata, inputs::numeric, |mut numeric| {
                    pn_epoch::compiler::compile_candidate(
                        &input.context,
                        &input.approval,
                        &mut numeric,
                        Limits::default(),
                        inputs::PRODUCTS,
                    )
                    .map_err(Box::new)
                });
            }
        }
    }
}

fn check_compact(bound: &pn_epoch::solve::compact::BoundProcedure<'_>, record: &conserved::bounded::Record) {
    let checked = conserved::bounded::replay(activation_plan(), bound, record).unwrap();
    assert_eq!(
        checked.solve.rounds.last().unwrap().standing,
        record.solve.rounds.last().unwrap().standing
    );
}

fn compact_actors(group: &mut Bench<'_>, output: &std::path::Path, mode: &str, seed: u64) {
    let ns = vec![2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256];
    for n in ns {
        for shape in ["ring", "dense"] {
            let names = [
                format!("unused-compact-n{n}-{shape}"),
                format!("B6-solve-n{n}-{shape}"),
                format!("B7-replay-n{n}-{shape}"),
            ];
            if !names.iter().any(|n| selected(n)) {
                continue;
            }
            let start = Instant::now();
            let input = inputs::candidate(seed, n, None, shape, "pass");
            let state = match pn_epoch::compiler::compact::compile_candidate(
                &input.context,
                &input.approval,
                &mut inputs::numeric(),
                Limits::default(),
                inputs::PRODUCTS,
            ) {
                Ok(state) => state,
                Err(error) => {
                    for name in &names {
                        if selected(name) {
                            std::fs::write(output.join(format!("{name}.txt")), format!("recipe=scaling-workloads/v2 seed={seed} N={n} outcome=REFUSED phase=construction refusal={error:?} setup_s={}\n", start.elapsed().as_secs_f64())).unwrap();
                        }
                    }
                    continue;
                }
            };
            assert_eq!(state.view().ledger.counts.len(), input.n);
            assert_eq!(state.view().ledger.debits.len(), input.m);
            let p = inputs::compact_scaling_procedure(&state, 16);
            let published = Published(p.clone());
            let bound = pn_epoch::solve::compact::bind_procedure(&state, p.clone(), &published, Limits::default()).unwrap();
            let metadata = compact_metadata(&input, &state, &p, seed, start.elapsed().as_secs_f64());
            if selected(&names[1]) || selected(&names[2]) {
                let accepted = fence::compact::search(&bound, None).unwrap();
                let produced = if selected(&names[1]) {
                    measure(
                        group,
                        output,
                        mode,
                        &names[1],
                        &metadata,
                        || (),
                        |()| conserved::bounded::solve(activation_plan(), &bound, &accepted).map_err(Box::new),
                    )
                } else {
                    Measurement(conserved::bounded::solve(activation_plan(), &bound, &accepted).map_err(Box::new))
                };
                // B7 consumes this exact B6 API result, never an independently generated case.
                match produced.0 {
                    Ok(record) => {
                        check_compact(&bound, &record);
                        let metadata = format!(
                            "{metadata} M_solve={} M_replay={} {}",
                            input.m,
                            input.m,
                            inputs::bounded_counters(&record.solve)
                        );
                        if selected(&names[1]) {
                            append_metadata(output, &names[1], &metadata);
                        }
                        if selected(&names[2]) {
                            measure(
                                group,
                                output,
                                mode,
                                &names[2],
                                &metadata,
                                || (),
                                |()| conserved::bounded::replay(activation_plan(), &bound, &record).map_err(Box::new),
                            );
                        }
                    }
                    Err(error) => {
                        if selected(&names[2]) {
                            std::fs::write(
                                output.join(format!("{}.txt", names[2])),
                                format!("{metadata} outcome=REFUSED producer={error:?}\n"),
                            )
                            .unwrap();
                        }
                    }
                }
            }
        }
    }
}

fn acts(group: &mut Bench<'_>, output: &std::path::Path, mode: &str, seed: u64) {
    for m in [8, 16, 32, 64, 128, 256, 512, 1024] {
        for shape in ["parallel", "mixed"] {
            let name = format!("B3-compile-m{m}-{shape}");
            if !selected(&name) {
                continue;
            }
            let start = Instant::now();
            let input = inputs::candidate(seed, 4, Some(m), shape, "pass");
            let state = match inputs::compile(&input) {
                Ok(state) => state,
                Err(error) => {
                    std::fs::write(output.join(format!("{name}.txt")), format!("recipe=scaling-workloads/v2 seed={seed} M={m} outcome=REFUSED phase=construction refusal={error:?} setup_s={}\n", start.elapsed().as_secs_f64())).unwrap();
                    continue;
                }
            };
            inputs::check_compilation(&input, &state);
            let metadata = format!(
                "recipe=scaling-workloads/v2 seed={seed} {} construction_s={}",
                inputs::dimensions(&input, &state),
                start.elapsed().as_secs_f64()
            );
            measure(group, output, mode, &name, &metadata, inputs::numeric, |mut numeric| {
                pn_epoch::compiler::compile_candidate(
                    &input.context,
                    &input.approval,
                    &mut numeric,
                    Limits::default(),
                    inputs::PRODUCTS,
                )
                .map_err(Box::new)
            });
        }
    }
}

fn fences(group: &mut Bench<'_>, output: &std::path::Path, mode: &str, seed: u64) {
    for bits in [8, 16] {
        for shape in ["equal", "late", "limited"] {
            let name = format!("B5-fence-{shape}-bits{bits}");
            if !selected(&name) {
                continue;
            }
            let input = inputs::candidate(seed, 2, None, "ring", if shape == "limited" { "late" } else { shape });
            let state = inputs::compile(&input).unwrap();
            let mut p = inputs::procedure(&state, bits);
            if shape == "limited" {
                p.maximum_work = 100_000;
                p.enclosure.as_mut().unwrap().operation.work = 100_000;
            }
            let published = Published(p.clone());
            let bound = bind_procedure(&state, p.clone(), &published, Limits::default()).unwrap();
            let metadata = format!(
                "recipe=scaling-workloads/v2 seed={seed} {} procedure={p:?} {}",
                inputs::dimensions(&input, &state),
                limits(&p)
            );
            measure(group, output, mode, &name, &metadata, || (), |()| fence::search(&bound, None));
        }
    }
}

fn admissions(group: &mut Bench<'_>, output: &std::path::Path, mode: &str, seed: u64) {
    for m in [4, 8, 16, 32, 64, 128, 256, 512] {
        for outcome in ["pass", "own", "individual", "policy"] {
            let name = format!("B8-admit-m{m}-{outcome}");
            if !selected(&name) {
                continue;
            }
            let input = inputs::candidate(seed, 2, Some(m), "self", outcome);
            let control = inputs::candidate(seed, 2, Some(m), "self", "pass");
            let state = inputs::compile(&control).unwrap();
            let p = inputs::procedure(&state, 8);
            let plan = admission::FinalProcedure {
                solve: p.clone(),
                arithmetic: Limits::default(),
                maximum_products: inputs::PRODUCTS,
            };
            let schedule = inputs::schedule(&input, if outcome == "policy" { "1000" } else { "2" });
            let published = Published(p);
            let metadata = format!(
                "recipe=scaling-workloads/v2 seed={seed} M={m} N=2 S=1 intended={outcome} plan={plan:?} {}",
                limits(&plan.solve)
            );
            measure(group, output, mode, &name, &metadata, inputs::numeric, |numeric| {
                admission::admit(&input.context, &schedule, &plan, &input.approval, &published, numeric)
            });
        }
    }
}

fn trials(group: &mut Bench<'_>, output: &std::path::Path, mode: &str, seed: u64) {
    for s in [1, 2, 4, 8, 16, 32, 64, 128] {
        let name = format!("B9-trials-s{s}");
        if !selected(&name) {
            continue;
        }
        let cases: Vec<_> = (0..s)
            .map(|i| inputs::candidate(seed + i, 2, Some(4), "trials", "pass"))
            .collect();
        let plans: Vec<_> = cases
            .iter()
            .map(|c| admission::FinalProcedure {
                solve: inputs::procedure(&inputs::compile(c).unwrap(), 8),
                arithmetic: Limits::default(),
                maximum_products: inputs::PRODUCTS,
            })
            .collect();
        let schedules: Vec<_> = cases.iter().map(|c| inputs::schedule(c, "2")).collect();
        let metadata = format!("recipe=scaling-workloads/v2 seed={seed} M=4 S={s} boundary_search=stand-in-no-live-scheduler");
        measure(
            group,
            output,
            mode,
            &name,
            &metadata,
            || cases.iter().map(|_| inputs::numeric()).collect::<Vec<_>>(),
            |numeric| {
                cases
                    .iter()
                    .zip(&plans)
                    .zip(&schedules)
                    .zip(numeric)
                    .map(|(((input, plan), schedule), numeric)| {
                        admission::admit(
                            &input.context,
                            schedule,
                            plan,
                            &input.approval,
                            &Published(plan.solve.clone()),
                            numeric,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            },
        );
    }
}

fn scalars(group: &mut Bench<'_>, output: &std::path::Path, mode: &str, seed: u64) {
    for cap in [1, 2, 4, 5, 6, 8, 12, 16] {
        for route in ["rational", "ridge"] {
            let name = format!("B10-{route}-cap{cap}");
            if !selected(&name) {
                continue;
            }
            let input = inputs::candidate(seed, 2, None, "ring", "equal");
            let state = inputs::compile(&input).unwrap();
            let p = inputs::procedure(&state, 16);
            inputs::scalar::check(&p);
            let metadata = format!("recipe=scaling-workloads/v2 seed={seed} route={route} cap={cap}");
            if route == "ridge" {
                let (p, i, r) = inputs::scalar::ridge(&p, cap);
                measure(
                    group,
                    output,
                    mode,
                    &name,
                    &format!(
                        "{metadata} work={} queries={} cells={} image={:?}",
                        r.work,
                        r.queries.len(),
                        r.cells.len(),
                        r.image
                    ),
                    || (),
                    |()| pn_graph::numeric::ridge::replay(&p, &i, &r),
                );
            } else {
                let started = Instant::now();
                let p = inputs::scalar::rational_procedure(&p);
                let produced = inputs::scalar::rational(&p, u64::from(cap));
                let (i, r) = match produced {
                    Ok(pair) => pair,
                    Err(error) => {
                        std::fs::write(
                            output.join(format!("{name}.txt")),
                            format!(
                                "{metadata} outcome=REFUSED phase=transcript-construction wall_s={} refusal={error:?}\n",
                                started.elapsed().as_secs_f64()
                            ),
                        )
                        .unwrap();
                        continue;
                    }
                };
                measure(
                    group,
                    output,
                    mode,
                    &name,
                    &format!("{metadata} verdict={:?} attempts={}", r.verdict, r.attempts.len()),
                    || (),
                    |()| pn_graph::numeric::controller::replay_with_work(&p, &i, None, &r),
                );
            }
        }
    }
}

fn limits(p: &pn_records::solve::Procedure) -> String {
    format!(
        "maximum_work={} maximum_solve_work={} maximum_replay_work={} maximum_iterations={} declared_precision={:?}",
        p.maximum_work, p.maximum_solve_work, p.maximum_replay_work, p.maximum_iterations, p.precision
    )
}

fn compact_metadata(
    input: &inputs::Candidate,
    state: &pn_epoch::compiler::compact::CompiledState,
    p: &pn_records::solve::Procedure,
    seed: u64,
    construction_s: f64,
) -> String {
    format!(
        "recipe=scaling-workloads/v2 seed={seed} {} construction_s={} procedure={p:?} activation_plan={:?} {}",
        format_args!(
            "N={} M={} Z={} H={} cells={} products={} S=1",
            input.n,
            input.m,
            state
                .view()
                .base
                .rows
                .values()
                .map(std::collections::BTreeMap::len)
                .sum::<usize>(),
            state.view().support.depth,
            state.view().cells.len(),
            state.view().support.support_visits
        ),
        construction_s,
        activation_plan(),
        limits(p)
    )
}

// Explicit fixture option selected from the kernel-3 scalar pilot; not a deployment default.
fn activation_plan() -> conserved::bounded::Plan {
    conserved::bounded::Plan { working_precision: 32 }
}
