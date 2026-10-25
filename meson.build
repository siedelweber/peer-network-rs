project('peer-network', meson_version: '>=1.12.1')

graph_files = []
graph_arguments = []
# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['.gitignore', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['Cargo.lock', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['Cargo.toml', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['LICENSE-CODE', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['LICENSE-DOCS', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['README.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['meson.build', 'build-graph', ''],
  ['rust-toolchain.toml', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['rustfmt.toml', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('ci')

# Skeleton report dependencies follow the existing serial entry. No step is delegated.
gate_steps = [
  ['build-graph', 'python3 -B ci/build_graph.py gate', ''],
  ['toolchain', 'python3 ci/discipline.py toolchain', 'build-graph'],
  ['discipline-tests', 'env FOUNDATION_COMPUTE_TESTS=1 python3 -B ci/run_ci.py test_discipline', 'toolchain'],
  ['harness-registry', 'python3 -B ci/harness.py', 'discipline-tests'],
  ['harness-tests', 'python3 -B ci/run_ci.py test_harness', 'harness-registry'],
  ['testkit-guard', 'python3 -B ci/testkit_guard.py', 'harness-tests'],
  ['testkit-tests', 'python3 -B ci/run_ci.py test_testkit', 'testkit-guard'],
  ['claim-tests', 'python3 -B ci/run_ci.py test_claims', 'testkit-tests'],
  ['linter-entry-tests', 'python3 -B ci/run_ci.py test_linter_entry', 'claim-tests'],
  ['observation-tests', 'python3 -B ci/run_ci.py test_observe', 'linter-entry-tests'],
  ['devperf-tests', 'python3 -B ci/run_ci.py test_devperf', 'observation-tests'],
  ['build-policy', 'python3 ci/discipline.py build-policy', 'devperf-tests'],
  ['cargo-config', 'python3 ci/discipline.py cargo-config', 'build-policy'],
  ['cargo-config-measurement', 'python3 -B ci/measure_rustflags.py', 'cargo-config'],
  ['vendor-set', 'python3 ci/discipline.py vendor-set', 'cargo-config-measurement'],
  ['member-lints', 'python3 ci/discipline.py members', 'vendor-set'],
  ['fmt', 'python3 ci/discipline.py fmt', 'member-lints'],
  ['clippy', 'python3 ci/discipline.py clippy', 'fmt'],
  ['nursery-advisory', 'python3 ci/discipline.py nursery', 'clippy'],
  ['host-postgresql-start', 'python3 -B ci/host_postgresql.py start --root "$PN_HOST_TEST_ROOT"', 'nursery-advisory'],
  ['wallet-elements-start', 'python3 -B ci/wallet_elements.py start --root "$PN_WALLET_TEST_ROOT"', 'host-postgresql-start'],
  ['tests', 'python3 -B ci/discipline.py tests', 'wallet-elements-start'],
  ['test-budgets', 'python3 -B ci/devperf.py --input .lane/performance-events.jsonl --findings .lane/performance-findings.jsonl', 'tests'],
  ['minimal', 'python3 ci/discipline.py minimal', 'test-budgets'],
  ['rustdoc', 'python3 ci/discipline.py rustdoc', 'minimal'],
  ['fixed-point-generate', 'cargo run -p documents --locked --profile gate -- generate', 'rustdoc'],
  ['fixed-point-write', 'cargo run -p documents --locked --profile gate -- write', 'fixed-point-generate'],
  ['fixed-point-clean', 'python3 ci/discipline.py tree-clean', 'fixed-point-write'],
  ['datasets', 'cargo run -p documents --locked --profile gate -- generate --check', 'fixed-point-clean'],
  ['documents', 'cargo run -p documents --locked --profile gate -- check', 'datasets'],
  ['determinism-datasets', 'cargo run -p documents --locked --profile gate -- generate --check', 'documents'],
  ['determinism-documents', 'cargo run -p documents --locked --profile gate -- check', 'determinism-datasets'],
  ['design-correspondence', 'python3 -B ci/design.py', 'determinism-documents'],
  ['design-tests', 'python3 -B ci/run_ci.py test_design', 'design-correspondence'],
  ['benchmarks', 'python3 -B ci/benchmarks.py', 'design-tests'],
  ['observation-build', 'cargo build --offline --locked --profile gate -p execwrap -p pn-records -p pn-graph --features pn-records/test-support --examples', 'benchmarks'],
  ['observation-runtime', 'python3 -B ci/run_ci.py test_observe_runtime', 'observation-build'],
  ['host-observation-build', 'python3 -B ci/host_evidence_build.py', 'observation-runtime'],
  ['host-observation-runtime', 'python3 -B ci/run_ci.py test_host_runtime', 'host-observation-build'],
  ['wallet-conformance', 'python3 -B ci/run_ci.py test_wallet_boundary', 'host-observation-runtime'],
  ['wallet-elements-stop', 'python3 -B ci/wallet_elements.py stop --root "$PN_WALLET_TEST_ROOT"', 'wallet-conformance'],
  ['host-postgresql-stop', 'python3 -B ci/host_postgresql.py stop --root "$PN_HOST_TEST_ROOT"', 'wallet-elements-stop'],
  ['observation-parser', 'python3 -B ci/run_ci.py test_observe_syntax', 'host-postgresql-stop'],
  ['observation-syntax', 'python3 -B ci/observe.py', 'observation-parser'],
  ['harness-matrix', 'python3 -B ci/harness.py --matrix', 'observation-syntax'],
  ['linter', '"$LINTER_BIN" check --root .', 'harness-matrix'],
  ['claim-evidence', 'python3 -B ci/claims.py --fail-respellings', 'linter'],
  ['token', 'python3 ci/discipline.py token', 'claim-evidence'],
  ['hash-citations', 'python3 -B ci/discipline.py hash-citations', 'token'],
  ['suppressions', 'python3 ci/discipline.py suppressions', 'hash-citations'],
  ['printing', 'python3 ci/discipline.py printing', 'suppressions'],
]
foreach step : gate_steps
  graph_arguments += ['--step', '\t'.join(step)]
endforeach


# Current-run artifact producers and consumers; logs are declared by every step.
gate_products = [
  ['.lane/gate-steps.tsv', 'entry', 'finalize'],
  ['.lane/gate-resource-start.raw', 'entry', 'finalize'],
  ['.lane/gate-resource-end.raw', 'entry', 'finalize'],
  ['.lane/performance-events.jsonl', 'tests', 'test-budgets,harness-matrix,claim-evidence'],
  ['.lane/harness-benchmarks.jsonl', 'benchmarks', 'harness-matrix,claim-evidence'],
  ['.lane/harness-matrix.json', 'harness-matrix', 'finalize'],
  ['.lane/claim-evidence.json', 'claim-evidence', 'finalize'],
  ['.lane/claim-gloss-review.json', 'claim-evidence', 'finalize'],
  ['.lane/host-test-binary.txt', 'host-observation-build', 'host-observation-runtime'],
  ['.lane/observation-syntax.json', 'observation-syntax', 'claim-evidence'],
  ['.lane/observation-coverage.json', 'observation-syntax', 'claim-evidence'],
  ['.lane/observation-registry-expanded.json', 'observation-syntax', 'claim-evidence'],
  ['.lane/harness-ci-test_discipline.jsonl', 'discipline-tests', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_harness.jsonl', 'harness-tests', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_testkit.jsonl', 'testkit-tests', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_claims.jsonl', 'claim-tests', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_linter_entry.jsonl', 'linter-entry-tests', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_observe.jsonl', 'observation-tests', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_devperf.jsonl', 'devperf-tests', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_design.jsonl', 'design-tests', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_observe_runtime.jsonl', 'observation-runtime', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_host_runtime.jsonl', 'host-observation-runtime', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_wallet_boundary.jsonl', 'wallet-conformance', 'harness-matrix,claim-evidence'],
  ['.lane/harness-ci-test_observe_syntax.jsonl', 'observation-parser', 'harness-matrix,claim-evidence'],
]
foreach product : gate_products
  graph_arguments += ['--product', '\t'.join(product)]
endforeach

# Tools remain external prerequisites; Cargo is never reimplemented here.
python = find_program('python3')
foreach tool : ['git', 'bash', 'ninja', 'cargo', 'rustc', 'rustfmt', 'cargo-clippy']
  find_program(tool, required: true)
endforeach
graph_reader = files('ci/build_graph.py')
graph_manifest = meson.project_build_root() / 'gate-graph.json'
run_command(python, graph_reader, 'configure', '--graph', graph_manifest,
  '--pattern', 'a^', graph_arguments, check: true)
custom_target('tracked-census',
  input: graph_files,
  output: 'tracked-census.json',
  command: [python, graph_reader, 'check', '--root', meson.project_source_root(),
    '--graph', graph_manifest, '--report', '@OUTPUT@'],
  build_always_stale: true,
  build_by_default: true,
  console: true,
)
