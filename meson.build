project('peer-network', meson_version: '>=1.12.1')

graph_files = []
graph_arguments = []
# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['clippy.toml', 'clippy,nursery-advisory,suppressions,discipline-tests', ''],
  ['.gitignore', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,test-build,extended-tests,reference-certificates,service-tests,test-evidence,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['Cargo.lock', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,test-build,extended-tests,reference-certificates,service-tests,test-evidence,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['Cargo.toml', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,test-build,extended-tests,reference-certificates,service-tests,test-evidence,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['LICENSE-CODE', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,test-build,extended-tests,reference-certificates,service-tests,test-evidence,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['LICENSE-DOCS', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,test-build,extended-tests,reference-certificates,service-tests,test-evidence,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['README.md', 'build-graph,linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['meson.build', 'build-graph', ''],
  ['rust-toolchain.toml', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,test-build,extended-tests,reference-certificates,service-tests,test-evidence,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
  ['rustfmt.toml', 'build-graph,toolchain,discipline-tests,harness-registry,harness-tests,testkit-guard,testkit-tests,claim-tests,linter-entry-tests,observation-tests,devperf-tests,build-policy,cargo-config,cargo-config-measurement,vendor-set,member-lints,fmt,clippy,nursery-advisory,host-postgresql-start,wallet-elements-start,test-build,extended-tests,reference-certificates,service-tests,test-evidence,tests,test-budgets,minimal,rustdoc,fixed-point-generate,fixed-point-write,fixed-point-clean,datasets,documents,determinism-datasets,determinism-documents,design-correspondence,design-tests,benchmarks,observation-build,observation-runtime,host-observation-build,host-observation-runtime,wallet-conformance,wallet-elements-stop,host-postgresql-stop,observation-parser,observation-syntax,harness-matrix,linter,claim-evidence,token,hash-citations,suppressions,printing,entry,finalize', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('ci')

# Single command declaration and completion dependencies for both execution routes.
gate_steps = [
  ['build-graph', 'python3 -B ci/build_graph.py gate', ''],
  ['fixed-point-generate', 'python3 -B ci/isolation.py generate', 'build-graph'],
  ['fixed-point-write', 'python3 -B ci/isolation.py write', 'fixed-point-generate'],
  ['fixed-point-clean', 'python3 ci/discipline.py tree-clean', 'fixed-point-write'],
  ['test-build', 'python3 -B ci/run_tests.py prepare', 'fixed-point-clean'],
  ['host-postgresql-start', 'python3 -B ci/host_postgresql.py start --root "$PN_HOST_TEST_ROOT"', 'test-build'],
  ['wallet-elements-start', 'python3 -B ci/wallet_elements.py start --root "$PN_WALLET_TEST_ROOT"', 'host-postgresql-start'],
  ['toolchain', 'python3 ci/discipline.py toolchain', 'wallet-elements-start'],
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
  ['vendor-set', 'python3 ci/discipline.py vendor-set', 'cargo-config'],
  ['member-lints', 'python3 ci/discipline.py members', 'vendor-set'],
  ['design-correspondence', 'python3 -B ci/design.py', 'member-lints'],
  ['design-tests', 'python3 -B ci/run_ci.py test_design', 'design-correspondence'],
  ['linter', '"$LINTER_BIN" check --root .', 'design-tests'],
  ['token', 'python3 ci/discipline.py token', 'linter'],
  ['hash-citations', 'python3 -B ci/discipline.py hash-citations', 'token'],
  ['suppressions', 'python3 ci/discipline.py suppressions', 'hash-citations'],
  ['printing', 'python3 ci/discipline.py printing', 'suppressions'],
  ['tests', 'python3 -B ci/discipline.py tests', 'printing'],
  ['extended-tests', 'python3 -B ci/run_tests.py extended', 'tests'],
  ['reference-certificates', 'python3 -B ci/run_tests.py reference-certificate', 'extended-tests'],
  ['service-tests', 'python3 -B ci/run_tests.py service', 'reference-certificates'],
  ['wallet-conformance', 'python3 -B ci/run_ci.py test_wallet_boundary', 'service-tests'],
  ['test-evidence', 'python3 -B ci/run_tests.py merge', 'wallet-conformance'],
  ['cargo-config-measurement', 'python3 -B ci/measure_rustflags.py', 'test-evidence'],
  ['wallet-elements-stop', 'python3 -B ci/wallet_elements.py stop-report --root "$PN_WALLET_TEST_ROOT"', 'cargo-config-measurement'],
  ['fmt', 'python3 ci/discipline.py fmt', 'wallet-elements-stop'],
  ['test-budgets', 'python3 -B ci/devperf.py --input .lane/performance-events.jsonl --findings .lane/performance-findings.jsonl', 'fmt'],
  ['clippy', 'python3 ci/discipline.py clippy', 'test-budgets'],
  ['nursery-advisory', 'python3 ci/discipline.py nursery', 'clippy'],
  ['minimal', 'python3 ci/discipline.py minimal', 'nursery-advisory'],
  ['rustdoc', 'python3 ci/discipline.py rustdoc', 'minimal'],
  ['datasets', 'python3 -B ci/precheck.py --run-checker documents -- generate --check', 'rustdoc'],
  ['documents', 'python3 -B ci/precheck.py --run-checker documents -- check', 'datasets'],
  ['determinism-datasets', 'python3 -B ci/precheck.py --run-checker documents -- generate --check', 'documents'],
  ['determinism-documents', 'python3 -B ci/precheck.py --run-checker documents -- check', 'determinism-datasets'],
  ['benchmarks', 'python3 -B ci/benchmarks.py', 'determinism-documents'],
  ['observation-build', 'cargo build --offline --locked --profile gate -p execwrap -p pn-records -p pn-graph -p pn-epoch --features pn-records/test-support --examples', 'benchmarks'],
  ['observation-runtime', 'python3 -B ci/run_ci.py test_observe_runtime', 'observation-build'],
  ['host-observation-build', 'python3 -B ci/host_evidence_build.py', 'observation-runtime'],
  ['host-observation-runtime', 'python3 -B ci/run_ci.py test_host_runtime', 'host-observation-build'],
  ['observation-parser', 'python3 -B ci/run_ci.py test_observe_syntax', 'host-observation-runtime'],
  ['host-postgresql-stop', 'python3 -B ci/host_postgresql.py stop --root "$PN_HOST_TEST_ROOT"', 'observation-parser'],
  ['observation-syntax', 'python3 -B ci/observe.py', 'host-postgresql-stop'],
  ['harness-matrix', 'python3 -B ci/harness.py --matrix', 'observation-syntax'],
  ['claim-evidence', 'python3 -B ci/claims.py --fail-respellings', 'harness-matrix'],
]
# Members of an exclusive class must be totally ordered by completion edges.
gate_resource_classes = {
  'shared-cargo': ['test-build', 'tests', 'cargo-config-measurement', 'fmt', 'clippy', 'nursery-advisory', 'minimal', 'rustdoc', 'datasets', 'documents', 'determinism-datasets', 'determinism-documents', 'benchmarks', 'observation-build', 'host-observation-build', 'observation-syntax'],
}
gate_dependencies = {
  'build-graph': [],
  'fixed-point-generate': ['build-graph'],
  'fixed-point-write': ['fixed-point-generate'],
  'fixed-point-clean': ['fixed-point-write'],
  'test-build': ['fixed-point-clean'],
  'host-postgresql-start': ['fixed-point-clean'],
  'wallet-elements-start': ['fixed-point-clean'],
  'toolchain': ['fixed-point-clean'],
  'discipline-tests': ['fixed-point-clean'],
  'harness-registry': ['fixed-point-clean'],
  'harness-tests': ['fixed-point-clean'],
  'testkit-guard': ['fixed-point-clean'],
  'testkit-tests': ['fixed-point-clean'],
  'claim-tests': ['fixed-point-clean'],
  'linter-entry-tests': ['fixed-point-clean'],
  'observation-tests': ['fixed-point-clean'],
  'devperf-tests': ['fixed-point-clean'],
  'build-policy': ['fixed-point-clean'],
  'cargo-config': ['fixed-point-clean'],
  'vendor-set': ['fixed-point-clean'],
  'member-lints': ['fixed-point-clean'],
  'design-correspondence': ['fixed-point-clean'],
  'design-tests': ['fixed-point-clean'],
  'linter': ['fixed-point-clean'],
  'token': ['fixed-point-clean'],
  'hash-citations': ['fixed-point-clean'],
  'suppressions': ['fixed-point-clean'],
  'printing': ['fixed-point-clean'],
  'tests': ['test-build'],
  'extended-tests': ['test-build'],
  'reference-certificates': ['test-build'],
  'service-tests': ['test-build', 'host-postgresql-start', 'wallet-elements-start'],
  'wallet-conformance': ['wallet-elements-start'],
  'test-evidence': ['tests', 'reference-certificates', 'service-tests', 'extended-tests'],
  'cargo-config-measurement': ['fixed-point-clean', 'tests'],
  'wallet-elements-stop': ['wallet-conformance', 'service-tests', 'linter-entry-tests'],
  'fmt': ['fixed-point-clean', 'cargo-config-measurement'],
  'test-budgets': ['test-evidence'],
  'clippy': ['fixed-point-clean', 'fmt'],
  'nursery-advisory': ['fixed-point-clean', 'clippy'],
  'minimal': ['fixed-point-clean', 'nursery-advisory'],
  'rustdoc': ['fixed-point-clean', 'minimal'],
  'datasets': ['fixed-point-clean', 'rustdoc'],
  'documents': ['fixed-point-clean', 'datasets'],
  'determinism-datasets': ['fixed-point-clean', 'documents'],
  'determinism-documents': ['fixed-point-clean', 'determinism-datasets'],
  'benchmarks': ['fixed-point-clean', 'determinism-documents'],
  'observation-build': ['fixed-point-clean', 'benchmarks'],
  'observation-runtime': ['observation-build'],
  'host-observation-build': ['fixed-point-clean', 'observation-build'],
  'host-observation-runtime': ['host-observation-build', 'host-postgresql-start', 'service-tests'],
  'observation-parser': ['fixed-point-clean', 'host-observation-build'],
  'host-postgresql-stop': ['host-observation-runtime', 'service-tests', 'linter-entry-tests'],
  'observation-syntax': ['observation-parser', 'observation-runtime', 'host-observation-runtime', 'service-tests', 'tests'],
  'harness-matrix': ['test-evidence', 'benchmarks', 'discipline-tests', 'harness-tests', 'testkit-tests', 'claim-tests', 'linter-entry-tests', 'observation-tests', 'devperf-tests', 'design-tests', 'observation-runtime', 'host-observation-runtime', 'wallet-conformance', 'observation-parser'],
  'claim-evidence': ['harness-matrix', 'linter', 'observation-syntax', 'design-correspondence', 'test-budgets'],
}
foreach step : gate_steps
  graph_arguments += ['--step', '\t'.join(step)]
endforeach


# Current-run artifact producers and consumers; logs are declared by every step.
gate_products = [
  ['.lane/gate-steps.tsv', 'entry', 'finalize'],
  ['.lane/gate-resource-start.raw', 'entry', 'finalize'],
  ['.lane/gate-resource-end.raw', 'entry', 'finalize'],
  ['.lane/performance-events.jsonl', 'test-evidence', 'test-budgets,harness-matrix,claim-evidence'],
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
  ['.lane/tier-tests/manifest.json', 'test-build', 'tests,extended-tests,reference-certificates,service-tests,test-evidence'],
  ['.lane/tier-tests/fast.result.json', 'tests', 'test-evidence'],
  ['.lane/tier-tests/extended.result.json', 'extended-tests', 'test-evidence'],
  ['.lane/tier-tests/reference-certificate.result.json', 'reference-certificates', 'test-evidence'],
  ['.lane/tier-tests/service.result.json', 'service-tests', 'test-evidence'],
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
  '--pattern', 'a^', '--root', meson.project_source_root(), graph_arguments, check: true)
custom_target('tracked-census',
  input: graph_files,
  output: 'tracked-census.json',
  command: [python, graph_reader, 'check', '--root', meson.project_source_root(),
    '--graph', graph_manifest, '--report', '@OUTPUT@'],
  build_always_stale: true,
  build_by_default: true,
  console: true,
)
