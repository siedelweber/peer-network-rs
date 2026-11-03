local_inputs = [
  ['ci/build-inputs/.cargo/meson.build', 'build-graph', ''],
  ['.cargo/config.toml', 'cargo-config,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,host-observation-runtime,wallet-conformance,observation-runtime,observation-parser,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,discipline-tests,design-tests,linter-entry-tests', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
