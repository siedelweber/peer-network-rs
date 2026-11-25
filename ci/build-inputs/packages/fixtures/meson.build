# Explicit source-root paths, consuming gate steps and generated-file producer.
crate_steps = 'protected-packages,fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,test-evidence,tests,benchmarks,observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing'
local_inputs = [
  ['ci/build-inputs/packages/fixtures/meson.build', 'build-graph', ''],
  ['packages/fixtures/Cargo.toml', 'vendor-set,' + crate_steps, ''],
  ['packages/fixtures/README.md', crate_steps, 'fixed-point-write'],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('src')
