# The fixture's runtime construction, independent literals and private controls.
crate_steps = 'protected-packages,fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,test-evidence,tests,benchmarks,observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing'
local_inputs = [
  ['ci/build-inputs/packages/fixtures/src/meson.build', 'build-graph', ''],
  ['packages/fixtures/src/base.rs', crate_steps, ''],
  ['packages/fixtures/src/expected.rs', crate_steps, ''],
  ['packages/fixtures/src/lib.rs', crate_steps, ''],
  ['packages/fixtures/src/root.rs', crate_steps, ''],
  ['packages/fixtures/src/root_preimage.txt', crate_steps, ''],
  ['packages/fixtures/src/tests.rs', crate_steps, ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
