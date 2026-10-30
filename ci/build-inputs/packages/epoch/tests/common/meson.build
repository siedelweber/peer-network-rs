# Shared public parameter fixture.
local_inputs = [
  ['ci/build-inputs/packages/epoch/tests/common/meson.build', 'build-graph', ''],
  ['packages/epoch/tests/common/mod.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,observation-runtime,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/epoch/tests/common/allocation.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,observation-runtime,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/epoch/tests/common/support.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,observation-runtime,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
