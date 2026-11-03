# Exact defining-ridge charge boundary consumers.
local_inputs = [
  ['packages/epoch/tests/solve/admission/ridge_charge.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,test-build,reference-certificates,service-tests,test-evidence,benchmarks,observation-build,observation-runtime,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['ci/build-inputs/packages/epoch/tests/solve/admission/meson.build', 'build-graph', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
