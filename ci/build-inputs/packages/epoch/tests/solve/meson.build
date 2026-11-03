# Certified partition comparison witnesses.
local_inputs = [
  ['ci/build-inputs/packages/epoch/tests/solve/meson.build', 'build-graph', ''],
  ['packages/epoch/tests/solve/partitions.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,test-build,reference-certificates,service-tests,test-evidence,benchmarks,observation-build,observation-runtime,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/epoch/tests/solve/controller.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,test-build,reference-certificates,service-tests,test-evidence,benchmarks,observation-build,observation-runtime,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/epoch/tests/solve/replay_work.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,test-build,reference-certificates,service-tests,test-evidence,benchmarks,observation-build,observation-runtime,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/epoch/tests/solve/schedules.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,test-build,reference-certificates,service-tests,test-evidence,benchmarks,observation-build,observation-runtime,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/epoch/tests/solve/admission.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,test-build,reference-certificates,service-tests,test-evidence,benchmarks,observation-build,observation-runtime,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('admission')
