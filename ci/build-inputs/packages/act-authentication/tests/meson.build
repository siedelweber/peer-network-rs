# Explicit source inputs and consumers.
local_inputs = [
  ['ci/build-inputs/packages/act-authentication/tests/meson.build', 'build-graph', ''],
  ['packages/act-authentication/tests/public.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/act-authentication/tests/golden.json', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
