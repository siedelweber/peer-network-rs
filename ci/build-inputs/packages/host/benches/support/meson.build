# Exact benchmark source paths and consumers.
local_inputs = [
  ['packages/host/benches/support/base.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/host/benches/support/control.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/host/benches/support/publication.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['ci/build-inputs/packages/host/benches/support/meson.build', 'build-graph', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
