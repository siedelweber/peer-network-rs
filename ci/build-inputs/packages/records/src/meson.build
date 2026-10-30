# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['ci/build-inputs/packages/records/src/meson.build', 'build-graph', ''],
  ['packages/records/src/burn.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/records/src/constants.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/records/src/lib.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/records/src/numerics.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/records/src/test_support.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/records/src/commitments.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
  ['packages/records/src/solve.rs', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,harness-registry,claim-evidence,observation-syntax,token,hash-citations,linter,suppressions,printing', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('test_support')
