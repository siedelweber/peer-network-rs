# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['ci/build-inputs/vendor/regexml/src/snapshots/meson.build', 'build-graph', ''],
  ['vendor/regexml/src/snapshots/regexml__re_compiler__tests__compile_a_star.snap', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/regexml/src/snapshots/regexml__re_compiler__tests__compile_combined.snap', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/regexml/src/snapshots/regexml__re_compiler__tests__simple_compile.snap', 'fmt,clippy,nursery-advisory,minimal,rustdoc,tests,benchmarks,observation-build,host-observation-build,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
