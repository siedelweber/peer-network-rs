# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['docs/design/workload-benchmarks.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['ci/build-inputs/docs/design/meson.build', 'build-graph', ''],
  ['docs/design/concept.md', 'build-graph,linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['docs/design/implementation.md', 'build-graph,linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['docs/design/inventory.md', 'build-graph,linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['docs/design/progress.md', 'build-graph,linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['docs/design/questions.md', 'build-graph,linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
