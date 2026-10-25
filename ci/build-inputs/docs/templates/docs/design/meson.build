# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['ci/build-inputs/docs/templates/docs/design/meson.build', 'build-graph', ''],
  ['docs/templates/docs/design/concept.md.j2', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', ''],
  ['docs/templates/docs/design/implementation.md.j2', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', ''],
  ['docs/templates/docs/design/inventory.md.j2', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', ''],
  ['docs/templates/docs/design/questions.md.j2', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
