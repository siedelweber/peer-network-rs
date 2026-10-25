# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['.linter/environments.toml', 'linter,build-graph,claim-evidence', ''],
  ['.linter/lists.toml', 'linter,build-graph,claim-evidence', ''],
  ['.linter/owners.toml', 'linter,build-graph,claim-evidence', ''],
  ['.linter/policies.toml', 'linter,build-graph,claim-evidence', ''],
  ['.linter/shape.toml', 'linter,build-graph,claim-evidence', ''],
  ['ci/build-inputs/.linter/meson.build', 'build-graph', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
