# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['docs/HTTP-NOTICES', 'member-lints,documents,hash-citations', ''],
  ['ci/build-inputs/docs/meson.build', 'build-graph', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('datasets')
subdir('design')
subdir('fragments')
subdir('inputs')
subdir('templates')
