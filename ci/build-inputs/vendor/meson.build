# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['ci/build-inputs/vendor/meson.build', 'build-graph', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('regexml')
subdir('elements')
subdir('secp256k1')
subdir('secp256k1-sys')
subdir('secp256k1-zkp')
subdir('secp256k1-zkp-sys')
