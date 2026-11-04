# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['vendor/secp256k1-zkp.patch', 'build-graph,wallet-conformance,hash-citations,linter,token', ''],
  ['vendor/secp256k1.patch', 'build-graph,wallet-conformance,hash-citations,linter,token', ''],
  ['vendor/elements.patch', 'build-graph,wallet-conformance,hash-citations,linter,token', ''],
  ['vendor/bitcoin.patch', 'build-graph,wallet-conformance,hash-citations,linter,token', ''],
  ['ci/build-inputs/vendor/meson.build', 'build-graph', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('regexml')
subdir('bitcoin')
subdir('elements')
subdir('secp256k1')
subdir('secp256k1-sys')
subdir('secp256k1-zkp')
subdir('secp256k1-zkp-sys')
