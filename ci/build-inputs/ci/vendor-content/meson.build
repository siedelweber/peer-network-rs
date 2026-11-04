# Explicit archived file inputs; content checks consume every file.
local_inputs = [
  ['ci/vendor-content/bitcoin.json', 'wallet-conformance,hash-citations,vendor-set', ''],
  ['ci/build-inputs/ci/vendor-content/meson.build', 'build-graph', ''],
  ['ci/vendor-content/elements.json', 'wallet-conformance,hash-citations,vendor-set', ''],
  ['ci/vendor-content/secp256k1-sys.json', 'wallet-conformance,hash-citations,vendor-set', ''],
  ['ci/vendor-content/secp256k1-zkp-sys.json', 'wallet-conformance,hash-citations,vendor-set', ''],
  ['ci/vendor-content/secp256k1-zkp.json', 'wallet-conformance,hash-citations,vendor-set', ''],
  ['ci/vendor-content/secp256k1.json', 'wallet-conformance,hash-citations,vendor-set', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
