# Explicit archived file inputs; content checks consume every file.
local_inputs = [
  ['ci/build-inputs/vendor/secp256k1-zkp-sys/depend/secp256k1/src/modules/meson.build', 'build-graph', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('bppp')
subdir('ecdh')
subdir('ecdsa_adaptor')
subdir('ecdsa_s2c')
subdir('ellswift')
subdir('extrakeys')
subdir('generator')
subdir('musig')
subdir('rangeproof')
subdir('recovery')
subdir('schnorrsig')
subdir('schnorrsig_halfagg')
subdir('surjection')
subdir('whitelist')
