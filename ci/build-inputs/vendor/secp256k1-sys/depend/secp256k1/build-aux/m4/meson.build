# Explicit archived file inputs; content checks consume every file.
local_inputs = [
  ['ci/build-inputs/vendor/secp256k1-sys/depend/secp256k1/build-aux/m4/meson.build', 'build-graph', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/build-aux/m4/bitcoin_secp.m4', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
