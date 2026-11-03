# Explicit archived file inputs; content checks consume every file.
local_inputs = [
  ['ci/build-inputs/vendor/secp256k1-zkp/meson.build', 'build-graph', ''],
  ['vendor/secp256k1-zkp/CHANGELOG.md', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-zkp/Cargo.lock', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-zkp/Cargo.toml', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-zkp/Cargo.toml.orig', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-zkp/LICENSE', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-zkp/Makefile', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-zkp/README.md', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('contrib')
subdir('src')
