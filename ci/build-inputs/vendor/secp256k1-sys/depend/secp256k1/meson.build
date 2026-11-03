# Explicit archived file inputs; content checks consume every file.
local_inputs = [
  ['ci/build-inputs/vendor/secp256k1-sys/depend/secp256k1/meson.build', 'build-graph', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/.cirrus.yml', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/.gitattributes', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/.gitignore', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/CHANGELOG.md', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/CMakeLists.txt', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/CMakePresets.json', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/CONTRIBUTING.md', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/COPYING', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/Makefile.am', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/README.md', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/SECURITY.md', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/autogen.sh', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/configure.ac', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/secp256k1-sys/depend/secp256k1/libsecp256k1.pc.in', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('.github')
subdir('build-aux')
subdir('ci')
subdir('cmake')
subdir('contrib')
subdir('doc')
subdir('examples')
subdir('include')
subdir('sage')
subdir('src')
subdir('tools')
