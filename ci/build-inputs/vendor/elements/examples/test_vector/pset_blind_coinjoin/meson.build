# Explicit archived file inputs; content checks consume every file.
local_inputs = [
  ['ci/build-inputs/vendor/elements/examples/test_vector/pset_blind_coinjoin/meson.build', 'build-graph', ''],
  ['vendor/elements/examples/test_vector/pset_blind_coinjoin/pset_coinjoined_B_blinded.hex', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
  ['vendor/elements/examples/test_vector/pset_blind_coinjoin/pset_coinjoined_blinded.hex', 'fmt,clippy,nursery-advisory,minimal,rustdoc,test-build,reference-certificates,service-tests,extended-tests,test-evidence,tests,benchmarks,observation-build,host-observation-build,wallet-conformance,fixed-point-generate,fixed-point-write,datasets,documents,determinism-datasets,determinism-documents,vendor-set,token,hash-citations', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
