# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['adr/001-label-calculus.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/002-environment-kinds.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/003-templated-documentation.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/004-command-line-output-contract.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/005-lint-discipline.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/006-identity-adjudication.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/007-crate-decomposition.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/008-interchange-conventions.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/009-interchange-concept.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/010-interchange-design.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/011-interchange-audit.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/012-interchange-commissioning.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/013-toolchain-and-build-profile.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/014-forward-only-development.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/015-durable-storage.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/016-observability.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/017-claim-based-testing.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/018-public-api.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/019-development-network.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/020-testing-harness.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/021-development-performance.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/022-host-intranet.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/023-cryptographic-base.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/024-build-graph.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['adr/README.md', 'linter,design-correspondence,documents,datasets,fixed-point-generate,fixed-point-write,fixed-point-clean,determinism-datasets,determinism-documents,claim-evidence,token,hash-citations', 'fixed-point-write'],
  ['ci/build-inputs/adr/meson.build', 'build-graph', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
