pkg_execwrap_rust = files(
  'src/bin/execwrap.rs',
  'src/lib.rs',
  'src/tests/mod.rs',
  'src/writer.rs',
  'tests/integration.rs',
)

pkg_execwrap_prose = files(
  'README.md',
)

pkg_execwrap_toml = []

pkg_execwrap_install = []

pkg_execwrap_excluded_rust = []

pkg_execwrap_excluded_prose = []

pkg_execwrap_excluded_toml = []

pkg_execwrap_sync_outputs = []

pkg_execwrap_sync_execwrap = custom_target(
  'sync-execwrap',
  output: ['execwrap', 'execwrap.build.json'],
  command: [cargo, 'run', '-q', '--release', '--locked', '--manifest-path', root_manifest, '-p', 'build-sync', '--', '--domain', domain, cargo.full_path(), root_manifest, 'execwrap', 'execwrap', '@OUTPUT0@'],
  build_always_stale: true,
  build_by_default: true,
  console: true,
)
pkg_execwrap_sync_outputs += pkg_execwrap_sync_execwrap
