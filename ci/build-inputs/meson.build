# Explicit source-root paths, consuming gate steps and generated-file producer.
# Add new files in the corresponding directory here; no globs or exemptions.
local_inputs = [
  ['ci/build-inputs/meson.build', 'build-graph', ''],
]
foreach row : local_inputs
  graph_files += files(meson.project_source_root() / row[0])
  graph_arguments += ['--input', row[0] + '\t' + row[1] + '\t' + row[2]]
endforeach
subdir('.linter')
subdir('adr')
subdir('ci')
subdir('docs')
subdir('packages')
subdir('vendor')

# Each delegated command has its own always-run target. The retained entry
# invokes them in roster order; current-run predecessor reports enforce it.
graph_python = find_program('python3')
graph_adapter = files(meson.project_source_root() / 'ci/build_graph.py')
configure_file(input: meson.project_source_root() / 'docs/inputs/build-graph-slices.toml',
  output: 'slice-selection.toml', copy: true)
delegation = run_command(graph_python, graph_adapter, 'targets',
  '--root', meson.project_source_root(), check: true).stdout().strip().split('\n')
foreach name : delegation
  custom_target('gate-' + name,
    input: graph_files,
    output: 'gate-' + name + '.json',
    command: [graph_python, graph_adapter, 'execute', '--root', meson.project_source_root(),
      '--graph', meson.project_build_root() / 'gate-graph.json', '--report', '@OUTPUT@'],
    build_always_stale: true,
    console: true,
  )
endforeach
