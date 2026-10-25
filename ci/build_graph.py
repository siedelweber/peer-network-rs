"""Fresh tracked-file and step incidence checks for the Meson gate skeleton."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time


PATTERN = r'a^'
SPECIAL = {'entry', 'finalize'}


def run(argv, **kwargs):
    started = time.monotonic()
    result = subprocess.run(argv, **kwargs)
    print(f'BUILD-GRAPH-COMMAND tool={Path(str(argv[0])).name} status={result.returncode} wall={time.monotonic()-started:.6f}s', flush=True)
    return result


def tracked(root):
    result = run(['git', '-C', str(root), 'ls-files', '--stage', '-z'], capture_output=True)
    if result.returncode:
        raise ValueError('cannot read the complete Git index')
    rows = []
    for raw in result.stdout.decode('utf-8').split('\0'):
        if not raw:
            continue
        metadata, path = raw.split('\t', 1)
        mode, identity, stage = metadata.split()
        if mode not in {'100644', '100755'} or stage != '0':
            raise ValueError('unsupported tracked mode or merge stage: '+path)
        rows.append(path)
    return rows


def roster(root):
    lines = (root/'ci/gate.sh').read_text().splitlines()
    result = []
    for line in lines:
        if not line.startswith('run_step '):
            continue
        match = re.fullmatch(r'run_step ([a-z0-9-]+) (.+)', line)
        if not match:
            raise ValueError('unreadable gate step: '+line)
        result.append((match[1], match[2]))
    if not result or len({name for name, _ in result}) != len(result):
        raise ValueError('empty or duplicate gate roster')
    return result


def list_for(path):
    # Keep typed source directories unchanged; mirror every non-root directory.
    if path.startswith('ci/build-inputs/') and path.endswith('/meson.build'):
        return path
    parent = PurePosixPath(path).parent
    if parent == PurePosixPath('.'):
        return 'meson.build'
    return str(PurePosixPath('ci/build-inputs')/parent/'meson.build')


def configure(args):
    """Serialize only the declarations evaluated by Meson, never discover inputs."""
    inputs = []
    for value in args.input:
        path, consumers, producer = value.split('\t')
        inputs.append(dict(path=path, consumers=consumers.split(',') if consumers else [], producer=producer))
    steps = []
    for value in args.step:
        name, command, previous = value.split('\t')
        steps.append(dict(name=name, command=command,
                          needs=[previous] if previous else [],
                          report=f'.lane/gate-{name}.log'))
    products = []
    for value in args.product:
        path, producer, consumers = value.split('\t')
        products.append(dict(path=path, producer=producer, consumers=consumers.split(',')))
    graph = dict(schema=1, pattern=args.pattern, inputs=inputs, excluded=[], steps=steps,
                 final_inputs=[step['report'] for step in steps],
                 prerequisites=['PN_MESON_BIN', 'LINTER_BIN', 'PN_POSTGRESQL_BIN', 'PN_ELEMENTS_BIN',
                                'python3', 'git', 'bash', 'ninja', 'cargo', 'rustc', 'rustfmt', 'cargo-clippy'],
                 products=products,
                 route='existing-shell-commands')
    Path(args.graph).write_text(json.dumps(graph, indent=2)+'\n')


def incidence(root, graph):
    """Check both directions against the live index, including ignored carriers."""
    findings = []
    if graph.get('schema') != 1:
        return ['unsupported graph schema'], 0
    current = tracked(root)
    current_set = set(current)
    if len(current) != len(current_set):
        findings.append('duplicate tracked index entry')
    if graph.get('pattern') != PATTERN:
        findings.append('exclusion pattern widened; only the nonmatching pattern is admitted')
    # There are no excluded tracked paths in slice one. A future exception needs
    # an explicit owner/reason schema and its own reviewed checker change.
    if graph.get('excluded') != []:
        findings.append('tracked exclusions are not admitted in this slice')
    expected = roster(root)
    steps = graph['steps']
    if [(s['name'], s['command']) for s in steps] != expected:
        findings.append('step roster or command differs from ci/gate.sh')
    names = {name for name, _ in expected}
    previous = ''
    reports = []
    for step in steps:
        if step['needs'] != ([previous] if previous else []):
            findings.append('report predecessor differs: '+step['name'])
        if step['report'] != f".lane/gate-{step['name']}.log":
            findings.append('report identity differs: '+step['name'])
        reports.append(step['report'])
        previous = step['name']
    if graph.get('final_inputs') != reports:
        findings.append('final report consumer does not cover the roster')
    produced = set()
    order = {'entry': -1, **{name: i for i, (name, _) in enumerate(expected)}, 'finalize': len(expected)}
    for product in graph['products']:
        path, producer, consumers = product['path'], product['producer'], product['consumers']
        if path in produced or not path.startswith('.lane/') or '*' in path or '..' in PurePosixPath(path).parts:
            findings.append('duplicate or invalid run product: '+path)
        produced.add(path)
        if producer not in order or not consumers or any(c not in order or order.get(producer, len(expected)) >= order[c] for c in consumers):
            findings.append('invalid run product edge: '+path)
    paths = [row['path'] for row in graph['inputs']]
    for path, count in Counter(paths).items():
        if count != 1:
            findings.append('duplicate declaration: '+path)
    declared = set(paths)
    for path in sorted(current_set-declared):
        findings.append(f'undeclared tracked file: {path}; add it to {list_for(path)} with its consumers')
    for path in sorted(declared-current_set):
        findings.append(f'stale declaration: {path}; remove it from {list_for(path)}')
    connected = set()
    for row in graph['inputs']:
        path = row['path']
        if not path or str(PurePosixPath(path)) != path or path.startswith('/') or '..' in PurePosixPath(path).parts:
            findings.append('noncanonical declared path: '+path)
        if not (root/path).is_file() or (root/path).is_symlink():
            findings.append('missing or nonregular declared input: '+path)
        consumers = row['consumers']
        if not consumers or len(set(consumers)) != len(consumers) or not set(consumers) <= names | SPECIAL:
            findings.append(f'unconnected or unknown consumer: {path}; edit {list_for(path)}')
        connected.update(consumers)
        if row['producer'] and row['producer'] not in names:
            findings.append('unknown generated-file producer: '+path)
    for name in sorted(names-connected):
        findings.append('step has no declared input: '+name)
    return findings, len(current)


def check(root, graph_path, report_path):
    root = Path(root).resolve()
    graph_path = Path(graph_path).resolve()
    report_path = Path(report_path).resolve()
    # Never let an earlier successful report survive a structural refusal.
    report_path.unlink(missing_ok=True)
    graph = json.loads(graph_path.read_text())
    findings, count = incidence(root, graph)
    print(f'GRAPH-INCIDENCE tracked={count} declared={len(graph["inputs"])} excluded={len(graph["excluded"])} steps={len(graph["steps"])} findings={len(findings)}', flush=True)
    for finding in findings:
        print('GRAPH-REFUSAL '+finding, flush=True)
    declared = report_path.with_suffix('.declared')
    excluded = report_path.with_suffix('.excluded')
    declared.write_text(''.join(row['path']+'\n' for row in graph['inputs']))
    excluded.write_text('')
    census_path = report_path.with_suffix('.census.json')
    census_path.unlink(missing_ok=True)
    stamp_path = report_path.with_suffix('.census.stamp')
    stamp_path.unlink(missing_ok=True)
    linter = os.environ.get('LINTER_BIN', '')
    if not linter:
        raise ValueError('LINTER_BIN must name the deployed linter')
    result = run([linter, 'census', '--root', str(root), '--declared', str(declared),
                  '--excluded', str(excluded), '--pattern', PATTERN, '--report', str(census_path),
                  '--stamp', str(stamp_path)])
    census = json.loads(census_path.read_text()) if census_path.exists() else {}
    print(f'BUILD-CENSUS tracked={census.get("tracked", "unavailable")} declared={census.get("declared", "unavailable")} excluded={census.get("excluded", "unavailable")} findings={census.get("failures", "unavailable")} exit={result.returncode}', flush=True)
    status = int(bool(findings) or result.returncode != 0 or not census.get('clean'))
    report_path.write_text(json.dumps(dict(schema=1, status=status, findings=findings, census=census), indent=2)+'\n')
    return status


def gate():
    meson = os.environ.get('PN_MESON_BIN', '')
    if not meson:
        raise ValueError('PN_MESON_BIN must name the provisioned Meson executable')
    root = Path.cwd()
    build = root/'.lane/build-graph'
    for command in ([meson, '--version'], ['ninja', '--version']):
        if run(command).returncode:
            return 1
    if not (build/'build.ninja').exists():
        if run([meson, 'setup', str(build), str(root)]).returncode:
            return 1
    return run([meson, 'compile', '-C', str(build), 'tracked-census']).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    create = sub.add_parser('configure')
    create.add_argument('--graph', required=True)
    create.add_argument('--pattern', required=True)
    create.add_argument('--input', action='append', default=[])
    create.add_argument('--step', action='append', default=[])
    create.add_argument('--product', action='append', default=[])
    audit = sub.add_parser('check')
    audit.add_argument('--root', required=True)
    audit.add_argument('--graph', required=True)
    audit.add_argument('--report', required=True)
    sub.add_parser('gate')
    args = parser.parse_args()
    if args.action == 'configure':
        configure(args)
        return 0
    if args.action == 'check':
        return check(args.root, args.graph, args.report)
    return gate()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('BUILD-GRAPH-ERROR '+str(error), file=sys.stderr)
        sys.exit(2)
