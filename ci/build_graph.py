"""Fresh tracked-file and step incidence checks for the Meson gate skeleton."""

import argparse
from collections import Counter
import hashlib
import math
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import subprocess
import sys
import time
import tomllib
import uuid


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
        if not line.startswith(('run_step ', 'run_graph ')):
            continue
        match = re.fullmatch(r'run_(?:step|graph) ([a-z0-9-]+) (.+)', line)
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
    # Ninja owns Meson's regeneration edge as well as always-run targets.
    # Avoid loading Meson's full introspection graph for each invocation.
    return run(['ninja', '-C', str(build), 'tracked-census.json']).returncode


PUBLIC_CONFIGURATION = ('PATH', 'CARGO_HOME', 'CARGO_TARGET_DIR', 'RUSTUP_HOME',
                        'RUSTUP_TOOLCHAIN', 'CARGO_NET_OFFLINE', 'RUSTFLAGS',
                        'CARGO_ENCODED_RUSTFLAGS', 'LINTER_BIN', 'PN_MESON_BIN',
                        'PN_POSTGRESQL_BIN', 'PN_ELEMENTS_BIN', 'TMPDIR',
                        'PN_OBSERVE_ARTIFACT_DIR', 'PN_OBSERVE_LEVEL',
                        'PN_HOST_TEST_ROOT', 'PN_WALLET_TEST_ROOT')


def selected(root):
    rows = tomllib.loads((root/'docs/inputs/build-graph-slices.toml').read_text())['rows']
    names = [row['name'] for row in rows]
    if Counter(names) != Counter(name for name, _ in roster(root)):
        raise ValueError('slice assignment differs from live roster')
    if any(type(row['slice']) is not int or row['slice'] not in {2, 3, 4, 5} for row in rows):
        raise ValueError('invalid delegation slice')
    return [row['name'] for row in rows if row['slice'] == 2]


def identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def report_path(build, step):
    return build/'ci/build-inputs'/('gate-'+step+'.json')


def context(root, graph, step):
    """Bind a command to this invocation, configuration, inputs and serial prefix."""
    names = [name for name, _ in roster(root)]
    if [(s['name'], s['command']) for s in graph['steps']] != roster(root):
        raise ValueError('configured command roster differs from entry')
    if step not in selected(root):
        raise ValueError('step is not delegated: '+step)
    run_id = os.environ.get('PN_BUILDGRAPH_RUN', '')
    if not run_id:
        raise ValueError('missing current gate invocation')
    source = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    history = (root/'.lane/gate-steps.tsv').read_text().splitlines()
    fields = [line.split('\t') for line in history]
    if any(len(row) != 4 for row in fields) or [row[0] for row in fields] != names[:names.index(step)]:
        raise ValueError('missing or out-of-order current step reports: '+step)
    inputs = []
    # The migrated Meson targets consume graph_files: a deliberately
    # conservative tracked envelope including their runner and list helpers.
    for row in graph['inputs']:
        inputs.append((row['path'], hashlib.sha256((root/row['path']).read_bytes()).hexdigest()))
    if not inputs:
        raise ValueError('delegated step has no declared inputs')
    command = next(s['command'] for s in graph['steps'] if s['name'] == step)
    return dict(run=run_id, source=source, step=step, command=command,
                configuration={name: os.environ.get(name) for name in PUBLIC_CONFIGURATION},
                inputs=identity(sorted(inputs)), graph=identity(graph), history=identity(history))


def read_result(path, request):
    """A completed Meson target is not a successful checker verdict."""
    result = json.loads(path.read_text())
    if result.get('schema') != 1 or result.get('request') != request:
        raise ValueError('stale or mismatched delegated result')
    status = result.get('status')
    if type(status) is not int or not 0 <= status <= 255:
        raise ValueError('invalid delegated command status')
    output = Path(request['log']).read_bytes()
    if result.get('output') != hashlib.sha256(output).hexdigest():
        raise ValueError('delegated output differs from result')
    # UTC can move backwards; only the monotonic duration measures elapsed work.
    # A wall-clock adjustment must not change the command verdict.
    if not all(type(result.get(key)) in (int, float) and math.isfinite(result[key]) for key in ('started', 'ended', 'wall')) or result['wall'] < 0:
        raise ValueError('invalid delegated measurement')
    return result, output


def execute(root, graph_path, output):
    """Publish raw status even on refusal; Ninja only transports this report."""
    request = json.loads(Path(os.environ['PN_BUILDGRAPH_REQUEST']).read_text())
    graph = json.loads(graph_path.read_text())
    if request['context'] != context(root, graph, request['context']['step']):
        raise ValueError('source, configuration or input changed before delegated execution')
    output.unlink(missing_ok=True)
    products = [row['path'] for row in graph['inputs'] if row.get('producer') == request['context']['step']]
    before = {path: hashlib.sha256((root/path).read_bytes()).hexdigest() for path in products}
    started = time.time()
    clock = time.monotonic()
    cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
    with Path(request['log']).open('wb') as log:
        status = subprocess.run(['bash', '-c', request['context']['command']], cwd=root,
                                stdout=log, stderr=subprocess.STDOUT).returncode
    ended = time.time()
    used = resource.getrusage(resource.RUSAGE_CHILDREN)
    status = 128-status if status < 0 else status
    result = dict(schema=1, request=request, status=status, started=started, ended=ended,
                  cpu_user=used.ru_utime-cpu.ru_utime, cpu_system=used.ru_stime-cpu.ru_stime,
                  products=[dict(path=path, before=before[path], after=hashlib.sha256((root/path).read_bytes()).hexdigest()) for path in products],
                  wall=time.monotonic()-clock,
                  output=hashlib.sha256(Path(request['log']).read_bytes()).hexdigest())
    temporary = output.with_suffix('.tmp')
    temporary.write_text(json.dumps(result, sort_keys=True)+'\n')
    temporary.replace(output)
    return 0


def delegate(root, step):
    """Invoke exactly one fresh target, then return its command's actual status."""
    build = root/'.lane/build-graph'
    graph = json.loads((build/'gate-graph.json').read_text())
    clock = time.monotonic()
    bound = context(root, graph, step)
    delegated = set(selected(root))
    # Predecessor edges mean ordered completion, not success: the legacy entry
    # continues independent checks after refusal. A missing/stale report is
    # structural, and every raw refusal remains in the gate's aggregate.
    for line in (root/'.lane/gate-steps.tsv').read_text().splitlines():
        name, status, _, _ = line.split('\t')
        if name not in delegated:
            continue
        prior = json.loads(report_path(build, name).read_text())
        request = prior['request']
        read_result(report_path(build, name), request)
        prior_context = request['context']
        if any(prior_context[key] != bound[key] for key in ('run', 'source', 'configuration', 'graph')) or prior['status'] != int(status):
            raise ValueError('stale or inconsistent predecessor: '+name)
    requests = build/'requests'
    requests.mkdir(exist_ok=True)
    nonce = uuid.uuid4().hex
    request = dict(context=bound, nonce=nonce, log=str(requests/(nonce+'.log')))
    request_path = requests/(nonce+'.json')
    request_path.write_text(json.dumps(request, sort_keys=True)+'\n')
    output = report_path(build, step)
    output.unlink(missing_ok=True)
    env = dict(os.environ, PN_BUILDGRAPH_REQUEST=str(request_path))
    prepared = time.monotonic()
    cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
    driver = subprocess.run(['ninja', '-C', str(build), str(output.relative_to(build))],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    used = resource.getrusage(resource.RUSAGE_CHILDREN)
    (requests/(nonce+'.timing.json')).write_text(json.dumps(dict(
        preparation_wall=prepared-clock, driver_wall=time.monotonic()-prepared,
        driver_user=used.ru_utime-cpu.ru_utime, driver_system=used.ru_stime-cpu.ru_stime))+'\n')
    (requests/(nonce+'.driver.log')).write_bytes(driver.stdout)
    if driver.returncode:
        raise ValueError('Meson adapter failed for '+step+'; current driver log: '+str(requests/(nonce+'.driver.log')))
    result, content = read_result(output, request)
    sys.stdout.buffer.write(content)
    sys.stdout.buffer.flush()
    return result['status']


def resource_line(root, line):
    """Enrich entry measurements, never the command's own comparison log."""
    if not line.startswith('STEP=') or os.environ.get('PN_BUILDGRAPH_ROUTE')=='legacy':
        return line
    fields=dict(item.split('=',1) for item in line.split() if '=' in item)
    step=fields['STEP']
    declared={parts[1] for text in (root/'ci/gate.sh').read_text().splitlines()
              if (parts:=text.split()) and parts[0]=='run_graph'}
    if step not in declared:return line
    suffix=' command_wall_s=unavailable delegation_overhead_s=unavailable'
    try:
        report=report_path(root/'.lane/build-graph',step)
        data=json.loads(report.read_text());request=data['request']
        result,_=read_result(report,request)
        if request['context']['run']!=os.environ.get('PN_BUILDGRAPH_RUN') or request['context']['step']!=step or result['status']!=int(fields['STATUS']):
            raise ValueError('measurement from another invocation')
        inclusive=float(fields['WALL'].removesuffix('s'))
        suffix=f" command_wall_s={result['wall']:.6f} delegation_overhead_s={inclusive-result['wall']:.6f}"
    except (OSError,ValueError,KeyError,TypeError):
        pass  # Structural refusal has no measured command; never borrow an old result.
    return line.rstrip('\n')+suffix+'\n'


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
    measurements=sub.add_parser('resource-lines')
    measurements.add_argument('path')
    targets = sub.add_parser('targets')
    targets.add_argument('--root', required=True)
    target = sub.add_parser('execute')
    target.add_argument('--root', required=True)
    target.add_argument('--graph', required=True)
    target.add_argument('--report', required=True)
    invoke = sub.add_parser('delegate')
    invoke.add_argument('step')
    args = parser.parse_args()
    if args.action == 'resource-lines':
        for line in Path(args.path).read_text().splitlines(keepends=True):
            print(resource_line(Path.cwd(),line),end='')
        return 0
    if args.action == 'configure':
        configure(args)
        return 0
    if args.action == 'check':
        return check(args.root, args.graph, args.report)
    if args.action == 'targets':
        print('\n'.join(selected(Path(args.root))))
        return 0
    if args.action == 'execute':
        return execute(Path(args.root).resolve(), Path(args.graph).resolve(), Path(args.report).resolve())
    if args.action == 'delegate':
        return delegate(Path.cwd(), args.step)
    return gate()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('BUILD-GRAPH-ERROR '+str(error), file=sys.stderr)
        sys.exit(2)
