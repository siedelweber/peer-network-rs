"""Fresh tracked-file and step incidence checks for the Meson gate skeleton."""

import argparse
import concurrent.futures
import ast
from collections import Counter
import hashlib
import math
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import signal
import subprocess
import sys
sys.dont_write_bytecode = True
import time
import tomllib
import uuid


PATTERN = r'a^'
SPECIAL = {'entry', 'finalize'}
SHELL_STEPS = {'build-graph', 'wallet-elements-stop', 'host-postgresql-stop'}


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
    """Read the single literal command declaration consumed by Meson and entry."""
    source = (root/'meson.build').read_text()
    match = re.search(r'^gate_steps = (\[.*?^\])', source, re.M | re.S)
    if not match:
        raise ValueError('missing literal Meson gate_steps declaration')
    rows = ast.literal_eval(match[1])
    result = []
    previous = ''
    for row in rows:
        if (not isinstance(row, list) or len(row) != 3 or
                not all(isinstance(value, str) for value in row)):
            raise ValueError('invalid Meson gate step')
        name, command, predecessor = row
        if not re.fullmatch('[a-z0-9-]+', name) or not command or '\n' in command or predecessor != previous:
            raise ValueError('invalid Meson command or predecessor: '+name)
        result.append((name, command))
        previous = name
    if not result or len({name for name, _ in result}) != len(result):
        raise ValueError('empty or duplicate gate roster')
    return result


def dependencies(root):
    """Read declared completion edges; older fixture graphs retain their chain."""
    source = (root/'meson.build').read_text()
    match = re.search(r'^gate_dependencies = (\{.*?^\})', source, re.M | re.S)
    names = [name for name, _ in roster(root)]
    if not match:
        return {name: names[index-1:index] for index, name in enumerate(names)}
    edges = ast.literal_eval(match[1])
    if set(edges) != set(names):
        raise ValueError('dependency declaration differs from roster')
    for name, parents in edges.items():
        if (not isinstance(parents, list) or len(parents) != len(set(parents)) or
                any(parent not in names[:names.index(name)] for parent in parents)):
            raise ValueError('unknown, repeated or non-topological dependency: '+name)
    declared = re.search(r'^gate_resource_classes = (\{.*?^\})', source, re.M | re.S)
    if not declared:
        raise ValueError('missing exclusive resource classes')
    classes = ast.literal_eval(declared[1])
    if not isinstance(classes, dict):
        raise ValueError('invalid exclusive resource declaration')
    ancestors = {}
    for name in names:
        ancestors[name] = set(edges[name]).union(*(ancestors[parent] for parent in edges[name]))
    for resource, members in classes.items():
        if (not isinstance(resource, str) or not isinstance(members, list) or
                len(members) != len(set(members)) or any(name not in names for name in members)):
            raise ValueError('invalid exclusive resource class')
        for index, left in enumerate(members):
            for right in members[index+1:]:
                if left not in ancestors[right] and right not in ancestors[left]:
                    raise ValueError(f'unordered exclusive resource {resource}: {left}, {right}')
    return edges


def predecessors(root, step):
    edges = dependencies(root)
    found = set()
    def visit(name):
        for parent in edges[name]:
            if parent not in found:
                found.add(parent)
                visit(parent)
    visit(step)
    return [name for name, _ in roster(root) if name in found]


def bound_history(root, step, history):
    names = [name for name, _ in roster(root)]
    fields = [line.split('\t') for line in history]
    if (any(len(row) != 4 for row in fields) or len({row[0] for row in fields}) != len(fields)
            or any(row[0] not in names for row in fields)):
        raise ValueError('malformed or duplicate current step reports: '+step)
    rows = {row[0]: line for row, line in zip(fields, history)}
    required = predecessors(root, step)
    if any(name not in rows for name in required):
        raise ValueError('missing or out-of-order current step reports: '+step)
    edges = dependencies(root)
    for index, row in enumerate(fields):
        if not set(edges[row[0]]) <= {earlier[0] for earlier in fields[:index]}:
            raise ValueError('out-of-order current step reports: '+step)
    return [rows[name] for name in required]


def plan(root):
    """Emit the serial entry from the same declaration, never a second roster."""
    # Planning must survive a bad slice assignment: configuration then refuses
    # delegated commands individually, while the explicit shutdown still runs.
    return ''.join(('run_step ' if name in SHELL_STEPS else 'run_graph ')+name+' '+command+'\n'
                   for name, command in roster(root))


def reap_cancelled_children(*, grace=5, deadline=30, signal_child=os.kill):
    """Drain this dedicated subreaper's children; elapsed time only escalates/refuses."""
    started = time.monotonic()
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid:
            continue
        # Unreaped children cannot have their PIDs reused. This process owns no
        # unrelated children; nested sessions orphaned by adapters are adopted.
        children = [int(pid) for pid in Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()]
        elapsed = time.monotonic()-started
        if elapsed >= deadline:
            raise ValueError(f'cancelled command tree not reaped by {deadline}s deadline: {children}')
        for pid in children:
            try:
                signal_child(pid, signal.SIGKILL if elapsed >= grace else signal.SIGTERM)
            except ProcessLookupError:
                pass
        time.sleep(0.01)


def become_child_subreaper():
    """Linux adoption is confined to the dedicated step-supervisor process."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise ValueError('cannot establish command-tree subreaper: '+os.strerror(ctypes.get_errno()))


def cancellable(argv, *, kill_after=5, reap_tree=False, **kwargs):
    """Forward termination through each adapter boundary and reap its child."""
    child = None
    pending = []
    def terminate(number, frame):
        if not pending:
            pending.extend((number, time.monotonic()))
        if child is not None and child.returncode is None:
            try:
                os.killpg(child.pid, number)
            except ProcessLookupError:
                pass
    old = {number: signal.signal(number, terminate) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        if reap_tree:
            become_child_subreaper()
        child = subprocess.Popen(argv, start_new_session=True, **kwargs)
        if pending:
            terminate(pending[0], None)
        while True:
            if pending and reap_tree and time.monotonic()-pending[1] >= 35:
                raise ValueError('cancelled command leader not reaped by 35s deadline')
            try:
                output, errors = child.communicate(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                if pending and kill_after is not None and time.monotonic()-pending[1] >= kill_after:
                    try:os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:pass
        if pending and reap_tree:
            elapsed = time.monotonic()-pending[1]
            reap_cancelled_children(grace=max(0, 5-elapsed), deadline=max(0, 35-elapsed))
        return subprocess.CompletedProcess(argv, -pending[0] if pending else child.returncode, output, errors)
    finally:
        for number, handler in old.items():
            signal.signal(number, handler)


def finish(root):
    """Require one current completion per declared step, including the final one."""
    names = [name for name, _ in roster(root)]
    history = (root/'.lane/gate-steps.tsv').read_text().splitlines()
    fields = [line.split('\t') for line in history]
    if any(len(row) != 4 for row in fields) or len(fields) != len(names) or {row[0] for row in fields} != set(names):
        raise ValueError('final roster is missing, duplicated or out of order')
    graph = json.loads((root/'.lane/build-graph/gate-graph.json').read_text())
    if [(row['name'], row['command']) for row in graph['steps']] != roster(root):
        raise ValueError('final configured roster differs')
    delegated = set(selected(root))
    source = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    configuration = {name: os.environ.get(name) for name in PUBLIC_CONFIGURATION}
    for index, row in enumerate(fields):
        name, status, _, _ = row
        if not (root/f'.lane/gate-{name}.log').is_file():
            raise ValueError('missing final log: '+name)
        if name in delegated and os.environ.get('PN_BUILDGRAPH_ROUTE') != 'legacy':
            path = report_path(root/'.lane/build-graph', name)
            data = json.loads(path.read_text()); request = data['request']
            result, _ = read_result(path, request)
            bound = request['context']
            expected = dict(run=os.environ.get('PN_BUILDGRAPH_RUN'), source=source,
                            configuration=configuration, graph=identity(graph),
                            history=identity(bound_history(root, name, history)), step=name,
                            command=dict(roster(root))[name])
            if any(bound[key] != value for key, value in expected.items()) or result['status'] != int(status):
                raise ValueError('stale final report: '+name)
    print(f'BUILD-FINAL steps={len(names)} exactly_once=true delegated={len(delegated)} fresh=true')
    return 0


def list_for(path):
    # Keep typed source directories unchanged; mirror every non-root directory.
    if path.startswith('ci/build-inputs/') and path.endswith('/meson.build'):
        return path
    parent = PurePosixPath(path).parent
    if parent == PurePosixPath('.'):
        return 'meson.build'
    return str(PurePosixPath('ci/build-inputs')/parent/'meson.build')


def configure(args):
    """Serialize Meson declarations and their admitted exact-index families."""
    inputs = []
    for value in args.input:
        path, consumers, producer = value.split('\t')
        inputs.append(dict(path=path, consumers=consumers.split(',') if consumers else [], producer=producer))
    from registry_fragments import expanded_inputs
    inputs.extend(expanded_inputs(Path(args.root), inputs))
    steps = []
    edges = dependencies(Path(args.root))
    for value in args.step:
        name, command, previous = value.split('\t')
        steps.append(dict(name=name, command=command,
                          needs=edges[name],
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
        findings.append('step roster or command differs from Meson declaration')
    names = {name for name, _ in expected}
    edges = dependencies(root)
    reports = []
    for step in steps:
        if step['needs'] != edges[step['name']]:
            findings.append('report predecessor differs: '+step['name'])
        if step['report'] != f".lane/gate-{step['name']}.log":
            findings.append('report identity differs: '+step['name'])
        reports.append(step['report'])
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
        elif producer != 'entry' and any(c != 'finalize' and producer not in predecessors(root, c) for c in consumers):
            findings.append('missing run product dependency: '+path)
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
    # A new indexed fragment need not edit a Meson filename manifest. Refresh
    # only the admitted families; all other exact declarations stay untouched.
    from registry_fragments import ROOTS, expanded_inputs
    static = [row for row in graph['inputs']
              if not any(row['path'].startswith(prefix+'/') and
                         row['path'] not in {prefix+'/schema.toml', prefix+'/schema.json'}
                         for prefix in ROOTS.values())]
    graph['inputs'] = static + expanded_inputs(root, static)
    refreshed = json.dumps(graph, indent=2)+'\n'
    if graph_path.read_text() != refreshed:
        graph_path.write_text(refreshed)
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
    # The generator also invokes this reader without Python's -B flag.
    # A census must not create bytecode files in the source it inventories.
    sys.dont_write_bytecode = True
    from isolation import tracked_snapshot
    with tracked_snapshot(root) as snapshot:
        result = run([linter, 'census', '--root', str(snapshot), '--declared', str(declared),
                      '--excluded', str(excluded), '--pattern', PATTERN, '--write-report', str(census_path),
                      '--write-stamp', str(stamp_path)])
    census = json.loads(census_path.read_text()) if census_path.exists() else {}
    print(f'BUILD-CENSUS tracked={census.get("tracked", "unavailable")} declared={census.get("declared", "unavailable")} excluded={census.get("excluded", "unavailable")} findings={census.get("failures", "unavailable")} exit={result.returncode}', flush=True)
    status = int(bool(findings) or result.returncode != 0 or not census.get('clean'))
    report_path.write_text(json.dumps(dict(schema=1, status=status, findings=findings, census=census), indent=2)+'\n')
    return status


def prepare(meson, build, root):
    """Bind reused configuration to the answering Meson once per gate."""
    result = run([meson, '--version'], capture_output=True, text=True)
    print(result.stdout, end='')
    print(result.stderr, end='', file=sys.stderr)
    if result.returncode:
        return result.returncode
    version = result.stdout.strip()
    if not version or len(version.splitlines()) != 1:
        raise ValueError('Meson returned no single version')
    info = build/'meson-info/meson-info.json'
    configured = json.loads(info.read_text())['meson_version']['full'] if info.exists() else None
    exists = (build/'build.ninja').exists()
    action = 'setup' if not exists else ('reuse' if configured == version else 'wipe-setup')
    print(f'BUILD-MESON version={version} configured={configured} action={action}', flush=True)
    if action != 'reuse':
        command = [meson, 'setup', *(['--wipe'] if exists else []), str(build), str(root)]
        if run(command).returncode:
            return 1
        if json.loads(info.read_text())['meson_version']['full'] != version:
            raise ValueError('configured Meson version differs from answering binary')
    return 0


def gate():
    meson = os.environ.get('PN_MESON_BIN', '')
    if not meson:
        raise ValueError('PN_MESON_BIN must name the provisioned Meson executable')
    root = Path.cwd()
    from claims import tracker_structure
    tracker_structure(root)
    build = root/'.lane/build-graph'
    if run(['ninja', '--version']).returncode or prepare(meson, build, root):
        return 1
    # Ninja owns Meson's regeneration edge as well as always-run targets.
    # Avoid loading Meson's full introspection graph for each invocation.
    return run(['ninja', '-C', str(build), 'tracked-census.json']).returncode


PUBLIC_CONFIGURATION = ('PATH', 'CARGO_HOME', 'CARGO_TARGET_DIR', 'RUSTUP_HOME',
                        'RUSTUP_TOOLCHAIN', 'CARGO_NET_OFFLINE', 'RUSTFLAGS',
                        'CARGO_ENCODED_RUSTFLAGS', 'LINTER_BIN', 'PN_MESON_BIN',
                        'PN_POSTGRESQL_BIN', 'PN_ELEMENTS_BIN', 'TMPDIR',
                        'PN_OBSERVE_ARTIFACT_DIR', 'PN_OBSERVE_LEVEL',
                        'PN_HOST_TEST_ROOT', 'PN_WALLET_TEST_ROOT', 'PN_BUILDGRAPH_ADMISSION', 'PN_GATE_PARALLEL')


def selected(root):
    rows = tomllib.loads((root/'docs/inputs/build-graph-slices.toml').read_text())['rows']
    names = [row['name'] for row in rows]
    if Counter(names) != Counter(name for name, _ in roster(root)):
        raise ValueError('slice assignment differs from live roster')
    if any(type(row['slice']) is not int or row['slice'] not in {2, 3, 4, 5} for row in rows):
        raise ValueError('invalid delegation slice')
    return [row['name'] for row in rows if row['slice'] in {2, 3, 4}]


def identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def report_path(build, step):
    return build/'ci/build-inputs'/('gate-'+step+'.json')


def bind_inputs(root):
    """Bind tracked inputs once, before any gate command can run."""
    path = root/'.lane/build-input-binding.json'
    path.unlink(missing_ok=True)
    dirty = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=no'])
    if dirty:
        raise ValueError('input binding requires a clean tracked tree')
    source, tree = subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', 'HEAD', 'HEAD^{tree}'], text=True).splitlines()
    run_id = os.environ.get('PN_BUILDGRAPH_RUN')
    if not run_id:
        raise ValueError('missing current gate run identity')
    value = dict(run=run_id, source=source, tree=tree)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value)+'\n')
    temporary.replace(path)
    return value


def check_inputs(root):
    """Refuse a final tracked edit or HEAD change; untracked products are owned."""
    bound = json.loads((root/'.lane/build-input-binding.json').read_text())
    source, tree = subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', 'HEAD', 'HEAD^{tree}'], text=True).splitlines()
    dirty = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=no'], text=True)
    if bound != dict(run=os.environ.get('PN_BUILDGRAPH_RUN'), source=source, tree=tree) or source != os.environ.get('PN_GATE_SOURCE') or dirty:
        raise ValueError('gate end input mismatch: HEAD='+source+' expected='+str(bound.get('source'))+' tracked='+repr(dirty))
    print('GATE-TREE unchanged=true source='+source+' tree='+tree)


def input_binding(root, graph, step, source, run_id):
    """Retain byte digests only for generated and current-run consumer inputs."""
    bound = json.loads((root/'.lane/build-input-binding.json').read_text())
    if (set(bound) != {'run', 'source', 'tree'} or bound['run'] != run_id or
            bound['source'] != source):
        raise ValueError('stale gate input binding')
    paths = {row['path'] for row in graph['inputs']
             if row.get('producer') and step in row['consumers']}
    paths.update(row['path'] for row in graph.get('products', []) if step in row['consumers'])
    inputs = [(path, hashlib.sha256((root/path).read_bytes()).hexdigest()
               if (root/path).is_file() else None) for path in sorted(paths)]
    return identity(dict(tree=bound['tree'], generated=inputs))


def context(root, graph, step):
    """Bind a command to this invocation, configuration, inputs and completed dependency reports."""
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
    if any(line.split('\t')[0] == step for line in history):
        raise ValueError('step already completed in this invocation: '+step)
    history = bound_history(root, step, history)
    if not graph['inputs']:
        raise ValueError('delegated step has no declared inputs')
    command = next(s['command'] for s in graph['steps'] if s['name'] == step)
    return dict(run=run_id, source=source, step=step, command=command,
                configuration={name: os.environ.get(name) for name in PUBLIC_CONFIGURATION},
                inputs=input_binding(root, graph, step, source, run_id),
                graph=identity(graph), history=identity(history))


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
        status = cancellable(['bash', '-c', request['context']['command']], cwd=root,
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
    required = set(predecessors(root, step))
    for line in (root/'.lane/gate-steps.tsv').read_text().splitlines():
        name, status, _, _ = line.split('\t')
        if name not in delegated or name not in required:
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
    if 'gate-'+step+'.json' not in (build/'build.ninja').read_text():
        raise ValueError('missing configured Meson target: '+step)
    argv = ([sys.executable, '-B', str(root/'ci/build_graph.py'), 'execute', '--root', str(root),
             '--graph', str(build/'gate-graph.json'), '--report', str(output)]
            if os.environ.get('PN_GATE_PARALLEL') == '1' and 'gate_dependencies = {' in (root/'meson.build').read_text() else
            ['ninja', '-C', str(build), str(output.relative_to(build))])
    driver = cancellable(argv,
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


def overrun_class(over, own, baseline, stall, build_cpu, old_build_cpu, changed, policy, *, compile_wall_growth=None, excess=None, wall=None, baseline_wall=None, baseline_stall=None, comparable_cases=True, comparable_wall=True, cache_state=None):
    """Classify warning evidence without changing the functional verdict."""
    if not over: return 'within-budget'
    if cache_state == 'cold': return 'cold-cache'
    unresolved = (type(stall) in (int, float) and 0 <= stall < 1
                  and stall > policy['load_unresolved_pressure_percent']/100)
    fallback = 'load-unresolved' if unresolved else 'unclassified'
    if stall is None: return 'unclassified'
    if wall is None or baseline_wall is None or baseline_stall is None or excess is None: return fallback
    # Remove the baseline's stall before projecting its work into this interval.
    # A pressure fraction is context, not an attribution of CPU to this tier.
    if not 0 <= stall < 1 or not 0 <= baseline_stall < 1: return 'unclassified'
    if comparable_cases and comparable_wall and wall*stall >= excess and wall <= baseline_wall*(1-baseline_stall)/(1-stall): return 'high-stall'
    margin = 1+policy['cpu_growth_percent']/100
    # Comparable CPU has already excluded matched compilation on both sides.
    noncompile = comparable_cases and own is not None and baseline is not None
    remaining = own if noncompile else None
    old_remaining = baseline if noncompile else None
    if (changed and build_cpu is not None and old_build_cpu is not None
            and build_cpu > old_build_cpu*margin
            and compile_wall_growth is not None and excess is not None
            and compile_wall_growth > 0
            and (compile_wall_growth >= excess or
                 (comparable_wall and noncompile and remaining <= old_remaining*margin))):
        return 'rebuild'
    if not comparable_cases or own is None or baseline is None: return fallback
    # Pressure can inflate CPU as well as wall. Without a quiet measurement,
    # the remainder is not attributable to plain work or owned growth.
    if stall > policy['load_unresolved_pressure_percent']/100: return 'load-unresolved'
    if own <= baseline*margin: return 'plain'
    return 'growth'


def baseline_context(root, registry, policy=None):
    """A retained target compares only the same runner configuration and lineage."""
    from harness import CONFIGURATION
    from gate_resources import node_identity
    lineage = os.environ.get('PN_GATE_LINEAGE', 'lane:'+str(root.resolve()))
    identity = dict(configuration=CONFIGURATION, lineage=lineage, tiers=registry.tiers, node=node_identity(),
        profiles=tomllib.loads((root/'Cargo.toml').read_text()).get('profile', {}),
        toolchain=subprocess.run(['rustc', '-Vv'], cwd=root, capture_output=True, text=True, check=True).stdout,
        runtime=dict(python=sys.version, machine=os.uname().machine, flags=os.environ.get('RUSTFLAGS'),
            rustdocflags=os.environ.get('RUSTDOCFLAGS'), services={key:os.environ.get(key) for key in ('PN_POSTGRESQL_BIN', 'PN_ELEMENTS_BIN')}),
        cargo_config=[(str(path), path.read_text()) for directory in (root, *root.parents)
            for path in (directory/'.cargo/config', directory/'.cargo/config.toml') if path.is_file()],
        cargo_home_config=[(name, path.read_text()) for name in ('config', 'config.toml')
            if (path := Path(os.environ.get('CARGO_HOME', str(Path.home()/'.cargo')))/name).is_file()])
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    directory = Path(os.environ['CARGO_TARGET_DIR'])/'gate-baselines'/key
    source = os.environ['PN_GATE_SOURCE']
    tree = subprocess.run(['git', 'rev-parse', source+'^{tree}'], cwd=root,
                          capture_output=True, text=True, check=True).stdout.strip()
    path = directory/(tree+'.json')
    baseline = None
    changed = []
    base = os.environ.get('PN_IMPORT_BASE')
    base_tree = subprocess.run(['git', 'rev-parse', '--verify', base+'^{tree}'], cwd=root,
                              capture_output=True, text=True) if base else None
    candidates = []
    if base_tree and not base_tree.returncode:
        candidates.append(directory/(base_tree.stdout.strip()+'.json'))
    # An explicit import base must match that tree: unrelated green candidates
    # cannot replace it. Without a base, retain the ancestor comparison route.
    else:
        candidates.extend(sorted(directory.glob('*.json'), key=lambda p:p.stat().st_mtime, reverse=True))
    legacy = directory.with_suffix('.json')
    if legacy.exists(): candidates.append(legacy)
    comparisons = {}
    if base_tree and not base_tree.returncode:
        # Follow retained as well as skipped imports, verifying every predecessor
        # in public ancestry. An older, quieter baseline must remain selectable.
        cursor = base_tree.stdout.strip()
        visited = set()
        while cursor not in visited:
            visited.add(cursor)
            try:
                retained = directory/(cursor+'.json')
                if retained.exists():
                    previous = json.loads(retained.read_text()).get('previous_baseline_tree')
                else:
                    previous = json.loads((directory/(cursor+'.skipped.json')).read_text())['previous_tree']
            except (FileNotFoundError, KeyError, ValueError):
                break
            if not previous: break
            history = subprocess.run(['git', 'log', '--format=%H %T', base], cwd=root,
                                     capture_output=True, text=True, check=True).stdout.splitlines()
            matches = [line.split()[0] for line in history if line.split()[-1] == previous]
            if not matches: break
            candidate = directory/(previous+'.json')
            candidates.append(candidate)
            comparisons[candidate] = matches[0]
            cursor = previous
    for candidate in candidates:
        try:
            value = json.loads(candidate.read_text())
            if not quiet_baseline(value, policy): continue
            if base_tree and not base_tree.returncode:
                if candidate in comparisons:
                    comparison = comparisons[candidate]
                    value['match'] = 'previous-quiet-import-tree'
                else:
                    if value.get('tree') != base_tree.stdout.strip(): continue
                    comparison = base
                    value['match'] = 'import-base-tree'
            else:
                ancestor = subprocess.run(['git', 'merge-base', '--is-ancestor', value['source'], source], cwd=root, capture_output=True)
                if ancestor.returncode: continue
                comparison = value['source']
                value['match'] = 'ancestor'
            if baseline is not None and baseline_rank(value) >= baseline_rank(baseline):
                continue
            baseline = value
            diff = subprocess.run(['git', 'diff', '--name-only', comparison, source], cwd=root, capture_output=True, text=True, check=True)
            changed = [name for name in diff.stdout.splitlines() if name in ('Cargo.lock', 'Cargo.toml') or name.endswith('/Cargo.toml') or name.startswith(('packages/', 'vendor/'))]
        except (FileNotFoundError, ValueError, KeyError):
            continue
    return path, baseline, changed


def baseline_stall(candidate):
    """Only observed, finite node-wide whole-gate pressure can rank baselines."""
    whole = candidate.get('whole', {})
    value = whole.get('stall')
    return value if (whole.get('node_scope') == 'node-wide' and type(value) in (int, float)
                     and math.isfinite(value) and 0 <= value < 1) else None


def baseline_rank(candidate):
    """Warm evidence precedes cold or unclassified evidence; stall orders peers."""
    warm = candidate.get('cache', {}).get('state') == 'warm'
    return (not warm, warm and candidate.get('provisional', True), baseline_stall(candidate))


def baseline_replacement(candidate, previous):
    """Quiet admission is checked separately from cache-aware replacement."""
    if previous is None:
        return True, 'first-compatible-run-provisional'
    current = candidate.get('cache', {}).get('state', 'unknown')
    retained = previous.get('cache', {}).get('state', 'unknown')
    if current == 'warm' and (retained != 'warm' or previous.get('provisional', True)):
        return True, 'warm-replaces-cold-or-provisional'
    if retained == 'warm' and current != 'warm':
        return False, 'retained-warm-cache'
    if baseline_stall(candidate) > baseline_stall(previous):
        return False, 'higher-whole-gate-stall'
    return True, 'no-higher-whole-gate-stall'


def quiet_baseline(candidate, policy=None):
    """Passive boundaries admit; observed whole-gate pressure orders replacements."""
    from gate_resources import node_stall
    if baseline_stall(candidate) is None:
        return False
    limit = (policy or candidate)['load_unresolved_pressure_percent']/100
    windows = candidate.get('quiet_windows', {})
    for phase in ('before', 'after'):
        window = windows.get(phase, {})
        value = node_stall(window)
        if (window.get('wall_seconds', 0) < 5 or not isinstance(value, (int, float))
                or not 0 <= value <= limit):
            return False
    return True


def retain_baseline(root):
    """Publish only after the whole invocation is functionally green."""
    candidate = json.loads((root/'.lane/gate-baseline.json').read_text())
    path = Path(candidate.pop('path'))
    previous = candidate.pop('previous_statuses', None)
    candidate['evidence_statuses'] = evidence_statuses(root)
    if previous is None:
        print('GATE-STATUS-CHANGES baseline=unavailable')
    else:
        changes = status_changes(candidate['evidence_statuses'], previous)
        for change in changes:
            print('GATE-STATUS-CHANGE '+json.dumps(change, sort_keys=True))
        print(f'GATE-STATUS-CHANGES count={len(changes)}')
    path.parent.mkdir(parents=True, exist_ok=True)
    retain_step_context(path.parent, candidate)
    prior = []
    for prior_path in (path, path.parent/(str(candidate.get('previous_baseline_tree'))+'.json')):
        try:
            value = json.loads(prior_path.read_text())
            if quiet_baseline(value):
                prior.append(value)
        except (FileNotFoundError, ValueError):
            pass
    previous_best = min(prior, key=baseline_rank) if prior else None
    accepted, reason = baseline_replacement(candidate, previous_best) if quiet_baseline(candidate) else (False, 'load-unresolved')
    candidate_cache = candidate.get('cache', {}).get('state', 'unknown')
    retained_cache = previous_best.get('cache', {}).get('state', 'unknown') if previous_best else 'unavailable'
    if not accepted:
        # Keep the prior quiet file intact, even for a loaded repeat of its tree.
        skipped = path.with_suffix('.skipped.json')
        temporary = skipped.with_suffix('.'+uuid.uuid4().hex+'.tmp')
        temporary.write_text(json.dumps(dict(previous_tree=candidate.get('previous_baseline_tree')))+'\n')
        temporary.replace(skipped)
        print('GATE-BASELINE retained=false reason='+reason+' candidate_cache='+candidate_cache+' retained_cache='+retained_cache+' retained_provisional='+str(previous_best.get('provisional', True) if previous_best else None).lower()+' previous_tree='+str(candidate.get('previous_baseline_tree')))
        return
    candidate['quiet'] = True
    candidate['provisional'] = previous_best is None
    temporary = path.with_suffix('.'+uuid.uuid4().hex+'.tmp')
    temporary.write_text(json.dumps(candidate, sort_keys=True)+'\n')
    temporary.replace(path)
    path.with_suffix('.skipped.json').unlink(missing_ok=True)
    print('GATE-BASELINE retained=true source='+candidate['source']+' candidate_cache='+candidate_cache+' retained_cache='+candidate_cache+' previous_cache='+retained_cache+' reason='+reason+' provisional='+str(candidate['provisional']).lower())


def retain_step_context(directory, candidate):
    """Keep observational context independently of quiet verdict baselines."""
    path = directory/'last-run.context'
    temporary = path.with_suffix('.'+uuid.uuid4().hex+'.tmp')
    temporary.write_text(json.dumps(dict(source=candidate['source'], steps=candidate.get('step_cpu', {})))+'\n')
    temporary.replace(path)


def step_cpu_context(current, previous):
    """No load attribution, budget comparison or verdict follows these deltas."""
    if (not isinstance(previous, dict) or not isinstance(previous.get('source'), str)
            or not isinstance(previous.get('steps'), dict)
            or any(not isinstance(name, str) or value is not None and
                   (type(value) not in (int, float) or not math.isfinite(value) or value < 0)
                   for name, value in previous.get('steps', {}).items())):
        previous = {}
    rows = []
    for name, own in sorted(current.items()):
        old = previous.get('steps', {}).get(name)
        rows.append(dict(step=name, own_cpu_s=own, previous_cpu_s=old,
                         delta_cpu_s=own-old if own is not None and old is not None else None,
                         previous_source=previous.get('source'),
                         attribution='unattributed-context', verdict_effect='none'))
    return rows


def compile_comparison(current, prior, serialized):
    """Compare non-build CPU symmetrically; keep serialized build wall separate."""
    def remaining(name, row):
        own = row.get('own_cpu_s')
        build = row.get('cargo_cpu_s') if row.get('layouts') else own if name in serialized else 0
        return own-build if own is not None and build is not None and 0 <= build <= own else None
    comparable = [name for name, row in current.items() if name in prior and
                  not row.get('partial') and not prior[name].get('partial') and
                  remaining(name, row) is not None and remaining(name, prior[name]) is not None and
                  row.get('layouts') == prior[name].get('layouts')]
    own = sum(remaining(name, current[name]) for name in comparable) if comparable else None
    old = sum(remaining(name, prior[name]) for name in comparable) if comparable else None
    serial = [name for name in comparable if name in serialized]
    growth = sum(current[name]['wall']-prior[name]['wall'] for name in serial) if serial else None
    return own, old, growth, sorted(set(current)-set(comparable))


def status_changes(current, previous):
    """Name changed evidence, including additions and removals, without aggregation."""
    return [dict(kind=kind, name=name, before=previous.get(kind, {}).get(name), after=current.get(kind, {}).get(name))
            for kind in sorted(set(current) | set(previous))
            for name in sorted(set(current.get(kind, {})) | set(previous.get(kind, {})))
            if current.get(kind, {}).get(name) != previous.get(kind, {}).get(name)]


def case_intersection(cases, previous, costs, old_costs, own, old):
    """Remove only printed exclusive-case CPU; missing evidence is unavailable."""
    added, removed = sorted(set(cases)-set(previous)), sorted(set(previous)-set(cases))
    if not added and not removed:
        return own, old, True, dict(added=[], removed=[], own_removed_s=0, baseline_removed_s=0)
    def charge(names, figures):
        values = [figures.get(name) for name in names]
        if any(not isinstance(value, (int, float)) or isinstance(value, bool) or
               not math.isfinite(value) or value < 0 for value in values):
            return None
        return sum(values)
    current_charge, old_charge = charge(added, costs), charge(removed, old_costs)
    evidence = dict(added=added, removed=removed, own_removed_s=current_charge, baseline_removed_s=old_charge)
    if None in (own, old, current_charge, old_charge) or own < current_charge or old < old_charge:
        return None, None, False, evidence
    return own-current_charge, old-old_charge, True, evidence


def evidence_statuses(root):
    """Read only the completed required result union used by the matrix."""
    paths = [root/'.lane/performance-events.jsonl', root/'.lane/harness-benchmarks.jsonl',
             *sorted((root/'.lane').glob('harness-ci-*.jsonl'))]
    cases = {}
    for path in paths:
        for line in path.read_text().splitlines():
            row = json.loads(line)
            if row.get('scope') == 'case':
                if row['operation'] in cases: raise ValueError('duplicate case in baseline evidence')
                cases[row['operation']] = row['outcome']
    evidence = json.loads((root/'.lane/claim-evidence.json').read_text())
    return dict(case=cases, obligation={row['name']:row['status'] for row in evidence['obligations']})


def tier_summary(root, registry, worker_statuses):
    from devperf import budgets
    from gate_resources import cpu_from_log, raw_sample, joined, compact
    declared = budgets(root/'docs/inputs/devperf-budgets.toml')
    policy = declared['gate']
    baseline_path, baseline, changed = baseline_context(root, registry, policy)
    fields = [line.split('\t') for line in (root/'.lane/gate-steps.tsv').read_text().splitlines()]
    step_cpu = {}
    for name, *_ in fields:
        own = cpu_from_log((root/f'.lane/gate-{name}.log').read_text().splitlines())
        step_cpu[name] = sum(own) if all(value is not None for value in own) else None
    if baseline is None:
        try:
            previous = json.loads((baseline_path.parent/'last-run.context').read_text())
        except (FileNotFoundError, ValueError):
            previous = {}
    else:
        previous = dict(source=baseline['source'], steps=baseline.get('step_cpu', {}))
    for row in step_cpu_context(step_cpu, previous):
        name = 'whole-tree-'+row['step']
        if name in declared:
            row.update(cpu_budget_s=declared[name]['budget_ms']/1000,
                       budget=name, provisional=declared[name]['provisional'])
        print('GATE-STEP-CONTEXT '+json.dumps(dict(source=os.environ['PN_GATE_SOURCE'], **row), sort_keys=True), flush=True)
    groups = {name: tier['steps'] for name, tier in registry.tiers.items() if 'steps' in tier}
    groups['finalize'] = registry.tiers['fast']['finalize_steps']
    if Counter(name for group in groups.values() for name in group) != Counter(row[0] for row in fields):
        raise ValueError('tier step partition differs from the exact roster')
    reports = {}
    gate_start = raw_sample(root/'.lane/gate-resource-start.raw')
    selected_cases = {name: [] for name in groups}
    case_costs = {name: {} for name in groups}
    paths = [root/'.lane/performance-events.jsonl', root/'.lane/harness-benchmarks.jsonl',
             *sorted((root/'.lane').glob('harness-ci-*.jsonl'))]
    for path in paths:
        if not path.exists(): continue
        for line in path.read_text().splitlines():
            row = json.loads(line)
            if row.get('scope') == 'case' and row.get('outcome') != 'held' and not row.get('retained'):
                selected_cases.setdefault(row['tier'], []).append(row['operation'])
                cpu = (row.get('own_user_s'), row.get('own_sys_s'))
                valid = all(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 for value in cpu)
                case_costs.setdefault(row['tier'], {})[row['operation']] = sum(cpu) if valid else None
    for tier, names in groups.items():
        selected_rows = [row for row in fields if row[0] in names]
        first = min(selected_rows, key=lambda row: float(row[2]))
        last = max(selected_rows, key=lambda row: float(row[3]))
        start = gate_start if tier == 'fast' else raw_sample(root/f'.lane/gate-{first[0]}-resource-start.raw')
        end = raw_sample(root/f'.lane/gate-{last[0]}-resource-end.raw')
        wall = float(last[3])-(gate_start['epoch_seconds'] if tier == 'fast' else float(first[2]))
        values = [cpu_from_log((root/f'.lane/gate-{row[0]}.log').read_text().splitlines()) for row in selected_rows]
        own = [sum(pair[i] for pair in values) if all(pair[i] is not None for pair in values) else None for i in (0,1)]
        budget = registry.tiers[tier]['invocation_budget'] if tier != 'finalize' else None
        status = int(any(int(row[1]) or worker_statuses[row[0]] for row in selected_rows))
        measurement = joined(start, end, wall)
        reports[tier] = dict(wall=wall, started=start['epoch_seconds'], ended=end['epoch_seconds'], status=status,
            budget=budget, own_user_s=own[0], own_sys_s=own[1], steps=names, resources=measurement)
        limit = declared[budget]['budget_ms']/1000 if budget else None
        excess = max(0.0, wall-limit) if limit is not None else None
        over_budget = excess is not None and excess > 0
        step_figures = {}
        for row, cpu in zip(selected_rows, values):
            log = (root/f'.lane/gate-{row[0]}.log').read_text()
            isolated = [json.loads(line.removeprefix('ISOLATION-COMPILE ')) for line in log.splitlines() if line.startswith('ISOLATION-COMPILE ')]
            isolated = [value for value in isolated if value.get('source') == os.environ['PN_GATE_SOURCE']]
            step_figures[row[0]] = dict(wall=float(row[3])-float(row[2]), own_cpu_s=sum(cpu) if None not in cpu else None,
                cargo_cpu_s=sum(value['cargo_cpu_s'] for value in isolated),
                layouts={value['owner']:value['layout'] for value in isolated},
                partial=any(value.get('cold_target') or value.get('layout_changed') for value in isolated))
        build_cpu = sum(row['cargo_cpu_s'] for row in step_figures.values())
        build_cpu += sum(row['own_cpu_s'] for name, row in step_figures.items() if name in policy['rebuild_steps'] and not row['layouts'] and row['own_cpu_s'] is not None)
        prior = baseline['tiers'].get(tier, {}) if baseline else {}
        cases = sorted(selected_cases[tier])
        comparable_cases = cases == prior.get('selected_cases')
        comparable_wall = comparable_cases
        old_cpu = prior.get('own_cpu_s')
        own_cpu = sum(own) if None not in own else None
        comparable_cpu, comparable_old, wall_growth, omitted = compile_comparison(step_figures, prior.get('step_figures', {}), policy['rebuild_steps'])
        def compile_cpu(figures):
            return sum(row['cargo_cpu_s'] if row['layouts'] else row['own_cpu_s']
                       for name, row in figures.items() if name in step_figures and name not in omitted
                       and (row['layouts'] or name in policy['rebuild_steps']))
        comparable_build = compile_cpu(step_figures) if comparable_cpu is not None else None
        comparable_old_build = compile_cpu(prior.get('step_figures', {})) if comparable_old is not None else None
        intersection = dict(added=[], removed=[], own_removed_s=0, baseline_removed_s=0)
        if not comparable_cases and not omitted:
            comparable_cpu, comparable_old, comparable_cases, intersection = case_intersection(
                cases, prior.get('selected_cases', []), case_costs[tier], prior.get('case_costs', {}), comparable_cpu, comparable_old)
        from gate_resources import node_stall
        stall = node_stall(measurement)
        old_stall = node_stall(prior.get('resources', {}))
        classification = overrun_class(over_budget, comparable_cpu, comparable_old, stall, comparable_build, comparable_old_build, changed, policy,
            compile_wall_growth=wall_growth, excess=excess, wall=wall, baseline_wall=prior.get('wall'),
            baseline_stall=old_stall, comparable_cases=comparable_cases, comparable_wall=comparable_wall)
        if not comparable_cases:
            comparable_cpu = comparable_old = None
        partial_steps = sorted(name for name, row in step_figures.items() if row['partial'])
        reports[tier].update(over_budget=over_budget, excess_s=excess, classification=classification, partial_steps=partial_steps,
            selected_cases=cases, case_costs=case_costs[tier], case_intersection=intersection, comparable_cases=comparable_cases, comparable_wall=comparable_wall,
            comparable_build_cpu_s=comparable_build, baseline_comparable_build_cpu_s=comparable_old_build,
            step_figures=step_figures, non_comparable_steps=omitted, comparable_cpu_s=comparable_cpu, baseline_comparable_cpu_s=comparable_old, compile_wall_growth_s=wall_growth,
            own_cpu_s=own_cpu, build_cpu_s=build_cpu, baseline_source=baseline['source'] if baseline else None,
            baseline_wall_s=prior.get('wall'), baseline_stall=old_stall,
            baseline_tree=baseline.get('tree') if baseline else None, baseline_match=baseline.get('match') if baseline else None,
            baseline_cpu_s=old_cpu, baseline_build_cpu_s=prior.get('build_cpu_s'), changed_build_inputs=changed)
        print(f'GATE-TIER tier={tier} WALL={wall:.6f}s budget_s={limit} verdict={"green" if not status else "red"} comparable_build_cpu_s={comparable_build} baseline_comparable_build_cpu_s={comparable_old_build} '
              f'baseline_wall_s={prior.get("wall")} baseline_stall={old_stall} comparable_cases={str(comparable_cases).lower()} comparable_wall={str(comparable_wall).lower()} case_intersection={json.dumps(intersection,separators=(",",":"))} '
              f'over_budget={str(over_budget).lower()} classification={classification} baseline_source={baseline["source"] if baseline else None} baseline_tree={baseline.get("tree") if baseline else None} baseline_match={baseline.get("match") if baseline else None} baseline_cpu_s={old_cpu} build_cpu_s={build_cpu} baseline_build_cpu_s={prior.get("build_cpu_s")} compile_wall_growth_s={wall_growth} comparable_cpu_s={comparable_cpu} baseline_comparable_cpu_s={comparable_old} partial_steps={json.dumps(partial_steps,separators=(",",":"))} non_comparable_steps={json.dumps(omitted,separators=(",",":"))} changed_build_inputs={json.dumps(changed,separators=(",",":"))} excess_s={excess} own_user_s={own[0]} own_sys_s={own[1]} interval_scope=gate '+compact(measurement), flush=True)
        if budget:
            result = subprocess.run([sys.executable, '-B', 'ci/devperf.py', '--operation', 'tier::'+tier,
                '--duration-s', str(wall), '--outcome', f'exit:{status}', '--source', os.environ['PN_GATE_SOURCE'],
                '--budget', budget, '--overrun-class', classification, '--findings', '.lane/performance-findings.jsonl'], cwd=root)
            if result.returncode: raise ValueError('tier performance reporting refused')
    (root/'.lane/gate-tiers.json').write_text(json.dumps(reports, indent=2)+'\n')
    tree = subprocess.run(['git', 'rev-parse', os.environ['PN_GATE_SOURCE']+'^{tree}'], cwd=root,
                          capture_output=True, text=True, check=True).stdout.strip()
    from gate_resources import node_identity
    from harness import build_cache_state
    cache = build_cache_state(root, os.environ['PN_GATE_SOURCE'], os.environ.get('PN_BUILDGRAPH_RUN'))
    print('GATE-CACHE '+json.dumps(cache, sort_keys=True), flush=True)
    (root/'.lane/gate-baseline.json').write_text(json.dumps(dict(path=str(baseline_path), source=os.environ['PN_GATE_SOURCE'], tree=tree, node=node_identity(), cache=cache,
        lineage=os.environ.get('PN_GATE_LINEAGE', 'lane:'+str(root.resolve())), tiers=reports, step_cpu=step_cpu,
        load_unresolved_pressure_percent=policy['load_unresolved_pressure_percent'],
        previous_baseline_tree=baseline.get('tree') if baseline else None,
        previous_whole=baseline.get('whole') if baseline else None,
        previous_statuses=baseline.get('evidence_statuses') if baseline else None))+'\n')


def wall_summary(root, status, interval=None):
    """Warn on the verdict's measured critical path without changing its exit."""
    from devperf import budgets
    declared = budgets(root/'docs/inputs/devperf-budgets.toml')
    policy, budget = declared['gate'], declared['whole-gate']
    resource_path = root/'.lane/gate-resources.json'
    measured = next((row for row in json.loads(resource_path.read_text()) if row['step'] == 'gate'), None) if resource_path.exists() else None
    if measured is None:
        if interval is None:
            raise ValueError('whole-gate interval is unavailable')
        measured = dict(wall_seconds=interval[1]-interval[0], own_user_s=None, own_sys_s=None,
                        start={'epoch_seconds':interval[0]}, end={'epoch_seconds':interval[1]})
    wall = measured['wall_seconds']
    pending_path = root/'.lane/gate-baseline.json'
    pending = json.loads(pending_path.read_text()) if pending_path.exists() and os.environ.get('PN_GATE_PARALLEL') == '1' else {}
    if pending and pending['source'] != os.environ['PN_GATE_SOURCE']:
        raise ValueError('whole-gate baseline belongs to another source')
    prior = pending.pop('previous_whole', None) or {}
    tiers = pending.get('tiers', {})
    def total(field):
        values = [row.get(field) for row in tiers.values()]
        return sum(values) if values and None not in values else None
    current_cpu = total('comparable_cpu_s')
    prior_cpu = total('baseline_comparable_cpu_s')
    # Keep preparation and result-joining CPU in the whole comparison while
    # retaining the tier comparisons' symmetric cold-owner exclusions.
    current_steps = total('own_user_s')
    current_system = total('own_sys_s')
    prior_steps = total('baseline_cpu_s')
    current_whole = (measured['own_user_s'], measured['own_sys_s'])
    prior_whole = (prior.get('own_user_s'), prior.get('own_sys_s'))
    current_cpu = current_cpu+sum(current_whole)-current_steps-current_system if None not in (*current_whole, current_cpu, current_steps, current_system) else None
    prior_cpu = prior_cpu+sum(prior_whole)-prior_steps if None not in (*prior_whole, prior_cpu, prior_steps) else None
    current_build = total('comparable_build_cpu_s')
    prior_build = total('baseline_comparable_build_cpu_s')
    growths = [row['compile_wall_growth_s'] for row in tiers.values() if row.get('compile_wall_growth_s') is not None]
    growth = sum(growths) if growths else None
    changed = sorted({path for row in tiers.values() for path in row['changed_build_inputs']})
    from gate_resources import node_stall
    stall = node_stall(measured)
    limit = budget['budget_ms']/1000
    excess = max(0.0, wall-limit)
    classification = overrun_class(excess > 0, current_cpu, prior_cpu, stall, current_build, prior_build, changed, policy,
        compile_wall_growth=growth, excess=excess, wall=wall, baseline_wall=prior.get('wall'), baseline_stall=prior.get('stall'),
        cache_state=pending.get('cache', {}).get('state'),
        comparable_cases=bool(tiers) and all(row.get('comparable_cases') for row in tiers.values()),
        comparable_wall=bool(tiers) and all(row.get('comparable_wall', row.get('comparable_cases')) for row in tiers.values()))
    fast = tiers.get('fast', {})
    result = dict(wall=wall, budget_s=limit, excess_s=excess, over_budget=excess > 0, classification=classification,
        status=status, own_user_s=measured['own_user_s'], own_sys_s=measured['own_sys_s'],
        stall=stall, node_scope=measured.get('node_scope', 'unavailable'), baseline_wall=prior.get('wall'), baseline_stall=prior.get('stall'),
        baseline_source=fast.get('baseline_source'), baseline_match=fast.get('baseline_match'),
        comparable_cpu_s=current_cpu, baseline_comparable_cpu_s=prior_cpu,
        comparable_build_cpu_s=current_build, baseline_comparable_build_cpu_s=prior_build,
        compile_wall_growth_s=growth, changed_build_inputs=changed,
        started=measured['start']['epoch_seconds'], ended=measured['end']['epoch_seconds'])
    (root/'.lane/gate-wall.json').write_text(json.dumps(result, indent=2)+'\n')
    if pending:
        pending['whole'] = result
        pending['quiet_windows'] = measured.get('quiet_windows', {})
        pending_path.write_text(json.dumps(pending)+'\n')
    fields = ' '.join(key+'='+(value if isinstance(value, str) else json.dumps(value, separators=(',', ':'))) for key, value in result.items() if key not in {'wall', 'status'})
    print(f'GATE-WALL WALL={wall:.6f}s verdict={"green" if status == 0 else "red"} '+fields, flush=True)
    return subprocess.run([sys.executable, '-B', 'ci/devperf.py', '--operation', 'gate::whole',
        '--duration-s', str(wall), '--outcome', f'exit:{status}', '--source', os.environ['PN_GATE_SOURCE'],
        '--budget', 'whole-gate', '--overrun-class', classification, '--findings', '.lane/performance-findings.jsonl'], cwd=root).returncode

def schedule(root):
    """Bound independent executors; only the scheduler publishes completions."""
    from harness import load
    registry = load()
    jobs = registry.tiers['fast']['jobs']
    if type(jobs) is not int or jobs <= 0:
        raise ValueError('gate jobs must be a positive declared integer')
    commands = dict(roster(root))
    edges = dependencies(root)
    remaining = list(commands)
    completed = set()
    active = {}
    children = {}
    worker_statuses = {}
    failed = 0
    def terminate(number, frame):
        for child in children.values():
            try: os.killpg(child.pid, number)
            except ProcessLookupError: pass
        statuses = [child.wait() for child in children.values()]
        raise SystemExit(2 if any(status not in (0, 128+number) for status in statuses) else 128+number)
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, terminate)
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        while remaining or active:
            for name in list(remaining):
                if len(active) == jobs: break
                if not set(edges[name]) <= completed: continue
                target = 'run_step' if name in SHELL_STEPS else 'run_graph'
                command = f'{target} {name} {commands[name]}; exit "$failed"'
                log = (root/f'.lane/schedule-{name}.log').open('wb')
                child = subprocess.Popen(['bash', '-c',
                    "failed=0; statuses=(); active_pid=; trap 'gate_signal 143' TERM; trap 'gate_signal 130' INT; "+command],
                    cwd=root, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                children[name] = child
                active[pool.submit(child.wait)] = (name, log)
                remaining.remove(name)
            if not active: raise ValueError('dependency graph made no progress')
            done, _ = concurrent.futures.wait(active, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                name, log = active.pop(future)
                log.close()
                worker_statuses[name] = future.result()
                failed |= int(worker_statuses[name] != 0)
                del children[name]
                row = (root/f'.lane/completed-{name}.tsv').read_text()
                with (root/'.lane/gate-steps.tsv').open('a') as output: output.write(row)
                print((root/f'.lane/schedule-{name}.log').read_text(), end='', flush=True)
                completed.add(name)
    tier_summary(root, registry, worker_statuses)
    print(f'BUILD-SCHEDULE jobs={jobs} steps={len(completed)} exactly_once=true')
    return failed


def resource_line(root, line):
    """Enrich entry measurements, never the command's own comparison log."""
    if not line.startswith('STEP=') or os.environ.get('PN_BUILDGRAPH_ROUTE')=='legacy':
        return line
    fields=dict(item.split('=',1) for item in line.split() if '=' in item)
    step=fields['STEP']
    declared={name for name, _ in roster(root)}-SHELL_STEPS
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
    create.add_argument('--root', default='.')
    create.add_argument('--input', action='append', default=[])
    create.add_argument('--step', action='append', default=[])
    create.add_argument('--product', action='append', default=[])
    audit = sub.add_parser('check')
    audit.add_argument('--root', required=True)
    audit.add_argument('--graph', required=True)
    audit.add_argument('--report', required=True)
    sub.add_parser('gate')
    sub.add_parser('bind-inputs')
    sub.add_parser('check-inputs')
    sub.add_parser('plan')
    sub.add_parser('finish')
    sub.add_parser('schedule')
    sub.add_parser('parallel-declared')
    sub.add_parser('tier-wall')
    whole = sub.add_parser('wall-summary')
    whole.add_argument('status', type=int)
    whole.add_argument('interval', nargs=2, type=float)
    sub.add_parser('retain-baseline')
    supervisor = sub.add_parser('supervise')
    supervisor.add_argument('command', nargs=argparse.REMAINDER)
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
    if args.action == 'bind-inputs':
        bind_inputs(Path.cwd())
        return 0
    if args.action == 'check-inputs':
        check_inputs(Path.cwd())
        return 0
    if args.action == 'plan':
        print(plan(Path.cwd()), end='')
        return 0
    if args.action == 'parallel-declared':
        return int('gate_dependencies = {' not in Path('meson.build').read_text())
    if args.action == 'retain-baseline':
        retain_baseline(Path.cwd())
        return 0
    if args.action == 'wall-summary':
        return wall_summary(Path.cwd(), args.status, args.interval)
    if args.action == 'tier-wall':
        print(json.loads(Path('.lane/gate-tiers.json').read_text())['fast']['wall'])
        return 0
    if args.action == 'schedule':
        return schedule(Path.cwd())
    if args.action == 'finish':
        return finish(Path.cwd())
    if args.action == 'supervise':
        result = cancellable(args.command, reap_tree=True)
        return 128-result.returncode if result.returncode < 0 else result.returncode
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
