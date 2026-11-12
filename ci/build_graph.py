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
import shutil
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
        if request['context']['step'] in {'datasets', 'documents', 'determinism-datasets', 'determinism-documents', 'fixed-point-generate', 'fixed-point-write'}:
            log.write(('DOCUMENT-CACHE step='+request['context']['step']+' persistent_hits=0 policy=always-execute internal_hits=unavailable\n').encode())
            log.flush()
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


def series_count():
    rows = tomllib.loads((Path(__file__).resolve().parent.parent/'docs/inputs/devperf-measurements.toml').read_text())['rows']
    return next(row['samples'] for row in rows if row['name'] == 'comparison')


def declare_run(root):
    """Record the invoker's plan before any gate work or outcome exists."""
    from datetime import datetime, timezone
    plan = os.environ.get('PN_GATE_PLAN')
    if plan not in {'one-run', 'warm-after-cold-first', 'warm-after-cold-second', 'refresh-first', 'refresh-second'}:
        raise ValueError('PN_GATE_PLAN must declare one-run, warm-after-cold-first/second or refresh-first/second')
    entry = os.environ.get('PN_GATE_ENTRY', '')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', entry):
        raise ValueError('PN_GATE_ENTRY must name the recorded ledger entry')
    first_cache = os.environ.get('PN_GATE_FIRST_CACHE', 'unavailable')
    if first_cache not in {'cold', 'warm', 'unknown', 'unavailable'}:
        raise ValueError('PN_GATE_FIRST_CACHE has an unknown form')
    if plan == 'refresh-second' and first_cache not in {'cold', 'warm'}:
        raise ValueError('refresh-second requires a complete first cache receipt')
    if plan == 'warm-after-cold-second' and first_cache != 'cold':
        raise ValueError('warm-after-cold-second requires the first observed cache to be cold')
    sample = os.environ.get('PN_GATE_SAMPLE', 'import')
    if sample not in {'import', 'import-transition'}:
        raise ValueError('PN_GATE_SAMPLE must name import or import-transition')
    source = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
    declared = dict(plan=plan, entry=entry, at=datetime.now(timezone.utc).isoformat(), source=source, first_cache=first_cache, sample=sample)
    if sample == 'import-transition':
        from isolation import import_base
        for key in ('PN_GATE_SERIES', 'PN_GATE_ORDINAL', 'PN_IMPORT_BASE', 'PN_GATE_SERIES_KEY', 'PN_GATE_SERIES_CACHE', 'PN_GATE_SERIES_COUNT'):
            if not os.environ.get(key):
                raise ValueError('series requires '+key)
        label, ordinal = os.environ['PN_GATE_SERIES'], os.environ['PN_GATE_ORDINAL']
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', label) or not re.fullmatch(r'[1-9][0-9]*', ordinal):
            raise ValueError('invalid series label or ordinal')
        count = os.environ['PN_GATE_SERIES_COUNT']
        if not re.fullmatch(r'[1-9][0-9]*', count) or int(count) != series_count() or int(ordinal) > int(count):
            raise ValueError('series count must match the declared comparison count and contain the ordinal')
        key, cache = os.environ['PN_GATE_SERIES_KEY'], os.environ['PN_GATE_SERIES_CACHE']
        if not re.fullmatch(r'[0-9a-f]{64}', key) or cache not in {'cold', 'warm'}:
            raise ValueError('invalid series configuration key or cache state')
        declared.update(series=label, ordinal=ordinal, base=import_base(root, source, os.environ['PN_IMPORT_BASE']),
                        configuration_key=key, cache=cache, count=count)
    print('GATE-DECLARED '+' '.join(key+'='+value for key, value in declared.items()), flush=True)
    lane = root/'.lane'
    lane.mkdir(exist_ok=True)
    path = lane/'gate-declaration.json'
    temporary = path.with_suffix('.'+uuid.uuid4().hex+'.tmp')
    temporary.write_text(json.dumps(declared, sort_keys=True)+'\n')
    temporary.replace(path)
    return declared




def series_idle(root, boundary):
    """The host wrapper records account scope outside the build container."""
    identity = {key:os.environ[key] for key in ('PN_GATE_SERIES','PN_GATE_ORDINAL','PN_GATE_ENTRY')}
    processes = subprocess.run(['ps','-u',str(os.getuid()),'-o','pid=,ppid=,args='],capture_output=True,text=True,check=True)
    command = json.loads(os.environ.get('PN_GATE_CONTAINER_LIST', 'null'))
    if not isinstance(command, list) or not command or any(not isinstance(x, str) or not x for x in command):
        raise ValueError('PN_GATE_CONTAINER_LIST must be a nonempty JSON argv')
    containers = subprocess.run(command,capture_output=True,text=True,check=True)
    record = dict(identity=identity, boundary=boundary, at=time.time(),
                  processes=processes.stdout, container_command=command, containers=containers.stdout, load=list(os.getloadavg()))
    path = root/('.lane/gate-series-host-'+boundary+'.json')
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(record,sort_keys=True)+'\n')
    if boundary == 'end':
        result_path=root/'.lane/gate-series-end.json'
        result=json.loads(result_path.read_text()) if result_path.exists() else None
        if result is not None and result['host_idle_start']['identity'] != identity:
            raise ValueError('series idle receipt belongs to another invocation')
        if result is not None:
            result['host_idle_end']=record
            result_path.write_text(json.dumps(result,sort_keys=True)+'\n')
    print('GATE-SERIES-IDLE '+json.dumps(record,sort_keys=True),flush=True)


def series_receipt(root, boundary):
    """Join the declared transition to raw idle and platform observations."""
    declaration = json.loads((root/'.lane/gate-declaration.json').read_text())
    if declaration.get('sample') != 'import-transition':
        return
    def observed(command):
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            return dict(status=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except OSError as error:
            return dict(status='unavailable', reason=str(error))
    record = dict(declaration=declaration, boundary=boundary, run=os.environ['PN_BUILDGRAPH_RUN'],
        tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'], cwd=root, text=True).strip(),
        processes=observed(['ps','-u',str(os.getuid()),'-o','pid=,ppid=,args=']),
        load=list(os.getloadavg()))
    try:
        record['automatic_ports'] = Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().strip()
    except OSError as error:
        record['automatic_ports'] = dict(state='unavailable', reason=str(error))
    record['counters'] = json.loads((root/'.lane/instructions-probe.json').read_text())
    host_idle = json.loads((root/'.lane/gate-series-host-start.json').read_text())
    identity = dict(PN_GATE_SERIES=declaration['series'], PN_GATE_ORDINAL=declaration['ordinal'], PN_GATE_ENTRY=declaration['entry'])
    if host_idle.get('identity') != identity or host_idle.get('boundary') != 'start':
        raise ValueError('series idle receipt belongs to another invocation')
    record['host_idle_start'] = host_idle
    from harness import load
    if reference_key(root, load()) != declaration['configuration_key']:
        raise ValueError('series configuration key differs at start')
    changed = subprocess.check_output(['git','diff','--name-only','--no-renames','--diff-filter=ACMT','-z',declaration['base'],declaration['source']], cwd=root, text=True).split('\0')
    record['changed_files'] = {name:(root/name).stat().st_mtime for name in changed if name}
    if boundary == 'end':
        pending = json.loads((root/'.lane/gate-baseline.json').read_text())
        record['changed_files'] = json.loads((root/'.lane/gate-series-start.json').read_text())['changed_files']
        record['compiled'] = {name:sorted(values,key=lambda x:json.dumps(x,sort_keys=True)) if values is not None else None for name,values in pending['cache']['compiled'].items()}
        record['comparison'] = pending
        record['observed_cache'] = pending['cache']['state']
        record['observed_key'] = Path(pending['path']).parent.name
        record['owners'] = series_owners(root, declaration, record['run'])
        record['whole'] = json.loads((root/'.lane/gate-wall.json').read_text())
        record['status'] = 'complete'
        if any(row['cold_target'] or row['layout_changed'] for row in record['owners']):
            record['status'] = 'refused-owner-target'
        if record['observed_cache'] != declaration['cache'] or record['observed_key'] != declaration['configuration_key']:
            record['status'] = 'refused-identity'
    (root/('.lane/gate-series-'+boundary+'.json')).write_text(json.dumps(record, sort_keys=True)+'\n')
    print('GATE-SERIES '+json.dumps(record, sort_keys=True), flush=True)
    if boundary == 'end' and record['status'] != 'complete':
        raise ValueError('series sample differs from declared configuration, cache or retained owner target')


def series_owners(root, declaration, invocation):
    """Only bound owner transitions of this invocation enter its sample."""
    rows = []
    for path in (root/'.lane').glob('gate-*-transitions.jsonl'):
        binding = json.loads(path.with_suffix('.binding.json').read_text())
        if binding.get('run') != invocation or binding.get('source') != declaration['source']:
            continue
        for line in path.read_text().splitlines():
            row = json.loads(line)
            if any(row.get(key) != binding.get(key) for key in ('run','source','step')):
                raise ValueError('foreign owner transition in bound receipt')
            if row.get('base') != declaration['base']:
                raise ValueError('owner transition differs from series base')
            rows.append(row)
    return rows


# Proposed sampling policy, not a budget or a measured reference value.
SERIES_POLICY = dict(pressure_multiple=2.0, absolute_pressure=0.10, attempts_per_ordinal=3,
                     status='proposed; confirm from the series')


def series_close(root, status):
    """Seal an ended attempt, including a gate that never wrote its end receipt."""
    start = json.loads((root/'.lane/gate-series-host-start.json').read_text())
    end = json.loads((root/'.lane/gate-series-host-end.json').read_text())
    if start['identity'] != end['identity'] or end['at'] < start['at']:
        raise ValueError('attempt idle identities or times disagree')
    declaration_path = root/'.lane/gate-declaration.json'
    declaration = json.loads(declaration_path.read_text()) if declaration_path.exists() else None
    receipt_path = root/'.lane/gate-series-end.json'
    receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else None
    attempt = dict(identity=start['identity'], started=start['at'], ended=end['at'],
                   exit_status=status, declaration=declaration, receipt=receipt)
    path = root/'.lane/series-attempt.json'
    if path.exists():
        raise ValueError('attempt was already closed')
    path.write_text(json.dumps(attempt, sort_keys=True)+'\n')
    print('GATE-SERIES-ATTEMPT '+json.dumps(attempt, sort_keys=True), flush=True)


def series_member(row, first):
    """Validate a completed measurement before it can affect sampling policy."""
    declaration = row['declaration']
    if any(declaration.get(key) != first['declaration'].get(key) for key in
           ('series','base','source','configuration_key','cache','count')) or row.get('tree') != first.get('tree'):
        raise ValueError('series samples disagree on identity')
    if row.get('status') != 'complete' or row.get('observed_key') != declaration['configuration_key'] or row.get('observed_cache') != declaration['cache']:
        raise ValueError('series sample is incomplete or refused')
    if type(row.get('whole', {}).get('status')) is not int or row['whole']['status'] != 0:
        raise ValueError('functional gate was not green')
    identity = dict(PN_GATE_SERIES=declaration['series'], PN_GATE_ORDINAL=declaration['ordinal'], PN_GATE_ENTRY=declaration['entry'])
    for boundary in ('start','end'):
        idle = row.get('host_idle_'+boundary, {})
        if idle.get('identity') != identity or idle.get('boundary') != boundary:
            raise ValueError('series requires both bound idle receipts')
    if not row.get('owners') or any(owner.get('cold_target') is not False or owner.get('layout_changed') is not False
            or owner.get('base') != declaration['base'] or owner.get('source') != declaration['source'] or owner.get('run') != row.get('run') for owner in row['owners']):
        raise ValueError('series owner target is cold, swept, unobserved or foreign')
    pressure = row.get('whole', {}).get('stall')
    if type(pressure) not in (int,float) or not math.isfinite(pressure) or not 0 <= pressure <= 1:
        raise ValueError('series whole pressure is unavailable')
    compiled = row.get('compiled')
    if not isinstance(compiled, dict) or set(compiled) != {'primary','lint'} or any(not isinstance(v,list) for v in compiled.values()):
        raise ValueError('series compilation evidence is unavailable')
    if compiled != first.get('compiled'):
        raise ValueError('series compiled sets differ')
    if not isinstance(row.get('changed_files'), dict) or set(row['changed_files']) != set(first.get('changed_files', {})):
        raise ValueError('series changed-file evidence differs')


def series_check(label, archive):
    """Read every terminal attempt; a later success never displaces a success."""
    import statistics
    attempts = []
    entries = set()
    for directory in archive.iterdir():
        if not directory.is_dir():
            raise ValueError('series archive contains a non-entry path')
        path = directory/'series-attempt.json'
        if not path.exists():
            raise ValueError('series attempt is incomplete; close it before checking: '+directory.name)
        attempt = json.loads(path.read_text())
        identity = attempt['identity']
        entry = identity['PN_GATE_ENTRY']
        if identity['PN_GATE_SERIES'] != label or entry != directory.name or entry in entries:
            raise ValueError('series entry or label is foreign or duplicate')
        entries.add(entry)
        if any(type(attempt.get(k)) not in (int,float) or not math.isfinite(attempt[k]) for k in ('started','ended')) or attempt['ended'] < attempt['started']:
            raise ValueError('series attempt times are invalid')
        if type(attempt.get('exit_status')) is not int:
            raise ValueError('series attempt outcome is incomplete')
        ordinal = int(identity['PN_GATE_ORDINAL'])
        if not 1 <= ordinal <= series_count():
            raise ValueError('series ordinal outside declared count')
        attempts.append((attempt['started'], entry, ordinal, attempt))
    attempts.sort()  # Receipt time decides, never directory order or outcome.
    if not attempts:
        raise ValueError('series has no attempts')
    if len({x[0] for x in attempts}) != len(attempts):
        raise ValueError('series attempt order is ambiguous')
    first = next((a['receipt'] for _,_,_,a in attempts if a.get('receipt')), None)
    if first is None or int(first['declaration']['count']) != series_count():
        raise ValueError('series count or first receipt is unavailable')
    candidates, excluded, counts = {}, [], {}
    previous_end = None
    for started,entry,ordinal,attempt in attempts:
        counts[ordinal] = counts.get(ordinal,0)+1
        if counts[ordinal] > SERIES_POLICY['attempts_per_ordinal']:
            raise ValueError('series attempt cap exceeded at ordinal '+str(ordinal))
        row = attempt.get('receipt')
        try:
            if previous_end is not None and started <= previous_end:
                raise ValueError('series attempts overlap')
            if attempt['exit_status'] != 0:
                raise ValueError('attempt gate or protocol refused')
            if row is None:
                raise ValueError('attempt measurement is incomplete')
            if row['declaration'] != attempt.get('declaration') or row['host_idle_start']['identity'] != attempt['identity']:
                raise ValueError('attempt and measurement disagree')
            series_member(row, first)
            for mtime in row['changed_files'].values():
                if type(mtime) not in (int,float) or not math.isfinite(mtime) or (previous_end is not None and mtime <= previous_end) or mtime > started:
                    raise ValueError('changed file was not reset after previous attempt')
            candidates.setdefault(ordinal, []).append((entry,row))
        except (ValueError, KeyError, TypeError) as error:
            excluded.append(dict(entry=entry, ordinal=ordinal, reason=str(error)))
        previous_end = attempt['ended']
    # Freeze on the first structurally complete set, independently of pressure.
    if set(candidates) != set(range(1,series_count()+1)):
        median = None
    else:
        median = statistics.median(rows[0][1]['whole']['stall'] for rows in candidates.values())
    selected = {}
    if median is not None:
        for ordinal, rows in candidates.items():
            for entry,row in rows:
                pressure = row['whole']['stall']
                reason = ('earlier attempt admitted' if ordinal in selected else
                          'absolute pressure bound' if pressure > SERIES_POLICY['absolute_pressure'] else
                          'frozen median pressure bound' if pressure > median*SERIES_POLICY['pressure_multiple'] else None)
                if reason:
                    excluded.append(dict(entry=entry,ordinal=ordinal,reason=reason))
                else:
                    selected[ordinal] = (entry,row)
    missing = [n for n in range(1,series_count()+1) if n not in (candidates if median is None else selected)]
    exhausted = [n for n in missing if counts.get(n,0) >= SERIES_POLICY['attempts_per_ordinal']]
    pairs = []
    chosen = list(selected.values())
    for index,(left_name,left) in enumerate(chosen):
        for right_name,right in chosen[index+1:]:
            evidence = [left.get('comparison',{}),right.get('comparison',{})]
            pairs.append(dict(entries=[left_name,right_name], stalls=[left['whole']['stall'],right['whole']['stall']],
                              common_work_cpu_s=peer_intersection(evidence),
                              common_work_instructions=peer_intersection(evidence,instructions=True)))
    result = dict(series=label, pairs=pairs, outcome='exhausted' if exhausted else 'incomplete' if median is None else 'repeat' if missing else 'admitted',
        selected={str(n):entry for n,(entry,_) in selected.items()}, excluded=excluded,
        frozen_median=median, policy=SERIES_POLICY, repeat_ordinals=missing, exhausted_ordinals=exhausted,
        samples=[dict(entry=entry,ordinal=n,stall=row['whole']['stall'],compiled=row['compiled']) for n,(entry,row) in selected.items()],
        ceiling=None if median is None or missing else max(row['whole']['stall'] for _,row in selected.values()))
    print('GATE-SERIES-CHECK '+json.dumps(result,sort_keys=True),flush=True)
    return 4 if median is None or missing else 0



def instruction_probe(root):
    """Probe permission before work; never retry a command if its counter fails."""
    executable = shutil.which('perf')
    result = subprocess.run([executable, 'stat', '-e', 'instructions', '--', 'true'], capture_output=True, text=True) if executable else None
    available = result is not None and result.returncode == 0
    path = root/'.lane/instructions-probe.json'
    path.write_text(json.dumps(dict(run=os.environ['PN_BUILDGRAPH_RUN'], executable=executable if available else None,
        reason='available' if available else result.stderr.strip() if result else 'perf executable unavailable'))+'\n')
    print('GATE-INSTRUCTIONS state='+('available' if available else 'unavailable'), flush=True)


def measured_command(root, command):
    """Keep the command's verdict; report unavailable counters without zero substitution."""
    step = os.environ.get('PN_GATE_STEP')
    probe = root/'.lane/instructions-probe.json'
    data = json.loads(probe.read_text()) if probe.exists() else {}
    enabled = bool(step and data.get('executable') and data.get('run') == os.environ.get('PN_BUILDGRAPH_RUN'))
    path = root/('.lane/instructions-'+str(step)+'.csv')
    receipt = root/('.lane/instructions-'+str(step)+'-'+uuid.uuid4().hex+'.status')
    wrapper = [sys.executable, '-B', str(Path(__file__).resolve()), 'counter-work', str(receipt), *command]
    argv = [data['executable'], 'stat', '-x', ';', '-e', 'instructions', '-o', str(path), '--', *wrapper] if enabled else command
    result = cancellable(argv, reap_tree=True)
    if enabled:
        if not receipt.exists():
            # The wrapper writes before starting work. A failed counter open
            # therefore admits one uncounted execution, not a workload retry.
            enabled = False
            if result.returncode >= 0:
                result = cancellable(command, reap_tree=True)
        else:
            try:
                status = json.loads(receipt.read_text()).get('status')
            except (OSError, ValueError, TypeError, AttributeError):
                print('GATE-COUNTER-REFUSED step='+str(step)+' reason=malformed-workload-receipt',flush=True)
                status = None
            result = subprocess.CompletedProcess(command, result.returncode if result.returncode < 0 else status if type(status) is int else 2)
    count = None
    if enabled and path.exists():
        for line in path.read_text().splitlines():
            fields = line.split(';')
            if len(fields) > 2 and fields[2] == 'instructions' and fields[0].strip().isdigit():
                count = int(fields[0])
    print('GATE-INSTRUCTIONS step='+str(step)+' retired='+('unavailable' if count is None else str(count)), flush=True)
    return result



def counter_work(receipt, command):
    """Keep the workload's wait status independently of the counter's exit."""
    receipt.write_text(json.dumps(dict(started=True))+'\n')
    result = cancellable(command, reap_tree=True)
    receipt.write_text(json.dumps(dict(started=True, status=result.returncode))+'\n')
    return 128-result.returncode if result.returncode < 0 else result.returncode


def overrun_class(over, own, baseline, stall, build_cpu, old_build_cpu, changed, policy, *, compile_wall_growth=None, excess=None, wall=None, baseline_wall=None, baseline_stall=None, comparable_cases=True, comparable_wall=True, cache_state=None):
    """Classify warning evidence without changing the functional verdict."""
    if not over: return 'within-budget'
    if cache_state == 'cold': return 'cold-cache'
    valid_stall = type(stall) in (int, float) and math.isfinite(stall) and 0 <= stall < 1
    unresolved = (valid_stall
                  and stall > policy['load_unresolved_pressure_percent']/100)
    fallback = 'load-unresolved' if unresolved else 'unclassified'
    if not valid_stall: return 'unclassified'
    if unresolved: return 'load-unresolved'
    if wall is None or baseline_wall is None or baseline_stall is None or excess is None: return fallback
    # Remove the baseline's stall before projecting its work into this interval.
    # A pressure fraction is context, not an attribution of CPU to this tier.
    if type(baseline_stall) not in (int, float) or not math.isfinite(baseline_stall) or not 0 <= baseline_stall < 1: return fallback
    if comparable_cases and comparable_wall and wall*stall >= excess and wall <= baseline_wall*(1-baseline_stall)/(1-stall): return 'high-stall'
    margin = 1+policy['cpu_growth_percent']/100
    # Comparable CPU has already excluded matched compilation on both sides.
    if (changed and build_cpu is not None and old_build_cpu is not None
            and build_cpu > old_build_cpu*margin
            and compile_wall_growth is not None and excess is not None
            and compile_wall_growth > 0
            and compile_wall_growth >= excess):
        return 'rebuild'
    if not comparable_cases or own is None or baseline is None: return fallback
    # Pressure can inflate CPU as well as wall. Without a quiet measurement,
    # the remainder is not attributable to plain work or owned growth.
    if stall > policy['load_unresolved_pressure_percent']/100: return 'load-unresolved'
    if own <= baseline*margin: return 'plain'
    return 'growth'


def step_context_key(identity):
    """Gross CPU context keeps every compatibility dimension except accounting."""
    context = {key:value for key,value in identity.items() if key not in {'accounting', 'waiting_cpu_wall_ratio'}}
    return hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()


def ancestry_trees(root, base, wanted):
    """Retain only requested trees and stop at the last required ancestor."""
    remaining = set(wanted)
    matches = {}
    if not remaining:
        return matches
    visited = 0
    process = subprocess.Popen(['git', 'log', '--format=%H %T', base], cwd=root,
                               stdout=subprocess.PIPE, text=True)
    try:
        for line in process.stdout:
            commit, tree = line.split()
            visited += 1
            if tree in remaining:
                matches[tree] = commit
                remaining.remove(tree)
                if not remaining:
                    break
        if remaining and process.wait():
            raise ValueError('cannot establish baseline ancestry')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
        process.wait()
    print(f'GATE-PEER-ANCESTRY requested={len(wanted)} matched={len(matches)} visited={visited} exhausted={str(bool(remaining)).lower()}', flush=True)
    return matches


def peer_frontier(records):
    """A cost improvement inside the noise margin cannot erase an incumbent."""
    return list(records)


def prune_peer_archive(archive, ancestry, current_base_tree=None):
    """Prune only after the eligible set and its retained dominators are known."""
    records = []
    removed = 0
    for path in archive.glob('*.json'):
        value = json.loads(path.read_text())
        recorded_base = value.get('import_base_tree')
        if (current_base_tree is not None and value.get('tree') not in ancestry and recorded_base in ancestry
                and recorded_base != current_base_tree):
            path.unlink()
            removed += 1
        else:
            records.append((path, value))
    eligible = [value for _, value in records if value.get('tree') in ancestry]
    # Comparison needs the nearest tree even when an older tree dominates it.
    kept = [member for tree in {value['tree'] for value in eligible}
            for member in peer_frontier([value for value in eligible if value['tree'] == tree])]
    kept.extend(value for _, value in records if value.get('tree') not in ancestry)
    for path, value in records:
        if not any(value is other for other in kept):
            path.unlink()
            removed += 1
    print(f'GATE-PEER-PRUNE removed={removed} retained={len(kept)}', flush=True)


def reference_identity(root, registry):
    from harness import CONFIGURATION
    from gate_resources import node_identity
    lineage = os.environ.get('PN_GATE_LINEAGE', 'lane:'+str(root.resolve()))
    identity = dict(configuration=CONFIGURATION, lineage=lineage, tiers=registry.tiers, node=node_identity(),
        accounting='own-cpu-minus-build-and-owner-window/producing-step/cache-union-v3',
        profiles=tomllib.loads((root/'Cargo.toml').read_text()).get('profile', {}),
        toolchain=subprocess.run(['rustc', '-Vv'], cwd=root, capture_output=True, text=True, check=True).stdout,
        runtime=dict(python=sys.version, machine=os.uname().machine, flags=os.environ.get('RUSTFLAGS'),
            rustdocflags=os.environ.get('RUSTDOCFLAGS'), services={key:os.environ.get(key) for key in ('PN_POSTGRESQL_BIN', 'PN_ELEMENTS_BIN')}),
        cargo_config=[(str(path), path.read_text()) for directory in (root, *root.parents)
            for path in (directory/'.cargo/config', directory/'.cargo/config.toml') if path.is_file()],
        cargo_home_config=[(name, path.read_text()) for name in ('config', 'config.toml')
            if (path := Path(os.environ.get('CARGO_HOME', str(Path.home()/'.cargo')))/name).is_file()])
    return identity


def reference_key(root, registry):
    return hashlib.sha256(json.dumps(reference_identity(root, registry), sort_keys=True).encode()).hexdigest()


def baseline_context(root, registry, policy=None):
    """A retained target compares only the same runner configuration and lineage."""
    selection_started = time.monotonic()
    selection_cpu = [resource.getrusage(kind) for kind in (resource.RUSAGE_SELF,resource.RUSAGE_CHILDREN)]
    identity = reference_identity(root, registry)
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    print('GATE-CONFIGURATION key='+key, flush=True)
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
    peers = sorted((directory/'peers').glob('*.json'))
    if base_tree and not base_tree.returncode:
        # Collect the legacy predecessor chain before one bounded ancestry read.
        cursor = base_tree.stdout.strip()
        visited = set()
        predecessors = []
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
            if not previous:
                break
            predecessors.append(previous)
            cursor = previous
        peer_records = {peer:json.loads(peer.read_text()) for peer in peers}
        peer_trees = {peer:value['tree'] for peer, value in peer_records.items()}
        recorded_bases = {value['import_base_tree'] for value in peer_records.values() if value.get('import_base_tree')}
        history = ancestry_trees(root, base, set(predecessors) | set(peer_trees.values()) | recorded_bases)
        for previous in predecessors:
            if previous not in history:
                break
            candidate = directory/(previous+'.json')
            candidates.append(candidate)
            comparisons[candidate] = history[previous]
        prune_peer_archive(directory/'peers', history, base_tree.stdout.strip())
        for peer, peer_tree in peer_trees.items():
            if peer.exists() and peer_tree in history:
                candidates.append(peer)
                comparisons[peer] = history[peer_tree]
    else:
        history = {}
        for peer in peers:
            value = json.loads(peer.read_text())
            ancestor = subprocess.run(['git', 'merge-base', '--is-ancestor', value['source'], source], cwd=root, capture_output=True)
            if ancestor.returncode == 0:
                history[value['tree']] = value['source']
            elif ancestor.returncode != 1:
                raise ValueError('cannot establish archived source ancestry')
        prune_peer_archive(directory/'peers', history)
        candidates.extend(peer for peer in peers if peer.exists())
    eligible = []
    retained_files = []
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
            eligible.append((value, comparison))
            if candidate.parent == directory:
                retained_files.append(value)
        except (FileNotFoundError, ValueError, KeyError):
            continue
    warm = [(value, comparison) for value, comparison in eligible if value.get('cache', {}).get('state') == 'warm']
    if warm:
        distances = [(int(subprocess.check_output(['git', 'rev-list', '--count', comparison+'..'+source], cwd=root, text=True)), value)
                     for value, comparison in warm]
        nearest = min(distance for distance, _ in distances)
        nearest_peers = [value for distance, value in distances if distance == nearest]
        retained = [value for value in nearest_peers if any(value is row for row in retained_files)]
        baseline = preferred_baseline(retained or nearest_peers)
    else:
        baseline = preferred_baseline([value for value, _ in eligible])
    if baseline is not None:
        comparison = next(comparison for value, comparison in eligible if value is baseline)
        diff = subprocess.run(['git', 'diff', '--name-only', comparison, source], cwd=root, capture_output=True, text=True, check=True)
        changed = [name for name in diff.stdout.splitlines() if name in ('Cargo.lock', 'Cargo.toml') or name.endswith('/Cargo.toml') or name.startswith(('packages/', 'vendor/'))]
        history = subprocess.check_output(['git', 'log', '--format=commit:%H', '--name-only', comparison+'..'+source], cwd=root, text=True)
        print('GATE-COMPARISON '+json.dumps(dict(reference=baseline['source'], intervening_commits_and_inputs=history.splitlines())), flush=True)
        baseline['selection_peers'] = [dict(value) for value, _ in eligible]
    context = Path(os.environ['CARGO_TARGET_DIR'])/'gate-step-context'/step_context_key(identity)
    selection_used = [resource.getrusage(kind) for kind in (resource.RUSAGE_SELF,resource.RUSAGE_CHILDREN)]
    cpu = sum(after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime for before,after in zip(selection_cpu,selection_used))
    from devperf import budgets
    warning = budgets(Path(__file__).resolve().parent.parent/'docs/inputs/devperf-budgets.toml')['whole-tree-build-graph']['budget_ms']/1000
    obsolete = [entry for entry in directory.parent.iterdir() if entry.is_dir() and entry != directory] if directory.parent.exists() else []
    print('GATE-ARCHIVE '+json.dumps(dict(records=len(peers), selection_wall_s=time.monotonic()-selection_started,
        context_own_cpu_s=cpu, context_cpu_warning_s=warning, review_required=cpu>warning,
        comparison='whole-baseline-context-own-cpu-against-whole-build-graph-warning',
        obsolete_keys=len(obsolete), obsolete_records=sum(1 for entry in obsolete for _ in entry.rglob('*.json')),
        obsolete_policy='retained-for-an-explicit-return-to-that-recipe; never-selected-under-current-key',
        growth='retained-frontiers-per-landed-tree')), flush=True)
    return path, baseline, changed, context


def baseline_stall(candidate):
    """Only observed, finite node-wide whole-gate pressure can rank baselines."""
    whole = candidate.get('whole', {})
    value = whole.get('stall')
    return value if (whole.get('node_scope') == 'node-wide' and type(value) in (int, float)
                     and math.isfinite(value) and 0 <= value < 1) else None


def baseline_rank(candidate):
    """Warm evidence precedes cold or unclassified evidence; stall orders peers."""
    warm = candidate.get('cache', {}).get('state') == 'warm'
    return (not warm, False, baseline_stall(candidate))


def baseline_replacement(candidate, previous):
    """Quiet admission is checked separately from cache-aware replacement."""
    if previous is None:
        return True, 'first-compatible-run-provisional'
    current = candidate.get('cache', {}).get('state', 'unknown')
    retained = previous.get('cache', {}).get('state', 'unknown')
    if current == 'warm' and retained != 'warm':
        return True, 'warm-replaces-cold-or-unknown'
    if retained == 'warm' and current != 'warm':
        return False, 'retained-warm-cache'
    if current == retained == 'warm':
        decision = warm_peer_replacement(candidate, previous)
        if decision is not None:
            return decision
    if baseline_stall(candidate) > baseline_stall(previous):
        return False, 'higher-whole-gate-stall'
    return True, 'no-higher-whole-gate-stall'


def peer_domain(value):
    """Only the same recorded case and step domain admits cost dominance."""
    return {name:(row.get('selected_cases'), row.get('case_steps'), row.get('steps'), row.get('non_comparable_steps', []))
            for name, row in value.get('tiers', {}).items()}


def peer_cost(value):
    row = dict(value.get('whole', {}))
    tiers = value.get('tiers', {})
    if tiers and all(tier.get('step_figures') for tier in tiers.values()):
        figures = {name:figure for tier in tiers.values() for name,figure in tier['step_figures'].items()}
        serial = [name for name,figure in figures.items() if figure.get('serialized_build')]
        program, _, _, omitted = compile_comparison(figures, figures, serial)
        raw = [figure.get('own_cpu_s') for figure in figures.values()]
        whole = (row.get('own_user_s'), row.get('own_sys_s'))
        row['comparable_cpu_s'] = (program+sum(whole)-sum(raw)
            if not omitted and None not in (*raw,*whole,program) else None)
    keys = ('wall', 'comparable_cpu_s')
    if any(type(row.get(key)) not in (int, float) or not math.isfinite(row[key]) or row[key] < 0 for key in keys):
        return None
    return tuple(row[key] for key in keys)


def dominates(a, b):
    x, y = peer_cost(a), peer_cost(b)
    return (bool(peer_domain(a)) and peer_domain(a) == peer_domain(b) and x is not None and y is not None
            and all(left <= right for left, right in zip(x,y)) and any(left < right for left, right in zip(x,y)))


def warm_peer_replacement(candidate, previous):
    """Only this candidate and its incumbent determine the common workload."""
    instructions = peer_intersection([previous, candidate], instructions=True)
    costs = instructions if instructions is not None else peer_intersection([previous, candidate])
    if costs is None:
        margin = reference_stall_margin()
        return (margin is not None and baseline_stall(previous)-baseline_stall(candidate) > margin,
                'warm-peer-intersection-unavailable-margin')
    margin = reference_noise_margin()
    if margin is None:
        return False, 'warm-peer-noise-margin-unavailable'
    return (costs[0]-costs[1] > costs[0]*margin,
            'warm-peer-'+('instructions' if instructions is not None else 'cpu')+'-noise-margin')


def reference_noise_margin():
    """Fractional common-work spread, sized by the scheduled quiet series."""
    raw = os.environ.get('PN_GATE_REFERENCE_NOISE_MARGIN')
    if raw is None:
        return None
    value = float(raw)
    if not math.isfinite(value) or not 0 <= value < 1:
        raise ValueError('reference noise margin must be finite and in [0,1)')
    return value


def reference_stall_margin():
    """The series supplies the margin; absence authorizes no replacement."""
    raw = os.environ.get('PN_GATE_REFERENCE_STALL_MARGIN')
    if raw is None:
        return None
    value = float(raw)
    if not math.isfinite(value) or not 0 <= value < 1:
        raise ValueError('reference stall margin must be finite and in [0,1)')
    return value


def peer_intersection(peers, instructions=False):
    """Project the given pair onto common work, counting each step once."""
    receipts = []
    for peer in peers:
        steps = {}
        for tier in peer.get('tiers', {}).values():
            for name, figure in tier.get('step_figures', {}).items():
                cases = {case for case in tier.get('selected_cases', []) if tier.get('case_steps', {}).get(case) == name}
                value = (figure, cases, tier.get('case_costs', {}))
                if name in steps and steps[name] != value:
                    return None
                steps[name] = value
        receipts.append(steps)
    common = set.intersection(*(set(row) for row in receipts)) if receipts else set()
    totals = [0.0 for _ in peers]
    retained = 0
    for name in sorted(common):
        rows = [receipt[name] for receipt in receipts]
        cases = set.intersection(*(row[1] for row in rows))
        if not cases and (any(row[1] for row in rows) or any(
                type(row[0].get('serialized_build')) is not bool or row[0]['serialized_build'] for row in rows)):
            continue
        values = []
        for figure, selected, charges in rows:
            if figure.get('serialized_build',False) != rows[0][0].get('serialized_build',False):
                break
            own, _, _, omitted = compile_comparison({name:figure}, {name:rows[0][0]},
                                                    (name,) if figure.get('serialized_build') else ())
            exclusive = selected-cases
            # Omit this entire step, not the unaffected intersection, when
            # exclusive case clocks could overlap the removed build clock.
            if omitted or exclusive and figure.get('compiled') is not False:
                break
            removed = [charges.get(case) for case in exclusive]
            if any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in removed):
                break
            if own is None or own < sum(removed):
                break
            if instructions:
                count = figure.get('instructions')
                # Step counters cannot supply unmeasured per-case, setup or
                # compilation deductions. Never compare different scopes.
                if (exclusive or figure.get('setup_cpu_s') != 0 or figure.get('cargo_cpu_s') != 0
                        or figure.get('serialized_build') or type(count) is not int or count < 0):
                    return None
                values.append(count)
            else:
                values.append(own-sum(removed))
        if len(values) == len(peers):
            totals = [total+value for total,value in zip(totals,values)]
            retained += len(cases) or 1
        elif instructions:
            return None
    return totals if retained else None


def preferred_baseline(candidates, incumbent=None):
    """Keep the named incumbent; bootstrap by cache, stall and stable identity."""
    if not candidates:
        return None
    rank = min(baseline_rank(value)[:2] for value in candidates)
    peers = [value for value in candidates if baseline_rank(value)[:2] == rank]
    if incumbent is not None and any(value is incumbent for value in peers):
        return incumbent
    return min(peers, key=lambda value:(baseline_stall(value), peer_cost(value) or (float('inf'),float('inf')),
                                      value.get('source',''), value.get('tree',''), json.dumps(value,sort_keys=True)))


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
    retain_step_context(Path(candidate.pop('context_directory', str(path.parent))), candidate)
    prior = [value for value in candidate.pop('previous_peers', []) if quiet_baseline(value)]
    for prior_path in (path, path.parent/(str(candidate.get('previous_baseline_tree'))+'.json')):
        try:
            value = json.loads(prior_path.read_text())
            if quiet_baseline(value):
                prior.append(value)
        except (FileNotFoundError, ValueError):
            pass
    for peer in (path.parent/'peers').glob('*.json'):
        try:
            value = json.loads(peer.read_text())
            if candidate.get('tree') is not None and value.get('tree') == candidate['tree'] and quiet_baseline(value):
                prior.append(value)
        except (OSError, ValueError):
            continue
    incumbent = candidate.pop('previous_reference', None)
    if incumbent is not None:
        prior.append(incumbent)
    else:
        incumbent = next((value for value in prior if value.get('tree') == candidate.get('previous_baseline_tree')), None)
    previous_best = preferred_baseline(prior, incumbent=incumbent)
    candidate['provisional'] = candidate.get('cache', {}).get('state') != 'warm'
    accepted, reason = baseline_replacement(candidate, previous_best) if quiet_baseline(candidate) else (False, 'load-unresolved')
    if quiet_baseline(candidate) and previous_best:
        if candidate.get('cache', {}).get('state') == 'warm' and previous_best.get('cache', {}).get('state') == 'warm':
            if not accepted:
                # Confirmation describes the pair, not which member won it.
                for retained_path in [*path.parent.glob('*.json'), *(path.parent/'peers').glob('*.json')]:
                    try:
                        retained = json.loads(retained_path.read_text())
                    except (OSError, ValueError):
                        continue
                    if retained.get('provisional', True) and (retained.get('source'), retained.get('tree'), retained.get('whole')) == (previous_best.get('source'), previous_best.get('tree'), previous_best.get('whole')):
                        retained['provisional'] = False
                        temporary = retained_path.with_suffix('.'+uuid.uuid4().hex+'.tmp')
                        temporary.write_text(json.dumps(retained, sort_keys=True)+'\n')
                        temporary.replace(retained_path)
                previous_best['provisional'] = False
    candidate_cache = candidate.get('cache', {}).get('state', 'unknown')
    retained_cache = previous_best.get('cache', {}).get('state', 'unknown') if previous_best else 'unavailable'
    if quiet_baseline(candidate) and candidate.get('tree'):
        archive = path.parent/'peers'
        archive.mkdir(exist_ok=True)
        record = dict(candidate, provisional=candidate['provisional'] or previous_best is None, quiet=True)
        temporary = archive/(uuid.uuid4().hex+'.tmp')
        temporary.write_text(json.dumps(record, sort_keys=True)+'\n')
        temporary.replace(temporary.with_suffix('.json'))
    if not accepted:
        # Keep the prior quiet file intact, even for a loaded repeat of its tree.
        skipped = path.with_suffix('.skipped.json')
        temporary = skipped.with_suffix('.'+uuid.uuid4().hex+'.tmp')
        temporary.write_text(json.dumps(dict(previous_tree=candidate.get('previous_baseline_tree')))+'\n')
        temporary.replace(skipped)
        print('GATE-BASELINE retained=false reason='+reason+' candidate_cache='+candidate_cache+' retained_cache='+retained_cache+' retained_provisional='+(str(previous_best.get('provisional', True)).lower() if previous_best else 'unavailable')+' previous_tree='+str(candidate.get('previous_baseline_tree') or 'unavailable'))
        return
    candidate['quiet'] = True
    candidate['provisional'] = candidate['provisional'] or previous_best is None
    temporary = path.with_suffix('.'+uuid.uuid4().hex+'.tmp')
    temporary.write_text(json.dumps(candidate, sort_keys=True)+'\n')
    temporary.replace(path)
    path.with_suffix('.skipped.json').unlink(missing_ok=True)
    print('GATE-BASELINE retained=true source='+candidate['source']+' candidate_cache='+candidate_cache+' retained_cache='+candidate_cache+' previous_cache='+retained_cache+' reason='+reason+' provisional='+str(candidate['provisional']).lower())


def retain_step_context(directory, candidate):
    """Keep observational context independently of quiet verdict baselines."""
    directory.mkdir(parents=True, exist_ok=True)
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
        setup = row.get('setup_cpu_s')
        return own-build-setup if (own is not None and build is not None and setup is not None
                                  and 0 <= build and 0 <= setup and build+setup <= own) else None
    comparable = [name for name, row in current.items() if name in prior and
                  not row.get('partial') and not prior[name].get('partial') and
                  remaining(name, row) is not None and remaining(name, prior[name]) is not None and
                  row.get('layouts') == prior[name].get('layouts')]
    own = sum(remaining(name, current[name]) for name in comparable) if comparable else None
    old = sum(remaining(name, prior[name]) for name in comparable) if comparable else None
    serial = [name for name in comparable if name in serialized]
    growth = sum(current[name]['wall']-prior[name]['wall'] for name in serial) if serial else None
    return own, old, growth, sorted(set(current)-set(comparable))


def setup_accounting(path, source, run, step):
    """Join current invocation receipts; old unmetered setup is unavailable."""
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    for row in rows:
        if row.get('run') != run or row.get('step') != step or row.get('gate_source') != source:
            raise ValueError('stale isolation setup receipt: '+step)
        if row.get('action') != 'owner-window' or any(
                type(row.get(key)) not in (int, float) or not math.isfinite(row[key]) or row[key] < 0
                for key in ('wall', 'own_user_s', 'own_sys_s')):
            raise ValueError('invalid isolation setup receipt: '+step)
    setup = [row for row in rows if row.get('source') == source]
    fixture = [row for row in rows if row.get('source') != source]
    cases = {}
    for row in setup:
        if row.get('case'):
            cases[row['case']] = cases.get(row['case'], 0)+row['own_user_s']+row['own_sys_s']
    return dict(setup_cpu_s=sum(row['own_user_s']+row['own_sys_s'] for row in setup),
                setup_wall_s=sum(row['wall'] for row in setup), setup_calls=len(setup), setup_case_cpu_s=cases,
                fixture_git_cpu_s=sum(row['own_user_s']+row['own_sys_s'] for row in fixture))


def status_changes(current, previous):
    """Name changed evidence, including additions and removals, without aggregation."""
    return [dict(kind=kind, name=name, before=previous.get(kind, {}).get(name), after=current.get(kind, {}).get(name))
            for kind in sorted(set(current) | set(previous))
            for name in sorted(set(current.get(kind, {})) | set(previous.get(kind, {})))
            if current.get(kind, {}).get(name) != previous.get(kind, {}).get(name)]


def case_intersection(cases, previous, costs, old_costs, own, old, *, steps=None, old_steps=None, omitted=(), build_steps=(), old_build_steps=()):
    """Remove only printed exclusive-case CPU; missing evidence is unavailable."""
    added, removed = sorted(set(cases)-set(previous)), sorted(set(previous)-set(cases))
    if not added and not removed:
        return own, old, True, dict(added=[], removed=[], own_removed_s=0, baseline_removed_s=0)
    if (any((steps or {}).get(name) in build_steps for name in added)
            or any((old_steps or {}).get(name) in old_build_steps for name in removed)):
        return None, None, False, dict(added=added, removed=removed, reason='exclusive case may overlap removed build CPU')
    if omitted and (any((steps or {}).get(name) is None or steps[name] in omitted for name in added)
                    or any((old_steps or {}).get(name) is None or old_steps[name] in omitted for name in removed)):
        return None, None, False, dict(added=added, removed=removed, reason='exclusive case belongs to an omitted or unknown step')
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


def case_producer_tier(registry, groups, row):
    """CPU belongs to the executing step even if a case's declared tier differs."""
    if row.get('step') != registry.producing_step(row['operation']):
        raise ValueError('case producing step differs: '+row['operation'])
    tiers = [tier for tier, steps in groups.items() if row['step'] in steps]
    if len(tiers) != 1:
        raise ValueError('case producing step has no unique accounting tier: '+row['operation'])
    return tiers[0]


def tier_wall_ownership(wall, intervals):
    """Subtract the interval union, not overlapping step durations, from wall."""
    ordered = sorted(intervals)
    total = sum(end-start for start,end in ordered)
    covered = 0.0
    previous = None
    for start,end in ordered:
        if end < start:
            raise ValueError('step ends before it starts')
        covered += max(0, end-max(start, previous if previous is not None else start))
        previous = max(end, previous if previous is not None else end)
    if covered > wall+.000001:
        raise ValueError('step interval union exceeds the tier wall')
    return dict(step_wall_sum_s=total, step_wall_union_s=covered, unowned_wall_s=max(0.0,wall-covered))


def largest_tier_gap(rows):
    """Name the two tier steps bounding its largest uncovered interval."""
    frontier = None
    largest = dict(wall_s=0.0, after=None, before=None)
    for name,start,end in sorted(rows,key=lambda row:(row[1],row[2],row[0])):
        if frontier is not None and start-frontier[0] > largest['wall_s']:
            largest = dict(wall_s=start-frontier[0],after=frontier[1],before=name)
        if frontier is None or end > frontier[0]:
            frontier = (end,name)
    return largest


def tier_summary(root, registry, worker_statuses):
    from devperf import budgets
    from gate_resources import cpu_from_log, raw_sample, joined, compact
    declared = budgets(root/'docs/inputs/devperf-budgets.toml')
    policy = declared['gate']
    baseline_path, baseline, changed, context_directory = baseline_context(root, registry, policy)
    fields = [line.split('\t') for line in (root/'.lane/gate-steps.tsv').read_text().splitlines()]
    step_cpu = {}
    for name, *_ in fields:
        own = cpu_from_log((root/f'.lane/gate-{name}.log').read_text().splitlines())
        step_cpu[name] = sum(own) if all(value is not None for value in own) else None
    if baseline is None:
        try:
            context_path = context_directory/'last-run.context'
            if not context_path.exists():
                # First use migrates the pre-split context of this same identity.
                context_path = baseline_path.parent/'last-run.context'
            previous = json.loads(context_path.read_text())
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
    selected_cases = {name: [] for name in groups}
    case_costs = {name: {} for name in groups}
    case_steps = {name: {} for name in groups}
    paths = [root/'.lane/performance-events.jsonl', root/'.lane/harness-benchmarks.jsonl',
             *sorted((root/'.lane').glob('harness-ci-*.jsonl'))]
    for path in paths:
        if not path.exists(): continue
        for line in path.read_text().splitlines():
            row = json.loads(line)
            if row.get('scope') == 'case' and row.get('outcome') != 'held' and not row.get('retained'):
                producing_tier = case_producer_tier(registry, groups, row)
                case_steps[producing_tier][row['operation']] = row['step']
                selected_cases[producing_tier].append(row['operation'])
                cpu = (row.get('own_user_s'), row.get('own_sys_s'))
                valid = all(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 for value in cpu)
                case_costs[producing_tier][row['operation']] = sum(cpu) if valid else None
    from harness import build_cache_state
    cache = build_cache_state(root, os.environ['PN_GATE_SOURCE'], os.environ.get('PN_BUILDGRAPH_RUN'))
    for tier, names in groups.items():
        selected_rows = [row for row in fields if row[0] in names]
        first = min(selected_rows, key=lambda row: float(row[2]))
        last = max(selected_rows, key=lambda row: float(row[3]))
        start = raw_sample(root/f'.lane/gate-{first[0]}-resource-start.raw')
        end = raw_sample(root/f'.lane/gate-{last[0]}-resource-end.raw')
        wall = float(last[3])-float(first[2])
        values = [cpu_from_log((root/f'.lane/gate-{row[0]}.log').read_text().splitlines()) for row in selected_rows]
        own = [sum(pair[i] for pair in values) if all(pair[i] is not None for pair in values) else None for i in (0,1)]
        budget = registry.tiers[tier]['invocation_budget'] if tier != 'finalize' else None
        status = int(any(int(row[1]) or worker_statuses[row[0]] for row in selected_rows))
        measurement = joined(start, end, wall)
        gap = largest_tier_gap([(row[0],float(row[2]),float(row[3])) for row in selected_rows])
        ownership = tier_wall_ownership(wall, [(float(row[2]),float(row[3])) for row in selected_rows])
        reports[tier] = dict(**ownership, wall=wall, started=start['epoch_seconds'], ended=end['epoch_seconds'], status=status,
            budget=budget, own_user_s=own[0], own_sys_s=own[1], steps=names, resources=measurement)
        limit = declared[budget]['budget_ms']/1000 if budget else None
        excess = max(0.0, wall-limit) if limit is not None else None
        over_budget = excess is not None and excess > 0
        step_figures = {}
        isolated_compiling_steps = []
        for row, cpu in zip(selected_rows, values):
            log = (root/f'.lane/gate-{row[0]}.log').read_text()
            isolated = [json.loads(line.removeprefix('ISOLATION-COMPILE ')) for line in log.splitlines() if line.startswith('ISOLATION-COMPILE ')]
            isolated = [value for value in isolated if value.get('source') == os.environ['PN_GATE_SOURCE']]
            isolated_compiling_steps.extend(dict(step=row[0], owner=value['owner'], cold_target=value['cold_target']) for value in isolated)
            step_figures[row[0]] = dict(wall=float(row[3])-float(row[2]), own_cpu_s=sum(cpu) if None not in cpu else None,
                serialized_build=row[0] in policy['rebuild_steps'],
                compiled=(True if row[0] in cache.get('compiling_steps', []) or any(value.get('compiled') for value in isolated) else
                    False if isolated or (row[0] in ('test-build','clippy') and cache.get('state') in ('cold','warm')) or row[0] not in policy['rebuild_steps'] else None),
                cargo_cpu_s=sum(value['cargo_cpu_s'] for value in isolated),
                layouts={value['owner']:value['layout'] for value in isolated},
                partial=any(value.get('cold_target') or value.get('layout_changed') for value in isolated))
            setup = setup_accounting(root/f'.lane/gate-{row[0]}-setup.jsonl', os.environ['PN_GATE_SOURCE'],
                                     os.environ['PN_BUILDGRAPH_RUN'], row[0])
            step_figures[row[0]].update(setup)
            counter = re.findall(r'^GATE-INSTRUCTIONS step='+re.escape(row[0])+r' retired=(\d+|unavailable)$', log, re.M)
            step_figures[row[0]]['instructions'] = int(counter[-1]) if counter and counter[-1].isdigit() else None
            wall_seconds = step_figures[row[0]]['wall']
            ratio = sum(cpu)/wall_seconds if None not in cpu and wall_seconds > 0 else None
            step_figures[row[0]].update(cpu_wall_ratio=ratio)
            print('GATE-STEP-COST '+json.dumps(dict(step=row[0], cpu_wall_ratio=ratio,
                exclusion='none', attribution='unattributed-context')), flush=True)
            for case, charge in setup['setup_case_cpu_s'].items():
                cost = case_costs[tier].get(case)
                if cost is not None:
                    # Millisecond child accounting can round below the setup
                    # clock by one tick; never turn unavailable CPU into zero.
                    if charge > cost+.002:
                        raise ValueError('case setup exceeds its own CPU: '+case)
                    case_costs[tier][case] = max(0, cost-charge)
            print('GATE-SETUP '+json.dumps(dict(step=row[0], **setup), sort_keys=True), flush=True)
        build_cpu = sum(row['cargo_cpu_s'] for row in step_figures.values())
        build_cpu += sum(row['own_cpu_s'] for name, row in step_figures.items() if name in policy['rebuild_steps'] and not row['layouts'] and row['own_cpu_s'] is not None)
        prior = baseline['tiers'].get(tier, {}) if baseline else {}
        cases = sorted(selected_cases[tier])
        comparable_cases = cases == prior.get('selected_cases')
        comparable_wall = comparable_cases
        old_cpu = prior.get('own_cpu_s')
        own_cpu = sum(own) if None not in own else None
        comparable_cpu, comparable_old, wall_growth, omitted = compile_comparison(step_figures, prior.get('step_figures', {}), policy['rebuild_steps'])
        if not baseline:
            comparable_cpu, _, _, omitted = compile_comparison(step_figures, step_figures, policy['rebuild_steps'])
        def compile_cpu(figures):
            return sum(row['cargo_cpu_s'] if row['layouts'] else row['own_cpu_s']
                       for name, row in figures.items() if name in step_figures and name not in omitted
                       and (row['layouts'] or name in policy['rebuild_steps']))
        comparable_build = compile_cpu(step_figures) if comparable_cpu is not None else None
        comparable_old_build = compile_cpu(prior.get('step_figures', {})) if comparable_old is not None else None
        comparable_setup = sum(row['setup_cpu_s'] for name, row in step_figures.items() if name not in omitted) if comparable_cpu is not None else None
        comparable_old_setup = sum(row['setup_cpu_s'] for name, row in prior.get('step_figures', {}).items() if name in step_figures and name not in omitted) if comparable_old is not None else None
        intersection = dict(added=[], removed=[], own_removed_s=0, baseline_removed_s=0)
        if not comparable_cases and baseline:
            comparable_cpu, comparable_old, comparable_cases, intersection = case_intersection(
                cases, prior.get('selected_cases', []), case_costs[tier], prior.get('case_costs', {}), comparable_cpu, comparable_old,
                steps=case_steps[tier], old_steps=prior.get('case_steps', {}),
                build_steps={name for name, row in step_figures.items() if row.get('compiled') is not False},
                old_build_steps={name for name, row in prior.get('step_figures', {}).items() if row.get('compiled') is not False},
                omitted=set(omitted) | (set(prior.get('step_figures', {}))-set(step_figures)))
        from gate_resources import node_stall
        stall = node_stall(measurement)
        old_stall = node_stall(prior.get('resources', {}))
        compiled_steps = [name for name in names if name in cache.get('compiling_steps', [])]
        tier_cache = cache['state'] if compiled_steps else 'not-compiling'
        classification = overrun_class(over_budget, comparable_cpu, comparable_old, stall, comparable_build, comparable_old_build, changed, policy,
            compile_wall_growth=wall_growth, excess=excess, wall=wall, baseline_wall=prior.get('wall'),
            baseline_stall=old_stall, comparable_cases=comparable_cases, comparable_wall=comparable_wall, cache_state=tier_cache)
        if not comparable_cases and baseline:
            comparable_cpu = comparable_old = None
        partial_steps = sorted(name for name, row in step_figures.items() if row['partial'])
        reports[tier].update(cache_state=cache['state'], compiling_steps=compiled_steps, isolated_compiling_steps=isolated_compiling_steps, over_budget=over_budget, excess_s=excess, classification=classification, partial_steps=partial_steps,
            selected_cases=cases, case_costs=case_costs[tier], case_steps=case_steps[tier], case_intersection=intersection, comparable_cases=comparable_cases, comparable_wall=comparable_wall,
            comparable_build_cpu_s=comparable_build, baseline_comparable_build_cpu_s=comparable_old_build,
            comparable_setup_cpu_s=comparable_setup, baseline_comparable_setup_cpu_s=comparable_old_setup,
            step_figures=step_figures, non_comparable_steps=omitted, comparable_reason='available' if comparable_cpu is not None else 'missing-or-incompatible-step-or-case-measurements', comparable_cpu_s=comparable_cpu, baseline_comparable_cpu_s=comparable_old, compile_wall_growth_s=wall_growth,
            own_cpu_s=own_cpu, build_cpu_s=build_cpu, baseline_source=baseline['source'] if baseline else None,
            baseline_provisional=baseline.get('provisional', True) if baseline else None,
            baseline_wall_s=prior.get('wall'), baseline_stall=old_stall,
            baseline_tree=baseline.get('tree') if baseline else None, baseline_match=baseline.get('match') if baseline else None,
            baseline_cpu_s=old_cpu, baseline_build_cpu_s=prior.get('build_cpu_s'), changed_build_inputs=changed)
        print(f'GATE-TIER tier={tier} cache_state={cache["state"]} compiling_steps={json.dumps(compiled_steps,separators=(",",":"))} isolated_compiling_steps={json.dumps(isolated_compiling_steps,separators=(",",":"))} WALL={wall:.6f}s step_wall_sum_s={ownership["step_wall_sum_s"]:.6f} step_wall_union_s={ownership["step_wall_union_s"]:.6f} unowned_wall_s={ownership["unowned_wall_s"]:.6f} largest_unowned_gap={json.dumps(gap,separators=(",",":"))} budget_s={limit} verdict={"green" if not status else "red"} comparable_build_cpu_s={comparable_build} baseline_comparable_build_cpu_s={comparable_old_build} comparable_setup_cpu_s={comparable_setup} baseline_comparable_setup_cpu_s={comparable_old_setup} '
              f'baseline_wall_s={prior.get("wall")} baseline_stall={old_stall} comparable_cases={str(comparable_cases).lower()} comparable_wall={str(comparable_wall).lower()} case_intersection={json.dumps(intersection,separators=(",",":"))} '
              f'over_budget={str(over_budget).lower()} classification={classification} baseline_source={baseline["source"] if baseline else None} baseline_provisional={str(baseline.get("provisional", True)).lower() if baseline else "unavailable"} baseline_tree={baseline.get("tree") if baseline else None} baseline_match={baseline.get("match") if baseline else None} baseline_cpu_s={old_cpu} build_cpu_s={build_cpu} baseline_build_cpu_s={prior.get("build_cpu_s")} compile_wall_growth_s={wall_growth} comparable_cpu_s={comparable_cpu} comparable_reason={reports[tier]['comparable_reason']} baseline_comparable_cpu_s={comparable_old} partial_steps={json.dumps(partial_steps,separators=(",",":"))} non_comparable_steps={json.dumps(omitted,separators=(",",":"))} changed_build_inputs={json.dumps(changed,separators=(",",":"))} excess_s={excess} own_user_s={own[0]} own_sys_s={own[1]} interval_scope=gate '+compact(measurement), flush=True)
        if budget:
            result = subprocess.run([sys.executable, '-B', 'ci/devperf.py', '--operation', 'tier::'+tier,
                '--duration-s', str(wall), '--outcome', f'exit:{status}', '--source', os.environ['PN_GATE_SOURCE'],
                '--budget', budget, '--overrun-class', classification, '--findings', '.lane/performance-findings.jsonl'], cwd=root)
            if result.returncode: raise ValueError('tier performance reporting refused')
    (root/'.lane/gate-tiers.json').write_text(json.dumps(reports, indent=2)+'\n')
    tree = subprocess.run(['git', 'rev-parse', os.environ['PN_GATE_SOURCE']+'^{tree}'], cwd=root,
                          capture_output=True, text=True, check=True).stdout.strip()
    import_base = os.environ.get('PN_IMPORT_BASE')
    import_base_tree = subprocess.run(['git', 'rev-parse', import_base+'^{tree}'], cwd=root,
                                     capture_output=True, text=True, check=True).stdout.strip() if import_base else None
    from gate_resources import node_identity
    print('GATE-CACHE '+json.dumps(cache, sort_keys=True), flush=True)
    (root/'.lane/gate-baseline.json').write_text(json.dumps(dict(path=str(baseline_path), context_directory=str(context_directory), source=os.environ['PN_GATE_SOURCE'], tree=tree, node=node_identity(), cache=cache,
        lineage=os.environ.get('PN_GATE_LINEAGE', 'lane:'+str(root.resolve())), import_base_tree=import_base_tree, tiers=reports, step_cpu=step_cpu,
        load_unresolved_pressure_percent=policy['load_unresolved_pressure_percent'],
        previous_baseline_tree=baseline.get('tree') if baseline else None,
        previous_reference={key:value for key,value in baseline.items() if key != 'selection_peers'} if baseline else None,
        previous_peers=baseline.get('selection_peers', []) if baseline else [],
        previous_whole=baseline.get('whole') if baseline else None,
        previous_statuses=baseline.get('evidence_statuses') if baseline else None))+'\n')


def quiet_repeat(source, tree, scope, measurement, budget, compiling):
    """Describe owed evidence; do not schedule or change a functional verdict."""
    if measurement.get('classification') != 'load-unresolved':
        return None
    share = .10
    excess = measurement.get('excess_s', 0)
    return dict(source=source, tree=tree, scope=scope, plan='one-run', entry='new-ledger-entry',
                node='account-batteries-and-containers-idle;quiet-boundaries-and-whole-window-recorded',
                required=bool(compiling) or budget is not None and excess > budget*share,
                excess_share=share, share_status='proposal-for-series-confirmation',
                compiling_steps=compiling, purpose='cost-versus-load', schedules='nothing')


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
    timing_path = root/'.lane/gate-steps.tsv'
    intervals = [line.split('\t') for line in timing_path.read_text().splitlines()] if timing_path.exists() else []
    preparation = min(float(row[2]) for row in intervals)-measured['start']['epoch_seconds'] if intervals else None
    closing = measured['end']['epoch_seconds']-max(float(row[3]) for row in intervals) if intervals else None
    result = dict(wall=wall, budget_s=limit, excess_s=excess, over_budget=excess > 0, classification=classification,
        preparation_s=preparation, step_span_s=wall-preparation-closing if None not in (preparation, closing) else None, closing_s=closing,
        status=status, own_user_s=measured['own_user_s'], own_sys_s=measured['own_sys_s'],
        stall=stall, node_scope=measured.get('node_scope', 'unavailable'), baseline_wall=prior.get('wall'), baseline_stall=prior.get('stall'),
        baseline_source=fast.get('baseline_source'), baseline_provisional=fast.get('baseline_provisional'), baseline_match=fast.get('baseline_match'),
        comparable_cpu_s=current_cpu, comparable_reason='available' if current_cpu is not None else 'missing-or-incompatible-step-case-or-resource-measurements', baseline_comparable_cpu_s=prior_cpu,
        comparable_build_cpu_s=current_build, baseline_comparable_build_cpu_s=prior_build,
        comparable_setup_cpu_s=total('comparable_setup_cpu_s'), baseline_comparable_setup_cpu_s=total('baseline_comparable_setup_cpu_s'),
        compile_wall_growth_s=growth, changed_build_inputs=changed,
        started=measured['start']['epoch_seconds'], ended=measured['end']['epoch_seconds'])
    (root/'.lane/gate-wall.json').write_text(json.dumps(result, indent=2)+'\n')
    if pending:
        pending['whole'] = result
        pending['quiet_windows'] = measured.get('quiet_windows', {})
        pending_path.write_text(json.dumps(pending)+'\n')
    fields = ' '.join(key+'='+('unavailable' if key == 'baseline_provisional' and value is None else
                     value if isinstance(value, str) else json.dumps(value, separators=(',', ':')))
                     for key, value in result.items() if key not in {'wall', 'status'})
    print(f'GATE-WALL WALL={wall:.6f}s verdict={"green" if status == 0 else "red"} '+fields, flush=True)
    for scope, measurement in [('whole', result), *tiers.items()]:
        ceiling = limit if scope == 'whole' else declared[measurement['budget']]['budget_ms']/1000 if measurement.get('budget') else None
        compiling = (pending.get('cache', {}).get('compiling_steps', []) if scope == 'whole'
                     else measurement.get('compiling_steps', []))
        compiling = sorted(set(compiling) | {step for row in (tiers.values() if scope == 'whole' else [measurement])
                           for step, figure in row.get('step_figures', {}).items() if figure.get('compiled')})
        repeat = quiet_repeat(os.environ['PN_GATE_SOURCE'], pending.get('tree'), scope, measurement, ceiling, compiling)
        if repeat is not None:
            print('GATE-QUIET-REPEAT '+json.dumps(repeat, sort_keys=True), flush=True)
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
    sub.add_parser('declare')
    sub.add_parser('instruction-probe')
    sub.add_parser('series-key')
    check_series = sub.add_parser('series-check')
    check_series.add_argument('label')
    check_series.add_argument('archive', type=Path)
    close_series = sub.add_parser('series-close')
    close_series.add_argument('status', type=int)
    counted = sub.add_parser('counter-work')
    counted.add_argument('receipt')
    counted.add_argument('command', nargs=argparse.REMAINDER)
    idle = sub.add_parser('series-idle')
    idle.add_argument('boundary', choices=('start','end'))
    series = sub.add_parser('series-receipt')
    series.add_argument('boundary', choices=('start','end'))
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
    if args.action == 'series-key':
        from harness import load
        print(reference_key(Path.cwd(), load()))
        return 0
    if args.action == 'series-check':
        try:
            return series_check(args.label, args.archive)
        except (OSError, ValueError, KeyError, TypeError) as error:
            print('GATE-SERIES-REFUSED '+str(error), flush=True)
            return 4
    if args.action == 'declare':
        declare_run(Path.cwd())
        return 0
    if args.action == 'series-close':
        series_close(Path.cwd(), args.status)
        return 0
    if args.action == 'series-idle':
        series_idle(Path.cwd(), args.boundary)
        return 0
    if args.action == 'series-receipt':
        try:
            series_receipt(Path.cwd(), args.boundary)
            return 0
        except (OSError, ValueError, KeyError, TypeError) as error:
            print('GATE-SERIES-REFUSED '+str(error), flush=True)
            return 4
    if args.action == 'counter-work':
        return counter_work(Path(args.receipt), args.command)
    if args.action == 'instruction-probe':
        instruction_probe(Path.cwd())
        return 0
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
        result = measured_command(Path.cwd(), args.command)
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
