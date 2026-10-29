"""Retain and compare complete gate evidence without rerunning its commands."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

from build_graph import SHELL_STEPS, identity, read_result, report_path, roster, selected, tracked


# These are execution measurements in harness/claim artifacts, not document data.
MEASUREMENTS = {'duration_ms', 'duration_s', 'utc', 'wall_s', 'duration', 'wall', 'started', 'ended', 'invocation_ms'}
SERVICE_CASE = 'ci::test_linter_entry.Conformance.test_service_ownership'
SERVICE_HOLD = 'ROOT::rule:buildgraph:service-selection'
# Four execution files plus the fixture, declaration helper, selection policy,
# provisioning declaration and registry that decide what the witness exercises.
SERVICE_INPUTS = ('ci/host_postgresql.py', 'ci/wallet_elements.py', 'ci/build_graph.py', 'ci/gate.sh',
                  'ci/build_graph_runtime_witnesses.py', 'ci/build_graph_witnesses.py',
                  'ci/build_graph_evidence.py', 'ci/test_linter_entry.py',
                  'packages/wallet/provisioning.json', 'docs/inputs/harness-registry.toml')


def service_selection(root, admission=False):
    """No cached pass: unchanged-input gates carry a named unexecuted hold."""
    fingerprint = identity([(name, hashlib.sha256((root/name).read_bytes()).hexdigest()) for name in SERVICE_INPUTS])
    changed = []
    for name in SERVICE_INPUTS:
        parent = subprocess.run(['git', '-C', str(root), 'show', 'HEAD^:'+name], capture_output=True)
        if parent.returncode or parent.stdout != (root/name).read_bytes():
            changed.append(name)
    return dict(run=bool(admission or changed), inputs=fingerprint, changed=changed,
                reason='admission requested' if admission else ('service inputs changed' if changed else
                'service ownership held: unchanged inputs; execute on input change or explicit admission request'), hold=SERVICE_HOLD)


def held_service(record, root):
    """Only this registered service case may be held under its current decision."""
    import os
    if record.get('operation') != SERVICE_CASE or record.get('outcome') != 'held':
        return False
    decision = service_selection(root, os.environ.get('PN_BUILDGRAPH_ADMISSION') == '1')
    return (not decision['run'] and record.get('hold') == decision['hold'] and
            record.get('reason') == decision['reason'] and record.get('selection_inputs') == decision['inputs'])


def stable(value):
    if isinstance(value, dict):
        return {key: stable(item) for key, item in value.items() if key not in MEASUREMENTS}
    if isinstance(value, list):
        return [stable(item) for item in value]
    return value


def case_projection(row):
    value = stable(row)
    if value.get('operation', '').startswith('benchmark::'):
        # Retained in the snapshot; these are adaptive measurement observations.
        for key in ('iterations', 'throughput_operations_per_s'):
            value.pop(key, None)
    return value


def capture(root, gate_log):
    root = root.resolve()
    source = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    if subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=no']):
        raise ValueError('retention requires a clean tracked tree')
    lane = root/'.lane'
    graph = json.loads((lane/'build-graph/gate-graph.json').read_text())
    commands = roster(root)
    names = [name for name, _ in commands]
    lines = (lane/'gate-steps.tsv').read_text().splitlines()
    fields = [line.split('\t') for line in lines]
    if any(len(row) != 4 for row in fields) or [row[0] for row in fields] != names:
        raise ValueError('retained roster is incomplete, repeated or out of order')
    if [(row['name'], row['command']) for row in graph['steps']] != commands:
        raise ValueError('retained configured commands differ')
    log = gate_log.read_text()
    verdicts = re.findall(r'^GATE-EXIT=(\d+)$', log, re.M)
    reported = re.findall(r'^STEP=(\S+) STATUS=(\d+) ', log, re.M)
    statuses = [(row[0], row[1]) for row in fields]
    if len(verdicts) != 1 or reported != statuses:
        raise ValueError('gate log does not join its complete status roster')
    if f'BUILD-FINAL steps={len(names)} exactly_once=true delegated={len(selected(root))} fresh=true' not in log:
        raise ValueError('gate lacks its complete final join')
    reports = {}
    configuration = None
    run = None
    for index, (name, status, _, _) in enumerate(fields):
        if name not in selected(root):
            continue
        path = report_path(lane/'build-graph', name)
        data = json.loads(path.read_text())
        request = data['request']
        read_result(path, request)
        context = request['context']
        configuration = context['configuration'] if configuration is None else configuration
        run = context['run'] if run is None else run
        expected = dict(source=source, run=run, configuration=configuration, graph=identity(graph),
                        history=identity(lines[:index]), step=name, command=dict(commands)[name])
        if any(context.get(key) != value for key, value in expected.items()) or data['status'] != int(status):
            raise ValueError('retained report has a stale join: '+name)
        reports[name] = dict(context=context, nonce=request['nonce'], status=data['status'])
    paths = tracked(root)
    documents = {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in paths
                 if name.endswith('.md') or (name.startswith(('docs/', 'adr/')) and name.endswith(('.json', '.toml')))}
    features = {name: (root/name).read_text() for name in paths
                if name.endswith('Cargo.toml') or name in ('Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml', 'ci/nextest.toml')}
    matrix = json.loads((lane/'harness-matrix.json').read_text())
    claims = json.loads((lane/'claim-evidence.json').read_text())
    event_paths = [lane/'performance-events.jsonl', lane/'harness-benchmarks.jsonl', *sorted(lane.glob('harness-ci-*.jsonl'))]
    cases = [stable(row) for path in event_paths for line in path.read_text().splitlines()
             if (row := json.loads(line)).get('scope') == 'case']
    if len({row['operation'] for row in cases}) != len(cases) or any(row['source'] != source for row in cases):
        raise ValueError('retained cases are duplicated or stale')
    cases.sort(key=lambda row: row['operation'])
    if claims['source'] != source or any(row['source'] != source for row in matrix['rows']):
        raise ValueError('retained claim or case source differs')
    # Property observations are a multiset: completion order is not case identity.
    for row in matrix['rows']:
        if 'property_observations' in row:
            row['property_observations'] = sorted(row['property_observations'], key=lambda value: json.dumps(value, sort_keys=True))
    setup = lane/'build-graph/meson-info/meson-info.json'
    actions = re.findall(r'^BUILD-MESON .* action=(\S+)$', (lane/'gate-build-graph.log').read_text(), re.M)
    if len(actions) != 1 or actions[0] not in ('setup', 'reuse'):
        raise ValueError('pair requires one fresh setup or unchanged reuse')
    return dict(schema=1, source=source, roster=commands, statuses=statuses, verdict=int(verdicts[0]),
                configuration=configuration, documents=documents, features=features, matrix=stable(matrix),
                claims=stable(claims), cases=cases, reports=reports, setup=dict(action=actions[0], stamp=setup.stat().st_mtime_ns,
                directory=str(setup.parent.parent), information=json.loads(setup.read_text())))


def compare(first, second):
    if first.get('schema') != 1 or second.get('schema') != 1:
        raise ValueError('unknown retained gate schema')
    for name in ('source', 'roster', 'statuses', 'verdict', 'configuration', 'documents', 'features', 'matrix', 'claims', 'cases'):
        left, right = first.get(name), second.get(name)
        if name == 'cases' and isinstance(left, list) and isinstance(right, list):
            left, right = [case_projection(row) for row in left], [case_projection(row) for row in right]
        if name not in first or left != right:
            raise ValueError('retained gates differ: '+name)
    names = [row[0] for row in first['roster']]
    if len(names) != len(set(names)) or [row[0] for row in first['statuses']] != names:
        raise ValueError('retained roster is not exactly once')
    if first['setup']['action'] != 'setup' or second['setup']['action'] != 'reuse':
        raise ValueError('expected fresh then reused directories')
    for key in ('stamp', 'directory', 'information'):
        if first['setup'][key] != second['setup'][key]:
            raise ValueError('reused directory was reconfigured: '+key)
    if set(first['reports']) != set(names)-SHELL_STEPS or first['reports'].keys() != second['reports'].keys():
        raise ValueError('missing delegated reports')
    for name, report in first['reports'].items():
        later = second['reports'][name]
        if report['nonce'] == later['nonce'] or report['context']['run'] == later['context']['run']:
            raise ValueError('reused evidence is not fresh: '+name)
        # Prefix digests contain timestamps; capture verified each against its own
        # full history. Compare the complete ordered status roster above instead.
        left = {key: value for key, value in report['context'].items() if key not in ('run', 'history')}
        right = {key: value for key, value in later['context'].items() if key not in ('run', 'history')}
        if left != right or report['status'] != later['status']:
            raise ValueError('delegated configuration or status differs: '+name)
    return f'BUILD-EQUIVALENCE steps={len(names)} delegated={len(first["reports"])} roster=equal features=equal cases=equal documents=equal claims=equal statuses=equal verdict={first["verdict"]} fresh=true reused=true'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    retain = commands.add_parser('retain')
    retain.add_argument('destination', type=Path)
    retain.add_argument('--root', type=Path, default=Path.cwd())
    retain.add_argument('--gate-log', type=Path, required=True)
    pair = commands.add_parser('compare')
    pair.add_argument('fresh', type=Path)
    pair.add_argument('reused', type=Path)
    args = parser.parse_args()
    started = time.monotonic()
    try:
        if args.command == 'retain':
            snapshot = capture(args.root, args.gate_log)
            args.destination.write_text(json.dumps(snapshot, sort_keys=True, indent=2)+'\n')
            print(f'BUILD-RETAIN source={snapshot["source"]} steps={len(snapshot["roster"])} state={snapshot["setup"]["action"]} path={args.destination}')
        else:
            print(compare(json.loads(args.fresh.read_text()), json.loads(args.reused.read_text())))
        return 0
    except (KeyError, ValueError, OSError) as error:
        print('BUILD-EQUIVALENCE-REFUSAL '+str(error))
        return 2
    finally:
        print(f'BUILD-EQUIVALENCE-WALL={time.monotonic()-started:.6f}s')


if __name__ == '__main__':
    raise SystemExit(main())
