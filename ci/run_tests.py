"""Build once, run nextest without retries, and retain a separate doctest path.

Raw evidence is retained under .lane/performance/<run id>. Both nextest and
rustdoc JSON exec_time fields are seconds; normalized duration_ms is milliseconds.
The reporter reads normalized events; it cannot control the execution roster.
"""

import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from devperf import StructuralError, inclusive_ms, number
from harness import CONFIGURATION, load as load_registry


def instant():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def event(operation, budget, duration_ms, outcome, source, configuration):
    return dict(operation=operation, budget=budget, duration_ms=duration_ms,
                outcome=outcome, source=source, configuration=configuration,
                owner='foundation implementer', utc=instant(), scope='operation', level='operation',
                suite='gate-operations', implementation='repository-tools', tier='fast',
                evidence='tooling', applicable_budgets=[budget, 'gate'])


def milliseconds(value):
    if value is None:
        return None
    if not number(value):
        raise StructuralError('malformed exec_time; expected finite nonnegative seconds')
    return value * 1000


def nextest_events(text, inventory, metadata, source, configuration, registry=None):
    registry = registry or load_registry()
    expected = {}
    for binary, suite in inventory['rust-suites'].items():
        for name, details in suite['testcases'].items():
            raw_name = f"{suite['package-name']}::{suite['binary-name']}${name}"
            if raw_name in expected:
                raise StructuralError(f'ambiguous structured test identity: {raw_name}')
            operation = f'{binary}::{name}'
            if operation not in registry.cases:
                raise StructuralError(f'unregistered case: {operation}')
            level = registry.levels[registry.cases[operation]['level']]['budget']
            expected[raw_name] = (operation, level, details['ignored'])
    registry.roster('nextest', [v[0] for v in expected.values()])
    records = []
    seen = set()
    started = set()
    for line in text.splitlines():
        item = json.loads(line)
        if item.get('type') != 'test':
            continue
        key = item['name']
        if key not in expected:
            raise StructuralError(f'unknown test result: {key}')
        if item['event'] == 'started':
            if key in started:
                raise StructuralError(f'repeated execution start: {key}')
            started.add(key)
            continue
        if key in seen or item['event'] not in {'ok', 'failed', 'ignored'}:
            raise StructuralError(f'duplicate or unknown test outcome: {key}')
        seen.add(key)
        operation, level, ignored = expected[key]
        duration = item.get('exec_time')
        records.append(event(operation, level, milliseconds(duration),
                             {'ok': 'passed', 'failed': 'failed', 'ignored': 'ignored'}[item['event']], source, configuration))
    for key, (operation, level, ignored) in expected.items():
        if key not in seen:
            records.append(event(operation, level, None, 'ignored' if ignored else 'incomplete', source, configuration))
    return [join_case(registry, r, source, configuration) for r in records]


def join_case(registry, record, source, configuration):
    for key in ('scope', 'level', 'suite', 'implementation', 'tier', 'evidence', 'applicable_budgets'):
        record.pop(key, None)
    return registry.join(record, source, configuration)


def doctest_events(text, source, configuration, registry=None):
    registry = registry or load_registry()
    expected = registry.expected('doctest')
    records = []
    started = set()
    finished = set()
    for line in text.splitlines():
        if not line.startswith('{'):
            continue
        item = json.loads(line)
        if item.get('type') != 'test':
            continue
        name = 'doctest::' + item['name']
        if name not in expected:
            raise StructuralError(f'unregistered doctest: {name}')
        if item['event'] == 'started':
            if name in started:
                raise StructuralError(f'repeated doctest start: {name}')
            started.add(name)
        elif item['event'] in {'ok', 'failed', 'ignored'}:
            if name in finished:
                raise StructuralError(f'duplicate doctest result: {name}')
            finished.add(name)
            records.append(event(name, 'crate', milliseconds(item.get('exec_time')),
                                 {'ok': 'passed', 'failed': 'failed', 'ignored': 'ignored'}[item['event']], source, configuration))
        else:
            raise StructuralError(f'unknown doctest outcome: {name}')
    for name in expected - finished:
        records.append(event(name, 'crate', None, 'incomplete', source, configuration))
    return [join_case(registry, r, source, configuration) for r in records]


def invoke(argv, stdout, stderr, env=None):
    """Capture raw output and observer offsets in ms since invocation, not instants."""
    start = time.monotonic()
    observations = []
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=stderr, env=env, text=True, bufsize=1) as process:
        for line in process.stdout:
            stdout.write(line)
            if line.startswith('{'):
                try:
                    observations.append({'offset_ms': (time.monotonic()-start)*1000, 'item': json.loads(line)})
                except ValueError:
                    pass  # The authoritative stream parser reports malformed evidence.
        result = subprocess.CompletedProcess(argv, process.wait())
    result.observations = observations
    return result


def suite_events(observations, inventory, registry, source, runner):
    starts = {}
    spans = {}
    outcomes = {}
    doc_start = None
    doc_names = set()
    for observation in observations:
        item, offset = observation['item'], observation['offset_ms']
        if runner == 'doctest':
            if item.get('type') == 'suite' and item.get('event') == 'started':
                doc_start, doc_names = offset, set()
            if item.get('type') == 'test':
                case = registry.cases.get('doctest::'+item['name'])
                if case:
                    doc_names.add(case['name'])
            if item.get('type') == 'suite' and item.get('event') in {'ok', 'failed'} and doc_start is not None:
                for name in doc_names:
                    spans.setdefault(name, []).append((doc_start, offset))
                    outcomes[name] = 'failed' if item['event'] == 'failed' or outcomes.get(name) == 'failed' else 'passed'
            continue
        if item.get('type') != 'suite':
            continue
        meta = item.get('nextest', {})
        names = [key for key, value in inventory['rust-suites'].items()
                 if (value['package-name'], value['binary-name'], value['kind']) ==
                 (meta.get('crate'), meta.get('test_binary'), meta.get('kind'))]
        if len(names) != 1:
            raise StructuralError('unknown suite in nextest stream')
        name = names[0]
        if name not in registry.suites:  # Empty Cargo targets have no cases.
            continue
        if item['event'] == 'started':
            if name in starts:
                raise StructuralError('repeated suite start')
            starts[name] = offset
        elif item['event'] in {'ok', 'failed'}:
            if name not in starts or name in spans:
                raise StructuralError('unpaired suite completion')
            spans[name] = [(starts[name], offset)]
            outcomes[name] = 'passed' if item['event'] == 'ok' else 'failed'
    return [registry.suite_event(name, inclusive_ms(spans.get(name, [])), outcomes.get(name, 'incomplete'), source)
            for name, suite in registry.suites.items() if suite.get('runner') == runner and suite['status'] == 'active']


def main():
    policy_path = Path(__file__).with_name('nextest.toml')
    run = Path('.lane/performance') / uuid.uuid4().hex
    run.mkdir(parents=True)
    records = []
    git_started = time.monotonic()
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    print(f'git rev-parse wall={time.monotonic() - git_started:.6f}s', flush=True)
    configuration = CONFIGURATION
    registry = load_registry()
    def execute(name, argv, budget='ordinary-check', env=None):
        start = time.monotonic()
        with (run / (name + '.stdout')).open('w') as stdout, (run / (name + '.stderr')).open('w') as stderr:
            result = invoke(argv, stdout=stdout, stderr=stderr,
                                    env={**(os.environ if env is None else env), 'CARGO_NET_OFFLINE': 'true'})
        (run / (name + '.observations.json')).write_text(json.dumps(getattr(result, 'observations', [])))
        wall = time.monotonic() - start
        records.append(event(name, budget, wall * 1000, f'exit:{result.returncode}', source, configuration))
        print(f'OPERATION={name} STATUS={result.returncode} WALL={wall:.6f}s', flush=True)
        # Keep full raw capture in private lane artifacts, not in timing findings.
        if result.returncode:
            print((run / (name + '.stderr')).read_text(), file=sys.stderr)
        return result.returncode
    started = time.monotonic()
    version_status = execute('nextest-version', ['cargo', 'nextest', '--version'])
    version = (run / 'nextest-version.stdout').read_text().strip().split()
    if version_status or version[:2] != ['cargo-nextest', '0.9.149']:
        print('PERFORMANCE-STRUCTURAL-ERROR cargo-nextest version must be exactly 0.9.149', file=sys.stderr)
        return 2
    metadata_status = execute('metadata', ['cargo', 'metadata', '--no-deps', '--locked', '--offline', '--format-version=1'])
    build_status = execute('build', ['cargo', 'nextest', 'list', '--workspace', '--locked', '--offline',
                                     '--cargo-profile', 'gate',
                                     '--config-file', str(policy_path), '--profile', 'default',
                                     '--user-config-file', 'none', '--list-type', 'binaries-only', '--message-format', 'json'], 'incremental-build')
    list_status = build_status
    if not build_status:
        list_status = execute('inventory', ['cargo', 'nextest', 'list',
                                          '--binaries-metadata', str(run / 'build.stdout'),
                                          '--config-file', str(policy_path), '--profile', 'default',
                                          '--user-config-file', 'none', '--message-format', 'json'])
    status = metadata_status or build_status or list_status
    structural = 0
    if not status:
        config = policy_path.read_text().replace('dir = ".lane/nextest"', 'dir = ' + json.dumps(str(run.resolve() / 'nextest')))
        (run / 'nextest.toml').write_text(config)
        status = execute('nextest', ['cargo', 'nextest', 'run', '--config-file', str(run / 'nextest.toml'),
                                   '--user-config-file', 'none', '--profile', 'default', '--retries', '0',
                                   '--no-fail-fast', '--ignore-default-filter', '--run-ignored', 'default',
                                   '--message-format', 'libtest-json-plus', '--message-format-version', '0.1',
                                   '--binaries-metadata', str(run / 'build.stdout')], 'test-command',
                         {**os.environ, 'NEXTEST_EXPERIMENTAL_LIBTEST_JSON': '1'})
        try:
            inventory = json.loads((run / 'inventory.stdout').read_text())
            metadata = json.loads((run / 'metadata.stdout').read_text())
            results = nextest_events((run / 'nextest.stdout').read_text(), inventory, metadata, source, configuration, registry)
            records.extend(results)
            records.extend(suite_events(json.loads((run / 'nextest.observations.json').read_text()), inventory, registry, source, 'nextest'))
            if any(row['outcome'] in {'incomplete', 'ignored'} for row in results):
                raise StructuralError('runner omitted or ignored required executions')
        except (ValueError, KeyError, TypeError, StopIteration) as error:
            print(f'PERFORMANCE-STRUCTURAL-ERROR {error}', file=sys.stderr)
            structural = 2
    doc_status = execute('doctests', ['cargo', 'test', '--workspace', '--doc', '--locked', '--offline', '--profile', 'gate', '--no-fail-fast',
                                    '--', '-Z', 'unstable-options', '--format', 'json', '--report-time'], 'incremental-build')
    try:
        results = doctest_events((run / 'doctests.stdout').read_text(), source, configuration, registry)
        records.extend(results)
        records.extend(suite_events(json.loads((run / 'doctests.observations.json').read_text()), {}, registry, source, 'doctest'))
        if any(row['outcome'] in {'incomplete', 'ignored'} for row in results):
            raise StructuralError('doctest runner omitted or ignored required executions')
    except (ValueError, KeyError, TypeError) as error:
        print(f'PERFORMANCE-STRUCTURAL-ERROR {error}', file=sys.stderr)
        structural = 2
    records.append(event('test-command', 'test-command', (time.monotonic() - started) * 1000,
                         f'exit:{status or doc_status}', source, configuration))
    events = run / 'events.jsonl'
    events.write_text(''.join(json.dumps(row, allow_nan=False) + '\n' for row in records))
    Path('.lane/performance-events.jsonl').write_text(events.read_text())
    print(f'PERFORMANCE-EVIDENCE={run}', flush=True)
    return status or doc_status or structural


if __name__ == '__main__':
    sys.exit(main())
