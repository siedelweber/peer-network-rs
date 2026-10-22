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

from devperf import StructuralError, number


def instant():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def event(operation, budget, duration_ms, outcome, source, configuration):
    return dict(operation=operation, budget=budget, duration_ms=duration_ms,
                outcome=outcome, source=source, configuration=configuration,
                owner='foundation implementer', utc=instant())


def milliseconds(value):
    if value is None:
        return None
    if not number(value):
        raise StructuralError('malformed exec_time; expected finite nonnegative seconds')
    return value * 1000


def target_level(suite, metadata):
    package = next(p for p in metadata['packages'] if p['id'] == suite['package-id'])
    targets = [t for t in package['targets'] if t['name'] == suite['binary-name'] and suite['kind'] in t['kind']]
    if len(targets) != 1:
        raise StructuralError('test binary must identify one Cargo source target')
    relative = Path(targets[0]['src_path']).relative_to(Path(package['manifest_path']).parent)
    if relative.parts[0] == 'tests':
        return 'integration'
    if relative.parts[0] == 'src':
        return 'unit'
    raise StructuralError(f'no interim location rule for test source: {relative}')


def nextest_events(text, inventory, metadata, source, configuration):
    expected = {}
    for binary, suite in inventory['rust-suites'].items():
        level = target_level(suite, metadata)
        for name, details in suite['testcases'].items():
            raw_name = f"{suite['package-name']}::{suite['binary-name']}${name}"
            if raw_name in expected:
                raise StructuralError(f'ambiguous structured test identity: {raw_name}')
            expected[raw_name] = (f'{binary}::{name}', level, details['ignored'])
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
    return records


def doctest_events(text, source, configuration):
    records = []
    started = set()
    finished = set()
    for line in text.splitlines():
        if not line.startswith('{'):
            continue
        item = json.loads(line)
        if item.get('type') != 'test':
            continue
        name = item['name']
        if item['event'] == 'started':
            started.add(name)
        elif item['event'] in {'ok', 'failed', 'ignored'}:
            if name in finished:
                raise StructuralError(f'duplicate doctest result: {name}')
            finished.add(name)
            duration = item.get('exec_time')
            records.append(event('doctest::' + name, 'crate', milliseconds(duration),
                                 {'ok': 'passed', 'failed': 'failed', 'ignored': 'ignored'}[item['event']], source, configuration))
    for name in started - finished:
        records.append(event('doctest::' + name, 'crate', None, 'incomplete', source, configuration))
    return records


def main():
    policy_path = Path(__file__).with_name('nextest.toml')
    run = Path('.lane/performance') / uuid.uuid4().hex
    run.mkdir(parents=True)
    records = []
    git_started = time.monotonic()
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    print(f'git rev-parse wall={time.monotonic() - git_started:.6f}s', flush=True)
    configuration = 'Cargo gate profile; nextest default profile; location-derived levels'
    def execute(name, argv, budget='ordinary-check', env=None):
        start = time.monotonic()
        with (run / (name + '.stdout')).open('w') as stdout, (run / (name + '.stderr')).open('w') as stderr:
            result = subprocess.run(argv, stdout=stdout, stderr=stderr,
                                    env={**(os.environ if env is None else env), 'CARGO_NET_OFFLINE': 'true'})
        wall = time.monotonic() - start
        records.append(event(name, budget, wall * 1000, f'exit:{result.returncode}', source, configuration))
        print(f'OPERATION={name} STATUS={result.returncode} WALL={wall:.6f}s', flush=True)
        # Keep full raw capture in private lane artifacts, not in timing findings.
        if result.returncode:
            print((run / (name + '.stderr')).read_text(), file=sys.stderr)
        return result.returncode
    started = time.monotonic()
    metadata_status = execute('metadata', ['cargo', 'metadata', '--no-deps', '--locked', '--offline', '--format-version=1'])
    build_status = execute('build', ['cargo', 'nextest', 'list', '--workspace', '--locked', '--offline',
                                     '--cargo-profile', 'gate',
                                     '--config-file', str(policy_path), '--profile', 'default',
                                     '--user-config-file', 'none', '--list-type', 'binaries-only', '--message-format', 'json'])
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
            results = nextest_events((run / 'nextest.stdout').read_text(), inventory, metadata, source, configuration)
            records.extend(results)
            if status == 0 and any(row['outcome'] == 'incomplete' for row in results):
                raise StructuralError('successful runner omitted required executions')
        except (ValueError, KeyError, TypeError, StopIteration) as error:
            print(f'PERFORMANCE-STRUCTURAL-ERROR {error}', file=sys.stderr)
            structural = 2
    doc_status = execute('doctests', ['cargo', 'test', '--workspace', '--doc', '--locked', '--offline', '--profile', 'gate', '--no-fail-fast',
                                    '--', '-Z', 'unstable-options', '--format', 'json', '--report-time'], 'test-command')
    try:
        records.extend(doctest_events((run / 'doctests.stdout').read_text(), source, configuration))
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
