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
from properties import environment as property_environment, evidence as property_evidence
from doctest_identity import identities as doctest_identities


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


def nextest_events(text, inventory, metadata, source, configuration, registry=None, selected=None):
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
            level = registry.case_budget(operation)
            expected[raw_name] = (operation, level, details['ignored'])
    registry.roster('nextest', [v[0] for v in expected.values()])
    if selected is not None:
        if not selected <= {value[0] for value in expected.values()}:
            raise StructuralError('tier selection exceeds the full inventory')
        expected = {key: value for key, value in expected.items() if value[0] in selected}
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
    for record in records:
        if record['operation'] in registry.properties:
            record.update(property_evidence(registry.properties[record['operation']], record['outcome'], source))
    return [join_case(registry, r, source, configuration) for r in records]


def join_case(registry, record, source, configuration):
    for key in ('scope', 'level', 'suite', 'implementation', 'tier', 'evidence', 'applicable_budgets'):
        record.pop(key, None)
    return registry.join(record, source, configuration)


def doctest_events(text, source, configuration, registry=None, selected=None):
    registry = registry or load_registry()
    expected = registry.expected('doctest')
    if selected is not None:
        if not selected <= expected or not selected:
            raise StructuralError('calibration doctest selection exceeds inventory')
        expected = selected
    records = []
    started = set()
    finished = set()
    items = [json.loads(line) for line in text.splitlines() if line.startswith('{')]
    names = doctest_identities({item['name'] for item in items if item.get('type') == 'test'})
    for item in items:
        if item.get('type') != 'test':
            continue
        name = names[item['name']]
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


def invoke(argv, stdout, stderr, env=None, observer=None):
    """Capture raw output and observer offsets in ms since invocation, not instants."""
    start = time.monotonic()
    observations = []
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=stderr, env=env, text=True, bufsize=1) as process:
        for line in process.stdout:
            stdout.write(line)
            if line.startswith('{'):
                try:
                    item = json.loads(line)
                    observations.append({'offset_ms': (time.monotonic()-start)*1000, 'item': item})
                    if observer is not None: observer(item)
                except ValueError:
                    pass  # The authoritative stream parser reports malformed evidence.
        result = subprocess.CompletedProcess(argv, process.wait())
    result.observations = observations
    return result


def contract_events(directory, registry, source, parents):
    records = [row for path in sorted(directory.glob('*.json')) for row in json.loads(path.read_text())]
    registry.roster('contract', [row['operation'] for row in records])
    joined = [registry.join(row, source) for row in records]
    parent_results = {row['operation']: row for row in parents}
    for name, suite in registry.suites.items():
        if suite.get('runner') == 'contract':
            parent = parent_results[suite['parent_case']]
            joined.append(registry.suite_event(name, parent['duration_ms'], parent['outcome'], source))
    return joined


def suite_events(observations, inventory, registry, source, runner, selected=None):
    starts = {}
    spans = {}
    outcomes = {}
    doc_start = None
    doc_names = set()
    doc_ids = doctest_identities({o['item']['name'] for o in observations if o['item'].get('type') == 'test'}) if runner == 'doctest' else {}
    grouped = {name for name, suite in registry.suites.items() if suite.get('case_span') and (selected is None or set(suite['cases']) <= selected)}
    identities = {f"{suite['package-name']}::{suite['binary-name']}${case}": f'{binary}::{case}'
                  for binary, suite in inventory.get('rust-suites', {}).items() for case in suite.get('testcases', {})}
    case_starts = {}
    case_finished = set()
    for observation in observations:
        item, offset = observation['item'], observation['offset_ms']
        if runner == 'nextest' and item.get('type') == 'test':
            operation = identities.get(item.get('name'))
            case = registry.cases.get(operation)
            if case and case['name'] in grouped:
                name = case['name']
                if item['event'] == 'started':
                    if operation in case_starts:
                        raise StructuralError('repeated grouped case start')
                    case_starts[operation] = offset
                elif item['event'] in {'ok', 'failed'}:
                    if operation not in case_starts or operation in case_finished:
                        raise StructuralError('unpaired grouped case completion')
                    case_finished.add(operation)
                    spans.setdefault(name, []).append((case_starts[operation], offset))
                    outcomes[name] = 'failed' if item['event'] == 'failed' or outcomes.get(name) == 'failed' else 'passed'
            continue
        if runner == 'doctest':
            if item.get('type') == 'suite' and item.get('event') == 'started':
                doc_start, doc_names = offset, set()
            if item.get('type') == 'test':
                case = registry.cases.get(doc_ids[item['name']])
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
        if name not in registry.suites or name in grouped:  # Empty targets or explicitly grouped cases.
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
    for name in grouped:
        if registry.suites[name].get('runner') != runner:
            continue
        if set(registry.suites[name]['cases']) - case_finished:
            raise StructuralError('grouped suite lacks completed required cases')
        intervals = spans[name]
        spans[name] = [(min(a for a, _ in intervals), max(b for _, b in intervals))]
    return [registry.suite_event(name, inclusive_ms(spans.get(name, [])), outcomes.get(name, 'incomplete'), source)
            for name, suite in registry.suites.items() if suite.get('runner') == runner and suite['status'] == 'active' and (selected is None or set(suite['cases']) <= selected)]


def invocation_tier(suite):
    return suite['tier'] if suite['tier'] in {'reference-certificate', 'service', 'extended'} else 'fast'


def split_main(action):
    """Build one complete inventory, execute disjoint tiers, require their union."""
    run = Path('.lane/tier-tests')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    registry = load_registry()
    from flake_ledger import Session
    ledger = Session(source)
    raw_cases = {}
    def observe(item):
        if item.get('type') != 'test' or item.get('name') not in raw_cases: return
        case = raw_cases[item['name']]
        if item.get('event') == 'started': ledger.begin(case)
        elif item.get('event') in {'ok', 'failed'}:
            ledger.finish(case, 'failed' if item['event'] == 'failed' else 'passed', str(item.get('stdout', item.get('message', ''))))
    policy = Path(__file__).with_name('nextest.toml')
    records = []
    def execute(name, argv, budget='ordinary-check', env=None):
        start = time.monotonic()
        with (run/(name+'.stdout')).open('w') as out, (run/(name+'.stderr')).open('w') as err:
            result = invoke(argv, out, err, env, observe)
        wall = time.monotonic()-start
        (run/(name+'.observations.json')).write_text(json.dumps(result.observations))
        record = event(name, budget, wall*1000, f'exit:{result.returncode}', source, CONFIGURATION)
        if action in {'service', 'reference-certificate', 'extended'}:
            record['tier'] = action
            record['applicable_budgets'] = [budget, registry.tiers[action]['invocation_budget']]
        records.append(record)
        print(f'OPERATION={name} STATUS={result.returncode} WALL={wall:.6f}s', flush=True)
        if result.returncode:
            print((run/(name+'.stderr')).read_text(), file=sys.stderr)
            print((run/(name+'.stdout')).read_text(), file=sys.stderr)
        return result.returncode
    if action == 'prepare':
        run.mkdir(parents=True, exist_ok=True)
        (run/'manifest.json').unlink(missing_ok=True)
        for name in ('fast', 'service', 'reference-certificate', 'extended'):
            (run/(name+'.result.json')).unlink(missing_ok=True)
        version = execute('version', ['cargo', 'nextest', '--version'])
        if version or (run/'version.stdout').read_text().strip().split()[:2] != ['cargo-nextest', '0.9.149']:
            raise StructuralError('cargo-nextest version must be exactly 0.9.149')
        status = execute('metadata', ['cargo', 'metadata', '--no-deps', '--locked', '--offline', '--format-version=1'])
        status |= execute('build', ['cargo', 'nextest', 'list', '--workspace', '--locked', '--offline',
            '--cargo-profile', 'gate', '--features', 'pn-wallet/fuzzing', '--config-file', str(policy),
            '--profile', 'default', '--user-config-file', 'none', '--list-type', 'binaries-only', '--message-format', 'json'], 'incremental-build')
        if status: return status
        status = execute('inventory', ['cargo', 'nextest', 'list', '--binaries-metadata', str(run/'build.stdout'),
            '--config-file', str(policy), '--profile', 'default', '--user-config-file', 'none', '--message-format', 'json'])
        if status: return status
        inventory = json.loads((run/'inventory.stdout').read_text())
        registry.roster('nextest', [f'{binary}::{case}' for binary, suite in inventory['rust-suites'].items() for case in suite['testcases']])
        (run/'contracts').mkdir(exist_ok=True)
        (run/'manifest.json').write_text(json.dumps(dict(source=source, configuration=CONFIGURATION,
            run=os.environ.get('PN_BUILDGRAPH_RUN'), records=records)))
        return 0
    manifest = json.loads((run/'manifest.json').read_text())
    if any(manifest[key] != value for key, value in dict(source=source, configuration=CONFIGURATION,
            run=os.environ.get('PN_BUILDGRAPH_RUN')).items()):
        raise StructuralError('stale test inventory invocation')
    inventory = json.loads((run/'inventory.stdout').read_text())
    raw_cases.update({f"{suite['package-name']}::{suite['binary-name']}${case}": f'{binary}::{case}'
        for binary, suite in inventory['rust-suites'].items() for case in suite['testcases']})
    if action == 'merge':
        records = list(manifest['records'])
        status = 0
        for tier in ('fast', 'reference-certificate', 'service', 'extended'):
            result = json.loads((run/(tier+'.result.json')).read_text())
            if result['manifest'] != manifest or result['tier'] != tier:
                raise StructuralError('stale or mismatched required tier')
            status |= result['status']
            records += result['records']
        cases = [row for row in records if row.get('scope') == 'case']
        registry.roster('nextest', [row['operation'] for row in cases if registry.cases[row['operation']]['runner'] == 'nextest'])
        registry.roster('doctest', [row['operation'] for row in cases if registry.cases[row['operation']]['runner'] == 'doctest'])
        if any(row['outcome'] not in {'passed', 'failed'} for row in cases):
            raise StructuralError('required invocation omitted or ignored a case')
        records += contract_events(run/'contracts', registry, source, cases)
        Path('.lane/performance-events.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in records))
        print(f'REQUIRED-TIERS joined=4 cases={len(cases)} exactly_once=true status={status}')
        return status
    if action not in {'fast', 'service', 'reference-certificate', 'extended'}:
        raise StructuralError('unknown required invocation')
    selected = {name for name, suite in registry.cases.items() if suite['runner'] == 'nextest' and invocation_tier(suite) == action}
    if not selected: raise StructuralError('required invocation is empty')
    expressions = []
    for binary, suite in inventory['rust-suites'].items():
        if all(f'{binary}::{case}' in selected for case in suite['testcases']):
            expressions.append(f'binary_id(={binary})')
            continue
        for case in suite['testcases']:
            if f'{binary}::{case}' in selected:
                expressions.append(f'(binary_id(={binary}) & test(={case}))')
    config = policy.read_text().replace('dir = ".lane/nextest"', 'dir = '+json.dumps(str(run.resolve()/action)))
    config_path = run/(action+'.toml'); config_path.write_text(config)
    env = {**{key:value for key,value in os.environ.items() if not key.startswith('PROPTEST_')},
           **property_environment(registry.properties, source), 'NEXTEST_EXPERIMENTAL_LIBTEST_JSON':'1',
           'PN_CONTRACT_RESULTS':str((run/'contracts').resolve()), 'PN_HARNESS_SOURCE':source,
           'PN_HARNESS_CONFIGURATION':CONFIGURATION, 'PN_HARNESS_UTC':instant()}
    budget = {'fast':'test-command', 'service':'service-gate', 'reference-certificate':'reference-gate', 'extended':'extended-gate'}[action]
    status = execute(action, ['cargo', 'nextest', 'run', '--config-file', str(config_path), '--user-config-file', 'none',
        '--profile', 'default', '--retries', '0', '--no-fail-fast', '--ignore-default-filter', '--run-ignored', 'default',
        '--message-format', 'libtest-json-plus', '--message-format-version', '0.1',
        '--binaries-metadata', str(run/'build.stdout'), '-E', ' | '.join(expressions)], budget, env)
    records += nextest_events((run/(action+'.stdout')).read_text(), inventory, {}, source, CONFIGURATION, registry, selected)
    records += suite_events(json.loads((run/(action+'.observations.json')).read_text()), inventory, registry, source, 'nextest', selected)
    if action == 'fast':
        status |= execute('doctests', ['cargo', 'test', '--workspace', '--doc', '--locked', '--offline', '--profile', 'gate',
            '--no-fail-fast', '--', '-Z', 'unstable-options', '--format', 'json', '--report-time'], 'incremental-build')
        docs = doctest_events((run/'doctests.stdout').read_text(), source, CONFIGURATION, registry)
        for row in docs:
            ledger.begin(row['operation'])
            ledger.finish(row['operation'], row['outcome'], (run/'doctests.stdout').read_text() if row['outcome'] == 'failed' else '')
        records += docs
        records += suite_events(json.loads((run/'doctests.observations.json').read_text()), {}, registry, source, 'doctest')
    (run/(action+'.result.json')).write_text(json.dumps(dict(manifest=manifest, tier=action, status=status, records=records)))
    return status


def main(action=None):
    if action is not None:
        return split_main(action)
    policy_path = Path(__file__).with_name('nextest.toml')
    run = Path('.lane/performance') / uuid.uuid4().hex
    run.mkdir(parents=True)
    contracts = run.resolve() / 'contracts'
    contracts.mkdir()
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
                                     '--cargo-profile', 'gate', '--features', 'pn-wallet/fuzzing',
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
                         {**{key: value for key, value in os.environ.items() if not key.startswith('PROPTEST_')},
                          **property_environment(registry.properties, source), 'NEXTEST_EXPERIMENTAL_LIBTEST_JSON': '1',
                          'PN_CONTRACT_RESULTS': str(contracts), 'PN_HARNESS_SOURCE': source,
                          'PN_HARNESS_CONFIGURATION': configuration, 'PN_HARNESS_UTC': instant()})
        try:
            inventory = json.loads((run / 'inventory.stdout').read_text())
            metadata = json.loads((run / 'metadata.stdout').read_text())
            results = nextest_events((run / 'nextest.stdout').read_text(), inventory, metadata, source, configuration, registry)
            records.extend(results)
            records.extend(contract_events(contracts, registry, source, results))
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
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else None))
