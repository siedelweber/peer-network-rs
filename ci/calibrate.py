"""Judge case budgets with one committed suite at a time, outside the gate."""
import json
import math
import os
from pathlib import Path
import resource
import shlex
import shutil
import subprocess
import sys
import time
import tomllib

from build_graph import cancellable
from devperf import StructuralError, budgets, excess_ledger, report
from gate_resources import joined, raw_sample, node_identity, node_stall
from flake_ledger import Session
from harness import CONFIGURATION, load, source_id
from isolation import import_base, workspace
from run_ci import publish_wallet
from run_tests import contract_events, doctest_events, instant, nextest_events, split_main
from properties import environment as property_environment


USAGE_FIELDS = ('ru_utime', 'ru_stime', 'ru_majflt', 'ru_inblock', 'ru_nvcsw', 'ru_nivcsw')
CASE_FIELDS = ('own_user_s', 'own_sys_s', *USAGE_FIELDS[2:])


def case_usage():
    """Process and reaped-child CPU; serial Python cases have no sibling case."""
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return tuple(getattr(own, key)+getattr(children, key) for key in USAGE_FIELDS)


def case_cpu(before, after):
    return dict(zip(CASE_FIELDS, (end-start for start, end in zip(before, after))),
                cpu_scope='case-process-and-reaped-descendants')


def case_runner(argv):
    """Meter the single nextest child, excluding this Python runner's startup."""
    name = os.environ.get('NEXTEST_TEST_NAME')
    if name is None:
        os.execv(argv[0], argv)
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    result = subprocess.run(argv, check=False)
    elapsed = time.monotonic()-started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    row = dict(operation=os.environ['NEXTEST_BINARY_ID']+'::'+name,
               source=os.environ['PN_HARNESS_SOURCE'], status=result.returncode,
               duration_ms=elapsed*1000,
               **case_cpu(tuple(getattr(before, key) for key in USAGE_FIELDS),
                          tuple(getattr(after, key) for key in USAGE_FIELDS)))
    destination = Path(os.environ['PN_CALIBRATION_CASE_CPU'])/f'{os.getpid()}.json'
    with destination.open('x') as output:
        json.dump(row, output)
    return result.returncode if result.returncode >= 0 else 128-result.returncode


def join_cpu(cases, directory, source):
    measured = [json.loads(path.read_text()) for path in directory.glob('*.json')]
    by_case = {row['operation']:row for row in measured}
    if len(by_case) != len(measured) or set(by_case) != {row['operation'] for row in cases}:
        raise StructuralError('calibration case CPU union differs')
    for case in cases:
        row = by_case[case['operation']]
        if row['source'] != source or (row['status'] == 0) != (case['outcome'] == 'passed'):
            raise StructuralError('calibration case CPU identity or outcome differs')
        if any(row[key] < 0 for key in ('duration_ms', *CASE_FIELDS)):
            raise StructuralError('calibration case CPU is negative')
        case['runner_duration_ms'] = case['duration_ms']
        case.update({key:row[key] for key in ('duration_ms', *CASE_FIELDS, 'cpu_scope')})


def comparison(before, after, changed):
    """Flag package-code changes conservatively, not as a causal attribution."""
    if not before.get('node') or before['node'] != after.get('node'):
        raise StructuralError('calibration comparison node identity is unavailable or differs')
    old = {row['operation']:row for row in before['records'] if row.get('scope') == 'case'}
    rows = []
    for row in after['records']:
        if row.get('scope') != 'case' or row['operation'] not in old:
            continue
        operation = row['operation']
        paths = [path for path in changed if path.startswith(('packages/', 'vendor/', 'docs/inputs/', 'docs/datasets/', 'ci/'))
                 or path in {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'}
                 or operation.startswith('ci::'+Path(path).stem+'.')]
        rows.append(dict(operation=operation, before=old[operation], after=row,
                         code_changed=bool(paths), changed_paths=paths,
                         declaration_changes=[path for path in changed if path.startswith('docs/inputs/')]))
    return dict(source_before=before['source'], source_after=after['source'],
                source_range=before['source']+'..'+after['source'], changed_files=changed,
                change_scope='all cases for any package or vendor, generated input/dataset or harness change; not causal attribution', cases=rows)


def selection(inventory, cases):
    """Select exact registered identities, including groups sharing one binary."""
    expressions = []
    found = set()
    for binary, suite in inventory['rust-suites'].items():
        for name in suite['testcases']:
            operation = binary+'::'+name
            if operation in cases:
                found.add(operation)
                expressions.append(f'(binary_id(={binary}) & test(={name}))')
    if found != set(cases) or not found:
        raise StructuralError('calibration selection differs from suite')
    return ' | '.join(expressions)


def complete(registry, records):
    """Missing, repeated, held or ignored cases cannot become calibration evidence."""
    cases = [row for row in records if row.get('scope') == 'case']
    for runner in ('nextest', 'doctest', 'ci', 'contract', 'benchmark'):
        registry.roster(runner, [row['operation'] for row in cases
                                if registry.cases[row['operation']]['runner'] == runner])
    if any(row['outcome'] not in {'passed', 'failed'} for row in cases):
        raise StructuralError('calibration requires completed cases')
    return int(any(row['outcome'] != 'passed' for row in cases))


def alone(contexts):
    """A calibration schedule cannot contain overlapping or repeated suites."""
    names = set()
    previous = None
    for context in contexts:
        if context['name'] in names or context['end'] < context['start'] or (previous is not None and context['start'] < previous):
            raise StructuralError('calibration suites overlap, repeat or reverse time')
        names.add(context['name'])
        previous = context['end']


def owning_package(operation, implementation, inventory, packages):
    """A test binary's Cargo package takes precedence over implementation credit."""
    binaries = [name for name in inventory['rust-suites'] if operation.startswith(name+'::')]
    if binaries:
        return inventory['rust-suites'][max(binaries, key=len)]['package-name']
    candidates = [name for name in packages if implementation == name or implementation.startswith(name+'-')]
    return max(candidates, key=len) if candidates else 'repository CI'


def sample(path):
    command = 'source ci/gate_resources.sh; gate_resource_sample "$1" "$(gate_cgroup_root)"'
    result = cancellable(['bash', '-c', command, 'calibration-sample', str(path)])
    if result.returncode:
        raise StructuralError('calibration resource sample failed')
    return raw_sample(path)


def measure(directory, name, argv, env):
    path = directory/str(len(list(directory.glob('*.context.json'))))
    before = sample(path.with_suffix('.start.raw'))
    load_start = os.getloadavg()
    cpu_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.time()
    with path.with_suffix('.stdout').open('w') as out, path.with_suffix('.stderr').open('w') as err:
        result = cancellable(argv, stdout=out, stderr=err, env=env)
    end = time.time()
    cpu_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    after = sample(path.with_suffix('.end.raw'))
    context = dict(name=name, command=argv, status=result.returncode, start=start, end=end,
                   wall_s=end-start, load_start=load_start, load_end=os.getloadavg(),
                   own_user_s=cpu_end.ru_utime-cpu_start.ru_utime,
                   own_sys_s=cpu_end.ru_stime-cpu_start.ru_stime,
                   cgroup_scope='gate-cgroup', load_scope='node-wide', interval_scope='calibration-suite',
                   resources=joined(before, after, end-start))
    path.with_suffix('.context.json').write_text(json.dumps(context, sort_keys=True)+'\n')
    print('CALIBRATION-SUITE '+json.dumps(context, sort_keys=True), flush=True)
    if result.returncode:
        print(path.with_suffix('.stderr').read_text(), file=sys.stderr)
    return result.returncode, path.with_suffix('.stdout').read_text(), context


def run():
    registry = load()
    source = source_id()
    directory = Path('.lane/calibration');directory.mkdir()
    started = time.time()
    before = sample(directory/'whole-start.raw')
    measured_node = node_identity()
    records = []
    contexts = []
    for key in list(os.environ):
        if key.startswith('PROPTEST_'):
            del os.environ[key]
    env = dict(os.environ, PN_CALIBRATION='1', PN_BUILDGRAPH_ADMISSION='1',
               PN_HOST_TEST_ROOT=str(Path('.lane/pg').resolve()),
               PN_WALLET_TEST_ROOT=str(Path('.lane/wallet-elements').resolve()),
               PN_PROFILE_TIMING_DIR=str((directory/'trace-split').resolve()),
               FOUNDATION_COMPUTE_TESTS='1', PN_BUILDGRAPH_RUN='calibration-'+str(time.time_ns()))
    (directory/'trace-split').mkdir()
    os.environ.update(env)
    ledger_session = Session(source)
    if split_main('prepare'):
        raise StructuralError('calibration build or inventory failed')
    inventory = json.loads(Path('.lane/tier-tests/inventory.stdout').read_text())
    metadata = json.loads(Path('.lane/tier-tests/metadata.stdout').read_text())
    packages = {p['name']:p for p in metadata['packages']}
    contracts = Path('.lane/tier-tests/contracts').resolve()
    env.update(property_environment(registry.properties, source))
    env.update(NEXTEST_EXPERIMENTAL_LIBTEST_JSON='1', PN_CONTRACT_RESULTS=str(contracts),
               PN_HARNESS_SOURCE=source, PN_HARNESS_CONFIGURATION=CONFIGURATION, PN_HARNESS_UTC=instant())
    status = 0
    benchmarks_done = False
    services = [('host_postgresql.py', env['PN_HOST_TEST_ROOT']), ('wallet_elements.py', env['PN_WALLET_TEST_ROOT'])]
    try:
        for script, root in services:
            if cancellable([sys.executable, '-B', 'ci/'+script, 'start', '--root', root], env=env).returncode:
                raise StructuralError('calibration service startup failed')
        # Runtime witnesses consume these binaries; their compilation is setup,
        # never included in an individual test's elapsed time.
        if cancellable(['cargo', 'build', '--offline', '--locked', '--profile', 'gate', '-p', 'execwrap', '-p', 'pn-records', '-p', 'pn-graph', '-p', 'pn-epoch', '--features', 'pn-records/test-support', '--examples'], env=env).returncode:
            raise StructuralError('calibration observation build failed')
        if cancellable([sys.executable, '-B', 'ci/host_evidence_build.py'], env=env).returncode:
            raise StructuralError('calibration host build failed')
        for name, suite in registry.suites.items():
            if suite['status'] != 'active' or suite['runner'] == 'contract':
                continue
            runner = suite['runner']
            expected_cases = set(suite['cases'])
            if runner == 'benchmark':
                if benchmarks_done:
                    continue
                benchmarks_done = True
                expected_cases = {case for item in registry.suites.values()
                                  if item['status'] == 'active' and item['runner'] == 'benchmark'
                                  for case in item['cases']}
            if runner == 'nextest':
                argv = ['cargo', 'nextest', 'run', '--config-file', 'ci/nextest.toml', '--user-config-file', 'none',
                        '--profile', 'default', '--retries', '0', '--no-fail-fast', '--ignore-default-filter',
                        '--run-ignored', 'default', '--test-threads', '1', '--message-format', 'libtest-json-plus',
                        '--message-format-version', '0.1', '--binaries-metadata', '.lane/tier-tests/build.stdout',
                        '-E', selection(inventory, suite['cases'])]
            elif runner == 'doctest':
                package = suite['implementation'].removesuffix('-rust')
                if package not in packages:
                    raise StructuralError('calibration doctest package missing')
                argv = ['cargo', 'test', '-p', package, '--doc', '--locked', '--offline', '--profile', 'gate',
                        '--', '-Z', 'unstable-options', '--format', 'json', '--report-time', '--test-threads=1']
            elif runner == 'ci':
                argv = [sys.executable, '-B', 'ci/run_ci.py', name.removeprefix('ci::')]
            elif runner == 'benchmark':
                argv = [sys.executable, '-B', 'ci/benchmarks.py']
            else:
                raise StructuralError('unknown calibration runner')
            suite_env = dict(env)
            if runner == 'nextest':
                cpu_directory = (directory/f'case-cpu-{len(contexts)}').resolve()
                cpu_directory.mkdir()
                suite_env['PN_CALIBRATION_CASE_CPU'] = str(cpu_directory)
                runner_key = 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER'
                if suite_env.get(runner_key):
                    raise StructuralError('calibration cannot replace an existing target runner')
                suite_env[runner_key] = shlex.join([sys.executable, '-B', str(Path(__file__).resolve()), '--case'])
            if runner == 'ci':
                # The whole calibration already owns this committed tree. No
                # other suite runs during its mutation and restoration probes.
                suite_env['PN_CI_ISOLATED'] = name.removeprefix('ci::')
            if runner != 'ci':
                for case in expected_cases:
                    ledger_session.begin(case)
            code, text, context = measure(directory, name, argv, suite_env)
            status |= code;contexts.append(context)
            if code < 0:
                raise StructuralError('calibration interrupted; remaining suites were not started')
            if runner == 'nextest':
                cases = nextest_events(text, inventory, {}, source, CONFIGURATION, registry, set(suite['cases']))
                join_cpu(cases, cpu_directory, source)
            elif runner == 'doctest':
                cases = doctest_events(text, source, CONFIGURATION, registry, set(suite['cases']))
            else:
                filename = 'harness-ci-'+name.removeprefix('ci::')+'.jsonl' if runner == 'ci' else 'harness-benchmarks.jsonl'
                cases = [json.loads(line) for line in (Path('.lane')/filename).read_text().splitlines()]
                if runner == 'benchmark':
                    cases, benchmark_suites = benchmark_batch(cases, registry, source)
                else:
                    cases = [row for row in cases if row.get('scope') == 'case']
            if {row['operation'] for row in cases} != expected_cases or len(cases) != len(expected_cases):
                raise StructuralError('calibration suite result union differs')
            if runner != 'ci':
                failed_output = []
                for line in text.splitlines():
                    if line.startswith('{'):
                        item = json.loads(line)
                        if item.get('type') == 'test' and item.get('event') == 'failed':
                            failed_output.append(line)
                for row in cases:
                    ledger_session.finish(row['operation'], row['outcome'], '\n'.join(failed_output))
            records += cases
            if runner == 'benchmark':
                records += benchmark_suites
            else:
                records.append(registry.suite_event(name, context['wall_s']*1000, 'failed' if code else 'passed', source))
        records += contract_events(contracts, registry, source, records)
        for row in records:
            if row.get('scope') == 'case' and 'cpu_scope' not in row:
                row.update({key:None for key in CASE_FIELDS})
                row.update(
                           cpu_scope='unavailable-within-shared-parent; suite CPU is not case CPU')
        alone(contexts)
        status |= complete(registry, records)
    finally:
        for script, root in reversed(services):
            status |= cancellable([sys.executable, '-B', 'ci/'+script, 'stop', '--root', root], env=env).returncode
    declared = budgets('docs/inputs/devperf-budgets.toml')
    admissions = tomllib.loads(Path('docs/inputs/devperf-registry.toml').read_text())['rows']
    report(records, declared, directory/'findings.jsonl', registry=admissions)
    ledger = excess_ledger([directory/'findings.jsonl'], source, declared)
    for row in ledger['entries']:
        row['owning_package'] = owning_package(row['operation'], row.get('implementation', ''), inventory, packages)
    ended = time.time()
    after = sample(directory/'whole-end.raw')
    if node_identity() != measured_node:
        raise StructuralError('calibration node changed during invocation')
    result = dict(source=source, configuration=CONFIGURATION, node=measured_node, start=started, end=ended,
                  resources=joined(before, after, ended-started),
                  status=status, records=records, suites=contexts, ledger=ledger,
                  policy='suites alone; nextest and doctest cases serial; external node load recorded')
    (directory/'result.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print('CALIBRATION '+json.dumps(dict(source=source, status=status, wall_s=result['end']-started,
          over_budget_cases=ledger['distinct_cases'], artifact='.lane/calibration/result.json')), flush=True)
    return status


def warm_allowance(samples, policy):
    """Size from every retained warm sample, never from a discarded cold run."""
    if len(samples) != policy['warm_samples']:
        raise StructuralError('calibration requires the declared warm sample count')
    if any(not math.isfinite(value) or value < 0 for value in samples):
        raise StructuralError('calibration walls must be finite and nonnegative')
    quantum = policy['allowance_round_ms']
    return math.ceil(max(samples)*policy['allowance_multiple']/quantum)*quantum


def quiet_campaign_run(sample, policy):
    """Every measured suite and the whole interval require node-wide pressure."""
    resources=[sample.get('resources', {})]+[context['resources'] for context in sample['suites']]
    return all(isinstance(node_stall(row), (int,float)) and
               0 <= node_stall(row) <= policy['load_unresolved_pressure_percent']/100 for row in resources)


def benchmark_batch(events, registry, source):
    """The smoke command emits every declared benchmark suite exactly once."""
    suites = {name: suite for name, suite in registry.suites.items()
              if suite['status'] == 'active' and suite['runner'] == 'benchmark'}
    expected = {case for suite in suites.values() for case in suite['cases']}
    cases = [row for row in events if row.get('scope') == 'case']
    aggregates = [row for row in events if row.get('scope') == 'suite']
    if (len(events) != len(cases)+len(aggregates)
            or len(cases) != len(expected) or {row['operation'] for row in cases} != expected
            or len(aggregates) != len(suites) or {row['suite'] for row in aggregates} != set(suites)):
        raise StructuralError('calibration benchmark batch union differs')
    if any(row.get('source') != source or row.get('configuration') != CONFIGURATION for row in events):
        raise StructuralError('calibration benchmark batch identity differs')
    return cases, aggregates


def campaign():
    """Retain a complete warm-up and three subsequent serial invocations."""
    root = Path.cwd()
    source = source_id()
    policy = next(row for row in tomllib.loads((root/'docs/inputs/devperf-budgets.toml').read_text())['rows']
                  if row['name'] == 'gate')
    destination = root/'.lane/calibration-campaign'
    destination.mkdir(parents=True, exist_ok=False)
    started = time.time()
    runs = []
    node = node_identity()
    for index in range(policy['warm_samples']+1):
        name = 'warmup' if index == 0 else f'sample-{index}'
        artifact = root/'.lane/calibration'
        # A child that fails before writing its result must not inherit the
        # preceding invocation's result through the parent's hand-back path.
        if artifact.exists():
            shutil.rmtree(artifact)
        result = cancellable([sys.executable, '-B', 'ci/calibrate.py'])
        shutil.copytree(artifact, destination/name)
        sample = json.loads((artifact/'result.json').read_text())
        runs.append(dict(name=name, warm=index != 0, source=sample['source'],
                         configuration=sample['configuration'], node=sample['node'], status=result.returncode,
                         start=sample['start'], end=sample['end']))
        status = result.returncode or sample['status']
        if sample['source'] != source or sample['configuration'] != CONFIGURATION or sample['node'] != node:
            raise StructuralError('calibration campaign source or configuration changed')
        quiet = quiet_campaign_run(sample, policy)
        report = dict(source=source, node=node, start=started, end=time.time(), status=status, runs=runs, quiet=quiet,
                      sample_choice='maximum-of-three-warm-serial', policy=policy)
        (destination/'result.json').write_text(json.dumps(report, indent=2)+'\n')
        print('CALIBRATION-CAMPAIGN '+json.dumps(dict(sample=name, status=status,
              wall_s=sample['end']-sample['start'], warm=index != 0)), flush=True)
        if status:
            return status
        if index and not quiet:
            print('CALIBRATION-NOT-ADMITTED reason=node-load-or-unavailable budgets=unchanged', flush=True)
            return 2
    return 0


def main():
    if sys.argv[1:] == ['--campaign']:
        return campaign()
    if sys.argv[1:2] == ['--case']:
        return case_runner(sys.argv[2:])
    if sys.argv[1:2] == ['--compare'] and len(sys.argv) == 4:
        before, after = [json.loads(Path(path).read_text()) for path in sys.argv[2:]]
        changed = subprocess.run(['git', 'diff', '--name-only', before['source'], after['source']],
                                 capture_output=True, text=True, check=True).stdout.splitlines()
        print(json.dumps(comparison(before, after, changed), sort_keys=True))
        return 0
    if sys.argv[1:] == ['--owned']:
        return run()
    if sys.argv[1:]:
        raise StructuralError('calibration takes no arguments')
    root = Path.cwd()
    source = source_id()
    if 'PN_IMPORT_BASE' in os.environ:
        os.environ['PN_IMPORT_BASE'] = import_base(root, source, os.environ['PN_IMPORT_BASE'])
    with workspace(root, 'calibration', source) as (tree, target):
        env = dict(os.environ, CARGO_TARGET_DIR=str(target), PN_GATE_SOURCE=source,
                   PN_FLAKE_LEDGER=str(target/'gate-flakes.jsonl'))
        env.pop('PN_CI_ISOLATED', None)
        result = cancellable([sys.executable, '-B', 'ci/calibrate.py', '--owned'], cwd=tree, env=env)
        # Raw suite streams, resource samples and recipe splits remain together.
        artifact = root/'.lane/calibration'
        artifact.mkdir(parents=True, exist_ok=True)
        for path in (tree/'.lane/calibration').rglob('*'):
            if path.is_file():
                destination = artifact/path.relative_to(tree/'.lane/calibration')
                destination.parent.mkdir(parents=True, exist_ok=True)
                publish_wallet(path, destination)
        return result.returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'CALIBRATION-STRUCTURAL-ERROR {error}', file=sys.stderr)
        raise SystemExit(2)
