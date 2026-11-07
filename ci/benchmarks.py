"""Own every Criterion stream; stdout is one JSON result, stderr JSON diagnostics."""

import contextlib
import datetime
import io
import json
import os
from pathlib import Path
import platform
import math
import hashlib
import resource
import subprocess
import sys
import time
import tomllib
import uuid
import copy
from functools import lru_cache
from decimal import Decimal

from devperf import StructuralError, budgets, report
from harness import CONFIGURATION, load as load_registry
from gate_resources import raw_sample, joined


def workload_points(rows, mode):
    """Expand only declared grids; names and coordinates are unique before any effects."""
    points = []
    for row in rows:
        if row.get('kind') != 'grid':
            continue
        if (row['package'], row['target']) not in (('pn-records', 'workload-records'), ('pn-interchange', 'workload-transport'), ('pn-graph', 'workload-graph'), ('pn-epoch', 'workload-epoch'), ('pn-host', 'workload-publication'), ('pn-host', 'workload-storage')):
            raise StructuralError('unknown workload target')
        for variant in row['variants']:
            for size in row['sizes'] if mode != 'smoke' else row.get('smoke_sizes', []):
                if mode == 'smoke' and variant != row.get('smoke_variant'):
                    continue
                if type(row.get('wall_seconds', 180)) is not int or row.get('wall_seconds', 180) <= 0:
                    raise StructuralError('invalid workload wall bound')
                if type(size) is not int or size <= 0:
                    raise StructuralError('invalid workload size')
                points.append({**row, 'size': size, 'variant': variant,
                               'name': f"{row['name']}-{variant}-{size}"})
    names = [row['name'] for row in points]
    if not points or len(names) != len(set(names)):
        raise StructuralError('missing or duplicate workload point')
    return points


def workload_decimal(value):
    """Expand the shortest round-trip float spelling without changing its digits."""
    if not math.isfinite(value):
        raise StructuralError('nonfinite workload number')
    spelling = format(Decimal(repr(value)), 'f')
    return spelling if '.' in spelling else spelling + '.0'


def read_workload_carrier(text):
    """Validate numeric tokens through TOML's float parser, not a text search."""
    def number(token):
        value = float(token)
        if token != workload_decimal(value):
            raise StructuralError('workload float requires exponent-free shortest round-trip decimal')
        return value
    return tomllib.loads(text, parse_float=number)


def write_workload_carrier(data):
    """Serialize the carrier with one round-trip representation for every float."""
    def value(item):
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False)
        if isinstance(item, bool):
            return str(item).lower()
        if isinstance(item, float):
            return workload_decimal(item)
        if isinstance(item, int):
            return str(item)
        if isinstance(item, list):
            return '[' + ', '.join(value(part) for part in item) + ']'
        if isinstance(item, dict):
            return '{ ' + ', '.join(json.dumps(key) + ' = ' + value(part) for key, part in item.items()) + ' }'
        raise StructuralError('unsupported workload carrier value')
    header = ''.join(key + ' = ' + value(item) + '\n' for key, item in data.items() if key != 'rows')
    return header + ''.join('\n[[rows]]\n' + ''.join(key + ' = ' + value(item) + '\n' for key, item in row.items()) for row in data['rows'])


def workload_declarations(*, kinds=None):
    # Content, not path, mtime or a producer digest, is the cache key. Every
    # invocation rereads it; callers receive their own mutable projection.
    rows = validated_workload_content(Path('docs/inputs/workload-benchmarks.toml').read_text())
    return copy.deepcopy([row for row in rows if kinds is None or row['kind'] in kinds])


@lru_cache(maxsize=1)
def validated_workload_content(text):
    """Reuse this validator's own result only under complete byte equality."""
    target = os.environ.get('CARGO_TARGET_DIR')
    cache = Path(target)/'workload-validation.json' if target else None
    checker = Path(__file__).read_text()
    if cache is not None:
        try:
            saved = json.loads(cache.read_bytes())
            if (set(saved) == {'text', 'checker', 'python', 'rows'}
                    and saved['text'] == text and saved['checker'] == checker
                    and saved['python'] == sys.version and isinstance(saved['rows'], list)):
                return saved['rows']
        except (OSError, ValueError, TypeError):
            pass
    rows = validate_workload_content(text)
    if cache is not None:
        cache.parent.mkdir(parents=True, exist_ok=True)
        temporary = cache.with_name(cache.name+'.'+uuid.uuid4().hex+'.tmp')
        temporary.write_text(json.dumps(dict(text=text, checker=checker, python=sys.version, rows=rows), allow_nan=False))
        temporary.replace(cache)
    return rows


def validate_workload_content(text):
    rows = read_workload_carrier(text)['rows']
    if len({row['name'] for row in rows}) != len(rows):
        raise StructuralError('duplicate workload carrier identity')
    policies = [row for row in rows if row['kind'] == 'policy']
    if len(policies) != 1 or tuple(policies[0][key] for key in ('samples', 'warmup_ms', 'measurement_ms', 'resamples', 'sampling', 'seed', 'profile')) != (10, 100, 1000, 1000, 'flat', 0, 'gate'):
        raise StructuralError('workload sampling recipe differs')
    for row in rows:
        if row['kind'] not in ('policy', 'grid', 'campaign', 'point'):
            raise StructuralError('unknown workload carrier kind')
        if row['kind'] in ('campaign', 'point'):
            if row['outcome'] not in policies[0]['outcomes'] or not isinstance(row.get('scope'), str):
                raise StructuralError('invalid measured workload outcome')
            for key in ('wall_s', 'own_cpu_s'):
                if type(row.get(key)) not in (int, float) or not math.isfinite(row[key]) or row[key] < 0:
                    raise StructuralError('invalid measured workload '+key)
            if row['kind'] == 'point' and row['outcome'] == 'passed':
                if len(row.get('sample_times_ns', [])) != policies[0]['samples'] or len(row.get('sample_iterations', [])) != policies[0]['samples']:
                    raise StructuralError('measured workload sample inventory differs')
            if row['outcome'] != 'passed' and not row.get('reason'):
                raise StructuralError('nonpassing workload lacks reason')
    return rows


def checked_result(directory, point, run_id, mode):
    """A fresh invocation receipt binds correctness and Criterion output to one point."""
    receipt_path = directory / 'receipt.json'
    if not receipt_path.is_file():
        raise StructuralError('missing workload correctness receipt')
    receipt = json.loads(receipt_path.read_text())
    expected = dict(name=point['name'], size=point['size'], variant=point['variant'], mode=mode, run=run_id)
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise StructuralError('wrong or stale workload receipt')
    if receipt.get('correctness') != 'passed':
        raise StructuralError('workload correctness failed')
    outcome = receipt.get('outcome', 'passed')
    if outcome not in ('passed', 'refused', 'unsupported', 'incomplete'):
        raise StructuralError('invalid workload receipt outcome')
    if outcome != 'passed':
        if not receipt.get('reason') or mode == 'smoke':
            raise StructuralError('refused workload needs reason and cannot pass smoke')
        if list(directory.glob('criterion/**/sample.json')):
            raise StructuralError('refused workload must not carry fitted samples')
        return receipt, None, None
    if mode == 'pilot':
        return receipt, None, None
    root = directory / 'criterion' / point['target'] / point['name'] / 'new'
    if not all((root / name).is_file() for name in ('estimates.json', 'sample.json', 'benchmark.json')):
        raise StructuralError('missing workload Criterion result')
    identity = json.loads((root / 'benchmark.json').read_text())
    if identity.get('full_id') != point['target'] + '/' + point['name']:
        raise StructuralError('wrong workload Criterion result')
    samples = json.loads((root / 'sample.json').read_text())
    estimates = json.loads((root / 'estimates.json').read_text())
    if len(samples.get('iters', [])) != 10 or len(samples.get('times', [])) != 10:
        raise StructuralError('wrong workload sample inventory')
    if any(not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0
           for value in samples['iters'] + samples['times']):
        raise StructuralError('invalid workload sample')
    mean = estimates['mean']['point_estimate']
    if not isinstance(mean, (int, float)) or not math.isfinite(mean) or mean <= 0:
        raise StructuralError('invalid workload estimate')
    return receipt, samples, estimates


def resource_sample(path):
    subprocess.run(['bash', '-c', 'source ci/gate_resources.sh; gate_resource_sample "$1" "$(gate_cgroup_root)"',
                    'benchmark-resource-sample', str(path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def measured_workloads(mode, directory):
    """Serial points have private outputs, per-point resources and nonbinding timings."""
    rows = workload_declarations(kinds=('policy', 'grid'))
    points = workload_points(rows, mode)
    targets = sorted({(point['package'], point['target'], tuple(point['features'])) for point in points})
    binaries = {}
    builds = []
    for package, target, features in targets:
        command = ['cargo', 'bench', '-p', package, '--bench', target, '--profile', 'gate',
                   '--no-run', '--locked', '--offline', '--message-format=json']
        if features:
            command += ['--features', ','.join(features)]
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        status, wall_ms = capture(command, directory, target + '-build')
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        builds.append(dict(package=package, target=target, status=status, wall_ms=wall_ms,
                           own_cpu_s=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime))
        if status:
            return dict(status='failed', phase='build', builds=builds, points=[]), 1
        artifacts = [json.loads(line) for line in (directory/(target+'-build.stdout.log')).read_text().splitlines() if line.startswith('{')]
        found = {row['executable'] for row in artifacts if row.get('reason') == 'compiler-artifact' and row.get('executable') and row['target']['name'] == target}
        if len(found) != 1:
            raise StructuralError('workload executable inventory differs')
        binaries[target] = found.pop()
    results = []
    for point in points:
        owned = directory / point['name']
        owned.mkdir()  # Never reuse a previous point's result directory.
        run_id = uuid.uuid4().hex
        environment = {key: value for key, value in os.environ.items() if not key.startswith('CARGO_CRITERION_')}
        environment.update(PN_BENCH_OUTPUT=str((owned/'criterion').resolve()), PN_BENCH_POINT=point['name'],
                           PN_BENCH_SIZE=str(point['size']), PN_BENCH_VARIANT=point['variant'], PN_BENCH_MODE=mode,
                           PN_BENCH_RUN=run_id, PN_BENCH_RECEIPT=str((owned/'receipt.json').resolve()))
        load = list(os.getloadavg())
        resource_sample(owned/'start.resources')
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        status, elapsed = capture([binaries[point['target']], '--test' if mode == 'pilot' else '--bench'], owned, 'run', environment, timeout=point.get('wall_seconds', 180))
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        resource_sample(owned/'end.resources')
        result = dict(name=point['name'], package=point['package'], target=point['target'], size=point['size'],
                      variant=point['variant'], mode=mode, outcome='failed' if status else 'passed', returncode=status,
                      invocation_ms=elapsed, own_cpu_s=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                      start_load=load, end_load=list(os.getloadavg()),
                      resource_scope="gate container cgroup; node-wide proc counters separately; own CPU from waited process accounting", resources=joined(raw_sample(owned/'start.resources'), raw_sample(owned/'end.resources'), elapsed/1000))
        if status == 124:
            result.update(outcome='incomplete', reason='declared per-point wall bound exhausted',
                          refusal=dict(kind='wall-bound', limit_seconds=point.get('wall_seconds', 180)),
                          samples=None, estimates=None,
                          raw_sample_unavailable_reason='terminated point; partial samples are not fitted')
        if not status:
            receipt, samples, estimates = checked_result(owned, point, run_id, mode)
            result.update(receipt=receipt, samples=samples, estimates=estimates, outcome=receipt.get('outcome', 'passed'),
                          raw_sample_reference=str(owned/'criterion'/point['target']/point['name']/'new'/'sample.json') if samples else None,
                          raw_sample_unavailable_reason='' if samples else 'pilot or retained nonsampled refusal',
                          evidence_reference=str(owned/'receipt.json'))
        results.append(result)
        (owned/'result.json').write_text(json.dumps(result, indent=2, allow_nan=False)+'\n')
    return dict(status='failed' if any(row['returncode'] for row in results) else 'passed', builds=builds, points=results), functional_status([row['returncode'] for row in results])


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def functional_status(returncodes):
    """Only command predicates determine completion; elapsed values are not inputs."""
    return int(any(code != 0 for code in returncodes))


def publish(records, declared, directory):
    warnings = io.StringIO()
    report(records, declared, directory / 'findings.jsonl', warnings=warnings)
    (directory / 'warnings.log').write_text(warnings.getvalue())
    return functional_status([0 if record['outcome'] == 'passed' else 1 for record in records])


def capture(command, directory, name, environment=None, timeout=None):
    start = time.monotonic()
    with (directory / (name+'.stdout.log')).open('w') as out, (directory / (name+'.stderr.log')).open('w') as err:
        try:
            result = subprocess.run(command, stdout=out, stderr=err, env=environment, check=False, timeout=timeout)
            status = result.returncode
        except subprocess.TimeoutExpired:
            status = 124
    return status, (time.monotonic()-start)*1000


def campaign(mode):
    directory = Path('.lane/benchmarks') / uuid.uuid4().hex
    directory.mkdir(parents=True)
    status, _ = capture(['git', 'rev-parse', 'HEAD'], directory, 'source')
    if status:
        raise StructuralError('benchmark source unavailable')
    toolchain_status, _ = capture(['rustc', '-Vv'], directory, 'toolchain')
    if toolchain_status:
        raise StructuralError('benchmark toolchain unavailable')
    metadata = dict(source=(directory/'source.stdout.log').read_text().strip(), mode=mode,
                    platform=platform.platform(), affinity=sorted(os.sched_getaffinity(0)),
                    machine=platform.node(), priority=os.getpriority(os.PRIO_PROCESS, 0),
                    lock_sha256=hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest(),
                    declarations=workload_declarations(kinds=('policy', 'grid')),
                    load=list(os.getloadavg()), utc=utc(), profile='gate',
                    allocation_measurement='transport decoder reservation counter only; otherwise unavailable',
                    memory_measurement='container cgroup readings; no per-point own peak measurement',
                    toolchain=(directory/'toolchain.stdout.log').read_text())
    (directory/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    resource_sample(directory/'start.resources')
    start = time.monotonic()
    summary, status = measured_workloads(mode, directory)
    wall = time.monotonic()-start
    resource_sample(directory/'end.resources')
    summary.update(artifact=str(directory), wall_s=wall, assessment='inconclusive',
                   reason='component measurement; no reviewed comparable baseline or capacity declaration',
                   resource_scope="gate container cgroup; node-wide proc counters separately; own CPU from waited process accounting", resources=joined(raw_sample(directory/'start.resources'), raw_sample(directory/'end.resources'), wall))
    (directory/'summary.json').write_text(json.dumps(summary, indent=2, allow_nan=False)+'\n')
    return summary, status


def run():
    registry = load_registry()
    workloads = tomllib.loads(Path('docs/inputs/harness-workloads.toml').read_text())['rows']
    if len({row['name'] for row in workloads}) != len(workloads) or not workloads:
        raise StructuralError('missing or duplicate benchmark workload')
    grids = workload_declarations(kinds=('policy', 'grid'))
    registry.roster('benchmark', ['benchmark::'+row['name'] for row in workloads + workload_points(grids, 'smoke')])
    if any(row.get('correctness_case') not in registry.cases or not row.get('claim') for row in workloads + workload_points(grids, 'smoke')):
        raise StructuralError('benchmark lacks its registered correctness case or claim')
    directory = Path('.lane/benchmarks') / uuid.uuid4().hex
    directory.mkdir(parents=True)
    source_status, source_wall = capture(['git', 'rev-parse', 'HEAD'], directory, 'source')
    if source_status:
        raise StructuralError('benchmark source unavailable')
    source = (directory/'source.stdout.log').read_text().strip()
    toolchain_status, toolchain_wall = capture(['rustc', '-Vv'], directory, 'toolchain')
    if toolchain_status:
        raise StructuralError('benchmark toolchain unavailable')
    machine = dict(source=source, configuration=CONFIGURATION, utc=utc(),
                   platform=platform.platform(), cpu=platform.processor(),
                   logical_cpus=os.cpu_count(), affinity=sorted(os.sched_getaffinity(0)),
                   load_average=list(os.getloadavg()), isolation='shared worker; no exclusive CPU reservation',
                   features='default package features; Criterion default features disabled',
                   observation='owned stdout/stderr capture; no profiler', cache_state='gate target reused',
                   peak_memory_bytes=None, cpu_time_s=None, allocations=None,
                   unavailable_reason='smoke runner does not instrument allocation or peak memory',
                   toolchain=(directory/'toolchain.stdout.log').read_text(),
                   identity_command_ms=source_wall+toolchain_wall,
                   dependencies=[dict(name=p['name'], version=p['version']) for p in tomllib.loads(Path('Cargo.lock').read_text())['package']],
                   workloads=workloads)
    cpu_info = Path('/proc/cpuinfo')
    if cpu_info.exists():
        machine['cpu'] = next((line.split(':', 1)[1].strip() for line in cpu_info.read_text().splitlines() if line.startswith('model name')), machine['cpu'])
    (directory/'metadata.json').write_text(json.dumps(machine, indent=2)+'\n')
    build_status, build_ms = capture(['cargo', 'bench', '-p', 'pn-interchange', '--bench', 'foundation',
                                    '--profile', 'gate', '--no-run', '--locked', '--offline', '--message-format=json'], directory, 'build')
    if build_status:
        return dict(status='failed', phase='build', artifact=str(directory), build_ms=build_ms), 1
    artifacts = [json.loads(line) for line in (directory/'build.stdout.log').read_text().splitlines() if line.startswith('{')]
    binaries = {row['executable'] for row in artifacts if row.get('reason') == 'compiler-artifact' and row.get('executable') and row['target']['name'] == 'foundation'}
    if len(binaries) != 1:
        raise StructuralError('benchmark executable inventory differs')
    executable = binaries.pop()
    records = []
    sample_started = time.monotonic()
    for workload in workloads:
        if (workload.get('samples'), workload.get('warmup_ms'), workload.get('measurement_ms')) != (10, 10, 30):
            raise StructuralError('benchmark sample policy differs from reviewed runner')
        name = workload['name']
        output = (directory/'criterion').resolve()
        status, elapsed = capture([executable, name, '--bench'], directory, name,
                                  {**{key: value for key, value in os.environ.items() if not key.startswith('CARGO_CRITERION_')},
                                   'PN_BENCH_OUTPUT': str(output)})
        estimate = output/name/'new/estimates.json'
        mean_ms = None
        if estimate.exists():
            mean_ms = json.loads(estimate.read_text())['mean']['point_estimate'] / 1_000_000
        samples = output/name/'new/sample.json'
        raw = json.loads(samples.read_text()) if samples.exists() else None
        record = dict(operation='benchmark::'+name, source=source, configuration=CONFIGURATION,
                      implementation=workload['implementation'], outcome='failed' if status else 'passed',
                      duration_ms=mean_ms, invocation_ms=elapsed, utc=utc(), owner='foundation benchmark implementer',
                      work_unit=workload['work_unit'], sample_count=len(raw['iters']) if raw else None,
                      claim=workload['claim'], claim_owner='INTERCHANGE', correctness_case=workload['correctness_case'],
                      iterations=sum(raw['iters']) if raw else None,
                      throughput_operations_per_s=1000/mean_ms if mean_ms else None,
                      cache_state='warm-within-invocation',
                      clock_quality='smoke-only-shared-worker', baseline_status=workload['baseline_status'])
        # Baselines are reviewed declarations, never Criterion's automatically saved previous run.
        if workload['baseline_status'] != 'held':
            raise StructuralError('reviewed comparable benchmark baseline not yet implemented')
        records.append(registry.join(record, source))
    records.append(registry.suite_event('foundation-benchmarks', (time.monotonic()-sample_started)*1000,
                                      'failed' if any(row['outcome'] == 'failed' for row in records) else 'passed', source))
    additional, additional_status = measured_workloads('smoke', directory)
    (directory/'workload-smoke.json').write_text(json.dumps(additional, indent=2, allow_nan=False)+'\n')
    if additional_status:
        return dict(status='failed', phase='workload-smoke', artifact=str(directory)), 1
    for point in additional['points']:
        declaration = next(row for row in workload_points(grids, 'smoke') if row['name'] == point['name'])
        records.append(registry.join(dict(operation='benchmark::'+point['name'], source=source, configuration=CONFIGURATION,
                            implementation=declaration['implementation'], outcome=point['outcome'],
                            duration_ms=point['estimates']['mean']['point_estimate']/1_000_000,
                            invocation_ms=point['invocation_ms'], own_cpu_s=point['own_cpu_s'], utc=utc(),
                            owner=declaration['package'], claim=declaration['claim'], correctness_case=declaration['correctness_case']), source))
        records.append(registry.suite_event(declaration['suite'], point['invocation_ms'], point['outcome'], source))
    result_status = publish(records, budgets(Path('docs/inputs/devperf-budgets.toml')), directory)
    events = ''.join(json.dumps(row, allow_nan=False)+'\n' for row in records)
    (directory/'events.jsonl').write_text(events)
    Path('.lane/harness-benchmarks.jsonl').write_text(events)
    summary = dict(status='failed' if result_status else 'passed', source=source, artifact=str(directory),
                   cases=len(workloads)+len(additional['points']),
                   build_ms=build_ms+sum(row['wall_ms'] for row in additional['builds']),
                   foundation_build_ms=build_ms, workload_builds=additional['builds'], assessment='inconclusive',
                   reason='shared-worker smoke; no reviewed comparable baseline',
                   findings=sum(1 for line in (directory/'findings.jsonl').read_text().splitlines() if line))
    summary['evidence_bytes_before_summary'] = sum(path.stat().st_size for path in directory.rglob('*') if path.is_file())
    (directory/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    return summary, result_status


def main():
    try:
        if sys.stdout.isatty():
            print(json.dumps({'error': 'stdout terminal refused before benchmark effects'}), file=sys.stderr)
            return 2
        arguments = sys.argv[1:]
        if arguments not in ([], ['--full'], ['--pilot']):
            print(json.dumps({'error': 'benchmark runner accepts only --full or --pilot; grids are committed data'}), file=sys.stderr)
            return 2
        # Own any incidental Python output as well as both child streams.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            summary, status = campaign(arguments[0][2:]) if arguments else run()
        print(json.dumps(summary, allow_nan=False), file=sys.stderr if status else sys.stdout)
        return status
    except BaseException as error:
        structural = isinstance(error, (ValueError, KeyError, TypeError))
        print(json.dumps({'error': str(error), 'exception': type(error).__name__,
                          'classification': 'structural' if structural else 'runtime'}), file=sys.stderr)
        return 2 if structural else 1


if __name__ == '__main__':
    sys.exit(main())
