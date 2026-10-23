"""Own every Criterion stream; stdout is one JSON result, stderr JSON diagnostics."""

import contextlib
import datetime
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import tomllib
import uuid

from devperf import StructuralError, budgets, report
from harness import CONFIGURATION, load as load_registry


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


def capture(command, directory, name, environment=None):
    start = time.monotonic()
    with (directory / (name+'.stdout.log')).open('w') as out, (directory / (name+'.stderr.log')).open('w') as err:
        result = subprocess.run(command, stdout=out, stderr=err, env=environment, check=False)
    return result.returncode, (time.monotonic()-start)*1000


def run():
    registry = load_registry()
    workloads = tomllib.loads(Path('docs/inputs/harness-workloads.toml').read_text())['rows']
    if len({row['name'] for row in workloads}) != len(workloads) or not workloads:
        raise StructuralError('missing or duplicate benchmark workload')
    registry.roster('benchmark', ['benchmark::'+row['name'] for row in workloads])
    if any(row.get('correctness_case') not in registry.cases or not row.get('claim') for row in workloads):
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
    result_status = publish(records, budgets(Path('docs/inputs/devperf-budgets.toml')), directory)
    events = ''.join(json.dumps(row, allow_nan=False)+'\n' for row in records)
    (directory/'events.jsonl').write_text(events)
    Path('.lane/harness-benchmarks.jsonl').write_text(events)
    summary = dict(status='failed' if result_status else 'passed', source=source, artifact=str(directory),
                   cases=len(workloads), build_ms=build_ms, assessment='inconclusive',
                   reason='shared-worker smoke; no reviewed comparable baseline',
                   findings=sum(1 for line in (directory/'findings.jsonl').read_text().splitlines() if line))
    summary['evidence_bytes_before_summary'] = sum(path.stat().st_size for path in directory.rglob('*') if path.is_file())
    (directory/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    return summary, result_status


def main():
    if sys.stdout.isatty():
        print(json.dumps({'error': 'stdout terminal refused before benchmark effects'}), file=sys.stderr)
        return 2
    if sys.argv[1:]:
        print(json.dumps({'error': 'benchmark runner takes no arguments; declarations are committed data'}), file=sys.stderr)
        return 2
    try:
        # Own any incidental Python output as well as both child streams.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            summary, status = run()
        print(json.dumps(summary, allow_nan=False), file=sys.stderr if status else sys.stdout)
        return status
    except BaseException as error:
        structural = isinstance(error, (ValueError, KeyError, TypeError))
        print(json.dumps({'error': str(error), 'exception': type(error).__name__,
                          'classification': 'structural' if structural else 'runtime'}), file=sys.stderr)
        return 2 if structural else 1


if __name__ == '__main__':
    sys.exit(main())
