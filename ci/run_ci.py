"""Inventory and meter unittest cases, preserving the unittest verdict."""

import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest

from devperf import StructuralError, budgets, report
from harness import CONFIGURATION, load, source_id
from run_tests import event, join_case


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def publish_wallet(source, destination):
    """Publish a complete step-owned artifact without exposing partial bytes."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=destination.name+'.', suffix='.tmp', delete=False) as output:
            temporary = Path(output.name)
            with source.open('rb') as input_stream:
                shutil.copyfileobj(input_stream, output)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def isolated_wallet(module):
    """Commit objects supply the whole input; the moving parent is not an input."""
    return isolated_runtime(module, 'wallet-conformance', 'PN_WALLET_CONFORMANCE_ISOLATED',
                            ('wallet-rpc-compile-fail.log',))


def isolated_host(module):
    """Host refusal probes own their source tree, compiler and service instance."""
    return isolated_runtime(module, 'host-observation-runtime', 'PN_HOST_RUNTIME_ISOLATED',
                            ('host-statement-compile-fail.log',))


def isolated_runtime(module, name, marker, logs):
    """Run a required suite from commit objects and publish its owned outputs."""
    from build_graph import cancellable
    root = Path.cwd()
    prefix = 'WALLET-ISOLATION' if module == 'test_wallet_boundary' else 'HOST-ISOLATION'
    tree = root/'.lane'/('host-tree' if module == 'test_host_runtime' else name+'-tree')
    if tree.exists(): shutil.rmtree(tree)
    source = os.environ.get('PN_GATE_SOURCE') or source_id()
    for argv in (['git', 'clone', '--quiet', '--shared', '--no-hardlinks', '--no-checkout', str(root), str(tree)],
                 ['git', '-C', str(tree), 'checkout', '--quiet', '--detach', source]):
        started = time.monotonic()
        result = cancellable(argv)
        print(f'{prefix} tool=git wall={time.monotonic()-started:.6f}s status={result.returncode}', flush=True)
        if result.returncode: return result.returncode
    for argv, expected in ((['rev-parse', 'HEAD'], source),
                           (['status', '--porcelain', '--untracked-files=no'], '')):
        started = time.monotonic()
        checked = cancellable(['git', '-C', str(tree), *argv], stdout=subprocess.PIPE, text=True)
        print(f'{prefix} tool=git verify={argv[0]} wall={time.monotonic()-started:.6f}s status={checked.returncode}', flush=True)
        if checked.returncode or checked.stdout.strip() != expected:
            raise StructuralError('isolated wallet checkout is not clean at the source commit')
    (tree/'.lane').mkdir()
    target = Path(os.environ['CARGO_TARGET_DIR']).resolve()/name
    env = dict(os.environ, CARGO_TARGET_DIR=str(target),
               PN_FLAKE_LEDGER=str(target/'gate-flakes.jsonl'),
               PN_OBSERVE_ARTIFACT_DIR=str(tree/'.lane/observations'))
    env[marker] = '1'
    if module == 'test_host_runtime':
        env['PN_HOST_TEST_ROOT'] = str(tree/'.lane/pg')
    try:
        result = cancellable([sys.executable, '-B', 'ci/run_ci.py', module], cwd=tree, env=env)
    finally:
        if module == 'test_host_runtime' and (Path(env['PN_HOST_TEST_ROOT'])/'data/postmaster.pid').exists():
            # The adapter reaps an interrupted child before returning. A daemon
            # can outlive that child, so cleanup is owned by this outer boundary.
            stopped = cancellable([sys.executable, '-B', 'ci/host_postgresql.py', 'stop',
                                   '--root', env['PN_HOST_TEST_ROOT']], cwd=tree, env=env)
            if stopped.returncode:
                raise StructuralError('isolated host service cleanup failed')
    outputs = (f'harness-ci-{module}.jsonl', *logs)
    for filename, destination in (*((item,item) for item in outputs),
                                  ('performance-findings.jsonl', name+'-findings.jsonl')):
        path = tree/'.lane'/filename
        if path.exists(): publish_wallet(path, root/'.lane'/destination)
    print(f'{prefix} source={source} inputs=commit clean=true target=separate handback=atomic', flush=True)
    return result.returncode


def main(module):
    if module == 'test_wallet_boundary' and os.environ.get('PN_GATE_PARALLEL') == '1' and os.environ.get('PN_WALLET_CONFORMANCE_ISOLATED') != '1':
        return isolated_wallet(module)
    if module == 'test_host_runtime' and os.environ.get('PN_GATE_PARALLEL') == '1' and os.environ.get('PN_HOST_RUNTIME_ISOLATED') != '1':
        return isolated_host(module)
    registry = load()
    source = source_id()
    suite_name = 'ci::' + module
    declared = registry.suites[suite_name]
    suite = unittest.defaultTestLoader.loadTestsFromName(module)
    inventory = ['ci::'+test.id() for test in flatten(suite)]
    if len(inventory) != len(set(inventory)) or set(inventory) != set(declared['cases']):
        raise StructuralError('CI inventory differs from declared suite cases')
    from flake_ledger import Session
    ledger = Session(source)
    records = []
    from build_graph_evidence import SERVICE_CASE, service_selection
    if SERVICE_CASE in inventory:
        selection = service_selection(Path.cwd(), os.environ.get('PN_BUILDGRAPH_ADMISSION') == '1')
        print('BUILD-SERVICE-SELECTION '+json.dumps(selection | dict(source=source, admission=os.environ.get('PN_BUILDGRAPH_ADMISSION', '0')), sort_keys=True), flush=True)
        if not selection['run']:
            raw = event(SERVICE_CASE, registry.levels[declared['level']]['budget'], None,
                        'held', source, CONFIGURATION)
            raw.update(hold=selection['hold'], reason=selection['reason'], selection_inputs=selection['inputs'])
            records.append(join_case(registry, raw, source, CONFIGURATION))
            suite = unittest.TestSuite(test for test in flatten(suite) if 'ci::'+test.id() != SERVICE_CASE)

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            self.started = time.monotonic()
            self.outcome = 'passed'
            self.failure_text = ''
            ledger.begin('ci::'+test.id())
            os.environ['PN_GATE_CASE'] = 'ci::'+test.id()
            super().startTest(test)

        def addFailure(self, test, err):
            self.outcome = 'failed'
            self.failure_text = self._exc_info_to_string(err, test)
            super().addFailure(test, err)

        def addError(self, test, err):
            self.outcome = 'failed'
            self.failure_text = self._exc_info_to_string(err, test)
            super().addError(test, err)

        def addSkip(self, test, reason):
            self.outcome = 'ignored'
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, err):
            self.outcome = 'failed'
            self.failure_text = self._exc_info_to_string(err, test)
            super().addExpectedFailure(test, err)

        def addUnexpectedSuccess(self, test):
            self.outcome = 'failed'
            self.failure_text = 'unexpected success of a required expected-failure case'
            super().addUnexpectedSuccess(test)

        def addSubTest(self, test, subtest, err):
            if err is not None:
                self.outcome = 'failed'
                self.failure_text = self._exc_info_to_string(err, test)
            super().addSubTest(test, subtest, err)

        def stopTest(self, test):
            ledger.finish('ci::'+test.id(), self.outcome, self.failure_text)
            duration = (time.monotonic()-self.started)*1000
            raw = event('ci::'+test.id(), registry.levels[declared['level']]['budget'], duration,
                        self.outcome, source, CONFIGURATION)
            if raw['operation'] == SERVICE_CASE:
                raw.update(reason=selection['reason'], selection_inputs=selection['inputs'],
                           selection_admission=os.environ.get('PN_BUILDGRAPH_ADMISSION', '0'))
            records.append(join_case(registry, raw, source, CONFIGURATION))
            super().stopTest(test)

    start = time.monotonic()
    result = unittest.TextTestRunner(resultclass=Result).run(suite)
    records.append(registry.suite_event(suite_name, (time.monotonic()-start)*1000,
                                       ('held' if any(r['outcome']=='held' for r in records) else 'passed') if result.wasSuccessful() else 'failed', source))
    Path('.lane').mkdir(exist_ok=True)
    Path(f'.lane/harness-ci-{module}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records))
    admissions = tomllib.loads(Path('docs/inputs/devperf-registry.toml').read_text())['rows']
    report(records, budgets('docs/inputs/devperf-budgets.toml'), '.lane/performance-findings.jsonl', registry=admissions)
    if any(r['outcome'] in {'ignored', 'incomplete'} for r in records):
        raise StructuralError('ignored or incomplete required CI test')
    return int(not result.wasSuccessful())


if __name__ == '__main__':
    try:
        if sys.argv[1] == 'test_host_runtime' and os.environ.get('PN_HOST_RUNTIME_ISOLATED') == '1':
            from host_postgresql import start, stop
            from build_graph import cancellable
            fixture = Path(os.environ['PN_HOST_TEST_ROOT'])
            try:
                built = cancellable([sys.executable, '-B', 'ci/host_evidence_build.py'])
                if built.returncode: sys.exit(built.returncode)
                start(fixture)
                sys.exit(main(sys.argv[1]))
            finally:
                stop(fixture)
        else:
            sys.exit(main(sys.argv[1]))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'HARNESS-STRUCTURAL-ERROR {error}', file=sys.stderr)
        sys.exit(2)
