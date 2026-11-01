"""Inventory and meter unittest cases, preserving the unittest verdict."""

import json
import os
import shutil
from pathlib import Path
import sys
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


def isolated_wallet(module):
    """Mutation and compile-failure witnesses own a checkout and a Cargo target."""
    from build_graph import cancellable, tracked
    import hashlib
    root = Path.cwd()
    tree = root/'.lane/wallet-conformance-tree'
    if tree.exists(): shutil.rmtree(tree)
    source = source_id()
    inputs = tracked(root)
    def digests(directory):
        return {name: hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in inputs}
    before = digests(root)
    for argv in (['git', 'clone', '--quiet', '--shared', '--no-hardlinks', '--no-checkout', str(root), str(tree)],
                 ['git', '-C', str(tree), 'checkout', '--quiet', source]):
        started = time.monotonic()
        result = cancellable(argv)
        print(f'WALLET-ISOLATION tool=git wall={time.monotonic()-started:.6f}s status={result.returncode}', flush=True)
        if result.returncode: return result.returncode
    if digests(tree) != before:
        raise StructuralError('isolated wallet input differs from the gate checkout')
    (tree/'.lane').mkdir()
    target = Path(os.environ['CARGO_TARGET_DIR']).resolve()
    env = dict(os.environ, PN_WALLET_CONFORMANCE_ISOLATED='1', CARGO_TARGET_DIR=str(target/'wallet-conformance'),
               PN_FLAKE_LEDGER=str(target/'gate-flakes.jsonl'))
    result = cancellable([sys.executable, '-B', 'ci/run_ci.py', module], cwd=tree, env=env)
    if digests(root) != before:
        raise StructuralError('wallet invocation changed the gate checkout')
    print('WALLET-ISOLATION inputs=equal parent=unchanged target=separate', flush=True)
    for name in ('harness-ci-test_wallet_boundary.jsonl', 'wallet-rpc-compile-fail.log'):
        path = tree/'.lane'/name
        if path.exists(): shutil.copyfile(path, root/'.lane'/name)
    findings = tree/'.lane/performance-findings.jsonl'
    if findings.exists():
        with (root/'.lane/performance-findings.jsonl').open('a') as output: output.write(findings.read_text())
    return result.returncode


def main(module):
    if module == 'test_wallet_boundary' and os.environ.get('PN_GATE_PARALLEL') == '1' and os.environ.get('PN_WALLET_CONFORMANCE_ISOLATED') != '1':
        return isolated_wallet(module)
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
        sys.exit(main(sys.argv[1]))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'HARNESS-STRUCTURAL-ERROR {error}', file=sys.stderr)
        sys.exit(2)
