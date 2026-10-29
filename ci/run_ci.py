"""Inventory and meter unittest cases, preserving the unittest verdict."""

import json
import os
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


def main(module):
    registry = load()
    source = source_id()
    suite_name = 'ci::' + module
    declared = registry.suites[suite_name]
    suite = unittest.defaultTestLoader.loadTestsFromName(module)
    inventory = ['ci::'+test.id() for test in flatten(suite)]
    if len(inventory) != len(set(inventory)) or set(inventory) != set(declared['cases']):
        raise StructuralError('CI inventory differs from declared suite cases')
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
            super().startTest(test)

        def addFailure(self, test, err):
            self.outcome = 'failed'
            super().addFailure(test, err)

        def addError(self, test, err):
            self.outcome = 'failed'
            super().addError(test, err)

        def addSkip(self, test, reason):
            self.outcome = 'ignored'
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, err):
            self.outcome = 'failed'
            super().addExpectedFailure(test, err)

        def addUnexpectedSuccess(self, test):
            self.outcome = 'failed'
            super().addUnexpectedSuccess(test)

        def addSubTest(self, test, subtest, err):
            if err is not None:
                self.outcome = 'failed'
            super().addSubTest(test, subtest, err)

        def stopTest(self, test):
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
