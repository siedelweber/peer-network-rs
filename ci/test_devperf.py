"""Claim area devperf: timing observations preserve execution predicates.

Python claim sites follow the authored gloss/claim/test form; the deployed
linter does not yet scan Python. These are local test inventory labels.
"""

import copy
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from devperf import StructuralError, assess, budgets, report, utc
import run_tests


def execution(duration=1, outcome='passed'):
    return dict(operation='probe', budget='unit', duration_ms=duration,
                outcome=outcome, source='controlled fixture', configuration='injected duration',
                owner='foundation implementer')


def inventory_fixture(kind='lib', location='src/lib.rs'):
    inventory = {'rust-suites': {'example': {'package-name': 'example', 'binary-name': 'example',
                 'package-id': 'example', 'kind': kind, 'testcases': {'case': {'ignored': False}}}}}
    metadata = {'packages': [{'id': 'example', 'manifest_path': '/fixture/Cargo.toml',
                 'targets': [{'name': 'example', 'kind': [kind], 'src_path': '/fixture/' + location}]}]}
    return inventory, metadata


class Performance(unittest.TestCase):
    def test_predicates(self):
        """Fast and slow passing and failing results retain their predicates.
        ´claim:devperf:timing-preserves-predicates´
        ´test:devperf:test-predicates´
        """
        for outcome in ['passed', 'failed']:
            for duration in [0, 1, 100, 101, 100000]:
                record = execution(duration, outcome)
                original = copy.deepcopy(record)
                findings = assess(record, {'unit': 100})
                self.assertEqual(record, original)
                self.assertEqual(len(findings), int(duration > 100))
                for finding in findings:
                    self.assertEqual(finding['outcome'], outcome)
                    self.assertEqual(finding['verdict_effect'], 'none')

    def test_roster(self):
        """Warnings append findings without retries, skips or termination.
        ´claim:devperf:warnings-preserve-roster´
        ´test:devperf:test-roster´
        """
        calls = []
        def run(label, outcome):
            calls.append(label)
            return {**execution(1000, outcome), 'operation': label}
        records = [run('first', 'passed'), run('second', 'failed'), run('third', 'passed')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'findings.jsonl'
            warnings = io.StringIO()
            self.assertEqual(report(records, {'unit': 100}, path, warnings), 0)
            self.assertEqual(calls, ['first', 'second', 'third'])
            findings = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([f['outcome'] for f in findings], ['passed', 'failed', 'passed'])
            self.assertEqual(len(warnings.getvalue().splitlines()), 3)

    def test_missing(self):
        """Missing measurements are findings with null duration and baseline.
        ´claim:devperf:missing-measurement-is-explicit´
        ´test:devperf:test-missing´
        """
        finding, = assess(execution(None), {'unit': 100})
        self.assertEqual(finding['kind'], 'missing-measurement')
        self.assertIsNone(finding['duration_ms'])
        self.assertIsNone(finding['baseline_ms'])
        record = execution()
        del record['duration_ms']
        self.assertEqual(assess(record, {'unit': 100})[0]['kind'], 'missing-measurement')

    def test_structural(self):
        """Missing and malformed declarations differ from an exceeded budget.
        ´claim:devperf:structural-errors-distinct´
        ´test:devperf:test-structural´
        """
        for record in [{}, {**execution(), 'budget': 'absent'}, {**execution(), 'owner': ''},
                       execution(-1), execution(float('nan')), execution(True)]:
            with self.assertRaises(StructuralError):
                assess(record, {'unit': 100})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'budgets.toml'
            for source in ['', '[[rows]]\nname="unit"\nbudget_ms=-1\n']:
                path.write_text(source)
                with self.assertRaises(StructuralError):
                    budgets(path)
        self.assertEqual(assess(execution(101), {'unit': 100})[0]['kind'], 'budget-excess')

    def test_utc(self):
        """Naive and offset instants are refused without assigning a zone.
        ´claim:devperf:utc-is-explicit´
        ´test:devperf:test-utc´
        """
        self.assertEqual(utc('2026-10-22T12:30:00.123Z'), '2026-10-22T12:30:00.123Z')
        for value in ['2026-10-22T12:30:00', '2026-10-22T12:30:00+00:00', 'badZ']:
            with self.assertRaises(StructuralError):
                utc(value)

    def test_runner_policy(self):
        """Runner execution and original failure status do not depend on durations.
        ´claim:devperf:runner-policy-is-nonverdict´
        ´test:devperf:test-runner-policy´
        """
        config = (Path(__file__).parent / 'nextest.toml').read_text()
        policy = tomllib.loads(config)['profile']['default']
        self.assertEqual(policy['retries'], 0)
        self.assertFalse(policy['fail-fast'])
        self.assertNotIn('terminate-after', policy['slow-timeout'])
        self.assertNotIn('global-timeout', policy)
        inventory, metadata = inventory_fixture()
        for outcome in [0, 100]:
            for duration in [0.001, 10000]:
                with self.subTest(outcome=outcome, duration=duration), tempfile.TemporaryDirectory() as directory:
                    calls = []
                    def execute(argv, stdout, stderr, env=None):
                        calls.append(argv)
                        self.assertEqual(env['CARGO_NET_OFFLINE'], 'true')
                        if argv[1] == 'metadata':
                            stdout.write(json.dumps(metadata))
                        elif argv[1:3] == ['nextest', 'list']:
                            stdout.write(json.dumps(inventory))
                        elif argv[1:3] == ['nextest', 'run']:
                            stdout.write(json.dumps({'type': 'test', 'event': 'failed' if outcome else 'ok',
                                                     'name': 'example::example$case', 'exec_time': duration,
                                                     'stdout': 'synthetic captured text'}))
                            return SimpleNamespace(returncode=outcome)
                        return SimpleNamespace(returncode=0)
                    original = Path.cwd()
                    try:
                        os.chdir(directory)
                        Path('ci').mkdir()
                        Path('ci/nextest.toml').write_text(config)
                        with patch('run_tests.subprocess.check_output', return_value='fixture'), patch('run_tests.subprocess.run', side_effect=execute):
                            self.assertEqual(run_tests.main(), outcome)
                        self.assertEqual(len(calls), 5)
                        self.assertIn('binaries-only', calls[1])
                        self.assertIn('--binaries-metadata', calls[2])
                        nextest = calls[3]
                        self.assertEqual(nextest[nextest.index('--retries') + 1], '0')
                        self.assertIn('--no-fail-fast', nextest)
                        self.assertNotIn('--locked', nextest)
                        self.assertNotIn('--offline', nextest)
                        self.assertIn('--doc', calls[4])
                        records = [json.loads(line) for line in Path('.lane/performance-events.jsonl').read_text().splitlines()]
                        case, = [r for r in records if r['operation'] == 'example::case']
                        self.assertEqual(case['duration_ms'], duration * 1000)
                        self.assertEqual(case['outcome'], 'failed' if outcome else 'passed')
                        self.assertNotIn('stdout', case)
                    finally:
                        os.chdir(original)

    def test_result_accounting(self):
        """A missing case remains incomplete and unknown results are structural errors.
        ´claim:devperf:result-accounting-is-explicit´
        ´test:devperf:test-result-accounting´
        """
        inventory, metadata = inventory_fixture('test', 'tests/example.rs')
        record, = run_tests.nextest_events('', inventory, metadata, 'fixture', 'test')
        self.assertEqual(record['outcome'], 'incomplete')
        self.assertIsNone(record['duration_ms'])
        self.assertEqual(record['budget'], 'integration')
        raw = json.dumps({'type': 'test', 'name': 'unknown', 'event': 'ok'})
        with self.assertRaises(StructuralError):
            run_tests.nextest_events(raw, inventory, metadata, 'fixture', 'test')

    def test_raw_duration(self):
        """Invalid raw durations cannot become valid normalized measurements.
        ´claim:devperf:raw-duration-validation´
        ´test:devperf:test-raw-duration´
        """
        for value in [True, -1, float('inf'), '1']:
            with self.assertRaises(StructuralError):
                run_tests.milliseconds(value)
        self.assertIsNone(run_tests.milliseconds(None))
        self.assertEqual(run_tests.milliseconds(0.125), 125)


if __name__ == '__main__':
    unittest.main()
