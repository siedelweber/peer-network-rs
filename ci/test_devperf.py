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

from devperf import StructuralError, assess, assessment, budgets, inclusive_ms, report, utc
from harness import CONFIGURATION
from test_harness import declarations, fixture
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
    def test_noisy_clock(self):
        """The reporter contract keeps injected noisy evidence inconclusive without changing a predicate or hiding an excess.
        ´claim:devperf:noisy-clock-is-nonverdict´
        ´test:devperf:test-noisy-clock´
        """
        for outcome in ['passed', 'failed']:
            record = {**execution(1000, outcome), 'clock_quality': 'noisy', 'baseline_ms': 1}
            original = copy.deepcopy(record)
            self.assertEqual(assessment(record)['reason'], 'noisy-clock')
            self.assertEqual([f['kind'] for f in assess(record, declarations())], ['budget-excess'])
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'findings.jsonl'
                self.assertEqual(report([record], declarations(), path, io.StringIO()), 0)
                evidence = json.loads(path.with_name('performance-assessments.jsonl').read_text())
                self.assertEqual(evidence['assessment'], 'inconclusive')
                self.assertNotIn('assessment', json.loads(path.read_text()))
            self.assertEqual(record, original)

    def test_cold_cache(self):
        """The reporter contract keeps injected cold/warm comparisons inconclusive while their excess remains visible.
        ´claim:devperf:cold-cache-is-nonverdict´
        ´test:devperf:test-cold-cache´
        """
        for outcome in ['passed', 'failed']:
            record = {**execution(1000, outcome), 'baseline_ms': 1, 'cache_state': 'cold', 'baseline_cache': 'warm'}
            self.assertEqual(assessment(record)['reason'], 'incompatible-cache')
            self.assertEqual(assess(record, declarations())[0]['outcome'], outcome)

    def test_overlapping_spans(self):
        """Inclusive suite timing never sums overlapping work, preventing inflated budget findings.
        ´claim:devperf:overlap-is-not-summed´
        ´test:devperf:test-overlapping-spans´
        """
        self.assertEqual(inclusive_ms([(0, 10), (5, 15)]), 15)
        self.assertEqual(inclusive_ms([(0, 5), (10, 15)]), 15)
        self.assertIsNone(inclusive_ms([]))
        for outcome in ['passed', 'failed']:
            record = execution(inclusive_ms([(0, 100), (50, 150)]), outcome)
            with tempfile.TemporaryDirectory() as directory:
                self.assertEqual(report([record], declarations(), Path(directory)/'findings.jsonl', io.StringIO()), 0)
            self.assertEqual(record['outcome'], outcome)
        with self.assertRaises(StructuralError):
            inclusive_ms([(2, 1)])

    def test_admitted_budget(self):
        """Admission changes only the warning threshold; an excess still preserves a failing predicate.
        ´claim:devperf:admission-is-nonverdict´
        ´test:devperf:test-admitted-budget´
        """
        admission = dict(name='probe', status='admitted', ordinary_budget='unit', budget_ms=200,
                         label='expt:fixture:probe', owner='fixture', reason='bounded work',
                         measurement='injected milliseconds', placement='fixture', settlement='fixture admission')
        self.assertEqual(assess(execution(150), declarations(), [admission]), [])
        finding, = assess(execution(201, 'failed'), declarations(), [admission])
        self.assertEqual((finding['budget_ms'], finding['outcome'], finding['verdict_effect']), (200, 'failed', 'none'))
        admission['status'] = 'candidate'
        self.assertEqual(assess(execution(150), declarations(), [admission])[0]['budget_ms'], 100)

    def test_budget_category(self):
        """Declared categories keep build/aggregate configuration findings distinct from case/suite performance findings.
        ´claim:devperf:category-controls-classification´
        ´test:devperf:test-budget-category´
        """
        for category in ['build', 'aggregate']:
            finding, = assess(execution(101), {'unit': {'budget_ms': 100, 'category': category}})
            self.assertEqual(finding['classification'], 'build-or-aggregate-misconfiguration')
        for category in ['case', 'suite']:
            finding, = assess(execution(101), {'unit': {'budget_ms': 100, 'category': category}})
            self.assertEqual(finding['classification'], 'performance')

    def test_version_mismatch(self):
        """An unreviewed stream version is refused before tests, preventing silent schema drift.
        ´claim:devperf:exact-runner-version´
        ´test:devperf:test-version-mismatch´
        """
        with tempfile.TemporaryDirectory() as directory:
            original = Path.cwd()
            try:
                os.chdir(directory)
                def execute(argv, stdout, stderr, env=None):
                    self.assertEqual(argv, ['cargo', 'nextest', '--version'])
                    stdout.write('cargo-nextest 0.9.150')
                    return SimpleNamespace(returncode=0)
                with patch('run_tests.subprocess.check_output', return_value='fixture'), patch('run_tests.load_registry', return_value=fixture()), patch('run_tests.invoke', side_effect=execute) as invoked:
                    self.assertEqual(run_tests.main(), 2)
                    self.assertEqual(invoked.call_count, 1)
            finally:
                os.chdir(original)

    def test_predicates(self):
        """Fast and slow passing and failing results retain their predicates.
        ´claim:devperf:timing-preserves-predicates´
        ´test:devperf:test-predicates´
        """
        for outcome in ['passed', 'failed']:
            for duration in [0, 1, 100, 101, 100000]:
                record = execution(duration, outcome)
                original = copy.deepcopy(record)
                findings = assess(record, declarations())
                self.assertEqual(record, original)
                self.assertEqual(len(findings), int(duration > 100))
                for finding in findings:
                    self.assertEqual(finding['outcome'], outcome)
                    self.assertEqual(finding['verdict_effect'], 'none')

    def test_roster(self):
        """Findings preserve input outcomes and order, keeping evidence attributable.
        ´claim:devperf:findings-preserve-outcome-order´
        ´test:devperf:test-roster´
        """
        def run(label, outcome):
            return {**execution(1000, outcome), 'operation': label}
        records = [run('first', 'passed'), run('second', 'failed'), run('third', 'passed')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'findings.jsonl'
            warnings = io.StringIO()
            self.assertEqual(report(records, declarations(), path, warnings), 0)
            findings = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([f['outcome'] for f in findings], ['passed', 'failed', 'passed'])
            self.assertEqual(len(warnings.getvalue().splitlines()), 3)

    def test_missing(self):
        """Missing measurements are findings with null duration and baseline.
        ´claim:devperf:missing-measurement-is-explicit´
        ´test:devperf:test-missing´
        """
        finding, = assess(execution(None), declarations())
        self.assertEqual(finding['kind'], 'missing-measurement')
        self.assertIsNone(finding['duration_ms'])
        self.assertIsNone(finding['baseline_ms'])
        record = execution()
        del record['duration_ms']
        self.assertEqual(assess(record, declarations())[0]['kind'], 'missing-measurement')

    def test_structural(self):
        """Missing and malformed declarations differ from an exceeded budget.
        ´claim:devperf:structural-errors-distinct´
        ´test:devperf:test-structural´
        """
        for record in [{}, {**execution(), 'budget': 'absent'}, {**execution(), 'owner': ''},
                       execution(-1), execution(float('nan')), execution(True)]:
            with self.assertRaises(StructuralError):
                assess(record, declarations())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'budgets.toml'
            for source in ['', '[[rows]]\nname="unit"\nbudget_ms=-1\n']:
                path.write_text(source)
                with self.assertRaises(StructuralError):
                    budgets(path)
        self.assertEqual(assess(execution(101), declarations())[0]['kind'], 'budget-excess')

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
                        elif argv[1:] == ['nextest', '--version']:
                            stdout.write('cargo-nextest 0.9.149')
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
                        with patch('run_tests.subprocess.check_output', return_value='fixture'), patch('run_tests.load_registry', return_value=fixture()), patch('run_tests.invoke', side_effect=execute):
                            self.assertEqual(run_tests.main(), outcome)
                        self.assertEqual(len(calls), 6)
                        self.assertIn('binaries-only', calls[2])
                        self.assertIn('--binaries-metadata', calls[3])
                        nextest = calls[4]
                        self.assertEqual(nextest[nextest.index('--retries') + 1], '0')
                        self.assertIn('--no-fail-fast', nextest)
                        self.assertNotIn('--locked', nextest)
                        self.assertNotIn('--offline', nextest)
                        self.assertIn('--doc', calls[5])
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
        record, = run_tests.nextest_events('', inventory, metadata, 'fixture', 'test', fixture(level='integration'))
        self.assertEqual(record['outcome'], 'incomplete')
        self.assertIsNone(record['duration_ms'])
        self.assertEqual(record['budget'], 'integration')
        raw = json.dumps({'type': 'test', 'name': 'unknown', 'event': 'ok'})
        with self.assertRaises(StructuralError):
            run_tests.nextest_events(raw, inventory, metadata, 'fixture', 'test', fixture(level='integration'))

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
