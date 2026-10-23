import unittest
from unittest.mock import patch
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile

from devperf import StructuralError
from testkit_guard import validate
import properties
import benchmarks


class SupportGuard(unittest.TestCase):
    # Claim: A benchmark command refuses terminal stdout before building, sampling or creating artifacts.
    # ´claim:harness:benchmark-terminal-preflight´
    # ´test:harness:test-benchmark-terminal´
    def test_benchmark_terminal(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        error = io.StringIO()
        with patch.object(benchmarks, 'run') as run, contextlib.redirect_stdout(Terminal()), contextlib.redirect_stderr(error):
            self.assertEqual(benchmarks.main(), 2)
            run.assert_not_called()
        self.assertIn('terminal refused', json.loads(error.getvalue())['error'])

    def benchmark_record(self, outcome):
        return dict(operation='benchmark::injected', budget='integration', outcome=outcome,
                    source='fixture', configuration='controlled', owner='probe', duration_ms=1500,
                    baseline_ms=1000, baseline_samples=5, baseline_compatible=True,
                    cache_state='warm', baseline_cache='warm', clock_quality='stable')

    # Claim: A benchmark correctness failure remains failing regardless of its duration or findings.
    # ´claim:harness:benchmark-correctness-fails´
    # ´test:harness:test-benchmark-correctness´
    def test_benchmark_correctness(self):
        with tempfile.TemporaryDirectory() as directory:
            declared = {'integration': {'budget_ms': 2000, 'category': 'case'}}
            self.assertEqual(benchmarks.publish([self.benchmark_record('failed')], declared, Path(directory)), 1)

    # Claim: An injected comparable regression produces a persistent warning while preserving a passing benchmark.
    # ´claim:harness:benchmark-regression-is-nonverdict´
    # ´test:harness:test-benchmark-regression´
    def test_benchmark_regression(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            declared = {'integration': {'budget_ms': 2000, 'category': 'case'}}
            record = self.benchmark_record('passed')
            self.assertEqual(benchmarks.publish([record], declared, root), 0)
            findings = [json.loads(line) for line in (root/'findings.jsonl').read_text().splitlines()]
            self.assertEqual([(r['kind'], r['outcome'], r['verdict_effect']) for r in findings], [('regression', 'passed', 'none')])
            self.assertIn('PERFORMANCE-WARNING', (root/'warnings.log').read_text())
            self.assertEqual(record['outcome'], 'passed')

    # Claim: Raw benchmark child output is retained in two artifacts and cannot pollute the runner's JSON channel.
    # ´claim:harness:benchmark-stream-ownership´
    # ´test:harness:test-benchmark-streams´
    def test_benchmark_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root/'child.py'
            child.write_text('import sys\nprint("raw stdout")\nprint("raw stderr", file=sys.stderr)\n')
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status, _ = benchmarks.capture([sys.executable, str(child)], root, 'probe')
            self.assertEqual(status, 0)
            self.assertEqual((out.getvalue(), err.getvalue()), ('', ''))
            self.assertEqual((root/'probe.stdout.log').read_text(), 'raw stdout\n')
            self.assertEqual((root/'probe.stderr.log').read_text(), 'raw stderr\n')

    # Claim: Missing property seeds are structural; a passing predicate cannot invent replay evidence.
    # ´claim:harness:property-seed-required´
    # ´test:harness:test-property-seed´
    def test_property_seed(self):
        rows = properties.declarations()
        self.assertNotIn('PROPTEST_DISABLE_FAILURE_PERSISTENCE', properties.environment(rows))
        name, row = next(iter(rows.items()))
        record = {'operation': name, 'outcome': 'passed', **properties.evidence(row, 'passed')}
        properties.validate(record, rows)
        del record['seed']
        with self.assertRaisesRegex(StructuralError, 'missing seed'):
            properties.validate(record, rows)

    # Claim: Normal and build edges to renamed support cannot enter a production graph; dev edges remain allowed.
    # ´claim:harness:development-only-support´
    # ´test:harness:test-support-edges´
    def test_support_edges(self):
        for kind in (None, 'build', 'dev'):
            metadata = {'packages': [{'name': 'consumer', 'dependencies': [
                {'name': 'pn-testkit', 'rename': 'helper', 'kind': kind}]}]}
            if kind == 'dev':
                validate(metadata)
            else:
                with self.assertRaisesRegex(StructuralError, 'normal/build'):
                    validate(metadata)


if __name__ == '__main__':
    unittest.main()
