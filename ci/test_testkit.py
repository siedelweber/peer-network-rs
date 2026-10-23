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
    def test_benchmark_terminal(self):
        """A benchmark command refuses terminal stdout before building, sampling or creating artifacts.
        ´claim:harness:benchmark-terminal-preflight´
        ´test:harness:test-benchmark-terminal´
        """
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

    def test_benchmark_correctness(self):
        """A benchmark correctness failure remains failing regardless of its duration or findings.
        ´claim:harness:benchmark-correctness-fails´
        ´test:harness:test-benchmark-correctness´
        """
        with tempfile.TemporaryDirectory() as directory:
            declared = {'integration': {'budget_ms': 2000, 'category': 'case'}}
            self.assertEqual(benchmarks.publish([self.benchmark_record('failed')], declared, Path(directory)), 1)

    def test_benchmark_regression(self):
        """An injected comparable regression produces a persistent warning while preserving a passing benchmark.
        ´claim:harness:benchmark-regression-is-nonverdict´
        ´test:harness:test-benchmark-regression´
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            declared = {'integration': {'budget_ms': 2000, 'category': 'case'}}
            record = self.benchmark_record('passed')
            self.assertEqual(benchmarks.publish([record], declared, root), 0)
            findings = [json.loads(line) for line in (root/'findings.jsonl').read_text().splitlines()]
            self.assertEqual([(r['kind'], r['outcome'], r['verdict_effect']) for r in findings], [('regression', 'passed', 'none')])
            self.assertIn('PERFORMANCE-WARNING', (root/'warnings.log').read_text())
            self.assertEqual(record['outcome'], 'passed')

    def test_benchmark_streams(self):
        """Raw benchmark child output is retained in two artifacts and cannot pollute the runner's JSON channel.
        ´claim:harness:benchmark-stream-ownership´
        ´test:harness:test-benchmark-streams´
        """
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
        for failure in [dict(status='failed', phase='build'), dict(status='failed', phase='correctness'), RuntimeError('unexpected'), KeyboardInterrupt()]:
            out, err = io.StringIO(), io.StringIO()
            options = {'side_effect': failure} if isinstance(failure, BaseException) else {'return_value': (failure, 1)}
            with patch.object(benchmarks, 'run', **options), patch.object(sys, 'argv', ['benchmarks.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(benchmarks.main(), 1)
            self.assertEqual(out.getvalue(), '')
            self.assertEqual(len(err.getvalue().splitlines()), 1)
            self.assertIsInstance(json.loads(err.getvalue()), dict)
        out, err = io.StringIO(), io.StringIO()
        with patch.object(out, 'isatty', side_effect=OSError('preflight failed')), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(benchmarks.main(), 1)
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(len(err.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(err.getvalue())['exception'], 'OSError')


    def test_property_seed(self):
        """Missing property seeds are structural; a passing predicate cannot invent replay evidence.
        ´claim:harness:property-seed-required´
        ´test:harness:test-property-seed´
        """
        rows = properties.declarations()
        self.assertNotIn('PROPTEST_DISABLE_FAILURE_PERSISTENCE', properties.environment(rows, 'fixture'))
        name, row = next(iter(rows.items()))
        record = {'operation': name, 'source': 'fixture', 'outcome': 'passed', **properties.evidence(row, 'passed', 'fixture')}
        properties.validate(record, rows)
        del record['seed']
        with self.assertRaisesRegex(StructuralError, 'missing seed'):
            properties.validate(record, rows)

    def test_support_edges(self):
        """Normal and build edges to renamed support cannot enter a production graph; dev edges remain allowed.
        ´claim:harness:development-only-support´
        ´test:harness:test-support-edges´
        """
        for kind in (None, 'build', 'dev'):
            metadata = {'packages': [{'name': 'consumer', 'dependencies': [
                {'name': 'pn-testkit', 'rename': 'helper', 'kind': kind}]}]}
            if kind == 'dev':
                validate(metadata)
            else:
                with self.assertRaisesRegex(StructuralError, 'normal/build'):
                    validate(metadata)


class PropertyDeclarations(unittest.TestCase):
    def test_undeclared_property(self):
        """A property discovered from its macro cannot silently run without replay declarations.
        ´claim:harness:undeclared-property-refused´
        ´test:harness:test-undeclared-property´
        """
        from source_sites import rust_sites, property_roster
        text = 'proptest! { #[test] fn hidden(value in 0..8) { assert!(value < 8); } }'
        sites = rust_sites('packages/example/tests/property.rs', text, 'example', 'ROOT')
        self.assertTrue(sites[0]['property'])
        with self.assertRaisesRegex(StructuralError, 'missing='):
            property_roster(sites, {})
        property_roster(sites, {sites[0]['operation']: {}})

    def test_source_seed(self):
        """Source-derived seeds repeat for replay and change across source identities to retain exploration.
        ´claim:harness:source-seed-exploration´
        ´test:harness:test-source-seed´
        """
        self.assertEqual(properties.seed('source-one'), properties.seed('source-one'))
        self.assertNotEqual(properties.seed('source-one'), properties.seed('source-two'))
        self.assertLess(int(properties.seed('source-one')), 2**64)


if __name__ == '__main__':
    unittest.main()
