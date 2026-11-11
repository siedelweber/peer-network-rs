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
    def test_workload_results(self):
        """Declared grids enumerate once, and missing, substituted, stale or correctness-failed results cannot become measurements; timing does not decide success.
        ´claim:harness:workload-result-binding´
        ´test:integration:test-workload-results´
        """
        rows = [dict(kind='grid', name='probe', package='pn-records', target='workload-records',
                     sizes=[1, 4], variants=['list', 'commitment'], smoke_sizes=[1], smoke_variant='list')]
        points = benchmarks.workload_points(rows, 'full')
        self.assertEqual([p['name'] for p in points], ['probe-list-1', 'probe-list-4', 'probe-commitment-1', 'probe-commitment-4'])
        self.assertEqual(len(benchmarks.workload_points(rows, 'smoke')), 1)
        with self.assertRaisesRegex(StructuralError, 'duplicate'):
            benchmarks.workload_points(rows+rows, 'full')
        raw = dict(rows=[dict(values=[1.25e-5, 1e20, -0.0, 1.25, 5e-324])])
        encoded = benchmarks.write_workload_carrier(raw)
        decoded = benchmarks.read_workload_carrier(encoded)
        self.assertEqual([v.hex() for v in decoded['rows'][0]['values']],
                         [v.hex() for v in raw['rows'][0]['values']])
        mutated = encoded.replace('0.0000125', '1.25e-05')
        self.assertNotEqual(mutated, encoded)
        with self.assertRaisesRegex(StructuralError, 'exponent-free'):
            benchmarks.read_workload_carrier(mutated)
        self.assertEqual(benchmarks.write_workload_carrier(decoded), encoded)
        point = points[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(StructuralError, 'missing'):
                benchmarks.checked_result(root, point, 'fresh', 'full')
            receipt = dict(name=point['name'], size=1, variant='list', mode='full', run='fresh', correctness='passed')
            def write_receipt(value):
                (root/'receipt.json').write_text(json.dumps(value))
            for changes in [dict(name='another'), dict(size=4), dict(variant='commitment'), dict(run='old')]:
                write_receipt({**receipt, **changes})
                with self.assertRaisesRegex(StructuralError, 'wrong or stale'):
                    benchmarks.checked_result(root, point, 'fresh', 'full')
            write_receipt({**receipt, 'correctness': 'failed'})
            with self.assertRaisesRegex(StructuralError, 'correctness failed'):
                benchmarks.checked_result(root, point, 'fresh', 'full')
            write_receipt(receipt)
            with self.assertRaisesRegex(StructuralError, 'missing workload Criterion'):
                benchmarks.checked_result(root, point, 'fresh', 'full')
            output = root/'criterion'/'workload-records'/point['name']/'new'
            output.mkdir(parents=True)
            (output/'benchmark.json').write_text(json.dumps(dict(full_id='wrong')))
            (output/'sample.json').write_text(json.dumps(dict(iters=[1]*10, times=[1]*10)))
            (output/'estimates.json').write_text(json.dumps(dict(mean=dict(point_estimate=1))))
            with self.assertRaisesRegex(StructuralError, 'wrong workload Criterion'):
                benchmarks.checked_result(root, point, 'fresh', 'full')
            (output/'benchmark.json').write_text(json.dumps(dict(full_id='workload-records/'+point['name'])))
            for time_ns in [1, 10**15]:
                (output/'estimates.json').write_text(json.dumps(dict(mean=dict(point_estimate=time_ns))))
                self.assertEqual(benchmarks.checked_result(root, point, 'fresh', 'full')[2]['mean']['point_estimate'], time_ns)
                self.assertEqual(benchmarks.functional_status([0]), 0)
            self.assertEqual(benchmarks.functional_status([1]), 1)
            for package, target in [('pn-graph', 'workload-graph'), ('pn-epoch', 'workload-epoch')]:
                self.assertEqual(len(benchmarks.workload_points([{**rows[0], 'package': package, 'target': target}], 'full')), 4)
            with self.assertRaisesRegex(StructuralError, 'unknown workload target'):
                benchmarks.workload_points([{**rows[0], 'package': 'pn-graph', 'target': 'workload-epoch'}], 'full')
            write_receipt({**receipt, 'outcome': 'refused', 'reason': 'Work ceiling'})
            with self.assertRaisesRegex(StructuralError, 'fitted samples'):
                benchmarks.checked_result(root, point, 'fresh', 'full')
            (output/'sample.json').unlink()
            self.assertEqual(benchmarks.checked_result(root, point, 'fresh', 'full')[1:], (None, None))
            with self.assertRaisesRegex(StructuralError, 'reason'):
                write_receipt({**receipt, 'outcome': 'refused'})
                benchmarks.checked_result(root, point, 'fresh', 'full')


    def test_workload_wall_bound(self):
        """A declared point deadline reaches the child invocation; expiration returns status 124 and other failures retain their status.
        ´claim:harness:workload-wall-bound-is-operational´
        ´test:integration:test-workload-wall-bound´
        """
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(benchmarks.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['probe'], 180)) as child:
                status, elapsed = benchmarks.capture(['probe'], Path(temporary), 'probe', timeout=180)
            self.assertEqual(status, 124)
            self.assertGreaterEqual(elapsed, 0)
            self.assertEqual(child.call_args.kwargs['timeout'], 180)
            with patch.object(benchmarks.subprocess, 'run') as child:
                child.return_value.returncode = 7
                self.assertEqual(benchmarks.capture(['probe'], Path(temporary), 'probe', timeout=180)[0], 7)
        row = dict(kind='grid', name='probe', package='pn-epoch', target='workload-epoch', sizes=[2], variants=['ring'], wall_seconds=0)
        with self.assertRaisesRegex(StructuralError, 'wall bound'):
            benchmarks.workload_points([row], 'full')

    def test_benchmark_terminal(self):
        """A benchmark command refuses terminal stdout before building, sampling or creating artifacts.
        ´claim:harness:benchmark-terminal-preflight´
        ´test:integration:test-benchmark-terminal´
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
        ´test:integration:test-benchmark-correctness´
        """
        with tempfile.TemporaryDirectory() as directory:
            declared = {'integration': {'budget_ms': 2000, 'category': 'case'}}
            self.assertEqual(benchmarks.publish([self.benchmark_record('failed')], declared, Path(directory)), 1)

    def test_benchmark_regression(self):
        """An injected comparable regression produces a persistent warning while preserving a passing benchmark.
        ´claim:harness:benchmark-regression-is-nonverdict´
        ´test:integration:test-benchmark-regression´
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
        ´test:integration:test-benchmark-streams´
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
        ´test:integration:test-property-seed´
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
        ´test:integration:test-support-edges´
        """
        for kind in (None, 'build', 'dev'):
            metadata = {'packages': [{'name': 'consumer', 'dependencies': [
                {'name': 'pn-testkit', 'rename': 'helper', 'kind': kind}]}]}
            if kind == 'dev':
                validate(metadata)
            else:
                with self.assertRaisesRegex(StructuralError, 'normal/build'):
                    validate(metadata)
        for provider in ('pn-epoch', 'pn-records'):
            for kind in (None, 'build', 'dev'):
                for route in ('explicit', 'default', 'forwarded', 'optional-forwarded', 'indirect'):
                    dependency = dict(name=provider, rename='helper', kind=kind, features=[])
                    consumer = dict(name='consumer', dependencies=[dependency], features={})
                    features = {'test-support': [], 'alias': ['test-support']}
                    if route == 'explicit': dependency['features'] = ['test-support']
                    if route == 'default': features['default'] = ['test-support']
                    if route == 'forwarded': consumer['features']['fixture'] = ['helper/test-support']
                    if route == 'optional-forwarded': consumer['features']['fixture'] = ['helper?/test-support']
                    if route == 'indirect': dependency['features'] = ['alias']
                    metadata = {'packages': [consumer, dict(name=provider, dependencies=[], features=features)]}
                    if kind == 'dev':
                        validate(metadata)
                    else:
                        with self.assertRaisesRegex(StructuralError, 'test-support normal/build'):
                            validate(metadata)
                dependency['features'] = []
                consumer['features'] = {'test-support': ['helper/test-support']}
                features.pop('default', None)
                validate(metadata)


class PropertyDeclarations(unittest.TestCase):
    def test_undeclared_property(self):
        """A property discovered from its macro cannot silently run without replay declarations.
        ´claim:harness:undeclared-property-refused´
        ´test:integration:test-undeclared-property´
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
        ´test:integration:test-source-seed´
        """
        self.assertEqual(properties.seed('source-one'), properties.seed('source-one'))
        self.assertNotEqual(properties.seed('source-one'), properties.seed('source-two'))
        self.assertLess(int(properties.seed('source-one')), 2**64)

    def test_consumer_seed(self):
        """Consumer qualification creates a distinct replayable observation and rejects a result carrying the inner seed as outer evidence.
        ´claim:harness:consumer-seeds-separate-observations´
        ´test:integration:test-consumer-seed´
        """
        rows = properties.declarations()
        inner = rows['pn-records::properties::closure_model']
        outer = rows['pn-verification::properties::closure_model']
        source = 'controlled-source'
        env = properties.environment(rows, source)
        self.assertEqual(env['PROPTEST_RNG_SEED'], properties.seed(source))
        self.assertEqual(env['PN_PROPERTY_SEED_PN_VERIFICATION'], properties.seed(source, 'pn-verification'))
        self.assertNotEqual(env['PROPTEST_RNG_SEED'], env['PN_PROPERTY_SEED_PN_VERIFICATION'])
        self.assertEqual(properties.seed(source, 'pn-verification'), properties.seed(source, 'pn-verification'))
        self.assertNotEqual(properties.seed(source, 'pn-verification'), properties.seed(source, 'pn-records'))
        record = dict(operation=outer['name'], source=source, outcome='passed', **properties.evidence(outer, 'passed', source))
        properties.validate(record, rows)
        record['seed'] = properties.evidence(inner, 'passed', source)['seed']
        with self.assertRaisesRegex(StructuralError, 'mismatch: seed'):
            properties.validate(record, rows)


if __name__ == '__main__':
    unittest.main()
