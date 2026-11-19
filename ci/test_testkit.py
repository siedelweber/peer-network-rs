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
        """The benchmark child wait passes its containment to the invocation; expiration has its own hang flag, a child status of 124 remains a failure, and completed points classify their declared wall threshold with load without changing their verdict.
        ´claim:harness:workload-wall-bound-is-operational´
        ´test:integration:test-workload-wall-bound´
        """
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(benchmarks.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['probe'], 180)) as child:
                status, elapsed, hung = benchmarks.capture(['probe'], Path(temporary), 'probe', timeout=180)
            self.assertEqual(status, 124)
            self.assertTrue(hung, 'capture expiration has a distinct hang flag')
            self.assertGreaterEqual(elapsed, 0)
            self.assertEqual(child.call_args.kwargs['timeout'], 180)
            self.assertIn('HANG awaiting benchmark child completion', (Path(temporary)/'probe.stderr.log').read_text())
            with patch.object(benchmarks.subprocess, 'run') as child:
                child.return_value.returncode = 7
                self.assertEqual(benchmarks.capture(['probe'], Path(temporary), 'probe', timeout=180)[0], 7)
                child.return_value.returncode = 124
                code, _, hung = benchmarks.capture(['probe'], Path(temporary), 'probe', timeout=180)
                self.assertEqual((code, hung), (124, False), 'child status 124 is not a hang')
        row = dict(kind='grid', name='probe', package='pn-epoch', target='workload-epoch', sizes=[2], variants=['ring'], wall_seconds=0)
        with self.assertRaisesRegex(StructuralError, 'wall bound'):
            benchmarks.workload_points([row], 'full')
        point = dict(name='point', package='fixture', target='fixture', features=[], size=1, variant='fixture', wall_seconds=180)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def build(*args):
                (directory/'fixture-build.stdout.log').write_text(json.dumps(dict(reason='compiler-artifact', executable='fixture', target=dict(name='fixture'))))
                args[-1].append(dict(cargo_cpu_s=0))
                return 0, 0
            with patch.object(benchmarks, 'workload_declarations', return_value=[]), patch.object(benchmarks, 'workload_points', return_value=[point]), patch.object(benchmarks, 'capture_build', side_effect=build), patch.object(benchmarks, 'resource_sample'), patch.object(benchmarks, 'raw_sample', return_value={}), patch.object(benchmarks, 'joined', return_value={}), patch.object(benchmarks, 'capture', return_value=(124, 600000, True)) as child:
                result, status = benchmarks.measured_workloads('full', directory, [])
            self.assertEqual(child.call_args.kwargs['timeout'], 600, 'point capture uses hang containment, not its measurement threshold')
            self.assertEqual(status, 1)
            self.assertEqual(result['points'][0]['reason'], 'HANG awaiting benchmark child completion')
            self.assertEqual(result['points'][0]['refusal'], dict(kind='hang', limit_seconds=600))
        for code, elapsed, expected in [(124, 1, 'within-threshold'), (0, 181000, 'over-threshold')]:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                with patch.object(benchmarks, 'workload_declarations', return_value=[]), patch.object(benchmarks, 'workload_points', return_value=[point]), patch.object(benchmarks, 'capture_build', side_effect=build), patch.object(benchmarks, 'resource_sample'), patch.object(benchmarks, 'raw_sample', return_value={}), patch.object(benchmarks, 'joined', return_value={}), patch.object(benchmarks, 'capture', return_value=(code, elapsed, False)), patch.object(benchmarks, 'checked_result', return_value=({}, [], {})), patch.object(benchmarks.os, 'getloadavg', return_value=(41, 42, 43)):
                    result, status = benchmarks.measured_workloads('full', directory, [])
                row = result['points'][0]
                self.assertNotIn('refusal', row, 'completed child is not a containment hang')
                self.assertEqual(row['wall_measurement'], dict(threshold_s=180, classification=expected, verdict_effect='none'), 'completed point classifies its threshold without deciding')
                self.assertEqual(row['start_load'], [41, 42, 43], 'threshold measurement retains load')
                self.assertEqual(row['end_load'], [41, 42, 43])
                self.assertEqual(status, int(code != 0), 'point wall does not decide success')
        recipe = dict(kind='grid', name='default', package='pn-epoch', target='workload-epoch', features=[], sizes=[1], variants=['ring'])
        point = benchmarks.workload_points([recipe], 'full')[0]
        self.assertEqual(point.get('wall_seconds'), 180, 'omitted recipe wall is materialized before point readers')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def default_build(*args):
                (directory/'workload-epoch-build.stdout.log').write_text(json.dumps(dict(reason='compiler-artifact', executable='fixture', target=dict(name='workload-epoch'))))
                args[-1].append(dict(cargo_cpu_s=0))
                return 0, 0
            with patch.object(benchmarks, 'workload_declarations', return_value=[recipe]), patch.object(benchmarks, 'capture_build', side_effect=default_build), patch.object(benchmarks, 'resource_sample'), patch.object(benchmarks, 'raw_sample', return_value={}), patch.object(benchmarks, 'joined', return_value={}), patch.object(benchmarks, 'capture', return_value=(0, 181000, False)), patch.object(benchmarks, 'checked_result', return_value=({}, [], {})):
                result, status = benchmarks.measured_workloads('full', directory, [])
            self.assertEqual(result['points'][0]['wall_measurement'], dict(threshold_s=180, classification='over-threshold', verdict_effect='none'), 'omitted recipe wall classifies against its admitted default')
            self.assertEqual(status, 0, 'default wall threshold does not decide success')

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
                status, _, _ = benchmarks.capture([sys.executable, str(child)], root, 'probe')
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
        def fixture(packages, development):
            metadata = dict(packages=packages, workspace_root='/fixture', workspace_members=[])
            classes = {}
            for package in packages:
                name = package['name']
                package.update(id=name, manifest_path='/fixture/packages/'+name+'/Cargo.toml')
                metadata['workspace_members'].append(name)
                classes[name] = {feature: 'development-only' if (name, feature) in development else 'production'
                                 for feature in package.get('features', {})}
            return metadata, classes
        for kind in (None, 'build', 'dev'):
            metadata = {'packages': [{'name': 'consumer', 'dependencies': [
                {'name': 'pn-testkit', 'rename': 'helper', 'kind': kind}]}]}
            metadata, classes = fixture(metadata['packages'], set())
            if kind == 'dev':
                validate(metadata, classes)
            else:
                with self.assertRaisesRegex(StructuralError, 'normal/build'):
                    validate(metadata, classes)
        for provider, feature in (('pn-epoch','test-support'), ('pn-records','test-support'), ('cli-common','observation-test-hook'), ('pn-wallet','fuzzing')):
            for kind in (None, 'build', 'dev'):
                for route in ('explicit', 'default', 'forwarded', 'optional-forwarded', 'indirect'):
                    dependency = dict(name=provider, rename='helper', kind=kind, features=[])
                    consumer = dict(name='consumer', dependencies=[dependency], features={})
                    features = {feature: [], 'alias': [feature]}
                    if route == 'explicit': dependency['features'] = [feature]
                    if route == 'default': features['default'] = [feature]
                    if route == 'forwarded': consumer['features']['fixture'] = ['helper/'+feature]
                    if route == 'optional-forwarded': consumer['features']['fixture'] = ['helper?/'+feature]
                    if route == 'indirect': dependency['features'] = ['alias']
                    metadata, classes = fixture([consumer, dict(name=provider, dependencies=[], features=features)], {(provider, feature)})
                    if kind == 'dev':
                        validate(metadata, classes)
                    else:
                        with self.assertRaisesRegex(StructuralError, feature+' normal/build'):
                            validate(metadata, classes)
                dependency['features'] = []
                consumer['features'] = {'test-support': ['helper/'+feature]}
                features.pop('default', None)
                metadata, classes = fixture(metadata['packages'], {(provider, feature), ('consumer', 'test-support')})
                validate(metadata, classes)
                if kind != 'dev':
                    classes['consumer']['test-support'] = 'production'
                    with self.assertRaisesRegex(StructuralError, feature+' normal/build'):
                        validate(metadata, classes)
        metadata, classes = fixture([dict(name='consumer', dependencies=[], features={'future-support': []})], set())
        del classes['consumer']['future-support']
        with self.assertRaisesRegex(StructuralError, 'unclassified feature: consumer/future-support'):
            validate(metadata, classes)
        classes['consumer']['future-support'] = 'development-only'
        validate(metadata, classes)
        del metadata['packages'][0]['features']['future-support']
        with self.assertRaisesRegex(StructuralError, 'absent classified feature: consumer/future-support'):
            validate(metadata, classes)


class PropertyDeclarations(unittest.TestCase):
    def test_binary_library_module_identity(self):
        """A resolved binary module gets the runner's target identity while library modules keep theirs, and shared or unresolved sources refuse.
        ´claim:harness:binary-library-module-identity´
        ´test:integration:test-binary-library-module-identity´
        """
        from source_sites import OWNERS, census
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            crate = root/'packages'/'example'
            source = crate/'src'
            source.mkdir(parents=True)
            (crate/'Cargo.toml').write_text('[package]\nname = "example"\nversion = "0.1.0"\n[[bin]]\nname = "example"\npath = "src/main.rs"\n')
            (source/'main.rs').write_text('#[path = "adapter.rs"]\nmod adapter;\n')
            (source/'adapter.rs').write_text('#[test]\nfn binary_case() {}\n')
            (source/'lib.rs').write_text('mod library;\n')
            (source/'library.rs').write_text('#[test]\nfn library_case() {}\n')
            with patch.dict(OWNERS, {'example': 'ROOT'}, clear=True):
                operations = {site['operation'] for site in census(root)}
                self.assertEqual(operations, {'example::bin/example::adapter::binary_case', 'example::library::library_case'})
                (source/'main.rs').write_text('mod adapter;\nmod shared;\n')
                (source/'lib.rs').write_text('mod library;\nmod shared;\n')
                (source/'shared.rs').write_text('#[test]\nfn shared_case() {}\n')
                with self.assertRaisesRegex(StructuralError, 'source reached from both library and binary roots'):
                    census(root)
                (source/'main.rs').write_text('mod adapter;\nmod missing;\n')
                (source/'lib.rs').write_text('mod library;\n')
                with self.assertRaisesRegex(StructuralError, 'unresolved module declaration missing'):
                    census(root)
                (source/'main.rs').write_text('mod adapter;\n')
                with (crate/'Cargo.toml').open('a') as manifest:
                    manifest.write('[[bin]]\nname = "second"\npath = "src/second.rs"\n')
                with self.assertRaisesRegex(StructuralError, 'more than one declared binary beside library'):
                    census(root)

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
