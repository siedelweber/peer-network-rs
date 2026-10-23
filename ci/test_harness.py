"""Claim area harness: declarations bound the evidence a passing matrix can claim."""

import copy
import unittest

from devperf import StructuralError
from harness import CONFIGURATION, Registry


def declarations():
    return {name: {'budget_ms': value, 'category': category} for name, value, category in
            [('unit', 100, 'case'), ('crate', 500, 'case'), ('integration', 2000, 'case'), ('pure-suite', 5000, 'suite'), ('mock-suite', 10000, 'suite')]}


def rows(runner='nextest', case='example::case', level='unit'):
    return [*[dict(kind='level', name=name, budget=budget) for name, budget in
               [('unit', 'unit'), ('public-surface', 'crate'), ('integration', 'integration'), ('doctest', 'crate')]],
            dict(kind='implementation', name='example', evidence='pure'),
            dict(kind='tier', name='fast', status='active'),
            dict(kind='tier', name='service', status='held', reason='worker unavailable'),
            dict(kind='suite', name='example', level=level, implementation='example', tier='fast',
                 status='active', runner=runner, budget='pure-suite', cases=[case])]


def fixture(runner='nextest', case='example::case', level='unit'):
    return Registry(rows(runner, case, level), declarations())


def result(registry):
    return registry.join(dict(operation=next(iter(registry.cases)), outcome='passed', duration_ms=1,
                              source='current', configuration=CONFIGURATION, owner='fixture'), 'current')


class Harness(unittest.TestCase):
    def test_nextest_suite_span(self):
        """Interleaved suite arrivals retain their own envelope, never summed case work.
        ´claim:harness:nextest-suite-arrival-envelope´
        ´test:integration:test-nextest-suite-span´
        """
        from run_tests import suite_events
        registry = fixture()
        inventory = {'rust-suites': {'example': {'package-name': 'example',
                     'binary-name': 'example', 'kind': 'lib'}}}
        meta = dict(crate='example', test_binary='example', kind='lib')
        for outcome in ['ok', 'failed']:
            observations = [dict(offset_ms=10, item=dict(type='suite', event='started', nextest=meta)),
                            dict(offset_ms=20, item=dict(type='test', event='ok', name='other', exec_time=9)),
                            dict(offset_ms=30, item=dict(type='suite', event=outcome, exec_time=15, nextest=meta))]
            record, = suite_events(observations, inventory, registry, 'current', 'nextest')
            self.assertEqual(record['duration_ms'], 20)
            self.assertEqual(record['outcome'], 'passed' if outcome == 'ok' else 'failed')

    def test_missing_level(self):
        """A missing level is structural, preventing an undeclared scope from borrowing evidence.
        ´claim:harness:missing-level-refused´
        ´test:integration:test-missing-level´
        """
        declared = rows()
        del declared[-1]['level']
        with self.assertRaisesRegex(StructuralError, 'missing level'):
            Registry(declared, declarations())

    def test_unregistered_implementation(self):
        """An unknown implementation cannot supply evidence under an admitted identity.
        ´claim:harness:unregistered-implementation-refused´
        ´test:integration:test-unregistered-implementation´
        """
        declared = rows()
        declared[-1]['implementation'] = 'unknown'
        with self.assertRaisesRegex(StructuralError, 'unregistered implementation'):
            Registry(declared, declarations())

    def test_dropped_case(self):
        """Both inventory and result joins refuse a missing case, preserving the whole suite contract.
        ´claim:harness:dropped-case-refused´
        ´test:integration:test-dropped-case´
        """
        registry = fixture()
        with self.assertRaisesRegex(StructuralError, 'inventory differs'):
            registry.roster('nextest', [])
        with self.assertRaisesRegex(StructuralError, 'dropped'):
            registry.matrix([], 'current')

    def test_ignored_case(self):
        """An ignored required case cannot make its suite pass without executing its predicate.
        ´claim:harness:ignored-case-refused´
        ´test:integration:test-ignored-case´
        """
        registry = fixture()
        record = result(registry)
        record['outcome'] = 'ignored'
        with self.assertRaisesRegex(StructuralError, 'ignored'):
            registry.matrix([record], 'current')

    def test_mock_as_real(self):
        """Mock evidence cannot be relabelled as real service evidence and discharge its hold.
        ´claim:harness:mock-is-not-real´
        ´test:integration:test-mock-as-real´
        """
        declared = rows()
        declared[4]['evidence'] = 'mock'
        declared[-1]['budget'] = 'mock-suite'
        registry = Registry(declared, declarations())
        record = result(registry)
        record['evidence'] = 'real'
        with self.assertRaisesRegex(StructuralError, 'misreported evidence'):
            registry.matrix([record], 'current')

    def test_stale_source(self):
        """A result for another source cannot certify the current tree.
        ´claim:harness:stale-source-refused´
        ´test:integration:test-stale-source´
        """
        registry = fixture()
        record = result(registry)
        with self.assertRaisesRegex(StructuralError, 'misreported source'):
            registry.matrix([record], 'new-source')
        changed = copy.deepcopy(record)
        changed['configuration'] = 'different-features'
        with self.assertRaisesRegex(StructuralError, 'misreported configuration'):
            registry.matrix([changed], 'current')
        suite = registry.suite_event('example', None, 'passed', 'old-source')
        with self.assertRaisesRegex(StructuralError, 'misreported source'):
            registry.matrix([record, suite], 'current')

    def test_service_hold(self):
        """An unavailable service tier remains visibly held even when all fast cases pass.
        ´claim:harness:service-hold-visible´
        ´test:integration:test-service-hold´
        """
        registry = fixture()
        matrix = registry.matrix([result(registry)], 'current')
        self.assertEqual([r['status'] for r in matrix], ['passed', 'held'])
        self.assertIsNone(matrix[-1]['implementation'])

    def test_doctest_inventory(self):
        """A never-started or unfinished doctest remains missing, preventing a partial run from passing.
        ´claim:harness:doctest-inventory-complete´
        ´test:integration:test-doctest-inventory´
        """
        from run_tests import doctest_events
        registry = fixture('doctest', 'doctest::src/lib.rs - fixture [example 1]', 'doctest')
        for text in ['', '{"type":"test","event":"started","name":"src/lib.rs - fixture (line 1)"}']:
            records = doctest_events(text, 'current', CONFIGURATION, registry)
            self.assertEqual(records[0]['outcome'], 'incomplete')
            self.assertIsNone(records[0]['duration_ms'])
            with self.assertRaisesRegex(StructuralError, 'incomplete'):
                registry.matrix(records, 'current')

    def test_doctest_identity(self):
        """Unrelated line shifts preserve item/example identity; ambiguous source positions refuse.
        ´claim:harness:doctest-identity-survives-line-shifts´
        ´test:integration:test-doctest-identity´
        """
        from doctest_identity import identities
        from run_tests import doctest_events
        import json
        names = ['src/../README.md - (line 10)', 'src/../README.md - (line 20)',
                 'src/lib.rs - item (line 30)']
        shifted = [n.replace('10', '110').replace('20', '120').replace('30', '130') for n in names]
        expected = ['doctest::README.md - <module> [example 1]',
                    'doctest::README.md - <module> [example 2]',
                    'doctest::src/lib.rs - item [example 1]']
        self.assertEqual(list(identities(names).values()), expected)
        self.assertEqual(identities(reversed(shifted)), identities(shifted))
        declared = rows('doctest', expected[0], 'doctest')
        declared[-1]['cases'] = expected
        registry = Registry(declared, declarations())
        for raw in [names, shifted]:
            stream = '\n'.join(json.dumps(dict(type='test', event=event, name=name, exec_time=0.01))
                               for event in ['started', 'ok'] for name in reversed(raw))
            records = doctest_events(stream, 'current', CONFIGURATION, registry)
            self.assertEqual({r['operation'] for r in records}, set(expected))
            self.assertTrue(all(r['outcome'] == 'passed' for r in records))
        for bad in [[names[0], names[0]], [names[0], 'README.md - (line 10)'], ['no location']]:
            with self.assertRaises(StructuralError):
                identities(bad)


if __name__ == '__main__':
    unittest.main()
