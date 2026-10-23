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
    def test_missing_level(self):
        """A missing level is structural, preventing an undeclared scope from borrowing evidence.
        ´claim:harness:missing-level-refused´
        ´test:harness:test-missing-level´
        """
        declared = rows()
        del declared[-1]['level']
        with self.assertRaisesRegex(StructuralError, 'missing level'):
            Registry(declared, declarations())

    def test_unregistered_implementation(self):
        """An unknown implementation cannot supply evidence under an admitted identity.
        ´claim:harness:unregistered-implementation-refused´
        ´test:harness:test-unregistered-implementation´
        """
        declared = rows()
        declared[-1]['implementation'] = 'unknown'
        with self.assertRaisesRegex(StructuralError, 'unregistered implementation'):
            Registry(declared, declarations())

    def test_dropped_case(self):
        """Both inventory and result joins refuse a missing case, preserving the whole suite contract.
        ´claim:harness:dropped-case-refused´
        ´test:harness:test-dropped-case´
        """
        registry = fixture()
        with self.assertRaisesRegex(StructuralError, 'inventory differs'):
            registry.roster('nextest', [])
        with self.assertRaisesRegex(StructuralError, 'dropped'):
            registry.matrix([], 'current')

    def test_ignored_case(self):
        """An ignored required case cannot make its suite pass without executing its predicate.
        ´claim:harness:ignored-case-refused´
        ´test:harness:test-ignored-case´
        """
        registry = fixture()
        record = result(registry)
        record['outcome'] = 'ignored'
        with self.assertRaisesRegex(StructuralError, 'ignored'):
            registry.matrix([record], 'current')

    def test_mock_as_real(self):
        """Mock evidence cannot be relabelled as real service evidence and discharge its hold.
        ´claim:harness:mock-is-not-real´
        ´test:harness:test-mock-as-real´
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
        ´test:harness:test-stale-source´
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
        ´test:harness:test-service-hold´
        """
        registry = fixture()
        matrix = registry.matrix([result(registry)], 'current')
        self.assertEqual([r['status'] for r in matrix], ['passed', 'held'])
        self.assertIsNone(matrix[-1]['implementation'])

    def test_doctest_inventory(self):
        """A never-started or unfinished doctest remains missing, preventing a partial run from passing.
        ´claim:harness:doctest-inventory-complete´
        ´test:harness:test-doctest-inventory´
        """
        from run_tests import doctest_events
        registry = fixture('doctest', 'doctest::fixture', 'doctest')
        for text in ['', '{"type":"test","event":"started","name":"fixture"}']:
            records = doctest_events(text, 'current', CONFIGURATION, registry)
            self.assertEqual(records[0]['outcome'], 'incomplete')
            self.assertIsNone(records[0]['duration_ms'])
            with self.assertRaisesRegex(StructuralError, 'incomplete'):
                registry.matrix(records, 'current')


if __name__ == '__main__':
    unittest.main()
