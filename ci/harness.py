"""Declared test accounting; functional results and performance evidence stay separate."""

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import time
import tomllib

from devperf import StructuralError, budgets

CONFIGURATION = 'foundation-fast/gate/default-features'
REGISTRY = Path(__file__).resolve().parent.parent / 'docs/inputs/harness-registry.toml'


def source_id():
    started = time.monotonic()
    result = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    print(f'git rev-parse wall={time.monotonic() - started:.6f}s', flush=True)
    return result


class Registry:
    def __init__(self, rows, declared, properties=None):
        self.properties = properties or {}
        self.levels = {}
        self.implementations = {}
        self.tiers = {}
        self.suites = {}
        self.cases = {}
        destinations = {'level': self.levels, 'implementation': self.implementations,
                        'tier': self.tiers, 'suite': self.suites}
        for row in rows:
            if row.get('kind') not in destinations or not row.get('name'):
                raise StructuralError('unknown or unnamed registry declaration')
            table = destinations[row['kind']]
            if row['name'] in table:
                raise StructuralError('duplicate registry declaration: ' + row['name'])
            table[row['name']] = row
        if set(self.levels) != {'unit', 'public-surface', 'integration', 'doctest'}:
            raise StructuralError('missing level declaration')
        for level in self.levels.values():
            if level.get('budget') not in declared or declared[level['budget']]['category'] != 'case':
                raise StructuralError('unknown level budget')
        for tier in self.tiers.values():
            if tier.get('status') not in {'active', 'held'} or (tier['status'] == 'held' and not tier.get('reason')):
                raise StructuralError('invalid tier declaration')
        for implementation in self.implementations.values():
            if implementation.get('evidence') not in {'pure', 'vendor', 'mock', 'real'}:
                raise StructuralError('unknown implementation evidence class')
        for suite in self.suites.values():
            if suite.get('tier') not in self.tiers or suite.get('status') not in {'active', 'held'}:
                raise StructuralError('unknown suite tier or status')
            if suite['status'] == 'held':
                if suite.get('implementation') or suite.get('cases') or not suite.get('reason'):
                    raise StructuralError('held suite must have no implementation or cases and name its reason')
                continue
            if suite.get('level') not in self.levels:
                raise StructuralError('missing level: ' + suite['name'])
            if suite.get('implementation') not in self.implementations:
                raise StructuralError('unregistered implementation: ' + suite['name'])
            if suite.get('budget') not in declared or declared[suite['budget']]['category'] != 'suite' or not isinstance(suite.get('cases'), list) or not suite['cases']:
                raise StructuralError('suite needs budget and nonempty case roster')
            evidence = self.implementations[suite['implementation']]['evidence']
            if self.tiers[suite['tier']]['status'] != 'active':
                raise StructuralError('active suite requires an active tier')
            if evidence == 'real' and suite['tier'] != 'service':
                raise StructuralError('real implementation requires service tier')
            if evidence == 'mock' and suite['budget'] != 'mock-suite':
                raise StructuralError('mock implementation requires mock-suite budget')
            if suite.get('runner') not in {'nextest', 'doctest', 'ci', 'contract', 'benchmark'}:
                raise StructuralError('unknown suite runner')
            for case in suite['cases']:
                if not isinstance(case, str) or not case or case in self.cases:
                    raise StructuralError('duplicate or malformed registered case')
                self.cases[case] = suite
        if not set(self.properties).issubset(self.cases):
            raise StructuralError('unregistered property case')
        for suite in self.suites.values():
            if suite.get('runner') == 'contract' and (suite.get('parent_case') not in self.cases or not suite.get('contract_edition') or not suite.get('claim')):
                raise StructuralError('contract case mapping lacks parent, edition or establishing claim')

    def expected(self, runner):
        return {name for name, suite in self.cases.items() if suite['runner'] == runner}

    def roster(self, runner, observed):
        actual = list(observed)
        expected = self.expected(runner)
        if len(actual) != len(set(actual)) or set(actual) != expected:
            raise StructuralError(f'{runner}: case inventory differs; missing={sorted(expected-set(actual))} extra={sorted(set(actual)-expected)}')

    def join(self, record, source, configuration=CONFIGURATION):
        from properties import validate
        validate(record, self.properties)
        name = record.get('operation')
        if name not in self.cases:
            raise StructuralError(f'unregistered case: {name}')
        suite = self.cases[name]
        implementation = self.implementations[suite['implementation']]
        level = self.levels[suite['level']]
        fields = dict(source=source, configuration=configuration, level=suite['level'],
                      suite=suite['name'], implementation=suite['implementation'], tier=suite['tier'],
                      evidence=implementation['evidence'], budget=level['budget'],
                      applicable_budgets=[level['budget'], suite['budget'], 'test-command', 'gate'])
        fields.update({key: suite[key] for key in ('contract_edition', 'claim', 'claim_owner', 'parent_case') if key in suite})
        for key, value in fields.items():
            if key in record and record[key] != value:
                raise StructuralError(f'{name}: stale or misreported {key}')
        return {**record, **fields, 'scope': 'case'}

    def suite_event(self, name, duration_ms, outcome, source):
        suite = self.suites[name]
        impl = self.implementations[suite['implementation']]
        return dict(operation='suite::'+name, scope='suite', suite=name, level=suite['level'],
                    implementation=suite['implementation'], tier=suite['tier'], evidence=impl['evidence'],
                    source=source, configuration=CONFIGURATION, budget=suite['budget'],
                    applicable_budgets=[suite['budget'], 'test-command', 'gate'], duration_ms=duration_ms,
                    outcome=outcome, owner='foundation implementer')

    def matrix(self, records, source):
        for record in records:
            if record.get('source') != source:
                raise StructuralError('stale or misreported source')
            if record.get('configuration') != CONFIGURATION:
                raise StructuralError('stale or misreported configuration')
            if record.get('scope') == 'suite':
                suite = self.suites.get(record.get('suite'))
                if not suite or suite['status'] != 'active':
                    raise StructuralError('unregistered suite result')
                for key in ('level', 'implementation', 'tier', 'budget'):
                    if record.get(key) != suite[key]:
                        raise StructuralError('misreported suite ' + key)
        cases = [r for r in records if r.get('scope') == 'case']
        if len(cases) != len(self.cases) or {r['operation'] for r in cases} != set(self.cases):
            raise StructuralError('dropped or duplicate suite case')
        joined = [self.join(r, source) for r in cases]
        if any(r['outcome'] not in {'passed', 'failed'} for r in joined):
            raise StructuralError('ignored or incomplete required test')
        result = []
        for suite in self.suites.values():
            row = dict(source=source, configuration=CONFIGURATION, suite=suite['name'],
                       implementation=suite.get('implementation') or None, tier=suite['tier'])
            if suite['status'] == 'held':
                result.append({**row, 'status': 'held', 'reason': suite['reason'], 'expected': 0, 'observed': 0})
            else:
                outcomes = Counter(r['outcome'] for r in joined if r['suite'] == suite['name'])
                result.append({**row, 'status': 'failed' if outcomes['failed'] else 'passed',
                               'expected': len(suite['cases']), 'observed': sum(outcomes.values()), 'outcomes': dict(outcomes)})
        for tier in self.tiers.values():
            if tier['status'] == 'held':
                result.append(dict(source=source, configuration=CONFIGURATION, suite=None, implementation=None,
                                   tier=tier['name'], status='held', reason=tier['reason']))
        return result


def load():
    from properties import declarations
    return Registry(tomllib.loads(REGISTRY.read_text())['rows'], budgets(REGISTRY.with_name('devperf-budgets.toml')), declarations())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', action='store_true')
    args = parser.parse_args()
    try:
        registry = load()
        if args.matrix:
            paths = [Path('.lane/performance-events.jsonl'), Path('.lane/harness-benchmarks.jsonl'), *sorted(Path('.lane').glob('harness-ci-*.jsonl'))]
            records = [json.loads(line) for path in paths for line in path.read_text().splitlines()]
            matrix = registry.matrix(records, source_id())
            Path('.lane/harness-matrix.json').write_text(json.dumps({'schema': 1, 'rows': matrix}, indent=2)+'\n')
            counts = Counter(row['status'] for row in matrix)
            print(f'HARNESS-MATRIX cases={len(registry.cases)} passed={counts["passed"]} failed={counts["failed"]} held={counts["held"]} artifact=.lane/harness-matrix.json')
            return int(bool(counts['failed']))
        print(f'HARNESS-REGISTRY levels={len(registry.levels)} suites={len(registry.suites)} implementations={len(registry.implementations)} cases={len(registry.cases)}')
        return 0
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'HARNESS-STRUCTURAL-ERROR {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
