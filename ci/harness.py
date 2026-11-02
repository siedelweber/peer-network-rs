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

CONFIGURATION = 'foundation-fast/gate/default-features+pn-records/test-support+pn-wallet/fuzzing'
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
            if 'invocation_budget' in tier and (tier['invocation_budget'] not in declared or declared[tier['invocation_budget']]['category'] != 'aggregate'):
                raise StructuralError('unknown tier invocation budget')
            if tier.get('status') not in {'active', 'held'} or (tier['status'] == 'held' and not tier.get('reason')):
                raise StructuralError('invalid tier declaration')
            if tier.get('case_budget_policy') not in {None, 'declared-suite'}:
                raise StructuralError('unknown tier case budget policy')
            if tier.get('case_budget_policy') and not tier.get('reason'):
                raise StructuralError('tier case budget policy requires a reason')
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
            tier_budget = self.tiers[suite['tier']].get('case_budget_policy') == 'declared-suite'
            if tier_budget:
                if suite.get('case_budget') not in declared or declared[suite['case_budget']]['category'] != 'case':
                    raise StructuralError('tier requires a declared case budget')
            elif 'case_budget' in suite:
                raise StructuralError('case budget override requires a declared tier policy')
            if 'case_span' in suite and (suite['case_span'] is not True or suite['runner'] != 'nextest'):
                raise StructuralError('case span requires an explicit nextest group')
            overrides=suite.get('case_levels',{})
            reasons=suite.get('case_level_reasons',{})
            if not isinstance(overrides,dict) or not isinstance(reasons,dict) or set(overrides)!=set(reasons) or not set(overrides)<=set(suite['cases']):
                raise StructuralError('case level override lacks a declared case and premise')
            if any(level not in self.levels or not isinstance(reasons[name],str) or not reasons[name].strip() for name,level in overrides.items()):
                raise StructuralError('missing case level or premise')
            case_budgets = suite.get('case_budgets', {})
            budget_reasons = suite.get('case_budget_reasons', {})
            if (not isinstance(case_budgets, dict) or not isinstance(budget_reasons, dict)
                    or set(case_budgets) != set(budget_reasons)
                    or not set(case_budgets) <= set(suite['cases'])):
                raise StructuralError('case budget override lacks a declared case and cost')
            if case_budgets and tier_budget:
                raise StructuralError('case budget cannot override a tier-declared suite budget')
            for case, budget in case_budgets.items():
                if (budget not in declared or declared[budget]['category'] != 'case'
                        or not isinstance(budget_reasons[case], str) or not budget_reasons[case].strip()):
                    raise StructuralError('missing case budget or named cost')
            for case in suite['cases']:
                if not isinstance(case, str) or not case or case in self.cases:
                    raise StructuralError('duplicate or malformed registered case')
                self.cases[case] = dict(suite,level=overrides.get(case,suite['level']))
                if case in case_budgets:
                    self.cases[case]['case_budget'] = case_budgets[case]
        if not set(self.properties).issubset(self.cases):
            raise StructuralError('unregistered property case')
        for suite in self.suites.values():
            if suite.get('runner') == 'contract' and (suite.get('parent_case') not in self.cases or not suite.get('contract_edition') or not suite.get('claim')):
                raise StructuralError('contract case mapping lacks parent, edition or establishing claim')

    def case_budget(self, name):
        suite = self.cases[name]
        return suite.get('case_budget', self.levels[suite['level']]['budget'])

    def expected(self, runner):
        return {name for name, suite in self.cases.items() if suite['runner'] == runner}

    def roster(self, runner, observed):
        actual = list(observed)
        expected = self.expected(runner)
        if len(actual) != len(set(actual)) or set(actual) != expected:
            raise StructuralError(f'{runner}: case inventory differs; missing={sorted(expected-set(actual))} extra={sorted(set(actual)-expected)}')

    def aggregate_budgets(self, tier):
        budget = self.tiers[tier].get('invocation_budget')
        return [budget] if budget and tier != 'fast' else ['test-command', 'gate']

    def join(self, record, source, configuration=CONFIGURATION):
        from properties import validate
        validate(record, self.properties)
        name = record.get('operation')
        if name not in self.cases:
            raise StructuralError(f'unregistered case: {name}')
        suite = self.cases[name]
        implementation = self.implementations[suite['implementation']]
        budget = self.case_budget(name)
        fields = dict(source=source, configuration=configuration, level=suite['level'],
                      suite=suite['name'], implementation=suite['implementation'], tier=suite['tier'],
                      evidence=implementation['evidence'], budget=budget,
                      applicable_budgets=[budget, suite['budget'], *self.aggregate_budgets(suite['tier'])])
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
                    applicable_budgets=[suite['budget'], *self.aggregate_budgets(suite['tier'])], duration_ms=duration_ms,
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
        from build_graph_evidence import held_service, retained_service
        if any(r.get('retained') and not retained_service(r, Path.cwd()) for r in joined):
            raise StructuralError('invalid retained service evidence')
        if any(r['outcome'] not in {'passed', 'failed'} and not held_service(r, Path.cwd()) for r in joined):
            raise StructuralError('ignored or incomplete required test')
        result = []
        for suite in self.suites.values():
            row = dict(source=source, configuration=CONFIGURATION, suite=suite['name'],
                       implementation=suite.get('implementation') or None, tier=suite['tier'],
                       contract_edition=suite.get('contract_edition'))
            if 'observation' in suite:
                row['observation'] = suite['observation']
                row['property_observations'] = [dict(operation=r['operation'], seed=r['seed'], consumer=r.get('seed_consumer'))
                                                for r in joined if r['suite']==suite['name'] and 'seed' in r]
            if suite['status'] == 'held':
                result.append({**row, 'status': 'held', 'reason': suite['reason'], 'expected': 0, 'observed': 0})
            else:
                outcomes = Counter(r['outcome'] for r in joined if r['suite'] == suite['name'])
                result.append({**row, 'status': 'failed' if outcomes['failed'] else ('held' if outcomes['held'] else 'passed'),
                               'expected': len(suite['cases']), 'observed': sum(r['outcome'] in {'passed', 'failed'} and not r.get('retained', False) for r in joined if r['suite']==suite['name']), 'outcomes': dict(outcomes),
                               'retained': [dict(operation=r['operation'], source=r['execution_source']) for r in joined if r['suite']==suite['name'] and r.get('retained')],
                               'holds': [dict(operation=r['operation'], hold=r['hold'], reason=r['reason']) for r in joined if r['suite']==suite['name'] and r['outcome']=='held']})
        for tier in self.tiers.values():
            if tier['status'] == 'held':
                result.append(dict(source=source, configuration=CONFIGURATION, suite=None, implementation=None,
                                   contract_edition=None, tier=tier['name'], status='held', reason=tier['reason']))
        return result


def load():
    from properties import declarations
    return Registry(tomllib.loads(REGISTRY.read_text())['rows'], budgets(REGISTRY.with_name('devperf-budgets.toml')), declarations())


def passing_editions(matrix):
    editions = {}
    for row in matrix:
        if row['status'] == 'passed' and row['contract_edition']:
            implementations = editions.setdefault(row['contract_edition'], {})
            implementation = row['implementation']
            if not implementation:
                raise StructuralError('passing contract edition lacks implementation')
            implementations[implementation] = implementations.get(implementation, 0) + 1
    return editions


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
            editions = passing_editions(matrix)
            print(f'HARNESS-MATRIX cases={len(registry.cases)} passed={counts["passed"]} failed={counts["failed"]} held={counts["held"]} passed_by_edition={json.dumps(editions, sort_keys=True, separators=(",", ":"))} artifact=.lane/harness-matrix.json')
            return int(bool(counts['failed']))
        print(f'HARNESS-REGISTRY levels={len(registry.levels)} suites={len(registry.suites)} implementations={len(registry.implementations)} cases={len(registry.cases)}')
        return 0
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'HARNESS-STRUCTURAL-ERROR {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
