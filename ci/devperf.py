"""Nonverdict performance reporting. Durations are milliseconds, instants UTC.

Input is JSONL: operation, budget, duration_ms (null when unavailable), outcome,
source, configuration, owner; optional baseline_ms. Output findings are separate
from raw execution results. Exit 2 means malformed declarations or evidence;
duration excess and missing measurements always exit 0. No execution is retried.
"""

import argparse
import datetime
import json
import math
from pathlib import Path
import re
import sys
import tomllib


class StructuralError(ValueError):
    """Invalid declarations, distinct from measured performance."""


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def budgets(path):
    rows = tomllib.loads(Path(path).read_text()).get('rows', [])
    result = {}
    for row in rows:
        name = row.get('name')
        value = row.get('budget_ms')
        if not isinstance(name, str) or not name or name in result or not number(value) or value == 0:
            raise StructuralError('missing, duplicate or malformed budget declaration')
        if row.get('category') not in {'case', 'suite', 'aggregate', 'build'} or not row.get('scope') or not row.get('reason'):
            raise StructuralError(f'{name}: missing budget scope, category or reason')
        result[name] = row
    if not result:
        raise StructuralError('missing budget declarations')
    return result


def utc(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise StructuralError('instant must be explicit UTC ending Z; naive and offset input refused')
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z', value):
        raise StructuralError('malformed UTC instant')
    try:
        datetime.datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError as error:
        raise StructuralError('malformed UTC instant') from error
    return value


def assessment(record):
    """Comparison confidence is evidence, never a functional verdict or finding."""
    reason = None
    if record.get('duration_ms') is None:
        reason = 'missing-measurement'
    elif record.get('clock_quality', 'stable') != 'stable':
        reason = 'noisy-clock'
    elif record.get('baseline_ms') is None:
        reason = 'missing-baseline'
    elif record.get('baseline_cache') != record.get('cache_state'):
        reason = 'incompatible-cache'
    elif record.get('baseline_compatible') is not True or record.get('baseline_samples', 0) < 5:
        reason = 'unestablished-comparison'
    return dict(operation=record['operation'], source=record['source'], configuration=record['configuration'],
                assessment='inconclusive' if reason else 'comparable', reason=reason,
                outcome=record['outcome'], verdict_effect='none')


def inclusive_ms(spans):
    """Inclusive envelope of measured spans in milliseconds, never their sum."""
    if not spans:
        return None
    if any(not number(a) or not number(b) or b < a for a, b in spans):
        raise StructuralError('malformed elapsed span in milliseconds')
    return max(b for a, b in spans) - min(a for a, b in spans)


def assess(record, declared, registry=()):
    if not isinstance(record, dict):
        raise StructuralError('measurement must be an object')
    for key in ('operation', 'budget', 'outcome', 'source', 'configuration', 'owner'):
        if not isinstance(record.get(key), str) or not record[key]:
            raise StructuralError(f'missing or malformed {key} declaration')
    if record['budget'] not in declared:
        raise StructuralError(f"unknown budget declaration: {record['budget']}")
    duration = record.get('duration_ms')
    if duration is not None and not number(duration):
        raise StructuralError('malformed duration_ms; expected finite nonnegative milliseconds or null')
    baseline = record.get('baseline_ms')
    if baseline is not None and not number(baseline):
        raise StructuralError('malformed baseline_ms')
    if 'utc' in record:
        utc(record['utc'])
    declaration = declared[record['budget']]
    threshold = declaration['budget_ms']
    admitted = [r for r in registry if r['name'] == record['operation'] and r['status'] == 'admitted']
    if len(admitted) > 1:
        raise StructuralError('duplicate admitted operation')
    if admitted:
        entry = admitted[0]
        if entry.get('ordinary_budget') != record['budget'] or not number(entry.get('budget_ms')) or entry['budget_ms'] <= 0 or any(not entry.get(k) for k in ('label', 'owner', 'reason', 'measurement', 'placement', 'settlement')):
            raise StructuralError('malformed admitted budget declaration')
        threshold = entry['budget_ms']
    findings = []
    kinds = []
    if duration is None:
        kinds.append('missing-measurement')
    elif duration > threshold:
        kinds.append('budget-excess')
    # Comparisons are supplied only after an external comparable five-sample
    # campaign. Missing baselines remain explicit and never become zero.
    if assessment(record)['assessment'] == 'comparable' and duration > baseline * 1.2 and duration - baseline > 100:
        kinds.append('regression')
    for kind in kinds:
        findings.append({**record, 'duration_ms': duration, 'kind': kind, 'budget_ms': threshold,
                         'baseline_ms': baseline, 'verdict_effect': 'none',
                         'admission': admitted[0]['label'] if admitted else None,
                         'classification': 'build-or-aggregate-misconfiguration' if declaration['category'] in
                         {'build', 'aggregate'} else 'performance'})
    return findings


def report(records, declared, output, warnings=sys.stderr, registry=()):
    # Validate the whole batch before publishing; raw records are never mutated.
    findings = [finding for record in records for finding in assess(record, declared, registry)]
    with Path(output).with_name('performance-assessments.jsonl').open('a') as stream:
        for record in records:
            stream.write(json.dumps(assessment(record), sort_keys=True) + '\n')
    with Path(output).open('a') as stream:
        for finding in findings:
            stream.write(json.dumps(finding, sort_keys=True, allow_nan=False) + '\n')
            print('PERFORMANCE-WARNING ' + json.dumps(finding, sort_keys=True, allow_nan=False), file=warnings)
    return 0


def report_loss(record, output, warnings=sys.stderr):
    """Persist trace incompleteness beside timing findings without changing outcomes."""
    for key in ('source','configuration','operation','outcome'):
        if not isinstance(record.get(key),str) or not record[key]:raise StructuralError('missing loss '+key)
    for key in ('delivered_records','lost_records'):
        if type(record.get(key)) is not int or record[key]<0:raise StructuralError('malformed '+key)
    utc(record['utc'])
    if record['level']!='trace' or record['lost_records']==0:return 0
    finding={**record,'kind':'observation-loss','classification':'observation-completeness','verdict_effect':'none'}
    with Path(output).open('a') as stream:stream.write(json.dumps(finding,sort_keys=True)+'\n')
    print('PERFORMANCE-WARNING '+json.dumps(finding,sort_keys=True),file=warnings)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--budgets', default='docs/inputs/devperf-budgets.toml')
    parser.add_argument('--input')
    parser.add_argument('--operation')
    parser.add_argument('--duration-s', type=float)
    parser.add_argument('--outcome')
    parser.add_argument('--source', default='working tree')
    parser.add_argument('--budget', default='ordinary-check')
    parser.add_argument('--findings', required=True)
    parser.add_argument('--registry', default='docs/inputs/devperf-registry.toml')
    args = parser.parse_args()
    try:
        if bool(args.input) == bool(args.operation):
            raise StructuralError('choose one input file or operation')
        if args.input:
            records = [json.loads(line) for line in Path(args.input).read_text().splitlines() if line.strip()]
        else:
            records = [dict(operation=args.operation, budget=args.budget,
                            duration_ms=None if args.duration_s is None else args.duration_s * 1000,
                            outcome=args.outcome, source=args.source, configuration='repository gate',
                            owner='foundation implementer', level='operation', suite='gate-operations',
                            implementation='repository-tools', tier='fast', applicable_budgets=[args.budget, 'gate'], utc=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'))]
        registry = tomllib.loads(Path(args.registry).read_text())['rows']
        return report(records, budgets(args.budgets), args.findings, registry=registry)
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'PERFORMANCE-STRUCTURAL-ERROR {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
