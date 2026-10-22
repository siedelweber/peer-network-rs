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
        result[name] = value
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


def assess(record, declared):
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
    threshold = declared[record['budget']]
    findings = []
    kinds = []
    if duration is None:
        kinds.append('missing-measurement')
    elif duration > threshold:
        kinds.append('budget-excess')
    # Comparisons are supplied only after an external comparable five-sample
    # campaign. Missing baselines remain explicit and never become zero.
    if duration is not None and baseline is not None and duration > baseline * 1.2 and duration - baseline > 100:
        kinds.append('regression')
    for kind in kinds:
        findings.append({**record, 'duration_ms': duration, 'kind': kind, 'budget_ms': threshold,
                         'baseline_ms': baseline, 'verdict_effect': 'none',
                         'classification': 'build-or-aggregate-misconfiguration' if record['budget'] in
                         {'clean-build', 'incremental-build', 'gate', 'service-gate', 'test-command'} else 'performance'})
    return findings


def report(records, declared, output, warnings=sys.stderr):
    # Validate the whole batch before publishing; raw records are never mutated.
    findings = [finding for record in records for finding in assess(record, declared)]
    with Path(output).open('a') as stream:
        for finding in findings:
            stream.write(json.dumps(finding, sort_keys=True, allow_nan=False) + '\n')
            print('PERFORMANCE-WARNING ' + json.dumps(finding, sort_keys=True, allow_nan=False), file=warnings)
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
                            owner='foundation implementer', utc=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'))]
        return report(records, budgets(args.budgets), args.findings)
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'PERFORMANCE-STRUCTURAL-ERROR {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
