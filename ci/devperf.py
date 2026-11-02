"""Nonverdict performance reporting. Durations are milliseconds, instants UTC.

Input is JSONL: operation, budget, duration_ms (null when unavailable), outcome,
source, configuration, owner; optional baseline_ms. Output findings are separate
from raw execution results. Exit 2 means malformed declarations or evidence;
duration excess and missing measurements always exit 0. No execution is retried.
"""

import argparse
import ast
import datetime
import hashlib
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
    calibration_declarations(result)
    return result


def calibration_declarations(declared):
    """A measured allowance is the stated rule over a named warm campaign."""
    from decimal import Decimal, ROUND_CEILING
    policy = declared.get('gate', {})
    campaigns = {}
    for campaign in policy.get('calibration_campaigns', []):
        label = campaign.get('label')
        if (not isinstance(label, str) or not re.fullmatch(r'campaign:[a-z0-9-]+:[a-z0-9-]+', label)
                or label in campaigns):
            raise StructuralError('missing, duplicate or malformed calibration campaign')
        expected = dict(multiplier=policy.get('allowance_multiple'), round_ms=policy.get('allowance_round_ms'),
                        warm_samples=policy.get('warm_samples'), discarded_warmups=1,
                        sample_choice='maximum-of-three-warm-serial', rounding='upward', warm=True)
        if (any(campaign.get(key) != value for key, value in expected.items())
                or any(type(expected[key]) is not int or expected[key] <= 0 for key in ('multiplier', 'round_ms', 'warm_samples'))
                or campaign.get('warm') is not True
                or not number(campaign.get('warmup_wall_seconds'))
                or not isinstance(campaign.get('sample_walls_seconds'), list)
                or len(campaign['sample_walls_seconds']) != expected['warm_samples']
                or not all(number(value) for value in campaign['sample_walls_seconds'])
                or not campaign.get('configuration')
                or not re.fullmatch(r'[0-9a-f]{40}', campaign.get('base_commit', ''))):
            raise StructuralError(label+': malformed campaign or rule parameters differ')
        series = campaign.get('measured_series')
        if (not isinstance(series, list) or not series
                or any(not isinstance(member, dict) or any(not re.fullmatch(r'[0-9a-f]{40}', member.get(key, '')) for key in ('commit', 'patch_id')) for member in series)
                or len({member['commit'] for member in series}) != len(series)):
            raise StructuralError(label+': measured public series is missing or malformed')
        campaigns[label] = campaign
    for name, row in declared.items():
        if not name.startswith('calibrated-') and 'calibration_campaign' not in row:
            continue
        pending = row.get('calibration_pending_owner')
        if 'calibration_pending_owner' in row:
            if not isinstance(pending, str) or not pending.strip() or 'calibration_campaign' in row:
                raise StructuralError(name+': pending calibration requires an owner and no asserted campaign')
            continue
        campaign = campaigns.get(row.get('calibration_campaign'))
        if campaign is None:
            raise StructuralError(name+': calibrated row requires an existing campaign or a pending owner')
        identity = row.get('calibration_source', {})
        if not isinstance(identity, dict):
            raise StructuralError(name+': calibration source must be a record')
        path = identity.get('path', '')
        if (not isinstance(identity, dict) or not path or Path(path).is_absolute()
                or '..' in Path(path).parts or not path.endswith(('.py', '.rs'))
                or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', identity.get('function', ''))
                or not re.fullmatch(r'[0-9a-f]{64}', identity.get('digest', ''))
                or not identity.get('owner')):
            raise StructuralError(name+': calibration requires a named source body and owner')
        walls = row.get('calibration_walls_ms')
        if (not isinstance(walls, list) or len(walls) != campaign['warm_samples']
                or not all(number(value) for value in walls)
                or row.get('calibration_warm') is not True
                or type(row.get('calibration_selected_sample')) is not int
                or row['calibration_selected_sample'] != walls.index(max(walls))+1
                or any(row.get('calibration_'+key) != campaign[key] for key in
                       ('sample_choice', 'configuration', 'multiplier', 'round_ms', 'discarded_warmups'))):
            raise StructuralError(name+': calibrated row differs from its warm campaign')
        unit = Decimal(str(campaign['round_ms']))
        expected = int((max(Decimal(str(value)) for value in walls)*campaign['multiplier']/unit).to_integral_value(rounding=ROUND_CEILING))*campaign['round_ms']
        if row['budget_ms'] != expected:
            raise StructuralError(name+': budget differs from the rule over recorded walls')


def identity_functions(text, path):
    """Collect exact functions and conservative same-file reference edges."""
    functions = {}
    if path.endswith('.py'):
        tree = ast.parse(text)
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        nodes = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        def scope(node):
            names = []
            while node in parents:
                node = parents[node]
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.append(node.name)
            return tuple(reversed(names))
        keys = {node: scope(node)+(node.name,) for node in nodes}
        known = set(keys.values())
        lines = text.splitlines(keepends=True)
        for node, key in keys.items():
            first = min([node.lineno]+[decorator.lineno for decorator in node.decorator_list])
            body = ''.join(lines[first-1:node.end_lineno])
            refs = set()
            for use in ast.walk(node):
                if isinstance(use, ast.Name) and isinstance(use.ctx, ast.Load):
                    for size in range(len(key), -1, -1):
                        target = key[:size]+(use.id,)
                        if target in known:
                            refs.add(target)
                            break
                elif isinstance(use, ast.Attribute) and isinstance(use.value, ast.Name):
                    if use.value.id in {'self', 'cls'}:
                        target = key[:-1]+(use.attr,)
                        if target in known: refs.add(target)
                    elif (use.value.id, use.attr) in known:
                        refs.add((use.value.id, use.attr))
            functions[key] = (body, refs)
    else:
        from source_sites import rust_mask
        masked = rust_mask(text)
        pairs = {}
        stack = []
        for match in re.finditer(r'[{}\[\]]', masked):
            char = match[0]
            if char in '{[': stack.append((char, match.start()))
            elif not stack or stack[-1][0] != {'}':'{', ']':'['}[char]:
                raise StructuralError('unbalanced Rust identity source: '+path)
            else:
                _, start = stack.pop()
                pairs[start] = match.start()
        if stack: raise StructuralError('unclosed Rust identity source: '+path)
        definitions = []
        for match in re.finditer(r'\bfn\s+(\w+)\s*(?:<|\()', masked):
            opening = masked.find('{', match.end())
            semicolon = masked.find(';', match.end())
            if opening < 0 or 0 <= semicolon < opening: continue
            end = pairs[opening]+1
            start = match.start()
            # Include declaration modifiers and every attached outer attribute.
            prefix = re.search(r'(?:(?:pub(?:\([^)]*\))?|async|const|unsafe|extern)\s+)*$', masked[:start])
            start = prefix.start()
            while True:
                previous = start-1
                while previous >= 0 and masked[previous].isspace(): previous -= 1
                if previous < 0 or masked[previous] != ']': break
                openings = [left for left, right in pairs.items() if right == previous]
                if not openings or openings[0] == 0 or masked[openings[0]-1] != '#': break
                start = openings[0]-1
            definitions.append((match[1], start, end, opening))
        counts = {}
        for name, start, end, opening in definitions:
            ordinal = counts.get(name, 0); counts[name] = ordinal+1
            key = (name, str(ordinal))
            references = set(re.findall(r'\b[A-Za-z_]\w*\b', masked[opening+1:end-1]))
            functions[key] = (text[start:end], references)
        # Method receivers and function values need not use direct call syntax.
        # Include every same-file candidate for a referenced name rather than
        # guessing a receiver type and silently omitting a possible callee.
        for key, (body, refs) in list(functions.items()):
            functions[key] = (body, {other for other in functions if other[0] in refs})
    return functions


def case_identity(text, path, function):
    """Hash attributes and transitive same-file callees, excluding other files."""
    functions = identity_functions(text, path)
    roots = [key for key in functions if (key[-1] if path.endswith('.py') else key[0]) == function]
    if len(roots) != 1:
        raise StructuralError('case identity is missing or ambiguous: '+path+'::'+function)
    pending = roots[:]
    reached = set()
    while pending:
        key = pending.pop()
        if key in reached: continue
        reached.add(key)
        pending.extend(functions[key][1]-reached)
    payload = [(key, functions[key][0]) for key in sorted(reached)]
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def calibration_identities(declared, root):
    """Changed bodies retain their allowance but lose calibrated standing."""
    result = []
    for name, row in declared.items():
        if 'calibration_pending_owner' in row:
            result.append(dict(budget=name, status='pending', owner=row['calibration_pending_owner'], reason='declared-pending'))
        elif 'calibration_campaign' in row:
            identity = row['calibration_source']
            path = root/identity['path']
            try:
                actual = case_identity(path.read_text(), identity['path'], identity['function'])
            except (OSError, StructuralError):
                actual = None
            result.append(dict(budget=name, status='exact' if actual == identity['digest'] else 'pending',
                               owner=identity['owner'], measured=identity['digest'], current=actual,
                               reason='same-case-closure' if actual == identity['digest'] else 'changed-case-closure'))
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
                         'classification': record.get('overrun_class') or ('build-or-aggregate-misconfiguration' if declaration['category'] in
                         {'build', 'aggregate'} else 'performance')})
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
    pending=record.get('undelivered_records',0)
    if type(pending) is not int or pending<0:raise StructuralError('malformed undelivered_records')
    if record['level']!='trace' or record['lost_records']+pending==0:return 0
    finding={**record,'kind':'observation-loss','classification':'observation-completeness','verdict_effect':'none'}
    with Path(output).open('a') as stream:stream.write(json.dumps(finding,sort_keys=True)+'\n')
    print('PERFORMANCE-WARNING '+json.dumps(finding,sort_keys=True),file=warnings)
    return 0


def excess_ledger(paths, source, declared):
    """Retain distinct current-run excesses; repeated reporting is not new work."""
    entries = {}
    for path in paths:
        if not path.exists(): continue
        for line in path.read_text().splitlines():
            record = json.loads(line)
            if record.get('source') != source or record.get('kind') != 'budget-excess': continue
            key = (record['configuration'], record['operation'], record['budget'], record['tier'])
            if key not in entries or entries[key]['duration_ms'] < record['duration_ms']:
                entries[key] = record
    rows = [entries[key] for key in sorted(entries)]
    cases = [row for row in rows if declared[row['budget']]['category'] == 'case']
    def counts(field):
        return {value: sum(row[field] == value for row in cases) for value in sorted({row[field] for row in cases})}
    return dict(source=source, distinct_cases=len(cases), by_budget=counts('budget'),
                by_tier=counts('tier'), distinct_excesses=len(rows), entries=rows,
                identity='configuration,operation,budget,tier', verdict_effect='none')


def print_ledger(source, declared, root):
    paths = [root/name for name in ('performance-findings.jsonl', 'wallet-conformance-findings.jsonl',
                                   'host-observation-runtime-findings.jsonl')]
    paths += sorted(root.glob('ci-test_*-findings.jsonl'))
    ledger = excess_ledger(paths, source, declared)
    identities = calibration_identities(declared, root.parent)
    ledger['calibration_identities'] = identities
    ledger['calibration_pending'] = [row for row in identities if row['status'] == 'pending']
    ledger['case_assessment'] = 'informational; judge case budgets in the separate calibration invocation'
    output = root/'over-budget-ledger.json'
    output.write_text(json.dumps(ledger, sort_keys=True, indent=2)+'\n')
    print('BUDGET-LEDGER '+json.dumps({key:value for key,value in ledger.items() if key not in ('entries', 'calibration_identities')} | {'artifact':str(output)}, sort_keys=True))
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
    parser.add_argument('--overrun-class', choices=['within-budget', 'unclassified', 'high-stall', 'rebuild', 'plain', 'growth'])
    parser.add_argument('--findings')
    parser.add_argument('--ledger', type=Path)
    parser.add_argument('--registry', default='docs/inputs/devperf-registry.toml')
    args = parser.parse_args()
    try:
        if args.ledger:
            return print_ledger(args.source, budgets(args.budgets), args.ledger)
        if not args.findings: raise StructuralError('findings output is required')
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
        if args.overrun_class:
            if args.input or not args.operation.startswith('tier::'):
                raise StructuralError('overrun class requires a tier operation')
            records[0]['overrun_class'] = args.overrun_class
            records[0]['tier'] = args.operation.removeprefix('tier::')
            records[0]['applicable_budgets'] = [args.budget]
        return report(records, budgets(args.budgets), args.findings, registry=registry)
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'PERFORMANCE-STRUCTURAL-ERROR {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
