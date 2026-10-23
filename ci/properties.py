"""Declared bounded property configuration and evidence, independent of timing."""

from pathlib import Path
import hashlib
import tomllib

from devperf import StructuralError

PATH = Path(__file__).resolve().parent.parent / 'docs/inputs/harness-properties.toml'


def declarations():
    rows = tomllib.loads(PATH.read_text())['rows']
    result = {}
    if not rows:
        raise StructuralError('missing property declarations')
    for row in rows:
        if row['name'] in result or row.get('seed_policy') != 'source-v1' or type(row.get('cases')) is not int or row['cases'] < 256:
            raise StructuralError('malformed property seed/case declaration')
        if row.get('algorithm') != 'cc' or any(not row.get(key) for key in ('generator', 'edition', 'dependency', 'regressions', 'case_count_kind')):
            raise StructuralError('missing property replay declaration')
        result[row['name']] = row
    locked = [package['version'] for package in tomllib.loads((PATH.parents[2]/'Cargo.lock').read_text())['package'] if package['name'] == 'proptest']
    if len(locked) != 1 or any(row['dependency'] != 'proptest '+locked[0] for row in rows):
        raise StructuralError('property dependency edition differs from Cargo.lock')
    from source_sites import census, property_roster
    property_roster(census(PATH.parents[2]), result)
    return result


def seed(source):
    if not isinstance(source, str) or not source:
        raise StructuralError('property seed requires source identity')
    return str(int.from_bytes(hashlib.sha256(('pn-property-seed-v1:'+source).encode()).digest()[:8], 'big'))


def environment(rows, source):
    if not rows:
        return {}
    configurations = {(row['seed_policy'], row['cases'], row['algorithm']) for row in rows.values()}
    if len(configurations) != 1:
        raise StructuralError('runner requires one declared bounded seed configuration')
    _, cases, algorithm = configurations.pop()
    return {'PROPTEST_RNG_SEED': seed(source), 'PROPTEST_CASES': str(cases), 'PROPTEST_RNG_ALGORITHM': algorithm,
            'PROPTEST_FORK': 'false', 'PROPTEST_TIMEOUT': '0', 'PROPTEST_MAX_SHRINK_TIME': '0',
            'PROPTEST_MAX_SHRINK_ITERS': '4294967295'}


def evidence(row, outcome, source):
    return dict(seed=seed(source), seed_policy=row['seed_policy'], case_count=row['cases'], case_count_kind=row['case_count_kind'],
                completed_generated_cases=row['cases'] if outcome == 'passed' else None,
                generator=row['generator'], generator_edition=row['edition'], shrinker_edition=row['dependency'],
                rng_algorithm=row['algorithm'], regression_corpus=row['regressions'],
                scheduling='synchronous; no fork or timeout', fault_choices='none')


def validate(record, rows):
    declaration = rows.get(record.get('operation'))
    if declaration is None:
        return
    if not record.get('seed'):
        raise StructuralError('property result missing seed')
    for key, value in evidence(declaration, record['outcome'], record['source']).items():
        if record.get(key) != value:
            raise StructuralError('property replay evidence mismatch: '+key)
