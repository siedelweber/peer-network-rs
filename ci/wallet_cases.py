"""Join every declared wallet case to a held remainder or executed source claim."""
import json
from pathlib import Path
import tomllib


def check(groups, rows, obligations, sites, results=None):
    expected = {(g['name'], case) for g in groups for case in g['cases']}
    actual = [(r['group'], r['case']) for r in rows]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ValueError('wallet case census omitted, duplicated or stale')
    by_claim = {}
    for site in sites:
        by_claim.setdefault(site['claim'], set()).add(site['operation'])
    passed = {r['operation'] for r in results or [] if r['outcome'] == 'passed'}
    declared = {r['name']: r for r in obligations}
    for group in groups:
        obligation = declared['ROOT::verif:devnet:wallet-'+group['name']]
        if obligation.get('case_census') != group['cases']:
            raise ValueError('wallet obligation differs from case census')
        group_rows = [r for r in rows if r['group'] == group['name']]
        for row in group_rows:
            if row['status'] == 'held':
                if not row.get('missing') or row.get('claims'):
                    raise ValueError('wallet held case lacks a remainder')
                if obligation['status'] != 'held':
                    raise ValueError('wallet group discharged with a held case')
            elif row['status'] == 'scoped':
                if not row.get('claims') or not set(row['claims']) <= set(by_claim):
                    raise ValueError('wallet case lacks source claim')
                if results is not None and any(not by_claim[c] <= passed for c in row['claims']):
                    raise ValueError('wallet case lacks passed execution')
                if obligation['status'] != 'held' and not set(row['claims']) <= set(obligation['claims']):
                    raise ValueError('wallet case claims missing from obligation')
            else:
                raise ValueError('unknown wallet case status')
    return len(expected)


def repository_check(sites, results=None):
    groups = tomllib.loads(Path('docs/inputs/devnet-profile.toml').read_text())['rows'][0]['wallet_case_groups']
    obligations = tomllib.loads(Path('docs/inputs/claim-obligations.toml').read_text())['rows']
    rows = json.loads(Path('ci/wallet-cases.json').read_text())['cases']
    count = check(groups, rows, obligations, sites, results)
    print(f'WALLET-CASE-CENSUS cases={count} scoped={sum(r["status"] == "scoped" for r in rows)} held={sum(r["status"] == "held" for r in rows)}')
