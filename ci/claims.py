"""Bidirectional source/claim/obligation/result accounting beside the linter."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
import tomllib

from devperf import StructuralError
from harness import CONFIGURATION, load as load_registry, source_id
from source_sites import census, claim_mints, OWNERS

LABEL = r'[a-z][a-z0-9-]*:[a-z0-9-]+:[a-z0-9.-]+'
OBLIGATION_KINDS = {'req', 'dec', 'verif', 'plan', 'gate'}



def owner_of(path):
    parts = Path(path).parts
    return OWNERS.get(parts[1], 'ROOT') if len(parts)>1 and parts[0]=='packages' else 'ROOT'


def qualify(label, owner):
    if label.startswith('['):
        prefix, label = label[1:-1].split('-', 1)
        return prefix+'::'+label
    return owner+'::'+label


def prose(root):
    """Harvest authored Markdown heads only, never planned double-backtick names."""
    paragraphs = {}
    obligations = {}
    root = Path(root)
    paths = [root/'README.md', *sorted((root/'adr').glob('*.md')),
             *sorted((root/'docs/design').glob('*.md')),
             *sorted((root/'packages').glob('*/README.md'))]
    for path in paths:
        if not path.exists(): continue
        owner = owner_of(path.relative_to(root))
        for paragraph in path.read_text().split('\n\n'):
            head = re.search(r'· `('+LABEL+r')`', paragraph)
            if not head: continue
            name = qualify(head[1], owner)
            if name in paragraphs: raise StructuralError('duplicate prose mint: '+name)
            citations = {qualify(m[1], owner) for m in re.finditer(r'\(`(\[[A-Z]+-'+LABEL+r'\]|'+LABEL+r')`\)', paragraph)}
            exhibits = {qualify(m[1], owner) for m in re.finditer(r'(?<!`)``(\[[A-Z]+-'+LABEL+r'\]|'+LABEL+r')``(?!`)', paragraph)
                        if 'claim:' in m[1]}
            row = dict(name=name, path=str(path.relative_to(root)), text=paragraph, citations=citations, exhibits=exhibits)
            paragraphs[name] = row
            if head[1].split(':')[0] in OBLIGATION_KINDS: obligations[name] = row
    return paragraphs, obligations


def site_claim(site):
    lines = site['doc'].strip().splitlines()
    if site['language']=='python':
        # Carrier validity and derived identity are owned by the checked linter.
        # Retain only the binding needed for source/result and semantic-review joins.
        carrier=lines[-2].strip(); label=carrier.strip('()´')
        gloss='\n'.join(lines[:-2]).strip()
        explicit=[line.strip() for line in lines[:-2] if line.strip().startswith('Claim:')]
        if explicit: gloss=explicit[0]
        return {**site,'claim':qualify(label,site['owner']),'mint':not carrier.startswith('('),
                'test_label':lines[-1].strip(' ´'),'gloss':gloss,'area':label.split(':')[1]}
    claim_lines = [(i, re.fullmatch(r'(\()?´('+LABEL+r')´(\))?', line.strip())) for i,line in enumerate(lines)]
    claims = [(i,m) for i,m in claim_lines if m and m[2].startswith('claim:')]
    if len(claims) != 1: raise StructuralError('site requires one claim mint or citation: '+site['operation'])
    i, match = claims[0]
    if bool(match[1]) != bool(match[3]): raise StructuralError('malformed claim citation')
    if (i == 0 and not match[1]) or i != len(lines)-2 or not re.fullmatch(r'´test:[a-z0-9-]+:[a-z0-9.-]+´', lines[-1].strip()):
        raise StructuralError('claim/test carrier order: '+site['operation'])
    gloss = '\n'.join(lines[:i]).strip()
    explicit = [line.strip() for line in lines[:i] if line.strip().startswith('Claim:')]
    if len(explicit) > 1: raise StructuralError('multiple explicit claim glosses: '+site['operation'])
    if explicit: gloss = explicit[0]
    test_label = lines[-1].strip(' ´')
    if test_label.split(':',2)[2] != site['function'].replace('_','-'):
        raise StructuralError('test label differs from function identity: '+site['operation'])
    return {**site, 'claim': qualify(match[2], site['owner']), 'mint': not bool(match[1]),
            'test_label': test_label, 'gloss': gloss, 'area': match[2].split(':')[1]}


def respells(site):
    gloss = re.sub(r'^Claim:\s*', '', site['gloss'], flags=re.I)
    words = lambda value: re.findall(r'[a-z0-9]+', value.lower())
    function = site['function'].removeprefix('test_')
    return words(gloss) in (words(function), ['the']+words(function))


def reconcile_mints(sites, minted):
    expected=Counter(s['claim'] for s in sites if s['mint'] and s['language']=='rust')
    if expected != minted: raise StructuralError('orphan or missing source claim mint')


def evaluate(sites, expected_sites, areas, obligations, declared, paragraphs, results, source, configuration=CONFIGURATION):
    if len({s['operation'] for s in sites}) != len(sites) or {s['operation'] for s in sites} != set(expected_sites):
        raise StructuralError('undeclared or omitted source site')
    if len({a['owner']+'::'+a['area'] for a in areas}) != len(areas): raise StructuralError('duplicate area register')
    actual_areas = {(s['owner'], s['area']) for s in sites}
    if actual_areas != {(a['owner'], a['area']) for a in areas}: raise StructuralError('missing or stale claim area')
    for area in areas:
        if any(not isinstance(area.get(k),str) or not area[k].strip() for k in ('stake','register','contract')): raise StructuralError('area lacks stake or local contract')
        entry = paragraphs.get(area['register'])
        if not entry or area['stake'] not in entry['text']: raise StructuralError('area stake is not rendered in owner prose')
        if area['contract'] not in paragraphs: raise StructuralError('unresolved local claim contract')
        if not area['register'].startswith(area['owner']+'::'): raise StructuralError('area register owner differs')
    claims = defaultdict(list)
    mints = Counter(s['claim'] for s in sites if s['mint'])
    for site in sites: claims[site['claim']].append(site)
    if set(mints) != set(claims) or any(v != 1 for v in mints.values()): raise StructuralError('unresolved or duplicate claim mint')
    if any('::claim:' in name for name in paragraphs): raise StructuralError('orphan prose claim mint outside a test site')
    for paragraph in paragraphs.values():
        if any('::claim:' in name and name not in claims for name in paragraph['citations']):
            raise StructuralError('unresolved prose claim citation')
    # Only designated evidence paragraphs assert support. Planned design names
    # remain exhibits, never mints or evidence merely because they are displayed.
    for name in {r.get('evidence_paragraph') for r in declared if r.get('evidence_paragraph')}:
        exhibits = paragraphs.get(name, {}).get('exhibits', set())
        if exhibits:
            raise StructuralError('evidence exhibits cannot claim support; use checked citations')
    if len({r['operation'] for r in results}) != len(results): raise StructuralError('duplicate result')
    actual = {r['operation']:r for r in results}
    missing = set(expected_sites)-set(actual)
    if missing: raise StructuralError('missing test results: '+str(sorted(missing)))
    for site in sites:
        result = actual[site['operation']]
        if result.get('source') != source or result.get('configuration') != configuration: raise StructuralError('stale result')
        if result.get('outcome') not in {'passed','failed'}: raise StructuralError('unexecuted or ignored result')
    states = {claim: ('failed' if any(actual[s['operation']]['outcome']=='failed' for s in members) else 'passed') for claim,members in claims.items()}
    if len(declared) != len({r['name'] for r in declared}) or {r['name'] for r in declared} != set(obligations):
        raise StructuralError('removed or extra source obligation')
    obligation_results = []
    for row in declared:
        name = row['name']
        if row.get('path') != obligations[name]['path']: raise StructuralError('obligation source differs')
        if row.get('status') not in {'held','scoped-supported'}: raise StructuralError('invalid obligation status')
        if row['status']=='held' and any(not isinstance(row.get(k),str) or not row[k].strip() for k in ('hold','owner','missing','closing_condition','closing_step')):
            raise StructuralError('hold lacks owner or closing condition')
        if row['status']=='held' and row['hold'] not in paragraphs: raise StructuralError('unlabelled hold')
        for field in ('claims','realizers'):
            if not isinstance(row.get(field),list) or any(not isinstance(n,str) for n in row[field]) or len(set(row[field]))!=len(row[field]):
                raise StructuralError('malformed or duplicate evidence edges')
        if row['claims'] and (not isinstance(row.get('premises'),str) or not row['premises'].strip()):
            raise StructuralError('evidence edge lacks scoped premises')
        for claim in row['claims']:
            if claim not in claims: raise StructuralError('planned name or unresolved claim presented as evidence')
            paragraph = paragraphs.get(row.get('evidence_paragraph'), {})
            citations = paragraph.get('citations', set())
            evidence = citations
            if claim not in evidence or name not in citations: raise StructuralError('uncited evidence presented as coverage')
        if row['status']=='scoped-supported' and not row['claims']: raise StructuralError('supported obligation lacks claims')
        if name.split('::',1)[1].startswith('req:'):
            edges = {key for key,value in obligations.items() if key != name and name in value['citations']}
            if set(row['realizers']) != edges: raise StructuralError('missing requirement edges')
            if not edges and row['status'] != 'held': raise StructuralError('requirement lacks realizing decision or plan')
        for target in row['realizers']:
            if target not in obligations: raise StructuralError('unresolved obligation edge')
        state = 'failed' if any(states[c]=='failed' for c in row['claims']) else ('held' if row['status']=='held' else 'scoped-passed')
        obligation_results.append({**row,'status':state})
    for name in {r.get('evidence_paragraph') for r in declared if r.get('evidence_paragraph')}:
        paragraph = paragraphs[name]
        displayed = paragraph.get('exhibits',set()) | {n for n in paragraph.get('citations',set()) if '::claim:' in n}
        edges = {n for row in declared if row.get('evidence_paragraph')==name for n in row['claims']}
        if displayed != edges: raise StructuralError('evidence paragraph and row edges differ')
    # Dependent requirements inherit failed or held realizers to a fixed point.
    indexed = {r['name']:r for r in obligation_results}
    for _ in obligation_results:
        changed = False
        for row in obligation_results:
            dependencies = [indexed[n]['status'] for n in row['realizers']]
            state = 'failed' if 'failed' in dependencies or row['status']=='failed' else ('held' if 'held' in dependencies or row['status']=='held' else 'scoped-passed')
            if state != row['status']: row['status']=state; changed=True
        if not changed: break
    return dict(claims=[dict(name=n,status=s,sites=[x['operation'] for x in claims[n]]) for n,s in sorted(states.items())], obligations=obligation_results)


def bite_one_started(root):
    """Both the conventional directory and a renamed workspace member trigger entry."""
    import glob
    if (root/'packages/records').exists(): return True
    workspace=tomllib.loads((root/'Cargo.toml').read_text()).get('workspace',{})
    excluded={Path(p) for pattern in workspace.get('exclude',[]) for p in glob.glob(str(root/pattern))}
    for pattern in workspace.get('members',[]):
        for member in glob.glob(str(root/pattern)):
            if Path(member) in excluded: continue
            manifest=Path(member)/'Cargo.toml'
            if manifest.is_file() and tomllib.loads(manifest.read_text()).get('package',{}).get('name')=='pn-records': return True
    return False


def enforce_entry(obligations, started, required=None):
    """A named entry hold remains a prerequisite, not a future-work caption."""
    entries=[row for row in obligations if row.get('entry_gate')=='ROOT::gate:design:bite-1']
    if required is not None and {row['name'] for row in entries}!=required:
        raise StructuralError('bite-1 entry register differs from the source amendment')
    pending=[]
    for row in entries:
        admission=row.get('admission',{})
        if (not row.get('owner') or admission.get('owner')!=row['owner'] or not isinstance(admission.get('evidence_kind'),str) or not admission['evidence_kind'].strip()
                or admission.get('status') not in ('held','submitted','admitted')):
            raise StructuralError('bite-1 entry admission requires owner and evidence kind')
        admitted=admission['status']=='admitted'
        if admission['status'] in ('submitted','admitted') and (not isinstance(admission.get('evidence'),str) or not admission['evidence'].strip()):
            raise StructuralError('bite-1 entry admission requires evidence')
        if row['status']!='scoped-passed' or not admitted: pending.append(row['name'])
    if started and pending:
        raise StructuralError('bite-1 entry evidence remains held: '+str(sorted(pending)))


def checked_linter(path,sites):
    summaries=[]
    for line in Path(path).read_text().splitlines():
        try: row=json.loads(line)
        except ValueError: continue
        if isinstance(row,dict) and 'clean' in row and 'profile' in row: summaries.append(row)
    if len(summaries)!=1 or not summaries[0]['clean']: raise StructuralError('checked linter census is missing or failed')
    covered=sites
    if summaries[0]['profile']['covered']!=len(covered) or summaries[0]['claim']['mints']!=sum(s['mint'] for s in covered):
        raise StructuralError('independent source census differs from checked Rust and Python profiles')


def reviewed_sites(sites, manifest, baseline=None):
    """Check review identities against source; semantic review remains item-specific."""
    if manifest.get('schema') != 1: raise StructuralError('claim review schema differs')
    actual = {s['operation']:s for s in sites}
    seen = set()
    for row in manifest['sites']:
        name = row['operation']
        if name in seen or name not in actual: raise StructuralError('duplicate or missing reviewed site')
        seen.add(name)
        site = actual[name]
        if any(row[k] != site[k] for k in ('path','claim')) or row['after'] != site['gloss']:
            raise StructuralError('stale claim gloss review: '+name)
        if not isinstance(row['before'],str) or not isinstance(row['review'],str) or not row['review'].strip():
            raise StructuralError('claim review lacks before gloss or assessment')
    if baseline is not None:
        if baseline.get('schema')!=1 or set(baseline.get('glosses',{}))!=set(actual):
            raise StructuralError('gloss baseline omits or retains a source site')
        required={n for n,s in actual.items() if baseline['glosses'][n]!=s['gloss']}
        if required-seen: raise StructuralError('rewritten site lacks review: '+str(sorted(required-seen)))
        for row in manifest['sites']:
            if row['before']!=baseline['glosses'][row['operation']]:
                raise StructuralError('review before gloss differs from baseline')
    return manifest['sites']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fail-respellings', action='store_true')
    args = parser.parse_args(argv)
    try:
        root = Path('.')
        registry = load_registry()
        sites = [site_claim(s) for s in census(root)]
        reconcile_mints(sites, claim_mints(root))
        checked_linter('.lane/gate-linter.log',sites)
        expected = {n for n,c in registry.cases.items() if c['runner']=='ci' or (c['runner']=='nextest' and c['implementation']!='regexml-rust')}
        paragraphs, obligations = prose(root)
        areas = tomllib.loads(Path('docs/inputs/claim-areas.toml').read_text())['rows']
        declared = tomllib.loads(Path('docs/inputs/claim-obligations.toml').read_text())['rows']
        paths = [Path('.lane/performance-events.jsonl'), Path('.lane/harness-benchmarks.jsonl'), *sorted(Path('.lane').glob('harness-ci-*.jsonl'))]
        records = [json.loads(line) for path in paths for line in path.read_text().splitlines()]
        source = source_id()
        registry.matrix(records, source)
        for site in sites:
            case = registry.cases.get(site['operation'])
            if case and site['path'].endswith('/tests/public.rs') and (case['level']!='public-surface' or not site['test_label'].startswith('test:integration:')):
                raise StructuralError('public carrier mapping differs')
        result = evaluate(sites, expected, areas, obligations, declared, paragraphs,
                          [r for r in records if r.get('scope')=='case'], source)
        entry = paragraphs['ROOT::amend:decomposition:bite-one-entry-evidence']['citations'] & set(obligations)
        enforce_entry(result['obligations'], bite_one_started(root), entry-{'ROOT::gate:design:bite-1'})
        reviews = reviewed_sites(sites, json.loads(Path('ci/claim_review.json').read_text()), json.loads(Path('ci/claim_gloss_baseline.json').read_text()))
        Path('.lane/claim-gloss-review.json').write_text(json.dumps({'schema':1,'source':source,'sites':reviews},indent=2)+'\n')
        offenders = [{k:s[k] for k in ('owner','path','line','function','operation','claim','gloss')} for s in sites if respells(s)]
        Path('.lane/claim-respellings.json').write_text(json.dumps({'schema':1,'source':source,'offenders':offenders},indent=2)+'\n')
        local_contracts={(a['owner'],a['area']):a['contract'] for a in areas}
        for site in sites:
            site['local_contract']=local_contracts[site['owner'],site['area']]
            site['execution']=next(r for r in records if r.get('scope')=='case' and r['operation']==site['operation'])
        missing_glosses=[s['operation'] for s in sites if not s['gloss']]
        observation=json.loads(Path('.lane/observation-coverage.json').read_text())
        if observation.get('source')!=source or observation.get('mechanical_status')!='passed':
            raise StructuralError('observation coverage is missing, stale or failed')
        Path('.lane/claim-evidence.json').write_text(json.dumps({'schema':1,'source':source,'configuration':CONFIGURATION,'sites':sites,'sibling_gloss_review':missing_glosses,'observation_declarations':observation,**result},indent=2)+'\n')
        counts = Counter(r['status'] for r in result['obligations'])
        print(f'CLAIM-REVIEW sites={len(reviews)} artifact=.lane/claim-gloss-review.json')
        print(f'CLAIM-RESPELLINGS count={len(offenders)} artifact=.lane/claim-respellings.json enforcement={args.fail_respellings}')
        print(f'CLAIM-EVIDENCE sites={len(sites)} claims={len(result["claims"])} obligations={len(obligations)} scoped_passed={counts["scoped-passed"]} failed={counts["failed"]} held={counts["held"]} artifact=.lane/claim-evidence.json')
        return int(any(r['status']=='failed' for r in result['claims']) or counts['failed']>0 or (args.fail_respellings and bool(offenders)))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print('CLAIM-STRUCTURAL-ERROR '+str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
