"""Bidirectional source/claim/obligation/result accounting beside the linter."""

import argparse
import ast
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import re
import sys
import time
import tomllib

from devperf import StructuralError
from harness import CONFIGURATION, load as load_registry, source_id
from source_sites import census, claim_mints, OWNERS

LABEL = r'[a-z][a-z0-9-]*:[a-z0-9-]+:[a-z0-9.-]+'
OBLIGATION_KINDS = {'req', 'dec', 'verif', 'plan', 'gate'}
REGISTERS = {'ci/claim_review.json': 'sites', 'ci/claim_gloss_baseline.json': 'glosses'}
REVIEW_FIELDS = ('operation', 'path', 'claim', 'before', 'after', 'review')


def unique_members(pairs):
    """Do not lose a repeated JSON member before checking register identities."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise StructuralError('duplicate register member: '+key)
        result[key] = value
    return result


def register_form(text, field):
    """Validate without discarding content, then build the one permitted form."""
    data = json.loads(text, object_pairs_hook=unique_members)
    if not isinstance(data, dict) or set(data) != {'schema', field} or type(data['schema']) is not int or data['schema'] != 1:
        raise StructuralError('register root requires schema 1 and '+field)
    if field == 'sites':
        if not isinstance(data[field], list):
            raise StructuralError('register sites must be a list')
        rows = []
        seen = set()
        for index, row in enumerate(data[field]):
            if not isinstance(row, dict) or set(row) != set(REVIEW_FIELDS) or any(not isinstance(row[key], str) for key in REVIEW_FIELDS):
                raise StructuralError('malformed register entry: '+str(index))
            name = row['operation']
            if name in seen:
                raise StructuralError('duplicate register operation: '+name)
            seen.add(name)
            rows.append({key: row[key] for key in REVIEW_FIELDS})
        ordered = sorted(rows, key=lambda row: (row['operation'], row['path'], row['claim']))
    else:
        if not isinstance(data[field], dict) or any(not isinstance(value, str) for value in data[field].values()):
            raise StructuralError('register glosses must map keys to strings')
        ordered = dict(sorted(data[field].items()))
    canonical = {'schema': 1, field: ordered}
    return data, canonical, json.dumps(canonical, ensure_ascii=False, indent=2, allow_nan=False)+'\n'


def check_register(text, field):
    """Refuse the first order/form difference; checking never writes a file."""
    data, canonical, formatted = register_form(text, field)
    actual = [row['operation'] for row in data[field]] if field == 'sites' else list(data[field])
    expected = [row['operation'] for row in canonical[field]] if field == 'sites' else list(canonical[field])
    for index, (left, right) in enumerate(zip(actual, expected)):
        if left != right:
            raise StructuralError(f'non-canonical register order: entry {left} at index {index}; expected {right}')
    if text != formatted:
        offset = next((i for i, (left, right) in enumerate(zip(text, formatted)) if left != right), min(len(text), len(formatted)))
        # The common prefix puts the first byte difference at the same location
        # in both strings. Locate that position in the canonical entry layout.
        entry = '<root>'
        if field == 'sites':
            matches = re.finditer(r'^    \{\n      "operation": ("(?:\\.|[^"\\])*")', formatted, re.M)
        else:
            matches = re.finditer(r'^    ("(?:\\.|[^"\\])*"): ', formatted, re.M)
        for match in matches:
            if match.start() > offset:
                break
            entry = json.loads(match[1])
        raise StructuralError(f'non-canonical register serialization: entry {entry}, byte {offset}; run ci/claims.py canonicalize')
    return data


def read_register(path, field):
    try:
        return check_register(Path(path).read_bytes().decode('utf-8'), field)
    except ValueError as error:
        raise StructuralError(str(path)+': '+str(error)) from error


def canonicalize_registers(paths):
    """Explicit edit route; validate every selected file before writing any."""
    prepared = []
    for path in paths:
        text = Path(path).read_bytes().decode('utf-8')
        _, _, formatted = register_form(text, REGISTERS[path])
        prepared.append((Path(path), formatted.encode('utf-8')))
    for path, content in prepared:
        changed = path.read_bytes() != content
        if changed:
            path.write_bytes(content)
        print(f'CLAIM-REGISTER path={path} changed={str(changed).lower()}')



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
        from build_graph_evidence import held_service, retained_service
        if result.get('retained') and not retained_service(result, Path.cwd()): raise StructuralError('invalid retained service evidence')
        if result.get('outcome') not in {'passed','failed'} and not held_service(result, Path.cwd()): raise StructuralError('unexecuted or ignored result')
    states = {claim: ('failed' if any(actual[s['operation']]['outcome']=='failed' for s in members) else ('held' if any(actual[s['operation']]['outcome']=='held' for s in members) else 'passed')) for claim,members in claims.items()}
    # Membership is declared by an owning obligation; it is never a mint.
    combined = {}
    for row in declared:
        if 'combined_claim' not in row:
            continue
        claim, members = row['combined_claim'], row.get('claims')
        if not isinstance(claim, str) or claim not in claims:
            raise StructuralError('unresolved combined claim')
        if claim in combined:
            raise StructuralError('duplicate combined claim declaration')
        if (not isinstance(members, list) or any(not isinstance(n, str) for n in members)
                or len(members) != len(set(members)) or claim not in members or len(members) < 2):
            raise StructuralError('malformed combined claim members')
        if any(member not in claims for member in members):
            raise StructuralError('unresolved combined claim member')
        combined[claim] = [member for member in members if member != claim]
    visited, visiting = set(), set()

    def join_members(claim):
        if claim in visiting:
            raise StructuralError('cyclic combined claim members')
        if claim not in visited:
            visiting.add(claim)
            outcomes = [states[claim], *(join_members(member) for member in combined.get(claim, []))]
            states[claim] = 'failed' if 'failed' in outcomes else ('held' if 'held' in outcomes else 'passed')
            visiting.remove(claim)
            visited.add(claim)
        return states[claim]

    for claim in combined:
        join_members(claim)
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
        state = 'failed' if any(states[c]=='failed' for c in row['claims']) else ('held' if row['status']=='held' or any(states[c]=='held' for c in row['claims']) else 'scoped-passed')
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
    evidence = dict(claims=[dict(name=n,status=s,sites=[x['operation'] for x in claims[n]],members=combined.get(n, [])) for n,s in sorted(states.items())], obligations=obligation_results)
    retained = [dict(operation=row['operation'], execution_source=row['execution_source'])
                for row in results if row.get('retained')]
    if retained: evidence['retained_execution'] = retained
    return evidence


def tracker_sentences(text):
    """Split prose punctuation outside Markdown code spans, never label dots."""
    masked = re.sub(r'(`+)(.*?)\1', lambda match: 'x'*len(match[0]), text)
    for match in tracker_portions(text):
        masked = masked[:match.start()] + 'x'*len(match[0]) + masked[match.end():]
    start = 0
    for boundary in re.finditer(r'[.!?]+(?=\s|$)|\n', masked):
        yield text[start:boundary.end()]
        start = boundary.end()
    if start < len(text):
        yield text[start:]


def tracker_portions(text):
    """Read explicitly bounded attention, retaining its covered clause."""
    pattern = r'portion\{``([^`\n{}]+)``; ([^{}\n]+)\}'
    matches = list(re.finditer(pattern, text))
    if 'portion{' in re.sub(pattern, '', text):
        raise StructuralError('malformed paper portion citation')
    if any(not match[2].strip() for match in matches):
        raise StructuralError('empty paper portion clause')
    return matches


def tracker_paper(text):
    """Admit exact paper citations and exhibits, not nearby free text."""
    for match in reversed(tracker_portions(text)):
        text = text[:match.start()] + ' '*len(match[0]) + text[match.end():]
    return (set(re.findall(r'\(`\[PAPER-([^\]`\n]+)\]`\)', text)) |
            set(re.findall(r'(?<!`)``([^`\n]+)``(?!`)', text)))


def tracker_claims(text, owner, claim_names):
    """Resolve ordinary qualified citations and unique bare claim exhibits."""
    cited = {qualify(m[1], owner) for m in re.finditer(
        r'\(`(\[[A-Z]+-'+LABEL+r'\]|'+LABEL+r')`\)', text)}
    cited.update(qualify(m[1], owner) for m in re.finditer(r'(?<!`)``(\[[A-Z]+-'+LABEL+r'\])``(?!`)', text))
    for label in re.findall(r'(?<!`)``(claim:[a-z0-9-]+:[a-z0-9.-]+)``(?!`)', text):
        matches = claim_names.get(label, set())
        if len(matches) > 1:
            raise StructuralError('ambiguous tracker claim exhibit: '+label)
        cited.update(matches)
    return cited


def tracker_selection_sites(root):
    """Read the selectable case's claim from source before any execution."""
    from build_graph_evidence import SERVICE_CASE
    module, class_name, function_name = SERVICE_CASE.removeprefix('ci::').split('.')
    path = Path('ci')/(module+'.py')
    tree = ast.parse((Path(root)/path).read_text())
    functions = [function for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and node.name == class_name
                 for function in node.body if isinstance(function, ast.FunctionDef) and function.name == function_name]
    if len(functions) != 1:
        raise StructuralError('tracker selectable service case does not resolve: '+SERVICE_CASE)
    return [site_claim(dict(operation=SERVICE_CASE, owner='ROOT', language='python',
                            doc=ast.get_docstring(functions[0]) or ''))]


def tracker_rows(inventory, paragraphs, evidence, bites, constants=(), plan=()):
    """Join exact paper mentions, scoped execution and bounded record edges."""
    labels = {row['label'] for row in inventory}
    if len(labels) != len(inventory):
        raise StructuralError('tracker inventory has duplicate labels')
    records = {name: row for name, row in paragraphs.items()
               if row.get('path') != 'docs/design/progress.md'}
    mentions = defaultdict(set)
    portions = defaultdict(list)
    for name, record in records.items():
        # Exhibits are how the repository names paper kinds the local linter
        # cannot import. Only exact inventory labels qualify, never free text.
        paper = {n.removeprefix('PAPER::') for n in record['citations'] if n.startswith('PAPER::')}
        paper.update(tracker_paper(record['text']))
        for match in tracker_portions(record['text']):
            if match[1] not in labels:
                raise StructuralError('unknown paper portion label: '+match[1])
            portions[match[1]].append(dict(record=name, clause=match[2].strip()))
        for label in paper & labels:
            mentions[label].add(name)
    for constant in constants:
        if constant['cites'] in labels:
            mentions[constant['cites']].add('CONSTANTS::'+constant['id'])
    claims = {row['name']: row for row in evidence['claims']}
    obligations = {row['name']: row for row in evidence['obligations']}
    from build_graph_evidence import SERVICE_CASE
    selected_claims = {site['claim'] for site in evidence.get('sites', []) if site.get('operation') == SERVICE_CASE}
    unstable = {name for name, row in obligations.items() if selected_claims.intersection(row['claims'])}
    for _ in obligations:
        unstable.update(name for name, row in obligations.items() if unstable.intersection(row.get('realizers', [])))
    claim_names = defaultdict(set)
    for claim in claims.keys() | {claim for row in obligations.values() for claim in row['claims']}:
        claim_names[claim.split('::', 1)[1]].add(claim)
    supported = defaultdict(set)
    precise = defaultdict(set)
    granular = defaultdict(set)
    attention = {name for name, record in records.items() if name.split('::', 1)[-1].split(':', 1)[0] in {'open', 'obs'}
                 or 'ROOT::conv:progress:outstanding-work' in record['citations']}
    holds = defaultdict(set)
    named_holds = {row['hold'] for row in obligations.values() if row['status'] == 'held' and row.get('hold')}
    scopes = defaultdict(set)
    by_record = defaultdict(set)
    for label, names in mentions.items():
        for name in names:
            by_record[name].add(label)
    for name, row in obligations.items():
        if row['status'] == 'scoped-passed':
            for claim in row['claims']:
                if claims.get(claim, {}).get('status') == 'passed':
                    scopes[claim].add(name)
            if name in records and row['claims'] and all(claims.get(c, {}).get('status') == 'passed' for c in row['claims']):
                supported[name].add(('obligation', '', name))
        elif row['status'] == 'held' and row.get('hold') and name in records:
            holds[name].add(row['hold'])
    cited_by_sites = defaultdict(set)
    for site in evidence.get('sites', []):
        claim = site['claim']
        citations = {qualify(m[1], site['owner']) for m in re.finditer(
            r'\(´(\[[A-Z]+-'+LABEL+r'\]|'+LABEL+r')´\)', site['doc'])}
        for name in citations & records.keys():
            cited_by_sites[name].add(claim)
            for scope in scopes[claim]:
                supported[name].add(('site-claim', claim, scope))
    for name, record in records.items():
        cited_claims = record['citations'] | record.get('exhibits', set()) | tracker_claims(record['text'], name.split('::', 1)[0], claim_names)
        if by_record[name] and (name in unstable or any(
                (cited_claims | cited_by_sites[name]).intersection(obligations[scope]['claims']) for scope in unstable)):
            raise StructuralError('tracker route depends on selectable service evidence: '+name)
        linked = defaultdict(set)
        for sentence in tracker_sentences(record['text']):
            for label in tracker_paper(sentence) & labels:
                linked[label].update(tracker_claims(sentence, name.split('::', 1)[0], claim_names))
        for claim in cited_claims:
            for scope in scopes[claim]:
                for label in by_record[name]:
                    if claim in linked[label]:
                        precise[label, name].add(('record-claim', claim, scope))
                    else:
                        granular[label, name].add(scope)
        holds[name].update(record['citations'] & named_holds)
        if name in named_holds:
            holds[name].add(name)
    bite_records = {}
    for bite in bites:
        roots = {'ROOT::'+name for name in bite['contracts']}
        roots.update('ROOT::req:vision:'+name for name in bite['requirements'])
        # Requirement realizers are checked directed edges, not prose reachability.
        pending = list(roots)
        while pending:
            for name in obligations.get(pending.pop(), {}).get('realizers', []):
                if name not in roots:
                    roots.add(name)
                    pending.append(name)
        bite_records[bite['ordinal']] = roots
    rows = []
    for item in inventory:
        names = sorted(mentions[item['label']])
        designs = [name for name in names if name not in attention]
        routes = [dict(kind=kind, record=name, scope=scope, **({'claim': claim} if claim else {}))
                  for name in designs for kind, claim, scope in sorted(supported[name] | precise[item['label'], name])]
        record_routes = [dict(kind='record', record=name, scope=scope)
                         for name in names for scope in sorted(granular[item['label'], name])]
        held = [dict(record=name, hold=hold) for name in names for hold in sorted(holds[name])]
        status = ('realized' if routes else 'held' if names and all(holds[name] for name in (designs or names))
                  else 'designed' if names else 'unassigned')
        rows.append(dict(label=item['label'], crate=item['crate'], kind=item['kind'], status=status,
                         records=names, routes=routes, record_routes=record_routes, holds=held,
                         portions=sorted(portions[item['label']], key=lambda part: (part['record'], part['clause'])),
                         tentative=int(status == 'designed' and not designs),
                         record_granular=int(status != 'realized' and bool(record_routes)),
                         bites=sorted({n for n, roots in bite_records.items() if roots.intersection(names)} |
                                      {b['ordinal'] for b in plan if item['label'] in b['labels']})))
    return rows



def tracker_elsewhere(root, rows):
    """Count exact labels outside the admitted mention carriers, never substrings."""
    from build_graph import tracked
    labels = {row['label'] for row in rows if row['status'] == 'unassigned'}
    found = defaultdict(set)
    if not labels:
        return {}
    excluded = {'docs/inputs/design-inventory.toml', 'docs/inputs/specification-progress.toml',
                'docs/datasets/org.peer-network.design.inventory.json',
                'docs/datasets/org.peer-network.design.progress.json', 'docs/design/progress.md',
                'docs/design/inventory.md'}
    token = re.compile(r'(?<![a-z0-9:.-])([a-z][a-z0-9-]*(?::[a-z0-9.-]+)+)(?![a-z0-9:.-])')
    for name in tracked(root):
        if name in excluded:
            continue
        try:
            text = (root/name).read_text()
        except UnicodeError:
            continue
        text = re.sub(r'\[PAPER-([^\]\n]+)\]', r'\1', text).replace('PAPER::', '')
        for label in set(token.findall(text)) & labels:
            found[label].add(name)
    return {label: sorted(paths) for label, paths in sorted(found.items())}


def tracker_changes(before, after, fields=None):
    """Describe changed statement fields, not an opaque byte mismatch."""
    indexed = lambda rows: {r['label']: r for r in rows if r['category'] == 'statement'}
    left, right = indexed(before), indexed(after)
    changes = []
    for label in sorted(left.keys() | right.keys()):
        old, new = left.get(label, {}), right.get(label, {})
        keys = fields if fields is not None else sorted(old.keys() | new.keys())
        changed = {key: dict(before=old.get(key), after=new.get(key)) for key in keys if old.get(key) != new.get(key)}
        if changed:
            changes.append(dict(label=label, fields=changed))
    return changes


def tracker_structure(root):
    """Refuse changed records and bite membership before requiring executions."""
    root = Path(root)
    read = lambda name: tomllib.loads((root/'docs/inputs'/name).read_text())['rows']
    rows = tracker_rows(read('design-inventory.toml'), prose(root)[0],
                        dict(claims=[], obligations=read('claim-obligations.toml'), sites=tracker_selection_sites(root)),
                        read('implementation-bites.toml'), read('design-constants.toml'), read('design-bites.toml'))
    changes = tracker_changes(read('specification-progress.toml'),
                              [dict(category='statement', **row) for row in rows],
                              ('crate', 'kind', 'records', 'bites', 'portions'))
    artifact = root/'.lane/specification-tracker-structure.json'
    artifact.parent.mkdir(exist_ok=True)
    artifact.write_text(json.dumps(dict(evidence='structural-only', changes=changes), indent=2)+'\n')
    for change in changes:
        print('SPECIFICATION-TRACKER-MOVED '+json.dumps(change, sort_keys=True), flush=True)
    if changes:
        raise StructuralError('specification tracker records or bites are stale; see .lane/specification-tracker-structure.json')
    print('SPECIFICATION-TRACKER structure=passed fields=crate,kind,records,bites,portions', flush=True)


def tracker_artifacts(root, projection):
    """Render checked replacement bytes in the shared commit-isolation boundary."""
    from build_graph import cancellable
    from isolation import workspace
    root = Path(root).resolve()
    source = source_id()
    binary = Path(os.environ.get('PN_GATE_BUILD_TARGET', os.environ.get('CARGO_TARGET_DIR', root/'target'))).resolve()/'gate/documents'
    paths = ('docs/inputs/specification-progress.toml',
             'docs/datasets/org.peer-network.design.progress.json', 'docs/design/progress.md')
    destination = root/'.lane/specification-tracker'
    (destination/'manifest.json').unlink(missing_ok=True)
    with workspace(root, 'specification-tracker', source) as (tree, _target):
        (tree/paths[0]).write_text(projection)
        for action in ('generate', 'write'):
            result = cancellable([str(binary), '--root', str(tree), action], cwd=tree)
            if result.returncode not in (0, 3):
                raise StructuralError('tracker artifact '+action+' failed')
        for name in paths:
            output = destination/name
            output.parent.mkdir(parents=True, exist_ok=True)
            temporary = output.with_name(output.name+'.tmp')
            temporary.write_bytes((tree/name).read_bytes())
            temporary.replace(output)
    manifest = destination/'manifest.json'
    temporary = manifest.with_name('manifest.json.tmp')
    temporary.write_text(json.dumps(dict(source=source, evidence='checked-execution', paths=list(paths)), indent=2)+'\n')
    temporary.replace(manifest)
    print('SPECIFICATION-TRACKER artifacts=.lane/specification-tracker/manifest.json', flush=True)


def check_tracker(root, projection):
    """Refuse stale committed bytes and emit the complete replacement triple."""
    root = Path(root)
    (root/'.lane/specification-progress.toml').write_text(projection)
    carrier = root/'docs/inputs/specification-progress.toml'
    if carrier.read_text() != projection:
        before = tomllib.loads(carrier.read_text())['rows']
        changes = tracker_changes(before, tomllib.loads(projection)['rows'])
        (root/'.lane/specification-tracker-moved.json').write_text(json.dumps(changes, indent=2)+'\n')
        for change in changes:
            print('SPECIFICATION-TRACKER-MOVED '+json.dumps(change, sort_keys=True), flush=True)
        tracker_artifacts(root, projection)
        raise StructuralError('specification tracker is stale; apply .lane/specification-tracker artifacts from checked execution evidence')
    gap = next(row['total'] for row in tomllib.loads(projection)['rows'] if row['category'] == 'citation-gaps')
    print(f'SPECIFICATION-TRACKER fixed-point=passed unassigned_exact_elsewhere={gap} artifact=.lane/specification-progress.toml')


def tracker_input(root, evidence):
    """Project execution-backed rows and disjoint totals into a TOML carrier."""
    root = Path(root)
    read = lambda name: tomllib.loads((root/'docs/inputs'/name).read_text())['rows']
    paragraphs = prose(root)[0]
    rows = tracker_rows(read('design-inventory.toml'), paragraphs, evidence,
                        read('implementation-bites.toml'), read('design-constants.toml'), read('design-bites.toml'))
    elsewhere = tracker_elsewhere(root, rows)
    for row in rows:
        row['elsewhere'] = elsewhere.get(row['label'], [])
    obligation_routes = {route['scope'] for row in rows for route in row['routes'] if route['kind'] == 'obligation'}
    summaries = [dict(category='obligation-support', name=r['name'], claim_count=len(r['claims']),
                      numeric_display={'claim_count': dict(display='exact', exact_digits=32)})
                 for r in evidence['obligations'] if r['name'] in obligation_routes]
    claim_names = defaultdict(set)
    for claim in evidence['claims']:
        claim_names[claim['name'].split('::', 1)[1]].add(claim['name'])
    obligations = {row['name']: row for row in evidence['obligations']}
    for record, scope in sorted({(route['record'], route['scope']) for row in rows for route in row['record_routes']}):
        paragraph = paragraphs[record]
        cited = paragraph['citations'] | paragraph.get('exhibits', set()) | tracker_claims(paragraph['text'], record.split('::', 1)[0], claim_names)
        summaries.append(dict(category='record-support', name=record, scope=scope,
                              claim_count=len(cited.intersection(obligations[scope]['claims'])),
                              numeric_display={'claim_count': dict(display='exact', exact_digits=32)}))
    summaries.append(dict(category='citation-gaps', name='exact-elsewhere', total=len(elsewhere),
                          numeric_display={'total': dict(display='exact', exact_digits=32)}))
    for category, groups in (
            ('total', {'implementation': [r for r in rows if r['crate'] != 'none'],
                       'prose': [r for r in rows if r['crate'] == 'none']}),
            ('crate', {name: [r for r in rows if r['crate'] == name] for name in sorted({r['crate'] for r in rows})}),
            ('kind', {name: [r for r in rows if r['kind'] == name] for name in sorted({r['kind'] for r in rows})}),
            ('bite', {str(b['ordinal']): [r for r in rows if b['ordinal'] in r['bites']]
                      for b in read('implementation-bites.toml')} | {'unlinked': [r for r in rows if not r['bites']]})):
        for name, members in groups.items():
            counts = Counter(r['status'] for r in members)
            summaries.append(dict(category=category, name=name, total=len(members),
                                  tentative=sum(r['tentative'] for r in members),
                                  record_granular=sum(r['record_granular'] for r in members),
                                  **{status: counts[status] for status in ('realized', 'held', 'designed', 'unassigned')},
                                  numeric_display={field: dict(display='exact', exact_digits=32)
                                                   for field in ('total', 'realized', 'held', 'designed', 'unassigned', 'tentative', 'record_granular')}))
    packages = {str(path.parent.relative_to(root)): tomllib.loads(path.read_text())['package']['name']
                for path in sorted((root/'packages').glob('*/Cargo.toml'))}
    records = {name: [] for name in sorted(set(packages.values()) |
               {r['crate'] for r in rows if r['crate'] != 'none'})}
    records['ROOT (repository-wide)'] = []
    records['CONSTANTS (named carrier)'] = ['CONSTANTS::'+r['id'] for r in read('design-constants.toml')]
    cited = {name for row in rows for name in row['records']}
    for name, paragraph in paragraphs.items():
        path = paragraph['path']
        if path == 'docs/design/progress.md': continue
        crate = packages.get(str(Path(path).parent), 'ROOT (repository-wide)')
        records[crate].append(name)
    for name, members in records.items():
        summaries.append(dict(category='record-coverage', name=name, total=len(members),
                              exact_citing=sum(member in cited for member in members),
                              numeric_display={field: dict(display='exact', exact_digits=32)
                                               for field in ('total', 'exact_citing')}))
    def value(item):
        if isinstance(item, str): return json.dumps(item, ensure_ascii=False)
        if isinstance(item, int): return str(item)
        if isinstance(item, list): return '['+', '.join(value(v) for v in item)+']'
        return '{ '+', '.join(k+' = '+value(v) for k, v in item.items())+' }'
    output = ['# Generated by ci/claims.py tracker from checked execution evidence; do not edit.',
              'namespace = "org.peer-network.design.progress"', 'version = [1, 0, 0]', '', 'rows = [']
    output.extend('  '+value(dict(category='statement', **row))+',' for row in rows)
    output.extend('  '+value(row)+',' for row in summaries)
    return '\n'.join([*output, ']', ''])


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


def entry_bases(paragraphs, required):
    """Read the independent authored classification, not the rendered register."""
    result={}
    for basis in ('review','executed'):
        label='ROOT::amend:decomposition:entry-'+basis+'-basis'
        if label not in paragraphs:
            raise StructuralError('missing authored entry basis paragraph: '+label)
        for name in paragraphs[label]['citations'] & required:
            if name in result: raise StructuralError('duplicate authored entry basis: '+name)
            result[name]=basis
    if set(result)!=required: raise StructuralError('authored entry bases omit an entry row')
    return result


def enforce_entry(obligations, started, required=None, paragraphs=None, bases=None):
    """A named entry hold remains a prerequisite, not a future-work caption."""
    entries=[row for row in obligations if row.get('entry_gate')=='ROOT::gate:design:bite-1']
    if required is not None and {row['name'] for row in entries}!=required:
        raise StructuralError('bite-1 entry register differs from the source amendment')
    pending=[]
    checked=[]
    for row in entries:
        basis=row.get('admission_basis')
        if basis not in ('review','executed'):
            raise StructuralError('bite-1 entry requires a declared admission basis')
        if bases is not None and bases.get(row['name'])!=basis:
            raise StructuralError('declared admission basis differs from authored entry basis: '+row['name'])
        admission=row.get('admission',{})
        if (not row.get('owner') or admission.get('owner')!=row['owner'] or not isinstance(admission.get('evidence_kind'),str) or not admission['evidence_kind'].strip()
                or admission.get('status') not in ('held','submitted','admitted')):
            raise StructuralError('bite-1 entry admission requires owner and evidence kind')
        admitted=admission['status']=='admitted'
        if admission['status'] in ('submitted','admitted') and (not isinstance(admission.get('evidence'),str) or not admission['evidence'].strip()):
            raise StructuralError('bite-1 entry admission requires evidence')
        if admitted:
            evidence=(paragraphs or {}).get(admission['evidence'])
            if (not evidence or not admission['evidence'].startswith('ROOT::amend:')
                    or row['name'] not in evidence.get('citations',set())):
                raise StructuralError('bite-1 entry admission evidence does not resolve to an amendment citing its row')
        clear=admitted and (basis=='review' or row['status']=='scoped-passed')
        if not clear: pending.append(row['name'])
        checked.append(dict(name=row['name'],basis=basis,status='clear' if clear else 'pending'))
    if started and pending:
        raise StructuralError('bite-1 entry evidence remains held: '+str(sorted(pending)))
    return checked


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
    commands = parser.add_subparsers(dest='command')
    canonicalize = commands.add_parser('canonicalize', help='explicitly reorder and format claim registers without changing entries')
    canonicalize.add_argument('registers', nargs='*', help='registered path(s); defaults to both registers')
    commands.add_parser('tracker', help='project the current checked execution evidence into the tracker carrier')
    args = parser.parse_args(argv)
    try:
        if args.command == 'tracker':
            evidence = json.loads(Path('.lane/claim-evidence.json').read_text())
            if evidence.get('source') != source_id() or evidence.get('configuration') != CONFIGURATION:
                raise StructuralError('tracker requires current-source checked execution evidence')
            if any(row['status'] == 'failed' for field in ('claims', 'obligations') for row in evidence[field]):
                raise StructuralError('tracker refuses failed execution evidence')
            Path('docs/inputs/specification-progress.toml').write_text(tracker_input('.', evidence))
            return 0
        if args.command == 'canonicalize':
            started = time.monotonic()
            try:
                paths = args.registers or list(REGISTERS)
                if any(path not in REGISTERS for path in paths) or len(paths) != len(set(paths)):
                    raise StructuralError('canonicalize requires distinct registered paths: '+', '.join(REGISTERS))
                canonicalize_registers(paths)
            finally:
                print(f'CLAIM-CANONICALIZE wall={time.monotonic() - started:.6f}s')
            return 0
        registers = {field: read_register(path, field) for path, field in REGISTERS.items()}
        print('CLAIM-REGISTERS canonical=2')
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
        from wallet_cases import repository_check
        repository_check(sites, [r for r in records if r.get('scope') == 'case'])
        entry = paragraphs['ROOT::amend:decomposition:bite-one-entry-evidence']['citations'] & set(obligations)
        required=entry-{'ROOT::gate:design:bite-1'}
        result['entries']=enforce_entry(result['obligations'], bite_one_started(root), required, paragraphs, entry_bases(paragraphs,required))
        for row in result['entries']:
            print(f'CLAIM-ENTRY name={row["name"]} basis={row["basis"]} status={row["status"]}')
        reviews = reviewed_sites(sites, registers['sites'], registers['glosses'])
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
        projection = tracker_input(root, dict(sites=sites, **result))
        check_tracker(root, projection)
        return int(any(r['status']=='failed' for r in result['claims']) or counts['failed']>0 or (args.fail_respellings and bool(offenders)))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print('CLAIM-STRUCTURAL-ERROR '+str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
