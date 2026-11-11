"""Check the declared deployment claim scope and its conditional dependency closure."""

import json
from pathlib import Path
import re
import sys
import tomllib
import time


NAMESPACE = 'org.peer-network.testing.deployment-claims'
FIELDS = {
    'statement': {'kind', 'name', 'paper_tag', 'classification', 'included', 'excluded', 'reason', 'witness_route', 'evidence_status'},
    'clause': {'kind', 'name', 'paper_tag', 'parent', 'classification', 'included', 'excluded', 'reason', 'witness_route', 'evidence_status'},
}
CLASSES = {'claimed', 'split', 'not-claimed', 'non-obligation'}
EDGE_NAMESPACE = 'org.peer-network.testing.deployment-edges'
COMMAND = 'python3 -B ci/deployment_claims.py generate'


class Refusal(ValueError):
    """An incomplete classification or an unconditional dependency refuses the check."""


def validate(rows, inventory, labels):
    """Validate the authored scope before projecting any dependency edges."""
    indexed = {}
    for row in rows:
        kind = row.get('kind')
        if kind not in {'statement', 'clause'} or set(row) != FIELDS[kind]:
            raise Refusal('deployment schema: unknown or missing field')
        if not all(isinstance(value, str) for value in row.values()):
            raise Refusal('deployment schema: fields must be strings')
        if any(any(character in value for character in ('\r', '\n', '|')) for value in row.values()):
            raise Refusal('deployment schema: single-line fields without table separators required')
        if row['name'] in indexed:
            raise Refusal('deployment duplicate: '+row['name'])
        indexed[row['name']] = row
    statements = {name for name, row in indexed.items() if row['kind'] == 'statement'}
    if statements != set(inventory):
        raise Refusal('deployment inventory differs: '+str(sorted(statements ^ set(inventory))))
    for row in indexed.values():
        if row['paper_tag'] != 'network-v0.31.1' or row['classification'] not in CLASSES:
            raise Refusal('deployment classification or paper edition: '+row['name'])
        if row['evidence_status'] != 'scope-only' or not row['reason']:
            raise Refusal('deployment scope is not execution evidence: '+row['name'])
        if row['classification'] in {'claimed', 'split'}:
            if not row['included'] or row['witness_route'] not in labels:
                raise Refusal('deployment missing witness route: '+row['name'])
        elif row['included'] or row['witness_route']:
            raise Refusal('deployment not-claimed row has a claimed part: '+row['name'])
        if bool(row['excluded']) != (row['classification'] in {'split', 'not-claimed'}):
            raise Refusal('deployment excluded part differs from class: '+row['name'])
        if row['kind'] == 'clause' and row['parent'] not in statements:
            raise Refusal('deployment unresolved clause parent: '+row['name'])


def closure(rows, edges):
    """Propagate only marked reliance; ordinary links cannot seed a condition."""
    result = {r['name']: {r['name']} for r in rows if r['classification'] in {'split', 'not-claimed'}}
    while True:
        changed = False
        for edge in edges:
            if edge['relation'] != 'relies':
                continue
            values = result.setdefault(edge['source'], set())
            extra = result.get(edge['target'], set()) - values
            if extra:
                values.update(extra)
                changed = True
        if not changed:
            return {name: sorted(values) for name, values in result.items() if values}


def decisions(source, text, owner, known):
    """Read the shared strict grammar, including acute claim-site citations."""
    from claims import conformance_marks, qualify
    def target(label):
        bare = label.strip('[]').split('-', 1)[-1] if label.startswith('[') else label
        return bare if bare in known else qualify(label, owner)
    return [dict(source=source, target=target(m['label']), relation=m[1], reason=m['reason'].strip())
            for m in conformance_marks(text)]


def source_units(root, rows):
    """Read paragraph, actual claim documentation and data-row decisions."""
    from claims import prose, site_claim, qualify
    from source_sites import census
    from registry_fragments import read, indexed, ROOTS
    paragraphs, _ = prose(root)
    known = {r['name'] for r in rows}
    pattern = re.compile(r'(?<![a-z0-9:.-])(?:[a-z][a-z0-9-]*:){2}[a-z0-9.-]+(?![a-z0-9:.-])')
    def mentions(text):
        return {m[0] for m in pattern.finditer(text) if m[0] in known}
    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for child in value.values():
                yield from strings(child)
        elif isinstance(value, list):
            for child in value:
                yield from strings(child)
    units = []
    for source, row in paragraphs.items():
        if source.split('::')[-1] in known or row['path'] == 'docs/design/progress.md':
            continue
        text = re.sub(r'· `[^`]+`', '', row['text'], count=1)
        units.append((source, text, source.split('::')[0], mentions(text) | row['citations']))
    for site in census(root):
        claim = site_claim(site)
        text = site['doc']
        cited = mentions(text)
        cited.update(qualify(m[1], site['owner']) for m in re.finditer(
            r'\(´(\[[A-Z]+-[a-z0-9:.-]+\]|[a-z0-9:.-]+)´\)', text))
        units.append((claim['claim'], text, site['owner'], cited))
    for row in read(root, 'claim-obligations')['rows']:
        text = '\n'.join(strings(row))
        cited = set(row.get('realizers', [])) | set(row.get('claims', [])) | mentions(text)
        units.append((row['name'], text, row['name'].split('::')[0], cited))
    for family in ('harness-registry', 'linter-owners', 'observation-registry'):
        if not (root/ROOTS[family]).exists():
            continue
        # Discovery and validation stay with the shared registry loader. Avoid
        # parsing a registry with no conformance citation or decision in it.
        relevant = False
        for path in indexed(root, family).values():
            text = path.read_text()
            if mentions(text) or re.search(r'(?:relies|realizes)\{', text):
                relevant = True
                break
        if not relevant:
            continue
        carrier = read(root, family)
        for section, entries in carrier.items():
            if not isinstance(entries, list):
                continue
            for index, row in enumerate(entries):
                text = '\n'.join(strings(row))
                identity = row.get('name', row.get('item', index)) if isinstance(row, dict) else index
                units.append((f'input:{family}:{section}:{identity}', text, 'ROOT', mentions(text)))
    for path in sorted((root/'docs/inputs').rglob('*.toml')):
        if any(path.is_relative_to(root/prefix) for prefix in ROOTS.values()):
            continue
        if path.name in {'deployment-claims.toml', 'deployment-edges.toml', 'specification-progress.toml'}:
            continue
        source = path.read_text()
        if not mentions(source) and not re.search(r'(?:relies|realizes)\{', source):
            continue
        carrier = tomllib.loads(source)
        for index, row in enumerate(carrier.get('rows', [])):
            identity = str(row.get('name', row.get('id', row.get('label', index))))
            if path.name == 'design-inventory.toml' and identity in known:
                continue
            text = '\n'.join(strings({k: v for k, v in row.items() if k not in {'name', 'id', 'label'}}))
            units.append(('input:'+carrier['namespace']+':'+identity, text, 'ROOT', mentions(text)))
    return units, {n.split('::')[-1] for n in paragraphs}


def project(rows, units):
    """Require author decisions, not an automated interpretation of prose."""
    known = {r['name'] for r in rows}
    classified = {r['name']: r for r in rows}
    edges = []
    for source, text, owner, _ in units:
        edges.extend(decisions(source, text, owner, known))
    fields = ('source', 'target', 'relation', 'reason')
    edges = [dict(zip(fields, item)) for item in sorted({tuple(e[k] for k in fields) for e in edges})]
    conditional = closure(rows, edges)
    marked = {(e['source'], e['target']) for e in edges}
    missing = []
    for source, _, _, cited in units:
        for target in sorted(cited & set(conditional)):
            if (source, target) not in marked:
                missing.append(f'unmarked deployment edge: {source} -> {target}')
    if missing:
        raise Refusal('\n'.join(missing)+f'; mark relies or realizes, then run {COMMAND}')
    sources = {source for source, _, _, _ in units}
    for edge in edges:
        if edge['target'] not in known | sources:
            raise Refusal('unresolved deployment edge: '+edge['source']+' -> '+edge['target'])
        if edge['relation'] == 'relies' and edge['target'] not in conditional:
            raise Refusal('reliance has no excluded premise: '+edge['source']+' -> '+edge['target'])
        if edge['relation'] == 'realizes' and edge['target'] in classified and not classified[edge['target']]['included']:
            raise Refusal('claimed-part citation has no claimed part: '+edge['source']+' -> '+edge['target'])
        edge['conditional_on'] = ','.join(conditional.get(edge['target'], [])) if edge['relation'] == 'relies' else ''
    return edges, conditional


def carrier_bytes(edges):
    """Canonical generated intermediary for the documents data stage."""
    lines = ['# Generated by '+COMMAND+'; edit citation marks, never these rows.',
             'namespace = "'+EDGE_NAMESPACE+'"', 'version = [1, 0, 0]', 'rows = [']
    for edge in edges:
        lines.append('  { '+', '.join(k+' = '+json.dumps(v, ensure_ascii=False) for k, v in edge.items())+' },')
    return '\n'.join(lines+ [']', ''])


def compare_edges(expected, actual):
    """Name missing and stale edges, including a removed citation's old row."""
    for row in expected:
        if row not in actual:
            raise Refusal('missing or changed deployment edge: '+row['source']+' -> '+row['target']+'; run '+COMMAND)
    for row in actual:
        if row not in expected:
            raise Refusal('stale deployment edge: '+row['source']+' -> '+row['target']+'; run '+COMMAND)


def check(root=Path('.'), generate=False):
    """Validate source decisions and emit or compare their derived carrier."""
    root = Path(root)
    carrier = tomllib.loads((root/'docs/inputs/deployment-claims.toml').read_text())
    if set(carrier) != {'namespace', 'version', 'rows'} or carrier['namespace'] != NAMESPACE or carrier['version'] != [1, 0, 0]:
        raise Refusal('deployment envelope differs')
    rows = carrier['rows']
    units, mints = source_units(root, rows)
    inventory = tomllib.loads((root/'docs/inputs/design-inventory.toml').read_text())['rows']
    validate(rows, {r['label'] for r in inventory if ':deployment' in r['label']}, mints)
    edges, conditional = project(rows, units)
    path = root/'docs/inputs/deployment-edges.toml'
    text = carrier_bytes(edges)
    if generate:
        path.write_text(text)
    else:
        if not path.exists():
            raise Refusal('missing deployment projection; run '+COMMAND)
        compare_edges(edges, tomllib.loads(path.read_text())['rows'])
        if path.read_text() != text:
            raise Refusal('noncanonical deployment projection; run '+COMMAND)
        for namespace, expected in ((NAMESPACE, rows), (EDGE_NAMESPACE, edges)):
            dataset = json.loads((root/'docs/datasets'/f'{namespace}.json').read_text())
            if dataset['rows'] != expected:
                raise Refusal('stale '+namespace+'; run documents generate, then documents write')
    print(f'DEPLOYMENT-CLAIMS edges={len(edges)} reliance={sum(e["relation"]=="relies" for e in edges)} conditional_claims={sum("::claim:" in s for s in conditional)}')
    return conditional


if __name__ == '__main__':
    started = time.monotonic()
    try:
        if sys.argv[1:] not in ([], ['generate']):
            raise Refusal('usage: deployment_claims.py [generate]')
        check(generate=bool(sys.argv[1:]))
    except (Refusal, ValueError, KeyError) as error:
        print('DEPLOYMENT-CLAIMS-ERROR '+str(error), file=sys.stderr)
        raise SystemExit(1) from error
    finally:
        print(f'DEPLOYMENT-CLAIMS-WALL seconds={time.monotonic()-started:.6f}')
