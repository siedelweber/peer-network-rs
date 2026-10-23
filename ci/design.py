"""Check the preserved inventory and the decomposition's declared correspondence."""

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import tomllib


def digest(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def data(name):
    return json.loads(Path(f'docs/datasets/org.peer-network.design.{name}.json').read_text())['rows']


def release_projection(name, rows):
    if name == 'inventory':
        return [row for row in rows if 'added_at' in row]
    if name == 'constants':
        return [row for row in rows if 'refreshed_at' in row]
    if name == 'questions':
        return [{key: value for key, value in row.items() if key in {'id', 'status', 'section', 'ambiguity'}} for row in rows]
    raise ValueError(f'unknown release projection: {name}')


def first_party_prose():
    members = tomllib.loads(Path('Cargo.toml').read_text())['workspace']['members']
    vendors = [Path(member) for member in members if member.startswith('vendor/')]
    started = time.monotonic()
    tracked = subprocess.run(['git', 'ls-files', '-z'], capture_output=True, check=True)
    print(f'git ls-files wall={time.monotonic() - started:.6f}s status={tracked.returncode}')
    return [path for raw in tracked.stdout.split(b'\0') if raw
            and (path := Path(raw.decode())).suffix in {'.md', '.j2'}
            and not any(path.is_relative_to(vendor) for vendor in vendors)]


def bare_mint_pattern(labels):
    # One compiled union preserves the exact literal and delimiter predicates.
    if not labels:
        raise ValueError("empty paper label set")
    return re.compile('(?<!`)`(' + '|'.join(re.escape(label) for label in sorted(labels)) + ')`(?!`)')


def validate():
    # Claim: nonempty release pins cover every current inventory and constants field.
    inventory = data('inventory')
    constants = data('constants')
    if not (len(inventory) == 1632 and len({row['label'] for row in inventory}) == 1632):
        raise ValueError('inventory label census')
    if not (len(constants) == 542 and len({row['id'] for row in constants}) == 542):
        raise ValueError('constants id census')
    for name, pin in [('inventory', ADDED_INVENTORY_PIN), ('constants', REFRESHED_CONSTANTS_PIN), ('questions', RELEASE_QUESTIONS_PIN)]:
        selection = release_projection(name, data(name))
        if not selection:
            raise ValueError(f'{name}: empty pin selection')
        if digest(selection) != pin:
            raise ValueError(f'{name}: release projection changed')
    relation = tomllib.loads(Path('.linter/environments.toml').read_text())
    kinds = {row['kind'] for key in ('environments', 'extensions') for row in relation[key]}
    kinds.update(relation['reserved_kinds'])
    kinds.update(relation['reserved_extensions'])
    if not (all((row['citable'] == (row['label'].split(':')[0] in kinds) for row in inventory))):
        raise ValueError('citable kind correspondence')
    summary = data('summary')
    if not ({row['name']: row['count'] for row in summary if row['category'] == 'chapter'} == Counter((row['chapter'] for row in inventory))):
        raise ValueError('chapter totals')
    if not ({(row['name'], row['home']): row['count'] for row in summary if row['category'] == 'constants'} == Counter(((row['class'], row['home']) for row in constants))):
        raise ValueError('constant class/home totals')
    if not ({row['name']: row['count'] for row in summary if row['category'] == 'totals'} == {'inventory': len(inventory), 'constants': len(constants)}):
        raise ValueError('global totals')

    # Claim: seven responsibility rows form an acyclic prerequisite graph and eleven slices retain their declared order.
    crates = data('crates')
    expected = ['pn-records', 'pn-graph', 'pn-epoch', 'pn-readouts', 'pn-host', 'pn-replay', 'pn-verification']
    if not ([row['name'] for row in crates] == expected):
        raise ValueError('crate roster')
    known = set()
    labels = {row['label'] for row in inventory}
    for row in crates:
        if not (row['responsibility'] and set(row['dependencies']) <= known):
            raise ValueError('dependency order')
        if not (len(row['dependencies']) == len(set(row['dependencies']))):
            raise ValueError('duplicate dependency')
        if not (set(row['surfaces']) <= labels):
            raise ValueError('crate surface missing from inventory')
        known.add(row['name'])
    if not ('pn-replay' not in next((row for row in crates if row['name'] == 'pn-host'))['dependencies']):
        raise ValueError('host/replay boundary')
    bites = data('bites')
    if not ([row['ordinal'] for row in bites] == list(range(1, 12))):
        raise ValueError('bite sequence')
    if not (all((row['slice'].split(':')[0] in known and row['records'] and row['dependency'] for row in bites))):
        raise ValueError('bite fields')

    # Claim: each correspondence pin identifies its accepted authority in the publication dataset.
    publications = data('publication')
    for name, pin in [('crates', CRATES_PIN), ('bites', BITES_PIN), ('questions', QUESTIONS_PIN)]:
        provenance = [row for row in publications if row['name'] == name]
        if len(provenance) != 1 or provenance[0]['namespace'] != f'org.peer-network.design.{name}':
            raise ValueError(f'{name}: missing unique pin provenance')
        if provenance[0]['dispatch'] != 'siedelweber/design-study/2026-10-21-1' or "accepted decomposition" not in provenance[0]['source']:
            raise ValueError(f'{name}: pin authority differs from the accepted study')
        projection = [{key: value for key, value in row.items() if key not in {'status', 'section', 'ambiguity'}} for row in data(name)] if name == 'questions' else data(name)
        if not projection:
            raise ValueError(f'{name}: empty pin selection')
        if digest(projection) != pin:
            raise ValueError(f'{name}: source projection changed')
    for name in ('paper', 'questions'):
        rows = [row for row in publications if row['name'] == name]
        if len(rows) != 1 or rows[0].get('tag') != PAPER_TAG:
            raise ValueError(f'{name}: paper release tag changed')
    for rows, field in ((inventory, 'added_at'), (constants, 'refreshed_at')):
        if any(row[field] != PAPER_TAG for row in rows if field in row):
            raise ValueError(f'{field}: paper release tag changed')
    questions = data('questions')
    if [row['id'] for row in questions] != [f'Q{number:02}' for number in range(1, 39)]:
        raise ValueError('question ids must be Q01 through Q38 in order')
    if any(row['class'] not in {'ANSWERED', 'DEFECT', 'OWNER-CALL'} for row in questions):
        raise ValueError('unknown maintainer question class')
    if any('questions' in row or 'question' in row for row in bites):
        raise ValueError('bite rows must not infer a question mapping')

    # Claim: paper labels are never minted here; the publication state controls citation versus exhibition.
    publications = data('publication')
    publication = next(row for row in publications if row['name'] == 'paper')
    if publication['namespace'] != 'class.linter.labels':
        raise ValueError('project-neutral registry namespace')
    owners = tomllib.loads(Path('.linter/owners.toml').read_text())
    imports = [row for row in owners['imports'] if row['owner'] == 'PAPER']
    registry = Path('.linter/imports/paper.toml')
    template = Path('docs/templates/.linter/imports/paper.toml.j2')
    if publication['imported']:
        if not (imports == [{'owner': 'PAPER', 'registry': str(registry)}]):
            raise ValueError('paper owner import')
        imported = tomllib.loads(registry.read_text())
        if not (imported['source'] == {'owner': 'PAPER', 'tag': publication['tag']}):
            raise ValueError('paper edition')
        if not (imported['namespace'] == publication['namespace']):
            raise ValueError('project-neutral registry')
        if not ('(`[PAPER-def:comparator:burn-interface]`)' in Path('adr/007-crate-decomposition.md').read_text()):
            raise ValueError('paper citation witness')
    else:
        if not (not imports and (not registry.exists()) and (not template.exists())):
            raise ValueError('withdrawn import remains present')
    labels.update(row['cites'] for row in constants if row['cites'])
    bare_mint = bare_mint_pattern(labels)
    for path in first_party_prose():
        source = path.read_text()
        if match := bare_mint.search(source):
            raise ValueError(f'{path}: bare paper mint {match.group(1)}')
        if not publication['imported'] and path.suffix == '.md':
            if not ('[PAPER-' not in source):
                raise ValueError(f'{path}: inactive imported citation')
    print(f'DESIGN-CORRESPONDENCE inventory={len(inventory)} constants={len(constants)} crates={len(crates)} bites={len(bites)} imported={publication["imported"]}')
    print('PAPER-KINDS=' + json.dumps({kind: dict(citable=sum(row['citable'] for row in inventory if row['label'].split(':')[0] == kind), ineligible=sum(not row['citable'] for row in inventory if row['label'].split(':')[0] == kind)) for kind in sorted({row['label'].split(':')[0] for row in inventory})}, sort_keys=True))


PAPER_TAG = 'network-v0.26.3'
ADDED_INVENTORY_PIN = '168c857b172ffe8c10fbfe153977e7b0d83e96d20b1e5c0e2bd72468259ae02f'
REFRESHED_CONSTANTS_PIN = 'a5f41236d2a66582ed4f02304893e62448b3b3c8e3551e27733bced8ac9203c9'
RELEASE_QUESTIONS_PIN = 'f0f3591d8e48acf2dc94bdfa069da82b53ff136e63fe58e7491e740996f399e9'


CRATES_PIN = 'b8188551b1f51e6afa88329f46b4a5d82391fdba4ecefea489043ceca227e476'
BITES_PIN = 'feb1a8a28938cb9edc599ea0769c471e6a2c2c3cb31b915b1c450aced1cd9fdc'
QUESTIONS_PIN = 'f764302dfe333160685cd47070335b7ab2bccec1151a45d96681947e61587a2b'

if __name__ == '__main__':
    validate()
