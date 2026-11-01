"""Check the preserved inventory and the decomposition's declared correspondence."""

from collections import Counter
import hashlib
import ast
import json
import math
import os
from fractions import Fraction
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
        return [row for row in rows if 'current_at' in row]
    if name == 'constants':
        return [row for row in rows if 'refreshed_at' in row]
    if name == 'questions':
        return [{key: value for key, value in row.items() if key in {'id', 'status', 'section', 'ambiguity'}} for row in rows]
    raise ValueError(f'unknown release projection: {name}')


def tracked_paths():
    started = time.monotonic()
    tracked = subprocess.run(['git', 'ls-files', '-z'], capture_output=True, check=True)
    print(f'git ls-files wall={time.monotonic() - started:.6f}s status={tracked.returncode}')
    return [Path(raw.decode()) for raw in tracked.stdout.split(b'\0') if raw]


def first_party_prose():
    members = tomllib.loads(Path('Cargo.toml').read_text())['workspace']['members']
    vendors = [Path(member) for member in members if member.startswith('vendor/')]
    return [path for path in tracked_paths() if path.suffix in {'.md', '.j2'}
            and not any(path.is_relative_to(vendor) for vendor in vendors)]


PAPER_EDITION_FIXTURES = {
    'ci/test_design.py',
    'packages/documents/tests/integration.rs',
}


def check_paper_editions(paths):
    """Check tracked UTF-8 text without NUL bytes, except named source fixtures."""
    checked = mentions = binary = exempt = 0
    findings = []
    for path in paths:
        if path.as_posix() in PAPER_EDITION_FIXTURES:
            exempt += 1
            continue
        try:
            source = path.read_bytes().decode('utf-8')
        except UnicodeDecodeError:
            binary += 1
            continue
        if '\0' in source:
            binary += 1
            continue
        checked += 1
        for number, line in enumerate(source.splitlines(), 1):
            for match in re.finditer(r'network-v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-z0-9.-]+)?', line, re.IGNORECASE):
                mentions += 1
                if match.group().casefold() != PAPER_TAG.casefold():
                    findings.append(f'{path}:{number}: stale paper edition {match.group()} (current {PAPER_TAG})')
    print(f'PAPER-EDITIONS files={checked} mentions={mentions} binary={binary} exempt={exempt} refused={len(findings)}')
    if findings:
        raise ValueError('\n'.join(findings))


def bare_mint_pattern(labels):
    # One compiled union preserves the exact literal and delimiter predicates.
    if not labels:
        raise ValueError("empty paper label set")
    return re.compile('(?<!`)`(' + '|'.join(re.escape(label) for label in sorted(labels)) + ')`(?!`)')


def check_numeric_word_fragments(paths):
    """Keep structural number-word compounds intact in migrated rendered prose."""
    pattern = re.compile(r'\b(?:twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)-[0-9]+\b'
                         r'|\b[0-9]+-(?:map|Actor|capable|unit|endpoint|proposal|width|minute|half|source|hop|mass|marker)\b'
                         r'|(?<![\w\u202f.])1-Work\b'
                         r'|\b(?:precision|wall|minus)-[0-9]+\b'
                         r'|\b[0-9]+ (?:half|quarter)\b|\bx=\s+[0-9]+\b', re.IGNORECASE)
    findings = []
    for path in paths:
        if path.suffix == '.j2':
            # Quoted strings may contain expression delimiters; keep their boundaries intact.
            expression = r'''\{\{(?:[^'"}]|}(?!})|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")*\}\}'''
            literal = re.sub(expression, lambda match: '\n' * match.group().count('\n'), path.read_text())
            findings.extend(f'{path}:{line}: literal U+202F outside template expression'
                            for line, text in enumerate(literal.splitlines(), 1) if '\u202f' in text)
            continue
        for line, text in enumerate(path.read_text().splitlines(), 1):
            findings.extend(f'{path}:{line}: numeric word fragment {match.group()}'
                            for match in pattern.finditer(text))
    print(f'NUMERIC-WORDS files={len(paths)} refused={len(findings)}')
    if findings:
        raise ValueError('\n'.join(findings))


# Per-path ceilings (repeated blank runs, continuation lines). Parent comparison
# refuses new paths and increased ceilings; clean or missing paths must retire.
PENDING_RENDERED_SPACING = {
    'README.md': (8, 0),
    'adr/002-environment-kinds.md': (16, 0),
    'adr/006-identity-adjudication.md': (4, 0),
    'adr/015-durable-storage.md': (6, 0),
    'adr/016-observability.md': (10, 0),
    'adr/019-development-network.md': (5, 0),
    'adr/021-development-performance.md': (2, 0),
    'adr/023-cryptographic-base.md': (1, 0),
    'adr/024-build-graph.md': (5, 0),
    'docs/design/inventory.md': (1, 0),
    'packages/act-profile/README.md': (1, 0),
    'packages/host/README.md': (2, 0),
    'packages/interchange/README.md': (22, 0),
}


def rendered_continuations(source):
    """Locate wrapped prose while keeping Markdown block boundaries distinct."""
    result = []
    paragraph = False
    fence = None
    comment = False
    front = False
    for number, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if number == 1 and line == '---':
            front = True
            continue
        if front:
            front = line not in {'---', '...'}
            continue
        if comment:
            comment = '-->' not in line
            continue
        if line.startswith('<!--'):
            comment = '-->' not in line
            paragraph = False
            continue
        marker = re.match(r'(`{3,}|~{3,})', line)
        if fence:
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence):
                fence = None
            continue
        if marker:
            fence = marker[1]
            paragraph = False
            continue
        if not line:
            paragraph = False
            continue
        # A quoted paragraph has the same physical-line convention as prose.
        line = re.sub(r'^(?:>\s*)+', '', line)
        if (not line or re.match(r'#{1,6}\s|\||(?:[-*_]\s*){3,}$|\[[^]]+\]:', line)):
            paragraph = False
            continue
        if re.match(r'(?:[-+*]|[0-9]+[.)])\s', line):
            paragraph = True
            continue
        if paragraph:
            result.append(number)
        elif raw.startswith(('    ', '\t')):
            # An indented code block after a block boundary is not prose.
            continue
        paragraph = True
    return result


def parent_rendered_spacing(base=None, root=None):
    """Read the declared import base; absent that interface, use the parent."""
    root = root or Path(__file__).resolve().parent.parent
    base = os.environ.get('PN_IMPORT_BASE', 'HEAD^') if base is None else base
    resolved = subprocess.run(['git', '-C', str(root), 'rev-parse', '--verify', base+'^{commit}'],
                              capture_output=True, text=True, check=True).stdout.strip()
    subprocess.run(['git', '-C', str(root), 'merge-base', '--is-ancestor', resolved, 'HEAD'],
                   capture_output=True, check=True)
    result = subprocess.run(['git', '-C', str(root), 'show', resolved+':ci/design.py'],
                            capture_output=True, text=True, check=True)
    for node in ast.parse(result.stdout).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                and target.id == 'PENDING_RENDERED_SPACING' for target in node.targets):
            value = node.value
            # The predecessor represented the same debt as a set of paths.
            if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == 'frozenset':
                value = value.args[0]
            return ast.literal_eval(value)
    raise ValueError('import base lacks rendered-spacing declaration')


def check_rendered_spacing(paths, pending=PENDING_RENDERED_SPACING, *, whole_tree=False, parent=None):
    """Check per-path debt ceilings, retirement and import-base-relative growth."""
    findings = []
    checked = deferred = 0
    paths = list(paths)
    present = {path.as_posix() for path in paths if path.exists()}
    if parent is not None:
        for name in sorted(set(pending) - set(parent)):
            findings.append(f'{name}: new rendered-spacing exception against source base')
        if isinstance(parent, dict):
            for name in sorted(set(pending) & set(parent)):
                if any(now > before for now, before in zip(pending[name], parent[name])):
                    findings.append(f'{name}: increased rendered-spacing ceiling against source base')
    if whole_tree:
        findings.extend(f'{name}: missing rendered-spacing pending path' for name in sorted(set(pending) - present))
    for path in paths:
        if path.suffix != '.md' or path.is_relative_to('vendor') or not path.exists():
            continue
        checked += 1
        source = path.read_text()
        repeated = re.findall(r'\n(?:[ \t]*\n){2,}', source)
        continuations = rendered_continuations(source)
        if path.as_posix() in pending:
            ceilings = pending[path.as_posix()]
            if not repeated and not continuations:
                findings.append(f'{path}: remove resolved rendered-spacing exception')
            for kind, count, ceiling in zip(('blank runs', 'continuation lines'),
                                            (len(repeated), len(continuations)), ceilings):
                if count > ceiling:
                    findings.append(f'{path}: rendered-spacing {kind} exceed ceiling {ceiling}: {count}')
            deferred += 1
        else:
            if repeated:
                findings.append(f'{path}: repeated blank lines in rendered Markdown')
            findings.extend(f'{path}:{line}: continuation line in rendered Markdown' for line in continuations)
    print(f'RENDERED-SPACING files={checked} pending={deferred} refused={len(findings)}')
    if findings:
        raise ValueError('\n'.join(findings))


def validate():
    # Claim: nonempty release pins cover every current inventory and constants field.
    inventory = data('inventory')
    constants = data('constants')
    if not (len(inventory) == 1676 and len({row['label'] for row in inventory}) == 1676):
        raise ValueError('inventory label census')
    placeholders = [row for row in inventory if re.search(r'^Track\s+.+\s+as a separately addressable\s+', row['statement'])]
    structural = {'section', 'subsection', 'appendix', 'motto'}
    refused = [row['label'] for row in placeholders if row['environment'] not in structural]
    print(f'INVENTORY-PLACEHOLDERS rows={len(inventory)} structural={len(placeholders) - len(refused)} refused={len(refused)}')
    if refused:
        raise ValueError('obligation-bearing inventory placeholders: ' + ', '.join(refused))
    if not (len(constants) == 2833 and len({row['id'] for row in constants}) == 2833):
        raise ValueError('constants id census')
    for name, pin in [('inventory', CURRENT_INVENTORY_PIN), ('constants', REFRESHED_CONSTANTS_PIN), ('questions', RELEASE_QUESTIONS_PIN)]:
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

    # Claim: eight responsibility rows form an acyclic prerequisite graph and eleven slices retain their declared order.
    crates = data('crates')
    expected = ['pn-records', 'pn-act-profile', 'pn-graph', 'pn-epoch', 'pn-readouts', 'pn-host', 'pn-replay', 'pn-verification']
    if not ([row['name'] for row in crates] == expected):
        raise ValueError('crate roster')
    known = {'pn-interchange'}
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
    for rows, field in ((inventory, 'current_at'), (constants, 'refreshed_at')):
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
    check_paper_editions(tracked_paths())
    for path in first_party_prose():
        source = path.read_text()
        if match := bare_mint.search(source):
            raise ValueError(f'{path}: bare paper mint {match.group(1)}')
        if not publication['imported'] and path.suffix == '.md':
            if not ('[PAPER-' not in source):
                raise ValueError(f'{path}: inactive imported citation')
    print(f'DESIGN-CORRESPONDENCE inventory={len(inventory)} constants={len(constants)} crates={len(crates)} bites={len(bites)} imported={publication["imported"]}')
    print('PAPER-KINDS=' + json.dumps({kind: dict(citable=sum(row['citable'] for row in inventory if row['label'].split(':')[0] == kind), ineligible=sum(not row['citable'] for row in inventory if row['label'].split(':')[0] == kind)) for kind in sorted({row['label'].split(':')[0] for row in inventory})}, sort_keys=True))


PAPER_TAG = 'network-v0.31.1'
CURRENT_INVENTORY_PIN = 'a2630aef618849af26e41afab16f77dd61a8c82adc81a695d717004d9fc195f3'
REFRESHED_CONSTANTS_PIN = '03aa866e0fabcf333b197ade3dc5022acf3eaa8101eab9f20c1779a14d61617a'
RELEASE_QUESTIONS_PIN = 'e15ab3d56900f3e696b1733cc32f1aa0b9491bb793cbddc7b13b0b9bd6c584e7'


CRATES_PIN = '779ad51bb7a4a5d2047c0307a7bea589e3add012f8b1ceb5c79a2be3ddb1f5d5'
BITES_PIN = '98bcd0533748b432a783e89676629088bb627f633d1009b0c2dcd5f954b191fb'
QUESTIONS_PIN = '1aa56833a069fca9ea47fa9e902241033faed3670689a649e7fc577423eafa95'

def published_correspondence(rows, path=None):
    """Join tagged published quantities to supplied external build values exactly."""
    suffixes = ('standing-before', 'standing-after', 'finite-change', 'certificate-before',
                'certificate-after', 'fence-before', 'fence-after')
    expected = {f'num:numbers:published-act-{family}-{suffix}':
                f'result.tilt_act_{family}.'+suffix.replace('-', '_')
                for family in ('isolated', 'retained') for suffix in suffixes}
    selected = {row['id']:row for row in rows if row['id'] in expected}
    if set(selected) != set(expected):
        raise ValueError('published registry: missing declared row')
    for name, row in selected.items():
        if row.get('paper_key') != expected[name] or row.get('paper_tag') != PAPER_TAG:
            raise ValueError('published registry: missing or mismatched paper key/tag')
    if path is not None:
        supplied = json.loads(Path(path).read_text())
        if supplied.get('schema') != 'peer-values-1':
            raise ValueError('published registry: unsupported external values schema')
        values = {row['id']:row for row in supplied['values']}
        if len(values) != len(supplied['values']):
            raise ValueError('published registry: duplicate external key')
        for row in selected.values():
            entry = values.get(row['paper_key'])
            if entry is None or 'computed' not in entry or Fraction(entry['computed']) != Fraction(row['value']):
                raise ValueError('published registry: external exact value differs or is missing: '+row['paper_key'])
    print(f'PUBLISHED-CORRESPONDENCE rows={len(selected)} tag={PAPER_TAG} mode={"external-exact" if path is not None else "metadata-only"}')


def numeric_correspondence():
    """Derived rate pins retain the recorded samples' full rational precision."""
    rows = tomllib.loads(Path('docs/inputs/numbers.toml').read_text())['rows']
    published_correspondence(rows, os.environ.get('PN_PAPER_VALUES'))
    values = {row['id']: Fraction(row['value']) for row in rows}
    def value(name):
        return values['num:numbers:' + name]
    derived = 0
    def equal(actual, expected):
        nonlocal derived
        derived += 1
        if actual != expected:
            raise ValueError('numeric registry: derived rate differs from recorded operands')
    for wall in ('enclosed', 'rational'):
        equal(value(f'{wall}-wall-mandatory-work'), value(f'{wall}-wall-production-work')
              + value(f'{wall}-wall-replay-work'))
    equal(value('solve-sixteenth-two-work'), value('candidate-total-work')
          + value('certified-map-work') + value('residual-arithmetic-work'))
    # The charter fixes four hops; the +3 term is structural in the cell envelope.
    for regime, depths in (('supported', value('frozen-supported-depth-count')), ('chartered', 4)):
        equal(value(f'projected-{regime}-cell-count'), value('solve-projection-actor-count') ** 2
              * (depths + 3))
    def pin_equal(actual, expected):
        if actual != expected:
            raise ValueError('numeric registry: derived rate differs from recorded operands')
    rates = {speed: value(f'rate-{speed}-sample-seconds') / value('rate-sample-work')
             for speed in ('fast', 'middle', 'slow')}
    for speed, rate in rates.items():
        equal(value(f'rate-{speed}-seconds-per-million'), rate * 10**6)
    for route in ('point', 'pair'):
        for size in ('four', 'thousand'):
            for grid in ('dyadic', 'nondyadic'):
                quantity = f'{route}-{size}-{grid}'
                for speed in ('fast', 'slow'):
                    equal(value(f'{quantity}-{speed}-seconds'), value(f'{quantity}-work') * rates[speed])
    solve_rates = [value(f'solve-{denominator}-{cap}-seconds') * 10**9
                   / value(f'solve-{denominator}-{cap}-work')
                   for denominator in ('quarter', 'sixteenth') for cap in ('one', 'two')]
    for bound, speed, rate in (('lower', 'fast', min(solve_rates)), ('upper', 'slow', max(solve_rates))):
        equal(value(f'solve-rate-{bound}-milliseconds-per-million'), rate)
        equal(value(f'projected-solve-{speed}-seconds'), value('projected-solve-work')
              * rate / 10**9)
    equal(value('projected-solve-work'),
          2 * (value('proposal-prefix-work') + value('projection-actor-scale')
               * (value('second-proposal-work') - value('proposal-prefix-work')))
          + value('solve-certifying-prefix-work') + value('projection-actor-scale')
          * (value('certified-map-work') - value('solve-certifying-prefix-work'))
          + value('projection-actor-scale')
          * (value('proposal-arithmetic-work') + value('residual-arithmetic-work')))
    equal(value('epoch-recipient-history-count'), value('epoch-recipient-scenario-count')
          * value('epoch-recipient-presentation-count'))
    equal(value('epoch-invitation-radicand'), value('epoch-invitation-urgency')
          * value('epoch-invitation-formality'))
    for family, operand in (('family', 'family-fixture'), ('mixed', 'mixed-tail')):
        count = value(f'epoch-{operand}-act-count')
        if count.denominator != 1:
            raise ValueError('numeric registry: permutation length must be integral')
        equal(value(f'epoch-{family}-presentation-count'), math.factorial(count.numerator))
    # The definition fixes the authored roster at nineteen families.
    equal(value('epoch-family-history-count'), 19 * value('epoch-family-presentation-count'))
    # Each settlement chain has the structural Bid, Accept, Ratify stages.
    chains = value('epoch-settlement-chain-count')
    if chains.denominator != 1 or chains < 0:
        raise ValueError('numeric registry: chain count must be a nonnegative integer')
    equal(value('epoch-settlement-interleaving-count'), math.factorial(3 * chains.numerator)
          // math.factorial(3) ** chains.numerator)
    equal(value('epoch-aggregate-case-count'), value('epoch-aggregate-family-count')
          * value('epoch-aggregate-member-maximum') * value('epoch-aggregate-coordinate-count'))
    equal(value('records-dag-proposal-epoch'), value('records-dag-history-epoch') + 1)
    equal(value('records-dag-proposal-maximum'), value('records-dag-proposal-minimum')
          + value('records-dag-word-capacity'))
    for kind in ('user', 'system'):
        changes = [value(f'buildgraph-admission-{sample}-entry-{kind}')
                   - value(f'buildgraph-entry-before-selection-{kind}') for sample in ('first', 'second')]
        equal(value(f'buildgraph-admission-{kind}-increase-lower'), min(changes))
        equal(value(f'buildgraph-admission-{kind}-increase-upper'), max(changes))
    equal(value('buildgraph-admission-obligation-count'),
          value('buildgraph-admission-supported-obligation-count')
          + value('buildgraph-admission-failed-obligation-count')
          + value('buildgraph-admission-held-obligation-count'))
    measurements = {row['name']: row for row in tomllib.loads(Path('docs/inputs/devperf-measurements.toml').read_text())['rows']}
    budgets = {row['name']: row for row in tomllib.loads(Path('docs/inputs/devperf-budgets.toml').read_text())['rows']}
    registry = {row['name']: row for row in tomllib.loads(Path('docs/inputs/devperf-registry.toml').read_text())['rows']}
    closing = {row['name']: row for row in tomllib.loads(Path('docs/inputs/devperf-close-measurements.toml').read_text())['rows']}
    for quantity, source in (
        ('devperf-profile-default-test-median', 'isolation-defaults-test-2'),
        ('devperf-profile-debugless-test-median', 'isolation-debugless-test-7'),
        ('devperf-profile-optimized-test-median', 'isolation-optimized-test-12'),
        ('devperf-profile-default-documents-median', 'isolation-defaults-documents-4'),
        ('devperf-profile-debugless-documents-median', 'isolation-debugless-documents-9'),
        ('devperf-profile-optimized-documents-median', 'isolation-optimized-documents-14'),
        ('devperf-profile-before-edit-median', 'baseline-default-edit-10'),
        ('devperf-profile-after-edit-median', 'baseline-candidate-edit-20'),
        ('devperf-runner-default-cargo-median', 'comparison-default-libtest-4'),
        ('devperf-runner-default-nextest-median', 'comparison-default-nextest-5'),
        ('devperf-runner-gate-cargo-median', 'comparison-candidate-libtest-8'),
        ('devperf-runner-gate-nextest-median', 'comparison-candidate-nextest-9'),
        ('devperf-bundled-link-edit-median', 'linker-bundled-link-edit-1'),
        ('devperf-system-link-edit-median', 'linker-system-link-edit-3'),
    ):
        operands = sorted(Fraction(str(sample)) for sample in measurements[source]['samples_s'])
        equal(value(quantity), (operands[(len(operands) - 1) // 2] + operands[len(operands) // 2]) / 2)
    equal(value('devperf-runner-gate-overhead-seconds'), value('devperf-runner-gate-nextest-median')
          - value('devperf-runner-gate-cargo-median'))
    equal(value('devperf-record-margin-percent'),
          (Fraction(budgets['gate']['budget_ms'], 1000) / Fraction(budgets['gate']['record_second_wall_seconds']) - 1) * 100)
    equal(value('devperf-former-warm-margin-percent'),
          (value('devperf-former-warm-budget-seconds') / value('devperf-complete-accounting-gate-seconds') - 1) * 100)
    equal(value('devperf-nullable-count-warm-ratio'),
          Fraction(str(closing['warmed-pair-2']['duration_ms'])) / Fraction(str(closing['warmed-pair-1']['duration_ms'])))
    runtime = registry['observation-runtime']
    equal(value('devperf-runtime-calibration-median-margin-percent'),
          (Fraction(runtime['budget_ms'], runtime['median_ms']) - 1) * 100)
    equal(Fraction(runtime['profile_wall_seconds']),
          sum(Fraction(runtime[field]) for field in ('profile_command_seconds', 'profile_reconstruction_seconds', 'profile_other_seconds')))
    observation_fixtures = {row['name']: row for row in
                            tomllib.loads(Path('docs/inputs/observe-fixtures.toml').read_text())['rows']}
    # The reserved metric summary contributes one delivered record, excluding final status.
    equal(value('observe-burst-delivered-record-count'), observation_fixtures['trace-burst']['ordinary_records'] + 1)
    equal(value('observe-reader-headroom-level-count'),
          value('observe-serde-json-default-recursion-limit') - value('observe-inline-nesting-level-count'))
    equal(value('observe-drain-maximum-seconds'), value('observe-drain-base-seconds')
          + value('observe-queued-byte-capacity') / (1024 * 1024) * value('observe-drain-per-mib-seconds'))
    properties = json.loads(Path('docs/datasets/org.peer-network.harness.properties.json').read_text())['rows']
    compiler = next(row for row in properties if row.get('name') == 'pn-epoch::compiler::compiler_generated')
    pin_equal(value('epoch-property-draw-count'), compiler['cases'])
    projected = json.loads(Path('docs/datasets/org.peer-network.numbers.registry.json').read_text())['rows']
    if len(projected) != len(rows):
        raise ValueError('numeric registry: projection census differs')
    for entry, view in zip(rows, projected):
        number = Fraction(entry['value'])
        quantum = Fraction(10) ** entry.get('magnitude', 0)
        if entry['display'] == 'rounded':
            scaled = abs(number) / quantum
            whole, remainder = divmod(scaled.numerator, scaled.denominator)
            nearest = whole + (2 * remainder >= scaled.denominator)
            expected = nearest * quantum * (-1 if number < 0 else 1)
        elif entry['display'] in {'floor', 'ceiling'}:
            scaled = number / quantum
            whole = scaled.numerator // scaled.denominator
            if entry['display'] == 'ceiling' and scaled != whole:
                whole += 1
            expected = whole * quantum
        else:
            expected = number
        if (view['id'] != entry['id'] or Fraction(view['num'].replace('\u202f', '')) != expected
                or view['num_exact'] != (expected == number)):
            raise ValueError('numeric registry: independent rational display comparison differs')
        relation = '=' if expected == number else {'floor': '≥', 'ceiling': '≤', 'rounded': '≈'}[entry['display']]
        if view.get('num_relation') != relation:
            raise ValueError('numeric registry: generated relation differs')
        admitted = sum(c.isdigit() for c in entry['value']) <= entry['exact_digits']
        if ('exact' in view) != admitted:
            raise ValueError('numeric registry: exact digit budget differs')
        if admitted and (Fraction(view['exact'].replace('\u202f', '')) != number
                         or view['exact_exact'] is not True or view.get('exact_relation') != '='):
            raise ValueError('numeric registry: exact form differs')
    print(f'NUMERIC-CORRESPONDENCE entries={len(rows)} derived={derived} displays={len(projected)}')


if __name__ == '__main__':
    validate()
    numeric_correspondence()
    check_rendered_spacing(tracked_paths(), whole_tree=True, parent=parent_rendered_spacing())
    check_numeric_word_fragments([path for path in tracked_paths()
                                  if path.as_posix() in {'docs/design/implementation.md', 'packages/epoch/README.md', 'packages/records/README.md', 'adr/024-build-graph.md', 'adr/021-development-performance.md', 'adr/016-observability.md'}
                                  or path.is_relative_to('docs/templates') and path.suffix == '.j2'])
