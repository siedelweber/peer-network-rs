"""Exercise correspondence refusals in isolated tracked trees."""

import json
import itertools
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from design import PAPER_EDITION_FIXTURES, PAPER_TAG, bare_mint_pattern, check_rendered_spacing, validate


REPOSITORY = Path(__file__).resolve().parent.parent

# Reuse the optimized interpreter, not validation results or parsed datasets.
# Each request executes the complete command in a fresh module namespace and
# rereads the fixture tree. Mutations still cross the real optimized boundary.
CHECKER = r'''
import contextlib, io, json, sys, traceback
path = sys.argv[1]
with open(path) as source:
    command = compile(source.read(), path, 'exec')
for request in sys.stdin:
    output, errors = io.StringIO(), io.StringIO()
    status = 0
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
        try:
            exec(command, {'__name__': '__main__', '__file__': path})
        except SystemExit as error:
            status = error.code
        except Exception:
            status = 1
            traceback.print_exc()
    print(json.dumps([status, output.getvalue(), errors.getvalue()]), flush=True)
'''


def git(root, *args):
    started = time.monotonic()
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, check=True)
    print(f'git {args[0]} wall={time.monotonic() - started:.6f}s status={result.returncode}')


class Correspondence(unittest.TestCase):
    def test_empty_selections(self):
        """Empty label and pin selections refuse vacuous correspondence evidence.
        ´claim:design:nonempty-correspondence-evidence´
        ´test:integration:test-empty-selections´
        """
        with self.assertRaisesRegex(ValueError, 'empty paper label set'):
            bare_mint_pattern(set())
        with patch('design.release_projection', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'empty pin selection'):
                validate()

    def test_indexed_mint_predicate(self):
        """The compiled union retains every literal and backtick boundary refusal.
        ´claim:devperf:correspondence-predicate-preserved´
        ´test:integration:test-indexed-mint-predicate´
        """
        labels = {'a', 'b', 'a.b', 'a+b', 'a:b:c'}
        union = bare_mint_pattern(labels)
        samples = (''.join(parts) for size in range(8) for parts in itertools.product('`ab.', repeat=size))
        for source in itertools.chain(samples, ['`a+b`', '``a+b``', '`a:b:c`', '`a.b`', '`a`b`']):
            expected = any(re.search('(?<!`)`' + re.escape(label) + '`(?!`)', source) for label in labels)
            self.assertEqual(bool(union.search(source)), expected, source)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        shutil.copytree(REPOSITORY / 'docs/datasets', self.root / 'docs/datasets')
        (self.root / 'docs/inputs').mkdir()
        shutil.copy(REPOSITORY / 'docs/inputs/numbers.toml', self.root / 'docs/inputs/numbers.toml')
        shutil.copy(REPOSITORY / 'docs/inputs/devperf-budgets.toml', self.root / 'docs/inputs/devperf-budgets.toml')
        (self.root / '.linter').mkdir()
        shutil.copy(REPOSITORY / '.linter/owners.toml', self.root / '.linter/owners.toml')
        shutil.copy(REPOSITORY / '.linter/environments.toml', self.root / '.linter/environments.toml')
        (self.root / 'Cargo.toml').write_text('[workspace]\nmembers = ["vendor/example"]\n')
        git(self.root, 'init', '--quiet')
        self.checker = None

    def close_checker(self):
        self.checker.stdin.close()
        self.checker.wait(timeout=10)
        self.checker.stdout.close()
        self.checker.stderr.close()

    def check(self):
        command = [sys.executable, '-B', '-O', '-u', '-c', CHECKER, str(REPOSITORY / 'ci/design.py')]
        if self.checker is None:
            self.checker = subprocess.Popen(command, cwd=self.root, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.addCleanup(self.close_checker)
        self.checker.stdin.write('check\n')
        self.checker.stdin.flush()
        response = self.checker.stdout.readline()
        if not response:
            raise RuntimeError(self.checker.stderr.read())
        status, output, errors = json.loads(response)
        return subprocess.CompletedProcess(command, status, output, errors)

    def test_numeric_correspondence(self):
        """Independent rational checks refuse changed rate operands, rounded display values, exactness flags and omitted-form budgets under optimized Python.
        ´claim:design:numeric-displays-match-rational-operands´
        ´test:integration:test-numeric-correspondence´
        """
        path = self.root / 'docs/datasets/org.peer-network.numbers.registry.json'
        original = json.loads(path.read_text())
        self.assertEqual(self.check().returncode, 0)
        for field, value in [('num', '0'), ('num_exact', False), ('exact_digits', 0)]:
            changed = json.loads(json.dumps(original))
            if field == 'exact_digits':
                changed['rows'][0].pop('exact')
            else:
                changed['rows'][0][field] = value
            path.write_text(json.dumps(changed))
            result = self.check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('numeric registry:', result.stderr)
        path.write_text(json.dumps(original))
        source = self.root / 'docs/inputs/numbers.toml'
        source_original = source.read_text()
        for name, truncated in [('solve-rate-lower-milliseconds-per-million', '1.895'),
                                ('solve-rate-upper-milliseconds-per-million', '1.969'),
                                ('projected-solve-fast-seconds', '59.1'),
                                ('projected-solve-slow-seconds', '61.5'),
                                ('enclosed-wall-mandatory-work', '993'),
                                ('epoch-recipient-history-count', '21'),
                                ('epoch-invitation-radicand', '0.56' + '1'),
                                ('epoch-family-presentation-count', '23'),
                                ('epoch-mixed-presentation-count', '23'),
                                ('epoch-family-history-count', '455'),
                                ('epoch-settlement-interleaving-count', '19'),
                                ('epoch-aggregate-case-count', '26'),
                                ('epoch-property-draw-count', '255'),
                                ('records-dag-proposal-maximum', '9'),
                                ('records-dag-proposal-epoch', '3')]:
            changed = re.sub(r'(id = "num:numbers:' + name + r'"\nvalue = ")[^"]+',
                             lambda match: match[1] + truncated, source_original)
            self.assertNotEqual(changed, source_original)
            source.write_text(changed)
            result = self.check()
            self.assertNotEqual(result.returncode, 0, name)
            self.assertIn('derived rate differs', result.stderr)
        source.write_text(source_original)
        sample = next(row['value'] for row in original['rows'] if row['id'] == 'num:numbers:rate-fast-sample-seconds')
        source.write_text(source.read_text().replace('value = '+json.dumps(sample), 'value = "1"'))
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('derived rate differs', result.stderr)

    def test_numeric_word_fragments(self):
        """Rendered numeric word fragments refuse while intact words, mathematical literals and measured units remain accepted.
        ´claim:design:numeric-word-fragments-refuse´
        ´test:integration:test-numeric-word-fragments´
        """
        path = self.root / 'docs/design/implementation.md'
        path.parent.mkdir(parents=True)
        path.write_text('two-map four-Actor twenty-four one half x = 1 wall 2 256-byte 2000000-Work 2\N{NARROW NO-BREAK SPACE}000\N{NARROW NO-BREAK SPACE}000-Work\n')
        git(self.root, 'add', 'docs/design/implementation.md')
        self.assertEqual(self.check().returncode, 0)
        for fragment in ('twenty-4', '1-map', '2-map', '4-Actor', '5-Actor', '0-capable',
                         '1 half', '1 quarter', 'N/N-minus-1', 'precision-4', '1-Work',
                         '8-unit', '2-endpoint', '2-proposal', '0-width', '1-minute', 'wall-2', 'x= 1', '1-half', '3-source', '1-hop', '0-mass', '3-marker'):
            path.write_text(fragment + '\n')
            result = self.check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('numeric word fragment', result.stderr)
        path.write_text('precision-four one-Work eight-unit two-endpoint two-proposal zero-width one-minute\n')
        readme = self.root / 'packages/epoch/README.md'
        readme.parent.mkdir(parents=True)
        readme.write_text('twenty-4')
        git(self.root, 'add', 'packages/epoch/README.md')
        self.assertNotEqual(self.check().returncode, 0)
        readme.write_text('twenty-four one-half two-map')
        self.assertEqual(self.check().returncode, 0)
        readme = self.root / 'packages/records/README.md'
        readme.parent.mkdir(parents=True)
        readme.write_text('3-marker')
        git(self.root, 'add', 'packages/records/README.md')
        self.assertNotEqual(self.check().returncode, 0)
        readme.write_text('three-marker')
        self.assertEqual(self.check().returncode, 0)
        template = self.root / 'docs/templates/fixture.md.j2'
        template.parent.mkdir(parents=True)
        template.write_text('{{ "1\N{NARROW NO-BREAK SPACE}024" }} {{ "}}\N{NARROW NO-BREAK SPACE}" }}\n')
        git(self.root, 'add', 'docs/templates/fixture.md.j2')
        self.assertEqual(self.check().returncode, 0)
        for source in ('1\N{NARROW NO-BREAK SPACE}024', '{{ "safe" }}1\N{NARROW NO-BREAK SPACE}024',
                       '{# 1\N{NARROW NO-BREAK SPACE}024 #}', '{% set number = "1\N{NARROW NO-BREAK SPACE}024" %}'):
            template.write_text(source + '\n')
            result = self.check()
            self.assertNotEqual(result.returncode, 0, source)
            self.assertIn('literal U+202F', result.stderr)

    def test_rendered_spacing(self):
        """First-party rendered Markdown accepts one blank line, refuses empty or whitespace-only repeated blanks outside the cleanup list, excludes vendor text, and refuses a stale cleanup exception.
        ´claim:design:rendered-spacing-refuses-new-or-stale-debt´
        ´test:integration:test-rendered-spacing´
        """
        path = self.root / 'packages/epoch/README.md'
        path.parent.mkdir(parents=True)
        git(self.root, 'add', '.')
        for source, accepted in [('a\n\nb\n', True), ('a\n\n\nb\n', False),
                                 ('a\n \n\t\nb\n', False), ('a\nb\n', True)]:
            path.write_text(source)
            git(self.root, 'add', 'packages/epoch/README.md')
            result = self.check()
            self.assertEqual(result.returncode == 0, accepted, result.stderr)
            if not accepted:
                self.assertIn('packages/epoch/README.md: repeated blank lines', result.stderr)
        vendor = self.root / 'vendor/example/README.md'
        vendor.parent.mkdir(parents=True)
        vendor.write_text('a\n\n\nb\n')
        git(self.root, 'add', 'vendor/example/README.md')
        self.assertEqual(self.check().returncode, 0)
        pending = self.root / 'README.md'
        pending.write_text('a\n\n\nb\n')
        git(self.root, 'add', 'README.md')
        self.assertEqual(self.check().returncode, 0)
        with patch('pathlib.Path.read_text', return_value='a\n\nb\n'):
            with self.assertRaisesRegex(ValueError, 'remove resolved rendered-spacing exception'):
                check_rendered_spacing([Path('README.md')], pending={'README.md'})

    def test_release_tags(self):
        """Release identities are pinned, and tracked UTF-8 text without NUL bytes refuses other paper editions regardless of case; only the two named source fixtures are exempt.
        ´claim:design:release-identities-are-pinned´
        ´test:integration:test-release-tags´
        """
        path = self.root / 'docs/datasets/org.peer-network.design.publication.json'
        original = path.read_text()
        for name in ('paper', 'questions'):
            with self.subTest(name=name):
                dataset = json.loads(original)
                next(row for row in dataset['rows'] if row['name'] == name)['tag'] = 'network-v0.25.2'
                path.write_text(json.dumps(dataset))
                result = self.check()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'{name}: paper release tag changed', result.stderr)
        path.write_text(original)
        for name in ('README.md', 'docs/templates/example.md.j2', 'example.rs', 'example.json'):
            prose = self.root / name
            prose.parent.mkdir(parents=True, exist_ok=True)
            prose.write_text('Network-v0.30.1\n')
            git(self.root, 'add', name)
            result = self.check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f'{name}:1: stale paper edition Network-v0.30.1', result.stderr)
            prose.write_text(PAPER_TAG.upper() + '\n')
            result = self.check()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('refused=0', result.stdout)
        self.assertEqual(PAPER_EDITION_FIXTURES, {'ci/test_design.py', 'packages/documents/tests/integration.rs'})
        for count, name in enumerate(sorted(PAPER_EDITION_FIXTURES), 1):
            fixture = self.root / name
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_text('Network-v0.30.1\n')
            git(self.root, 'add', name)
            result = self.check()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f'exempt={count} refused=0', result.stdout)
            probe = self.root / 'not-allow-listed.txt'
            probe.write_bytes(fixture.read_bytes())
            git(self.root, 'add', probe.name)
            result = self.check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('not-allow-listed.txt:1: stale paper edition Network-v0.30.1', result.stderr)
            probe.write_text(PAPER_TAG + '\n')
        for name, content in [('nul.bin', b'Network-v0.30.1\0'), ('non-utf8.bin', b'Network-v0.30.1\xff')]:
            (self.root / name).write_bytes(content)
            git(self.root, 'add', name)
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('binary=2 exempt=2 refused=0', result.stdout)

    def test_release_projections(self):
        """Release fields remain pinned, and only structural inventory rows may retain placeholders.
        ´claim:design:release-fields-cannot-drift´
        ´test:integration:test-release-projections´
        """
        baseline = self.check()
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertIn('INVENTORY-PLACEHOLDERS rows=1676 structural=132 refused=0', baseline.stdout)
        path = self.root / 'docs/datasets/org.peer-network.design.inventory.json'
        original = path.read_text()
        dataset = json.loads(original)
        labels = []
        for kind in ('cond', 'case', 'prop'):
            row = next(row for row in dataset['rows'] if row['label'].startswith(kind + ':'))
            row['statement'] = f'Track the witness as a separately addressable {row["environment"]}.'
            labels.append(row['label'])
        path.write_text(json.dumps(dataset))
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('INVENTORY-PLACEHOLDERS rows=1676 structural=132 refused=3', result.stdout)
        self.assertIn('obligation-bearing inventory placeholders:', result.stderr)
        for label in labels:
            self.assertIn(label, result.stderr)
        path.write_text(original)
        for name, marker, field in [('inventory', 'current_at', 'label'), ('constants', 'refreshed_at', 'cites'), ('constants', 'refreshed_at', 'class'), ('constants', 'refreshed_at', 'home'), ('questions', 'status', 'status'), ('questions', 'status', 'section'), ('questions', 'status', 'ambiguity')]:
            with self.subTest(name=name, field=field):
                path = self.root / f'docs/datasets/org.peer-network.design.{name}.json'
                original = path.read_text()
                dataset = json.loads(original)
                next(row for row in dataset['rows'] if marker in row)[field] += ' changed'
                path.write_text(json.dumps(dataset))
                result = self.check()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'{name}: release projection changed', result.stderr)
                path.write_text(original)

    def test_pinned_decisions_under_optimization(self):
        """optimized Python still rejects changed crate responsibilities and bite order through their pins.
        ´claim:design:optimized-validation-keeps-pins´
        ´test:integration:test-pinned-decisions-under-optimization´
        """
        for name, field in [('crates', 'responsibility'), ('bites', 'slice')]:
            with self.subTest(name=name):
                path = self.root / f'docs/datasets/org.peer-network.design.{name}.json'
                original = path.read_text()
                dataset = json.loads(original)
                dataset['rows'][0][field] += ' changed'
                path.write_text(json.dumps(dataset))
                result = self.check()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'{name}: source projection changed', result.stderr)
                path.write_text(original)

    def test_tracked_prose_boundaries(self):
        """tracked first-party documents and templates refuse bare paper labels while vendored members remain excluded.
        ´claim:design:paper-mints-stay-exhibited´
        ´test:integration:test-tracked-prose-boundaries´
        """
        vendor = self.root / 'vendor/example/README.md'
        vendor.parent.mkdir(parents=True)
        vendor.write_text('`def:comparator:burn-interface`\n')
        git(self.root, 'add', 'vendor/example/README.md')
        baseline = self.check()
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        for name in ['README.md', 'docs/templates/other.md.j2']:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('`def:comparator:burn-interface`\n')
            git(self.root, 'add', name)
            result = self.check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f'{name}: bare paper mint', result.stderr)
            path.write_text('``def:comparator:burn-interface``\n')
            result = self.check()
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
