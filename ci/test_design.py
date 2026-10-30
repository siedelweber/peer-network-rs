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

from design import PAPER_EDITION_FIXTURES, PAPER_TAG, bare_mint_pattern, validate


REPOSITORY = Path(__file__).resolve().parent.parent


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
        (self.root / '.linter').mkdir()
        shutil.copy(REPOSITORY / '.linter/owners.toml', self.root / '.linter/owners.toml')
        shutil.copy(REPOSITORY / '.linter/environments.toml', self.root / '.linter/environments.toml')
        (self.root / 'Cargo.toml').write_text('[workspace]\nmembers = ["vendor/example"]\n')
        git(self.root, 'init', '--quiet')

    def check(self):
        return subprocess.run([sys.executable, '-B', '-O', str(REPOSITORY / 'ci/design.py')], cwd=self.root, capture_output=True, text=True)

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
