"""Regression witnesses for first-party source discipline checks.

Claim-area register: hash-citations protects public provenance accounting without
forcing prose writers to avoid ordinary words. A failed claim in this area means
either an identity can escape accounting or ordinary text can fail the gate.
New hash-reader sites use the gloss, authored claim, test-inventory order of
record 017. Python is outside the registered linter scanners (record 001);
the local inventory uses area discipline and the function name with underscores
hyphenated. The suite checks this form without claiming linter profile coverage.
"""

from pathlib import Path
import unittest
import tomllib
import os
import copy
import subprocess
import sys
import tempfile
import time
import json
from unittest.mock import patch

from discipline import cargo_config_findings, inherits_lints, main, run_clippy, source_findings, test_sources, validate_build_policy, validate_toolchain
from clippy_fixture import crate
from hash_citations import audit, establish, occurrences


class WorkspaceChecks(unittest.TestCase):
    # Claim: feature-minimal and documentation checks include a new binary-only member, exclude the engine and ignore nonmembers.
    def test_discovered_members(self):
        metadata = {"workspace_members": ["engine", "new", "existing"], "packages": [
            {"id": "engine", "name": "regexml"},
            {"id": "new", "name": "new-tool", "targets": [{"kind": ["bin"]}]},
            {"id": "existing", "name": "documents"},
            {"id": "external", "name": "external"},
        ]}
        for mode, subcommand, flag in [("minimal", "check", "--no-default-features"), ("rustdoc", "doc", "--no-deps")]:
            with self.subTest(mode=mode), patch("sys.argv", ["discipline.py", mode]), patch("discipline.subprocess.run") as run:
                run.side_effect = [subprocess.CompletedProcess([], 0, json.dumps(metadata)), subprocess.CompletedProcess([], 7)]
                self.assertEqual(main(), 7)
                self.assertEqual(run.call_args_list[0].args[0], ["cargo", "metadata", "--no-deps", "--format-version=1", "--locked"])
                self.assertEqual(run.call_args_list[1].args[0], ["cargo", subcommand, "-p", "documents", "-p", "new-tool", flag, "--locked"])


class HashCitations(unittest.TestCase):
    # Claim: imported literal families distinguish replay and encoding data from identity claims.
    def test_interchange_literal_boundaries(self):
        root = Path.cwd()
        def reader(name):
            return establish(root, {"reader": name, "establishment": "defined"})
        seed = "f" * 64
        self.assertTrue(reader("proptest-seed")(seed, "cc " + seed + " # shrinks to text"))
        self.assertFalse(reader("proptest-seed")(seed, "digest = " + seed))
        encoded = "a2" + "00" * 20
        self.assertTrue(reader("cbor-vectors")(encoded, '"hex": "' + encoded + '"'))
        self.assertFalse(reader("cbor-vectors")(encoded, '"digest": "' + encoded + '"'))
        self.assertFalse(reader("regexp-subject")(seed, seed))
        self.assertFalse(reader("regexp-subject")("f" * 40, "f" * 40))
        self.assertTrue(reader("regexp-subject")("a" * 8, 'subject = "' + "a" * 8 + '"'))
        self.assertFalse(reader("interchange-literal")(seed, seed))

    # Claim: a provenance family requires the exact declared public Git commit locator.
    def test_public_git_locator(self):
        commit = "f" * 40
        rule = {"reader": "public-git", "establishment": "resolvable", "commit": commit,
                "locator": "https://github.com/example/engine/commit/" + commit}
        check = establish(Path.cwd(), rule)
        self.assertTrue(check(commit, commit))
        self.assertFalse(check("e" * 40, "e" * 40))
        rule["locator"] = "file:///private/" + commit
        with self.assertRaises(ValueError):
            establish(Path.cwd(), rule)

    def table(self):
        return {
            "namespace": "org.peer-network.ci.hash-citations",
            "version": [1, 0, 0],
            "rows": [{"family": "bytes", "group": "first-party", "measures": "literal byte value",
                      "producer": "None; authored numeric input", "establishment": "defined", "reader": "byte",
                      "definition": "ASCII control, euro-sign UTF-8, excluded UTF-8 byte or visible payload pattern.", "paths": ["sample.rs"]}],
        }

    def test_hex_boundary(self):
        """Explicit literals and version tokens remain visible without classifying ordinary quantities as identities.
        ´claim:hash-citations:literal-and-version-boundaries´
        ´test:discipline:test-hex-boundary´
        """
        text = r"0xff 0xe2_u8 \x1f \u{fffd} %x30-39 abcdef (123456 date) 123456 20261021"
        self.assertEqual([match.group() for match in occurrences(text)], [r"0xff", "0xe2_u8", r"\x1f", r"\u{fffd}", "%x30-39", "123456"])

    def test_hex_words(self):
        """Hex-letter English words remain prose, so the reader does not dictate vocabulary.
        ´claim:hash-citations:ordinary-words-are-not-identities´
        ´test:discipline:test-hex-words´
        """
        for text in ["facade", "deadbeef-free prose", "accede", "decade", "effaced", "bead", "cafe",
                     "FACADE", "a facade beside an effaced wall", "prefix_abcdef", "abcdef_suffix"]:
            with self.subTest(text=text):
                self.assertEqual(occurrences(text), [])

    def test_hex_identity_context(self):
        """Short identity fields and dated tool-version tokens remain accounted even when their digits are all letters.
        ´claim:hash-citations:identity-context-retains-short-values´
        ´test:discipline:test-hex-identity-context´
        """
        word = "ab" + "cdef"
        for text in ["commit " + word, "COMMIT: `" + word + "`", 'digest = "' + word + '"',
                     "checksum: " + word, "SHA-256 " + word, "sha1=" + word, "sha512=" + word,
                     "https://example.test/commit/" + word, "rustc nightly (" + word + " 2026-10-22)"]:
            with self.subTest(text=text):
                self.assertEqual([m.group() for m in occurrences(text)], [word])
        digits = "12" + "3456"
        self.assertEqual([m.group() for m in occurrences("commit " + digits)], [digits])
        self.assertEqual(occurrences(digits), [])
        self.assertEqual([m.group() for m in occurrences("commit " + word + "\nfacade")], [word])

    def test_hex_additional_identity_context(self):
        """Each additional identity keyword retains short values, so common provenance fields cannot evade accounting.
        ´claim:hash-citations:additional-context-retains-short-values´
        ´test:discipline:test-hex-additional-identity-context´
        """
        word = "ab" + "cdef"
        for context in ["hash", "rev", "revision", "tree", "object"]:
            with self.subTest(context=context):
                for spelling in [context, context.upper()]:
                    self.assertEqual([m.group() for m in occurrences(spelling + ' = "' + word + '"')], [word])
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "sample.rs").write_text("0xff\n" + context + " " + word + "\n")
                    findings, count = audit(root, ["sample.rs"], self.table())
                    self.assertEqual(count, 2)
                    self.assertTrue(any("unaccounted hexadecimal value " + word in f for f in findings))

    def test_hex_context_word_and_line_boundaries(self):
        """Context words alone, short prose words and keywords on other lines do not turn ordinary prose into identities.
        ´claim:hash-citations:context-respects-word-and-line-boundaries´
        ´test:discipline:test-hex-context-word-and-line-boundaries´
        """
        for text in ["The hash map stores the cafe menu.", "The rev counter sits beside a bead.",
                     "The revision describes a cafe.", "A tree shades the cafe.", "The object is a bead."]:
            with self.subTest(text=text):
                self.assertEqual(occurrences(text), [])
                self.assertEqual(occurrences(text + "\nAn effaced facade stands nearby."), [])
        for text in ["hashes", "revving", "revisionist", "treehouse", "objects"]:
            with self.subTest(text=text):
                self.assertEqual(occurrences(text + " beside an effaced facade"), [])

    def test_hex_full_identifiers(self):
        """Full identifiers and mixed short values remain visible without contextual keywords, preserving provenance checks.
        ´claim:hash-citations:full-and-mixed-identifiers-remain-visible´
        ´test:discipline:test-hex-full-identifiers´
        """
        values = ["a" * 40, "F" * 64, "1" * 40, "2" * 64, "a" * 39 + "1", "a" * 41,
                  "abc123", "abc" + "12a", "1" + "abcde"]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual([m.group() for m in occurrences(value)], [value])
        self.assertEqual(occurrences("a" * 39), [])
        self.assertEqual(occurrences("9" * 39), [])

    def test_hex_context_accounting(self):
        """Recognition never authorizes an identity: unaccounted short, full and pathname values still fail the audit.
        ´claim:hash-citations:recognized-identities-still-need-evidence´
        ´test:discipline:test-hex-context-accounting´
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.rs"
            sample.write_text("0xff\nfacade accede decade effaced bead cafe\n")
            self.assertEqual(audit(root, ["sample.rs"], self.table()), ([], 1))
            for value in ["ab" + "cdef", "abc123", "a" * 40, "f" * 64]:
                sample.write_text("0xff\ncommit " + value + "\n")
                findings, count = audit(root, ["sample.rs"], self.table())
                self.assertEqual(count, 2)
                self.assertTrue(any("unaccounted hexadecimal value " + value in f for f in findings))
            name = "abc123.txt"
            (root / name).write_text("")
            findings, _ = audit(root, [name], self.table())
            self.assertTrue(any("pathname" in f for f in findings))

    def test_hex_claim_sites(self):
        """Hash-reader claim sites carry a checkable gloss, one authored claim and the local inventory label in order.
        ´claim:hash-citations:probe-documentation-has-ordered-claims´
        ´test:discipline:test-hex-claim-sites´
        """
        names = [name for name in vars(type(self)) if name.startswith("test_hex_")]
        claims = set()
        for name in names:
            lines = [line.strip() for line in getattr(type(self), name).__doc__.strip().splitlines()]
            self.assertEqual(len(lines), 3)
            self.assertTrue(lines[0].endswith("."))
            self.assertTrue(lines[1].startswith("´claim:hash-citations:"))
            self.assertTrue(lines[1].endswith("´"))
            self.assertNotIn(lines[1], claims)
            claims.add(lines[1])
            self.assertEqual(lines[2], "´test:discipline:" + name.replace("_", "-") + "´")

    # Claim: an uncovered value, a stale family and a reader establishment the checker cannot validate each fail the audit.
    def test_hash_accounting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.rs"
            sample.write_text("0xff\n")
            self.assertEqual(audit(root, ["sample.rs"], self.table()), ([], 1))
            cbor = copy.deepcopy(self.table())
            cbor["rows"][0]["reader"] = "cbor-header"
            sample.write_text(format(23, "#x") + "\n")
            self.assertEqual(audit(root, ["sample.rs"], cbor), ([], 1))
            sample.write_text(format(28, "#x") + "\n")
            findings, _ = audit(root, ["sample.rs"], cbor)
            self.assertTrue(any("unaccounted" in finding for finding in findings))
            sample.write_text("0x" + "ab" + "\n")
            findings, _ = audit(root, ["sample.rs"], self.table())
            self.assertTrue(any("unaccounted" in finding for finding in findings))
            sample.write_text("f" * 64 + "\n")
            findings, count = audit(root, ["sample.rs"], self.table())
            self.assertEqual(count, 1)
            self.assertTrue(any("unaccounted" in finding for finding in findings))
            self.assertTrue(any("describes no tracked value" in finding for finding in findings))
            for field, value in [("reader", "uncheckable"), ("establishment", "none"), ("producer", "")]:
                table = copy.deepcopy(self.table())
                table["rows"][0][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    audit(root, ["sample.rs"], table)

    # Claim: the complete tracked set includes binary content and hexadecimal pathnames, with read failures surfaced.
    def test_hash_carrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.rs").write_bytes(b"\x00" + b"f" * 64)
            findings, _ = audit(root, ["sample.rs"], self.table())
            self.assertTrue(any("unaccounted" in finding for finding in findings))
            name = "f" * 40 + ".txt"
            (root / name).write_text("")
            findings, _ = audit(root, [name], self.table())
            self.assertTrue(any("pathname" in finding for finding in findings))
            with self.assertRaises(ValueError):
                audit(root, ["absent.rs"], self.table())

    # Claim: every CLI audit discovers Git's tracked set anew; an untracked hexadecimal value enters the verdict only after staging.
    def test_hash_tracked_cli(self):
        script = Path(__file__).with_name("discipline.py").resolve()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci").mkdir()
            (root / "sample.rs").write_text("0xff\n")
            (root / "ci/hash-citation-families.toml").write_text('namespace = "org.peer-network.ci.hash-citations"\nversion = [1,0,0]\n[[rows]]\nfamily="bytes"\ngroup="first-party"\nmeasures="byte"\nproducer="None; authored input"\nestablishment="defined"\nreader="byte"\ndefinition="Explicit integer byte."\npaths=["sample.rs"]\n')
            for arguments in [["init", "--quiet"], ["add", "."]]:
                started = time.monotonic()
                subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True)
                print(f"hash fixture git {arguments[0]} wall={time.monotonic()-started:.6f}s")
            (root / "unknown.txt").write_text("f" * 64)
            command = [sys.executable, "-B", str(script), "hash-citations"]
            result = subprocess.run(command, cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            started = time.monotonic()
            subprocess.run(["git", "add", "unknown.txt"], cwd=root, check=True, capture_output=True)
            print(f"hash fixture git add wall={time.monotonic()-started:.6f}s")
            result = subprocess.run(command, cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("unknown.txt:1: unaccounted", result.stdout)


class SourceDiscipline(unittest.TestCase):
    # Claim: minimum compiler claims, profile drift and stale policy data each fail the build policy.
    def test_build_policy(self):
        manifest = '[workspace]\nmembers=["packages/example"]\n[workspace.package]\n[profile.release]\nlto="thin"\ncodegen-units=1\n'
        member = '[package]\nname="example"\n'
        policy = Path('docs/inputs/build-policy.toml').read_text()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'packages/example').mkdir(parents=True)
            (root / 'docs/inputs').mkdir(parents=True)
            (root / 'Cargo.toml').write_text(manifest)
            (root / 'packages/example/Cargo.toml').write_text(member)
            (root / 'docs/inputs/build-policy.toml').write_text(policy)
            validate_build_policy(root)
            for changed in [manifest.replace('"thin"', '"fat"'), manifest.replace('units=1', 'units=2'),
                            manifest + '[profile.dev]\nopt-level=1\n', manifest + '[profile.test]\nopt-level=1\n',
                            manifest.replace('[workspace.package]', '[workspace.package]\nrust-version="1.90"')]:
                (root / 'Cargo.toml').write_text(changed)
                with self.assertRaises(ValueError):
                    validate_build_policy(root)
            (root / 'Cargo.toml').write_text(manifest)
            (root / 'packages/example/Cargo.toml').write_text(member + 'rust-version.workspace=true\n')
            with self.assertRaises(ValueError):
                validate_build_policy(root)
            (root / 'packages/example/Cargo.toml').write_text(member)
            (root / 'docs/inputs/build-policy.toml').write_text(policy.replace('"nightly"', '"stable"'))
            with self.assertRaises(ValueError):
                validate_build_policy(root)

    # Claim: controlled stream boundaries admit only their named operation; printing and unrelated items still refuse.
    def test_controlled_stream_boundaries(self):
        path = Path('packages/cli-common/src/lib.rs')
        self.assertFalse(source_findings(path, 'pub fn emit() { io::stdout(); }', 'printing'))
        self.assertTrue(source_findings(path, 'pub fn other() { io::stdout(); }', 'printing'))
        self.assertTrue(source_findings(path, 'pub fn emit() { println!("x"); }', 'printing'))
        self.assertTrue(source_findings(path, 'pub fn emit() { std::process::exit(1); }', 'printing'))
        self.assertTrue(source_findings(Path('src/lib.rs'), 'pub fn emit() { io::stdout(); }', 'printing'))

    # Claim: direct calls, imported aliases and inactive printing all refuse.
    def test_printing(self):
        for source in [
            'fn main() { process::exit(3); }',
            'use std::process::exit; fn main() { exit(3); }',
            'use std::{process::exit as stop}; fn main() { stop(3); }',
            'use std::io::{stdout as output};',
            'fn f() { std::io::Write::write_all(&mut std::io::stdout(), b"x"); }',
            'fn f() { io::stderr(); }',
            '#[cfg(any())] fn f() { print!("x"); eprint!("x"); dbg!(1); }',
        ]:
            with self.subTest(source=source):
                self.assertTrue(source_findings(Path('src/lib.rs'), source, 'printing'))

    # Claim: inner, conditional and inline-test suppressions refuse, including nesting.
    def test_suppressions(self):
        for source in [
            '#![cfg_attr(all(), allow(clippy::pedantic))]',
            '# ! [ cfg_attr(all(), allow(clippy::pedantic)) ]',
            '#[cfg_attr(test, allow(clippy::float_cmp))] fn f() {}',
            '#[cfg_attr(all(), cfg_attr(all(), allow(clippy::float_cmp)))] fn f() {}',
            '#[cfg(test)] mod tests { // Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn f() {} }',
            '#[test]\n// Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn f() {}',
            '// Justified: Exact values are required.\n#![allow(clippy::float_cmp)] fn f() {}',
        ]:
            with self.subTest(source=source):
                self.assertTrue(source_findings(Path('src/lib.rs'), source, 'suppressions'))
        source = '// Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn f() {}'
        self.assertFalse(source_findings(Path('src/lib.rs'), source, 'suppressions'))
        self.assertTrue(source_findings(Path('tests/probe.rs'), source, 'suppressions'))

    # Claim: examples in comments and literals are not executable source.
    def test_literals(self):
        source = '/* outer /* nested */ print!("x"); */ const X: &str = r###"exit(1)"###;'
        self.assertFalse(source_findings(Path('src/lib.rs'), source, 'printing'))

    # Claim: missing inheritance and any member-local lint table fail the manifest rule.
    def test_member_lints(self):
        self.assertTrue(inherits_lints(tomllib.loads('[lints]\nworkspace = true\n')))
        for source in ['', '[lints]\nworkspace = false\n', '[lints]\nworkspace = true\n[lints.rust]\nunused = "allow"\n']:
            self.assertFalse(inherits_lints(tomllib.loads(source)))

    # Claim: out-of-line test modules and their descendants are suppression-free test trees.
    def test_external_test_modules(self):
        sources = {
            Path('src/lib.rs'): '#[cfg(test)] mod checks;',
            Path('src/checks.rs'): 'mod nested;\n// Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn exact() {}',
            Path('src/checks/nested.rs'): '// Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn exact() {}',
        }
        marked = test_sources(sources)
        self.assertEqual(marked, {Path('src/checks.rs'), Path('src/checks/nested.rs')})
        for path in marked:
            self.assertTrue(source_findings(path, sources[path], 'suppressions', path in marked))

    # Claim: any test-configured item, including impls and constants, rejects suppressions.
    def test_other_test_items(self):
        for source in [
            '#[cfg(test)] impl Thing { // Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn exact() {} }',
            '#[cfg(test)] // Justified: Exact values are required.\n#[allow(clippy::float_cmp)] const VALUE: bool = true;',
            '#![cfg(test)] // Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn exact() {}',
        ]:
            self.assertTrue(source_findings(Path('src/lib.rs'), source, 'suppressions'))

    # Claim: tracked Cargo settings cannot supply rustflags or lint-level command flags.
    def test_cargo_config(self):
        for source in [
            '[build]\nrustflags = ["-A", "clippy::pedantic"]',
            '[target.example]\nrustflags = []',
            '[alias]\ncheck = "clippy -- -D warnings"',
            '[env]\nCARGO_ENCODED_RUSTFLAGS = "--cap-lints=allow"',
        ]:
            self.assertTrue(cargo_config_findings(tomllib.loads(source)))
        self.assertFalse(cargo_config_findings(tomllib.loads('[build]\njobs = 2')))

    # Claim: only undated nightly with both answering components satisfies the policy.
    def test_toolchain_versions(self):
        versions = ['rustc 1.101.0-nightly (abcdef 2026-10-16)', 'cargo 1.101.0-nightly', 'clippy 0.1.101', 'rustfmt 1.9.0-nightly']
        validate_toolchain('nightly', versions, ['rustfmt', 'clippy'])
        for channel in ['nightly-2026-10-16', 'stable', '1.99.1']:
            with self.assertRaises(ValueError):
                validate_toolchain(channel, versions, ['rustfmt', 'clippy'])
        for components in [[], ['rustfmt'], ['clippy']]:
            with self.assertRaises(ValueError):
                validate_toolchain('nightly', versions, components)
        for index in range(4):
            missing = versions.copy()
            missing[index] = ''
            with self.assertRaises(ValueError):
                validate_toolchain('nightly', missing, ['rustfmt', 'clippy'])
        with self.assertRaises(ValueError):
            validate_toolchain('nightly', ['rustc 1.99.1', *versions[1:]], ['rustfmt', 'clippy'])

    # Claim: the real advisory invocation emits and counts a known nursery warning despite warnings-deny in the manifest.
    @unittest.skipUnless(os.environ.get('FOUNDATION_COMPUTE_TESTS') == '1', 'compute-node compiler witness')
    def test_nursery_warning(self):
        with crate('foundation-nursery-probe', 'pub fn candidate(value: u32) -> u32 { value + 1 }\n', '[lints.rust]\nwarnings = "deny"\n[lints.clippy]\nnursery = "allow"\n') as root:
            result, count = run_clippy(root, advisory=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreaterEqual(count, 1)
            self.assertIn('clippy::missing_const_for_fn', result.stdout)
            print(f'NURSERY-WITNESS-FINDINGS={count}')


if __name__ == '__main__':
    unittest.main()
