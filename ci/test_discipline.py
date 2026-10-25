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
    def test_secret_carrier_traits(self):
        """Secret-owned strings and bytes reject Display and serde serialization while their Debug-only control compiles, preventing accidental output opt-in.
        ´claim:discipline:secret-carriers-reject-printable-traits´
        ´test:integration:test-secret-carrier-traits´
        """
        if os.environ.get('FOUNDATION_COMPUTE_TESTS') != '1':
            self.skipTest('requires the provisioned compute toolchain')
        root = Path.cwd()
        with tempfile.TemporaryDirectory(prefix='secret-traits-', dir=os.environ['TMPDIR']) as directory:
            fixture = Path(directory)
            (fixture/'src').mkdir()
            (fixture/'Cargo.toml').write_text('[package]\nname="secret-trait-probe"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\ncli-common={path='+json.dumps(str(root/'packages/cli-common'))+'}\nserde_json="1"\n[profile.gate]\ninherits="dev"\nopt-level=1\ndebug=0\n')
            constructors = [
                'SecretString::from("private-sentinel")',
                'SecretBox::<[u8]>::new(vec![1,2,3].into_boxed_slice())',
                'PrivateString::new(SecretRole::Authentication,SecretString::from("private-sentinel"))',
                'PrivateBytes::new(SecretRole::Connection,SecretBox::new(vec![1,2,3].into_boxed_slice()))',
            ]
            for constructor in constructors:
                for expression, expected in [('format!("{:?}", value)',None),('format!("{}", value)','Display'),('serde_json::to_string(&value)','Serialize')]:
                    (fixture/'src/main.rs').write_text('use cli_common::secrets::*; fn main(){let value='+constructor+'; let _result='+expression+';}')
                    result=subprocess.run(['cargo','check','--offline','--profile','gate','--manifest-path',str(fixture/'Cargo.toml')],capture_output=True,text=True)
                    if expected is None: self.assertEqual(result.returncode,0,result.stderr)
                    else:
                        self.assertNotEqual(result.returncode,0)
                        self.assertIn(expected,result.stderr)

    def test_discovered_members(self):
        """feature-minimal and documentation checks include a new binary-only member, exclude the engine and ignore nonmembers.
        ´claim:discipline:new-members-receive-feature-checks´
        ´test:integration:test-discovered-members´
        """
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
                self.assertEqual(run.call_args_list[1].args[0], ["cargo", subcommand, "-p", "documents", "-p", "new-tool", flag, "--locked", "--profile", "gate"])


class HashCitations(unittest.TestCase):
    def test_artifact_vector(self):
        """The artifact address family recomputes its declared payload, refusing a substituted digest, changed payload or unknown recipe rather than accepting any identity-shaped literal.
        ´claim:hashcitations:artifact-vector-binds-its-payload´
        ´test:integration:test-artifact-vector´
        """
        source = Path('packages/cli-common/src/observation/artifact-digest-v1.json')
        vector = json.loads(source.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'vector.json'
            rule = dict(reader='artifact-vector', establishment='recomputable', source='vector.json')
            path.write_text(json.dumps(vector))
            check = establish(root, rule)
            self.assertTrue(check(vector['digest'], ''))
            self.assertFalse(check('f'*64, ''))
            for field, value in [('digest', 'f'*64), ('payload', 'y'), ('recipe', 'unknown')]:
                changed = dict(vector)
                changed[field] = value
                path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, 'artifact vector'):
                    establish(root, rule)

    def test_interchange_literal_boundaries(self):
        """imported literal families distinguish replay and encoding data from identity claims.
        ´claim:discipline:literal-warrants-are-bounded´
        ´test:integration:test-interchange-literal-boundaries´
        """
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
        alphabet = ''.join(format(digit, 'x') for digit in range(16))
        self.assertTrue(reader("hex-alphabet")(alphabet, 'DIGITS = "' + alphabet + '"'))
        self.assertFalse(reader("hex-alphabet")(alphabet[:-1], alphabet[:-1]))
        self.assertFalse(reader("hex-alphabet")(alphabet[::-1], alphabet[::-1]))
        self.assertFalse(reader("hex-alphabet")(alphabet, 'digest = "' + alphabet + '"'))

    def test_public_git_locator(self):
        """a provenance family requires the exact declared public Git commit locator.
        ´claim:discipline:public-locators-identify-objects´
        ´test:integration:test-public-git-locator´
        """
        commit = "f" * 40
        rule = {"reader": "public-git", "establishment": "resolvable", "commit": commit,
                "locator": "https://github.com/example/engine/commit/" + commit}
        check = establish(Path.cwd(), rule)
        self.assertTrue(check(commit, commit))
        self.assertFalse(check("e" * 40, "e" * 40))
        rule["locator"] = "file:///private/" + commit
        with self.assertRaises(ValueError):
            establish(Path.cwd(), rule)

        # The repository-history family uses real commits, including a present
        # object outside HEAD ancestry; no private review reference is needed.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*arguments):
                started = time.monotonic()
                result = subprocess.run(["git", "-c", "commit.gpgsign=false", *arguments], cwd=root,
                                        check=True, capture_output=True, text=True)
                print(f"hash fixture git {arguments[0]} wall={time.monotonic()-started:.6f}s")
                return result.stdout.strip()
            git("init")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("commit", "--allow-empty", "-m", "Initial fixture")
            ancestor = git("rev-parse", "HEAD")
            git("commit", "--allow-empty", "-m", "Detached admission witness")
            unreachable = git("rev-parse", "HEAD")
            git("reset", "--hard", ancestor)
            rule = {"reader": "ancestor-commit", "establishment": "resolvable", "commit": ancestor}
            check = establish(root, rule)
            self.assertTrue(check(ancestor, ancestor))
            self.assertFalse(check(unreachable, unreachable))
            rule["commit"] = unreachable
            with self.assertRaisesRegex(ValueError, "not reachable from HEAD"):
                establish(root, rule)
            rule["commit"] = ancestor[:7]
            with self.assertRaisesRegex(ValueError, "full commit identity"):
                establish(root, rule)
            tree = git("rev-parse", ancestor + "^{tree}")
            imported = dict(reader="imported-commit", establishment="resolvable", commit=ancestor, tree=tree)
            check = establish(root, imported)
            self.assertTrue(check(ancestor, ancestor))
            self.assertTrue(check(tree, tree))
            self.assertFalse(check(unreachable, unreachable))
            self.assertFalse(check("f" * 40, ""))
            with self.assertRaisesRegex(ValueError, "not reachable from HEAD"):
                establish(root, dict(imported, commit=unreachable))
            with self.assertRaisesRegex(ValueError, "full commit identity"):
                establish(root, dict(imported, commit=ancestor[:7]))
            with self.assertRaisesRegex(ValueError, "full tree identity"):
                establish(root, dict(imported, tree=tree[:7]))
            (root / "changed").write_text("different source tree")
            git("add", "changed")
            git("commit", "-m", "Different tree")
            with self.assertRaisesRegex(ValueError, "imported source tree differs"):
                establish(root, dict(imported, tree=git("rev-parse", "HEAD^{tree}")))
            campaign = dict(reader="campaign-tree", establishment="resolvable", tree=tree)
            check = establish(root, campaign)
            self.assertTrue(check(tree, tree))
            self.assertFalse(check(ancestor, ancestor))
            with self.assertRaisesRegex(ValueError, "full tree identity"):
                establish(root, dict(campaign, tree=tree[:7]))
            detached_tree = git("rev-parse", "HEAD^{tree}")
            git("reset", "--hard", ancestor)
            for wrong in [detached_tree, "f" * 40]:
                with self.assertRaisesRegex(ValueError, "not in HEAD history"):
                    establish(root, dict(campaign, tree=wrong))

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
        ´claim:hashcitations:literal-and-version-boundaries´
        ´test:integration:test-hex-boundary´
        """
        text = r"0xff 0xe2_u8 \x1f \u{fffd} %x30-39 abcdef (123456 date) 123456 20261021"
        self.assertEqual([match.group() for match in occurrences(text)], [r"0xff", "0xe2_u8", r"\x1f", r"\u{fffd}", "%x30-39", "123456"])

    def test_hex_words(self):
        """Hex-letter English words remain prose, so the reader does not dictate vocabulary.
        ´claim:hashcitations:ordinary-words-are-not-identities´
        ´test:integration:test-hex-words´
        """
        for text in ["facade", "deadbeef-free prose", "accede", "decade", "effaced", "bead", "cafe",
                     "FACADE", "a facade beside an effaced wall", "prefix_abcdef", "abcdef_suffix"]:
            with self.subTest(text=text):
                self.assertEqual(occurrences(text), [])

    def test_hex_identity_context(self):
        """Short identity fields and dated tool-version tokens remain accounted even when their digits are all letters.
        ´claim:hashcitations:identity-context-retains-short-values´
        ´test:integration:test-hex-identity-context´
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
        ´claim:hashcitations:additional-context-retains-short-values´
        ´test:integration:test-hex-additional-identity-context´
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
        ´claim:hashcitations:context-respects-word-and-line-boundaries´
        ´test:integration:test-hex-context-word-and-line-boundaries´
        """
        for text in ["The hash map stores the facade.", "The rev counter sits beside an effaced facade.",
                     "The revision describes a decade.", "A tree shades the facade.", "The object is effaced."]:
            with self.subTest(text=text):
                self.assertEqual(occurrences(text), [])
                self.assertEqual(occurrences(text + "\nAn effaced facade stands nearby."), [])
        for text in ["hashes", "revving", "revisionist", "treehouse", "objects"]:
            with self.subTest(text=text):
                self.assertEqual(occurrences(text + " beside an effaced facade"), [])

    def test_hex_full_identifiers(self):
        """Full identifiers and mixed short values remain visible without contextual keywords, preserving provenance checks.
        ´claim:hashcitations:full-and-mixed-identifiers-remain-visible´
        ´test:integration:test-hex-full-identifiers´
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
        ´claim:hashcitations:recognized-identities-still-need-evidence´
        ´test:integration:test-hex-context-accounting´
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

        # Evaluation checksums have a public archive locator before admission,
        # but do not authorize unrelated values or malformed locators.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "profile.toml"
            checksum = "a" * 64
            prefix = 'namespace = "org.peer-network.devnet.profile"\n[[rows]]\nname = "testnet-signet"\n'
            candidate = '{ name = "codec", version = "1.2.3", checksum = "' + checksum + '", archive = "https://static.crates.io/crates/codec/codec-1.2.3.crate" }'
            valid = prefix + 'wallet_candidates = [' + candidate + ']\n'
            path.write_text(valid)
            rule = dict(reader="evaluated-crate-archive", establishment="resolvable", source="profile.toml")
            check = establish(root, rule)
            self.assertTrue(check(checksum, checksum))
            self.assertFalse(check("b" * 64, ""))
            for text in [valid.replace("https://static.crates.io", "https://example.invalid"),
                         valid.replace("codec-1.2.3.crate", "codec-1.2.4.crate"),
                         valid.replace(checksum, "a" * 63),
                         prefix + 'wallet_candidates = [' + candidate + ',' + candidate + ']\n',
                         prefix + 'wallet_candidates = []\n']:
                path.write_text(text)
                with self.assertRaisesRegex(ValueError, "evaluated archive"):
                    establish(root, rule)

    def test_hex_claim_sites(self):
        """Hash-reader claim sites carry a checkable gloss, one authored claim and the local inventory label in order.
        ´claim:hashcitations:probe-documentation-has-ordered-claims´
        ´test:integration:test-hex-claim-sites´
        """
        names = [name for name in vars(type(self)) if name.startswith("test_hex_")]
        claims = set()
        for name in names:
            lines = [line.strip() for line in getattr(type(self), name).__doc__.strip().splitlines()]
            self.assertEqual(len(lines), 3)
            self.assertTrue(lines[0].endswith("."))
            self.assertTrue(lines[1].startswith("´claim:hashcitations:"))
            self.assertTrue(lines[1].endswith("´"))
            self.assertNotIn(lines[1], claims)
            claims.add(lines[1])
            self.assertEqual(lines[2], "´test:integration:" + name.replace("_", "-") + "´")

    def test_hash_accounting(self):
        """an uncovered value, a stale family and a reader establishment the checker cannot validate each fail the audit.
        ´claim:discipline:identity-occurrences-need-warrants´
        ´test:integration:test-hash-accounting´
        """
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

    def test_hash_carrier(self):
        """the complete tracked set includes binary content and hexadecimal pathnames, with read failures surfaced.
        ´claim:discipline:identity-warrants-bind-carriers´
        ´test:integration:test-hash-carrier´
        """
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

    def test_hash_tracked_cli(self):
        """every CLI audit discovers Git's tracked set anew; an untracked hexadecimal value enters the verdict only after staging.
        ´claim:discipline:tracked-identities-are-checked´
        ´test:integration:test-hash-tracked-cli´
        """
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
    def test_build_policy(self):
        """Gate profile drift and disabled runtime checks fail structural policy.
        ´claim:devperf:gate-profile-guards´
        ´test:integration:test-build-policy´
        """
        manifest = '[workspace]\nmembers=["packages/example"]\n[workspace.package]\n[profile.release]\nlto="thin"\ncodegen-units=1\n'
        manifest += '[profile.gate]\ninherits="dev"\nopt-level=1\ndebug=0\ndebug-assertions=true\noverflow-checks=true\n'
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
                            manifest.replace('debug-assertions=true', 'debug-assertions=false'),
                            manifest.replace('overflow-checks=true', 'overflow-checks=false'),
                            manifest.replace('opt-level=1', 'opt-level=2'), manifest.replace('debug=0', 'debug=2'),
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
            (root / 'docs/inputs/build-policy.toml').write_text(policy.replace('"nightly-2026-10-16"', '"stable"'))
            with self.assertRaises(ValueError):
                validate_build_policy(root)

    def test_controlled_stream_boundaries(self):
        """controlled stream boundaries admit only their named operation; printing and unrelated items still refuse.
        ´claim:discipline:output-exceptions-stay-local´
        ´test:integration:test-controlled-stream-boundaries´
        """
        path = Path('packages/cli-common/src/lib.rs')
        self.assertFalse(source_findings(path, 'pub fn emit() { io::stdout(); }', 'printing'))
        self.assertTrue(source_findings(path, 'pub fn other() { io::stdout(); }', 'printing'))
        self.assertTrue(source_findings(path, 'pub fn emit() { println!("x"); }', 'printing'))
        self.assertTrue(source_findings(path, 'pub fn emit() { std::process::exit(1); }', 'printing'))
        self.assertTrue(source_findings(Path('src/lib.rs'), 'pub fn emit() { io::stdout(); }', 'printing'))

    def test_printing(self):
        """direct calls, imported aliases and inactive printing all refuse.
        ´claim:discipline:uncontrolled-output-is-refused´
        ´test:integration:test-printing´
        """
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

    def test_suppressions(self):
        """inner, conditional and inline-test suppressions refuse, including nesting.
        ´claim:discipline:test-lints-cannot-be-suppressed´
        ´test:integration:test-suppressions´
        """
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

    def test_literals(self):
        """examples in comments and literals are not executable source.
        ´claim:discipline:comments-and-strings-are-not-code´
        ´test:integration:test-literals´
        """
        source = '/* outer /* nested */ print!("x"); */ const X: &str = r###"exit(1)"###;'
        self.assertFalse(source_findings(Path('src/lib.rs'), source, 'printing'))

    def test_member_lints(self):
        """missing inheritance and any member-local lint table fail the manifest rule.
        ´claim:discipline:members-inherit-workspace-lints´
        ´test:integration:test-member-lints´
        """
        self.assertTrue(inherits_lints(tomllib.loads('[lints]\nworkspace = true\n')))
        for source in ['', '[lints]\nworkspace = false\n', '[lints]\nworkspace = true\n[lints.rust]\nunused = "allow"\n']:
            self.assertFalse(inherits_lints(tomllib.loads(source)))

    def test_external_test_modules(self):
        """out-of-line test modules and their descendants are suppression-free test trees.
        ´claim:discipline:external-test-modules-keep-lints´
        ´test:integration:test-external-test-modules´
        """
        sources = {
            Path('src/lib.rs'): '#[cfg(test)] mod checks;',
            Path('src/checks.rs'): 'mod nested;\n// Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn exact() {}',
            Path('src/checks/nested.rs'): '// Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn exact() {}',
        }
        marked = test_sources(sources)
        self.assertEqual(marked, {Path('src/checks.rs'), Path('src/checks/nested.rs')})
        for path in marked:
            self.assertTrue(source_findings(path, sources[path], 'suppressions', path in marked))

    def test_other_test_items(self):
        """any test-configured item, including impls and constants, rejects suppressions.
        ´claim:discipline:test-implementations-keep-lints´
        ´test:integration:test-other-test-items´
        """
        for source in [
            '#[cfg(test)] impl Thing { // Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn exact() {} }',
            '#[cfg(test)] // Justified: Exact values are required.\n#[allow(clippy::float_cmp)] const VALUE: bool = true;',
            '#![cfg(test)] // Justified: Exact values are required.\n#[allow(clippy::float_cmp)] fn exact() {}',
        ]:
            self.assertTrue(source_findings(Path('src/lib.rs'), source, 'suppressions'))

    def test_cargo_config(self):
        """tracked Cargo settings cannot supply rustflags or lint-level command flags.
        ´claim:discipline:configuration-cannot-relax-lints´
        ´test:integration:test-cargo-config´
        """
        for source in [
            '[build]\nrustflags = ["-A", "clippy::pedantic"]',
            '[target.example]\nrustflags = []',
            '[alias]\ncheck = "clippy -- -D warnings"',
            '[env]\nCARGO_ENCODED_RUSTFLAGS = "--cap-lints=allow"',
        ]:
            self.assertTrue(cargo_config_findings(tomllib.loads(source)))
        self.assertFalse(cargo_config_findings(tomllib.loads('[build]\njobs = 2')))

    def test_toolchain_versions(self):
        """Only the pinned dated nightly answering with the full declared compiler commit and both required components satisfies the compiler policy.
        ´claim:discipline:toolchain-family-is-consistent´
        ´test:integration:test-toolchain-versions´
        """
        expected = tomllib.loads(Path('docs/inputs/build-policy.toml').read_text())['rows'][0]['rustc_commit']
        versions = [f'rustc 1.101.0-nightly ({expected[:9]} 2026-10-15)\ncommit-hash: {expected}', 'cargo 1.101.0-nightly', 'clippy 0.1.101', 'rustfmt 1.9.0-nightly']
        validate_toolchain('nightly-2026-10-16', versions, ['rustfmt', 'clippy'], expected)
        for channel in ['nightly', 'nightly-2026-10-17', 'stable', '1.99.1']:
            with self.assertRaises(ValueError):
                validate_toolchain(channel, versions, ['rustfmt', 'clippy'], expected)
        for components in [[], ['rustfmt'], ['clippy']]:
            with self.assertRaises(ValueError):
                validate_toolchain('nightly-2026-10-16', versions, components, expected)
        for index in range(4):
            missing = versions.copy()
            missing[index] = ''
            with self.assertRaises(ValueError):
                validate_toolchain('nightly-2026-10-16', missing, ['rustfmt', 'clippy'], expected)
        with self.assertRaises(ValueError):
            validate_toolchain('nightly-2026-10-16', ['rustc 1.99.1', *versions[1:]], ['rustfmt', 'clippy'], expected)
        for answer in [versions[0].replace(expected, '0' * 40), versions[0].splitlines()[0],
                       versions[0] + '\ncommit-hash: ' + expected,
                       versions[0].replace(expected, expected[:9])]:
            with self.subTest(answer=answer), self.assertRaisesRegex(ValueError, 'commit-hash'):
                validate_toolchain('nightly-2026-10-16', [answer, *versions[1:]], ['rustfmt', 'clippy'], expected)
        with self.assertRaisesRegex(ValueError, 'full rustc commit'):
            validate_toolchain('nightly-2026-10-16', versions, ['rustfmt', 'clippy'], expected[:9])

    @unittest.skipUnless(os.environ.get('FOUNDATION_COMPUTE_TESTS') == '1', 'compute-node compiler witness')
    def test_nursery_warning(self):
        """The real advisory invocation emits and counts a known nursery warning despite warnings-deny in the manifest.
        ´claim:discipline:advisory-invocation-counts-real-warnings´
        ´test:integration:test-nursery-warning´
        """
        with crate('foundation-nursery-probe', 'pub fn candidate(value: u32) -> u32 { value + 1 }\n', '[lints.rust]\nwarnings = "deny"\n[lints.clippy]\nnursery = "allow"\n') as root:
            result, count = run_clippy(root, advisory=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreaterEqual(count, 1)
            self.assertIn('clippy::missing_const_for_fn', result.stdout)
            print(f'NURSERY-WITNESS-FINDINGS={count}')


if __name__ == '__main__':
    unittest.main()
