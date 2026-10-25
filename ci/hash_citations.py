"""Account for tracked hexadecimal values without recomputing their subjects."""

import ast
import hashlib
import json
import fnmatch
import pathlib
import re
import tomllib
import subprocess
import time


# Short bare words need digits or an identity context; explicit literals and full
# identifiers keep their original boundary. Ordinary decimal quantities are not hashes.
# Explicit Rust integer suffixes belong to the representation, not to its value.
HEX = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"0[xX][0-9A-Fa-f]+(?:_[0-9A-Fa-f]+)*(?:_?[ui](?:8|16|32|64|128|size))?"
    r"|\\x[0-9A-Fa-f]{2}|\\u\{[0-9A-Fa-f]+\}|\\u[0-9A-Fa-f]{4}"
    r"|%x[0-9A-Fa-f]+(?:-[0-9A-Fa-f]+)?"
    r"|(?=[0-9A-Fa-f]*[A-Fa-f])[0-9A-Fa-f]{6,}"
    r"|[0-9]{6,}"
    r")(?![A-Za-z0-9_])"
)


IDENTITY_CONTEXT = re.compile(r"\b(?:commit|digest|checksum|sha(?:-?(?:1|256|512))?)\b", re.I)
IDENTITY_FIELD = re.compile(r'''\b(?:hash|rev|revision|tree|object)\b[ \t]*(?:[=:][ \t]*)?["'`]?\Z''', re.I)
BARE = re.compile(r"[0-9a-f]+", re.I)


def occurrences(text):
    """Read values, not short English words that happen to use hex letters.

    Commit, digest, checksum and sha contexts are line-scoped. Hash, rev,
    revision, tree and object bind only the immediately following value,
    optionally after a field separator or quote, never another prose word.
    Parenthesized tool-version tuples also carry abbreviated commit identity.
    This changes recognition only; every recognized value still needs a family.
    """
    found = []
    for match in HEX.finditer(text):
        value = match.group()
        if (not BARE.fullmatch(value) or len(value) in {40, 64}
                or (any(c.isalpha() for c in value) and (len(value) >= 40 or any(c.isdigit() for c in value)))):
            found.append(match)
            continue
        start = text.rfind("\n", 0, match.start()) + 1
        end = text.find("\n", match.end())
        line = text[start:end if end >= 0 else len(text)]
        version = (text[max(start, match.start() - 1):match.start()] == "("
                   and re.match(r" \d{4}-\d{2}-\d{2}\)", text[match.end():]))
        decimal_version = (value.isdecimal() and len(value) <= 40
                           and text[max(start, match.start() - 1):match.start()] == "("
                           and text[match.end():match.end() + 1] == " ")
        if IDENTITY_CONTEXT.search(line) or IDENTITY_FIELD.search(text[start:match.start()]) or version or decimal_version:
            found.append(match)
    return found


def relative_file(root, name):
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in name.split("/")):
        raise ValueError(f"hash citations: non-relative evidence path {name}")
    full = root / path
    if not full.is_file() or full.is_symlink():
        raise ValueError(f"hash citations: absent regular evidence file {name}")
    return full


def literal_integer(value):
    if value.lower().startswith("0x"):
        return int(re.sub(r"_?[ui](?:8|16|32|64|128|size)$", "", value)[2:].replace("_", ""), 16)
    if value.startswith("\\x"):
        return int(value[2:], 16)
    if value.startswith("\\u"):
        return int(value[2:].strip("{}"), 16)
    return None


def establish(root, rule):
    """Compile a family's reader-checkable evidence, refusing unsupported claims."""
    kind = rule["reader"]
    standing = rule["establishment"]
    if kind == "storage-vectors" and standing == "recomputable":
        from storage_vectors import check
        values = check(relative_file(root, rule["source"]))
        return lambda value, _line: value in values
    if kind == "policy-vectors" and standing == "recomputable":
        from policy_vectors import check
        values = check(relative_file(root, rule["source"]))
        return lambda value, _line: value in values
    if kind == "artifact-vector" and standing == "recomputable":
        vector = json.loads(relative_file(root, rule["source"]).read_text())
        if (vector.get("recipe") != "json-string-utf8" or not isinstance(vector.get("payload"), str)
                or type(vector.get("repeat")) is not int or not 0 < vector["repeat"] <= 65536):
            raise ValueError("hash citations: invalid artifact vector recipe")
        encoded = json.dumps(vector["payload"] * vector["repeat"], ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        expected = hashlib.sha256(encoded).hexdigest()
        if vector.get("digest") != expected:
            raise ValueError("hash citations: artifact vector differs from its payload")
        return lambda value, _line: value == expected
    if kind == "ancestor-commit" and standing == "resolvable":
        commit = rule["commit"]
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("hash citations: admitted import requires a full commit identity")
        started = time.monotonic()
        history = subprocess.run(["git", "rev-list", "HEAD"], cwd=root, capture_output=True, text=True)
        print(f"hash citations git rev-list wall={time.monotonic()-started:.6f}s status={history.returncode}")
        if history.returncode or commit not in history.stdout.splitlines():
            raise ValueError("hash citations: admitted import is not reachable from HEAD")
        return lambda value, _line: value == commit
    if kind == "imported-commit" and standing == "resolvable":
        # Campaigns identify the exercised tree and its public history location.
        commit = rule["commit"]
        tree = rule["tree"]
        establish(root, dict(reader="ancestor-commit", establishment="resolvable", commit=commit))
        if not re.fullmatch(r"[0-9a-f]{40}", tree):
            raise ValueError("hash citations: admitted import requires a full tree identity")
        started = time.monotonic()
        result = subprocess.run(["git", "rev-parse", commit + "^{tree}"], cwd=root, capture_output=True, text=True)
        print(f"hash citations git rev-parse wall={time.monotonic()-started:.6f}s status={result.returncode}")
        if result.returncode or tree != result.stdout.strip():
            raise ValueError("hash citations: imported source tree differs")
        return lambda value, _line: value in {commit, tree}
    if kind == "public-git" and standing == "resolvable":
        locator = rule["locator"]
        commit = rule["commit"]
        if not re.fullmatch(r"https://github.com/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+/commit/[0-9a-f]{40}", locator) or not locator.endswith("/" + commit):
            raise ValueError("hash citations: public Git locator must identify the declared commit")
        return lambda value, _line: value == commit
    if kind == "interchange-literal" and standing == "defined":
        def literal(value, line):
            integer = literal_integer(value)
            if integer is not None:
                # Numeric constants and escape witnesses are data, including invalid-input tests.
                return 0 <= integer < 2**64
            if value.startswith("%x"):
                return all(0 <= int(part, 16) < 2**21 for part in value[2:].split("-"))
            return bool(re.fullmatch(r"0b[01]+", value))
        return literal
    if kind == "cbor-vectors" and standing == "defined":
        # Encodings, including deliberately invalid encodings, are the test input itself.
        # Scientific-notation fragments and repeated text subjects are also visible data.
        return lambda value, line: bool(
            re.fullmatch(r"[0-9a-f]+", value, re.I)
            and not re.search(r"\b(?:commit|digest|sha256|checksum)\b", line, re.I)
            and (re.search(r'"(?:hex|diagnostic|roundtrip)"\s*:', line)
                 or re.search(r'"[0-9a-f]+"', line, re.I))
        )
    if kind == "regexp-subject" and standing == "defined":
        return lambda value, line: bool(
            re.fullmatch(r"[a-fA-F0-9]{6,64}", value)
            and len(value) not in {40, 64}
            and (value in {"10FFFF", "987654321A"} or re.fullmatch(r"[a-fA-F]+(?:12[a-f]+)?", value))
            and not re.search(r"\b(?:commit|digest|sha256|checksum)\b", line, re.I)
        )
    if kind == "proptest-seed" and standing == "defined":
        return lambda value, line: bool(re.fullmatch(r"[0-9a-f]{64}", value) and line.startswith("cc " + value + " # shrinks to "))
    if kind == "evaluated-crate-archive" and standing == "resolvable":
        profile = tomllib.loads(relative_file(root, rule["source"]).read_text())
        if profile.get("namespace") != "org.peer-network.devnet.profile":
            raise ValueError("hash citations: invalid evaluated archive profile")
        rows = profile.get("rows", [])
        if len(rows) != 1 or rows[0].get("name") != "testnet-signet":
            raise ValueError("hash citations: invalid evaluated archive profile row")
        candidates = rows[0].get("wallet_candidates", [])
        values, identities = set(), set()
        if not candidates:
            raise ValueError("hash citations: empty evaluated archive register")
        for candidate in candidates:
            name, version = candidate.get("name", ""), candidate.get("version", "")
            checksum = candidate.get("checksum", "")
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name)
                    or not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version)
                    or not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum)
                    or candidate.get("archive") != f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
                    or (name, version) in identities):
                raise ValueError("hash citations: invalid evaluated archive locator or checksum")
            identities.add((name, version))
            values.add(checksum)
        return lambda value, _line: value in values
    if kind == "cargo-archive" and standing == "resolvable":
        packages = tomllib.loads(relative_file(root, rule["source"]).read_text())["package"]
        values = set()
        for package in packages:
            if "checksum" in package:
                if package.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
                    raise ValueError("hash citations: unsupported Cargo registry locator")
                if not package.get("name") or not package.get("version"):
                    raise ValueError("hash citations: archive locator lacks package or version")
                values.add(package["checksum"])
        return lambda value, _line: value in values
    if kind == "projection-pin" and standing == "recomputable":
        program = ast.parse(relative_file(root, rule["source"]).read_text())
        if not any(isinstance(node, ast.FunctionDef) and node.name == rule["function"] for node in program.body):
            raise ValueError("hash citations: projection producer is absent")
        pins = {}
        for name, source in rule["subjects"].items():
            relative_file(root, source)
            for node in program.body:
                if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
                    pins[name] = ast.literal_eval(node.value)
        if set(pins) != set(rule["subjects"]) or rule["algorithm"] != "SHA-256 over the digest function's canonical JSON rows":
            raise ValueError("hash citations: incomplete projection recipe")
        return lambda value, line: any(value == pin and re.match(r"^" + re.escape(name) + r"\s*=", line) for name, pin in pins.items())
    if kind == "byte" and standing == "defined":
        # ASCII controls, the two bytes excluded by UTF-8, the euro sign's UTF-8
        # encoding, and the pack's visible alternating-pair payload pattern.
        defined = {0, 1, 27, 31, 254, 255, *"€".encode("utf-8"), int("10100101", 2)}
        return lambda value, _line: value.startswith(("0x", "0X", "\\x")) and literal_integer(value) in defined
    if kind == "unicode" and standing == "defined":
        return lambda value, _line: value.startswith("\\u") and 0 <= literal_integer(value) <= 0x10ffff and not 0xd800 <= literal_integer(value) <= 0xdfff
    if kind == "cbor-header" and standing == "defined":
        return lambda value, _line: value.startswith(("0x", "0X")) and literal_integer(value) in {0, 23, 24, 25, 26, 27}
    if kind == "abnf" and standing == "defined":
        return lambda value, _line: value.startswith("%x") and all(0 <= int(part, 16) <= 127 for part in value[2:].split("-"))
    if kind == "fixture-pattern" and standing == "defined":
        patterns = rule["patterns"]
        if not patterns or any(pattern not in {"abc123", "abcdef", "abcdef123", "123456"} for pattern in patterns):
            raise ValueError("hash citations: fixture has no stated visible pattern")
        return lambda value, _line: value in patterns
    if kind == "unicode-bound" and standing == "defined":
        return lambda value, _line: value in {"0x10ffff", "0xd800", "0xdfff"}
    raise ValueError(f"hash citations: no reader establishment for {rule['family']}")


def audit(root, paths, table):
    if list(table)[:2] != ["namespace", "version"] or table.get("namespace") != "org.peer-network.ci.hash-citations":
        raise ValueError("hash citations: expected namespace then version")
    if table.get("version") != [1, 0, 0] or any(type(part) is not int for part in table["version"]):
        raise ValueError("hash citations: unsupported version")
    rules = table["rows"]
    if not rules:
        raise ValueError("hash citations: no families declared")
    names = set()
    compiled = []
    for rule in rules:
        if any(not isinstance(rule.get(field), str) or not rule[field].strip() for field in ("family", "group", "measures", "producer", "establishment", "reader", "definition")):
            raise ValueError("hash citations: each family requires its accounting and reader fields")
        if rule["family"] in names or not rule.get("paths") or not all(isinstance(path, str) and path for path in rule["paths"]):
            raise ValueError("hash citations: duplicate family or absent paths")
        names.add(rule["family"])
        compiled.append((rule, establish(root, rule)))
    findings = []
    used = set()
    count = 0
    for path in paths:
        full = relative_file(root, path)
        # Decode one byte to one character, so binary tracked content is scanned too.
        for number, line in enumerate(full.read_bytes().decode("latin1").splitlines(), 1):
            for match in occurrences(line):
                value = match.group()
                count += 1
                matches = [rule["family"] for rule, check in compiled if any(fnmatch.fnmatchcase(path, pattern) for pattern in rule["paths"]) and check(value, line)]
                if not matches:
                    findings.append(f"{path}:{number}: unaccounted hexadecimal value {value}")
                else:
                    used.update(matches)
        for match in occurrences(path):
            findings.append(f"{path}: hexadecimal pathname value needs an explicit path identity rule: {match.group()}")
    findings.extend(f"family {name}: describes no tracked value" for name in sorted(names - used))
    return findings, count


def check(root, paths):
    table = tomllib.loads((root / "ci/hash-citation-families.toml").read_text())
    findings, count = audit(root, paths, table)
    for finding in findings:
        print(finding)
    print(f"HASH-CITATIONS values={count} families={len(table['rows'])} findings={len(findings)}")
    return int(bool(findings))
