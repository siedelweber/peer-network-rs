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


def act_profile_vector_rows():
    """Rebuild fixed typed preimages independently of the Rust projection.

    This deliberately restricted reader uses Python hashlib SHA-256 and only
    null, integer, byte/text strings and arrays. It neither imports a production
    encoder nor accepts arbitrary fixture-supplied projections as its oracle.
    """
    def head(major, size):
        if size < 24:
            return bytes([major * 32 + size])
        for width, marker in ((1, 24), (2, 25), (4, 26), (8, 27)):
            if size < 1 << (8 * width):
                return bytes([major * 32 + marker]) + size.to_bytes(width, "big")
        raise ValueError("act-profile vector integer is outside the restricted domain")

    def encode(value):
        if value is None:
            return bytes([246])
        if type(value) is int:
            return head(0, value) if value >= 0 else head(1, -1 - value)
        if isinstance(value, bytes):
            return head(2, len(value)) + value
        if isinstance(value, str):
            raw = value.encode("utf-8")
            return head(3, len(raw)) + raw
        if isinstance(value, list):
            return head(4, len(value)) + b"".join(map(encode, value))
        raise ValueError("unsupported act-profile vector constructor")

    author = "pn-devnet-v1/" + "12" * 32 + "/" + "34" * 32
    identity = ["act", author, 2, "Registration"]
    dependencies = [["act", author, 1, "Registration"]]
    body = [identity, "binary", [["binary", ["named", "addr", author], ["named", "prof", author]]],
            [], None, [], [], None, "full", "full"]
    nonce = (2).to_bytes(8, "big") + bytes(range(32))
    payload = b"fixture private aggregate"
    salts = [(1).to_bytes(16, "big") + bytes(range(32, 64)),
             (2).to_bytes(16, "big") + bytes(range(64, 96))]
    rows = []

    def verify(name, role, tag, fields):
        recipe = "pn-act-profile/act-" + role + "/v1"
        raw = recipe.encode() + bytes([0]) + encode([tag, fields])
        digest = hashlib.sha256(raw).digest()
        expected = dict(name=name, recipe=recipe, tag=tag, preimage=raw.hex(), digest=digest.hex())
        rows.append(expected)
        return digest

    content_pre = verify("content-pre", "proposal", "PN-content-pre-v1", [identity, nonce, payload])
    dependency_pre = verify("dependency-pre", "proposal", "PN-dependency-pre-v1", [identity, nonce, dependencies])
    proposal = verify("proposal", "proposal", "PN-act-proposal-v1", [body, content_pre, dependency_pre])
    verify("content", "content", "PN-content-v1", [identity, proposal, salts[0], payload])
    verify("dependency", "dependency", "PN-dependency-v1", [identity, proposal, salts[1], dependencies])
    # These authored branches are independent of the production schema table.
    # The exact integers distinguish authored pairs rather than rational values.
    def act(family, sequence=2):
        return ["act", author, sequence, family]

    def quantities(pairs):
        return sorted([[name + "." + part, value, "one", 0]
                       for name, numerator, denominator in pairs
                       for part, value in (("denominator", denominator), ("numerator", numerator))])

    cases = [
        ("publish", "Publish", "binary", [["attachment", -2, 4]], "mint", [[1, 2], [2, 4]], None, "full", "full"),
        ("opinion-act", "Opinion", "binary", [["polarity", -1, 2], ["reaction", 1, 2]], "act", None, None, "full", "full"),
        ("participant-edge-a", "Participant", "paired", [["continuity", 1, 2], ["interactivity", -1, 2], ["responsibility", 2, 4]], "A", None, None, "full", "full"),
        ("reference-edge-t", "Reference", "paired", [["effort", -1, 2], ["enthusiasm", 1, 2]], "T", None, None, "full", "full"),
        ("registration-edge-binary", "Registration", "binary", [], "binary", None, None, "full", "full"),
        ("registration-name", "Registration", "binary", [], "name", None, None, "full", "full"),
        ("accept", "Accept", "binary", [["comfort", 1, 2], ["equity", -1, 2]], "prof", None, ["Accept", act("Bid", 1)], "full", "full"),
        ("ratify", "Ratify", "binary", [["comfort", 1, 2], ["equity", -1, 2]], "prof", None, ["Ratify", act("Bid", 1), act("Accept", 1)], "full", "full"),
        ("empty", "Registration", "binary", [], "prof", None, None, "full-empty", "full-empty"),
        ("reduced", "Registration", "binary", [], "prof", None, None, "reduced", "tombstoned"),
    ]
    for name, family, layout, pairs, reference, license_value, settlement, content, dependency in cases:
        current = act(family)
        target = {"mint": ["mint", current], "act": act("Registration", 1),
                  "A": ["record", act("Reference", 1), "A"],
                  "T": ["record", act("Reference", 1), "T"],
                  "binary": ["record", act("Registration", 1), "binary"],
                  "name": ["named", "name", "fixture-name"], "prof": ["named", "prof", author]}[reference]
        legs = [["binary", ["named", "addr", author], target]] if layout == "binary" else [
            ["A", ["named", "addr", author], ["named", "prof", author]],
            ["T", ["named", "prof", author], target]]
        projected = [current, layout, legs, quantities(pairs), license_value,
                     [act("Registration", 1)], [], settlement, content, dependency]
        y = b"" if content == "full-empty" else payload
        d = [] if dependency == "full-empty" else dependencies
        def pre(tag, fields):
            return hashlib.sha256(b"pn-act-profile/act-proposal/v1\0" + encode([tag, fields])).digest()
        verify("proposal-" + name, "proposal", "PN-act-proposal-v1",
               [projected, pre("PN-content-pre-v1", [current, nonce, y]),
                pre("PN-dependency-pre-v1", [current, nonce, d])])
    return rows


def act_profile_vectors(path):
    """Refuse any fixture that differs from the independent fixed reader."""
    rows = json.loads(path.read_text()).get("vectors", [])
    expected = act_profile_vector_rows()
    if len(rows) != len(expected) or len({row.get("name") for row in rows}) != len(expected):
        raise ValueError("act-profile vector census differs")
    checked = {}
    for row in expected:
        name = row["name"]
        if next((item for item in rows if item.get("name") == name), None) != row:
            raise ValueError(f"act-profile vector differs: {name}")
        checked[name] = {row["preimage"], row["digest"]}
    return checked


def establish(root, rule):
    """Compile a family's reader-checkable evidence, refusing unsupported claims."""
    kind = rule["reader"]
    standing = rule["establishment"]
    if kind == "act-profile-vector" and standing == "recomputable":
        values = act_profile_vectors(relative_file(root, rule["source"]))[rule["vector"]]
        return lambda value, _line: value in values
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
    if kind == "campaign-tree" and standing == "resolvable":
        # Signing changes commit identity, never the exercised tree. Before
        # import, cite that tree only; the public commit locator is added then.
        tree = rule["tree"]
        if not re.fullmatch(r"[0-9a-f]{40}", tree):
            raise ValueError("hash citations: campaign requires a full tree identity")
        started = time.monotonic()
        history = subprocess.run(["git", "log", "--format=%T", "HEAD"], cwd=root, capture_output=True, text=True)
        print(f"hash citations git log wall={time.monotonic()-started:.6f}s status={history.returncode}")
        if history.returncode or tree not in history.stdout.splitlines():
            raise ValueError("hash citations: campaign tree is not in HEAD history")
        return lambda value, _line: value == tree
    if kind == "historical-inputs" and standing == "recomputable":
        commit = rule["commit"]
        establish(root, dict(reader="ancestor-commit", establishment="resolvable", commit=commit))
        def historical(name):
            path = pathlib.PurePosixPath(name)
            if path.is_absolute() or any(part in {"", ".", ".."} for part in name.split("/")):
                raise ValueError("hash citations: invalid historical input path")
            started = time.monotonic()
            result = subprocess.run(["git", "show", commit+":"+name], cwd=root, capture_output=True)
            print(f"hash citations git show wall={time.monotonic()-started:.6f}s status={result.returncode}")
            if result.returncode:
                raise ValueError("hash citations: absent historical input")
            return result.stdout
        program = ast.parse(historical(rule["source"]))
        assignments = [node for node in program.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == rule["symbol"] for target in node.targets)]
        if len(assignments) != 1:
            raise ValueError("hash citations: historical input declaration is not unique")
        names = ast.literal_eval(assignments[0].value)
        if not isinstance(names, (tuple, list)) or not names or any(not isinstance(name, str) for name in names) or len(names) != len(set(names)):
            raise ValueError("hash citations: malformed historical input declaration")
        projection = [(name, hashlib.sha256(historical(name)).hexdigest()) for name in names]
        expected = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if rule["digest"] != expected:
            raise ValueError("hash citations: historical input fingerprint differs")
        return lambda value, _line: value == expected
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
    if kind == "hex-alphabet" and standing == "defined":
        alphabet = ''.join(format(digit, 'x') for digit in range(16))
        return lambda value, line: value == alphabet and not IDENTITY_CONTEXT.search(line) and not re.search(r"\b(?:hash|rev|revision|tree|object)\b", line, re.I)
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
    if kind == "null-hash" and standing == "defined":
        # The all-zero hash names no object; it declares an absence, never an identity.
        return lambda value, _line: value == "0" * 64
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
