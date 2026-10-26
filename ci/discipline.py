"""Check universal bytes and first-party source disciplines."""

import pathlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib


def git(*args):
    started = time.monotonic()
    result = subprocess.run(["git", *args], capture_output=True)
    print(f"git {args[0]} wall={time.monotonic() - started:.6f}s status={result.returncode}")
    return result


def absent(values, exclusions, ignore_case=False):
    failed = False
    for value in values:
        flags = ["-i"] if ignore_case else []
        result = git("grep", *flags, "-a", "-l", "-F", "-e", value, "--", ".", ":(exclude)target/**", ":(exclude).git/**", *exclusions)
        if result.returncode != 1:
            failed = True
            sys.stdout.buffer.write(result.stdout)
            sys.stderr.buffer.write(result.stderr)
            print("prohibited bytes found or search failed")
    return int(failed)


def rust_code(source):
    """Mask comments and literals without moving source offsets or newlines."""
    pattern = re.compile(r'//[^\n]*|/\*|(?:br|cr|r)(\#*)"|(?:b|c)?"|\'(?:\\.|[^\'\\\n])\'')
    chars = list(source)
    offset = 0
    while match := pattern.search(source, offset):
        start = match.start()
        end = match.end()
        token = match.group()
        if token == "/*":
            depth = 1
            while depth and end < len(source):
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
        elif match.group(1) is not None:
            terminator = '"' + match.group(1)
            closing = source.find(terminator, end)
            end = len(source) if closing < 0 else closing + len(terminator)
        elif token.endswith('"'):
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                elif source[end] == '"':
                    end += 1
                    break
                else:
                    end += 1
        for index in range(start, min(end, len(source))):
            if chars[index] != "\n":
                chars[index] = " "
        offset = end
    return "".join(chars)


def item_end(code, start):
    brackets = 0
    parentheses = 0
    for index in range(start, len(code)):
        token = code[index]
        brackets += (token == "[") - (token == "]")
        parentheses += (token == "(") - (token == ")")
        if brackets == parentheses == 0:
            if token == ";":
                return index + 1
            if token == "{":
                depth = 1
                end = index + 1
                while depth and end < len(code):
                    depth += (code[end] == "{") - (code[end] == "}")
                    end += 1
                return end
    return len(code)


def test_item_ranges(code):
    pattern = r"#\s*!?\s*\[\s*(?:cfg(?:_attr)?\s*\([^]]*\btest\b[^]]*\)|test)\s*\]"
    ranges = []
    for match in re.finditer(pattern, code):
        end = len(code) if "!" in match.group()[:match.group().index("[")] else item_end(code, match.end())
        ranges.append((match.start(), end))
    return ranges


def test_sources(sources):
    edges = []
    marked = {path for path in sources if any(part in {"tests", "harness", "harnesses"} for part in path.parts)}
    for path, source in sources.items():
        code = rust_code(source)
        ranges = test_item_ranges(code)
        bases = [path.parent]
        if path.stem not in {"lib", "main", "mod"}:
            bases.append(path.with_suffix(""))
        for match in re.finditer(r"\bmod\s+(\w+)\s*([;{])", code):
            if match.group(2) != ";":
                continue
            inline = []
            for parent in re.finditer(r"\bmod\s+(\w+)\s*\{", code[:match.start()]):
                if item_end(code, parent.end() - 1) > match.start():
                    inline.append(parent.group(1))
            explicit = re.search(r'#\s*\[\s*path\s*=\s*"([^"\n]+)"\s*\](?:\s|#\[[^]]*\])*$', source[:match.start()])
            candidates = []
            for base in bases:
                directory = base.joinpath(*inline)
                if explicit:
                    candidates.append(directory / explicit.group(1))
                else:
                    candidates.extend([directory / (match.group(1) + ".rs"), directory / match.group(1) / "mod.rs"])
            is_test = any(start <= match.start() < end for start, end in ranges)
            edges.extend((path, target, is_test) for target in candidates if target in sources)
    while True:
        added = {target for source, target, conditional in edges if conditional or source in marked} - marked
        if not added:
            return marked
        marked.update(added)


SECRET_EXITS = {"expose_bytes", "expose_storage", "expose_secret", "expose_secret_mut", "init_with_mut", "init_with", "try_init_with"}


def exposure_sites(path, source):
    """Inventory explicit exits; semantic copies and consumer lifetimes remain reviewed."""
    code = rust_code(source)
    functions = []
    for match in re.finditer(r"\bfn\s+(\w+)\b", code):
        start = source.rfind("\n", 0, match.start()) + 1
        # Comments and attributes immediately before the smallest function item.
        prefix = source[:start].splitlines(keepends=True)
        header = []
        while prefix and (prefix[-1].lstrip().startswith(("//", "#[")) or not prefix[-1].strip()):
            header.insert(0, prefix.pop())
        if not re.fullmatch(r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?", code[start:match.start()]):
            header = []
        functions.append((match.start(), item_end(code, match.end()), match.group(1), "".join(header)))
    rows = []
    findings = []
    grouped = {}
    pattern = r"\b(?:" + "|".join(sorted(SECRET_EXITS)) + r")\b"
    for match in re.finditer(pattern, code):
        # Imports name the trait, not the method; method definitions are not exits.
        if re.search(r"\bfn\s*$", code[:match.start()]):
            continue
        parents = [item for item in functions if item[0] < match.start() < item[1]]
        if not parents:
            findings.append(f"secret exit outside a function at line {source[:match.start()].count(chr(10)) + 1}")
            continue
        owner = max(parents, key=lambda item: item[0])
        grouped.setdefault(owner, []).append(match)
    for (_, _, name, header), calls in grouped.items():
        labels = re.findall(r"\(´\[ROOT-(cav:observe:secret-[a-z0-9-]+)\]´\)", header)
        allowed = re.search(r"#\[allow\(clippy::disallowed_methods\)\]", header)
        justified = re.search(r"// Justified: [^\n]+\.\n\s*#\[allow\(clippy::disallowed_methods\)\]", header)
        if not allowed or not justified or len(labels) != len(calls) or len(set(labels)) != len(labels):
            findings.append(f"secret exits in {name} require one unique Caveat label per exit and a justified item-local allow")
        for index, call in enumerate(calls):
            label = labels[index] if index < len(labels) else None
            citation = re.match(r"\s*(?:\(\s*)?/\* \(´\[ROOT-(cav:observe:secret-[a-z0-9-]+)\]´\) \*/", source[call.end():])
            if not citation or citation.group(1) != label:
                findings.append(f"secret exit in {name} lacks its own site citation")
            rows.append({"path": str(path), "item": name, "line": source[:call.start()].count("\n") + 1,
                         "method": call.group(), "label": label})
    if re.search(r"\bSerializableSecret\b", code):
        findings.append("secret serialization is not admitted; use a labelled explicit exposure boundary")
    return rows, findings


def source_findings(path, source, mode, forced_test=False):
    code = rust_code(source)
    if mode == "printing":
        # Record 004 assigns these exact stream/exit boundaries to the shared
        # emitter and child-byte relay. Other calls, imports and print macros
        # remain prohibited even inside these items.
        boundaries = {
            "packages/cli-common/src/lib.rs": {
                "exit_with": r"std\s*::\s*process\s*::\s*exit",
                "stdout_tty_refusal_record": r"io\s*::\s*stdout",
                "emit": r"io\s*::\s*stdout",
                "locked_stderr": r"io\s*::\s*stderr",
                "try_locked_stderr": r"io\s*::\s*stderr",
            },
            "packages/execwrap/src/lib.rs": {"run_observed": r"(?:io\s*::\s*(?:stdout|stderr)|(?<=\.)(?:stdout|stderr))"},
        }
        for match in reversed(list(re.finditer(r"\bfn\s+(\w+)\b", code))):
            allowed = boundaries.get(path.as_posix(), {}).get(match.group(1))
            if allowed:
                end = item_end(code, match.end())
                item = re.sub(allowed + r"(?=\s*\()", lambda found: " " * len(found.group()), code[match.end():end])
                code = code[:match.end()] + item + code[end:]
        # Reject the imported names as well as calls, so aliases cannot hide them.
        pattern = r"\b(?:print|println|eprint|eprintln|dbg)\s*!|\b(?:exit|stdout|stderr)\s*(?:\(|\bas\b)|\b(?:process|io)\s*::\s*(?:exit|stdout|stderr)\b"
        imports = re.finditer(r"\buse\s+[^;]+;", code)
        forbidden_import = any(re.search(r"\b(?:exit|stdout|stderr|print|println|eprint|eprintln|dbg)\b|\b(?:process|io)\s*::\s*\*", item.group()) for item in imports)
        return ["uncontrolled printing, stream handle or exit"] if forbidden_import or re.search(pattern, code) else []
    findings = []
    test_ranges = test_item_ranges(code)
    for match in re.finditer(r"#\s*(!?)\s*\[([^]]*)\]", code, re.S):
        body = match.group(2)
        suppressions = list(re.finditer(r"\b(?:allow|expect)\s*\(([^()]*)\)", body))
        if not suppressions:
            continue
        preceding = source[:match.start()].rstrip().splitlines()
        justified = bool(preceding and re.fullmatch(r"\s*// Justified: .+\.\s*", preceding[-1]))
        test_tree = forced_test or any(part in {"tests", "harness", "harnesses"} for part in path.parts)
        test_tree |= any(start <= match.start() < end for start, end in test_ranges)
        following = code[match.end():]
        test_tree |= bool(re.match(r"\s*#\[\s*(?:test|cfg\s*\([^]]*\btest\b)", following))
        item_follows = bool(re.match(r"\s*(?:#\[[^]]+\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:fn|struct|enum|impl|trait|const|static|type|mod)\b", following))
        names = suppressions[0].group(1).strip()
        named = bool(re.fullmatch(r"[a-z_][a-z_0-9]*(?:::[a-z_][a-z_0-9]*)?(?:\s*,\s*[a-z_][a-z_0-9]*(?:::[a-z_][a-z_0-9]*)?)*\s*,?", names))
        groups = {"warnings", "unused", "all", "pedantic", "nursery", "complexity", "correctness", "perf", "style", "suspicious", "deprecated_safe", "future_incompatible", "let_underscore", "nonstandard_style", "rust_2018_compatibility", "rust_2018_idioms", "rust_2021_compatibility", "rust_2024_compatibility"}
        named &= not any(name.strip().split("::")[-1] in groups for name in names.split(","))
        conditional = bool(re.search(r"\bcfg_attr\b", body))
        fixture_exit = (names == "clippy::disallowed_methods" and
                        "// Fixture-only secret boundary:" in source[:match.start()].split("\n\n")[-1] and
                        bool(re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\b", following)))
        if match.group(1) or conditional or (test_tree and not fixture_exit) or not justified or not named or not item_follows:
            findings.append("suppression is not a justified named production-item attribute")
    findings.extend(exposure_sites(path, source)[1])
    return findings


def exposure_registry_findings(sites, register):
    expected = {row["label"]: (row["path"], row["function"], row["method"]) for row in register}
    actual = {row["label"]: (row["path"], row["item"], row["method"]) for row in sites}
    if len(expected) != len(register) or len(actual) != len(sites) or expected != actual:
        return ["secret exposure register differs from sites: " + str(sorted(set(expected.items()) ^ set(actual.items()), key=str))]
    return []


def inherits_lints(manifest):
    return manifest.get("lints") == {"workspace": True}


HTTP_ROOTS = {"hyper", "tower", "hyper-util", "http-body-util", "http"}


def http_admission_findings(metadata, rows):
    """Check the active HTTP dependency graph against the admitted feature ceiling."""
    admitted = {(row["name"], row["version"]): set(row["features"]) for row in rows}
    packages = {row["id"]: row for row in metadata["packages"]}
    nodes = {row["id"]: row for row in metadata["resolve"]["nodes"]}
    pending = [key for key, row in packages.items() if row["name"] in HTTP_ROOTS]
    visited = set()
    findings = []
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        package, node = packages[key], nodes[key]
        identity = (package["name"], package["version"])
        if identity not in admitted:
            findings.append(f"HTTP dependency is not admitted: {identity}")
        elif not set(node["features"]) <= admitted[identity]:
            findings.append(f"HTTP dependency features exceed admission: {identity}: {sorted(set(node['features']) - admitted[identity])}")
        pending.extend(dep["pkg"] for dep in node.get("deps", [])
                       if any(kind["kind"] != "dev" for kind in dep["dep_kinds"]))
    return findings, len(visited)


def check_http_admission(root):
    rows = tomllib.loads((root / "docs/inputs/http-dependencies.toml").read_text())["rows"]
    declarations = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["dependencies"]
    for name in HTTP_ROOTS:
        version = next(row["version"] for row in rows if row["name"] == name)
        if declarations.get(name) != {"version": "=" + version, "default-features": False}:
            raise ValueError(f"workspace HTTP declaration differs from admission: {name}")
    start = time.monotonic()
    result = subprocess.run(["cargo", "metadata", "--format-version=1", "--locked"], cwd=root, capture_output=True, text=True, check=True)
    metadata = json.loads(result.stdout)
    findings, active = http_admission_findings(metadata, rows)
    secret_findings = secret_dependency_findings(metadata)
    print(f"SECRET-LIBRARY reviewed=0.10.3 serde=disabled findings={len(secret_findings)}")
    findings.extend(secret_findings)
    for finding in findings:
        print(finding)
    print(f"HTTP-ADMISSION admitted={len(rows)} active={active} findings={len(findings)} wall={time.monotonic() - start:.6f}s")
    if findings:
        raise ValueError("HTTP dependency admission failed")


def secret_dependency_findings(metadata):
    nodes = {row["id"]: row for row in metadata["resolve"]["nodes"]}
    return ["secrecy exit review requires version 0.10.3 without serde" for package in metadata["packages"]
            if package["name"] == "secrecy" and
            (package["version"] != "0.10.3" or "serde" in nodes[package["id"]]["features"])]


def vendor_members(root):
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    members = manifest.get("workspace", {}).get("members", [])
    vendors = []
    for member in members:
        if any(part in {"", ".", ".."} for part in member.split("/")) or any(char in member for char in "*?[\\"):
            raise ValueError(f"Cargo.toml: member path must be explicit and normalized: {member}")
        if member.startswith("vendor/"):
            package = tomllib.loads((root / member / "Cargo.toml").read_text())["package"]["name"]
            vendors.append((member, package))
    return sorted(vendors)


def run_clippy(root, advisory=False):
    command = ["cargo", "clippy", "--workspace"]
    if "gate" in tomllib.loads((root / "Cargo.toml").read_text()).get("profile", {}):
        command.extend(["--profile", "gate"])
    # The vendored engine keeps its upstream Clippy policy.
    for _, package in vendor_members(root):
        command.extend(["--exclude", package])
    command.extend(["--all-targets", "--no-deps", "--locked", "--message-format=json"])
    if advisory:
        command.extend(["--", "-W", "warnings", "-W", "clippy::nursery"])
    else:
        command.extend(["--", "-D", "warnings"])
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    pathlib.Path(".lane").mkdir(exist_ok=True)
    pathlib.Path(".lane/" + ("nursery" if advisory else "clippy") + "-diagnostics.jsonl").write_text(result.stdout)
    count = 0
    for line in result.stdout.splitlines():
        record = json.loads(line)
        if record.get("reason") == "compiler-message":
            message = record["message"]
            if message.get("level") == "warning" and (message.get("code") or {}).get("code", "").startswith("clippy::"):
                count += 1
            print(message.get("rendered", ""), end="")
    print(result.stderr, end="")
    return result, count


def cargo_config_findings(value):
    if isinstance(value, dict):
        return any("rustflags" in key.lower() or cargo_config_findings(item) for key, item in value.items())
    if isinstance(value, list):
        return any(cargo_config_findings(item) for item in value)
    if isinstance(value, str):
        return bool(re.search(r"(?:^|[\s\"'\x1f])(?:-[AWDF]|--(?:allow|warn|deny|forbid|cap-lints|force-warn)\b)", value))
    return False


def validate_toolchain(channel, versions, components, expected_commit):
    if channel != "nightly-2026-10-16":
        raise ValueError("rust-toolchain.toml: expected nightly-2026-10-16")
    if not {"rustfmt", "clippy"} <= set(components):
        raise ValueError("rust-toolchain.toml: rustfmt and clippy are required")
    if len(versions) != 4 or any(not value.strip() for value in versions):
        raise ValueError("all four toolchain commands must answer")
    for value, prefix in zip(versions, ["rustc ", "cargo ", "clippy ", "rustfmt "]):
        if not value.startswith(prefix):
            raise ValueError(f"unexpected toolchain response: {value}")
    if "-nightly" not in versions[0].splitlines()[0]:
        raise ValueError("the compiler must be nightly")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise ValueError("build policy requires a full rustc commit identity")
    commits = re.findall(r"^commit-hash: ([0-9a-f]{40})$", versions[0], re.M)
    if commits != [expected_commit]:
        raise ValueError("answering rustc commit-hash differs from build policy")


def workspace_packages():
    result = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version=1", "--locked"], capture_output=True, text=True, check=True)
    metadata = json.loads(result.stdout)
    members = set(metadata["workspace_members"])
    return sorted((package for package in metadata["packages"] if package["id"] in members), key=lambda package: package["name"])


def validate_build_policy(root):
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    if "rust-version" in manifest["workspace"]["package"]:
        raise ValueError("pinned compiler declares no checked minimum compiler")
    for member in manifest["workspace"]["members"]:
        if member.startswith("vendor/"):
            continue
        if "rust-version" in tomllib.loads((root / member / "Cargo.toml").read_text())["package"]:
            raise ValueError(f"{member}: no minimum compiler declaration is checked")
    policy = tomllib.loads((root / "docs/inputs/build-policy.toml").read_text())["rows"]
    expected = {"name": "workspace", "channel": "nightly-2026-10-16", "components": ["rustfmt", "clippy"],
                "rustc_commit": "4ebd258257737d5b7635c116fa7d281627a7e937",
                "lto": "thin", "codegen_units": 1, "toolchain_gate": "toolchain",
                "profile_gate": "build-policy", "tests_gate": "discipline-tests"}
    if policy != [expected]:
        raise ValueError("rendered build policy must state the enforced workspace policy")
    profiles = manifest.get("profile", {})
    if profiles != {"release": {"lto": "thin", "codegen-units": 1},
                    "gate": {"inherits": "dev", "opt-level": 1, "debug": 0,
                             "debug-assertions": True, "overflow-checks": True}}:
        raise ValueError("expected reviewed release and gate profiles; dev and test use defaults")


def main():
    mode = sys.argv[1]
    if mode == "tests":
        from run_tests import main as run_tests
        return run_tests()
    if mode == "fmt":
        command = ["cargo", "fmt"]
        for package in workspace_packages():
            # regexml preserves the reviewed upstream engine layout.
            if package["name"] != "regexml":
                command.extend(["-p", package["name"]])
        return subprocess.run([*command, "--check"]).returncode
    if mode in {"minimal", "rustdoc"}:
        command = ["cargo", "check" if mode == "minimal" else "doc"]
        for package in workspace_packages():
            # regexml retains its upstream feature and documentation policy.
            if package["name"] != "regexml":
                command.extend(["-p", package["name"]])
        command.extend(["--no-default-features" if mode == "minimal" else "--no-deps", "--locked"])
        command.extend(["--profile", "gate"])
        return subprocess.run(command).returncode
    if mode == "build-policy":
        validate_build_policy(pathlib.Path.cwd())
        return 0
    if mode == "tree-clean":
        result = git("status", "--porcelain", "--untracked-files=all")
        result.check_returncode()
        sys.stdout.buffer.write(result.stdout)
        return int(bool(result.stdout))
    if mode == "members":
        metadata = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version=1", "--locked"], capture_output=True, text=True)
        if metadata.returncode:
            raise ValueError(f"Cargo.toml: member discovery failed: {metadata.stderr}")
        workspace = json.loads(metadata.stdout)
        members = set(workspace["workspace_members"])
        manifests = {pathlib.Path(package["manifest_path"]) for package in workspace["packages"] if package["id"] in members}
        if not manifests:
            raise ValueError("workspace has no member manifests")
        for path in sorted(manifests):
            manifest = tomllib.loads(path.read_text())
            # The engine retains its upstream manifest and compiler policy.
            if path.parent == pathlib.Path.cwd() / "vendor/regexml":
                continue
            if not inherits_lints(manifest):
                raise ValueError(f"{path}: expected only [lints] workspace = true; local lint tables are forbidden")
        print(f"MEMBER-LINTS={len(manifests)}")
        check_http_admission(pathlib.Path.cwd())
        return 0
    if mode in {"clippy", "nursery"}:
        result, count = run_clippy(pathlib.Path.cwd(), advisory=mode == "nursery")
        if mode == "nursery":
            print(f"NURSERY-FINDINGS={count} COMMAND-STATUS={result.returncode} ADVISORY=true")
            return 0
        return result.returncode
    if mode == "toolchain":
        revision = git("rev-parse", "HEAD")
        revision.check_returncode()
        print("VERIFY-COMMIT=" + revision.stdout.decode().strip(), flush=True)
        toolchain = tomllib.loads(pathlib.Path("rust-toolchain.toml").read_text())["toolchain"]
        versions = []
        for command in [["rustc", "-vV"], ["cargo", "-V"], ["cargo", "clippy", "-V"], ["rustfmt", "-V"]]:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            print(result.stdout.strip())
            versions.append(result.stdout.strip())
        policy = tomllib.loads(pathlib.Path("docs/inputs/build-policy.toml").read_text())["rows"][0]
        validate_toolchain(toolchain["channel"], versions, toolchain.get("components", []), policy["rustc_commit"])
        print("TOOLCHAIN-CHANNEL=" + toolchain["channel"])
        print("TOOLCHAIN-COMMIT=" + policy["rustc_commit"])
        return 0
    if mode == "cargo-config":
        tracked = git("ls-files", "-z")
        tracked.check_returncode()
        for name in tracked.stdout.split(b"\0"):
            if not name:
                continue
            path = pathlib.Path(os.fsdecode(name))
            if path.parent.name == ".cargo" and path.name in {"config", "config.toml"}:
                if cargo_config_findings(tomllib.loads(path.read_text())):
                    raise ValueError(f"{path}: tracked Cargo configuration may not carry rustflags or lint flags")
        return 0
    if mode == "vendor-set":
        vendors = vendor_members(pathlib.Path.cwd())
        expected = "( " + " / ".join(f'%s"{path}/" *VCHAR' for path, _ in vendors) + " )"
        owners = tomllib.loads(pathlib.Path(".linter/owners.toml").read_text())
        declared = [row["pattern"] for row in owners["partitions"] if row["owner"] == "VENDOR"]
        if declared != [expected]:
            raise ValueError(f".linter/owners.toml: VENDOR partition differs from workspace members: expected {expected}")
        print("VENDOR-MEMBERS=" + json.dumps(vendors))
        return 0
    if mode == "diagnostics":
        for name in ["clippy", "tests", "minimal", "datasets", "documents", "linter", "design-tests", "discipline-tests", "hash-citations"]:
            lines = pathlib.Path(f".lane/gate-{name}.log").read_text().splitlines()
            if name in {"design-tests", "discipline-tests", "hash-citations"}:
                print(name + ":\n" + "\n".join(lines)[-3000:])
                continue
            selected = []
            for index, line in enumerate(lines):
                if line.startswith("error") or '"level":"ERROR"' in line or line == "failures:" or "Blocking waiting" in line:
                    selected.extend(lines[index:index + 9])
                elif line.startswith("test result:"):
                    selected.append(line)
            if selected:
                print(name + ":\n" + "\n".join(selected)[:2600])
        return 0
    if mode == "token":
        status = absent(["<" + "char" + ">"], [])
        tracked = git("ls-files", "-z")
        tracked.check_returncode()
        forbidden = re.compile("<" + "char" + ">")
        for raw in tracked.stdout.split(b"\0"):
            if forbidden.search(os.fsdecode(raw)):
                print("prohibited pathname", os.fsdecode(raw))
                status = 1
        return status
    if mode == "hash-citations":
        from hash_citations import check
        tracked = git("ls-files", "-z")
        tracked.check_returncode()
        return check(pathlib.Path.cwd(), [os.fsdecode(path) for path in tracked.stdout.split(b"\0") if path])
    tracked = git("ls-files", "-z")
    tracked.check_returncode()
    sources = {}
    for raw_path in tracked.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = pathlib.Path(os.fsdecode(raw_path))
        if path.parts[0] != "vendor" and path.suffix == ".rs":
            sources[path] = path.read_text()
    tests = test_sources(sources)
    failed = False
    exposures = []
    for path, source in sources.items():
        for finding in source_findings(path, source, mode, path in tests):
            print(f"{path}: {finding}")
            failed = True
        if mode == "suppressions":
            exposures.extend(exposure_sites(path, source)[0])
    if mode == "suppressions":
        labels = [row["label"] for row in exposures if row["label"]]
        if len(labels) != len(set(labels)):
            print("SECRET-EXPOSURES duplicate labels")
            failed = True
        register = tomllib.loads(pathlib.Path("docs/inputs/secret-exposures.toml").read_text())["rows"]
        for finding in exposure_registry_findings(exposures, register):
            print(finding)
            failed = True
        config = tomllib.loads(pathlib.Path("clippy.toml").read_text())
        required = {"pn_host::secret::Buffer::expose_bytes", "pn_host::secret::Buffer::expose_storage", "secrecy::ExposeSecret::expose_secret", "secrecy::ExposeSecretMut::expose_secret_mut",
                    "secrecy::SecretBox::init_with_mut", "secrecy::SecretBox::init_with", "secrecy::SecretBox::try_init_with"}
        manifest = tomllib.loads(pathlib.Path("Cargo.toml").read_text())
        if not required <= {row["path"] for row in config["disallowed-methods"]} or manifest["workspace"]["lints"]["clippy"].get("disallowed_methods") != "deny":
            print("SECRET-EXPOSURES deny configuration missing")
            failed = True
        pathlib.Path(".lane/secret-exposures.json").write_text(json.dumps(exposures, indent=2) + "\n")
        print(f"SECRET-EXPOSURES sites={len(exposures)} labels={len(set(labels))} findings={int(failed)} artifact=.lane/secret-exposures.json")
        print(f"SUPPRESSIONS files={len(sources)} findings={int(failed)}")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
