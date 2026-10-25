"""Cargo-identity and source confinement for the public Elements codec."""
from pathlib import Path
import re
import json
import subprocess
import tomllib
import itertools
from discipline import item_end
from dependency_identity import metadata, spellings
from source_sites import rust_mask

CODEC_PACKAGES = {'elements', 'bitcoin', 'bitcoin_hashes', 'secp256k1', 'secp256k1-zkp',
                  'secp256k1-sys', 'secp256k1-zkp-sys', 'bitcoin-consensus-encoding'}
ADAPTER = 'packages/wallet/src/decoder.rs'


def delimiters(text):
    """Yield each bracket and comma with its depth change; a return arrow's > closes nothing."""
    for index, character in enumerate(text):
        if character in '<([{':
            yield index, character, 1
        elif character in ')]}' or (character == '>' and text[index-1:index] != '-'):
            yield index, character, -1
        elif character == ',':
            yield index, character, 0


def public_struct_types(body):
    """Return the struct's header, generic bounds, where clause and public fields."""
    # The field block follows the name and generics: a tuple struct's
    # parenthesis, otherwise the first top-level brace. Parentheses inside
    # generic bounds or a where clause, such as Fn() -> T, are header text.
    name = re.match(r'\s*\w+\s*', body)
    position = name.end() if name else 0
    depth = 0
    if body[position:position+1] == '<':
        for index, _, change in delimiters(body[position:]):
            depth += change
            if depth == 0:
                position += index + 1
                break
    rest = body[position:]
    opening = None
    if rest.lstrip().startswith('('):
        opening = position + len(rest) - len(rest.lstrip())
    else:
        depth = 0
        for index, character, change in delimiters(rest):
            if depth == 0 and character == '{':
                opening = position + index
                break
            depth += change
    if opening is None:
        return body
    depth = 0
    start = opening + 1
    exposed = [body[:opening]]
    for index, character, change in delimiters(body[opening:]):
        index += opening
        depth += change
        if (character == ',' and depth == 1) or depth == 0:
            field = body[start:index]
            if re.search(r'\bpub\b', field):
                exposed.append(field)
            start = index + 1
            if depth == 0:
                exposed.append(body[index + 1:])
                break
    return ' '.join(exposed)


def check_build_scripts(rows, packages):
    for row in rows:
        matches = [p for p in packages if (p['name'], p['version']) == (row['name'], row['version'])]
        if len(matches) != 1:
            raise ValueError('wallet build-script package missing: '+row['name'])
        package = matches[0]
        targets = [Path(t['src_path']).relative_to(Path(package['manifest_path']).parent).as_posix()
                   for t in package['targets'] if 'custom-build' in t['kind']]
        if targets != ([] if row['build'] == 'none' else [row['build']]):
            raise ValueError('wallet build-script field differs: '+row['name'])


def check_production_tree(owner, tree, allowed, host_wallet=False):
    actual = set(re.findall(r'^([^\s]+) v([^\s]+)', tree, re.M))
    names = {name for name, _ in actual}
    unknown = {name+' '+version for name, version in actual} - set(allowed[owner])
    if unknown or (owner == 'pn-host' and not host_wallet and 'pn-wallet' in names):
        raise ValueError('development dependency reached production graph: '+owner+' '+repr(sorted(unknown)))


def check_features(root=Path('.')):
    profile = tomllib.loads((root/'docs/inputs/devnet-profile.toml').read_text())['rows'][0]
    output = subprocess.check_output(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1',
                                      '--filter-platform', profile['wallet_evaluation_target']], cwd=root, text=True)
    data = json.loads(output)
    packages = {p['id']: p for p in data['packages']}
    nodes = {n['id']: n for n in data['resolve']['nodes']}
    evaluated = next(row for row in profile['wallet_candidates'] if row['name'] == 'elements')
    # The evaluation includes resolved optional packages. Check the actual normal
    # build subtree: metadata's workspace graph also joins unrelated test features.
    tree = subprocess.check_output(['cargo', 'tree', '--offline', '--locked', '-p',
        'pn-wallet', '--no-default-features', '--edges', 'normal,build', '--prefix',
        'depth', '--format', '{p}', '--no-dedupe', '--target',
        profile['wallet_evaluation_target']], cwd=root, text=True)
    resolved = set()
    inside = False
    for line in tree.splitlines():
        match = re.match(r'(\d+)(\S+) v(\S+)', line)
        if not match:
            continue
        depth, name, version = match.groups()
        if int(depth) == 1:
            inside = name == 'elements'
        if inside:
            resolved.add(name+' '+version)
    if 'elements 0.27.0' not in resolved or not resolved <= set(evaluated['packages']):
        raise ValueError('wallet decoder build exceeds evaluated packages: '+repr(sorted(resolved - set(evaluated['packages']))))
    lock = tomllib.loads((root/'Cargo.lock').read_text())['package']
    locked = {(p['name'],p['version']): p.get('checksum') for p in lock}
    for row in tomllib.loads((root/'docs/inputs/wallet-dependencies.toml').read_text())['rows']:
        if locked.get((row['name'],row['version'])) != row['checksum']:
            raise ValueError('wallet dependency checksum differs from reviewed pin')
    check_build_scripts(tomllib.loads((root/'docs/inputs/wallet-dependencies.toml').read_text())['rows'], packages.values())
    for row in profile['wallet_unified_features']:
        matches = [p for p in packages.values() if (p['name'], p['version']) == (row['name'], row['version'])]
        if len(matches) != 1 or sorted(nodes[matches[0]['id']]['features']) != sorted(row['features']):
            raise ValueError('wallet unified binding features differ: '+row['name'])
    allowed = json.loads((root/'ci/wallet-production-packages.json').read_text())
    for package in data['packages']:
        if package['id'] not in data['workspace_members']:
            continue
        owner = package['name']
        features = sorted(set(package['features']) - {'default'})
        combinations = [list(c) for n in range(len(features)+1) for c in itertools.combinations(features,n)]
        for defaults in [True, False]:
            for combination in combinations:
                args = [] if defaults else ['--no-default-features']
                if combination:
                    args += ['--features', ','.join(combination)]
                tree = subprocess.check_output(['cargo','tree','--offline','--locked','-p',owner,*args,
                    '--edges','normal,build','--prefix','none','--format','{p}'], cwd=root, text=True)
                check_production_tree(owner, tree, allowed, host_wallet='development-network' in combination)
    return True


def check(root=Path('.')):
    data = metadata(root)
    for package in data['packages']:
        directory = Path(package['manifest_path']).parent
        try:
            relative = directory.relative_to(root.resolve())
        except ValueError:
            continue
        if not relative.parts or relative.parts[0] != 'packages':
            continue
        names = spellings(data, package['name'], CODEC_PACKAGES)
        for path in directory.rglob('*.rs'):
            original = path.read_text()
            if path.name == 'observation_metrics.rs' and package['name'] == 'cli-common':
                generated = rust_mask((path.parent/'observation_operations.rs').read_text())
                if not re.fullmatch(r'\s*pub\(super\)\s+const\s+RECORDS_OPERATIONS:\s*\[&str;\s*\d+\]\s*=\s*\[[\s,]*\];\s*', generated):
                    raise ValueError('reviewed operation vocabulary is not a string constant')
                original = original.replace('include!("observation_operations.rs");','',1)
            source = rust_mask(original)
            name = path.relative_to(root.resolve()).as_posix()
            if re.search(r'\binclude\s*!', source):
                raise ValueError('codec confinement requires reviewed include expansion: '+name)
            if name == ADAPTER:
                if re.search(r'\bpub(?:\s*\([^)]*\))?\s+(?:use|extern\s+crate)\b', source):
                    raise ValueError('adapter re-export is not admitted')
                if re.search(r'\bpub\s*(?:\([^)]*\)\s*)?type\b', source):
                    raise ValueError('adapter public type alias is not admitted')
                # Follow local aliases as well as Cargo's resolved spellings.
                tainted = set(names)
                for _ in range(len(source.splitlines())):
                    before = set(tainted)
                    for declaration in re.finditer(r'\b(use|type)\s+([^;]+);', source):
                        body = declaration.group(2)
                        if any(re.search(r'\b'+re.escape(alias)+r'\b', body) for alias in tainted):
                            if declaration.group(1) == 'type':
                                tainted.add(re.match(r'\s*(\w+)', body).group(1))
                            else:
                                if '*' in body:
                                    raise ValueError('adapter codec glob import is not admitted')
                                # Only the imported binding is introduced. In
                                # `Transaction as Hidden`, Transaction may also
                                # name our unrelated first-party projection.
                                for part in body.split(','):
                                    binding = re.search(r'(\w+)\s*[}]*\s*$', part)
                                    if binding:
                                        tainted.add(binding.group(1))
                    if before == tainted:
                        break
                for signature in re.finditer(r'\bpub\s*(?:\([^)]*\)\s*)?(?:(?:async|const|unsafe|extern)\s+)*fn\b[^{};]*', source):
                    if any(re.search(r'\b'+re.escape(alias)+r'\b', signature.group()) for alias in tainted):
                        raise ValueError('adapter public signature carries codec type')
                for declaration in re.finditer(r'\bpub\s*(?:\([^)]*\)\s*)?(struct|enum|const|static)\b', source):
                    kind = declaration.group(1)
                    body = source[declaration.end():item_end(source, declaration.start())]
                    if kind in ('const', 'static'):
                        # A const fn was checked above; an item's declared type
                        # ends before its initializer, which is not exported.
                        if re.match(r'\s+fn\b', body):
                            continue
                        exposed = body.split('=', 1)[0]
                    elif kind == 'enum':
                        # Every variant of an exported enum is exported too.
                        exposed = body
                    else:
                        # Include generic bounds and public named/tuple fields,
                        # while allowing private codec storage in a wrapper.
                        exposed = public_struct_types(body)
                    if any(re.search(r'\b'+re.escape(alias)+r'\b', exposed) for alias in tainted):
                        raise ValueError('adapter public '+kind+' carries codec type')
                production = list(source)
                # Only unconditional cfg(test) removes a production item.
                for marker in re.finditer(r'#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]', source):
                    end = item_end(source, marker.end())
                    production[marker.start():end] = ' ' * (end-marker.start())
                if re.search(r'\bSECP256K1\b', ''.join(production)):
                    raise ValueError('adapter production global context is not admitted')
                continue
            if re.search(r'\bSECP256K1\b', source) or any(
                    re.search(r'\b'+re.escape(alias)+r'\b', source) for alias in names):
                raise ValueError('codec path outside decoder adapter: '+name)
    return True
