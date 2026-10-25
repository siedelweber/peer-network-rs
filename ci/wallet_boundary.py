"""Cargo-identity and source confinement for the public Elements codec."""
from pathlib import Path
import re
import json
import subprocess
import tomllib
from dependency_identity import metadata, spellings
from source_sites import rust_mask

CODEC_PACKAGES = {'elements', 'bitcoin', 'bitcoin_hashes', 'secp256k1', 'secp256k1-zkp',
                  'secp256k1-sys', 'secp256k1-zkp-sys', 'bitcoin-consensus-encoding'}
ADAPTER = 'packages/wallet/src/decoder.rs'


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
    for row in profile['wallet_unified_features']:
        matches = [p for p in packages.values() if (p['name'], p['version']) == (row['name'], row['version'])]
        if len(matches) != 1 or sorted(nodes[matches[0]['id']]['features']) != sorted(row['features']):
            raise ValueError('wallet unified binding features differ: '+row['name'])
    for owner in ['pn-wallet', 'pn-host']:
        tree = subprocess.check_output(['cargo','tree','--offline','--locked','-p',owner,'--no-default-features','--edges','normal,build','--prefix','none','--format','{p}'], cwd=root, text=True)
        names = {line.split()[0] for line in tree.splitlines() if line.strip()}
        if 'dhat' in names or ('pn-wallet' in names and owner == 'pn-host'):
            raise ValueError('development dependency reached production graph')
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
                if re.search(r'\bpub\s+(?:\([^)]*\)\s*)?(?:use|extern\s+crate)\b', source):
                    raise ValueError('adapter re-export is not admitted')
                continue
            if re.search(r'\bSECP256K1\b', source) or any(
                    re.search(r'\b'+re.escape(alias)+r'\b', source) for alias in names):
                raise ValueError('codec path outside decoder adapter: '+name)
    return True
