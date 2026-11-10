"""Reproduce the wallet's admitted pins for the authentication edge; no duplicate pins."""
import json
from pathlib import Path
import re
import subprocess
import tomllib
import wallet_crypto
import wallet_boundary

BACKEND = 'packages/act-authentication/src/verification/backend.rs'
ITEMS = {
    'secp256k1_zkp::XOnlyPublicKey',
    'secp256k1_zkp::XOnlyPublicKey::from_slice',
    'secp256k1_zkp::schnorr::Signature::from_slice',
    'secp256k1_zkp::Message::from_digest',
    'secp256k1_zkp::Secp256k1::preallocated_verification_only',
    'secp256k1_zkp::ffi::types::AlignedType::zeroed',
}


def check_sources(sources):
    """One explicit backend; no aliases, re-exports, global context or other operations."""
    found = set()
    for name, source in sources.items():
        code = wallet_boundary.rust_mask(source)
        if name != BACKEND:
            if re.search(r'\b(?:secp256k1\w*|elements|bitcoin)::', code):
                raise ValueError('authentication binding outside backend')
            continue
        if re.search(r'\b(?:use|extern|unsafe|macro_rules)\b|\bas\b', code):
            raise ValueError('authentication backend alias or escape')
        paths = set(re.findall(r'\bsecp256k1_zkp::[A-Za-z0-9_:]+', code))
        if paths != ITEMS:
            raise ValueError('authentication admitted binding items differ')
        methods = re.findall(r'\.([a-zA-Z_]\w*)\s*\(', code)
        if sorted(methods) != ['map', 'map_err', 'map_err', 'map_err', 'map_err', 'verify_schnorr']:
            raise ValueError('authentication backend method set differs')
        if re.search(r'\b(?:SECP256K1|secp256k1_sys|secp256k1_zkp_sys)\b', code):
            raise ValueError('authentication unadmitted native path')
        if re.findall(r'#[\s]*\[derive\(([^)]*)\)\]', code) != ['Clone, Copy, Debug']:
            raise ValueError('authentication backend derived operation differs')
        if 'struct Key(secp256k1_zkp::XOnlyPublicKey);' not in code:
            raise ValueError('authentication backend key must remain opaque')
        found = paths
    if found != ITEMS:
        raise ValueError('authentication backend missing')


def check(root=Path('.')):
    root = root.resolve()
    check_sources({p.relative_to(root).as_posix(): p.read_text()
                   for p in (root/'packages/act-authentication/src').rglob('*.rs')})
    wallet_boundary.check_features(root)
    channel, commit = wallet_crypto.reviewed_compiler(root)
    wallet_crypto.check_channel(tomllib.loads((root/'rust-toolchain.toml').read_text())['toolchain']['channel'], channel)
    answer = lambda flag: subprocess.check_output(['rustc', flag], cwd=root, text=True).strip()
    wallet_crypto.check_answering(answer('-vV'), commit)
    version = answer('-V')
    tree = subprocess.check_output(['cargo', 'tree', '--offline', '--locked', '-p', 'pn-act-authentication',
                                   '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}', '--no-dedupe'], cwd=root, text=True)
    packages = set(re.findall(r'^([^\s]+) v([^\s]+)', tree, re.M))
    rows = [dict(row, name=row['name'].split()[0]) for name in ('wallet', 'host')
            for row in tomllib.loads((root/f'docs/inputs/{name}-dependencies.toml').read_text())['rows']]
    wallet_crypto.check_checksums(tomllib.loads((root/'Cargo.lock').read_text()), rows, packages, root)
    check_artifacts(root, version, commit)
    return dict(packages=len(packages), binding_items=sorted(ITEMS), method='verify_schnorr', compiler=version)


def check_artifacts(root, version, commit):
    """Bind this package's actual sys artifacts to the existing wallet records."""
    artifacts = wallet_crypto.build_artifacts(root, 'pn-act-authentication')
    for name, spec in wallet_crypto.SNAPSHOTS.items():
        entry = artifacts[name]
        if entry['version'] != spec['version']:
            raise ValueError('authentication artifact version differs')
        wallet_crypto.check_provenance(name, (entry['manifest']/'depend/secp256k1-HEAD-revision.txt').read_text())
        wallet_crypto.check_modules(name, wallet_crypto.archive_symbols((entry['out_dir']/spec['library']).read_bytes()))
        wallet_crypto.check_compiler(name, entry['rlib'].read_bytes(), version, commit)


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
