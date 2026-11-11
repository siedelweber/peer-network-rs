"""Reproduce the wallet's admitted pins for the authentication edge; no duplicate pins."""
import re
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
        if re.search(r'>\s*::', code):
            raise ValueError('authentication qualified type call')
        calls = {re.sub(r'\s+', '', call) for call in
                 re.findall(r'\b(?:[A-Za-z_]\w*\s*::\s*)+[A-Za-z_]\w*\s*(?=\()', code)}
        # Attribute instrumentation and test-only stage witnesses are not binding calls.
        if calls - ITEMS - {'super::tests::visit', 'tracing::instrument'}:
            raise ValueError('authentication unlisted qualified call')
        if re.search(r'::\s*<', code):
            raise ValueError('authentication turbofish call')
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
