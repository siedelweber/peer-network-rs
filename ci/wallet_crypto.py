"""Bind the codec's resolved packages, bundled C modules, C provenance and compiler to their reviewed records."""
import json
from pathlib import Path
import re
import subprocess
import tomllib

# Bundled C snapshots as record 023 states them. Each module is witnessed by
# one exported function of its public header, found in the built archive's
# symbol index; a module outside the reviewed set must leave no symbol.
SNAPSHOTS = {
    'secp256k1-sys': dict(
        version='0.10.1',
        revision='1ad5185cd42c0636104129fcc9f6a4bf9c67cc40',
        library='libsecp256k1.a',
        prefix='rustsecp256k1_v0_10_0_',
        enabled={'ECDH': 'ecdh', 'SCHNORRSIG': 'schnorrsig_sign32', 'EXTRAKEYS': 'xonly_pubkey_parse',
                 'ELLSWIFT': 'ellswift_encode'},
        absent={'RECOVERY': 'ecdsa_recover'},
        families={'context', 'ec', 'ecdh', 'ecdsa', 'ecmult', 'ellswift', 'keypair', 'nonce', 'pre', 'schnorrsig',
                  'selftest', 'tagged', 'xonly'},
    ),
    'secp256k1-zkp-sys': dict(
        version='0.10.1',
        revision='6152622613fdf1c5af6f31f74c427c4e9ee120ce',
        library='libsecp256k1zkp.a',
        prefix='rustsecp256k1zkp_v0_10_0_',
        enabled={'SURJECTIONPROOF': 'surjectionproof_parse', 'GENERATOR': 'generator_parse',
                 'RANGEPROOF': 'rangeproof_info', 'ECDSA_ADAPTOR': 'ecdsa_adaptor_encrypt',
                 'WHITELIST': 'whitelist_sign'},
        absent={'RECOVERY': 'ecdsa_recover', 'MUSIG': 'musig_nonce_gen', 'ECDSA_S2C': 'ecdsa_s2c_sign',
                'SCHNORRSIG': 'schnorrsig_sign32', 'ECDH': 'ecdh'},
        families={'context', 'ec', 'ecdsa', 'ecmult', 'generator', 'nonce', 'pedersen', 'pre', 'rangeproof', 'selftest',
                  'surjectionproof', 'tagged', 'whitelist'},
    ),
}


def archive_symbols(data):
    """Global symbols from a System V archive's symbol index."""
    if data[:8] != b'!<arch>\n':
        raise ValueError('codec archive is not a static library')
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        name, size = header[:16].strip(), int(header[48:58])
        body = data[offset + 60:offset + 60 + size]
        if name in (b'/', b'/SYM64/'):
            width = 8 if name == b'/SYM64/' else 4
            count = int.from_bytes(body[:width], 'big')
            return set(part.decode() for part in body[width * (count + 1):].split(b'\0')[:count])
        offset += 60 + size + (size & 1)
    raise ValueError('codec archive has no symbol index')


def check_modules(package, symbols):
    spec = SNAPSHOTS[package]
    missing = sorted(module for module, name in spec['enabled'].items() if spec['prefix'] + name not in symbols)
    extra = sorted(module for module, name in spec['absent'].items() if spec['prefix'] + name in symbols)
    # Exported names group by module family; any family outside the review is an unreviewed module.
    families = {name[len(spec['prefix']):].split('_')[0] for name in symbols if name.startswith(spec['prefix'])}
    if missing or extra or families != spec['families']:
        raise ValueError(f'codec C modules differ: {package} missing={missing} unreviewed={extra} '
                         f'families={sorted(families ^ spec["families"])}')


def reviewed_compiler(root):
    """The channel and full rustc commit the build policy pins: the one statement of the reviewed compiler."""
    row = next(row for row in tomllib.loads((root/'docs/inputs/build-policy.toml').read_text())['rows']
               if row.get('name') == 'workspace')
    return row['channel'], row['rustc_commit']


def check_channel(channel, pinned):
    if channel != pinned:
        raise ValueError('workspace compiler differs from the reviewed pin')


def check_answering(verbose, commit):
    """The answering rustc reports the pinned commit; agreement with its own libraries is not enough."""
    fields = dict(line.split(': ', 1) for line in verbose.splitlines() if ': ' in line)
    if fields.get('commit-hash') != commit:
        raise ValueError('answering compiler differs from the pinned commit')


def check_provenance(package, revision_file):
    revisions = re.findall(r'^[0-9a-f]{40}$', revision_file, re.M)
    if revisions != [SNAPSHOTS[package]['revision']]:
        raise ValueError(f'codec C provenance differs: {package} {revisions}')


def check_compiler(package, rlib, version, commit):
    """The library embeds exactly one compiler identity: the answering one, carrying the pinned commit."""
    found = set(re.findall(rb'rustc [0-9][^\s()]* \(([0-9a-f]{7,40}) [0-9]{4}-[0-9]{2}-[0-9]{2}\)', rlib))
    if (not version.startswith('rustc ') or version.encode() not in rlib or len(found) != 1
            or not commit.startswith(found.pop().decode())):
        raise ValueError(f'codec built by another compiler: {package}')


def check_checksums(lock, rows, tree):
    """Every registry package of the wallet's normal and build closure has its reviewed archive checksum."""
    reviewed = {}
    for row in rows:
        key = (row['name'], row['version'])
        if row.get('checksum') and reviewed.setdefault(key, row['checksum']) != row['checksum']:
            raise ValueError('reviewed archive checksums disagree: ' + ' '.join(key))
    locked = {(p['name'], p['version']): p.get('checksum') for p in lock['package']}
    for key in sorted(tree):
        if locked.get(key) is None:
            continue
        if reviewed.get(key) != locked[key]:
            raise ValueError('codec archive checksum differs from review: ' + ' '.join(key))


def check_record(record, channel):
    """The record states the revisions, modules and compiler this check enforces."""
    for package, spec in SNAPSHOTS.items():
        for value in [spec['revision'], *spec['enabled']]:
            if value not in record:
                raise ValueError(f'codec record omits {package} {value}')
    if channel not in record:
        raise ValueError('codec record omits the pinned compiler')


def build_artifacts(root):
    output = subprocess.run(['cargo', 'build', '--offline', '--locked', '--profile', 'gate', '-p', 'pn-wallet',
                             '--message-format=json'], cwd=root, capture_output=True, text=True, check=True).stdout
    artifacts = {}
    for line in output.splitlines():
        message = json.loads(line)
        package = re.search(r'#([\w-]+)@', message.get('package_id', ''))
        if not package or package.group(1) not in SNAPSHOTS:
            continue
        entry = artifacts.setdefault(package.group(1), {})
        if message['reason'] == 'build-script-executed':
            entry['out_dir'] = Path(message['out_dir'])
        elif message['reason'] == 'compiler-artifact' and 'custom-build' not in message['target']['kind']:
            entry['rlib'] = next(Path(name) for name in message['filenames'] if name.endswith('.rlib'))
            entry['manifest'] = Path(message['manifest_path']).parent
            entry['version'] = message['package_id'].rsplit('@', 1)[1]
    return artifacts


def check(root=Path('.')):
    root = root.resolve()
    channel, commit = reviewed_compiler(root)
    check_channel(tomllib.loads((root/'rust-toolchain.toml').read_text())['toolchain']['channel'], channel)
    answer = lambda flag: subprocess.run(['rustc', flag], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
    check_answering(answer('-vV'), commit)
    version = answer('-V')
    check_record((root/'adr/023-cryptographic-base.md').read_text(), channel)
    tree = subprocess.check_output(['cargo', 'tree', '--offline', '--locked', '-p', 'pn-wallet', '--edges', 'normal,build',
                                    '--prefix', 'none', '--format', '{p}', '--no-dedupe'], cwd=root, text=True)
    packages = set(re.findall(r'^([^\s]+) v([^\s]+)', tree, re.M))
    # Shared packages keep their earlier host review; wallet-only packages carry the wallet review.
    # The host register spells each name with its version, as "name version".
    rows = [dict(row, name=row['name'].split()[0]) for name in ('wallet', 'host')
            for row in tomllib.loads((root/f'docs/inputs/{name}-dependencies.toml').read_text())['rows']]
    check_checksums(tomllib.loads((root/'Cargo.lock').read_text()), rows, packages)
    artifacts = build_artifacts(root)
    for package, spec in SNAPSHOTS.items():
        entry = artifacts.get(package, {})
        if set(entry) != {'out_dir', 'rlib', 'manifest', 'version'} or entry['version'] != spec['version']:
            raise ValueError('codec build artifacts incomplete: ' + package)
        check_provenance(package, (entry['manifest']/'depend/secp256k1-HEAD-revision.txt').read_text())
        check_modules(package, archive_symbols((entry['out_dir']/spec['library']).read_bytes()))
        check_compiler(package, entry['rlib'].read_bytes(), version, commit)
    print(f'WALLET-CODEC-ARTIFACTS packages={len(packages)} snapshots={len(SNAPSHOTS)} compiler="{version}"')
    return True


if __name__ == '__main__':
    check()
