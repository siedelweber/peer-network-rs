"""Provision checksum-pinned public vendor archives separately from offline gates."""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request
from discipline import vendor_packages

COMMAND = 'python3 -B ci/provision_vendor.py'


def archive_directory(root):
    """A declared external input, never Cargo's incidental registry cache."""
    directory = Path(os.environ.get('PN_VENDOR_ARCHIVES', '~/.cache/peer-network/vendor-archives')).expanduser().resolve()
    if directory.is_relative_to(root.resolve()):
        raise ValueError('vendor archive directory must be outside the repository')
    return directory


def archive_name(name, version):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', name) or not re.fullmatch(r'[A-Za-z0-9.+_-]+', version):
        raise ValueError('invalid vendor archive identity')
    return f'{name}-{version}.crate'


def checked_archive(root, name, version, checksum):
    """Read exactly one pinned archive offline; never search or fetch."""
    path = archive_directory(root) / archive_name(name, version)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f'vendor archive unavailable: {path}; provision with {COMMAND}')
    if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
        raise ValueError(f'vendor archive checksum differs: {path}; provision with {COMMAND}')
    return path


def fetch_archive(root, name, version, checksum, opener=urllib.request.urlopen):
    """Verify before atomic installation; a failed fetch leaves no new archive."""
    filename = archive_name(name, version)
    url = f'https://static.crates.io/crates/{name}/{filename}'
    with opener(url) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError(f'vendor archive fetch checksum differs: {filename}')
    directory = archive_directory(root)
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, directory / filename)
        finally:
            temporary.unlink(missing_ok=True)
    return checked_archive(root, name, version, checksum)


def provision(root):
    """Fetch only the excluded packages named by the committed vendor list."""
    rows = []
    for row in vendor_packages(root):
        if row['mode'] != 'patch':
            continue
        evidence = json.loads((root / row['content_manifest']).read_text())
        if (evidence['name'], evidence['version']) != (row['name'], row['version']):
            raise ValueError('vendor archive provisioning identity differs')
        checksum = evidence['archive_checksum']
        if not re.fullmatch(r'[0-9a-f]{64}', checksum):
            raise ValueError('invalid vendor archive checksum')
        rows.append((row['name'], row['version'], checksum))
    for name, version, checksum in rows:
        path = fetch_archive(root, name, version, checksum)
        print(f'VENDOR-ARCHIVE name={name} version={version} checksum={checksum} path={path} status=verified', flush=True)
    print(f'VENDOR-PROVISION archives={len(rows)} directory={archive_directory(root)} status=verified', flush=True)


if __name__ == '__main__':
    provision(Path.cwd())
