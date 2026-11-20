"""Provision locked public archives and Git objects separately from offline gates."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request
from discipline import vendor_packages
from installation_inventory import catalogue, committed_lock, git, lock_packages, require_coverage

COMMAND = 'python3 -B ci/provision_vendor.py'


def check_installation_notices(root):
    """Keep the locked fetch and tracked path closure covered before any import pays."""
    commit = git(root, 'rev-parse', 'HEAD').decode().strip()
    reviewed = require_coverage(root, catalogue(root, commit=commit), commit)
    print(f'INSTALLATION-NOTICES reviewed={len(reviewed)} status=covered', flush=True)
    return reviewed


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


def provision_git_objects(root, packages):
    """Prepare the one locked Git repository at its declared offline input."""
    sources = {item['source'] for item in packages if item.get('source', '').startswith('git+')}
    if len(sources) != 1:
        raise ValueError('Git object provisioning requires one locked repository')
    source = sources.pop()
    location, revision = source[4:].split('?rev=', 1)
    revision, pinned = revision.split('#', 1)
    if not location.startswith('https://') or not re.fullmatch(r'[0-9a-f]{40}', revision) or pinned != revision:
        raise ValueError('locked Git source has an unsupported locator')
    declared = os.environ.get('PN_INSTALLATION_GIT_OBJECTS', '')
    destination = Path(declared)
    if not declared or not destination.is_absolute() or destination.is_relative_to(root.resolve()) or destination.is_symlink():
        raise ValueError('declare an absolute PN_INSTALLATION_GIT_OBJECTS outside the checkout before provisioning')
    if destination.exists():
        try:
            git(destination, 'cat-file', '-e', f'{revision}^{{commit}}')
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError(f'locked Git object missing: {revision}; reprovision PN_INSTALLATION_GIT_OBJECTS') from error
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='installation-git-', dir=destination.parent) as directory:
            staged = Path(directory) / 'objects.git'
            fetched = subprocess.run(['git', 'clone', '--mirror', location, str(staged)],
                                     capture_output=True, text=True, check=False)
            if fetched.returncode != 0:
                raise ValueError(f'locked Git source fetch failed: {location} status={fetched.returncode}')
            try:
                git(staged, 'cat-file', '-e', f'{revision}^{{commit}}')
            except (OSError, subprocess.CalledProcessError) as error:
                raise ValueError(f'fetched Git repository lacks locked object: {revision}') from error
            os.replace(staged, destination)
    print(f'GIT-PROVISION revision={revision} directory={destination} status=verified', flush=True)


def provision(root):
    """Provision the complete locked registry closure outside an offline gate."""
    packages = lock_packages(committed_lock(root, git(root, 'rev-parse', 'HEAD').decode().strip()))
    rows = {(item['name'], item['version'], item['checksum']) for item in packages
            if item.get('source', '').startswith('registry+')}
    for row in vendor_packages(root):
        if row['mode'] != 'patch':
            continue
        evidence = json.loads((root / row['content_manifest']).read_text())
        if (evidence['name'], evidence['version']) != (row['name'], row['version']):
            raise ValueError('vendor archive provisioning identity differs')
        checksum = evidence['archive_checksum']
        if not re.fullmatch(r'[0-9a-f]{64}', checksum):
            raise ValueError('invalid vendor archive checksum')
        rows.add((row['name'], row['version'], checksum))
    for name, version, checksum in sorted(rows):
        try:
            path = checked_archive(root, name, version, checksum)
        except ValueError:
            path = fetch_archive(root, name, version, checksum)
        print(f'VENDOR-ARCHIVE name={name} version={version} checksum={checksum} path={path} status=verified', flush=True)
    print(f'VENDOR-PROVISION archives={len(rows)} directory={archive_directory(root)} status=verified', flush=True)
    provision_git_objects(root, packages)


if __name__ == '__main__':
    provision(Path.cwd())
