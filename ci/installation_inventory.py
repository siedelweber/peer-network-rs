"""Source and notice inventories for the installation import witness.

The lock and Git objects establish expected bytes. A separately supplied source
view establishes captured bytes. Neither manifest is made from the other.
"""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tomllib


NOTICE_OWNERS = frozenset({
    'packages/graph/NOTICE-DEPENDENCIES',
    'packages/host/NOTICE-DEPENDENCIES',
    'packages/wallet/NOTICE-DEPENDENCIES',
    'packages/wallet/fuzz/NOTICE-DEPENDENCIES',
    'packages/records/NOTICE-NUMERIC',
    'docs/HTTP-NOTICES',
    'docs/NODE-NOTICES',
})
FOLLOWED_OWNER = 'docs/inputs/host-dependencies.toml'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def row(kind, identity, data):
    return {'kind': kind, 'identity': identity, 'sha256': digest(data)}


def checked_provenance(root, commit, versions, components, selection):
    """Bind answering tools and package-alone selection to committed policy."""
    from discipline import validate_toolchain
    toolchain = tomllib.loads(git(root, 'show', f'{commit}:rust-toolchain.toml').decode())['toolchain']
    policy = tomllib.loads(git(root, 'show', f'{commit}:docs/inputs/build-policy.toml').decode())['rows'][0]
    validate_toolchain(toolchain['channel'], versions, components, policy['rustc_commit'])
    expected = [
        {'package': 'pn', 'bin': 'pn'},
        {'package': 'pn-credential-generator', 'bin': 'pn-credential-generator'},
    ]
    if selection.get('targets') != expected or selection.get('profile') != 'release' or selection.get('features') != 'default':
        raise ValueError('installation release selection differs')
    host = re.findall(r'^host: (\S+)$', versions[0], re.M)
    if host != [selection.get('target')]:
        raise ValueError('installation target differs from answering native compiler')
    root_manifest = tomllib.loads(git(root, 'show', f'{commit}:Cargo.toml').decode())
    if root_manifest.get('profile', {}).get('release') != {'lto': 'thin', 'codegen-units': 1}:
        raise ValueError('installation release profile differs')
    for target in expected:
        member = 'packages/node' if target['package'] == 'pn' else 'packages/credential-generator'
        manifest = tomllib.loads(git(root, 'show', f'{commit}:{member}/Cargo.toml').decode())
        if manifest['package']['name'] != target['package'] or not any(binary['name'] == target['bin'] for binary in manifest.get('bin', [])):
            raise ValueError('installation binary target differs')
    return {
        'toolchain_channel': toolchain['channel'],
        'toolchain_components': sorted(components),
        'answering_versions': versions,
        'rustc_commit': policy['rustc_commit'],
        'release_profile': root_manifest['profile']['release'],
        'selection': selection,
    }


def checked_rows(rows):
    result = sorted(rows, key=lambda item: (item['kind'], item['identity']))
    if not result or len({(item['kind'], item['identity']) for item in result}) != len(result):
        raise ValueError('installation inventory rows are empty or duplicated')
    return result


def git(repo, *args):
    environment = dict(os.environ, GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1')
    completed = subprocess.run(['git', '-C', str(repo), *args], check=True, stdout=subprocess.PIPE, env=environment)
    return completed.stdout


def committed_lock(root, commit):
    return git(root, 'show', f'{commit}:Cargo.lock')


def lock_packages(data):
    packages = tomllib.loads(data.decode())['package']
    identities = set()
    for package in packages:
        key = (package['name'], package['version'], package.get('source', 'path'))
        if key in identities:
            raise ValueError('duplicate locked package identity')
        identities.add(key)
    return packages


def source_key(package):
    name = f"{package['name']}@{package['version']}"
    source = package.get('source', '')
    if source.startswith('registry+'):
        return 'registry', name
    if source.startswith('git+'):
        return 'git', f"{name}#{source.rsplit('#', 1)[-1]}"
    if source:
        raise ValueError(f'unsupported locked source: {source}')
    return 'path', name


def path_sources(root, commit, packages):
    """Join locked path identities to declared members and vendor packages."""
    workspace = tomllib.loads(git(root, 'show', f'{commit}:Cargo.toml').decode())['workspace']
    vendors = tomllib.loads(git(root, 'show', f'{commit}:ci/vendor-packages.toml').decode()).get('packages', [])
    vendor_paths = {item['path'] for item in vendors}
    paths = set(workspace['members']) | vendor_paths
    by_identity = {}
    for path in paths:
        manifest = tomllib.loads(git(root, 'show', f'{commit}:{path}/Cargo.toml').decode())['package']
        version = manifest['version']
        if version == {'workspace': True}:
            version = workspace['package']['version']
        key = f"{manifest['name']}@{version}"
        if key in by_identity:
            raise ValueError(f'ambiguous declared path source: {key}')
        by_identity[key] = (path, path in vendor_paths)
    result = {}
    for package in packages:
        source, identity = source_key(package)
        if source == 'path':
            if identity not in by_identity:
                raise ValueError(f'undeclared locked path source: {identity}')
            result[identity] = by_identity[identity]
    return result


def first_party_notice_paths(root, commit, path):
    """A tracked path is notice-named when its final component begins with uppercase LICENSE, LICENCE, NOTICE, COPYING or COPYRIGHT, followed only by end of name or -, _ or ."""
    names = git(root, 'ls-tree', '-r', '--name-only', '-z', commit, '--', path).split(b'\0')
    prefix = path.rstrip('/') + '/'
    stems = ('LICENSE', 'LICENCE', 'NOTICE', 'COPYING', 'COPYRIGHT')
    return sorted(name for raw in names if raw
                  if (name := raw.decode('utf-8')).startswith(prefix)
                  if any(PurePosixPath(name).name == stem or
                         PurePosixPath(name).name.startswith((stem + '-', stem + '_', stem + '.'))
                         for stem in stems))


def first_party_projection(root, commit, package, path):
    """Bind licence members without binding unrelated first-party code."""
    manifest = tomllib.loads(git(root, 'show', f'{commit}:{path}/Cargo.toml').decode())['package']
    workspace = tomllib.loads(git(root, 'show', f'{commit}:Cargo.toml').decode())['workspace'].get('package', {})
    licence = manifest.get('license')
    inherited = licence == {'workspace': True}
    resolved = workspace.get('license') if inherited else licence
    reference = manifest.get('license-file')
    if not isinstance(resolved, str) and not isinstance(reference, str):
        raise ValueError(f'first-party licence declaration missing: {path}')
    if reference is not None and not isinstance(reference, str):
        raise ValueError(f'invalid first-party licence reference: {path}')
    files = []
    if reference is not None:
        relative = PurePosixPath(reference)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError(f'escaping first-party licence reference: {path}')
        source_path = f'{path}/{reference}'
        files.append({'path': source_path, 'sha256': digest(git(root, 'show', f'{commit}:{source_path}'))})
    projection = {'manifest': f'{path}/Cargo.toml', 'name': manifest['name'],
                  'version': package['version'], 'member': 'license',
                  'raw': licence, 'workspace_member': 'workspace.package.license' if inherited else None,
                  'workspace_value': workspace.get('license') if inherited else None,
                  'resolved': resolved, 'license_file': reference, 'license_files': files,
                  'notice_paths': first_party_notice_paths(root, commit, path)}
    return projection


def catalogue(root, path=None, commit=None):
    if path is not None:
        source = Path(path).read_bytes()
    elif commit is not None:
        source = git(root, 'show', f'{commit}:ci/installation-notices.json')
    else:
        source = (root / 'ci/installation-notices.json').read_bytes()
    document = json.loads(source)
    if set(document) != {'schema', 'entries'} or document['schema'] != 2 or not isinstance(document['entries'], list):
        raise ValueError('invalid installation notice catalogue')
    result = {}
    for entry in document['entries']:
        source = entry.get('source')
        identity = entry.get('identity')
        key = (source, identity)
        if source not in {'registry', 'git', 'path'} or not isinstance(identity, str) or key in result:
            raise ValueError('duplicate or invalid installation notice identity')
        if not isinstance(entry.get('owners'), list):
            raise ValueError(f'invalid notice owner: {identity}')
        if source == 'path' and not isinstance(entry.get('path'), str):
            raise ValueError(f'missing path source location: {identity}')
        if source == 'git' and not isinstance(entry.get('repository'), str):
            raise ValueError(f'missing Git source location: {identity}')
        notices = entry.get('evidence')
        if not isinstance(notices, list) or not notices:
            raise ValueError(f'invalid notice evidence: {identity}')
        seen = set()
        for notice in notices:
            if notice.get('kind') not in {'notice-file', 'embedded-statement', 'declaration-only'}:
                raise ValueError(f'invalid notice kind: {identity}')
            relative = PurePosixPath(notice.get('path', ''))
            signature = (relative.as_posix(), notice['kind'], notice.get('first_line'), notice.get('last_line'))
            if relative.is_absolute() or '..' in relative.parts or not relative.parts or signature in seen:
                raise ValueError(f'invalid notice path: {identity}')
            seen.add(signature)
        if any(n['kind'] == 'declaration-only' for n in notices) and len(notices) != 1:
            raise ValueError(f'declaration-only evidence is not exclusive: {identity}')
        review = entry.get('review')
        if not isinstance(review, dict) or not isinstance(review.get('inspection'), str) or not review['inspection']:
            raise ValueError(f'missing installation notice review: {identity}')
        if review.get('scope') == 'first-party-notice':
            if not isinstance(review.get('declaration_projection'), dict) or not isinstance(review.get('declaration_projection_sha256'), str) or 'member_map' in review or 'member_map_sha256' in review:
                raise ValueError(f'invalid first-party notice scope: {identity}')
        elif not isinstance(review.get('member_map'), list) or not isinstance(review.get('member_map_sha256'), str):
            raise ValueError(f'missing complete member map: {identity}')
        result[key] = entry
    return result


def archive_material(data, name, version):
    """Use the verified archive's complete member map, including modes and links."""
    import io
    prefix = f'{name}-{version}/'
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive.getmembers():
            if not member.name.startswith(prefix):
                raise ValueError(f'archive source root differs: {name}@{version}')
            path = member.name[len(prefix):]
            relative = PurePosixPath(path)
            if not path or relative.is_absolute() or '..' in relative.parts:
                raise ValueError('archive has escaping source path')
            if member.isdir():
                continue
            if path in result:
                raise ValueError('archive has duplicate source path')
            if member.isfile():
                result[path] = ('100755' if member.mode & 0o111 else '100644', archive.extractfile(member).read(), None)
            elif member.issym():
                result[path] = ('120000', member.linkname.encode(), member.linkname)
            else:
                raise ValueError('archive has unsupported source kind')
    if not result:
        raise ValueError('archive source is empty')
    return result


def members(material):
    return [{'path': path, 'kind': 'symlink' if mode == '120000' else 'file',
             'mode': mode, 'sha256': digest(data), 'target': target}
            for path, (mode, data, target) in sorted(material.items())]


def git_source_repository(location, git_sources=None, revision=None):
    if git_sources is not None:
        if location not in git_sources:
            raise ValueError(f'locked Git source missing: {location}')
        return Path(git_sources[location][0])
    if revision is None:
        raise ValueError('locked Git revision is absent')
    declared = os.environ.get('PN_INSTALLATION_GIT_OBJECTS', '')
    repository = Path(declared)
    if not repository.is_absolute() or not repository.is_dir():
        raise ValueError(f'locked Git source missing: {location}; provision PN_INSTALLATION_GIT_OBJECTS before the gate')
    found = subprocess.run(['git', '-C', str(repository), 'cat-file', '-e', f'{revision}^{{commit}}'],
                           capture_output=True, env=dict(os.environ, GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1'))
    if found.returncode != 0:
        raise ValueError(f'locked Git source object missing: {location}; provision PN_INSTALLATION_GIT_OBJECTS before the gate')
    return repository


def package_manifest(material, name, version, workspace_version=None):
    matches = []
    for path, (_, data, _) in material.items():
        if path != 'Cargo.toml' and not path.endswith('/Cargo.toml'):
            continue
        try:
            package = tomllib.loads(data.decode()).get('package', {})
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            continue
        declared = package.get('version')
        if declared == {'workspace': True}:
            declared = workspace_version or tomllib.loads(material['Cargo.toml'][1].decode()).get('workspace', {}).get('package', {}).get('version')
        if package.get('name') == name and declared == version:
            matches.append(path)
    if len(matches) != 1:
        raise ValueError(f'package manifest missing or ambiguous: {name}@{version}')
    return matches[0]


def verified_material(root, commit, package, entry, archives, git_sources, tracked):
    source, identity = source_key(package)
    name, version = package['name'], package['version']
    if source == 'registry':
        try:
            data = (archives / f'{name}-{version}.crate').read_bytes()
        except OSError as error:
            raise ValueError(f'registry archive missing: {identity}; provision PN_VENDOR_ARCHIVES before the gate') from error
        if digest(data) != package['checksum']:
            raise ValueError(f'registry checksum differs: {identity}; provision PN_VENDOR_ARCHIVES before the gate')
        try:
            material = archive_material(data, name, version)
        except (tarfile.TarError, OSError) as error:
            raise ValueError(f'registry archive corrupt: {identity}; provision PN_VENDOR_ARCHIVES before the gate') from error
        provenance = {'name': name, 'version': version, 'origin': 'registry',
                      'archive_sha256': package['checksum'], 'package_path': ''}
    elif source == 'git':
        location = package['source'].split('?')[0][4:]
        revision = package['source'].rsplit('#', 1)[-1]
        if entry.get('repository') != location:
            raise ValueError(f'locked Git source location differs: {identity}')
        repository = git_source_repository(location, git_sources, revision)
        try:
            objects = object_files(repository, revision)
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError(f'locked Git source objects missing: {identity}; provision PN_INSTALLATION_GIT_OBJECTS before the gate') from error
        material = {path: (mode, data, data.decode() if mode == '120000' else None)
                    for path, (mode, data) in objects.items()}
        manifest = package_manifest(material, name, version)
        provenance = {'name': name, 'version': version, 'origin': 'git',
                      'revision': revision, 'tree': git(repository, 'rev-parse', f'{revision}^{{tree}}').decode().strip(),
                      'repository': location, 'package_path': '' if '/' not in manifest else manifest.rsplit('/', 1)[0]}
    else:
        path = entry['path']
        prefix = path.rstrip('/') + '/'
        material = {name[len(prefix):]: (mode, data, data.decode() if mode == '120000' else None)
                    for name, (mode, data) in tracked.items() if name.startswith(prefix)}
        if path.startswith('packages/'):
            mode, data = tracked['LICENSE-CODE']
            material['LICENSE-CODE'] = (mode, data, None)
        workspace_version = tomllib.loads(tracked['Cargo.toml'][1].decode()).get('workspace', {}).get('package', {}).get('version')
        if not material or package_manifest(material, name, version, workspace_version) != 'Cargo.toml':
            raise ValueError(f'path source location differs: {identity}')
        provenance = {'name': name, 'version': version, 'origin': 'path',
                      'tracked_tree': git(root, 'rev-parse', f'{commit}:{path}').decode().strip(),
                      'package_path': path}
    return material, provenance


def manifest_declarations(material, package_path, workspace_license=None):
    declarations = []
    prefix = '' if package_path == '' else package_path.rstrip('/') + '/'
    for name in (f'{prefix}Cargo.toml', f'{prefix}Cargo.toml.orig'):
        if name not in material:
            continue
        package = tomllib.loads(material[name][1].decode()).get('package', {})
        licence = package.get('license')
        if licence == {'workspace': True}:
            licence = workspace_license
            if licence is None and 'Cargo.toml' in material:
                licence = tomllib.loads(material['Cargo.toml'][1].decode()).get('workspace', {}).get('package', {}).get('license')
        licence_file = package.get('license-file')
        if isinstance(licence_file, str):
            target = str(PurePosixPath(name).parent / licence_file)
            if target not in material:
                raise ValueError(f'unresolved licence-file reference: {name} -> {target}')
        elif licence_file is not None:
            raise ValueError(f'unresolved licence-file reference: {name}')
        declarations.append({'path': name, 'member': 'license',
                             'license': licence if isinstance(licence, str) else None,
                             'license_file': licence_file})
    return declarations


def owner_correspondences(key, entry, identity, declarations, vendor_rows, read_committed):
    source_expressions = {d['license'] for d in declarations if d['license']}
    required = entry['review'].get('required_owners')
    actual = [{'path': owner.get('path'), 'first_line': owner.get('first_line'),
               'last_line': owner.get('last_line')} for owner in entry['owners']]
    if not isinstance(required, list) or sorted(required, key=str) != sorted(actual, key=str):
        return False
    for owner in entry['owners']:
        if not isinstance(owner, dict) or owner.get('path') not in NOTICE_OWNERS | {FOLLOWED_OWNER} or owner.get('covered_identity') != key[1]:
            return False
        data = read_committed(owner['path'])
        lines = data.decode('utf-8').splitlines()
        first, last = owner.get('first_line'), owner.get('last_line')
        if (owner.get('sha256') != digest(data) or not isinstance(first, int) or not isinstance(last, int)
                or first < 1 or last < first or last > len(lines)):
            return False
        asserted = owner.get('asserted')
        correspondence = owner.get('correspondence')
        if not isinstance(asserted, dict) or not isinstance(correspondence, dict):
            return False
        excerpt = '\n'.join(lines[first - 1:last])
        if owner['path'] == FOLLOWED_OWNER:
            parent = owner.get('parent')
            if not isinstance(parent, dict) or parent.get('path') != 'packages/host/NOTICE-DEPENDENCIES':
                return False
            parent_bytes = read_committed(parent['path'])
            parent_lines = parent_bytes.decode().splitlines()
            parent_first, parent_last = parent.get('first_line'), parent.get('last_line')
            if (parent.get('sha256') != digest(parent_bytes) or not isinstance(parent_first, int)
                    or not isinstance(parent_last, int) or parent_first < 1 or parent_last > len(parent_lines)
                    or parent_last < parent_first or FOLLOWED_OWNER not in '\n'.join(parent_lines[parent_first - 1:parent_last])):
                return False
            try:
                table_row = tomllib.loads(excerpt)['rows'][0]
            except (KeyError, IndexError, tomllib.TOMLDecodeError):
                return False
            if (table_row.get('name') != asserted.get('identity') or table_row.get('checksum') != asserted.get('source_digest')
                    or table_row.get('licence') != asserted.get('expression')):
                return False
        elif any(value is not None and re.search(r'(?<![\w+-])' + re.escape(value) + r'(?![\w+-])', excerpt) is None
                 for value in asserted.values()):
            return False
        if asserted.get('identity') not in (None, f"{identity['name']} {identity['version']}"):
            return False
        if asserted.get('identity') is None and owner['path'] != 'packages/records/NOTICE-NUMERIC':
            return False
        source_digest = identity.get('archive_sha256') or identity.get('revision')
        vendor = vendor_rows.get(identity.get('package_path'))
        if key[0] == 'path' and vendor and vendor.get('content_manifest'):
            source_digest = json.loads(read_committed(vendor['content_manifest']))['archive_checksum']
        if asserted.get('source_digest') is not None and asserted['source_digest'] != source_digest:
            return False
        expression = asserted.get('expression')
        if expression is not None and expression not in source_expressions and correspondence.get('source_expression') not in source_expressions:
            return False
        if expression is not None and expression not in source_expressions and not correspondence.get('note'):
            return False
    return True


def catalogue_gaps(root, entries, commit=None, *, archives=None, git_sources=None):
    commit = commit or git(root, 'rev-parse', 'HEAD').decode().strip()
    committed_cache = {}
    def read_committed(path):
        if path not in committed_cache:
            committed_cache[path] = git(root, 'show', f'{commit}:{path}')
        return committed_cache[path]
    locked = lock_packages(committed_lock(root, commit))
    required = {source_key(package) for package in locked}
    if set(entries) - required:
        raise ValueError('installation catalogue has identities outside the lock: ' + ', '.join(str(key) for key in sorted(set(entries) - required)))
    missing = set(required - set(entries))
    by_key = {source_key(package): package for package in locked}
    from provision_vendor import archive_directory
    verified_archives = Path(archives) if archives is not None else archive_directory(root)
    path_locations = path_sources(root, commit, locked)
    vendor_rows = {item['path']: item for item in tomllib.loads(git(root, 'show', f'{commit}:ci/vendor-packages.toml').decode()).get('packages', [])}
    tracked = object_files(root, commit, [*vendor_rows, 'Cargo.toml', 'LICENSE-CODE'])
    for key, entry in entries.items():
        package = by_key[key]
        if key[0] == 'path':
            declared_path, vendor = path_locations[key[1]]
            if entry.get('path') != declared_path:
                raise ValueError(f'path source location differs: {key[1]}')
            if not vendor:
                review = entry['review']
                if review.get('scope') != 'first-party-notice':
                    raise ValueError(f'missing first-party notice scope: {key[1]}')
                projection = first_party_projection(root, commit, package, declared_path)
                identity = {'name': package['name'], 'version': package['version'],
                            'origin': 'path', 'package_path': declared_path}
                if (review.get('source_identity') != identity or review.get('declaration_projection') != projection
                        or review.get('declaration_projection_sha256') != digest(encoded(projection))):
                    raise ValueError(f'first-party licence declaration differs: {key[1]}')
                if review.get('selected_evidence') != entry['evidence']:
                    raise ValueError(f'missing bound installation notice evidence: {key[1]}')
                for evidence in entry['evidence']:
                    path = evidence['path']
                    source_path = path if path == 'LICENSE-CODE' else f'{declared_path}/{path}'
                    try:
                        data = git(root, 'show', f'{commit}:{source_path}')
                    except subprocess.CalledProcessError as error:
                        raise ValueError(f'first-party notice path missing: {key[1]}/{path}') from error
                    if evidence.get('sha256') != digest(data):
                        raise ValueError(f'first-party notice bytes differ: {key[1]}/{path}')
                if not owner_correspondences(key, entry, identity, [], vendor_rows, read_committed):
                    raise ValueError(f'notice owner correspondence differs: {key[1]}')
                continue
        if key[0] == 'registry':
            archive_path = verified_archives / f"{package['name']}-{package['version']}.crate"
            if not archive_path.is_file() or archive_path.is_symlink():
                raise ValueError(f'registry archive missing: {key[1]}; provision PN_VENDOR_ARCHIVES before the gate')
        material, identity = verified_material(root, commit, package, entry, verified_archives, git_sources, tracked)
        review = entry['review']
        member_map = members(material)
        if not review.get('inspection') or review.get('selected_evidence') != entry['evidence']:
            raise ValueError(f'missing bound installation notice evidence: {key[0]}:{key[1]}')
        if review.get('source_identity') != identity or review.get('member_map') != member_map or review.get('member_map_sha256') != digest(encoded(member_map)):
            raise ValueError(f'foreign or incomplete installation member map: {key[0]}:{key[1]}')
        workspace_license = None
        if key[0] == 'path':
            workspace_license = tomllib.loads(tracked['Cargo.toml'][1].decode()).get('workspace', {}).get('package', {}).get('license')
        declarations = manifest_declarations(material, '' if key[0] == 'path' else identity['package_path'], workspace_license)
        if review.get('declarations') != declarations:
            raise ValueError(f'installation licence declaration differs: {key[0]}:{key[1]}')
        for evidence in entry['evidence']:
            path = evidence['path']
            if path not in material:
                raise ValueError(f'notice path missing: {key[0]}:{key[1]}/{path}')
            data = material[path][1]
            if evidence.get('sha256') != digest(data):
                raise ValueError(f'notice bytes differ: {key[0]}:{key[1]}/{path}')
            if evidence['kind'] == 'declaration-only':
                if not review.get('absence') or evidence.get('member') != 'license' or not evidence.get('expression') or not any(d['path'] == path and d['license'] == evidence['expression'] for d in declarations):
                    raise ValueError(f'unreviewed declaration-only evidence: {key[0]}:{key[1]}')
            else:
                if evidence['kind'] == 'embedded-statement':
                    lines = data.decode('utf-8').splitlines()
                    first, last = evidence.get('first_line'), evidence.get('last_line')
                    if not isinstance(first, int) or not isinstance(last, int) or first < 1 or last < first or last > len(lines):
                        raise ValueError(f'embedded statement range differs: {key[0]}:{key[1]}')
                elif 'first_line' in evidence or 'last_line' in evidence:
                    raise ValueError(f'invalid notice-file range: {key[0]}:{key[1]}')
        if not owner_correspondences(key, entry, identity, declarations, vendor_rows, read_committed):
            raise ValueError(f'notice owner correspondence differs: {key[0]}:{key[1]}')
    return sorted(missing)


def require_coverage(root, entries, commit=None, *, archives=None, git_sources=None):
    missing = catalogue_gaps(root, entries, commit, archives=archives, git_sources=git_sources)
    if missing:
        raise ValueError('installation notice coverage missing: ' + ', '.join(f'{source}:{identity}' for source, identity in missing))
    return entries


def archive_files(data, name, version):
    return {path: data for path, (_, data, _) in archive_material(data, name, version).items()}


def walk_files(root, *, ignored=frozenset()):
    files = {}
    if not root.is_dir():
        raise ValueError(f'source view missing: {root}')
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in list(dirs):
            path = Path(directory) / name
            if path.is_symlink():
                files[path.relative_to(root).as_posix()] = os.readlink(path).encode()
                dirs.remove(name)
        dirs[:] = [name for name in dirs if Path(directory) != root or name not in ignored]
        for name in names:
            if Path(directory) == root and name in ignored:
                continue
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                files[relative] = os.readlink(path).encode()
            elif path.is_file():
                files[relative] = path.read_bytes()
            else:
                raise ValueError(f'unsupported source-view kind: {relative}')
    return files


def object_files(repo, commit, paths=None):
    files = {}
    arguments = ('ls-tree', '-r', '-z', commit) if paths is None else ('ls-tree', '-r', '-z', commit, '--', *paths)
    for item in git(repo, *arguments).split(b'\0'):
        if not item:
            continue
        head, relative = item.split(b'\t', 1)
        mode, kind, oid = head.split(b' ')
        if kind != b'blob':
            raise ValueError('source object is not a blob')
        files[relative.decode()] = (mode.decode(), git(repo, 'cat-file', 'blob', oid.decode()))
    return files


def view_mode(path):
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        return '120000'
    if not stat.S_ISREG(mode):
        raise ValueError(f'unsupported source mode: {path}')
    return '100755' if mode & 0o111 else '100644'


def registry_root(directory):
    children = [child for child in Path(directory).iterdir() if child.is_dir()]
    if len(children) != 1:
        raise ValueError('registry source root is ambiguous')
    return children[0]


def registry_archive_root(directory):
    children = [child for child in Path(directory).iterdir() if child.is_dir()]
    if len(children) != 1:
        raise ValueError('registry archive root is ambiguous')
    return children[0]


def source_rows(root, commit, cargo_home, git_sources, entries, *, captured_view=None, provenance=None):
    """Produce one side of the manifest; captured_view selects independent build bytes."""
    expected = captured_view is None
    lock_data = committed_lock(root, commit) if expected else (captured_view / 'Cargo.lock').read_bytes()
    packages = lock_packages(lock_data)
    rows = [row('lock', 'Cargo.lock', lock_data)]
    for policy_path in ('rust-toolchain.toml', 'docs/inputs/build-policy.toml', 'Cargo.toml'):
        policy_bytes = git(root, 'show', f'{commit}:{policy_path}') if expected else (captured_view / policy_path).read_bytes()
        rows.append(row('build-policy', policy_path, policy_bytes))
    archive_dir = registry_archive_root(cargo_home / 'registry/cache')
    source_dir = registry_root(cargo_home / 'registry/src') if not expected else None
    for package in packages:
        source, identity = source_key(package)
        entry = entries.get((source, identity))
        modes = {}
        if source == 'registry':
            name, version = package['name'], package['version']
            data = (archive_dir / f'{name}-{version}.crate').read_bytes()
            if expected and digest(data) != package['checksum']:
                raise ValueError(f'registry checksum differs: {identity}')
            rows.append(row('registry-archive', identity, data))
            files = archive_files(data, name, version) if expected else walk_files(source_dir / f'{name}-{version}', ignored=frozenset({'.cargo-ok', '.cargo-checksum.json'}))
        elif source == 'git':
            location = package['source'].split('?')[0][4:]
            if location not in git_sources:
                raise ValueError(f'locked Git source missing: {identity}')
            repository, checkout = git_sources[location]
            revision = package['source'].rsplit('#', 1)[-1]
            if expected:
                objects = object_files(repository, revision)
                files = {path: body for path, (_, body) in objects.items()}
                modes = {path: mode for path, (mode, _) in objects.items()}
            else:
                files = walk_files(checkout, ignored=frozenset({'.git', '.cargo-ok'}))
                modes = {path: view_mode(checkout / path) for path in files}
        else:
            if expected:
                continue
            files = {}
        for path, data in files.items():
            suffix = f'{modes[path]}:{path}' if modes else path
            rows.append(row(f'{source}-source', f'{identity}/{suffix}', data))
        if entry:
            for notice in entry['evidence']:
                if notice['kind'] == 'declaration-only':
                    continue
                path = notice['path']
                if source == 'path':
                    continue
                if path not in files:
                    raise ValueError(f'notice path missing: {identity}/{path}')
                rows.append(row('notice', f'{source}:{identity}/{path}', files[path]))
    tracked = object_files(root, commit) if expected else None
    if expected:
        for path, (mode, data) in tracked.items():
            rows.append(row('tracked-source', f'{mode}:{path}', data))
    else:
        for path, data in walk_files(captured_view, ignored=frozenset({'.git', '.lane'})).items():
            rows.append(row('tracked-source', f'{view_mode(captured_view / path)}:{path}', data))
    for key, entry in entries.items():
        if key[0] != 'path':
            continue
        for notice in entry['evidence']:
            if notice['kind'] == 'declaration-only':
                continue
            path = notice['path']
            source_path = path if path == 'LICENSE-CODE' and entry['path'].startswith('packages/') else f"{entry['path']}/{path}"
            data = tracked[source_path][1] if expected else (captured_view / source_path).read_bytes()
            rows.append(row('notice', f'path:{key[1]}/{path}', data))
    if provenance is not None:
        rows.append(row('provenance', 'toolchain-and-selection', encoded(provenance)))
    return checked_rows(rows)


def compare_manifests(expected, captured):
    left = {(item['kind'], item['identity']): item['sha256'] for item in checked_rows(expected)}
    right = {(item['kind'], item['identity']): item['sha256'] for item in checked_rows(captured)}
    if left != right:
        changed = sorted(set(left) ^ set(right) | {key for key in left.keys() & right.keys() if left[key] != right[key]})
        raise ValueError('installation source inventory differs: ' + ', '.join(f'{kind}:{identity}' for kind, identity in changed[:8]))
    return True
