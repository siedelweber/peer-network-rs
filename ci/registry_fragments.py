"""Index-scoped, duplicate-refusing registry input assembly.

The declared roots are input families, not glob exclusions. Every indexed path
below one is validated and remains an exact census and citation input.
"""
import argparse
import json
from pathlib import Path
import stat
import subprocess
import tomllib


ROOTS = {
    'claim-obligations': 'docs/inputs/claim-obligations',
    'harness-registry': 'docs/inputs/harness-registry',
    'linter-owners': 'docs/inputs/linter-owners',
    'observation-registry': 'ci/observation-registry',
}


def indexed(root):
    result = subprocess.run(['git', '-C', str(root), 'ls-files', '--stage', '-z'],
                            capture_output=True, check=True)
    found = {}
    for entry in result.stdout.decode().split('\0'):
        if not entry:
            continue
        metadata, path = entry.split('\t', 1)
        if not any(path.startswith(prefix+'/') for prefix in ROOTS.values()):
            continue
        mode, _, stage = metadata.split()
        if stage != '0' or mode not in {'100644', '100755'} or path in found:
            raise ValueError('fragment index mode or stage: '+path)
        full = root/path
        if not stat.S_ISREG(full.lstat().st_mode):
            raise ValueError('fragment is not a regular file: '+path)
        for parent in full.parents:
            if parent == root:
                break
            if parent.is_symlink():
                raise ValueError('fragment symlink ancestor: '+path)
        expected = '.json' if path.startswith(ROOTS['observation-registry']+'/') else '.toml'
        if full.suffix != expected:
            raise ValueError('unknown fragment suffix: '+path)
        found[path] = full
    return found


def distinct(pairs):
    result = {}
    for key, path, value in pairs:
        if key in result:
            raise ValueError(f'duplicate fragment {key}: {result[key][0]} and {path}')
        result[key] = (path, value)
    return result


def read(root, name):
    """Read an admitted fragment family, or its not-yet-migrated monolith."""
    root = Path(root).resolve()
    prefix = ROOTS[name]
    if not (root/prefix).exists():
        suffix = '.json' if name == 'observation-registry' else '.toml'
        text = (root/(prefix+suffix)).read_text()
        return json.loads(text) if suffix == '.json' else tomllib.loads(text)
    paths = {path: full for path, full in indexed(root).items() if path.startswith(prefix+'/')}
    if name == 'observation-registry':
        raise ValueError('observation fragment schema has not been admitted')
    schema_path = prefix+'/schema.toml'
    if schema_path not in paths:
        raise ValueError('missing central fragment schema: '+schema_path)
    schema = tomllib.loads(paths.pop(schema_path).read_text())
    if set(schema) != {'namespace', 'version', 'fields'}:
        raise ValueError('unknown or missing fragment schema key: '+schema_path)
    fields = schema['fields']
    pairs = []
    for path, full in paths.items():
        row = tomllib.loads(full.read_text())
        kind = row.get('kind', 'row')
        if kind not in fields or set(row)-set(fields[kind]) or not isinstance(row.get('name'), str):
            raise ValueError('unknown fragment key or missing identity: '+path)
        pairs.append(((kind, row['name']), path, row))
    rows = distinct(pairs)
    order = {'level': 0, 'implementation': 1, 'tier': 2, 'suite': 3, 'row': 0}
    keys = sorted(rows, key=lambda key: (order[key[0]], key[1].encode('utf-8')))
    return dict(namespace=schema['namespace'], version=schema['version'],
                rows=[rows[key][1] for key in keys])


def expanded_inputs(root, declared):
    """Expand exact index paths with their registry's declared incidence edges."""
    by_path = {row['path']: row for row in declared}
    result = []
    for path in sorted(indexed(Path(root).resolve())):
        name = next(name for name, prefix in ROOTS.items() if path.startswith(prefix+'/'))
        suffix = '.json' if name == 'observation-registry' else '.toml'
        carrier = ROOTS[name]+'/schema'+suffix
        if carrier not in by_path:
            raise ValueError('fragment family lacks declared incidence: '+carrier)
        if path not in by_path:
            result.append(dict(by_path[carrier], path=path, producer=''))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('registry', choices=ROOTS)
    args = parser.parse_args()
    print(json.dumps(read(args.root, args.registry), ensure_ascii=False))


if __name__ == '__main__':
    main()
