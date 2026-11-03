#!/usr/bin/env python3
"""Preserve Cargo's registry lint treatment for declared excluded vendor sources."""
import fnmatch
import os
from pathlib import Path
import sys
import tomllib


def capped(root, arguments, environment, cwd):
    """Only an excluded declared patch's own source receives the dependency cap."""
    manifest_dir = environment.get('CARGO_MANIFEST_DIR')
    if not manifest_dir:
        return False  # Cargo's compiler discovery queries have no package.
    directory = Path(manifest_dir).resolve()
    root = root.resolve()
    manifest = tomllib.loads((root / 'Cargo.toml').read_text())
    members = manifest['workspace'].get('members', [])
    rows = tomllib.loads((root / 'ci/vendor-packages.toml').read_text())['packages']
    for row in rows:
        relative = row['path']
        parts = Path(relative).parts
        if (not relative.startswith('vendor/') or any(p in ('', '.', '..') for p in relative.split('/'))
                or any(c in relative for c in '*?[\\')):
            raise ValueError('vendor compiler path must be explicit and normalized')
        package = root.joinpath(*parts).resolve()
        if package != directory:
            continue
        if (row['mode'] != 'patch' or any(fnmatch.fnmatchcase(relative, member) for member in members)
                or relative not in manifest['workspace'].get('exclude', [])):
            return False
        if not package.is_relative_to(root / 'vendor'):
            raise ValueError('vendor compiler path escapes its root')
        if manifest.get('patch', {}).get('crates-io', {}).get(row['name']) != {'path': relative}:
            raise ValueError('vendor compiler package is not routed')
        identity = tomllib.loads((package / 'Cargo.toml').read_text())['package']
        if (identity['name'], identity['version']) != (row['name'], row['version']):
            raise ValueError('vendor compiler package identity differs')
        # A package environment alone cannot cap another crate's source.
        sources = [Path(cwd, argument).resolve() for argument in arguments if argument.endswith('.rs')]
        return len(sources) == 1 and sources[0].is_relative_to(package)
    return False


def main():
    compiler, *arguments = sys.argv[1:]
    if capped(Path(__file__).resolve().parent.parent, arguments, os.environ, Path.cwd()):
        arguments += ['--cap-lints', 'allow']
    os.execv(compiler, [compiler, *arguments])


if __name__ == '__main__':
    main()
