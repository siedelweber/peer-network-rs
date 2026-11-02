"""The sole writable source-tree boundary for gate mutation witnesses."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from build_graph import cancellable


def storage_root(root):
    """Keep mutable witnesses outside the checkout, even with an in-tree target."""
    root = root.resolve()
    declared = os.environ.get('PN_ISOLATION_ROOT')
    target = Path(os.environ.get('CARGO_TARGET_DIR', str(root/'target'))).resolve()
    base = Path(declared).resolve() if declared else (
        target/'isolation' if not target.is_relative_to(root) else root.with_name(root.name+'-isolation'))
    if base.is_relative_to(root):
        raise ValueError('isolation storage must be outside the gate checkout')
    return base/hashlib.sha256(str(root).encode()).hexdigest()


@contextmanager
def tracked_snapshot(root):
    """Give a traversing census only index-enumerated regular source files."""
    from build_graph import tracked
    base = storage_root(root)
    base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='census-', dir=base) as directory:
        tree = Path(directory)
        paths = []
        for name in tracked(root):
            source = root/name
            if not source.is_file() or source.is_symlink():
                raise ValueError('missing or nonregular tracked census input: '+name)
            destination = tree/name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            paths.append(name)
        if cancellable(['git', 'init', '--quiet', str(tree)]).returncode:
            raise ValueError('tracked census snapshot initialization failed')
        selection = tree/'.git/census-paths'
        selection.write_bytes(''.join(name+'\0' for name in paths).encode())
        if cancellable(['git', '-C', str(tree), 'add', '--force', '--pathspec-from-file='+str(selection), '--pathspec-file-nul']).returncode:
            raise ValueError('tracked census snapshot index failed')
        yield tree


def import_base(root, source, base):
    """Resolve a parent-local name once, requiring a commit in source history."""
    resolved = cancellable(['git', '-C', str(root), 'rev-parse', '--verify', '--end-of-options', base+'^{commit}'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if resolved.returncode:
        raise ValueError('import base does not resolve to a commit: '+base)
    commit = resolved.stdout.strip()
    ancestor = cancellable(['git', '-C', str(root), 'merge-base', '--is-ancestor', commit, source])
    if ancestor.returncode:
        raise ValueError('import base is not an ancestor of source: '+base)
    return commit


@contextmanager
def workspace(root, name, source):
    """Retain owned build products, but bind every invocation to commit objects."""
    if not re.fullmatch(r'[a-z0-9_-]+', name):
        raise ValueError('invalid isolation owner')
    base = storage_root(root)/hashlib.sha256(name.encode()).hexdigest()[:12]
    base.mkdir(parents=True, exist_ok=True)
    with (base/'lock').open('a') as lock:
        started = time.monotonic()
        fcntl.flock(lock, fcntl.LOCK_EX)
        print(f'ISOLATION-LOCK owner={name} wall={time.monotonic()-started:.6f}s', flush=True)
        binding = base/'owner'
        if binding.exists() and binding.read_text() != name:
            raise ValueError('isolation owner key collision')
        binding.write_text(name)
        tree = base/'s'
        # Older shared clones borrow objects that the parent may prune.
        if (tree/'.git/objects/info/alternates').exists():
            shutil.rmtree(tree)
        commands = []
        if not tree.exists():
            commands.append(['git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', str(root), str(tree)])
        commands += [['git', '-C', str(tree), 'fetch', '--quiet', 'origin', source],
                     ['git', '-C', str(tree), 'checkout', '--quiet', '--force', '--detach', source],
                     ['git', '-C', str(tree), 'clean', '--quiet', '-fdx']]
        for argv in commands:
            started = time.monotonic()
            result = cancellable(argv)
            print(f'ISOLATION-GIT owner={name} action={argv[-1]} wall={time.monotonic()-started:.6f}s status={result.returncode}', flush=True)
            if result.returncode:
                raise ValueError('commit-scoped checkout failed')
        for argv, expected in ((['rev-parse', 'HEAD'], source), (['status', '--porcelain', '--untracked-files=no'], '')):
            checked = cancellable(['git', '-C', str(tree), *argv], stdout=subprocess.PIPE, text=True)
            if checked.returncode or checked.stdout.strip() != expected:
                raise ValueError('isolated checkout is not clean at the source commit')
        configuration = dict(files={name:(tree/name).read_text() if (tree/name).exists() else None
                                    for name in ('rust-toolchain.toml',)},
                             environment={name:os.environ.get(name) for name in
                                          ('RUSTUP_TOOLCHAIN', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET')})
        key = hashlib.sha256(json.dumps(configuration, sort_keys=True).encode()).hexdigest()
        target = base/'c'/key
        target.mkdir(parents=True, exist_ok=True)
        (tree/'.lane').mkdir()
        print(f'ISOLATION owner={name} source={source} tree={tree} target={target} cache=retained cargo=fingerprinted', flush=True)
        yield tree, target


def generate(action):
    """Check generated bytes in an owned checkout, never repair the gate root."""
    root = Path.cwd()
    source = os.environ.get('PN_GATE_SOURCE') or subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    with workspace(root, 'fixed-point', source) as (tree, target):
        result = cancellable(['cargo', 'run', '-p', 'documents', '--locked', '--profile', 'gate', '--', action],
                             cwd=tree, env=os.environ | {'CARGO_TARGET_DIR':str(target)})
        if result.returncode:
            return result.returncode
        changed = cancellable(['git', '-C', str(tree), 'diff', '--exit-code'], stdout=subprocess.PIPE)
        if changed.returncode:
            sys.stdout.buffer.write(changed.stdout)
            print('ISOLATION-FIXED-POINT generated bytes differ from the source commit', flush=True)
        return changed.returncode


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == 'import-base':
        try:
            print(import_base(Path.cwd(), os.environ['PN_GATE_SOURCE'], os.environ['PN_IMPORT_BASE']))
        except ValueError as error:
            raise SystemExit('GATE-STRUCTURAL-ERROR: '+str(error))
        raise SystemExit(0)
    if len(sys.argv) != 2 or sys.argv[1] not in {'generate', 'write'}:
        raise SystemExit('expected generate or write')
    raise SystemExit(generate(sys.argv[1]))
