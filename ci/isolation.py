"""The sole writable source-tree boundary for gate mutation witnesses."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

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


def allocated(paths):
    """Measure allocated cache bytes, including hard-linked artifacts once."""
    existing = [str(path) for path in paths if path.exists()]
    if not existing: return 0
    output = subprocess.check_output(['du', '-sc', '--block-size=1', *existing], text=True)
    return int(output.splitlines()[-1].split()[0])


def bound_target(target, ceiling, owner):
    """Bound retained profile caches at a quiescent owner boundary."""
    if type(ceiling) is not int or ceiling <= 0:
        raise ValueError('target ceiling must be positive bytes')
    names = ('debug', 'gate', 'release', 'doc')
    profiles = [target/name for name in names]
    # Cargo puts root metadata in each independent target, not in a triple.
    nested = [path for path in target.iterdir() if path.is_dir()
              and (path/'.rustc_info.json').is_file()] if target.exists() else []
    triples = [path for path in target.iterdir() if path.is_dir() and path.name not in (*names, 'isolation')
               and path not in nested and any((path/name/'.fingerprint').is_dir() for name in names)] if target.exists() else []
    profiles.extend(path/name for path in triples for name in names)
    other = [path for path in target.iterdir() if path.is_dir() and path.name not in names and path not in triples] if target.exists() else []
    for path in sorted(other):
        kind = 'nested_target' if path in nested else 'outside_profiles'
        print(f'TARGET-DIRS owner={owner} {kind}={path.name} bytes={allocated([path])} scope=reported-not-profile-ceiling path={path}', flush=True)
    before = allocated(profiles)
    after = before
    if before > ceiling:
        for profile in profiles:
            shutil.rmtree(profile/'incremental', ignore_errors=True)
        after = allocated(profiles)
        if after > ceiling:
            for profile in profiles:
                if profile.exists(): shutil.rmtree(profile)
            after = 0
    for path in sorted(triples):
        print(f'TARGET-DIRS owner={owner} target_layout={path.name} bytes={allocated([path])} scope=profiles-bounded-metadata-reported path={path}', flush=True)
    print(f'TARGET-DIRS owner={owner} before_bytes={before} after_bytes={after} ceiling_bytes={ceiling} path={target}', flush=True)
    return before > after


def gate_target(command):
    """Hold the target lock in a supervisor, never in a gate descendant."""
    target = Path(os.environ.get('CARGO_TARGET_DIR', str(Path.cwd()/'target')))
    target.mkdir(parents=True, exist_ok=True)
    with (target/'.gate-target.lock').open('a') as lock:
        started = time.monotonic()
        fcntl.flock(lock, fcntl.LOCK_EX)
        print(f'GATE-TARGET-LOCK wait_s={time.monotonic()-started:.6f} path={target}', flush=True)
        # The gate owns adapter escalation and service-stop deadlines. Killing
        # it here would release exclusion before its EXIT cleanup has finished.
        status = cancellable(command, kill_after=None, close_fds=True).returncode
        return 128-status if status < 0 else status


def cache_policy(root):
    path = root/'docs/inputs/devperf-budgets.toml'
    if not path.exists(): return None
    return next(row for row in tomllib.loads(path.read_text())['rows'] if row['name'] == 'gate')


def retention(root, source, imports):
    """Expire idle owner artifacts on distinct imports, never while in use."""
    if type(imports) is not int or imports < 1:
        raise ValueError('isolation retention must be a positive import count')
    policy = cache_policy(root)
    if policy:
        target = Path(os.environ.get('CARGO_TARGET_DIR', str(root/'target'))).resolve()
        bound_target(target, policy['shared_target_ceiling_bytes'], 'shared-gate')
    base = storage_root(root)
    base.mkdir(parents=True, exist_ok=True)
    # The pre-external layout belongs to this checkout alone. Keep lock inodes
    # stable so an older invocation waiting on one cannot lose its exclusion.
    for owner in sorted((root/'target/i').glob('*/owner')):
        with (owner.parent/'lock').open('a') as old_lock:
            try:
                fcntl.flock(old_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue
            for child in ('s', 'c'):
                if (owner.parent/child).exists():
                    shutil.rmtree(owner.parent/child)
                    print(f'ISOLATION-SWEEP owner={owner.read_text()} artifact={child} reason=superseded-storage', flush=True)
    identity = subprocess.check_output(['git', '-C', str(root), 'rev-parse', source+'^{tree}'], text=True).strip()
    with (base/'retention.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state_path = base/'retention.json'
        state = json.loads(state_path.read_text()) if state_path.exists() else dict(trees=[], generation=0)
        if identity not in state['trees']:
            state['trees'].append(identity)
            state['generation'] += 1
        temporary = state_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(state)+'\n')
        temporary.replace(state_path)
        for owner in sorted(base.glob('*/owner')):
            directory = owner.parent
            with (directory/'lock').open('a') as owner_lock:
                try:
                    fcntl.flock(owner_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                used = directory/'last-use'
                if not used.exists():
                    used.write_text(str(state['generation']))
                if state['generation']-int(used.read_text()) >= imports:
                    for child in ('s', 'c'):
                        if (directory/child).exists():
                            shutil.rmtree(directory/child)
                            print(f'ISOLATION-SWEEP owner={owner.read_text()} artifact={child} idle_imports={state["generation"]-int(used.read_text())}', flush=True)


def target_sizes(root):
    """Report allocated bytes for each checkout-owned isolation partition."""
    for owner in sorted(storage_root(root).glob('*/owner')):
        result = subprocess.check_output(['du', '-s', '--block-size=1', str(owner.parent)], text=True)
        print(f'TARGET-DIRS owner={owner.read_text()} bytes={result.split()[0]} path={owner.parent}', flush=True)


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


def setup_receipt(row):
    """Retain waited Git CPU even when a nested witness captures its stdout."""
    print('ISOLATION-GIT '+json.dumps(row, sort_keys=True), flush=True)
    destination = os.environ.get('PN_GATE_SETUP_LOG')
    if destination:
        row = dict(row, gate_source=os.environ['PN_GATE_SETUP_SOURCE'],
                   run=os.environ['PN_BUILDGRAPH_RUN'], step=os.environ['PN_GATE_STEP'])
        with Path(destination).open('a') as output:
            fcntl.flock(output, fcntl.LOCK_EX)
            output.write(json.dumps(row)+'\n')


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
        state = base.parent/'retention.json'
        generation = json.loads(state.read_text())['generation'] if state.exists() else 0
        (base/'last-use').write_text(str(generation))
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
            cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
            result = cancellable(argv)
            used = resource.getrusage(resource.RUSAGE_CHILDREN)
            setup_receipt(dict(owner=name, source=source, action=argv[1] if argv[1] != '-C' else argv[3],
                wall=time.monotonic()-started, own_user_s=used.ru_utime-cpu.ru_utime,
                own_sys_s=used.ru_stime-cpu.ru_stime, status=result.returncode))
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
        cold_target = not target.is_dir()
        target.mkdir(parents=True, exist_ok=True)
        policy = cache_policy(tree)
        if policy:
            cold_target |= bound_target(target, policy['owner_target_ceiling_bytes'], name)
        for obsolete in target.parent.iterdir():
            if obsolete != target and obsolete.is_dir():
                shutil.rmtree(obsolete)
                print(f'ISOLATION-SWEEP owner={name} artifact=target reason=superseded-configuration', flush=True)
        (tree/'.lane').mkdir()
        print(f'ISOLATION owner={name} source={source} tree={tree} target={target} cache=retained cargo=fingerprinted', flush=True)
        layout = hashlib.sha256(json.dumps(dict(storage=str(base.parent), configuration=configuration,
            format='owner-compile-only-v2'), sort_keys=True).encode()).hexdigest()
        identity = base/'layout'
        layout_changed = identity.exists() and identity.read_text() != layout
        identity.write_text(layout)
        try:
            yield tree, target
        finally:
            if state.exists():
                (base/'last-use').write_text(str(json.loads(state.read_text())['generation']))
            log = tree/'.lane/cargo-work.jsonl'
            rows = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            print('ISOLATION-COMPILE '+json.dumps(dict(owner=name, source=source, layout=layout, cold_target=cold_target, layout_changed=layout_changed,
                cargo_cpu_s=sum(row['own_cpu'] for row in rows if row.get('compile_only')),
                cargo_wall_s=sum(row['wall'] for row in rows if row.get('compile_only')),
                cargo_and_run_cpu_s=sum(row['own_cpu'] for row in rows if not row.get('compile_only')),
                calls=len(rows), scope='compile-only; mixed Cargo-and-run reported separately')), flush=True)


def cargo_environment(tree):
    """Meter Cargo and its waited descendants in the isolated owner's process."""
    real = os.environ.get('PN_ISOLATION_CARGO') or shutil.which('cargo')
    if not real: raise ValueError('isolated Cargo executable is unavailable')
    directory = tree/'.lane/cargo-bin'
    directory.mkdir(exist_ok=True)
    wrapper = directory/'cargo'
    command = [sys.executable, '-B', str(Path(__file__).resolve()), 'cargo-work', real, str(tree/'.lane/cargo-work.jsonl')]
    wrapper.write_text('#!/bin/sh\nexec '+shlex.join(command)+' "$@"\n')
    wrapper.chmod(0o755)
    return dict(PATH=str(directory)+os.pathsep+os.environ['PATH'], PN_ISOLATION_CARGO=real)


def cargo_work(arguments):
    """Keep inclusive Cargo CPU separate from the enclosing suite's own CPU."""
    real, destination, *arguments = arguments
    started = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = subprocess.run([real, *arguments])
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    row = dict(wall=time.monotonic()-started, own_cpu=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
               command=arguments, status=result.returncode,
               compile_only=bool(arguments) and arguments[0] in ('build', 'check', 'clippy', 'rustdoc'))
    with Path(destination).open('a') as output:
        fcntl.flock(output, fcntl.LOCK_EX)
        output.write(json.dumps(row)+'\n')
    return result.returncode


def generate(action):
    """Check generated bytes in an owned checkout, never repair the gate root."""
    root = Path.cwd()
    source = os.environ.get('PN_GATE_SOURCE') or subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    with workspace(root, 'fixed-point', source) as (tree, target):
        result = cancellable(['cargo', 'build', '-p', 'documents', '--bin', 'documents', '--locked',
                              '--profile', 'gate', '--message-format=json'], stdout=subprocess.PIPE, text=True,
                             cwd=tree, env=os.environ | cargo_environment(tree) | {'CARGO_TARGET_DIR':str(target)})
        if result.returncode:
            print(result.stdout)
            return result.returncode
        if action == 'generate':
            projection = cancellable([sys.executable, '-B', 'ci/deployment_claims.py', 'generate'], cwd=tree)
            if projection.returncode:
                return projection.returncode
        result = cancellable([built_executable(result.stdout), action], cwd=tree,
                             env=os.environ | {'CARGO_TARGET_DIR':str(target)})
        if result.returncode:
            return result.returncode
        changed = cancellable(['git', '-C', str(tree), 'diff', '--exit-code'], stdout=subprocess.PIPE)
        if changed.returncode:
            sys.stdout.buffer.write(changed.stdout)
            print('ISOLATION-FIXED-POINT generated bytes differ from the source commit', flush=True)
        return changed.returncode


def built_executable(output):
    """Use Cargo's artifact identity, including a configured target triple."""
    messages = [json.loads(line) for line in output.splitlines()]
    paths = {row['executable'] for row in messages if row.get('reason') == 'compiler-artifact'
             and row.get('target', {}).get('name') == 'documents' and row.get('executable')}
    if len(paths) != 1:
        raise ValueError('documents build did not identify exactly one executable')
    return paths.pop()


if __name__ == '__main__':
    if len(sys.argv) > 2 and sys.argv[1] == 'gate-target':
        raise SystemExit(gate_target(sys.argv[2:]))
    if len(sys.argv) == 2 and sys.argv[1] in {'retention', 'target-sizes'}:
        if sys.argv[1] == 'target-sizes':
            target_sizes(Path.cwd())
        else:
            from devperf import budgets
            retention(Path.cwd(), os.environ.get('PN_IMPORT_BASE', os.environ['PN_GATE_SOURCE']),
                      budgets('docs/inputs/devperf-budgets.toml')['gate']['isolation_retention_imports'])
        raise SystemExit(0)
    if len(sys.argv) > 2 and sys.argv[1] == 'cargo-work':
        raise SystemExit(cargo_work(sys.argv[2:]))
    if len(sys.argv) == 2 and sys.argv[1] == 'import-base':
        try:
            print(import_base(Path.cwd(), os.environ['PN_GATE_SOURCE'], os.environ['PN_IMPORT_BASE']))
        except ValueError as error:
            raise SystemExit('GATE-STRUCTURAL-ERROR: '+str(error))
        raise SystemExit(0)
    if len(sys.argv) != 2 or sys.argv[1] not in {'generate', 'write'}:
        raise SystemExit('expected generate or write')
    raise SystemExit(generate(sys.argv[1]))
