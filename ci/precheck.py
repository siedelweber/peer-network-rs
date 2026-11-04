"""Run registration checks without compiling or executing test cases."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time


CHECKERS = {
    'documents': ('gate/documents', ['-p', 'documents', '--bin', 'documents']),
    'observations': ('gate/examples/observe_census', ['-p', 'cli-common', '--example', 'observe_census']),
}


def prepared_state(root, target, name):
    """Bind the executable to Cargo's dep-info inputs and workspace manifests."""
    root, target = Path(root).resolve(), Path(target).resolve()
    binary = target/CHECKERS[name][0]
    dependency = binary.with_suffix('.d')
    lines = dependency.read_text().splitlines()
    if not lines or ': ' not in lines[0]:
        raise ValueError('prepared checker dep-info is malformed: '+name)
    line = lines[0]
    inputs = {Path(path) for path in shlex.split(line.split(': ', 1)[1])}
    indexed = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'],
                             capture_output=True, check=True).stdout.decode().split('\0')
    inputs.update(root/path for path in indexed if path and
                  (Path(path).name in {'Cargo.toml', 'Cargo.lock', 'build.rs', 'rust-toolchain.toml'}
                   or path.startswith('.cargo/')))
    if not inputs:
        raise ValueError('prepared checker lacks source inputs: '+name)
    sources = [(str(path), hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(inputs)]
    return dict(schema=1, checker=name, sources=sources,
                binary=hashlib.sha256(binary.read_bytes()).hexdigest())


def check_prepared(root, target, name):
    """The pre-check and gate refuse the same stale prepared input binding."""
    binary = Path(target)/CHECKERS[name][0]
    try:
        recorded = json.loads(binary.with_suffix('.prepared.json').read_text())
        actual = prepared_state(root, target, name)
        # JSON tuples round-trip as arrays.
        if recorded != json.loads(json.dumps(actual)):
            raise ValueError('prepared checker sources or executable differ: '+name)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        message = 'CHECKER-STRUCTURAL-ERROR '+str(error)
        print(message, file=sys.stderr, flush=True)
        raise ValueError(message) from error
    return binary


def prepare_checker(root, target, name):
    """Only a successful locked Cargo build publishes a prepared binding."""
    root, target = Path(root).resolve(), Path(target).resolve()
    binary = target/CHECKERS[name][0]
    binding = binary.with_suffix('.prepared.json')
    binding.unlink(missing_ok=True)
    subprocess.run(['cargo', 'build', '--offline', '--locked', '--profile', 'gate', *CHECKERS[name][1]],
                   cwd=root, env=dict(os.environ, CARGO_TARGET_DIR=str(target)), check=True)
    state = prepared_state(root, target, name)
    temporary = binding.with_suffix('.'+str(os.getpid())+'.tmp')
    temporary.write_text(json.dumps(state, sort_keys=True)+'\n')
    temporary.replace(binding)
    return check_prepared(root, target, name)


def commands(target, linter):
    """Keep checks at their gate entry points, including their refusal diagnostics."""
    return (
        ('census', [sys.executable, '-B', 'ci/build_graph.py', 'gate']),
        ('linter', [linter, 'check', '--root', '.']),
        ('claims', [sys.executable, '-B', 'ci/claims.py', 'registration']),
        ('observations', [sys.executable, '-B', 'ci/observe.py', '--census-binary', str(target/'gate/examples/observe_census')]),
        ('datasets', [str(target/'gate/documents'), 'generate', '--check']),
        ('documents', [str(target/'gate/documents'), 'check']),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-checkers', action='store_true', help='explicit build preparation; not a registration pre-check')
    parser.add_argument('--run-checker', choices=CHECKERS, help='gate build-and-check route')
    parser.add_argument('checker_args', nargs=argparse.REMAINDER)
    parser.add_argument('--only', choices=('census', 'linter', 'claims', 'observations', 'datasets', 'documents'),
                        help='run one named stage; not a complete pre-check')
    args = parser.parse_args()
    started = time.time()
    status = 0
    try:
        target = Path(os.environ.get('CARGO_TARGET_DIR', 'target')).resolve()
        if args.prepare_checkers:
            for name in CHECKERS:
                prepare_checker(Path.cwd(), target, name)
            return 0
        if args.run_checker:
            prepare_checker(Path.cwd(), target, args.run_checker)
            binary = check_prepared(Path.cwd(), target, args.run_checker)
            arguments = args.checker_args
            if arguments[:1] == ['--']: arguments = arguments[1:]
            return subprocess.run([str(binary), *arguments], check=False).returncode
        linter = os.environ.get('LINTER_BIN')
        if not linter:
            raise ValueError('LINTER_BIN must name the deployed linter')
        Path('.lane').mkdir(exist_ok=True)
        for name, argv in commands(target, linter):
            if args.only and args.only != name:
                continue
            before = time.time()
            if name in {'datasets', 'documents', 'observations'}:
                check_prepared(Path.cwd(), target, 'observations' if name == 'observations' else 'documents')
            result = subprocess.run(argv, check=False)
            print(f'PRECHECK step={name} status={result.returncode} start={before:.9f} end={time.time():.9f}', flush=True)
            status = max(status, result.returncode if result.returncode >= 0 else 128-result.returncode)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print('PRECHECK-STRUCTURAL-ERROR '+str(error), file=sys.stderr)
        status = 2
    print(f'PRECHECK-EXIT={status} wall_s={time.time()-started:.6f} execution=not-evaluated scope={args.only or 'all'}', flush=True)
    return status


if __name__ == '__main__':
    sys.exit(main())
