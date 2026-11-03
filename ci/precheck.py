"""Run registration checks without compiling or executing test cases."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import time


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
    parser.add_argument('--only', choices=('census', 'linter', 'claims', 'observations', 'datasets', 'documents'),
                        help='run one named stage; not a complete pre-check')
    args = parser.parse_args()
    started = time.time()
    status = 0
    try:
        linter = os.environ.get('LINTER_BIN')
        if not linter:
            raise ValueError('LINTER_BIN must name the deployed linter')
        target = Path(os.environ.get('CARGO_TARGET_DIR', 'target')).resolve()
        Path('.lane').mkdir(exist_ok=True)
        for name, argv in commands(target, linter):
            if args.only and args.only != name:
                continue
            before = time.time()
            result = subprocess.run(argv, check=False)
            print(f'PRECHECK step={name} status={result.returncode} start={before:.9f} end={time.time():.9f}', flush=True)
            status = max(status, result.returncode if result.returncode >= 0 else 128-result.returncode)
    except (OSError, ValueError) as error:
        print('PRECHECK-STRUCTURAL-ERROR '+str(error), file=sys.stderr)
        status = 2
    print(f'PRECHECK-EXIT={status} wall_s={time.time()-started:.6f} execution=not-evaluated scope={args.only or 'all'}', flush=True)
    return status


if __name__ == '__main__':
    sys.exit(main())
