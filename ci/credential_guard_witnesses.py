"""Execute the closed credential source-guard mutations without changing source files."""
import argparse
import difflib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import types
import unittest


CASES = (
    ('required-roster', 'protected_packages', 'required = required_packages(root)', 'required = declared',
     'test_protected_package_resolution', 'roster refuses before resolution'),
    ('future-executable', 'protected_packages', "required.add(package['name'])", 'pass',
     'test_protected_package_resolution', 'every executable with a secret closure is protected'),
    ('foreign-entry', 'discipline', "if re.search(r'\\bacquire_receivers\\b', code):", 'if False:',
     'test_credential_receiver_census', 'second generator acquisition reference refuses'),
    ('receiver-conversion', 'discipline', 'if re.search(roles, header) and not (path == home', 'if False and not (path == home',
     'test_credential_receiver_census', 'receiver conversion and duplication refuses'),
    ('receiver-constructor', 'discipline', "if not re.search(r'pub struct '+role+r'\\(File\\);', code):", 'if False:',
     'test_credential_receiver_census', 'public receiver constructor refuses'),
)


def source(case):
    """Require one exact source site before executing a changed module in memory."""
    name, module, before, after, _, _ = case
    path = Path('ci')/(module+'.py')
    original = path.read_text()
    if original.count(before) != 1:
        raise ValueError('mutation source differs: '+name)
    changed = original.replace(before, after)
    compile(changed, str(path), 'exec')
    return path, original, changed


def child(case):
    """Run exactly the owning control with only its imported checker mutated."""
    path, _, changed = source(case)
    module = types.ModuleType(case[1])
    module.__file__ = str(path.resolve())
    sys.modules[case[1]] = module
    exec(compile(changed, str(path), 'exec'), module.__dict__)
    suite = unittest.defaultTestLoader.loadTestsFromName('ci.test_discipline.WorkspaceChecks.'+case[4])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return int(not result.wasSuccessful())


def run(output):
    """Keep each patch and assertion failure; an error or another failure is not a kill."""
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for case in CASES:
        name, _, before, _, test, assertion = case
        path, original, changed = source(case)
        patch = ''.join(difflib.unified_diff(original.splitlines(True), changed.splitlines(True),
                                           fromfile='a/'+str(path), tofile='b/'+str(path)))
        (output/(name+'.patch')).write_text(patch)
        start = time.monotonic()
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--case', name],
                                env=dict(os.environ, PYTHONPATH='ci'+os.pathsep+'.'), capture_output=True, text=True)
        log = result.stdout+result.stderr
        (output/(name+'.log')).write_text(log)
        if result.returncode != 1 or 'FAILED (failures=1)' not in log or 'AssertionError' not in log or assertion not in log:
            raise AssertionError('own assertion did not kill mutation: '+name)
        row = dict(name=name, file=str(path), line=original[:original.index(before)].count('\n')+1,
                   test=test, assertion=assertion, wall=time.monotonic()-start, exit=result.returncode)
        rows.append(row)
        print('CREDENTIAL-GUARD-MUTANT '+json.dumps(row), flush=True)
    (output/'results.json').write_text(json.dumps(rows, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output', type=Path)
    mode.add_argument('--case', choices=[case[0] for case in CASES])
    args = parser.parse_args()
    if args.case:
        sys.exit(child(next(case for case in CASES if case[0] == args.case)))
    run(args.output)
