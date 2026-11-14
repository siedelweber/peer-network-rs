"""Hold package-scoped secret closures and test them without workspace unification."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def parse_tree(text):
    """Retain each build-context feature set rather than unioning distinct rows."""
    rows = set()
    for line in text.splitlines():
        match = re.fullmatch(r'([^ ]+) v([^ ]+)(?: .*?)?\|([^|]*)', line)
        if not match:
            raise ValueError('unreadable protected dependency row: '+line)
        name, version, features = match.groups()
        features = features.removesuffix(' (*)').strip()
        rows.add((name, version, tuple(sorted(features.split(','))) if features else ()))
    return [dict(name=n,version=v,features=list(f)) for n,v,f in sorted(rows)]


def resolve(root, package):
    command = ['cargo','tree','--offline','--locked','-p',package,'-e','normal,build',
               '--prefix','none','-f','{p}|{f}']
    result = subprocess.run(command,cwd=root,text=True,capture_output=True,check=True)
    return parse_tree(result.stdout)


def compare(package, expected, actual):
    if actual != expected:
        raise ValueError('protected package closure differs: '+package+' expected='+
                         json.dumps(expected,sort_keys=True)+' actual='+json.dumps(actual,sort_keys=True))


def check(root, run_tests=False):
    records = root/'ci/protected-packages'
    rows = sorted(records.glob('*.json'))
    if not rows:
        raise ValueError('protected package roster is empty')
    declared = set()
    loaded = []
    for path in rows:
        record = json.loads(path.read_text())
        package = record['package']
        if package in declared or set(record) != {'package','closure'}:
            raise ValueError('invalid protected package record')
        declared.add(package)
        loaded.append(record)
    required = {'pn-secret-home','pn-credential-derivation'}
    if (root/'packages/credential-generator/Cargo.toml').exists():
        required.add('pn-credential-generator')
    if declared != required:
        raise ValueError('protected package roster differs from required consumers')
    for record in loaded:
        package = record['package']
        compare(package,record['closure'],resolve(root,package))
        print('PROTECTED-PACKAGE package='+package+' closure=matched',flush=True)
        if run_tests:
            subprocess.run(['cargo','build','--offline','--locked','--profile','gate','-p',package],cwd=root,check=True)
            subprocess.run(['cargo','test','--offline','--locked','--profile','gate','-p',package],cwd=root,check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tests',action='store_true')
    args = parser.parse_args()
    try:
        check(Path.cwd(),args.tests)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print('PROTECTED-PACKAGE-REFUSED '+str(error),flush=True)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
