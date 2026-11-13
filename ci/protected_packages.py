"""Hold package-scoped secret closures and test them without workspace unification."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tomllib


def parse_tree(text):
    """Retain each build-context feature set rather than unioning distinct rows."""
    rows = set()
    for line in text.splitlines():
        line = line.replace(' (proc-macro)', '')
        match = re.fullmatch(r'([^ ]+) v([^ ]+)(?: (.*?))?\|([^|]*)', line)
        if not match:
            raise ValueError('unreadable protected dependency row: '+line)
        name, version, origin, features = match.groups()
        features = features.removesuffix(' (*)').strip()
        rows.add((name, version, origin or '', tuple(sorted(features.split(','))) if features else ()))
    return [dict(name=n,version=v,origin=o,features=list(f)) for n,v,o,f in sorted(rows)]


def bind_sources(root, rows):
    """Join registry identities to locked checksums and retain every path identity."""
    locked = tomllib.loads((root/'Cargo.lock').read_text())['package']
    result = []
    for raw in rows:
        row = dict(raw)
        origin = row.pop('origin')
        candidates = [p for p in locked if (p['name'],p['version']) == (row['name'],row['version'])]
        if origin.startswith('(') and origin.endswith(')'):
            location = origin[1:-1]
            path = Path(location)
            if path.is_absolute():
                try:
                    relative = path.resolve().relative_to(root.resolve()).as_posix()
                except ValueError as error:
                    raise ValueError('external path in protected closure') from error
                manifest = tomllib.loads((path/'Cargo.toml').read_text())
                if manifest['package']['name'] != row['name']:
                    raise ValueError('protected path identity differs')
                row['source'] = 'workspace:'+relative
                row['checksum'] = None
            else:
                def matches(package):
                    source = package.get('source','').removeprefix('git+')
                    if source == location:
                        return True
                    url, separator, revision = source.rpartition('#')
                    shown_url, shown_separator, shown_revision = location.rpartition('#')
                    return bool(separator and shown_separator and url == shown_url and len(shown_revision) >= 7 and revision.startswith(shown_revision))
                candidates = [p for p in candidates if matches(p)]
                if len(candidates) != 1:
                    raise ValueError('ambiguous protected source identity: '+row['name']+' '+row['version']+' '+location)
                row['source'] = candidates[0]['source']
                row['checksum'] = candidates[0].get('checksum')
        elif not origin:
            candidates = [p for p in candidates if p.get('source','').startswith('registry+')]
            if len(candidates) != 1 or not candidates[0].get('checksum'):
                raise ValueError('ambiguous protected registry identity')
            row['source'] = candidates[0]['source']
            row['checksum'] = candidates[0]['checksum']
        else:
            raise ValueError('unreadable protected source identity')
        result.append(row)
    return result


def required_packages(root):
    """Protect every binary whose own closure contains either secret-handling root."""
    required = {'pn-secret-home','pn-credential-derivation'}
    metadata = json.loads(subprocess.run(
        ['cargo','metadata','--offline','--locked','--no-deps','--format-version=1'],
        cwd=root,text=True,capture_output=True,check=True).stdout)
    for package in metadata['packages']:
        if package['id'] in metadata['workspace_members'] and any('bin' in t['kind'] for t in package['targets']):
            closure = resolve(root,package['name'],bind=False)
            if required.intersection(row['name'] for row in closure):
                required.add(package['name'])
    return required


def resolve(root, package, bind=True):
    command = ['cargo','tree','--offline','--locked','-p',package,'-e','normal,build',
               '--prefix','none','-f','{p}|{f}']
    result = subprocess.run(command,cwd=root,text=True,capture_output=True,check=True)
    rows = parse_tree(result.stdout)
    return bind_sources(root,rows) if bind else rows


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
        if not isinstance(package,str) or package in declared or set(record) != {'package','closure'} or not isinstance(record['closure'],list):
            raise ValueError('invalid protected package record')
        declared.add(package)
        loaded.append(record)
    required = required_packages(root)
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
