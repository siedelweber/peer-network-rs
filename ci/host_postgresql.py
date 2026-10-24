"""Own an isolated, real PostgreSQL prerelease for the transport evidence."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

def binary_directory():
    value = os.environ.get('PN_POSTGRESQL_BIN')
    if not value:
        raise RuntimeError('PN_POSTGRESQL_BIN must name the PostgreSQL binary directory')
    return Path(value)

TARGET = Path('packages/host/postgresql-target.txt').read_text().strip()

def dependency_pins(packages, reviewed):
    """Require every reachable registry archive to retain its reviewed pin."""
    by_name={}
    for package in packages:
        by_name.setdefault(package['name'], []).append(package)
    pending=[next(package for package in packages if package['name']=='pn-host')]
    seen={}
    while pending:
        package=pending.pop()
        key=(package['name'],package['version'])
        if key in seen:
            continue
        seen[key]=package
        for dependency in package.get('dependencies',[]):
            fields=dependency.split()
            choices=by_name[fields[0]]
            if len(fields)>1:
                choices=[choice for choice in choices if choice['version']==fields[1]]
            if len(choices)!=1:
                raise ValueError('ambiguous host lock edge')
            pending.extend(choices)
    actual={name+' '+version:package['checksum'] for (name,version),package in seen.items() if 'source' in package}
    expected={row['name']:row['checksum'] for row in reviewed}
    if len(expected)!=len(reviewed) or actual!=expected:
        raise ValueError('host dependency closure differs from reviewed archive pins')
    return len(actual)

def command(args, log, env=None):
    result = subprocess.run([str(v) for v in args], stdout=log, stderr=log, env=env, check=False)
    if result.returncode:
        raise RuntimeError('PostgreSQL fixture command failed; private fixture log retained')

def stop(root):
    if (root/'data'/'postmaster.pid').exists():
        with (root/'fixture.log').open('ab') as log:
            command([binary_directory()/'pg_ctl', '-D', root/'data', '-m', 'immediate', '-w', 'stop'], log)

def start(root):
    count=dependency_pins(tomllib.loads(Path('Cargo.lock').read_text())['package'],tomllib.loads(Path('docs/inputs/host-dependencies.toml').read_text())['rows'])
    version = subprocess.run([str(binary_directory()/'postgres'), '--version'], capture_output=True, text=True, check=True).stdout.strip()
    if version != 'postgres (PostgreSQL) '+TARGET:
        raise RuntimeError('unsupported PostgreSQL version; required declared prerelease')
    if (root/'data'/'postmaster.pid').exists():
        raise RuntimeError('fixture already running; do not replace an active instance')
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(mode=0o700, parents=True)
    (root/'socket').mkdir(mode=0o700)
    password = 'private_password_fixture_731'
    (root/'password').write_text(password+'\n')
    (root/'password').chmod(0o600)
    with (root/'fixture.log').open('wb') as log:
        command([binary_directory()/'initdb','-D',root/'data','--locale-provider=libc','--locale=C','--encoding=UTF8','-U','private_role_fixture_731','--auth=scram-sha-256','--pwfile',root/'password'],log)
        with (root/'data'/'postgresql.conf').open('a') as config:
            config.write("\nlisten_addresses='127.0.0.1'\nport=42100\nunix_socket_directories='"+str(root/'socket')+"'\nmax_connections=20\nshared_buffers='16MB'\nlog_line_prefix=''\ntimezone='Pacific/Honolulu'\ndatestyle='SQL, DMY'\n")
        command([binary_directory()/'pg_ctl','-D',root/'data','-l',root/'server.log','-w','start'],log)
        env = dict(os.environ, PGPASSWORD=password)
        command([binary_directory()/'createdb','-h',root/'socket','-p','42100','-U','private_role_fixture_731','private_database_fixture_731'],log,env)
    base = dict(transport='unix',endpoint=str(root/'socket'/'.s.PGSQL.42100'),port='42100',user='private_role_fixture_731',password=password,database='private_database_fixture_731')
    configurations = {
        'unix':base,
        'tcp':dict(base,transport='tcp',endpoint='127.0.0.1'),
        'wrong-password':dict(base,password='private_wrong_password_fixture_731'),
        'unknown-role':dict(base,user='private_unknown_role_fixture_731'),
        'unknown-database':dict(base,database='private_unknown_database_fixture_731'),
        'absent-socket':dict(base,endpoint=str(root/'absent_private_socket')),
        'refused-port':dict(base,transport='tcp',endpoint='127.0.0.1',port='42104'),
        'unreachable-host':dict(base,transport='tcp',endpoint='127.0.0.2',port='42104'),
    }
    for name, data in configurations.items():
        path = root/(name+'.json')
        path.write_text(json.dumps(data))
        path.chmod(0o600)
    print(f'HOST-POSTGRES version={TARGET} transport=unix,tcp persistence=disabled pinned_archives={count}')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['start','stop'])
    parser.add_argument('--root',required=True,type=Path)
    args=parser.parse_args()
    root=args.root.resolve()
    if root.parent != (Path.cwd()/'.lane').resolve():
        raise RuntimeError('fixture root must be directly under workspace .lane')
    try:
        (start if args.action=='start' else stop)(root)
    except Exception:
        if args.action=='start':
            stop(root)
        raise

if __name__=='__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'kind':'host_fixture_failure','message':'PostgreSQL fixture unavailable; inspect its private log'}),file=sys.stderr)
        sys.exit(1)
