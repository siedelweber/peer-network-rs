"""Own an isolated, real PostgreSQL prerelease for the transport evidence."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
import socket
import time
from contextlib import contextmanager

@contextmanager
def port_selection():
    """Serialize allocation until PostgreSQL owns its reserved TCP port.

    The Linux abstract socket is common to this user's gate processes, without
    relying on their checkout or TMPDIR. The kernel releases it on process exit.
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as lock:
        deadline = time.monotonic() + 60
        while True:
            try:
                lock.bind('\0pn-host-postgresql-ports-' + str(os.getuid()))
                break
            except OSError as error:
                if error.errno != 98 or time.monotonic() >= deadline:
                    raise RuntimeError('PostgreSQL port allocation unavailable') from None
                time.sleep(0.05)
        for port in range(42100, 42120):
            with socket.socket() as reservation:
                try:
                    reservation.bind(('127.0.0.1', port))
                except OSError:
                    continue
                # Keep the allocation mutex through server startup. All gate
                # allocators use this mutex; the server then owns the port.
                reservation.close()
                yield port
                return
        raise RuntimeError('PostgreSQL reserved port range exhausted')

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
    numeric=tomllib.loads(Path('docs/inputs/numeric-dependencies.toml').read_text())['rows']
    admitted_git={(row['name'],row['version']):row['source'] for row in numeric if row.get('source','').startswith('git+')}
    for (name,version),package in seen.items():
        if package.get('source','').startswith('git+') and admitted_git.get((name,version))!=package['source']:
            raise ValueError('host dependency closure differs from reviewed git pins')
    actual={name+' '+version:package['checksum'] for (name,version),package in seen.items() if package.get('source','').startswith('registry+')}
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
        with port_selection() as port:
            with (root/'data'/'postgresql.conf').open('a') as config:
                config.write("\nlisten_addresses='127.0.0.1'\nport="+str(port)+"\nunix_socket_directories='"+str(root/'socket')+"'\nmax_connections=64\nshared_buffers='16MB'\nlog_line_prefix=''\ntimezone='Pacific/Honolulu'\ndatestyle='SQL, DMY'\n")
            command([binary_directory()/'pg_ctl','-D',root/'data','-l',root/'server.log','-w','start'],log)
        env = dict(os.environ, PGPASSWORD=password)
        command([binary_directory()/'createdb','-h',root/'socket','-p',port,'-U','private_role_fixture_731','private_database_fixture_731'],log,env)
        for suffix in ('storage','storage-race','storage-rebuild','storage-schema','storage-restart','storage-constants','storage-scaling','storage-trace-initial','storage-trace-default','storage-trace-trace'):
            command([binary_directory()/'createdb','-h',root/'socket','-p',port,'-U','private_role_fixture_731','private_'+suffix.replace('-','_')+'_731'],log,env)
    base = dict(transport='unix',endpoint=str(root/'socket'/('.s.PGSQL.'+str(port))),port=str(port),user='private_role_fixture_731',password=password,database='private_database_fixture_731')
    configurations = {
        'unix':base,
        'tcp':dict(base,transport='tcp',endpoint='127.0.0.1'),
        'wrong-password':dict(base,password='private_wrong_password_fixture_731'),
        'unknown-role':dict(base,user='private_unknown_role_fixture_731'),
        'unknown-database':dict(base,database='private_unknown_database_fixture_731'),
        'absent-socket':dict(base,endpoint=str(root/'absent_private_socket')),
        # Gate servers bind only 127.0.0.1. Their own reserved port is never
        # another gate's endpoint on these distinct loopback addresses.
        'refused-port':dict(base,transport='tcp',endpoint='127.0.0.2'),
        'unreachable-host':dict(base,transport='tcp',endpoint='127.0.0.3'),
    }
    configurations.update({suffix:dict(base,database='private_'+suffix.replace('-','_')+'_731') for suffix in ('storage','storage-race','storage-rebuild','storage-schema','storage-restart','storage-constants','storage-scaling','storage-trace-initial','storage-trace-default','storage-trace-trace')})
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
