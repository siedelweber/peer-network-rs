"""Own a genesis-only Elements service; producer authority never enters pn-wallet."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import struct
import sys
import time

BINARY = Path('/workspace/toolchains/elements/29.4.1rc1/bin/elementsd')
PROFILE = Path('packages/wallet/provisioning.json')


@contextmanager
def allocation_lock():
    # Same kernel-owned mutex as every PostgreSQL gate allocator; reservation
    # remains serialized until the daemon owns the TCP socket.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as lock:
        deadline = time.monotonic() + 60
        while True:
            try:
                lock.bind('\0pn-host-postgresql-ports-' + str(os.getuid()))
                break
            except OSError as error:
                if error.errno != 98 or time.monotonic() >= deadline:
                    raise RuntimeError('Elements gate ports unavailable') from None
                time.sleep(0.05)
        yield


@contextmanager
def port_selection():
    with allocation_lock():
        for port in range(42110, 42120):
            with socket.socket() as reservation:
                try:
                    reservation.bind(('127.0.0.1', port))
                except OSError:
                    continue
            yield port
            return
        raise RuntimeError('Elements gate port range exhausted')


def rpc(config, method, params=None, credential=None):
    connection = http.client.HTTPConnection('127.0.0.1', config['port'], timeout=10)
    credential = credential if credential is not None else config['producer']
    try:
        connection.request('POST', '/', json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params or [])), {
            'Authorization': 'Basic ' + base64.b64encode(credential.encode()).decode(),
            'Connection': 'close', 'Content-Type': 'application/json'})
        response = connection.getresponse()
        body = response.read(8_001_025)
        if response.status != 200 or len(body) > 8_001_024:
            raise RuntimeError('Elements harness exchange refused')
        value = json.loads(body)
        if value.get('jsonrpc') != '2.0' or value.get('id') != 1 or 'error' in value:
            raise RuntimeError('Elements harness RPC refused')
        return value['result']
    finally:
        connection.close()


def write_private(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def stop(root):
    pidfile = root/'elementsregtest'/'elementsd.pid'
    if not pidfile.exists():
        return
    pid = int(pidfile.read_text())
    try:
        config = json.loads((root/'producer.json').read_text())
        rpc(config, 'stop')
    except Exception:
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 20
    while pidfile.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if pidfile.exists():
        os.kill(pid, signal.SIGKILL)
        raise RuntimeError('Elements required forced shutdown')


def start(root):
    if (root/'elementsregtest'/'elementsd.pid').exists():
        raise RuntimeError('Elements fixture already running')
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(mode=0o700, parents=True)
    profile = json.loads(PROFILE.read_text())
    version = subprocess.run([BINARY, '-version'], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    if version != profile['binary']:
        raise RuntimeError('Elements binary differs from provisioning declaration')
    password, salt = secrets.token_hex(32), secrets.token_hex(16)
    producer = '__fixture_producer__:' + password
    auth = '__fixture_producer__:' + salt + '$' + hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    with port_selection() as port:
        config = dict(port=port, producer=producer)
        write_private(root/'producer.json', config)
        lines = ['chain=' + profile['chain'], 'server=1', 'rpcauth=' + auth, 'rpcwhitelistdefault=0',
                 'signblockscript=' + bytes(profile['challenge']).hex(), 'rpccookiefile=' + str(root/'cookie')]
        lines += [name+'='+value for name, value in profile['parameters'].items()]
        lines += ['[elementsregtest]', 'rpcport='+str(port), 'rpcbind=127.0.0.1', 'rpcallowip=127.0.0.1']
        (root/'elements.conf').write_text('\n'.join(lines)+'\n')
        (root/'elements.conf').chmod(0o600)
        with (root/'private.log').open('wb') as log:
            result = subprocess.run([BINARY, '-datadir='+str(root), '-daemonwait'], stdout=log, stderr=log, timeout=30)
        if result.returncode:
            raise RuntimeError('Elements startup failed; private fixture log retained')
    info = rpc(config, 'getblockchaininfo')
    if info['chain'] != profile['chain'] or info['blocks'] != 0:
        raise RuntimeError('Elements startup chain differs')
    challenge = bytes(profile['challenge'])
    if len(challenge) != 35 or challenge[0] != 33 or challenge[-1] != 172:
        raise RuntimeError('Elements challenge is not the declared nontrivial P2PK script')
    if info['current_signblock_hex'] != '0020'+hashlib.sha256(challenge).hexdigest():
        raise RuntimeError('Elements active signing challenge differs')
    cookie = (root/'cookie').read_bytes()
    if len(cookie) != 75 or cookie[:11] != b'__cookie__:' or any(byte not in b'0123456789abcdef' for byte in cookie[11:]):
        raise RuntimeError('Elements cookie grammar differs')
    if cookie.decode() == producer:
        raise RuntimeError('Elements producer credential is not separate')
    for name, content in [('wrong-cookie',b'__cookie__:'+b'0'*64),('partial-cookie',b'partial'),('acl-cookie',cookie)]:
        (root/name).write_bytes(content)
        (root/name).chmod(0o600)
    (root/'acl-parent').mkdir(mode=0o700)
    (root/'acl-parent'/'cookie').write_bytes(cookie)
    (root/'acl-parent'/'cookie').chmod(0o600)
    def acl(owner, named, mask, other=0):
        return struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,permissions,uid) for tag,permissions,uid in [
            (1,owner,0xffffffff),(2,named,os.getuid()+1),(4,0,0xffffffff),(16,mask,0xffffffff),(32,other,0xffffffff)])
    os.setxattr(root/'acl-cookie','system.posix_acl_access',acl(6,4,4))
    os.setxattr(root/'acl-parent','system.posix_acl_access',acl(7,3,3))
    genesis = rpc(config, 'getblockhash', [0])
    header = rpc(config, 'getblockheader', [genesis, False])
    block = rpc(config, 'getblock', [genesis, 0])
    # Both independent credentials reach the same public genesis. Only the
    # separate producer route can select arbitrary harness RPC methods.
    if rpc(config, 'getblockhash', [0], cookie.decode()) != genesis:
        raise RuntimeError('Elements reader credential cannot reach genesis')
    declaration = dict(profile, genesis=list(bytes.fromhex(genesis)), header=list(bytes.fromhex(header)))
    write_private(root/'reader.json', dict(endpoint='127.0.0.1', port=port, cookie='cookie', uid=os.getuid()))
    (root/'provisioning.json').write_text(json.dumps(declaration))
    (root/'genesis-block.hex').write_text(block)
    (root/'credential-separation.json').write_text(json.dumps(dict(separate=True, producer_cookie=False, reader_cookie=True, chain=info['chain'])))
    print('WALLET-ELEMENTS version=elements-29.4.1rc1 scope=genesis signed-fixtures=held credentials=separate')


def restart(root):
    with allocation_lock():
        stop(root)
        with (root/'private.log').open('ab') as log:
            result = subprocess.run([BINARY, '-datadir='+str(root), '-daemonwait'], stdout=log, stderr=log, timeout=30)
        if result.returncode:
            raise RuntimeError('Elements restart failed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['start', 'stop', 'restart'])
    parser.add_argument('--root', required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if root.parent != (Path.cwd()/'.lane').resolve():
        raise RuntimeError('Elements fixture must be directly under workspace .lane')
    os.umask(0o077)
    try:
        {'start':start,'stop':stop,'restart':restart}[args.action](root)
    except BaseException:
        if args.action in ('start','restart'):
            stop(root)
        raise


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Elements fixture unavailable; inspect private fixture log', file=sys.stderr)
        sys.exit(1)
