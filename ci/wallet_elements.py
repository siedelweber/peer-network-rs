"""Own bounded genesis and signed-fixture Elements services; producer authority never enters pn-wallet."""
import argparse
import base64
from contextlib import contextmanager
from decimal import Decimal
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
import tomllib
import traceback

PROFILE = Path('packages/wallet/provisioning.json')


def binary():
    # The node layout is the caller's declaration, never a committed path.
    value = os.environ.get('PN_ELEMENTS_BIN')
    if not value:
        raise RuntimeError('PN_ELEMENTS_BIN must name the Elements binary directory')
    return Path(value)/'elementsd'


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


def rpc(config, method, params=None, credential=None, refusal=False):
    connection = http.client.HTTPConnection('127.0.0.1', config['port'], timeout=10)
    credential = credential if credential is not None else config['producer']
    try:
        connection.request('POST', '/', json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params or [])), {
            'Authorization': 'Basic ' + base64.b64encode(credential.encode()).decode(),
            'Connection': 'close', 'Content-Type': 'application/json'})
        response = connection.getresponse()
        body = response.read(8_001_025)
        if response.status not in (200, 400, 404, 500) or len(body) > 8_001_024:
            raise RuntimeError('Elements harness exchange refused')
        value = json.loads(body)
        if value.get('jsonrpc') != '2.0' or value.get('id') != 1:
            raise RuntimeError('Elements harness RPC refused')
        if refusal:
            if not isinstance(value.get('error', {}).get('code'), int):
                raise RuntimeError('Elements expected refusal absent')
            return value['error']['code']
        if 'error' in value:
            raise RuntimeError('Elements harness RPC refused: '+method)
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
    version = subprocess.run([binary(), '-version'], capture_output=True, text=True, check=True).stdout.splitlines()[0]
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
            result = subprocess.run([binary(), '-datadir='+str(root), '-daemonwait'], stdout=log, stderr=log, timeout=30)
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
    print('WALLET-ELEMENTS version=elements-29.4.1rc1 scope=genesis signed-fixtures=separate-route credentials=separate')


def signed(root):
    start(root)
    config = json.loads((root/'producer.json').read_text())
    profile = json.loads(PROFILE.read_text())
    challenge = bytes(profile['challenge']).hex()
    rpc(config, 'createwallet', ['producer', False, False, '', False, False])
    # The fixture challenge key is the secp256k1 generator, private scalar
    # one, which is publicly known: these blocks witness the node's signature
    # validation, not who produced them. No operator key is read, copied or
    # exposed to pn-wallet; the node signs blocks and transactions.
    payload = bytes([239]) + bytes(31) + bytes([1, 1])
    number = int.from_bytes(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4], 'big')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    key = ''
    while number:
        number, remainder = divmod(number, 58)
        key = alphabet[remainder] + key
    rpc(config, 'importprivkey', [key, 'fixture', True])
    if rpc(config, 'getwalletinfo')['descriptors']:
        raise RuntimeError('Elements producer is not a legacy wallet')
    blocks = []
    def mine():
        proposed = rpc(config, 'getnewblockhex')
        signatures = rpc(config, 'signblock', [proposed, challenge])
        combined = rpc(config, 'combineblocksigs', [proposed, signatures, challenge])
        if not combined['complete'] or rpc(config, 'submitblock', [combined['hex']]) is not None:
            raise RuntimeError('Elements signed fixture refused')
        locator = rpc(config, 'getbestblockhash')
        blocks.append(locator)
        (root/('block-'+str(len(blocks))+'.hex')).write_text(rpc(config, 'getblock', [locator, 0]))
        return locator
    proposed = rpc(config, 'getnewblockhex')
    signatures = rpc(config, 'signblock', [proposed, challenge])
    combined = rpc(config, 'combineblocksigs', [proposed, signatures, challenge])
    if not combined['complete']:
        raise RuntimeError('Elements challenge cannot be signed')
    encoded = bytes.fromhex(combined['hex'])
    signature = bytes.fromhex(signatures[0]['sig'])
    offset = encoded.index(signature)
    invalid = bytearray(encoded)
    invalid[offset + 10] ^= 1
    invalid_signature = rpc(config, 'submitblock', [invalid.hex()])
    # Dynafed full current parameters: replace the declared P2WSH program
    # with OP_TRUE. This is submitted to the same nontrivial deployed chain.
    if encoded[76:78] != bytes([2, 34]):
        raise RuntimeError('Elements fixture header shape differs')
    witness_start = offset - 2
    witness_end = offset + len(signature) + 1 + len(bytes.fromhex(challenge))
    if encoded[witness_start:offset] != bytes([2, len(signature)]):
        raise RuntimeError('Elements fixture signature stack differs')
    trivial = (encoded[:78] + bytes([0, 32]) + hashlib.sha256(bytes([81])).digest()
               + encoded[112:witness_start] + bytes([1, 1, 81]) + encoded[witness_end:])
    trivial_challenge = rpc(config, 'submitblock', [trivial.hex()])
    if invalid_signature != 'block-proof-invalid' or trivial_challenge != 'invalid-dyna-fed':
        raise RuntimeError('Elements signature/challenge negative witness differs')
    fee_asset = rpc(config, 'getsidechaininfo')['pegged_asset']
    genesis = rpc(config, 'getblockhash', [0])
    genesis_json = rpc(config, 'getblock', [genesis, 2])
    # Genesis OP_TRUE coins are fee funding, not exclusively controlled stock.
    # A distinct issuance has no token output and is never the pegged asset.
    stock = tomllib.loads(Path('docs/inputs/devnet-profile.toml').read_text())['rows'][0]['initial_units']
    if stock <= 0 or stock % 100_000_000:
        raise RuntimeError('Elements fixture stock must be a positive whole-token quantity')
    coins = rpc(config, 'listunspent')
    funding = [coin for coin in coins if coin['asset'] == fee_asset and coin['scriptPubKey'] == '51']
    if len(coins) != 1 or len(funding) != 1:
        raise RuntimeError('Elements genesis funding is not one anyone-can-spend output')
    def address(label):
        created = rpc(config, 'getnewaddress', [label, 'bech32'])
        return rpc(config, 'getaddressinfo', [created])['unconfidential']
    fee = Decimal('0.0001')
    def spend(coin, label):
        return rpc(config, 'createrawtransaction', [[dict(txid=coin['txid'], vout=coin['vout'])],
                   [{address(label): str(Decimal(str(coin['amount'])) - fee)}, {'fee': str(fee)}]])
    def send(raw, role):
        signed = rpc(config, 'signrawtransactionwithwallet', [raw])
        if not signed['complete']:
            raise RuntimeError('Elements '+role+' transaction is not signed')
        return rpc(config, 'sendrawtransaction', [signed['hex']])
    # The node refuses an issuance whose entropy input is the genesis
    # anyone-can-spend output, so block 1 first moves that whole output to
    # a producer-owned reserve; the issuance then spends the reserve.
    reserve = send(spend(funding[0], 'fee-reserve'), 'reserve')
    mine()
    owned = [coin for coin in rpc(config, 'listunspent') if coin['txid'] == reserve]
    if len(owned) != 1 or owned[0]['asset'] != fee_asset:
        raise RuntimeError('Elements fee reserve is not one producer-owned output')
    raw = spend(owned[0], 'fee-reserve')
    stock_address = address('initial-stock')
    stock_owner = rpc(config, 'getaddressinfo', [stock_address])
    if not stock_owner['ismine']:
        raise RuntimeError('Elements fixture stock is not controlled by producer wallet')
    issuance = rpc(config, 'rawissueasset', [raw, [dict(asset_amount=stock // 100_000_000,
                 asset_address=stock_address, blind=False)]])[0]
    issuance['txid'] = send(issuance['hex'], 'initial stock')
    if issuance['asset'] == fee_asset:
        raise RuntimeError('Elements fixture asset aliases pegged fee asset')
    mine()
    address = rpc(config, 'getnewaddress', ['grant', 'bech32'])
    address_info = rpc(config, 'getaddressinfo', [address])
    grant = rpc(config, 'sendtoaddress', dict(address=address_info['unconfidential'], amount=10,
                                            assetlabel=issuance['asset'], fee_rate=1))
    mine()
    address = rpc(config, 'getnewaddress', ['transfer', 'bech32'])
    address_info = rpc(config, 'getaddressinfo', [address])
    transfer = rpc(config, 'sendtoaddress', dict(address=address_info['unconfidential'], amount=2,
                                               assetlabel=issuance['asset'], fee_rate=1))
    mine()
    destruction = rpc(config, 'destroyamount', [issuance['asset'], 1])
    mine()
    reissuance = rpc(config, 'reissueasset', [issuance['asset'], 1], refusal=True)
    peg = rpc(config, 'claimpegin', ['', '', '', 1], refusal=True)
    transactions = dict(reserve=reserve, issuance=issuance['txid'], grant=grant, transfer=transfer,
                        destruction=destruction)
    for role, locator in transactions.items():
        (root/(role+'.hex')).write_text(rpc(config, 'getrawtransaction', [locator, False]))
    evidence = dict(blocks=blocks, transactions=transactions, asset=issuance['asset'], token=issuance['token'],
                    entropy=issuance['entropy'], fee_asset=fee_asset, initial_units=stock,
                    stock_script=stock_owner['scriptPubKey'], stock_owned=stock_owner['ismine'],
                    invalid_signature=invalid_signature, trivial_challenge=trivial_challenge,
                    reissuance_code=reissuance, malformed_peg_code=peg,
                    genesis=genesis_json, producer_descriptors=False)
    (root/'signed.json').write_text(json.dumps(evidence))
    print('WALLET-ELEMENTS version=elements-29.4.1rc1 scope=signed-fixtures blocks=5 credentials=separate')


def restart(root):
    with allocation_lock():
        stop(root)
        with (root/'private.log').open('ab') as log:
            result = subprocess.run([binary(), '-datadir='+str(root), '-daemonwait'], stdout=log, stderr=log, timeout=30)
        if result.returncode:
            raise RuntimeError('Elements restart failed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['start', 'signed', 'stop', 'stop-all', 'restart'])
    parser.add_argument('--root', required=True, type=Path)
    args = parser.parse_args()
    if args.action in ('start', 'signed', 'restart') and not os.environ.get('PN_ELEMENTS_BIN'):
        print('PN_ELEMENTS_BIN must name the Elements binary directory', file=sys.stderr)
        sys.exit(2)
    root = args.root.resolve()
    if root.parent != (Path.cwd()/'.lane').resolve():
        raise RuntimeError('Elements fixture must be directly under workspace .lane')
    os.umask(0o077)
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if args.action == 'stop-all':
            stop(root)
            for child in root.parent.iterdir():
                if child.is_dir() and child.name.startswith(('wallet-signed-', 'wallet-rotation-')):
                    stop(child)
        else:
            {'start':start,'signed':signed,'stop':stop,'restart':restart}[args.action](root)
    except BaseException:
        if root.is_dir():
            with (root/'harness-error.log').open('w') as log:
                traceback.print_exc(file=log)
        if args.action in ('start','signed','restart'):
            stop(root)
        raise


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Elements fixture unavailable; inspect private fixture log', file=sys.stderr)
        sys.exit(1)
