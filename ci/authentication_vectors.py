"""Regenerate public authentication vectors with the admitted Elements daemon.

Run with pn-env: python3 -B ci/authentication_vectors.py --generate PATH.
Unit tests consume the committed output; they never start a service.
"""
import argparse
from contextlib import redirect_stdout
from decimal import Decimal
import hashlib
import io
import json
import math
import os
from pathlib import Path
import tempfile
import traceback

import wallet_elements as elements


def midpoint(left, right):
    """Independent single-block SHA-256 compression, without final padding."""
    primes = []
    candidate = 2
    while len(primes) < 64:
        if all(candidate % p for p in primes if p * p <= candidate):
            primes.append(candidate)
        candidate += 1
    mask = (1 << 32) - 1
    def cube_root(n):
        low, high = 0, 1 << 36
        while high - low > 1:
            middle = (low + high) // 2
            if middle ** 3 <= n:
                low = middle
            else:
                high = middle
        return low
    constants = [cube_root(p << 96) & mask for p in primes]
    initial = [math.isqrt(p << 64) & mask for p in primes[:8]]
    rotate = lambda x, n: ((x >> n) | (x << (32 - n))) & mask
    block = left + right
    words = [int.from_bytes(block[i:i+4], 'big') for i in range(0, 64, 4)]
    for i in range(16, 64):
        x, y = words[i-15], words[i-2]
        words.append((words[i-16] + (rotate(x, 7) ^ rotate(x, 18) ^ (x >> 3)) +
            words[i-7] + (rotate(y, 17) ^ rotate(y, 19) ^ (y >> 10))) & mask)
    a, b, c, d, e, f, g, h = initial
    for word, constant in zip(words, constants):
        first = (h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) +
            ((e & f) ^ (~e & g)) + constant + word) & mask
        second = ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) +
            ((a & b) ^ (a & c) ^ (b & c))) & mask
        a, b, c, d, e, f, g, h = (first + second) & mask, a, b, c, (d + first) & mask, e, f, g
    return b''.join(((x + y) & mask).to_bytes(4, 'big') for x, y in zip(initial, [a,b,c,d,e,f,g,h]))


def transaction_parts(text):
    """Independent bounded fixture decoder; retain consensus sections verbatim."""
    raw = bytes.fromhex(text)
    at = 0
    def take(n):
        nonlocal at
        if n < 0 or at + n > len(raw):
            raise ValueError('truncated transaction')
        result = raw[at:at+n]; at += n
        return result
    def count():
        first = take(1)[0]
        if first < 253: return first
        width = {253: 2, 254: 4, 255: 8}[first]
        n = int.from_bytes(take(width), 'little')
        if n < {253:253,254:65536,255:4294967296}[first] or n > 100000:
            raise ValueError('noncanonical or excessive fixture count')
        return n
    def vector(): return take(count())
    def confidential(explicit):
        prefix = take(1)
        return prefix + take(0 if prefix == b'\0' else explicit if prefix == b'\1' else 32)
    version = take(4); flags = take(1)
    if flags not in (b'\0',b'\1'): raise ValueError('transaction flag')
    n = count(); inputs = []
    for _ in range(n):
        start = at; prevout = take(36); script = vector(); sequence = take(4)
        index = int.from_bytes(prevout[32:], 'little'); issuance = None
        if index != 0xffffffff and index & 0x80000000:
            nonce = take(32); contract = take(32)
            issuance = dict(nonce=nonce, contract=contract, amount=confidential(8), token_amount=confidential(8))
        inputs.append(dict(raw=raw[start:at], prevout=prevout[:32]+(index & 0x3fffffff).to_bytes(4,'little'), issuance=issuance))
    m = count(); outputs = []
    for _ in range(m):
        start = at; asset = confidential(32); amount = confidential(8); nonce = confidential(32); script = vector()
        outputs.append(dict(raw=raw[start:at], asset=asset, amount=amount, nonce=nonce, script=script))
    lock = take(4); input_witness = []; output_witness = []
    if flags == b'\1':
        for _ in inputs:
            start = at; vector(); vector()
            for _ in range(count()): vector()
            for _ in range(count()): vector()
            input_witness.append(raw[start:at])
        for _ in outputs:
            start = at; vector(); vector(); output_witness.append(raw[start:at])
    if at != len(raw): raise ValueError('trailing transaction bytes')
    if n >= 253 or m >= 253: raise ValueError('fixture compact-count scope')
    base = version + b'\0' + bytes([n]) + b''.join(i['raw'] for i in inputs) + bytes([m]) + b''.join(o['raw'] for o in outputs) + lock
    reordered = version + flags + bytes([n]) + b''.join(i['raw'] for i in reversed(inputs)) + bytes([m]) + b''.join(o['raw'] for o in outputs) + lock + b''.join(reversed(input_witness)) + b''.join(output_witness)
    return dict(inputs=inputs, outputs=outputs, base=base, reordered=reordered)


def check(value):
    """Recompute declared scripts and digests without the Rust implementation."""
    for row in value['keys']:
        key = bytes.fromhex(row['encoding'])
        if len(key) != 32:
            raise ValueError('key length differs')
        digest = hashlib.sha256(b'pn-act-authentication/signing-key-hash/v1\0' + key).hexdigest()
        if row['digest'] != digest or row['script'] != b'\x6a\x25PNAK\x01'.hex() + digest:
            raise ValueError('key digest or script differs')
    for row in value['assets']:
        if row.get('marker_version') == 2:
            check_version_two(row, value['fee_asset'])
            continue
        wire = bytes.fromhex(row['transaction'])
        if wire[4:6] != bytes([1, 1]) or wire[42] != 0:
            raise ValueError('fixture transaction header differs')
        if wire[79:111].hex() != row['contract'] or bytes.fromhex(row['contract_rpc'])[::-1].hex() != row['contract']:
            raise ValueError('contract byte order differs')
        marker = b'\x6a\x2aPNAT\x01'.hex() + row['run'] + '0000000000'
        matches = [output for output in row['decoded']['vout'] if output['scriptPubKey']['hex'] == marker]
        if len(matches) != 1 or matches[0]['value'] != 0 or matches[0]['asset'] != value['fee_asset']:
            raise ValueError('qualification script differs')
        if row['decoded']['vin'][0]['issuance']['asset'] != row['asset']:
            raise ValueError('daemon identifier differs')
        prevout = bytes.fromhex(row['prevout'])[::-1] + row['vout'].to_bytes(4, 'little')
        if wire[6:38] != prevout[:32] or int.from_bytes(wire[38:42], 'little') != row['vout'] | 0x80000000:
            raise ValueError('issuance prevout differs')
        digest = hashlib.sha256(hashlib.sha256(prevout).digest()).digest()
        asset = midpoint(midpoint(digest, bytes.fromhex(row['contract'])), bytes(32))[::-1].hex()
        if asset != row['asset']:
            raise ValueError('independent asset identifier differs')
    return len(value['assets']), len(value['keys'])


def check_version_two(row, fee_asset):
    parts = transaction_parts(row['transaction'])
    prevout = bytes.fromhex(row['prevout'])[::-1] + row['vout'].to_bytes(4,'little')
    inputs = [i for i in parts['inputs'] if i['prevout'] == prevout]
    if len(inputs) != 1 or inputs[0]['issuance'] is None: raise ValueError('issuance prevout differs')
    contract = inputs[0]['issuance']['contract']
    if contract.hex() != row['contract'] or contract[::-1].hex() != row['contract_rpc']: raise ValueError('contract differs')
    digest = hashlib.sha256(hashlib.sha256(prevout).digest()).digest()
    if midpoint(midpoint(digest,contract),bytes(32))[::-1].hex() != row['asset']: raise ValueError('asset differs')
    marker = b'\x6a\x4aPNAT\x02' + bytes.fromhex(row['run']) + prevout + b'\0'
    matches = [o for o in parts['outputs'] if o['script']==marker]
    if len(matches)!=1 or matches[0]['asset']!=b'\1'+bytes.fromhex(fee_asset)[::-1] or matches[0]['amount']!=b'\1'+bytes(8) or matches[0]['nonce']!=b'\0': raise ValueError('marker differs')
    if bytes.fromhex(row['run']) == bytes.fromhex(row['run'])[::-1]: raise ValueError('palindromic run')
    if 'reordered_transaction' in row and parts['reordered'].hex()!=row['reordered_transaction']: raise ValueError('reorder differs')


def generate():
    with tempfile.TemporaryDirectory(prefix='author-vectors-', dir=os.environ['TMPDIR']) as directory:
        root = Path(directory)
        try:
            with redirect_stdout(io.StringIO()):
                elements.signed(root)
            config = json.loads((root / 'producer.json').read_text())
            rpc = lambda method, params=None: elements.rpc(config, method, params)
            help_text = rpc('help', ['rawissueasset'])
            fee_asset = rpc('getsidechaininfo')['pegged_asset']
            legacy = json.loads(Path('packages/act-authentication/tests/golden.json').read_text())
            rows = []
            for ordinal, contract in enumerate(['00' * 32, '11' * 32, bytes(range(32)).hex()]):
                coins = []
                for part in range(1 if ordinal == 0 else 2):
                    address = rpc('getnewaddress', ['author-funding', 'bech32'])
                    address = rpc('getaddressinfo', [address])['unconfidential']
                    funding = rpc('sendtoaddress', dict(address=address,amount=1,assetlabel=fee_asset))
                    elements.sign_block(root, False)
                    coins.append(next(c for c in rpc('listunspent',[0]) if c['txid']==funding and c['asset']==fee_asset and c['address']==address))
                    rpc('lockunspent',[False,[dict(txid=coins[-1]['txid'],vout=coins[-1]['vout'])]])
                address = rpc('getnewaddress', ['author-vector','bech32'])
                address = rpc('getaddressinfo',[address])['unconfidential']
                run = bytes(range(ordinal*32,(ordinal+1)*32))
                coin = coins[0]
                prevout = bytes.fromhex(coin['txid'])[::-1]+coin['vout'].to_bytes(4,'little')
                marker = b'PNAT\x02'+run+prevout+b'\0'
                raw = rpc('createrawtransaction', [[dict(txid=c['txid'],vout=c['vout']) for c in coins],
                    [{address: str(sum(Decimal(str(c['amount'])) for c in coins)-Decimal('0.0001'))}, {'data':marker.hex()},{'fee':'0.0001'}]])
                issues = [dict(asset_amount=0.00000001,asset_address=address,blind=False,contract_hash=contract)]
                if ordinal==2: issues.append(dict(asset_amount=0.00000001,asset_address=address,blind=False,contract_hash='22'*32))
                issued = rpc('rawissueasset',[raw,issues])
                signed = rpc('signrawtransactionwithwallet',[issued[-1]['hex'],[],'ALL|ANYONECANPAY'])
                if not signed['complete']: raise RuntimeError('incomplete fixture signature ordinal '+str(ordinal)+': '+json.dumps(signed.get('errors')))
                decoded = rpc('decoderawtransaction',[signed['hex']])
                row = dict(id='issuance-'+str(ordinal),marker_version=2,txid=decoded['txid'],transaction=signed['hex'],
                    asset=issued[0]['asset'],contract=bytes.fromhex(contract)[::-1].hex(),contract_rpc=contract,
                    prevout=coin['txid'],vout=coin['vout'],run=run.hex(),decoded=decoded,
                    issuance_results=[{k:v for k,v in i.items() if k!='hex'} for i in issued])
                if ordinal:
                    reordered=transaction_parts(signed['hex'])['reordered'].hex()
                    checked=rpc('testmempoolaccept',[[reordered]])
                    if not checked[0]['allowed']: raise RuntimeError('reordered fixture refused: '+json.dumps(checked))
                    row['reordered_transaction']=reordered
                    row['reordered_txid']=rpc('decoderawtransaction',[reordered])['txid']
                txid=rpc('sendrawtransaction',[signed['hex']])
                if txid!=row['txid']: raise RuntimeError('producer txid differs')
                elements.sign_block(root,False)
                rows.append(row)
            keys = []
            for key in [bytes(32), bytes([255]) * 32, bytes(range(32))]:
                digest = hashlib.sha256(b'pn-act-authentication/signing-key-hash/v1\0' + key).hexdigest()
                keys.append(dict(encoding=key.hex(), digest=digest, script=b'\x6a\x25PNAK\x01'.hex() + digest))
            return dict(producer=elements.installed_version(root), key_route='Python hashlib.sha256',
                rawissueasset_help=help_text, fee_asset=fee_asset, assets=rows, keys=keys,
                legacy_version_one=legacy.get('legacy_version_one',legacy['assets']),
                byte_orders=dict(prevout='display transaction id',vout='integer output index',contract='consensus raw contract',contract_rpc='RPC display contract',run='opaque bytes; never reversed',txid='display transaction id',reordered_txid='display transaction id'),
                reordered_status='Unconfirmed alternative accepted by testmempoolaccept before the original was broadcast; identical ANYONECANPAY witnesses, not a second mined spend.')
        finally:
            elements.stop(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generate', type=Path, required=True)
    args = parser.parse_args()
    try:
        value = generate()
        check(value)
        args.generate.parent.mkdir(parents=True, exist_ok=True)
        args.generate.write_text(json.dumps(value, indent=2) + '\n')
        print(json.dumps(dict(status='generated', assets=len(value['assets']), keys=len(value['keys']))))
    except Exception as error:
        print(json.dumps(dict(status='refused', error=repr(error), trace=traceback.format_exc())))
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
