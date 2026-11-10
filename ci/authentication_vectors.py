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
            funding_address = rpc('getnewaddress', ['author-funding', 'bech32'])
            funding_address = rpc('getaddressinfo', [funding_address])['unconfidential']
            funding_txid = rpc('sendtoaddress', dict(address=funding_address, amount=1, assetlabel=fee_asset))
            elements.sign_block(root, False)
            rows = []
            for ordinal, contract in enumerate(['00' * 32, '11' * 32, bytes(range(32)).hex()]):
                coins = rpc('listunspent', [0])
                coin = next(coin for coin in coins if coin['asset'] == fee_asset
                    and coin['txid'] == funding_txid and coin['address'] == funding_address)
                address = rpc('getnewaddress', ['author-vector', 'bech32'])
                address = rpc('getaddressinfo', [address])['unconfidential']
                marker = b'PNAT\x01' + bytes([ordinal + 1]) * 32 + bytes(5)
                raw = rpc('createrawtransaction', [[dict(txid=coin['txid'], vout=coin['vout'])],
                    [{address: str(Decimal(str(coin['amount'])) - Decimal('0.0001'))},
                     {'data': marker.hex()}, {'fee': '0.0001'}]])
                parameters = [raw, [dict(asset_amount=0.00000001,
                    asset_address=address, blind=False, contract_hash=contract)]]
                try:
                    issued = rpc('rawissueasset', parameters)[0]
                except RuntimeError:
                    detail = elements.rpc(config, 'rawissueasset', parameters, refusal=True, detail=True)
                    raise RuntimeError(str(detail) + '\n' + help_text) from None
                signed = rpc('signrawtransactionwithwallet', [issued['hex']])
                if not signed['complete']:
                    raise RuntimeError('incomplete fixture signature')
                try:
                    txid = rpc('sendrawtransaction', [signed['hex']])
                except RuntimeError:
                    detail = elements.rpc(config, 'sendrawtransaction', [signed['hex']], refusal=True, detail=True)
                    raise RuntimeError(json.dumps(dict(refusal=detail, ordinal=ordinal))) from None
                funding_txid = txid
                funding_address = address
                elements.sign_block(root, False)
                decoded = rpc('decoderawtransaction', [signed['hex']])
                rows.append(dict(id='issuance-' + str(ordinal), txid=txid, transaction=signed['hex'],
                    asset=issued['asset'], contract=bytes.fromhex(contract)[::-1].hex(),
                    contract_rpc=contract, prevout=coin['txid'],
                    vout=coin['vout'], run=(bytes([ordinal + 1]) * 32).hex(), decoded=decoded))
            keys = []
            for key in [bytes(32), bytes([255]) * 32, bytes(range(32))]:
                digest = hashlib.sha256(b'pn-act-authentication/signing-key-hash/v1\0' + key).hexdigest()
                keys.append(dict(encoding=key.hex(), digest=digest, script=b'\x6a\x25PNAK\x01'.hex() + digest))
            return dict(producer=elements.installed_version(root), key_route='Python hashlib.sha256',
                rawissueasset_help=help_text, fee_asset=fee_asset, assets=rows, keys=keys)
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
