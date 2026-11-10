"""Independent BIP-340 publication validity with Python integers and hashlib.

No signing or native binding. The CSV is the unchanged publication at bitcoin/bips
200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb, bip-0340/test-vectors.csv.
"""
import csv
import hashlib
import io
import json
from pathlib import Path

FIELD = 2**256 - 2**32 - 977
ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
GENERATOR = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
             0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


def lift(encoded):
    if len(encoded) != 32:
        return None
    x = int.from_bytes(encoded, 'big')
    if x >= FIELD:
        return None
    square = (x*x*x + 7) % FIELD
    y = pow(square, (FIELD+1)//4, FIELD)
    if y*y % FIELD != square:
        return None
    return (x, y if y % 2 == 0 else FIELD-y)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y+v) % FIELD == 0:
        return None
    slope = ((3*x*x)*pow(2*y, -1, FIELD) if a == b else (v-y)*pow(u-x, -1, FIELD)) % FIELD
    out = (slope*slope-x-u) % FIELD
    return out, (slope*(x-out)-y) % FIELD


def multiply(n, point):
    result = None
    while n:
        if n & 1:
            result = add(result, point)
        point = add(point, point)
        n >>= 1
    return result


def verify(key, signature, message):
    point = lift(key)
    if point is None or len(signature) != 64:
        return False
    r, s = int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big')
    if r >= FIELD or s >= ORDER:
        return False
    tag = hashlib.sha256(b'BIP0340/challenge').digest()
    challenge = int.from_bytes(hashlib.sha256(tag+tag+signature[:32]+key+message).digest(), 'big') % ORDER
    result = add(multiply(s, GENERATOR), multiply(ORDER-challenge, point))
    return result is not None and result[1] % 2 == 0 and result[0] == r


def check(root=Path('.')):
    directory = root/'packages/act-authentication/tests'
    raw = (directory/'bip340.csv').read_bytes()
    if hashlib.sha256(raw).hexdigest() != '34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d':
        raise ValueError('BIP-340 publication bytes differ')
    rows = list(csv.DictReader(io.StringIO(raw.decode())))
    if [int(r['index']) for r in rows] != list(range(19)):
        raise ValueError('BIP-340 publication inventory differs')
    for row in reversed(rows):
        actual = verify(bytes.fromhex(row['public key']), bytes.fromhex(row['signature']), bytes.fromhex(row['message']))
        if actual != (row['verification result'] == 'TRUE'):
            raise ValueError('BIP-340 publication equation differs at '+row['index'])
    cases = json.loads((directory/'malformed-points.json').read_text())['cases']
    for row in reversed(cases):
        encoded = bytes.fromhex(row['encoding'])
        expected = 'length' if len(encoded) != 32 else 'invalid-point'
        if expected != row['class'] or lift(encoded) is not None:
            raise ValueError('malformed point class differs')
    return dict(publication_rows=len(rows), malformed_points=len(cases), valid=sum(r['verification result']=='TRUE' for r in rows))


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
