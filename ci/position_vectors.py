"""Independent position preimages: literal public fixture fields, RFC 8949, hashlib.

No Rust process, host helper or interchange encoder is called. These fixtures
describe the existing host publication fixture's root and ordinary child, plus
component projections over recognized marker fixtures; they prove no settlement.
"""
import hashlib
import json
from pathlib import Path

RECIPE = 'pn-host/result-position/v1'
TAG = 'PN-result-position-v1'

def encode(value):
    def head(major, number):
        if number < 24:
            return bytes([major * 32 + number])
        for size, discriminator in ((1, 24), (2, 25), (4, 26), (8, 27)):
            if number < 1 << (size * 8):
                return bytes([major * 32 + discriminator]) + number.to_bytes(size, 'big')
        raise ValueError('fixture unsigned overflow')
    if value is None:
        return b'\xf6'
    if isinstance(value, bool):
        return b'\xf5' if value else b'\xf4'
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode('utf-8')
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(encode(item) for item in value)
    if value == {}:
        return b'\xa0'
    raise ValueError('fixture kind outside projection')

def vectors():
    rows = []
    root = None
    # Deliberately not lexical order; consumers must not pre-sort these cases.
    for case in ['root', 'ordinary', 'initial-lineage', 'whole-prefix', 'commitment', 'utf8', 'set-order']:
        encoding = {'commitment': 1, 'whole-prefix': 2}.get(case, 0)
        history = 'histoire-λ' if case == 'utf8' else 'history'
        scope = [history, 'policy', '1', 'sequence']
        policy = ['policy', '1', 'sequence', '0', '1', 'm0', True,
                  'any party submits public evidence', 'one candidate per index; no liveness guarantee',
                  [encoding], [1], 'fixture-public-v1', '7']
        genesis = [['deployment', 'genesis', '1'], '0', '0', [1, '1']]
        record = ['r0', 'd0', 'a', [['30', '1'], 'burn']]
        initial_lineage = [record] if case in ('initial-lineage', 'set-order') else []
        def acceptance(initial):
            if encoding == 1:
                return [1, b'set:' if initial else b'set:r0']
            if encoding == 2:
                return [2]
            return [0, [] if initial else (['aa', 'b'] if case == 'set-order' else ['r0'])]
        initial = scope + [0, 0, None, initial_lineage, acceptance(True), [], {}, None]
        if case == 'ordinary':
            marker = scope + [2, 11, 10, [], [0, []], [], None, None]
            projection = [None, root, marker]
        else:
            lineage = [[identity, 'd0', 'a', [['30', '1'], 'burn']] for identity in ['aa', 'b']] if case == 'set-order' else ([] if initial_lineage else [record])
            marker = scope + [1, 10, 0, lineage, acceptance(False), ['aa', 'b'] if case == 'set-order' else ['r0'], None, None]
            projection = [[scope, genesis, policy, initial], None, marker]
        canonical = encode([TAG, projection])
        preimage = RECIPE.encode() + b'\0' + canonical
        residue = hashlib.sha256(preimage).digest()
        if case == 'root':
            root = residue
        rows.append({'case': case, 'canonical': canonical.hex(), 'preimage': preimage.hex(), 'residue': residue.hex()})
    return rows

def check(path):
    expected = vectors()
    if json.loads(Path(path).read_text()) != expected:
        raise ValueError('position fixtures differ from independent public projection')
    return {row['residue'] for row in expected}

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    path = Path('packages/host/src/admitted_result/position/vectors.json')
    if args.write:
        path.write_text(json.dumps(vectors(), indent=2) + '\n')
    check(path)
    print(f'POSITION-VECTORS distinct={len(vectors())} order=unsorted')
