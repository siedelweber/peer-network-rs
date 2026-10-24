"""Recompute the permanent marker-policy/v1 correspondence corpus independently."""
import hashlib
import json
from pathlib import Path


def vectors():
    texts = ('marker/policy', 'edition-7', 'sequence-public', 'genesis',
             'open placement', 'cadence-public', 'verifier-v1')
    framed = bytearray(b'pn-records/marker-policy/v1\0')
    for text in texts:
        encoded = text.encode('utf-8')
        framed.extend(len(encoded).to_bytes(8, 'big'))
        framed.extend(encoded)
    for number in (3, 11, 5):
        framed.extend(number.to_bytes(8, 'big'))
    framed.append(1)
    return [[encoding, rule, hashlib.sha256(framed + bytes((encoding, rule))).hexdigest()]
            for encoding in range(3) for rule in range(2)]


def check(path):
    expected = vectors()
    if json.loads(Path(path).read_text()) != expected:
        raise ValueError('policy vector differs from the permanent framed recipe')
    return {row[2] for row in expected}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    target = Path('packages/records/tests/public/policy-digest-v1.json')
    if args.write:
        target.write_text(json.dumps(vectors(), indent=2) + '\n')
    check(target)
    print('POLICY-VECTORS checked=6 recipe=pn-records/marker-policy/v1')
