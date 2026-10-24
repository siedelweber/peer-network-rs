"""Independent domain framing for storage's SHA-256 identity recipes."""
import hashlib
import json
from pathlib import Path

def vectors():
    return [dict(recipe=recipe, canonical_bytes=[128], digest=hashlib.sha256(recipe.encode()+b'\0'+bytes([128])).hexdigest())
            for recipe in ('pn-host/storage-payload/v1','pn-host/recognition-disclosure/v1')]

def check(path):
    expected=vectors()
    if json.loads(Path(path).read_text())!=expected:
        raise ValueError('storage recipe vector differs from independent domain framing')
    return {row['digest'] for row in expected}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    target=Path('packages/host/src/storage/vectors.json')
    if args.write:
        target.write_text(json.dumps(vectors(),indent=2)+'\n')
    check(target)
    print('STORAGE-VECTORS checked=2')
