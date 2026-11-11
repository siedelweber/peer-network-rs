"""Independent authentication CBOR and SHA-256 golden values; no Rust subprocess."""
import hashlib
import json
from pathlib import Path
from storage_vectors import canonical as scalar_canonical

EDITION = 'pn-act-authentication/author-token-bip340/v1'
PROPOSAL = 'pn-act-profile/act-proposal/v1'
CONTENT = 'pn-act-profile/act-content/v1'
DEPENDENCY = 'pn-act-profile/act-dependency/v1'
TARGET = Path('packages/act-authentication/tests/encoding-golden.json')

def head(major, count):
    if count < 24:
        return bytes([major * 32 + count])
    for size, extra in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if count < 1 << (size * 8):
            return bytes([major * 32 + extra]) + count.to_bytes(size, 'big')
    raise ValueError('integer range')

def canonical(value):
    # Reuse the independent storage fixture encoder for primitive values.
    # Arrays recurse here to add maps and negative authored integers.
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(canonical(v) for v in value)
    if isinstance(value, dict):
        entries = sorted((canonical(k), canonical(v)) for k, v in value.items())
        return head(5, len(entries)) + b''.join(k + v for k, v in entries)
    if isinstance(value, int) and value < 0:
        return head(1, -1 - value)
    return scalar_canonical(value)

def frame(recipe, tag, fields):
    return hashlib.sha256(recipe.encode() + b'\0' + canonical([tag, fields])).digest()

def vectors():
    rows = []
    for case, family, count in ((3, 'Opinion', 1), (0, 'Registration', 0), (7, 'Tag', 1024), (1, 'Withdraw', 0), (16, 'Registration', 0)):
        run = bytes([1 if case == 16 else case + 1]) * 32
        author = 'pn-devnet-v1/' + run.hex() + '/' + bytes([case + 2]).hex() * 32
        key = bytes([9]) * 32
        identity = ['act', author, 2**64 - 1 if case == 7 else (0 if case == 16 else case), family]
        named = ['named', 'addr', author]
        target = ['named', 'name', 'x' * (1024 if case == 7 else 1)]
        paired = family == 'Tag'
        legs = [['A', named, target], ['T', target, named]] if paired else [['binary', named, target]]
        names = {'Opinion': ['polarity', 'reaction'], 'Tag': ['confidence', 'relevance']}.get(family, [])
        quantities = sorted([[name + suffix, number, 'one', 0] for name in names for suffix, number in (('.denominator', 2**63 - 1 if case == 7 else 2), ('.numerator', -(2**63 - 1) if case == 7 and name == 'relevance' else 1))])
        parents = [['act', author, n, 'Registration'] for n in range(count)]
        body = [identity, 'paired' if paired else 'binary', legs, quantities, None, parents, [], None, 'full' if count else 'full-empty', 'full' if count else 'full-empty']
        nonce = identity[2].to_bytes(8, 'big') + bytes([11]) * 32
        payload = b'p' if count else b''
        deps = parents
        cy = frame(PROPOSAL, 'PN-content-pre-v1', [identity, nonce, payload])
        cd = frame(PROPOSAL, 'PN-dependency-pre-v1', [identity, nonce, deps])
        proposal = frame(PROPOSAL, 'PN-act-proposal-v1', [body, cy, cd])
        content = frame(CONTENT, 'PN-content-v1', [identity, proposal, bytes([12])*48, payload])
        dependency = frame(DEPENDENCY, 'PN-dependency-v1', [identity, proposal, bytes([13])*48, deps])
        signature = bytes([14])*64
        header = canonical({0:'org.peer-network.test.verified-act',1:[1,0,0],2:body,3:[PROPOSAL,proposal],4:signature,5:[CONTENT,content],6:[DEPENDENCY,dependency],7:'1',8:'1'})
        host = 'pn-host-bip340-v1/' + bytes([10]).hex()*32
        material = canonical([EDITION,run,key,host,bytes([10])*32])
        seal = bytes([15])*64
        messages = [proposal,frame('pn-act-authentication/host-seal/v1','PN-verified-act-v1',[run,host,header]),frame('pn-act-authentication/actor-approval/v1','PN-act-approval-v1',[run,host,header,seal])]
        rows.append(dict(nonce=nonce.hex(),payload=payload.hex(),dependencies=deps,case=case,header=header.hex(),material=material.hex(),messages=[m.hex() for m in messages],run=run.hex(),author=author,host=host,seal=seal.hex()))
    return dict(source='Python standard-library hashlib and independent canonical CBOR; primitive encoding reused from ci/storage_vectors.py; supplied nonce, salts and signatures are deterministic fixture bytes, not authentication evidence', rows=rows)

def check(value=None):
    expected=vectors()
    if (json.loads(TARGET.read_text()) if value is None else value) != expected:
        raise ValueError('authentication encoding golden values differ')
    return expected

if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    if args.write:
        TARGET.write_text(json.dumps(vectors(),indent=2)+'\n')
    check()
    print(json.dumps(dict(status='pass',rows=5)))
