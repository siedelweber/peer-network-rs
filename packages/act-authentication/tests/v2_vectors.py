"""Independent fixture route: standard-library CBOR framing and SHA-256 only. (´def:authentication:version-two´)"""
import hashlib
import json
import sys
from pathlib import Path


def head(major, count):
    if count < 24:
        return bytes([major * 32 + count])
    for size, extra in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if count < 1 << (size * 8):
            return bytes([major * 32 + extra]) + count.to_bytes(size, 'big')
    raise ValueError('integer range')


def canonical(value):
    if value is None:
        return b'\xf6'
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1-value)
    if isinstance(value, str):
        encoded = value.encode()
        return head(3, len(encoded)) + encoded
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(canonical(v) for v in value)
    if isinstance(value, dict):
        entries = sorted((canonical(k), canonical(v)) for k, v in value.items())
        return head(5, len(entries)) + b''.join(k+v for k, v in entries)
    raise ValueError('fixture type')


def vectors():
    rows = []
    for case, family, count in ((3, 'Opinion', 2), (0, 'Registration', 0), (7, 'Tag', 1024)):
        run = bytes([case+1])*32
        author = 'pn-devnet-v1/'+run.hex()+'/'+(bytes([case+2])*32).hex()
        identity = ['act', author, 2**64-1 if case == 7 else case, family]
        named = ['named', 'addr', author]
        target = ['named', 'name', 'x']
        paired = family == 'Tag'
        legs = [['A', named, target], ['T', target, named]] if paired else [['binary', named, target]]
        names = {'Opinion': ['polarity', 'reaction'], 'Tag': ['confidence', 'relevance']}.get(family, [])
        quantities = sorted([[name+suffix, number, 'one', 0] for name in names for suffix, number in (('.denominator', 2), ('.numerator', 1))])
        deps = [['act', author, n, 'Registration'] for n in range(count)]
        retirement = bytes(range(32))
        body = [identity, retirement, 'paired' if paired else 'binary', legs, quantities, None, deps, [], None, 'full' if count else 'full-empty', 'full' if count else 'full-empty']
        ny = identity[2].to_bytes(8, 'big')+bytes([11])*32
        nd = identity[2].to_bytes(8, 'big')+bytes([21])*32
        payload = b'content' if count else b''
        sy, sd = bytes([12])*48, bytes([13])*48
        preimages = {}
        def frame(role, tag, fields):
            recipe = 'pn-act-profile/act-'+role+'/v2'
            value = recipe.encode()+b'\0'+canonical([tag, fields])
            preimages[tag] = value.hex()
            return hashlib.sha256(value).digest()
        hy = frame('proposal', 'PN-content-pre-v2', [identity, ny, payload])
        hd = frame('proposal', 'PN-dependency-pre-v2', [identity, nd, deps])
        p = frame('proposal', 'PN-act-proposal-v2', [body, hy, hd])
        cy = frame('content', 'PN-content-v2', [identity, p, sy, hy])
        cd = frame('dependency', 'PN-dependency-v2', [identity, p, sd, deps])
        signature, seal = bytes([14])*64, bytes([15])*64
        header = canonical({0:'org.peer-network.test.verified-act',1:[2,0,0],2:body,3:['pn-act-profile/act-proposal/v2',p],4:signature,5:['pn-act-profile/act-content/v2',cy],6:['pn-act-profile/act-dependency/v2',cd],7:'2',8:'2'})
        host = 'pn-host-bip340-v1/'+(bytes([10])*32).hex()
        material = canonical(['pn-act-authentication/author-token-bip340/v2',run,bytes([9])*32,host,bytes([10])*32])
        messages = [p]
        for recipe, tag, fields in [('host-seal/v1','PN-verified-act-v1',[run,host,header]),('actor-approval/v1','PN-act-approval-v1',[run,host,header,seal])]:
            value = ('pn-act-authentication/'+recipe).encode()+b'\0'+canonical([tag,fields])
            preimages[tag] = value.hex()
            messages.append(hashlib.sha256(value).digest())
        rows.append(dict(case=case,body=canonical(body).hex(),header=header.hex(),material=material.hex(),ny=ny.hex(),nd=nd.hex(),payload=payload.hex(),dependencies=deps,sy=sy.hex(),sd=sd.hex(),hy=hy.hex(),hd=hd.hex(),p=p.hex(),cy=cy.hex(),cd=cd.hex(),run=run.hex(),host=host,seal=seal.hex(),messages=[m.hex() for m in messages],preimages=preimages))
    return dict(source='Independent Python standard-library framing and hashlib; no Rust, production projection or production helper calls. Public deterministic fixture inputs establish no entropy, signature validity or authority.', rows=rows)


if __name__ == '__main__':
    expected = vectors()
    if len(sys.argv) == 3 and sys.argv[1] == '--write':
        Path(sys.argv[2]).write_text(json.dumps(expected, indent=2)+'\n')
    else:
        assert json.load(sys.stdin) == expected, 'independent version-two vectors differ'
