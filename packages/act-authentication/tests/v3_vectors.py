"""Independent fixture route: standard-library CBOR framing and SHA-256 only. (´[ROOT-amend:identity:formation-three-vectors]´)"""
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
        body = [identity, retirement, 'paired' if paired else 'binary', legs, quantities, None, deps, [], None, b'\xff\x00opaque' if count else b'']
        ny = identity[2].to_bytes(8, 'big')+bytes([11])*32
        nd = identity[2].to_bytes(8, 'big')+bytes([21])*32
        payload = b'content' if count else b''
        sy, sd = bytes([12])*48, bytes([13])*48
        preimages = {}
        def frame(role, tag, fields):
            recipe = 'pn-act-profile/act-'+role+'/v3'
            value = recipe.encode()+b'\0'+canonical([tag, fields])
            preimages[tag] = value.hex()
            return hashlib.sha256(value).digest()
        hy = frame('proposal', 'PN-content-pre-v3', [identity, ny, payload])
        hd = frame('proposal', 'PN-dependency-pre-v3', [identity, nd, deps])
        p = frame('proposal', 'PN-act-proposal-v3', [body, hy, hd])
        cy = frame('content', 'PN-content-v3', [identity, p, sy, hy])
        cd = frame('dependency', 'PN-dependency-v3', [identity, p, sd, deps])
        signature, seal = bytes([14])*64, bytes([15])*64
        header = canonical({0:'org.peer-network.test.verified-act',1:[3,0,0],2:body,3:['pn-act-profile/act-proposal/v3',p],4:signature,5:['pn-act-profile/act-content/v3',cy],6:['pn-act-profile/act-dependency/v3',cd],7:'3',8:'3'})
        host = 'pn-host-bip340-v1/'+(bytes([10])*32).hex()
        material = canonical(['pn-act-authentication/author-token-bip340/v3',run,bytes([9])*32,host,bytes([10])*32])
        messages = [p]
        for recipe, tag, fields in [('host-seal/v1','PN-verified-act-v1',[run,host,header]),('actor-approval/v1','PN-act-approval-v1',[run,host,header,seal])]:
            value = ('pn-act-authentication/'+recipe).encode()+b'\0'+canonical([tag,fields])
            preimages[tag] = value.hex()
            messages.append(hashlib.sha256(value).digest())
        rows.append(dict(case=case,body=canonical(body).hex(),header=header.hex(),material=material.hex(),ny=ny.hex(),nd=nd.hex(),payload=payload.hex(),dependencies=deps,sy=sy.hex(),sd=sd.hex(),hy=hy.hex(),hd=hd.hex(),p=p.hex(),cy=cy.hex(),cd=cd.hex(),run=run.hex(),host=host,seal=seal.hex(),messages=[m.hex() for m in messages],preimages=preimages))
    return dict(boundaries=boundaries(), refusals=refusals(), source='Independent Python standard-library framing and hashlib; no Rust, production projection or production helper calls. Public deterministic fixture inputs establish no entropy, signature validity or authority.', rows=rows)


def boundaries():
    # Full framing, including recipe, separator, both arrays and byte-string heads.
    identity = ['act', 'pn-devnet-v1/' + '01'*32 + '/' + '02'*32, 0, 'Registration']
    recipe = b'pn-act-profile/act-proposal/v3\0'
    nonce = bytes(8) + bytes([11])*32
    def pre(payload):
        return recipe + canonical(['PN-content-pre-v3', [identity, nonce, payload]])
    limit = 2097152
    n = limit - len(pre(b'')) - 4
    assert len(pre(bytes(n))) == limit
    body = [identity, bytes(range(32)), 'binary', [['binary', ['named','addr',identity[1]], ['named','prof',identity[1]]]], [], None, [], [], None, b'']
    def encoded(extension):
        return canonical(body[:-1] + [extension])
    m = 1048576 - len(encoded(b'')) - 4
    assert len(encoded(bytes(m))) == 1048576
    rows = []
    for kind, maximum, encode in [('payload', n, pre), ('extension', m, encoded)]:
        for delta in (-1, 0, 1):
            raw = encode(bytes(maximum+delta))
            rows.append(dict(name=kind+str(delta), fill_byte=0, count=maximum+delta,
                             encoded_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                             result='Bound' if delta > 0 else 'valid'))
    for n in (65536, 65537):
        raw=pre(bytes(n))
        rows.append(dict(name='carriage'+str(n), fill_byte=0, count=n,
                         encoded_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                         result='valid', carriage='valid' if n == 65536 else 'Bound'))
    return dict(identity=identity, nonce=nonce.hex(), body_without_extension=body[:-1][0:1]+[{'bytes':bytes(range(32)).hex()}]+body[2:-1], rows=rows)


def refusals():
    # Declarative substitutions on independently encoded row 0, not executions of a validator.
    return [dict(name=name, change=change, expected=expected) for name, change, expected in (
        ('body-old-one', 'select B1 for a B3 consumer', 'BodyShape'),
        ('body-old-two', 'select B2 for a B3 consumer', 'BodyShape'),
        ('body-extension-type', 'replace extension byte string with text', 'BodyShape'),
        ('proposal-old-anchor', 'select proposal/v2 for a v3 comparison', 'Recipe'),
        ('header-old-version', 'replace key 1 with [2,0,0]', 'Edition'),
        ('header-old-recipe', 'replace key 3 recipe with proposal/v2', 'Recipe'),
        ('header-content-recipe', 'replace key 5 recipe with content/v2', 'Recipe'),
        ('header-dependency-recipe', 'replace key 6 recipe with dependency/v2', 'Recipe'),
        ('header-content-edition', 'replace key 7 with text 2', 'ContentEdition'),
        ('header-dependency-edition', 'replace key 8 with text 2', 'DependencyEdition'),
        ('header-extension-binding', 'change extension byte with expected body fixed', 'Body'),
        ('header-proposal-binding', 'change expected P with supplied header fixed', 'Proposal'),
        ('header-content-binding', 'change expected C_Y with supplied header fixed', 'Content'),
        ('header-dependency-binding', 'change expected C_D with supplied header fixed', 'Dependency'),
        ('header-signature-binding', 'change expected Actor signature with supplied header fixed', 'ActorSignature'),
        ('material-old-edition', 'replace material edition with v2', 'Edition'),
        ('material-foreign-run', 'supply a different independently selected run', 'Run'),
        ('material-foreign-host', 'supply a different independently selected host', 'Host'),
        ('legacy-does-not-upgrade', 'supply v3 header/material to an explicitly v1 or v2 consumer', 'Edition'),
    )]


def refusal_vectors():
    """Independent, declarative substitutions on the admitted public operands."""
    cases = []
    def add(name, owner, change, expected, base_case=3, scope='public'):
        cases.append(dict(name=name, owner=owner, base_case=base_case,
                          change=change, expected=expected, scope=scope))
    for name, change, expected in (
        ('body-trailing', {'body_bytes': 'append 00'}, 'Canonical'),
        ('body-nonpreferred', {'body_bytes': 'replace first array head by longer form'}, 'Canonical'),
        ('body-short', {'body_bytes': 'truncate final byte'}, 'Canonical'),
        ('body-shape', {'body': 'remove extension member'}, 'BodyShape'),
        ('body-extension-type', {'body[9]': 'text rather than bytes'}, 'BodyShape'),
        ('body-author', {'body[0].author': 'foreign run'}, 'BodyShape'),
        ('body-retirement', {'body[1]': '31 bytes'}, 'BodyShape'),
        ('body-legs', {'body[3]': 'remove required leg'}, 'BodyShape'),
        ('body-quantity', {'body[4][0].denominator': 0}, 'BodyShape'),
        ('body-parent-order', {'body[6]': 'descending ids'}, 'BodyShape'),
        ('body-protocols', {'body[7]': ['unexpected']}, 'BodyShape'),
        ('body-settlement', {'body[8]': ['Accept']}, 'BodyShape'),
        ('body-authored-pair', {'expected.body.quantity': '2/4 instead of 1/2'}, 'Body'),
    ): add(name, 'B3', change, expected)
    add('body-bound-and-shape', 'B3', {'body[9]': 'extension+1', 'body[0].family': 'unknown'}, 'Bound', scope='overlap')
    for name, change, expected in (
        ('proposal-recipe-body', {'P.recipe': 'v2', 'body[9]': 'extension+1'}, 'Recipe'),
        ('proposal-ny', {'N_Y': '39 bytes'}, 'Blinding'),
        ('proposal-nd', {'N_D': '41 bytes'}, 'Blinding'),
        ('proposal-hy-width', {'hY': '31 bytes'}, 'ContentPreDigest'),
        ('proposal-hy-act', {'hY.act': 'different sequence'}, 'ContentPreDigest'),
        ('proposal-d-count', {'D': '1025 distinct identifiers'}, 'Dependencies'),
        ('proposal-d-order', {'D': 'descending identifiers'}, 'Dependencies'),
        ('proposal-p', {'expected.P': 'flip first byte'}, 'Proposal'),
    ): add(name, 'proposal/v3', change, expected)
    add('proposal-nd-before-y', 'proposal/v3', {'N_D': '39 bytes', 'Y': 'one above preimage limit'}, 'Blinding', scope='overlap')
    for name, change, expected in (
        ('content-recipe-absent', {'C_Y.recipe': 'v2', 'opening': None}, 'Recipe'),
        ('content-sy-absent', {'S_Y': '47 bytes', 'opening': None}, 'Blinding'),
        ('content-ny-sy', {'N_Y': '39 bytes', 'S_Y': '47 bytes'}, 'Blinding'),
        ('content-residue', {'expected.C_Y': 'flip first byte'}, 'Content'),
        ('dependency-recipe-absent', {'C_D.recipe': 'v2', 'opening': None}, 'Recipe'),
        ('dependency-sd', {'S_D': '49 bytes'}, 'Blinding'),
        ('dependency-duplicate', {'D': 'duplicate identifier'}, 'Dependencies'),
        ('dependency-residue', {'expected.C_D': 'flip first byte'}, 'Dependency'),
    ): add(name, 'opening', change, expected)
    for name, owner, change, expected in (
        ('header-namespace', 'header', {'key0': 'foreign namespace'}, 'Edition'),
        ('header-version', 'header', {'key1': [2, 0, 0]}, 'Edition'),
        ('header-recipe', 'header', {'key3.recipe': 'v2'}, 'Recipe'),
        ('header-signature', 'header', {'key4': '63 bytes'}, 'Shape'),
        ('header-body-proposal', 'header', {'key2': 'invalid B3', 'key3.recipe': 'v2'}, 'BodyShape'),
        ('header-proposal-content', 'header', {'expected.P': 'different', 'expected.C_Y': 'different'}, 'Proposal'),
        ('material-edition', 'material', {'edition': 'v2'}, 'Edition'),
        ('material-run-host', 'material', {'selected_run': 'foreign', 'expected_host': 'foreign'}, 'Run'),
        ('material-host-version', 'material', {'expected_host': 'foreign', 'header_version': [2, 0, 0]}, 'Host'),
        ('material-version', 'material', {'header_version': [2, 0, 0]}, 'Edition'),
        ('roles-material', 'roles', {'expected_host': 'foreign'}, 'Host'),
    ): add(name, owner, change, expected)
    encoded = json.dumps(cases, sort_keys=True, separators=(',', ':')).encode()
    return dict(source='Independent named substitutions on admitted public fixture operands; no package output or signature proof.',
                cases=cases, cases_sha256=hashlib.sha256(encoded).hexdigest())


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--write-refusals':
        Path(sys.argv[2]).write_text(json.dumps(refusal_vectors(), indent=2)+'\n')
    elif len(sys.argv) == 3 and sys.argv[1] == '--check-refusals':
        assert json.loads(Path(sys.argv[2]).read_text()) == refusal_vectors(), 'independent version-three refusals differ'
    elif len(sys.argv) == 3 and sys.argv[1] == '--write':
        Path(sys.argv[2]).write_text(json.dumps(vectors(), indent=2)+'\n')
    else:
        assert json.load(sys.stdin) == vectors(), 'independent version-three vectors differ'
