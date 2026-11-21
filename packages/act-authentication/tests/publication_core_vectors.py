"""Independent projection fixtures, not publication documents. (´[ROOT-amend:identity:publication-core-digest]´)"""
import hashlib
import json
import sys
from pathlib import Path

RECIPE = 'pn-host/publication-core/v1'
PREFIX = RECIPE.encode('ascii') + b'\0'
MAXIMUM = (1 << 61) - 1
NAMESPACE = 'org.peer-network.test.publication'


def head(major, count):
    if count < 24:
        return bytes([major * 32 + count])
    for size, extra in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if count < 1 << (size * 8):
            return bytes([major * 32 + extra]) + count.to_bytes(size, 'big')
    raise ValueError('integer range')


def canonical(value):
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, str):
        raw = value.encode('utf-8')
        return head(3, len(raw)) + raw
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(canonical(v) for v in value)
    if isinstance(value, dict):
        pairs = sorted((canonical(k), canonical(v)) for k, v in value.items())
        return head(5, len(pairs)) + b''.join(k + v for k, v in pairs)
    raise ValueError('fixture type')


def projection_fixture(value, wire=None):
    # Exact comparison to this independent encoder checks this fixture's spelling;
    # this is not a parser or the future complete-publication validator.
    expected = canonical(value)
    if wire is not None and wire != expected:
        return dict(result='Canonical')
    if value[0] != NAMESPACE or value[1][:2] != [3, 0]:
        return dict(result='Edition')
    if value[1][2] != 0:
        return dict(result='Patch')
    core = canonical({k: v for k, v in value.items() if k != 9})
    framed = PREFIX + core
    if len(framed) > MAXIMUM:
        return dict(result='PreimageBound')
    return dict(result='projection fixture only', core=core.hex(), preimage=framed.hex(), digest=hashlib.sha256(framed).hexdigest())


def vectors():
    base = {0: NAMESPACE, 1: [3, 0, 0], **{k: bytes([k]) for k in range(2, 9)}}
    annotated = {**base, 9: {'fixture': {'opaque': b'annotation'}}}
    plain = projection_fixture(base)
    rows = []
    for name, obj in (('absent-annotation', base), ('present-annotation', annotated), ('changed-annotation', {**base, 9: {'fixture': {'opaque': b'changed'}}})):
        result = projection_fixture(obj)
        assert result == plain
        rows.append(dict(name=name, input=canonical(obj).hex(), **result))
    assert bytes.fromhex(plain['core'])[0] == 0xa9
    assert canonical(annotated)[0] == 0xaa
    mutations = []
    for key in range(9):
        obj = dict(base)
        obj[key] = NAMESPACE + 'x' if key == 0 else [3, 0, 1] if key == 1 else bytes([key ^ 1])
        core = canonical(obj)
        residue = hashlib.sha256(PREFIX + core).hexdigest()
        assert residue != plain['digest']
        mutations.append(dict(key=key, input=core.hex(), framing_digest=residue, operation_result=projection_fixture(obj)['result'], scope='framing sensitivity; coordinate mutations are refused, not identities'))
    refusals = []
    raw = canonical(base)
    for name, obj, wire, expected in (
        ('nonminimal-map-head', base, b'\xb8\x09' + raw[1:], 'Canonical'),
        ('trailing-byte', base, raw + b'\x00', 'Canonical'),
        ('wrong-namespace', {**base, 0: NAMESPACE+'x'}, None, 'Edition'),
        ('wrong-major', {**base, 1: [2, 0, 0]}, None, 'Edition'),
        ('wrong-minor', {**base, 1: [3, 1, 0]}, None, 'Edition'),
        ('wrong-patch', {**base, 1: [3, 0, 1]}, None, 'Patch'),
        ('edition-before-patch', {**base, 1: [2, 0, 1]}, None, 'Edition'),
    ):
        result = projection_fixture(obj, wire)
        assert result == dict(result=expected)
        refusals.append(dict(name=name, input=(canonical(obj) if wire is None else wire).hex(), **result))
    # These are witnesses of distinct framing, not alternative admitted identities.
    core = bytes.fromhex(plain['core'])
    domains = []
    for recipe, tag in (('pn-act-profile/act-proposal/v3', 'PN-act-proposal-v3'), ('pn-act-profile/act-content/v3', 'PN-content-v3'), ('pn-act-profile/act-dependency/v3', 'PN-dependency-v3'), ('pn-act-authentication/host-seal/v1', 'PN-verified-act-v1'), ('pn-act-authentication/actor-approval/v1', 'PN-act-approval-v1')):
        framed = recipe.encode() + b'\0' + canonical([tag, [core]])
        value = hashlib.sha256(framed).hexdigest()
        assert value != plain['digest'] and framed != PREFIX + core
        domains.append(dict(recipe=recipe, tag=tag, preimage=framed.hex(), framing_digest=value, scope='domain witness only; fields are not an act or message'))
    limit = MAXIMUM - len(PREFIX)
    allowances = [dict(core_bytes=n, prefix_bytes=len(PREFIX), preimage_bytes=n+len(PREFIX), maximum_preimage_bytes=MAXIMUM, result='within primitive guard' if n <= limit else 'PreimageBound', scope='arithmetic only; no allocation or digest of this length') for n in (limit-1, limit, limit+1)]
    assert len(PREFIX) == 28
    return dict(recipe=RECIPE, source='Independent Python standard-library encoding and hashlib; opaque section placeholders are not documents of the unassigned theory; no Rust or production helpers.', rows=rows, mutations=mutations, refusals=refusals, domains=domains, allowances=allowances)


if __name__ == '__main__':
    expected = vectors()
    if len(sys.argv) == 3 and sys.argv[1] == '--write':
        Path(sys.argv[2]).write_text(json.dumps(expected, indent=2)+'\n')
        state = 'written=true'
    else:
        assert json.load(sys.stdin) == expected, 'independent publication core projection fixtures differ'
        state = 'equal=true'
    print('PUBLICATION-CORE-VECTORS projections=3 mutations=9 refusals=7 domains=5 allowances=3 '+state)
