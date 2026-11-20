"""Independent fixture route: standard-library CBOR framing and SHA-256 only. (´[ROOT-amend:identity:closure-component-vectors]´)"""
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
        body = [identity, retirement, 'paired' if paired else 'binary', legs, quantities, None, [], [], None, b'\xff\x00opaque' if count else b'']
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
        epoch, position, logical_time = 4, case+10, case+20
        approval = bytes([16])*64
        closure = canonical([2, header, material, seal, approval, epoch, position, logical_time])
        proof = canonical([2, identity, epoch, position, p, cd, sd, deps])
        assert len(closure) <= 2097152 and len(proof) <= 262453
        anchor = dict(identity=identity, epoch=epoch, position=position, p=p.hex(), cd=cd.hex(), authentication='explicit fixture premise, not established')
        rows.append(dict(closure=closure.hex(),proof=proof.hex(),anchor=anchor,approval=approval.hex(),epoch=epoch,position=position,logical_time=logical_time,case=case,body=canonical(body).hex(),header=header.hex(),material=material.hex(),ny=ny.hex(),nd=nd.hex(),payload=payload.hex(),dependencies=deps,sy=sy.hex(),sd=sd.hex(),hy=hy.hex(),hd=hd.hex(),p=p.hex(),cy=cy.hex(),cd=cd.hex(),run=run.hex(),host=host,seal=seal.hex(),messages=[m.hex() for m in messages],preimages=preimages))
    return dict(refusals=refusals(), absence=[dict(proof='absent', anchor='authenticated', result='UnavailableOpening'),dict(proof='present', anchor='unavailable', result='UnavailableAnchor')], source='Independent Python standard-library framing and hashlib; no Rust, production projection or production helper calls. Public deterministic fixture inputs establish no entropy, signature validity or authority.', rows=rows, boundaries=boundaries())


def boundaries():
    author = 'pn-devnet-v1/' + '01'*32 + '/' + '02'*32
    maximum = 2**64-1
    identity = ['act', author, maximum, 'Registration']
    assert len(author.encode()) == 142 and len(canonical(identity)) == 171
    proposal, blinding = bytes(32), bytes(48)
    rows = []
    for name, deps, placement, result, construction in (
        ('maximum-admissible', [['act', author, n, 'Registration'] for n in range(maximum-1024, maximum)], maximum, 'opening-match under fixture anchor', dict(first_sequence=maximum-1024, count=1024)),
        ('D-byte-limit', [['act', 'x'*262119, 0, 'Registration']], 0, 'Identity', dict(author_fill='x', author_bytes=262119, count=1)),
        ('D-byte-above', [['act', 'x'*262120, 0, 'Registration']], 0, 'DependenciesBound', dict(author_fill='x', author_bytes=262120, count=1)),
    ):
        d = canonical(deps)
        preimage = b'pn-act-profile/act-dependency/v3\0' + canonical(['PN-dependency-v3', [identity, proposal, blinding, deps]])
        commitment = hashlib.sha256(preimage).digest()
        proof = canonical([2, identity, placement, placement, proposal, commitment, blinding, deps])
        assert len(proof) <= 262453
        expected_size = {'maximum-admissible':175107, 'D-byte-limit':262144, 'D-byte-above':262145}[name]
        assert len(d) == expected_size
        rows.append(dict(name=name, construction=construction, placement=placement, dependency_bytes=len(d), proof_bytes=len(proof), dependency_sha256=hashlib.sha256(d).hexdigest(), proof_sha256=hashlib.sha256(proof).hexdigest(), commitment=commitment.hex(), result=result))
    return dict(identity=identity, proposal=proposal.hex(), blinding=blinding.hex(), fragment_limit=262453, dependency_limit=262144, fixed_maximum_bytes=309, authority='explicit fixture premise, not established', rows=rows)


def refusals():
    # Expected future checks on fresh values, not results from an implemented validator.
    return [dict(name=n, change=c, expected=e) for n,c,e in (
        ('closure-edition','replace fragment edition 2 with 1','Edition'),
        ('closure-proof-as-act','supply a proof array to the closure decoder','Shape'),
        ('proof-act-as-proof','supply a closure array to the proof decoder','Shape'),
        ('historical-act-as-new','supply the historical ten-field CandidateAct array to the new closure decoder','Shape'),
        ('new-act-as-historical','supply the new eight-field closure array to the historical CandidateAct decoder','Shape'),
        ('closure-extra-removal','append a removal member','Shape'),
        ('closure-extra-D','append a dependency list member','Shape'),
        ('closure-old-header','replace V with canonical major-two V','Header:Edition'),
        ('closure-old-material','replace material with canonical v2 material','Material:Edition'),
        ('closure-seal','replace seal bytes with expected context fixed','Seal'),
        ('closure-approval','replace approval bytes with expected context fixed','Approval'),
        ('closure-epoch','change epoch with expected context fixed','Epoch'),
        ('closure-position','change position with expected context fixed','Position'),
        ('closure-time','change time with expected context fixed','Time'),
        ('proof-edition','replace proof edition 2 with 1','Edition'),
        ('proof-extra','append a ninth field','Shape'),
        ('proof-digest','shorten P by one byte','Digest'),
        ('proof-blinding','shorten S_D by one byte','Blinding'),
        ('proof-count','supply 1025 distinct ordered identifiers','DependenciesBound'),
        ('proof-order','reverse a two-member list','Dependencies'),
        ('proof-duplicate','repeat one identifier','Dependencies'),
        ('proof-id','replace I with another valid I, anchor fixed','AnchorIdentity'),
        ('proof-epoch','change epoch, anchor fixed','AnchorEpoch'),
        ('proof-position','change position, anchor fixed','AnchorPosition'),
        ('proof-proposal','change P, anchor fixed','AnchorProposal'),
        ('proof-commitment','change C_D, anchor fixed','AnchorCommitment'),
        ('proof-opening','change S_D while all anchor fields remain','OpeningMismatch'),
        ('proof-subset','drop one member from nonempty D, anchor fixed','OpeningMismatch'),
        ('proof-empty-substitution','replace nonempty D with [], anchor fixed','OpeningMismatch'),
    )]

if __name__ == '__main__':
    expected = vectors()
    if len(sys.argv) == 3 and sys.argv[1] == '--write':
        Path(sys.argv[2]).write_text(json.dumps(expected, indent=2)+'\n')
    else:
        assert json.load(sys.stdin) == expected, 'independent closure component vectors differ'
