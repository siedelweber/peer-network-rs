"""Independent fixed-fixture storage projections and restricted canonical CBOR reader."""
import hashlib
import copy
import json
from pathlib import Path

PAYLOAD='pn-host/storage-payload/v1'
DISCLOSURE='pn-host/recognition-disclosure/v1'

def canonical(value):
    def head(major,n):
        if n<24:return bytes([major*32+n])
        for size,extra in ((1,24),(2,25),(4,26),(8,27)):
            if n < 1<<(8*size):return bytes([major*32+extra])+n.to_bytes(size,'big')
        raise ValueError('integer outside fixture profile')
    if value is None:return b'\xf6'
    if isinstance(value,bool):return b'\xf5' if value else b'\xf4'
    if isinstance(value,int):return head(0,value)
    if isinstance(value,bytes):return head(2,len(value))+value
    if isinstance(value,str):
        data=value.encode();return head(3,len(data))+data
    if isinstance(value,list):return head(4,len(value))+b''.join(map(canonical,value))
    raise ValueError('value outside fixture profile')

def commitment(recipe,value):
    return hashlib.sha256(recipe.encode()+b'\0'+canonical(value)).digest()

def vectors():
    # Fixed fixture: generator word 19, one r0 destruction and markers m0/m1.
    amount=['4','burn'];address='address-5'
    record=['r0','d0',address,amount,b'd0:address-5:4:burn']
    policy=['policy','1','sequence',0,1,'m0',True,'any party submits public evidence',
            'one candidate per index; no liveness guarantee','complete-list','unique-per-index','fixture-public-v1',7]
    publication=['opaque-fixture','edition-1','settled-boundary',2,[address],[[address,amount]],
                 [['0','burn'],True,'external acquisition starts at opening'],
                 ['1/4','fixture-unit','burn','fixture-terms'],
                 ['edition-1','settled-boundary',6,'fixture assumption, not chain evidence',
                  'public fixture proof profile',[],['absent','fixture rules grant no operational accrual']]]
    markers=[['m0','history','policy','1','sequence',0,0,None,[],['complete-list',[]],[]],
             ['m1','history','policy','1','sequence',1,10,0,['r0'],['complete-list',['r0']],None]]
    disclosure=['history',[record],markers,policy,publication]
    output=[['history','policy','1','fixture-public-v1','edition-1','settled-boundary'],
            [[markers[0],[],[]],[markers[1],['r0'],[record]]],None,'unsettled']
    constants=[['numeric','constants',1],'rational-3/37',['nu','2','burn'],'formula','controller-1',
               [['literal','margin','2','2']],[],['finite'],'exact-or-indecisive','fixture','internal',
               ['expression','structural-floor','3/37','case:epoch:safety-wall-floor-rational-floor']]
    bodies=[('constants',constants),('rule','public-rule-v1'),('marker-policy',[policy,publication]),
            ('lineage',disclosure),('burn-publication',publication),
            ('unsettled-recognition',[DISCLOSURE,commitment(DISCLOSURE,disclosure),disclosure,output])]
    rows=[]
    for family,body in bodies:
        value=[PAYLOAD,family,body]
        rows.append(dict(family=family,recipe=PAYLOAD,canonical_bytes=list(canonical(value)),digest=commitment(PAYLOAD,value).hex()))
    rows.append(dict(family='disclosure',recipe=DISCLOSURE,canonical_bytes=list(canonical(disclosure)),digest=commitment(DISCLOSURE,disclosure).hex()))
    def add(name,family,body):
        value=[PAYLOAD,family,body]
        rows.append(dict(family=name,recipe=PAYLOAD,canonical_bytes=list(canonical(value)),digest=commitment(PAYLOAD,value).hex()))
    ridge=copy.deepcopy(constants)
    ridge[0][2]=2;ridge[1]='ridge-image';ridge[4]='controller-2'
    ridge[-1]=['expression','structural-floor','p_ridge/(1-p_ridge); p_ridge is the defining ridge real','case:epoch:safety-wall-floor-ridge-floor']
    add('constants-ridge','constants',ridge)
    committed=copy.deepcopy(disclosure)
    committed[3][9]='public-commitment';committed[3][10]='first-valid'
    committed[4][-1][-1]=['bound',amount,'public operator bound proof']
    for marker in committed[2]:
        members=marker[9][1];proof=('set:'+'|'.join(members)).encode()
        marker[9]=['commitment',proof,[[members,proof]]]
    add('commitment-policy','marker-policy',[committed[3],committed[4]])
    add('commitment-lineage','lineage',committed)
    prefix=copy.deepcopy(disclosure);prefix[3][9]='whole-prefix';prefix[3][10]='first-valid'
    for marker in prefix[2]:marker[9]=['whole-prefix']
    add('whole-prefix-lineage','lineage',prefix)
    refused=copy.deepcopy(disclosure)
    competitor=copy.deepcopy(markers[1]);competitor[0]='competitor';competitor[6]=11
    refused[2].append(competitor)
    refused_output=[output[0],[output[1][0]],[markers[1],'succession',[markers[1],competitor]],'unsettled']
    add('refused-recognition','unsettled-recognition',[DISCLOSURE,commitment(DISCLOSURE,refused),refused,refused_output])
    causes=['policy-selection','policy-binding','deployment-binding','policy-digest','unsupported-policy-recipe','publication','evidence-binding','sample-coverage','units','bootstrap','policy','buffer','verifier','record-identity','history-policy','history-position','initial','succession','missing-lineage','regressed-lineage','encoding','missing-opening','ambiguous-opening','invalid-opening','regressed-acceptance','out-of-lineage','invalid-member','inconsistent-alias']
    # Component table pins every spelling using the existing payload domain; it is not an admitted family.
    add('cause-spellings','component-table',causes)
    return rows

def check(path):
    expected=vectors()
    if json.loads(Path(path).read_text())!=expected:
        raise ValueError('storage projection vector differs from independent fixed-fixture encoding')
    return {row['digest'] for row in expected}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    target=Path('packages/host/src/storage/vectors.json')
    if args.write:target.write_text(json.dumps(vectors(),indent=2)+'\n')
    check(target)
    print(f'STORAGE-VECTORS checked={len(vectors())}')
