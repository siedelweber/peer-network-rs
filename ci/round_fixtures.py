"""Controlled build environment for the prepared-round protocol tests."""

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import sys
from contextlib import contextmanager
from unittest.mock import patch

from series_round import Round, Refusal, copy_manifest, argv, write


@contextmanager
def refuses(test, pattern, message):
    try:
        yield
    except Refusal as error:
        test.assertRegex(str(error),pattern,message)
    except Exception as error:
        test.fail(message+': wrong outcome '+repr(error))
    else:
        test.fail(message+': no refusal')


def controls(test, group):
    production_command = Round.command
    with tempfile.TemporaryDirectory() as temporary:
        area = Path(temporary)
        root = area/'tree'; root.mkdir()
        (root/'.lane').mkdir()
        args = SimpleNamespace(label='fixture',base='base',source='source',mode='sample',ordinal=1,
            repeat_of=None,directory=area/'evidence',build_prefix=['fixture-build'],
            container_list=['fixture-containers'],service_list=['fixture-services'])
        calls = []
        state = dict(key='a'*64,gate=0,start=0,end=0,archive=0,complete=True,head='source',dirty='',ancestor=0,base_build=0)

        def command(instance, command, environment=None, build=False):
            calls.append((command,environment,build))
            if command[:3] == ['git','rev-parse','--verify']:
                return 0, command[-1].removesuffix('^{commit}')
            if command == ['git','rev-parse','HEAD']: return 0,state['head']
            if command == ['git','status','--porcelain']: return 0,state['dirty']
            if command[:2] == ['git','merge-base']: return state['ancestor'],''
            if command == ['python3','-B','ci/run_tests.py','prepare']: return state['base_build'],''
            if command[-1] == 'series-key': return 0,state['key']
            if command == ['bash','ci/gate.sh']:
                write(root/'.lane/gate-baseline.json',dict(cache=dict(state='warm',compiled=dict(primary=[],lint=[]) if state['complete'] else {})))
                return state['gate'],'gate output'
            if 'series-idle' in command and command[-1] == 'end': return state['end'],''
            if 'series-idle' in command and command[-1] == 'start': return state['start'],''
            if 'series-archive-list' in command:
                sidecar=root/'.lane/gate-baseline.json'
                return state['archive'],json.dumps(dict(files=[dict(source=str(sidecar),destination=sidecar.name,bytes=sidecar.stat().st_size)]))
            return 0,''

        with patch('series_round.Round.command',command),patch('build_graph.series_count',return_value=5),patch('build_graph.series_policy',return_value=dict(series_attempts_per_ordinal=3)):
            round = Round(root,args)
            priming = dict(base='base',source='source',configuration_key='a'*64,cache='warm',status=0,complete=True)
            def prime(value=priming): write(round.store/'priming.json',value)
            if group == 'guards':
                for field,value,message in [('status',1,'green'),('base','other','green'),('source','other','green'),('complete',False,'green')]:
                    prime(dict(priming,**{field:value}))
                    with refuses(test,message,message='sample refuses priming '+field): round.run()
                (round.store/'priming.json').unlink()
                with refuses(test,'green',message='missing priming refuses'): round.run()
                prime();state['key']='b'*64
                test.assertEqual(round.run(),5,'key mismatch is restartable before an attempt')
                test.assertFalse((round.store/'plans.jsonl').exists(),'preflight refusal writes no attempt plan')
                test.assertFalse(any(c[0]==['bash','ci/gate.sh'] for c in calls),'preflight refuses before measured gate')
                state['key']='a'*64
                write(round.store/'ended.json',dict(reason='ended'))
                with refuses(test,'ended',message='ended labels never restart'): Round(root,args)
                (round.store/'ended.json').unlink()
                for field,value,pattern in [('label','../escape','label'),('ordinal',6,'ordinal'),('directory',root,'outside'),('repeat_of',area/'owed','repeat')]:
                    modified=SimpleNamespace(**vars(args));setattr(modified,field,value)
                    with refuses(test,pattern,message='round argument refuses '+field): Round(root,modified)
                args.base='source'
                with refuses(test,'equals',message='equal transition refuses'): round.run()
                args.base='base'
                for key,value,pattern in [('head','other','clean source'),('dirty',' M file','clean source'),('ancestor',1,'command failed'),('key','invalid','malformed')]:
                    prior=state[key];state[key]=value
                    with refuses(test,pattern,message='round precondition '+key): round.run()
                    state[key]=prior
                state['base_build']=1;calls.clear()
                with refuses(test,'command failed',message='failed base build refuses'): round.run()
                test.assertEqual(calls[-1][0],['git','reset','--hard','source'],'failed base build restores source')
                state['base_build']=0
                (round.store/'ledger.jsonl').write_text(''.join(json.dumps(dict(ordinal=1))+'\n' for _ in range(3)))
                with refuses(test,'cap',message='cap closes label before another attempt'): round.run()
            elif group == 'sequence':
                args.mode='priming';args.ordinal=None
                test.assertEqual(round.run(),0,'green complete priming succeeds')
                expected=[['git','reset','--hard','base'],['python3','-B','ci/run_tests.py','prepare'],
                    ['python3','-B','ci/discipline.py','clippy'],['git','reset','--hard','source'],
                    ['git','clean','-fdx','-e','/.lane/build-graph/'],['python3','-B','ci/build_graph.py','series-key'],['bash','ci/gate.sh']]
                selected=[c[0] for c in calls if c[0] in expected]
                test.assertEqual(selected,expected,'priming pays the exact base-build/source-reset sequence')
                test.assertFalse((round.store/'ledger.jsonl').exists(),'priming is not an attempt')
                test.assertTrue(json.loads((round.store/'priming.json').read_text())['complete'],'priming retains complete compilation')
                with refuses(test,'already',message='priming record cannot be overwritten'): round.run()
                args.mode='sample';args.ordinal=1;calls.clear()
                state['gate']=1
                test.assertEqual(round.run(),1,'red gate remains red after completed close and archive')
                operations=[c[0][3:] for c in calls if c[0][:3]==['python3','-B','ci/build_graph.py']]
                test.assertEqual([c[0] for c in operations],['series-key','series-idle','series-idle','series-close','series-archive-list'],'red gate still ends closes and archives')
                ledger=json.loads((round.store/'ledger.jsonl').read_text())
                test.assertEqual(ledger['gate_status'],1,'ledger retains original red status')
                test.assertEqual(ledger['declared_identity'],{k:priming[k] for k in ('base','source','configuration_key','cache')},'ledger carries label identity')
                test.assertGreater(ledger['sidecar_bytes'],0,'sidecar size is declared')
                test.assertEqual(len(list((round.store/'archive').iterdir())),1,'manifest is outside archive entries')
                declaration=next(c[1] for c in calls if c[0]==['bash','ci/gate.sh'])
                test.assertEqual(declaration['PN_GATE_SAMPLE'],'import-transition','sample reaches gate unchanged')
                test.assertEqual(declaration['PN_GATE_PLAN'],'one-run','sample declares one run')
                test.assertEqual(declaration['PN_GATE_SERIES_COUNT'],'5','count comes from tree')
                test.assertEqual(json.loads((round.store/'plans.jsonl').read_text())['entry'],ledger['entry'],'plan and outcome join')
                test.assertGreater(json.loads((round.store/'plans.jsonl').read_text())['start'],0,'plan uses node clock')
            elif group == 'failures':
                args.mode='priming';args.ordinal=None;state['gate']=1
                test.assertEqual(round.run(),1,'red priming cannot authorize samples')
                test.assertTrue((round.store/'ended.json').exists(),'red priming ends label')
                (round.store/'ended.json').unlink();(round.store/'priming.json').unlink();state['gate']=0;state['complete']=False
                test.assertEqual(round.run(),4,'incomplete receipts cannot characterize')
                test.assertTrue((round.store/'ended.json').exists(),'incomplete priming ends label')
                (round.store/'ended.json').unlink();state['complete']=True;prime()
                args.mode='sample';args.ordinal=1;state['end']=4
                test.assertEqual(round.run(),4,'end receipt failure is a protocol refusal')
                ledger=json.loads((round.store/'ledger.jsonl').read_text())
                test.assertEqual(ledger['end_status'],4,'failed end status is retained separately')
                state['end']=0;state['archive']=4
                test.assertEqual(round.run(),4,'archive failure is a protocol refusal')
                test.assertEqual(json.loads((round.store/'ledger.jsonl').read_text().splitlines()[-1])['archive_status'],4,'failed archive has ledger row')
                before=(round.store/'ledger.jsonl').read_text();state['start']=4;calls.clear()
                test.assertEqual(round.run(),4,'failed start is a pre-gate abort')
                test.assertEqual((round.store/'ledger.jsonl').read_text(),before,'abort consumes no sample attempt')
                test.assertFalse(any(c[0]==['bash','ci/gate.sh'] for c in calls),'failed start never launches gate')
            elif group == 'repeat':
                args.mode='repeat';args.ordinal=None;args.repeat_of=area/'owed.json'
                request=dict(base='base',source='source',configuration_key='a'*64,sample='import-transition',owing_entry='owing')
                write(args.repeat_of,request);write(area/'gate-baseline.json',dict(cache=dict(state='warm')))
                test.assertEqual(round.run(),0,'repeat completes through its close')
                environment=next(c[1] for c in calls if c[0]==['bash','ci/gate.sh'])
                test.assertEqual(environment['PN_GATE_REPEAT_OF'],str(args.repeat_of),'repeat carries exact obligation')
                test.assertEqual(environment['PN_GATE_SERIES_CACHE'],'warm','transition repeat carries owed cache class')
                test.assertTrue(any('repeat-close' in c[0] for c in calls),'repeat is discharged only through repeat-close')
                test.assertFalse((round.store/'ledger.jsonl').exists(),'repeat is not a series attempt')
                write(args.repeat_of,dict(request,source='foreign'))
                with refuses(test,'transition',message='foreign repeat transition refuses'): round.run()
                write(args.repeat_of,dict(request,configuration_key='b'*64))
                with refuses(test,'configuration',message='foreign repeat key refuses'): round.run()
            elif group == 'copy':
                source=area/'source';source.write_text('evidence')
                row=dict(source=str(source),destination='nested/receipt',bytes=source.stat().st_size)
                copy_manifest(dict(files=[row]),area/'copied')
                test.assertEqual((area/'copied/nested/receipt').read_text(),'evidence','copy creates parents and preserves bytes')
                for index,changed in enumerate([dict(row,destination='../escape'),dict(row,bytes=1)]):
                    with refuses(test,'destination|size',message='unsafe or changed copy refuses'): copy_manifest(dict(files=[changed]),area/str(index))
                link=area/'link';link.symlink_to(source)
                with refuses(test,'link',message='copy follows no source link'): copy_manifest(dict(files=[dict(row,source=str(link))]),area/'linked')
                with refuses(test,'duplicate',message='duplicate destination refuses'): copy_manifest(dict(files=[row,row]),area/'duplicate')
                copy_manifest(dict(files=[dict(row,destination='round.log',bytes=0)]),area/'growing')
                test.assertEqual((area/'growing/round.log').read_text(),'evidence','round log may grow after manifest')
                for value in ('null','[]','[""]','[1]'):
                    with refuses(test,'argument vector',message='argv must be executable words'): argv(value)
                args.build_prefix=['env']
                probe=area/'probe.py';probe.write_text('import os,json\nprint(json.dumps(dict(declaration=os.environ.get("PN_GATE_ENTRY"),inherited=os.environ.get("ROUND_FIXTURE"))))\n')
                with patch.dict('os.environ',ROUND_FIXTURE='kept'):
                    status,output=production_command(round,[sys.executable,str(probe)],environment=dict(PN_GATE_ENTRY='declared'),build=True)
                test.assertEqual(status,0,'build prefix executes the supplied command')
                test.assertEqual(json.loads(output),dict(declaration='declared',inherited='kept'),'gate environment is overlaid, never cleared')
