"""Controlled build environment for the prepared-round protocol tests."""

import json
import copy
import time
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
        from test_devperf import series_records
        def idle(environment,boundary):
            row=copy.deepcopy(series_records()[0]['host_idle_start'])
            row.update(identity={key:environment[key] for key in ('PN_GATE_SERIES','PN_GATE_ORDINAL','PN_GATE_ENTRY')},boundary=boundary)
            row['at']=time.time()
            row['processes']['stdout']=state.get(boundary+'_processes','')
            write(root/('.lane/gate-series-host-'+boundary+'.json'),row)
            return row

        def command(instance, command, environment=None, build=False):
            calls.append((command,environment,build))
            if command[:3] == ['git','rev-parse','--verify']:
                return 0, command[-1].removesuffix('^{commit}')
            if command == ['git','rev-parse','HEAD']: return 0,state['head']
            if command == ['git','status','--porcelain']: return 0,state['dirty']
            if command[:2] == ['git','merge-base']: return state['ancestor'],''
            if command == ['python3','-B','ci/run_tests.py','prepare']: return state['base_build'],''
            if command[-1] == 'series-key': return 0,state['key']
            if command[-1] == 'series-owner-heads': return 0,json.dumps(state.get('owners',dict(kept='source')))
            if command == ['bash','ci/gate.sh']:
                write(root/'.lane/gate-baseline.json',dict(cache=dict(state='warm',compiled=dict(primary=[],lint=[]) if state['complete'] else {})))
                return state['gate'],'gate output'
            if 'series-idle' in command:
                idle(environment,command[-1]);return state[command[-1]],''
            if 'series-close' in command:
                row=copy.deepcopy(series_records()[0])
                row['declaration'].update(series='fixture',base='base',source='source',configuration_key='a'*64,
                    entry=environment['PN_GATE_ENTRY'],ordinal=environment['PN_GATE_ORDINAL'])
                row['whole'].update(status=state['gate'],stall=state.get('pressure',.05))
                for owner in row['owners']:owner.update(base='base',source='source')
                for boundary in ('start','end'):row['host_idle_'+boundary]=json.loads((root/('.lane/gate-series-host-'+boundary+'.json')).read_text())
                write(root/'.lane/gate-series-end.json',row)
                write(root/'.lane/gate-declaration.json',row['declaration'])
                from build_graph import series_close
                (root/'.lane/series-attempt.json').unlink(missing_ok=True)
                series_close(root,state['gate'])
                return state.get('close',0),''
            if 'repeat-close' in command:return state.get('discharge',0),''
            if 'series-archive-list' in command:
                sidecar=root/'.lane/gate-baseline.json'
                paths=[sidecar,root/'.lane/series-attempt.json']
                return state['archive'],json.dumps(dict(files=[dict(source=str(p),destination=p.name,bytes=p.stat().st_size) for p in paths]))
            return 0,''

        with patch('series_round.Round.command',command),patch('build_graph.series_count',return_value=5),patch('build_graph.series_policy',return_value=dict(series_attempts_per_ordinal=3 if group=='guards' else 100,series_absolute_pressure=.1)):
            round = Round(root,args)
            priming = dict(base='base',source='source',configuration_key='a'*64,cache='warm',status=0,complete=True)
            def prime(value=priming): write(round.store/'priming.json',value)
            if group == 'guards':
                from build_graph import retained_owner_heads
                owners=area/'owners';owners.mkdir()
                for name in ('kept','swept'):
                    directory=owners/name;directory.mkdir();(directory/'owner').write_text(name)
                (owners/'kept/s').mkdir()
                with patch('isolation.storage_root',return_value=owners),patch('build_graph.subprocess.check_output',return_value='observed-head\n') as read:
                    test.assertEqual(retained_owner_heads(root),dict(kept='observed-head'),'owner observation keeps actual heads and skips swept checkouts')
                    test.assertEqual(read.call_args.args[0],['git','-C',str(owners/'kept/s'),'rev-parse','HEAD'],'owner observation reads without fetching')
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
                state['owners']=dict(kept='foreign');calls.clear()
                test.assertEqual(round.run(),5,'foreign retained owner is restartable')
                test.assertFalse(any(c[0][:3]==['git','reset','--hard'] for c in calls),'owner refusal precedes resets')
                state['owners']=dict(kept='base')
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
                test.assertEqual(json.loads((round.store/'priming.json').read_text())['owners'],dict(kept='source'),'priming records actual retained owner heads')
                with refuses(test,'already',message='priming record cannot be overwritten'): round.run()
                args.mode='sample';args.ordinal=1;calls.clear()
                state['gate']=1
                test.assertEqual(round.run(),1,'red gate remains red after completed close and archive')
                operations=[c[0][3:] for c in calls if c[0][:3]==['python3','-B','ci/build_graph.py']]
                test.assertEqual([c[0] for c in operations],['series-owner-heads','series-key','series-idle','series-idle','series-close','series-archive-list'],'red gate still ends closes and archives')
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
                test.assertLessEqual(json.loads((round.store/'plans.jsonl').read_text())['start'],json.loads((root/'.lane/series-attempt.json').read_text())['started'],'accepted plan predates the idle observation it joins')
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
                test.assertTrue((round.store/'ended.json').exists(),'end failure ends label')
                with refuses(test,'ended',message='failed evidence cannot resume label'):Round(root,args)
                (round.store/'ended.json').unlink()
                state['end']=0;state['archive']=4
                test.assertEqual(round.run(),4,'archive failure is a protocol refusal')
                test.assertEqual(json.loads((round.store/'ledger.jsonl').read_text().splitlines()[-1])['archive_status'],4,'failed archive has ledger row')
                test.assertTrue((round.store/'ended.json').exists(),'archive failure ends label')
                (round.store/'ended.json').unlink()
                before=(round.store/'ledger.jsonl').read_text();state['start']=4;calls.clear()
                test.assertEqual(round.run(),5,'failed start is a restartable preflight')
                test.assertEqual((round.store/'ledger.jsonl').read_text(),before,'abort consumes no sample attempt')
                test.assertFalse(any(c[0]==['bash','ci/gate.sh'] for c in calls),'failed start never launches gate')
                state['start']=0;state['archive']=0;state['start_processes']='321 1 cargo test busy';calls.clear()
                plans=(round.store/'plans.jsonl').read_text()
                test.assertEqual(round.run(),5,'busy start refuses before measurement')
                test.assertEqual((round.store/'plans.jsonl').read_text(),plans,'busy start consumes no plan or attempt')
                test.assertFalse(any(c[0]==['bash','ci/gate.sh'] for c in calls),'busy start never launches gate')
                state['start_processes']='';state['end_processes']='321 1 cargo test busy'
                test.assertEqual(round.run(),4,'busy end reports excluded measurement')
                test.assertIn('end other account battery',json.loads((round.store/'ledger.jsonl').read_text().splitlines()[-1])['exclusion'],'ledger names end exclusion')
                state['end_processes']='';state['pressure']=.2
                test.assertEqual(round.run(),4,'absolute pressure exclusion is reported')
                state['pressure']=.05;state['close']=4
                test.assertEqual(round.run(),4,'close failure is a protocol refusal')
                test.assertTrue((round.store/'ended.json').exists(),'close failure ends label')
                (round.store/'ended.json').unlink()
                write(round.store/'active.json',dict(entry='interrupted-priming'))
                with refuses(test,'ended',message='active preparation ends label at next start'):Round(root,args)
                (round.store/'ended.json').unlink();(round.store/'active.json').unlink()
                with (round.store/'plans.jsonl').open('a') as stream:stream.write(json.dumps(dict(series='fixture',entry='unfinished',ordinal=1,start=time.time()))+'\n')
                with refuses(test,'ended',message='orphan plan ends label at next start'):Round(root,args)
                test.assertIn('unfinished',json.loads((round.store/'ended.json').read_text())['entries'],'end preserves interrupted entry')
                from build_graph import series_check
                try:series_check('fixture',round.store/'archive',round.store/'ledger.jsonl',round.store/'plans.jsonl')
                except ValueError as error:test.assertIn('planned attempt missing',str(error),'series checker refuses the interrupted command store')
                else:test.fail('series checker must refuse unfinished planned attempt')
                round.planned='exception-entry'
                with patch.object(round,'execute',side_effect=ValueError('controlled failure')):
                    with test.assertRaisesRegex(ValueError,'controlled failure'):round.run()
                test.assertEqual(json.loads((round.store/'ended.json').read_text()).get('entry'),'exception-entry','caught post-plan failure ends label with its entry')
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
                state['discharge']=4
                test.assertEqual(round.run(),4,'failed discharge remains a refusal')
                test.assertEqual(json.loads((round.store/'repeat-ledger.jsonl').read_text().splitlines()[-1])['discharge_status'],4,'repeat ledger preserves discharge status')
                prior=args.repeat_of;args.repeat_of=root/'owed.json';write(args.repeat_of,request)
                with refuses(test,'outside checkout',message='in-tree obligation refuses before reset'):round.run()
                args.repeat_of=prior;write(prior,dict(request,sample='import'));(area/'gate-baseline.json').unlink()
                with refuses(test,'exist before reset',message='missing repeat sidecar refuses before reset'):round.run()
                write(prior,request)
                write(area/'gate-baseline.json',dict(cache=dict(state='warm')))
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
                from build_graph import DECLARATION_VARIABLES
                foreign={key:'caller-foreign' for key in DECLARATION_VARIABLES}
                args.build_prefix=['env',*[key+'=prefix-foreign' for key in DECLARATION_VARIABLES]]
                probe=area/'probe.py';probe.write_text('import os,json\nkeys='+repr(DECLARATION_VARIABLES)+'\nprint(json.dumps(dict(declaration=os.environ.get("PN_GATE_ENTRY"),inherited=os.environ.get("ROUND_FIXTURE"),members={key:os.environ[key] for key in keys if key in os.environ})))\n')
                with patch.dict('os.environ',dict(foreign,ROUND_FIXTURE='kept')):
                    status,output=production_command(round,[sys.executable,str(probe)],environment=dict(PN_GATE_ENTRY='declared'),build=True)
                test.assertEqual(status,0,'build prefix executes the supplied command')
                test.assertEqual(json.loads(output),dict(declaration='declared',inherited='kept',members=dict(PN_GATE_ENTRY='declared')),'command owns every declaration member after prefix and preserves unrelated environment')
                with patch.dict('os.environ',dict(foreign,ROUND_FIXTURE='kept')):
                    status,output=production_command(round,[sys.executable,str(probe)],environment=dict(PN_GATE_ENTRY='declared'))
                test.assertEqual(status,0,'host receipt command runs')
                test.assertEqual(json.loads(output)['members'],dict(PN_GATE_ENTRY='declared'),'host commands also remove every foreign declaration member')
