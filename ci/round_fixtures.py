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
            if command[-1] == 'storage-root': return state.get('storage_status',0),state.get('storage_output',str(area/'storage'))
            if command[-1] == 'series-identity': return 0,json.dumps(dict(key=state['key'],identity=state.get('identity',dict(configuration='fixture'))))
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
            priming = dict(base='base',source='source',configuration_key='a'*64,identity=dict(configuration='fixture'),cache='warm',status=0,complete=True)
            def prime(value=priming): write(round.store/'priming.json',value)
            if group == 'guards':
                state.update(storage_status=5,storage_output='GATE-STORAGE-REFUSED members=target,storage')
                with refuses(test,'members=target,storage',message='round binding refusal preserves differing members'):
                    round.run()
                test.assertFalse(any(c[0][:2]==['git','reset'] for c in calls),'binding refusal precedes every reset')
                state.pop('storage_status');state.pop('storage_output')
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
                prime();state['key']='b'*64;state['identity']=dict(configuration='changed');calls.clear()
                test.assertEqual(round.run(),4,'key mismatch ends the label before an attempt')
                test.assertFalse(any(c[0][:2]==['git','reset'] for c in calls),'source key refusal precedes every reset')
                test.assertEqual(json.loads((round.store/'ended.json').read_text())['differences'],[dict(member='configuration',kind='source')],'source key refusal names differing members')
                test.assertTrue((round.store/'ended.json').is_file(),'changed key retains an end record')
                test.assertEqual(json.loads((round.store/'ended.json').read_text())['reason'],'configuration key differs from priming','changed key records the terminal cause')
                test.assertEqual(json.loads((round.store/'ended.json').read_text())['observed'],'b'*64,'end records observed key')
                test.assertFalse((round.store/'plans.jsonl').exists(),'preflight refusal writes no attempt plan')
                test.assertFalse(any(c[0]==['bash','ci/gate.sh'] for c in calls),'preflight refuses before measured gate')
                with refuses(test,'ended',message='changed key label cannot resume'): round.run()
                (round.store/'ended.json').unlink()
                state['identity']=dict(configuration='fixture',lineage='other');calls.clear()
                test.assertEqual(round.run(),5,'invoker key mismatch is restartable')
                test.assertFalse((round.store/'ended.json').exists(),'invoker mistake cannot end label')
                test.assertFalse(any(c[0][:2]==['git','reset'] for c in calls),'invoker key refusal precedes resets')
                test.assertEqual(json.loads((round.store/'preparations.jsonl').read_text().splitlines()[-1])['differences'],[dict(member='lineage',kind='invoker')],'restartable key refusal names member')
                legacy = dict(priming); legacy.pop('identity')
                prime(legacy)
                state['identity'] = dict(lineage='other')
                test.assertEqual(round.run(),4,'legacy priming cannot justify invoker restartability')
                test.assertTrue((round.store/'ended.json').exists(),'legacy priming mismatch ends label')
                (round.store/'ended.json').unlink(); prime()
                from series_round import configuration_differences
                for member in ('node','toolchain','runtime','cargo_home_config'):
                    test.assertEqual(configuration_differences({member:1},{member:2},root),[dict(member=member,kind='invoker')],'execution context is invoker-owned: '+member)
                for member in ('configuration','tiers','accounting','profiles','new-member'):
                    test.assertNotEqual(configuration_differences({member:1},{member:2},root)[0]['kind'],'invoker','source or unknown key member ends: '+member)
                test.assertEqual([r['kind'] for r in configuration_differences({},dict(cargo_config=[[str(root/'.cargo/config'),'x']]),root)],['source'],'checkout Cargo configuration is source-owned')
                test.assertEqual([r['kind'] for r in configuration_differences({},dict(cargo_config=[[str(area/'.cargo/config'),'x']]),root)],['invoker'],'ancestor Cargo configuration is invoker-owned')
                state['identity']=dict(configuration='fixture');state['key']='a'*64
                from isolation import storage_lock
                with storage_lock(area/'storage','gate'):
                    before=len(calls)
                    with refuses(test,'holder=gate',message='storage exclusion crosses evidence roots'):
                        other=SimpleNamespace(**vars(args));other.directory=area/'other-evidence'
                        Round(root,other).run()
                    test.assertFalse(any(c[0][:2]==['git','reset'] for c in calls[before:]),'storage refusal precedes reset')
                from series_round import round_lock
                with round_lock(args.directory,dict(label='other',base='other',source='other')):
                    before=list(calls)
                    with refuses(test,'holds.*lock',message='concurrent round refuses the held lock'): round.run()
                    test.assertEqual(calls,before,'lock refusal precedes every preparation command')
                    import subprocess
                    child=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('series_round.py')),
                        '--label','fixture','--base','base','--source','source','--mode','sample','--ordinal','1',
                        '--directory',str(args.directory),'--container-list','["fixture"]','--service-list','["fixture"]',
                        '--build-prefix','["fixture"]'],cwd=root,capture_output=True,text=True)
                    test.assertEqual(child.returncode,5,'busy round command has restartable status five')
                    test.assertIn('holds the evidence-root lock',child.stdout,'busy command names cooperative exclusion')
                def locked_execute():
                    with refuses(test,'holds.*lock',message='round holds lock throughout execution'):
                        with round_lock(args.directory,{}): pass
                    test.assertEqual(json.loads((args.directory/'.series-round.lock').read_text()),dict(label='fixture',base='base',source='source'),'lock names the label transition')
                    return 5
                with patch.object(round,'execute',side_effect=locked_execute):
                    test.assertEqual(round.run(),5,'lock wraps execution')
                with round_lock(args.directory,{}): pass
                with patch.object(round,'execute',side_effect=ValueError('controlled preflight')):
                    with test.assertRaisesRegex(ValueError,'controlled preflight'):round.run()
                with round_lock(args.directory,{}): pass
                state['key']='a'*64
                state['owners']=dict(kept='foreign');calls.clear()
                test.assertEqual(round.run(),5,'foreign retained owner is restartable')
                test.assertFalse(any(c[0][:3]==['git','reset','--hard'] for c in calls),'owner refusal precedes resets')
                state['owners']=dict(kept='base')
                write(round.store/'ended.json',dict(reason='ended'))
                with refuses(test,'ended',message='ended labels never restart'): Round(root,args).run()
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
                (round.store/'ledger.jsonl').write_text(''.join(json.dumps(dict(ordinal=1,entry=str(i)))+'\n' for i in range(3)))
                with refuses(test,'cap',message='cap closes label before another attempt'): round.run()
            elif group == 'sequence':
                args.mode='priming';args.ordinal=None
                test.assertEqual(round.run(),0,'green complete priming succeeds')
                expected=[['git','reset','--hard','base'],['python3','-B','ci/run_tests.py','prepare'],
                    ['python3','-B','ci/discipline.py','clippy'],['git','reset','--hard','source'],
                    ['git','clean','-fdx','-e','/.lane/build-graph/'],['bash','ci/gate.sh']]
                expected.insert(0,['python3','-B','ci/build_graph.py','series-identity'])
                selected=[c[0] for c in calls if c[0] in expected]
                test.assertEqual(selected,expected,'priming pays the exact base-build/source-reset sequence')
                test.assertFalse((round.store/'ledger.jsonl').exists(),'priming is not an attempt')
                test.assertTrue(json.loads((round.store/'priming.json').read_text())['complete'],'priming retains complete compilation')
                test.assertEqual(json.loads((round.store/'priming.json').read_text())['identity'],dict(configuration='fixture'),'priming retains identity members beside key')
                test.assertEqual(json.loads((round.store/'priming.json').read_text())['owners'],dict(kept='source'),'priming records actual retained owner heads')
                with refuses(test,'already',message='priming record cannot be overwritten'): round.run()
                args.mode='sample';args.ordinal=1;calls.clear()
                state['gate']=1
                test.assertEqual(round.run(),1,'red gate remains red after completed close and archive')
                operations=[c[0][3:] for c in calls if c[0][:3]==['python3','-B','ci/build_graph.py']]
                test.assertEqual([c[0] for c in operations],['series-identity','series-owner-heads','series-idle','series-idle','series-close','series-archive-list'],'red gate still ends closes and archives')
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
                with refuses(test,'ended',message='failed evidence cannot resume label'):Round(root,args).run()
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
                with refuses(test,'ended',message='active preparation ends label at next start'):Round(root,args).run()
                (round.store/'ended.json').unlink();(round.store/'active.json').unlink()
                with (round.store/'plans.jsonl').open('a') as stream:stream.write(json.dumps(dict(series='fixture',entry='unfinished',ordinal=1,start=time.time()))+'\n')
                with refuses(test,'ended',message='orphan plan ends label at next start'):Round(root,args).run()
                test.assertIn('unfinished',json.loads((round.store/'ended.json').read_text())['entries'],'end preserves interrupted entry')
                from build_graph import series_check
                try:series_check('fixture',round.store/'archive',round.store/'ledger.jsonl',round.store/'plans.jsonl')
                except ValueError as error:test.assertIn('planned attempt missing',str(error),'series checker refuses the interrupted command store')
                else:test.fail('series checker must refuse unfinished planned attempt')
                round.planned='exception-entry'
                with patch.object(round,'check_store'),patch.object(round,'execute',side_effect=ValueError('controlled failure')):
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
                import io
                from contextlib import redirect_stdout
                round.storage_token='live-fixture-token'
                printed=io.StringIO()
                with redirect_stdout(printed):
                    status,_=production_command(round,[sys.executable,'-c','pass','PN_GATE_STORAGE_TOKEN=second-live-token'],build=True)
                recorded=json.loads((round.store/'commands.jsonl').read_text().splitlines()[-1])['argv']
                test.assertNotIn('PN_GATE_STORAGE_TOKEN=live-fixture-token',recorded,'retained command masks the live storage token')
                test.assertNotIn('live-fixture-token',printed.getvalue(),'printed command masks the live storage token')
                test.assertNotIn('PN_GATE_STORAGE_TOKEN=second-live-token',recorded,'retained command masks a second token assignment')
                test.assertNotIn('second-live-token',printed.getvalue(),'printed command masks a second token assignment')
                with patch('build_graph.cancellable',return_value=SimpleNamespace(returncode=-15,stdout='')):
                    try:production_command(round,[sys.executable,'-c','pass'])
                    except InterruptedError as error:test.assertIn('signal 15',str(error),'series interruption names signal')
                    else:test.fail('series command raises interruption rather than returning an ordinary result')
                test.assertIn('PN_GATE_STORAGE_TOKEN=[redacted]',recorded,'record keeps an explicitly non-replayable token marker')
                import os, subprocess
                from isolation import storage_binding, storage_lock
                subprocess.run(['git','init','-q',str(root)],check=True)
                args.build_prefix=['env']
                with patch.dict(os.environ,CARGO_TARGET_DIR=str(area/'target'),PN_ISOLATION_ROOT=str(area/'isolation')):
                    bound=storage_binding(root)
                    with storage_lock(bound,'series') as token:
                        round.storage_token=token
                        code='import sys; sys.path.insert(0,'+repr(str(Path(__file__).resolve().parent))+'); from isolation import storage_entry,storage_token; from pathlib import Path; storage_entry(Path.cwd(),storage_token())'
                        with redirect_stdout(io.StringIO()):
                            status,_=production_command(round,[sys.executable,'-B','-c',code],build=True)
                        test.assertEqual(status,0,'original command can join its live storage holder')
                        recorded=json.loads((round.store/'commands.jsonl').read_text().splitlines()[-1])['argv']
                        replay=subprocess.run(recorded,cwd=root,capture_output=True,text=True)
                        test.assertNotEqual(replay.returncode,0,'recorded vector cannot replay the live storage token')
                        test.assertIn('storage lock token differs',replay.stderr,'replayed vector fails at token validation')


def storage_controls(test):
    """Exercise ownership and holder death with real processes and lock files."""
    import os
    import signal
    import subprocess
    from isolation import storage_binding, storage_lock
    with tempfile.TemporaryDirectory() as temporary:
        area=Path(temporary);root=area/'tree';root.mkdir()
        subprocess.run(['git','init','-q',str(root)],check=True)
        env=dict(CARGO_TARGET_DIR=str(area/'target'),PN_ISOLATION_ROOT=str(area/'owners'))
        with patch.dict(os.environ,env):
            directory=storage_binding(root)
            test.assertEqual(storage_binding(root),directory,'bound storage can be reused by its checkout')
            from isolation import publish_binding, storage_driver, storage_entry
            for point in ('write', 'flush', 'link', 'published'):
                record=area/('atomic-'+point)
                real_link=os.link
                def interrupted(*args, **kwargs):
                    if point == 'published':real_link(*args, **kwargs)
                    raise OSError('interrupted publication')
                target={'write':'isolation.json.dump','flush':'isolation.os.fsync','link':'isolation.os.link','published':'isolation.os.link'}[point]
                with patch(target,side_effect=interrupted):
                    try:publish_binding(record,dict(complete=True))
                    except OSError:pass
                test.assertEqual(record.read_text() if record.exists() else None,
                                 json.dumps(dict(complete=True))+'\n' if point=='published' else None,
                                 'binding interruption publishes complete bytes or nothing: '+point)
                publish_binding(record,dict(complete=True))
                test.assertEqual(json.loads(record.read_text()),dict(complete=True),'binding interruption permits consistent retry: '+point)
            with patch('isolation.Path.read_text',side_effect=PermissionError('unreadable')):
                try:storage_binding(root)
                except ValueError as error:test.assertIn('storage binding unreadable',str(error),'unreadable binding has a named refusal')
                else:test.fail('unreadable binding must refuse')
            driver=root/'driver.sh';driver.write_text('exit 0\n')
            try:storage_driver(root,['bash',str(driver)])
            except ValueError as error:test.assertIn(str(driver),str(error),'inside driver refusal names resolved path')
            else:test.fail('wrapper refuses driver inside checkout')
            outside=area/'driver.sh';outside.write_text('exit 0\n')
            storage_driver(root,['bash',str(outside)])
            with storage_lock(directory,'gate') as token:
                test.assertEqual(storage_entry(root,token)['kind'],'gate','join reads real gate holder kind')
                from isolation import gate_storage
                from contextlib import redirect_stdout
                import io
                output=io.StringIO()
                with patch('isolation.Path.cwd',return_value=root),patch.dict(os.environ,PN_GATE_STORAGE_TOKEN=token),redirect_stdout(output):
                    test.assertEqual(gate_storage([sys.executable,'-c','pass']),0,'joined gate control succeeds')
                test.assertIn('action=joined kind=gate',output.getvalue(),'join line prints real gate holder kind')
            record=area/'target/.gate-storage-owner.json';original=record.read_text()
            record.write_text(json.dumps(dict(json.loads(original),checkout=str(area/'foreign-checkout'))))
            try:
                try:storage_binding(root)
                except ValueError as error:test.assertIn('checkout',str(error),'isolated checkout difference is named')
                else:test.fail('binding refuses isolated checkout difference')
            finally:record.write_text(original)
            for field,value,member in [('CARGO_TARGET_DIR',str(area/'other-target'),'target'),('PN_ISOLATION_ROOT',str(area/'other-storage'),'storage')]:
                with patch.dict(os.environ,{field:value}):
                    try:storage_binding(root)
                    except ValueError as error:test.assertIn(member,str(error),'binding refusal names changed '+member)
                    else:test.fail('binding refuses changed '+member)
                    refused=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('isolation.py')),'storage-root'],cwd=root,capture_output=True,text=True)
                    test.assertEqual(refused.returncode,5,'storage lookup has its own uncounted refusal')
                    test.assertIn('GATE-STORAGE-REFUSED',refused.stdout,'storage lookup reports its refusal without traceback')
                    test.assertIn(member,refused.stdout,'storage lookup names the differing member')
            other=area/'other';other.mkdir();subprocess.run(['git','init','-q',str(other)],check=True)
            try:storage_binding(other)
            except ValueError as error:test.assertIn('checkout',str(error),'shared target refusal names checkout')
            else:test.fail('target cannot be shared by different checkouts')
            with patch.dict(os.environ,CARGO_TARGET_DIR=str(area/'fresh-target'),PN_ISOLATION_ROOT=str(area/'fresh-storage')):
                try:storage_binding(root)
                except ValueError as error:test.assertIn('target',str(error),'checkout binding names simultaneous target and storage change')
                else:test.fail('checkout binding refuses simultaneous target and storage change')
        child_code='import os,time,pathlib; pathlib.Path("child-ready").write_text(str(os.getpid())); time.sleep(60)'
        ci=str(Path(__file__).resolve().parent)
        armed=subprocess.run([sys.executable,'-B',str(Path(ci)/'build_graph.py'),'parent-bound','-1',sys.executable,'-c','pass'],capture_output=True,text=True)
        test.assertEqual(armed.returncode,-signal.SIGTERM,'parent change before arming prevents workload exec')
        gate=(Path(ci)/'gate.sh').read_text()
        handlers=gate[gate.index('active_pid='):gate.index('source ci/gate_resources.sh')]
        stopped=subprocess.run(['bash'],input=handlers+'\nkill -HUP $$\nexit 0\n',capture_output=True,text=True)
        test.assertEqual(stopped.returncode,129,'gate hang-up reaches its cleanup handler')
        def alive(pid):
            path=Path('/proc')/str(pid)/'stat'
            return path.exists() and path.read_text().split(') ',1)[1][0]!='Z'
        # The joined entry has no parent relationship to the holder: this
        # stands in for a prefix which leaves its workload running.
        token_path=area/'holder-token';ready=root/'child-ready'
        ready.unlink(missing_ok=True)
        holder_code='from isolation import storage_lock; from pathlib import Path; import time; c=storage_lock(Path('+repr(str(directory))+'),"series"); token=c.__enter__(); Path('+repr(str(token_path))+').write_text(token); time.sleep(60)'
        child_env=dict(os.environ,**env,PYTHONPATH=ci);child_env.pop('PN_GATE_STORAGE_TOKEN',None)
        holder=subprocess.Popen([sys.executable,'-B','-c',holder_code],cwd=root,env=child_env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        joined=None;pid=None
        try:
            deadline=time.monotonic()+10
            while not token_path.exists() and holder.poll() is None and time.monotonic()<deadline:time.sleep(.01)
            test.assertTrue(token_path.exists(),'watch control establishes holder')
            joined_code='from isolation import gate_storage; raise SystemExit(gate_storage('+repr([sys.executable,'-c',child_code])+'))'
            joined=subprocess.Popen([sys.executable,'-B','-c',joined_code],cwd=root,env=dict(child_env,PN_GATE_STORAGE_TOKEN=token_path.read_text()),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            deadline=time.monotonic()+10
            while not ready.exists() and joined.poll() is None and time.monotonic()<deadline:time.sleep(.01)
            test.assertTrue(ready.exists(),'independent joined workload starts')
            pid=int(ready.read_text());started=time.monotonic();holder.kill();holder.communicate()
            deadline=started+7
            while (alive(pid) or joined.poll() is None) and time.monotonic()<deadline:time.sleep(.01)
            test.assertFalse(alive(pid),'lock watch ends workload behind non-relaying prefix')
            test.assertIsNotNone(joined.poll(),'lock watch ends joined entry within polling and cleanup bound')
            output,_=joined.communicate()
            test.assertEqual(joined.returncode,5,'lost holder is uncounted status five')
            test.assertIn('reason=holder-lock-released',output,'lost holder names the lock release')
        finally:
            if holder.poll() is None:holder.kill();holder.communicate()
            if joined is not None and joined.poll() is None:joined.kill();joined.communicate()
            if pid and alive(pid):os.kill(pid,signal.SIGKILL)
        for mode,number in [('storage',signal.SIGKILL),('storage',signal.SIGHUP),('series',signal.SIGTERM)]:
            ready=root/'child-ready';ready.unlink(missing_ok=True)
            if mode=='storage':
                code='from isolation import gate_storage; raise SystemExit(gate_storage('+repr([sys.executable,'-c',child_code])+'))'
            else:
                code='from series_round import Round; from pathlib import Path; from types import SimpleNamespace; r=Round.__new__(Round); r.root=Path.cwd(); r.store=Path('+repr(str(area))+'); r.log=None; r.storage_token=None; r.args=SimpleNamespace(build_prefix=[]); r.command('+repr([sys.executable,'-c',child_code])+')'
            child_env=dict(os.environ,**env,PYTHONPATH=ci);child_env.pop('PN_GATE_STORAGE_TOKEN',None)
            holder=subprocess.Popen([sys.executable,'-B','-c',code],cwd=root,env=child_env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            pid=None
            try:
                deadline=time.monotonic()+10
                while not ready.exists() and holder.poll() is None and time.monotonic()<deadline:time.sleep(.01)
                test.assertTrue(ready.exists(),'holder control reaches its gate-shaped child: '+mode)
                pid=int(ready.read_text());holder.send_signal(number)
                deadline=time.monotonic()+5
                while alive(pid) and time.monotonic()<deadline:time.sleep(.01)
                test.assertFalse(alive(pid),'holder termination ends its running child: '+mode+' '+str(number))
                holder.communicate(timeout=10)
                if mode=='storage' and number==signal.SIGHUP:
                    test.assertEqual(holder.returncode,129,'hang-up is forwarded and reaped by the holder')
                with storage_lock(directory,'gate'):pass
            finally:
                if holder.poll() is None:holder.kill();holder.communicate()
                if pid and alive(pid):os.kill(pid,signal.SIGKILL)
