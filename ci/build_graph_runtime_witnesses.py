"""Runtime composition witnesses; the underlying service and evidence checkers are unchanged."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import tomllib

from build_graph import roster, selected


def invoke(root, argv, env=None):
    started = time.monotonic()
    result = subprocess.run(argv, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(f'RUNTIME-FIXTURE tool={Path(str(argv[0])).name} status={result.returncode} wall={time.monotonic()-started:.6f}s')
    return result


def graph_tree(case, root, commands, shell, checker, env, inputs):
    """Build an isolated actual Meson adapter, with shell-only cleanup in its roster."""
    (root/'ci/build-inputs').mkdir(parents=True, exist_ok=True)
    (root/'docs/inputs').mkdir(parents=True, exist_ok=True)
    (root/'.gitignore').write_text('.lane/\n')
    (root/'ci/gate.sh').write_text(''.join(('run_step ' if n in shell else 'run_graph ')+n+' '+c+'\n' for n,c in commands))
    (root/'docs/inputs/build-graph-slices.toml').write_text(''.join(f'[[rows]]\nname="{n}"\nslice={5 if n in shell else 4}\n' for n,_ in commands))
    (root/'meson.build').write_text("project('runtime-composition')\nsubdir('ci/build-inputs')\n")
    (root/'ci/build-inputs/meson.build').write_text("python=find_program('python3')\n"+''.join(
        "custom_target('gate-"+n+"', output:'gate-"+n+".json', command:[python, '"+str(checker)+"', 'execute', '--root', meson.project_source_root(), '--graph', meson.project_build_root() / 'gate-graph.json', '--report', '@OUTPUT@'], build_always_stale:true)\n"
        for n,_ in commands if n not in shell))
    for argv in (['git','init','-q'], ['git','add','-A'], ['git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','Runtime fixture']):
        result=invoke(root,argv,env);case.assertEqual(result.returncode,0,result.stdout)
    build=root/'.lane/build-graph';build.parent.mkdir(exist_ok=True)
    (root/'.lane/gate-steps.tsv').write_text('')
    result=invoke(root,[env['PN_MESON_BIN'],'setup',str(build),str(root)],env)
    case.assertEqual(result.returncode,0,result.stdout)
    (build/'gate-graph.json').write_text(json.dumps(dict(steps=[dict(name=n,command=c) for n,c in commands],
        inputs=[dict(path=p,consumers=[n for n,_ in commands]) for p in inputs])))
    return build


def runtime_delegation(case):
    """Compare real evidence evaluators behind isolated legacy and Meson routes."""
    repository=Path(__file__).resolve().parent.parent
    checker=repository/'ci/build_graph.py'
    expected={
        'host-postgresql-start':'python3 -B ci/host_postgresql.py start --root "$PN_HOST_TEST_ROOT"',
        'wallet-elements-start':'python3 -B ci/wallet_elements.py start --root "$PN_WALLET_TEST_ROOT"',
        'tests':'python3 -B ci/discipline.py tests',
        'test-budgets':'python3 -B ci/devperf.py --input .lane/performance-events.jsonl --findings .lane/performance-findings.jsonl',
        'observation-runtime':'python3 -B ci/run_ci.py test_observe_runtime',
        'host-observation-runtime':'python3 -B ci/run_ci.py test_host_runtime',
        'wallet-conformance':'python3 -B ci/run_ci.py test_wallet_boundary',
        'wallet-elements-stop':'python3 -B ci/wallet_elements.py stop --root "$PN_WALLET_TEST_ROOT"',
        'host-postgresql-stop':'python3 -B ci/host_postgresql.py stop --root "$PN_HOST_TEST_ROOT"',
        'harness-matrix':'python3 -B ci/harness.py --matrix',
        'claim-evidence':'python3 -B ci/claims.py --fail-respellings',
    }
    stops={'wallet-elements-stop','host-postgresql-stop'}
    case.assertEqual({n:c for n,c in roster(repository) if n in expected},expected)
    rows=tomllib.loads((repository/'docs/inputs/build-graph-slices.toml').read_text())['rows']
    case.assertEqual({r['name'] for r in rows if r['slice']==4},set(expected)-stops)
    case.assertTrue((set(expected)-stops)<=set(selected(repository)))
    case.assertFalse(stops & set(selected(repository)))
    entry=(repository/'ci/gate.sh').read_text()
    trap=next(line for line in entry.splitlines() if line.startswith('trap '))
    case.assertEqual(trap, 'trap \'python3 -B ci/wallet_elements.py stop-all --root "$PN_WALLET_TEST_ROOT"; python3 -B ci/host_postgresql.py stop --root "$PN_HOST_TEST_ROOT"\' EXIT')
    case.assertIn('run_step wallet-elements-stop '+expected['wallet-elements-stop'],entry)
    case.assertIn('run_step host-postgresql-stop '+expected['host-postgresql-stop'],entry)
    commands=[(n,'python3 -B fixture.py '+n) for n in ('start','tests','stop','matrix','claims','measurement')]
    driver=r'''import json,os,pathlib,signal,sys
sys.path.insert(0,os.environ['FIXTURE_CHECKERS'])
from harness import Registry,CONFIGURATION
from test_harness import rows,declarations
from test_claims import fixture
from claims import evaluate
from devperf import StructuralError,report
action=sys.argv[1];mode=pathlib.Path('mode').read_text();alive=pathlib.Path('.lane/alive');status=0;value={}
decl=rows();decl[-1]['cases']=['first','sibling'];registry=Registry(decl,declarations())
if action=='start':
 status=7 if mode=='startup-refusal' else 0
 if status==0:alive.write_text('owned')
 value={'class':'service-refusal' if status else 'service-ready'}
elif action=='tests':
 failure=mode=='failing-test' or not alive.exists()
 records=[registry.join(dict(operation=n,outcome='failed' if n=='sibling' and failure else 'passed',duration_ms=1),'current') for n in ('first','sibling')]
 if mode=='stale-case':records[0]['source']='old'
 if mode=='stale-configuration':records[0]['configuration']='other'
 pathlib.Path('.lane/results.json').write_text(json.dumps(records));status=int(failure)
 value={'class':'test-failure' if failure else 'tests-passed','cases':[(r['operation'],r['outcome']) for r in records]}
elif action=='stop':
 if mode=='interrupted-cleanup':
  print('FIXTURE '+json.dumps({'action':action,'status':143,'class':'interrupted-cleanup'}),flush=True)
  os.kill(os.getpid(),signal.SIGTERM)
 alive.unlink(missing_ok=True);value={'class':'service-stopped'}
elif action in ('matrix','claims'):
 records=json.loads(pathlib.Path('.lane/results.json').read_text())
 try:
  if action=='matrix':
   value={'rows':registry.matrix(records,'current')};status=int(any(r['status']=='failed' for r in value['rows']))
  else:
   data=fixture();data['configuration']=CONFIGURATION;data['results']=records
   held=data['declared'][0];held.update(status='held',hold='ROOT::sec:testing:fixture-area',owner='fixture',missing='integration',closing_condition='complete evidence',closing_step='later')
   value=evaluate(**data);status=int(any(r['status']=='failed' for r in value['claims']))
  value['class']='evidence-failure' if status else 'evidence-current'
 except StructuralError as error:status=2;value={'class':'structural','diagnostic':str(error)}
else:
 status=report([dict(operation='fixture',budget='unit',duration_ms=None if mode=='unavailable-measurement' else 1,outcome='exit:0',source='current',configuration=CONFIGURATION,owner='fixture')],declarations(),'.lane/performance.jsonl')
 value={'class':'measurement','findings':[json.loads(line) for line in pathlib.Path('.lane/performance.jsonl').read_text().splitlines()]}
print('FIXTURE '+json.dumps(dict(action=action,status=status,**value),sort_keys=True),flush=True)
sys.exit(status)
'''
    cleanup="import pathlib\npathlib.Path('.lane/alive').unlink(missing_ok=True)\nprint('EXIT-CLEANUP')\n"
    for scenario in ('clean','startup-refusal','interrupted-cleanup','failing-test','stale-case','stale-configuration','unavailable-measurement','graph-refusal'):
        outcomes=[]
        with tempfile.TemporaryDirectory() as directory:
            for route in ('legacy','graph'):
                root=Path(directory)/route;root.mkdir()
                (root/'fixture.py').write_text(driver);(root/'mode').write_text(scenario)
                env=dict(os.environ,PN_BUILDGRAPH_RUN='runtime-'+scenario,FIXTURE_CHECKERS=str(repository/'ci'),
                         PN_HOST_TEST_ROOT=str(root/'.lane/host'),PN_WALLET_TEST_ROOT=str(root/'.lane/wallet'))
                build=graph_tree(case,root,commands,{'stop'},checker,env,['fixture.py','mode'])
                (root/'ci/host_postgresql.py').write_text(cleanup);(root/'ci/wallet_elements.py').write_text(cleanup)
                history=root/'.lane/gate-steps.tsv';records=[]
                for name,command in commands:
                    if scenario=='graph-refusal' and name=='stop':
                        (build/'gate-graph.json').unlink()
                    # Configuration-refusal is a graph prerequisite, not an equivalent
                    # command verdict. The cleanup control still executes on both routes.
                    if scenario=='graph-refusal' and name in ('matrix','claims','measurement'):
                        if route=='graph':
                            refused=invoke(root,['python3','-B',str(checker),'delegate',name],env)
                            case.assertEqual(refused.returncode,2,refused.stdout)
                        continue
                    argv=['bash','-c',command] if route=='legacy' or name=='stop' else ['python3','-B',str(checker),'delegate',name]
                    result=invoke(root,argv,env);status=result.returncode if result.returncode>=0 else 128-result.returncode
                    values=[json.loads(line[8:]) for line in result.stdout.decode().splitlines() if line.startswith('FIXTURE ')]
                    case.assertEqual(len(values),1,result.stdout);value=values[0];case.assertEqual(value['status'],status)
                    records.append(value)
                    with history.open('a') as output:output.write(f'{name}\t{status}\t1\t2\n')
                case.assertEqual((root/'.lane/alive').exists(),scenario=='interrupted-cleanup')
                result=invoke(root,['bash','-c',trap+'\nexit 0\n'],env)
                case.assertEqual(result.returncode,0,result.stdout);case.assertEqual(result.stdout.count(b'EXIT-CLEANUP'),2)
                case.assertFalse((root/'.lane/alive').exists())
                outcomes.append(records)
                print('RUNTIME-DELEGATION scenario='+scenario+' route='+route+' statuses='+str([r['status'] for r in records])+' cleanup=complete')
            case.assertEqual(outcomes[0],outcomes[1])
            results={r['action']:r for r in outcomes[0]}
            if scenario in ('startup-refusal','failing-test'):
                case.assertEqual(results['claims']['claims'][0]['status'],'failed')
                case.assertEqual(results['claims']['obligations'][0]['status'],'failed')
            elif scenario.startswith('stale-'):
                case.assertEqual(results['matrix']['status'],2);case.assertEqual(results['claims']['status'],2)
            elif scenario!='graph-refusal':
                case.assertEqual(results['claims']['obligations'][0]['status'],'held')
            if scenario=='unavailable-measurement':
                case.assertEqual(results['measurement']['status'],0)
                case.assertEqual(results['measurement']['findings'][0]['kind'],'missing-measurement')
                case.assertEqual(results['measurement']['findings'][0]['verdict_effect'],'none')
    print('RUNTIME-DELEGATION commands=11 delegated=9 cleanup=shell fixtures=equal sibling-failure=retained holds=retained')


def service_instances(case):
    """Two actual daemons of each kind coexist; stopping one preserves the other."""
    import socket
    from concurrent.futures import ThreadPoolExecutor
    repository=Path(__file__).resolve().parent.parent
    checker=repository/'ci/build_graph.py'
    for service,script,variable in (('postgresql','host_postgresql.py','PN_HOST_TEST_ROOT'),('elements','wallet_elements.py','PN_WALLET_TEST_ROOT')):
        for route in ('legacy','graph'):
            with tempfile.TemporaryDirectory() as directory:
                instances=[]
                commands=[(action,'python3 -B ci/'+script+' '+action+' --root "$'+variable+'"') for action in ('start','stop')]
                for suffix in ('a','b'):
                    root=Path(directory)/suffix
                    result=invoke(repository,['git','clone','--quiet','--no-hardlinks',str(repository),str(root)])
                    case.assertEqual(result.returncode,0,result.stdout)
                    # Each invocation has a separate graph, directory and history,
                    # as two independent gates do; neither graph executes in parallel.
                    path=root/'.lane/instance'
                    env=dict(os.environ,PN_BUILDGRAPH_RUN='services-'+service+'-'+suffix,**{variable:str(path)})
                    graph_tree(case,root,commands,{'stop'},checker,env,['ci/'+script])
                    instances.append((root,path,env))
                paths=[entry[1] for entry in instances]
                def step(instance,name):
                    root,path,env=instance
                    command=dict(commands)[name]
                    argv=['python3','-B',str(checker),'delegate',name] if route=='graph' and name=='start' else ['bash','-c',command]
                    result=invoke(root,argv,env)
                    with (root/'.lane/gate-steps.tsv').open('a') as output:output.write(f'{name}\t{result.returncode}\t1\t2\n')
                    case.assertEqual(result.returncode,0,result.stdout)
                def alive(port):
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=2):return True
                    except OSError:return False
                try:
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        futures=[pool.submit(step,instance,'start') for instance in instances]
                        for future in futures:future.result()
                    configs=[json.loads((path/('tcp.json' if service=='postgresql' else 'producer.json')).read_text()) for path in paths]
                    ports=[int(config['port']) for config in configs]
                    case.assertNotEqual(ports[0],ports[1]);case.assertNotEqual(paths[0],paths[1])
                    pidfiles=[path/('data/postmaster.pid' if service=='postgresql' else 'elementsregtest/elementsd.pid') for path in paths]
                    pids=[int(path.read_text().splitlines()[0]) for path in pidfiles]
                    case.assertNotEqual(pids[0],pids[1]);case.assertTrue(all(alive(port) for port in ports))
                    first,second=(0,1) if route=='legacy' else (1,0)
                    step(instances[first],'stop');case.assertFalse(pidfiles[first].exists());case.assertTrue(pidfiles[second].exists());case.assertTrue(alive(ports[second]))
                    case.assertEqual(int(pidfiles[second].read_text().splitlines()[0]),pids[second])
                    # An absent listener on the stopped port is not an ownership claim:
                    # another gate may already have reused it. The owned pidfile is gone.
                    step(instances[second],'stop');case.assertFalse(pidfiles[second].exists())
                    print(f'SERVICE-OWNERSHIP kind={service} route={route} ports={ports} concurrent-starts=true distinct-directories=true distinct-pids=true first-stop-preserves-sibling=true both-stopped=true')
                finally:
                    cleanup=[]
                    for root,path,env in instances:
                        result=invoke(root,['python3','-B','ci/'+script,'stop','--root',str(path)],env)
                        cleanup.append((result.returncode,result.stdout))
                    for status,output in cleanup:case.assertEqual(status,0,output)
