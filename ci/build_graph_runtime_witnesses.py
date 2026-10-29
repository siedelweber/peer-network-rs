"""Runtime composition witnesses; the underlying service and evidence checkers are unchanged."""

import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import time
import tomllib

from build_graph import roster, selected, plan
from build_graph_witnesses import declaration


def invoke(root, argv, env=None):
    started = time.monotonic()
    result = subprocess.run(argv, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(f'RUNTIME-FIXTURE tool={Path(str(argv[0])).name} status={result.returncode} wall={time.monotonic()-started:.6f}s')
    return result


def graph_tree(case, root, commands, shell, checker, env, inputs, setup=True):
    """Build an isolated actual Meson adapter, with shell-only cleanup in its roster."""
    (root/'ci/build-inputs').mkdir(parents=True, exist_ok=True)
    (root/'docs/inputs').mkdir(parents=True, exist_ok=True)
    (root/'.gitignore').write_text('.lane/\n')
    (root/'ci/gate.sh').write_text(''.join(('run_step ' if n in shell else 'run_graph ')+n+' '+c+'\n' for n,c in commands))
    (root/'docs/inputs/build-graph-slices.toml').write_text(''.join(f'[[rows]]\nname="{n}"\nslice={5 if n in shell else 4}\n' for n,_ in commands))
    (root/'meson.build').write_text("project('runtime-composition')\n"+declaration(commands)+"subdir('ci/build-inputs')\n")
    (root/'ci/build-inputs/meson.build').write_text("python=find_program('python3')\n"+''.join(
        "custom_target('gate-"+n+"', output:'gate-"+n+".json', command:[python, '"+str(checker)+"', 'execute', '--root', meson.project_source_root(), '--graph', meson.project_build_root() / 'gate-graph.json', '--report', '@OUTPUT@'], build_always_stale:true)\n"
        for n,_ in commands if n not in shell))
    for argv in (['git','init','-q'], ['git','add','-A'], ['git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','Runtime fixture']):
        result=invoke(root,argv,env);case.assertEqual(result.returncode,0,result.stdout)
    build=root/'.lane/build-graph';build.parent.mkdir(exist_ok=True)
    (root/'.lane/gate-steps.tsv').write_text('')
    if setup:
        result=invoke(root,[env['PN_MESON_BIN'],'setup',str(build),str(root)],env)
        case.assertEqual(result.returncode,0,result.stdout)
    else:
        build.mkdir()
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
    case.assertIn('run_step wallet-elements-stop '+expected['wallet-elements-stop'],plan(repository))
    case.assertIn('run_step host-postgresql-stop '+expected['host-postgresql-stop'],plan(repository))
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
    started=time.monotonic()
    scenarios=('clean','startup-refusal','interrupted-cleanup','failing-test','stale-case','stale-configuration','unavailable-measurement','graph-refusal')
    outcomes={}
    with tempfile.TemporaryDirectory() as directory:
        for route in ('legacy','graph'):
            root=Path(directory)/route;root.mkdir()
            (root/'fixture.py').write_text(driver);(root/'mode').write_text('clean')
            env=dict(os.environ,FIXTURE_CHECKERS=str(repository/'ci'),
                     PN_HOST_TEST_ROOT=str(root/'.lane/host'),PN_WALLET_TEST_ROOT=str(root/'.lane/wallet'))
            build=graph_tree(case,root,commands,{'stop'},checker,env,['fixture.py','mode'],setup=route=='graph')
            graph_text=(build/'gate-graph.json').read_text()
            (root/'ci/host_postgresql.py').write_text(cleanup);(root/'ci/wallet_elements.py').write_text(cleanup)
            for scenario in scenarios:
                env['PN_BUILDGRAPH_RUN']='runtime-'+scenario
                (root/'mode').write_text(scenario)
                (build/'gate-graph.json').write_text(graph_text)
                for path in (root/'.lane').iterdir():
                    if path != build:
                        if path.is_dir():shutil.rmtree(path)
                        else:path.unlink()
                history=root/'.lane/gate-steps.tsv';history.write_text('');records=[]
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
                outcomes[route,scenario]=records
                print('RUNTIME-DELEGATION scenario='+scenario+' route='+route+' statuses='+str([r['status'] for r in records])+' cleanup=complete')
        for scenario in scenarios:
            case.assertEqual(outcomes['legacy',scenario],outcomes['graph',scenario])
            results={r['action']:r for r in outcomes['legacy',scenario]}
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
    interrupted_gate(case, repository)
    print(f'RUNTIME-WITNESS-WALL seconds={time.monotonic()-started:.6f} scenario_setups=1 signal_setups=1 scenarios=8 routes=2')
    print('RUNTIME-DELEGATION commands=11 delegated=9 cleanup=shell fixtures=equal sibling-failure=retained holds=retained')


def service_instances(case):
    """Two actual daemons of each kind coexist; stopping one preserves the other."""
    import socket
    from concurrent.futures import ThreadPoolExecutor
    started = time.monotonic()
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    daemon_cpu_control(case)
    daemon_samples = []
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
                    graph_tree(case,root,commands,{'stop'},checker,env,['ci/'+script],setup=route=='graph')
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
                    first_cpu = daemon_cpu(pidfiles[first])
                    case.assertEqual(first_cpu['pid'], pids[first])
                    daemon_samples.append(first_cpu)
                    print('SERVICE-DAEMON-CPU '+json.dumps(dict(kind=service, route=route, **first_cpu), sort_keys=True))
                    step(instances[first],'stop');case.assertFalse(pidfiles[first].exists());case.assertTrue(pidfiles[second].exists());case.assertTrue(alive(ports[second]))
                    case.assertEqual(int(pidfiles[second].read_text().splitlines()[0]),pids[second])
                    # An absent listener on the stopped port is not an ownership claim:
                    # another gate may already have reused it. The owned pidfile is gone.
                    second_cpu = daemon_cpu(pidfiles[second])
                    case.assertEqual(second_cpu['pid'], pids[second])
                    daemon_samples.append(second_cpu)
                    print('SERVICE-DAEMON-CPU '+json.dumps(dict(kind=service, route=route, **second_cpu), sort_keys=True))
                    step(instances[second],'stop');case.assertFalse(pidfiles[second].exists())
                    print(f'SERVICE-OWNERSHIP kind={service} route={route} ports={ports} concurrent-starts=true distinct-directories=true distinct-pids=true first-stop-preserves-sibling=true both-stopped=true')
                finally:
                    cleanup=[]
                    for root,path,env in instances:
                        result=invoke(root,['python3','-B','ci/'+script,'stop','--root',str(path)],env)
                        cleanup.append((result.returncode,result.stdout))
                    for status,output in cleanup:case.assertEqual(status,0,output)


    used = resource.getrusage(resource.RUSAGE_SELF)
    waited = resource.getrusage(resource.RUSAGE_CHILDREN)
    source = invoke(repository, ['git', 'rev-parse', 'HEAD']).stdout.decode().strip()
    print('SERVICE-WITNESS-RESOURCES '+json.dumps(dict(source=source,
          command='PYTHONPATH=ci python3 -B -m unittest test_linter_entry.Conformance.test_service_ownership',
          own_user_s=used.ru_utime-own.ru_utime+waited.ru_utime-children.ru_utime,
          own_system_s=used.ru_stime-own.ru_stime+waited.ru_stime-children.ru_stime,
          daemon_user_s=sum(row['user_s'] for row in daemon_samples),
          daemon_system_s=sum(row['system_s'] for row in daemon_samples),
          wall_s=time.monotonic()-started, load=os.getloadavg(),
          scope='witness-self-and-waited-descendants; daemon-tick-snapshots-separate-before-stop'), sort_keys=True))


def interrupted_gate(case, repository):
    """Signal the actual entry trap while Ninja owns a blocked command."""
    import socket
    checker=repository/'ci/build_graph.py'
    entry=(repository/'ci/gate.sh').read_text()
    traps=entry[entry.index("trap 'python3"):entry.index('gate_started=')]
    runners=entry[entry.index('run_step() {'):entry.index('# Meson owns the serial roster;')]
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory)
        listener=socket.socket(socket.AF_UNIX)
        listener.bind(str(root/'ready.sock'));listener.listen();listener.settimeout(30)
        (root/'wait.py').write_text("import os,socket\ns=socket.socket(socket.AF_UNIX)\ns.connect(os.environ['READY_SOCKET'])\ns.sendall(b'R')\ns.recv(1)\n")
        env=dict(os.environ,PN_BUILDGRAPH_RUN='interrupted-gate',READY_SOCKET=str(root/'ready.sock'),
                 PN_HOST_TEST_ROOT=str(root/'.lane/host'),PN_WALLET_TEST_ROOT=str(root/'.lane/wallet'))
        graph_tree(case,root,[('blocked','python3 -B wait.py')],set(),checker,env,['wait.py'])
        shutil.copyfile(checker,root/'ci/build_graph.py')
        cleanup="import pathlib,sys\np=pathlib.Path(sys.argv[sys.argv.index('--root')+1]);(p/'alive').unlink();(p/'cleaned').write_text('owned')\n"
        for script in ('host_postgresql.py','wallet_elements.py'):(root/'ci'/script).write_text(cleanup)
        for name in ('host','wallet','sibling'):
            path=root/'.lane'/name;path.mkdir();(path/'alive').write_text('owned')
        (root/'ci/devperf.py').write_text('raise SystemExit(0)\n')
        (root/'entry.sh').write_text('set -u\nfailed=0\nstatuses=()\nresource_root=\nsource_id=fixture\ngate_resource_sample() { :; }\n'+traps+runners+'run_graph blocked python3 -B wait.py\n')
        with (root/'entry.log').open('wb') as output:
            child=subprocess.Popen(['bash','entry.sh'],cwd=root,env=env,stdout=output,stderr=subprocess.STDOUT)
            connection=None
            descendants={child.pid}
            try:
                connection,_=listener.accept();case.assertEqual(connection.recv(1),b'R')
                # The socket handshake establishes that the actual command is
                # running inside Ninja, rather than relying on a sleep.
                descendants={child.pid}
                process_rows={}
                for path in Path('/proc').glob('[0-9]*/stat'):
                    try:
                        fields=path.read_text().rsplit(')',1)[1].split()
                        process_rows[int(path.parent.name)]=(int(fields[1]),fields[0])
                    except (OSError,ValueError,IndexError):pass
                while True:
                    expanded=descendants|{pid for pid,(parent,_) in process_rows.items() if parent in descendants}
                    if expanded==descendants:break
                    descendants=expanded
                case.assertTrue(any('ninja' in Path(f'/proc/{pid}/comm').read_text() for pid in descendants))
                child.send_signal(signal.SIGTERM)
                status=child.wait(timeout=30)
                case.assertEqual(status,143,(root/'entry.log').read_text())
                connection.settimeout(5);case.assertEqual(connection.recv(1),b'')
                for name in ('host','wallet'):
                    case.assertTrue((root/'.lane'/name/'cleaned').exists())
                    case.assertFalse((root/'.lane'/name/'alive').exists())
                case.assertTrue((root/'.lane/sibling/alive').exists())
                survivors=[]
                for pid in descendants:
                    path=Path(f'/proc/{pid}/stat')
                    if path.exists():survivors.append((pid,path.read_text()))
                case.assertEqual(survivors,[])
                print('RUNTIME-INTERRUPTION signal=SIGTERM inside=ninja status=143 roots=cleaned sibling=preserved descendants=0')
            finally:
                if child.poll() is None:
                    print((root/'entry.log').read_text(),flush=True)
                    for pid in sorted(descendants,reverse=True):
                        try:os.kill(pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                    child.wait(timeout=5)
                if connection is not None:connection.close()
                listener.close()


def completion(case):
    """Exercise final joins on fresh/reused targets, not cached verdicts."""
    from unittest.mock import patch
    from build_graph import finish, read_result, report_path
    repository=Path(__file__).resolve().parent.parent
    checker=repository/'ci/build_graph.py'
    live=roster(repository)
    emitted=plan(repository).splitlines()
    case.assertEqual([(line.split(' ',2)[1],line.split(' ',2)[2]) for line in emitted],live)
    case.assertEqual([line.split()[1] for line in emitted if line.startswith('run_step ')],
                     ['build-graph','wallet-elements-stop','host-postgresql-stop'])
    case.assertNotRegex((repository/'ci/gate.sh').read_text(),r'(?m)^run_(step|graph) [a-z]')
    commands=[('compile','python3 -B fixture.py compile'),('write','python3 -B fixture.py write'),
              ('final','python3 -B fixture.py final')]
    fixture="""import json,pathlib,sys
action=sys.argv[1]
with pathlib.Path('.lane/executed').open('a') as out:out.write(action+'\\n')
if action=='compile':pathlib.Path('.lane/cases.json').write_text(json.dumps({'features':['default','test-support'],'cases':['unit','doctest'],'passed':2,'failed':0,'held':1}))
if action=='write':pathlib.Path('document').write_text('rendered\\n')
print('FIXTURE '+action)
"""
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);(root/'fixture.py').write_text(fixture)
        env=dict(os.environ,PN_BUILDGRAPH_ROUTE='meson')
        build=graph_tree(case,root,commands,set(),checker,env,['fixture.py'])
        stamp=(build/'meson-info/meson-info.json').stat().st_mtime_ns
        observations=[];nonces=[]
        for run_id in ('fresh','reused'):
            env['PN_BUILDGRAPH_RUN']=run_id
            history=root/'.lane/gate-steps.tsv';history.write_text('')
            (root/'.lane/executed').unlink(missing_ok=True)
            statuses=[];outputs=[]
            for name,command in commands:
                result=invoke(root,['python3','-B',str(checker),'delegate',name],env)
                case.assertEqual(result.returncode,0,result.stdout)
                (root/f'.lane/gate-{name}.log').write_bytes(result.stdout)
                statuses.append(result.returncode);outputs.append(result.stdout)
                with history.open('a') as out:out.write(f'{name}\t{result.returncode}\t1\t2\n')
            with patch.dict(os.environ,env):case.assertEqual(finish(root),0)
            case.assertEqual((root/'.lane/executed').read_text().splitlines(),[n for n,_ in commands])
            case.assertEqual((build/'meson-info/meson-info.json').stat().st_mtime_ns,stamp)
            observations.append((statuses,outputs,(root/'document').read_bytes(),(root/'.lane/cases.json').read_bytes()))
            data=json.loads(report_path(build,'final').read_text());nonces.append(data['request']['nonce'])
            case.assertEqual(data['request']['context']['run'],run_id)
            print('BUILD-COMPLETION route='+run_id+' steps=3 exactly_once=true cases=equal documents=equal')
        case.assertEqual(observations[0],observations[1]);case.assertNotEqual(*nonces)
        final=report_path(build,'final');saved=final.read_text();saved_history=history.read_text()
        with patch.dict(os.environ,env):
            final.unlink()
            with case.assertRaises(OSError):finish(root)
            final.write_text(saved)
            history.write_text(saved_history+saved_history.splitlines(keepends=True)[-1])
            with case.assertRaisesRegex(ValueError,'final roster'):finish(root)
            history.write_text(saved_history)
            with patch.dict(os.environ,PN_BUILDGRAPH_RUN='later'):
                with case.assertRaisesRegex(ValueError,'stale final report'):finish(root)
            with patch.dict(os.environ,PN_OBSERVE_LEVEL='changed'):
                with case.assertRaisesRegex(ValueError,'stale final report'):finish(root)
        slices=root/'docs/inputs/build-graph-slices.toml';saved_slices=slices.read_text()
        slices.write_text(saved_slices[saved_slices.index('[[rows]]',1):])
        case.assertEqual(len(plan(root).splitlines()),len(commands))
        slices.write_text(saved_slices)
        # A configured declaration without its Ninja target must refuse, even
        # with the earlier successful report left on disk.
        ninja=build/'build.ninja';ninja.write_text(ninja.read_text().replace('ci/build-inputs/gate-compile.json:', 'ci/build-inputs/absent-compile.json:'))
        history.write_text('')
        result=invoke(root,['python3','-B',str(checker),'delegate','compile'],env)
        case.assertEqual(result.returncode,2,result.stdout)
        case.assertFalse(report_path(build,'compile').exists())
        print('BUILD-COMPLETION missing-target=refused missing-report=refused duplicate=refused stale-run=refused stale-configuration=refused')


def capture_evidence(case):
    """Retain a real tracked fixture and refuse each damaged artifact boundary."""
    import copy
    import hashlib
    from build_graph import identity, report_path
    from build_graph_evidence import capture
    repository = Path(__file__).resolve().parent.parent
    checker = repository/'ci/build_graph.py'
    commands = [('first', 'true'), ('last', 'true')]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root/'README.md').write_text('rendered fixture\n')
        (root/'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
        build = graph_tree(case, root, commands, set(), checker, dict(os.environ), ['README.md'], setup=False)
        source = invoke(root, ['git', 'rev-parse', 'HEAD']).stdout.decode().strip()
        graph = json.loads((build/'gate-graph.json').read_text())
        lane = root/'.lane'
        lines = [f'{name}\t0\t1\t2' for name, _ in commands]
        (lane/'gate-steps.tsv').write_text('\n'.join(lines)+'\n')
        (build/'meson-info').mkdir()
        (build/'meson-info/meson-info.json').write_text('{"meson_version":{"full":"fixture"}}')
        (lane/'gate-build-graph.log').write_text('BUILD-MESON source=fixture action=setup\n')
        gate_log = lane/'complete.log'
        gate_log.write_text(''.join(f'STEP={name} STATUS=0 WALL=1s\n' for name, _ in commands)+'BUILD-FINAL steps=2 exactly_once=true delegated=2 fresh=true\nGATE-EXIT=0\n')
        for index, (name, command) in enumerate(commands):
            output = lane/(name+'.log');output.write_bytes(b'public command result\n')
            context = dict(source=source, run='fixture-run', configuration={'features': 'fixture'}, graph=identity(graph),
                           history=identity(lines[:index]), step=name, command=command)
            request = dict(context=context, nonce=name, log=str(output))
            result = dict(schema=1, request=request, status=0, output=hashlib.sha256(output.read_bytes()).hexdigest(), started=1, ended=2, wall=1)
            path = report_path(build, name);path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result))
        (lane/'harness-matrix.json').write_text(json.dumps(dict(rows=[dict(source=source, status='passed')])) )
        (lane/'claim-evidence.json').write_text(json.dumps(dict(source=source, claims=[], obligations=[])))
        (lane/'performance-events.jsonl').write_text('')
        (lane/'harness-benchmarks.jsonl').write_text('')
        event = dict(scope='case', operation='fixture', source=source, outcome='passed')
        events = lane/'harness-ci-fixture.jsonl';events.write_text(json.dumps(event)+'\n')
        snapshot = capture(root, gate_log)
        case.assertEqual((len(snapshot['roster']), len(snapshot['reports']), len(snapshot['cases'])), (2, 2, 1))
        case.assertIn('README.md', snapshot['documents'])
        case.assertIn('Cargo.toml', snapshot['features'])
        baseline = {path: path.read_bytes() for path in lane.rglob('*') if path.is_file()}
        report = report_path(build, 'last')
        original_report = json.loads(report.read_text())
        faults = []
        def fault(name, path, content, diagnostic):
            faults.append((name, path, content.encode(), diagnostic))
        fault('dirty-tree', root/'README.md', 'stale render\n', 'clean tracked tree')
        fault('roster-order', lane/'gate-steps.tsv', '\n'.join(reversed(lines))+'\n', 'roster')
        fault('roster-repeat', lane/'gate-steps.tsv', '\n'.join(lines+[lines[-1]])+'\n', 'roster')
        changed_graph = copy.deepcopy(graph);changed_graph['steps'][1]['command']='false'
        fault('configured-command', build/'gate-graph.json', json.dumps(changed_graph), 'configured commands')
        fault('second-exit', gate_log, gate_log.read_text()+'GATE-EXIT=0\n', 'status roster')
        fault('log-status', gate_log, gate_log.read_text().replace('STEP=last STATUS=0', 'STEP=last STATUS=1'), 'status roster')
        fault('missing-final', gate_log, gate_log.read_text().replace('BUILD-FINAL steps=2 exactly_once=true delegated=2 fresh=true\n', ''), 'final join')
        for field in ('source', 'run', 'configuration', 'graph', 'history', 'step', 'command'):
            changed = copy.deepcopy(original_report);changed['request']['context'][field]='stale'
            fault('report-'+field, report, json.dumps(changed), 'stale join')
        changed = copy.deepcopy(original_report);changed['status']=1
        fault('report-status', report, json.dumps(changed), 'stale join')
        fault('report-integrity', lane/'last.log', 'tampered output\n', 'output differs')
        fault('case-repeat', events, events.read_text()*2, 'duplicated or stale')
        fault('case-source', events, json.dumps(event | dict(source='stale'))+'\n', 'duplicated or stale')
        fault('claim-source', lane/'claim-evidence.json', json.dumps(dict(source='stale')), 'source differs')
        fault('matrix-source', lane/'harness-matrix.json', json.dumps(dict(rows=[dict(source='stale')])), 'source differs')
        fault('two-actions', lane/'gate-build-graph.log', 'BUILD-MESON action=setup\nBUILD-MESON action=reuse\n', 'one fresh setup')
        fault('invalid-action', lane/'gate-build-graph.log', 'BUILD-MESON action=unknown\n', 'one fresh setup')
        for name, path, content, diagnostic in faults:
            original = path.read_bytes()
            path.write_bytes(content)
            try:
                with case.subTest(fault=name), case.assertRaisesRegex(ValueError, diagnostic):
                    capture(root, gate_log)
            finally:
                path.write_bytes(original)
        case.assertEqual(baseline, {path: path.read_bytes() for path in lane.rglob('*') if path.is_file()})
        case.assertEqual(capture(root, gate_log), snapshot)
        print(f'BUILD-RETENTION controls={len(faults)} refused={len(faults)} clean=passed reconstructed-artifacts=true')


def daemon_cpu(pidfile, proc=Path('/proc'), ticks=None):
    """Sample daemon roots, live descendants and waited-child ticks before stop."""
    pid = int(pidfile.read_text().splitlines()[0])
    ticks = os.sysconf('SC_CLK_TCK') if ticks is None else ticks
    rows = {}
    for path in proc.glob('[0-9]*/stat'):
        try:
            fields = path.read_text().rsplit(')', 1)[1].split()
            rows[int(path.parent.name)] = dict(parent=int(fields[1]), user=int(fields[11]), system=int(fields[12]),
                                               waited_user=int(fields[13]), waited_system=int(fields[14]), start=int(fields[19]))
        except (OSError, ValueError, IndexError):
            if path.parent.name == str(pid):
                raise
    if pid not in rows:
        raise ValueError('owned daemon vanished before CPU sample')
    descendants = {pid}
    while True:
        expanded = descendants | {child for child, row in rows.items() if row['parent'] in descendants}
        if expanded == descendants:
            break
        descendants = expanded
    return dict(pid=pid, start_ticks=rows[pid]['start'], processes=len(descendants), ticks_per_second=ticks,
                user_s=sum(rows[child]['user']+rows[child]['waited_user'] for child in descendants)/ticks,
                system_s=sum(rows[child]['system']+rows[child]['waited_system'] for child in descendants)/ticks,
                scope='daemon-tree-proc-snapshot-before-stop', shutdown='excluded', accuracy='non-atomic-tick-snapshot')


def daemon_cpu_control(case):
    """Known ticks include only the owned tree and its already waited children."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory);pidfile=root/'pid';pidfile.write_text('10\n')
        for pid, parent, user, system, waited_user, waited_system in ((10,1,100,50,5,2),(11,10,20,10,0,0),(12,1,900,900,0,0)):
            fields = ['0']*20
            fields[0]='S';fields[1]=str(parent)
            for index,value in ((11,user),(12,system),(13,waited_user),(14,waited_system),(19,1000+pid)):
                fields[index]=str(value)
            path=root/str(pid);path.mkdir()
            (path/'stat').write_text(str(pid)+' (fixture process) '+' '.join(fields))
        value=daemon_cpu(pidfile,root,100)
        case.assertEqual((value['processes'],value['user_s'],value['system_s'],value['start_ticks']), (2,1.25,0.62,1010))
        (root/'10/stat').unlink()
        with case.assertRaisesRegex(ValueError, 'vanished'):
            daemon_cpu(pidfile,root,100)
