"""Constructed trees used by the registered tracked-corpus integration claim."""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

from build_graph import gate, incidence, run


def exercise(case):
    """Exercise the real Meson target and deployed census, then isolated graph faults."""
    source = Path(__file__).resolve().parent.parent
    checker = source/'ci/build_graph.py'
    meson = os.environ['PN_MESON_BIN']
    for value in (None, ''):
        with patch.dict(os.environ):
            if value is None:
                os.environ.pop('PN_MESON_BIN', None)
            else:
                os.environ['PN_MESON_BIN'] = value
            with case.assertRaisesRegex(ValueError, 'PN_MESON_BIN'):
                gate()
    print('GRAPH-WITNESS missing-or-empty-meson=refused')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        build = root/'.lane/build'

        def write(path, text):
            destination = root/path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text)

        def command(argv):
            result = run(argv, cwd=root, capture_output=True, text=True)
            print(result.stdout)
            print(result.stderr)
            return result

        write('.linter/shape.toml', 'namespace="org.fixture.shape"\nversion=[1,0,0]\nuniverse="tracked-exclusive"\nignore=[{name="run",pattern=\'%s".lane/" *VCHAR\'}]\n')
        write('.linter/owners.toml', 'namespace="org.fixture.owners"\nversion=[1,0,0]\nowners=["ROOT"]\npartitions=[{name="all",owner="ROOT",pattern="1*VCHAR"}]\nmay_cite=[]\n')
        write('.linter/policies.toml', 'namespace="org.fixture.policies"\nversion=[1,0,0]\npolicies=[]\n')
        write('.linter/environments.toml', 'namespace="org.fixture.environments"\nversion=[1,0,0]\nenvironments=[]\nreserved_kinds=[]\n')
        write('.linter/lists.toml', 'namespace="class.linter.lists"\nversion=[1,0,0]\n')
        write('.gitignore', '.lane/\n')
        write('ci/gate.sh', 'run_step verify true\n')
        write('src/source.rs', '// Input fixture.\n')
        write('vendor/input.rs', '// Vendor input fixture.\n')
        write('docs/datasets/generated.json', '{}\n')
        names = sorted(str(path.relative_to(root)) for path in root.rglob('*') if path.is_file())+['meson.build']
        arguments = []
        for name in names:
            producer = 'verify' if name=='docs/datasets/generated.json' else ''
            arguments.extend(['--input', name+'\tverify\t'+producer])
        quote = lambda value: "'"+str(value).replace('\\', '\\\\').replace("'", "\\'").replace('\t', '\\t')+"'"
        script = "project('census-witness', meson_version: '>=1.12.1')\npython=find_program('python3')\n"
        script += "manifest=meson.project_build_root() / 'gate-graph.json'\n"
        script += "run_command(python, "+quote(checker)+", 'configure', '--graph', manifest, '--pattern', 'a^', '--step', 'verify\\ttrue\\t', "+', '.join(map(quote, arguments))+", check:true)\n"
        script += "custom_target('tracked-census', output:'tracked-census.json', command:[python, "+quote(checker)+", 'check', '--root', meson.project_source_root(), '--graph', manifest, '--report', '@OUTPUT@'], build_always_stale:true, console:true)\n"
        write('meson.build', script)
        case.assertEqual(command(['git', 'init', '-q']).returncode, 0)
        case.assertEqual(command(['git', 'add', '-A']).returncode, 0)
        case.assertEqual(command([meson, 'setup', str(build), str(root)]).returncode, 0)

        def compile_graph():
            return command(['ninja', '-C', str(build), 'tracked-census.json'])

        result = compile_graph()
        case.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        case.assertIn('GRAPH-INCIDENCE', result.stdout)
        case.assertIn('BUILD-CENSUS', result.stdout)
        manifest = build/'gate-graph.json'
        original = json.loads(manifest.read_text())
        before = manifest.stat().st_mtime_ns
        report = build/'tracked-census.json'
        first = report.stat().st_mtime_ns
        case.assertEqual(compile_graph().returncode, 0)
        case.assertGreater(report.stat().st_mtime_ns, first)
        case.assertEqual(manifest.stat().st_mtime_ns, before)
        print('GRAPH-WITNESS vendor=passed generated=passed fresh-repeat=passed')

        # Direct Ninja invocation retains Meson's regeneration edge. Reusing
        # the build directory must not mean reusing an old configuration.
        meson_source = root/'meson.build'
        meson_source.write_text(meson_source.read_text()+'\n# Changed configuration witness.\n')
        case.assertEqual(compile_graph().returncode, 0)
        case.assertGreater(manifest.stat().st_mtime_ns, before)
        before = manifest.stat().st_mtime_ns
        case.assertEqual(compile_graph().returncode, 0)
        case.assertEqual(manifest.stat().st_mtime_ns, before)
        print('GRAPH-WITNESS ninja-regeneration=passed unchanged-configuration=reused')

        # Only the Git index changes: neither the graph nor Meson is reconfigured.
        for path in ('src/new.rs', '.new-config', '.lane/ignored-source'):
            write(path, 'New tracked input.\n')
            case.assertEqual(command(['git', 'add', '-f', path]).returncode, 0)
            result = compile_graph()
            case.assertNotEqual(result.returncode, 0)
            case.assertIn('undeclared tracked file: '+path, result.stdout)
            expected = {'src/new.rs': 'ci/build-inputs/src/meson.build',
                        '.new-config': 'meson.build',
                        '.lane/ignored-source': 'ci/build-inputs/.lane/meson.build'}[path]
            case.assertIn('add it to '+expected, result.stdout)
            case.assertEqual(manifest.stat().st_mtime_ns, before)
            case.assertNotEqual(json.loads(report.read_text())['status'], 0)
            print('GRAPH-WITNESS new-tracked='+path+' without-reconfigure=refused')
            case.assertEqual(command(['git', 'rm', '-f', path]).returncode, 0)
        case.assertEqual(compile_graph().returncode, 0)

        faults = []
        value = copy.deepcopy(original);value['inputs'][0]['consumers']=[]
        faults.append(('unconnected', value, 'unconnected or unknown consumer'))
        value = copy.deepcopy(original);value['inputs'].append(dict(path='gone.txt',consumers=['verify'],producer=''))
        faults.append(('stale', value, 'stale declaration: gone.txt'))
        value = copy.deepcopy(original);value['pattern']='.*'
        faults.append(('wide-pattern', value, 'exclusion pattern widened'))
        value = copy.deepcopy(original);value['excluded']=['src/source.rs']
        faults.append(('excluded-tracked', value, 'tracked exclusions are not admitted'))
        value = copy.deepcopy(original);value['steps']=[]
        faults.append(('missing-step', value, 'step roster or command differs'))
        value = copy.deepcopy(original);value['inputs'].append(value['inputs'][0])
        faults.append(('duplicate', value, 'duplicate declaration'))
        value = copy.deepcopy(original);value['final_inputs']=[]
        faults.append(('missing-report-edge', value, 'final report consumer'))
        value = copy.deepcopy(original);value['steps'][0]['needs']=['verify']
        faults.append(('cycle', value, 'report predecessor differs'))
        for name, value, diagnostic in faults:
            with case.subTest(graph_fault=name):
                findings, _ = incidence(root, value)
                case.assertTrue(any(diagnostic in finding for finding in findings), findings)
                manifest.write_text(json.dumps(value))
                result = compile_graph()
                case.assertNotEqual(result.returncode, 0)
                case.assertIn(diagnostic, result.stdout)
                print('GRAPH-WITNESS '+name+'=refused')
        manifest.write_text(json.dumps(original))
        case.assertEqual(compile_graph().returncode, 0)


def delegation(case):
    """Compare isolated legacy/graph executions and reject stale result envelopes."""
    import time
    from build_graph import context, execute, identity, read_result, resource_line
    checker = Path(__file__).resolve().with_name('build_graph.py')
    meson = os.environ['PN_MESON_BIN']
    commands = [('before', 'python3 fixture.py read'),
                ('write', 'python3 fixture.py write'),
                ('clean', 'git diff --exit-code -- rendered.txt'),
                ('after', 'python3 fixture.py read'),
                ('check', 'python3 fixture.py check'),
                ('repeat', 'python3 fixture.py read')]
    fixture = """import pathlib,sys
p=pathlib.Path('rendered.txt')
if sys.argv[1]=='write':
 p.write_text('current\\n');print('WRITE current')
elif sys.argv[1]=='read':
 print('READ '+p.read_text().strip());sys.exit(0 if p.read_text()=='current\\n' else 3)
else:
 print('CHECK refusal' if pathlib.Path('refuse').exists() else 'CHECK accepted');sys.exit(7 if pathlib.Path('refuse').exists() else 0)
"""
    def run_at(root, argv, **kwargs):
        return subprocess.run(argv, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    for scenario in ('clean', 'stale-render', 'failing-check'):
        outcomes = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base/'source';source.mkdir()
            (source/'ci').mkdir();(source/'docs/inputs').mkdir(parents=True)
            (source/'fixture.py').write_text(fixture)
            (source/'rendered.txt').write_text('stale\n' if scenario=='stale-render' else 'current\n')
            if scenario=='failing-check':(source/'refuse').write_text('refuse\n')
            (source/'.gitignore').write_text('.lane/\n')
            (source/'ci/gate.sh').write_text(''.join('run_graph '+name+' '+command+'\n' for name,command in commands))
            (source/'docs/inputs/build-graph-slices.toml').write_text(''.join('[[rows]]\nname="'+name+'"\nslice=2\n' for name,_ in commands))
            (source/'meson.build').write_text("project('delegation-witness')\nsubdir('ci')\n")
            (source/'ci/meson.build').write_text("subdir('build-inputs')\n")
            (source/'ci/build-inputs').mkdir()
            script = "python=find_program('python3')\n"
            for name,_ in commands:
                script += "custom_target('gate-"+name+"', output:'gate-"+name+".json', command:[python, '"+str(checker)+"', 'execute', '--root', meson.project_source_root(), '--graph', meson.project_build_root() / 'gate-graph.json', '--report', '@OUTPUT@'], build_always_stale:true, console:true)\n"
            (source/'ci/build-inputs/meson.build').write_text(script)
            for argv in (['git','init','-q'],['git','add','-A'],['git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','Fixture source']):
                result=run_at(source,argv);case.assertEqual(result.returncode,0,result.stdout)
            for route in ('legacy','graph'):
                root=base/route
                result=run_at(base,['git','clone','-q',str(source),str(root)]);case.assertEqual(result.returncode,0,result.stdout)
                build=root/'.lane/build-graph';build.parent.mkdir()
                history=root/'.lane/gate-steps.tsv';history.write_text('')
                graph=dict(steps=[dict(name=n,command=c) for n,c in commands],inputs=[dict(path='fixture.py',consumers=[n for n,_ in commands])])
                if route=='graph':
                    result=run_at(root,[meson,'setup',str(build),str(root)]);case.assertEqual(result.returncode,0,result.stdout)
                    (build/'gate-graph.json').write_text(json.dumps(graph))
                results=[];walls=[]
                with patch.dict(os.environ,PN_BUILDGRAPH_RUN='fixture-'+scenario):
                    for name,command in commands:
                        start=time.monotonic()
                        argv=['bash','-c',command] if route=='legacy' else ['python3','-B',str(checker),'delegate',name]
                        result=run_at(root,argv)
                        walls.append(time.monotonic()-start)
                        results.append((name,result.returncode,result.stdout))
                        with history.open('a') as output:output.write(f'{name}\t{result.returncode}\t1\t2\n')
                    if route=='graph':
                        report=build/'ci/build-inputs/gate-repeat.json'
                        data=json.loads(report.read_text());request=data['request']
                        case.assertEqual(read_result(report,request)[0]['status'],0)
                        line=f"STEP=repeat STATUS=0 WALL={data['wall']+2:.6f}s own_user_s=1\n"
                        measured=resource_line(root,line)
                        case.assertIn(f"command_wall_s={data['wall']:.6f}",measured)
                        case.assertIn('delegation_overhead_s=2.000000',measured)
                        case.assertEqual(resource_line(root,'GATE-RESOURCES unchanged\n'),'GATE-RESOURCES unchanged\n')
                        with patch.dict(os.environ,PN_BUILDGRAPH_RUN='other-run'):
                            case.assertIn('command_wall_s=unavailable',resource_line(root,line))
                        with patch.dict(os.environ,PN_BUILDGRAPH_ROUTE='legacy'):
                            case.assertEqual(resource_line(root,line),line)
                        reversed_clock=dict(data,ended=data['started']-1)
                        report.write_text(json.dumps(reversed_clock))
                        case.assertEqual(read_result(report,request)[0]['status'],0)
                        report.write_text(json.dumps(data))
                        for key in ('run','source','configuration','inputs','graph','history'):
                            wrong=copy.deepcopy(request);wrong['context'][key]='changed'
                            with case.assertRaises(ValueError):read_result(report,wrong)
                        missing=report.with_name('absent.json')
                        with case.assertRaises(FileNotFoundError):read_result(missing,request)
                        Path(request['log']).write_text('changed output')
                        with case.assertRaises(ValueError):read_result(report,request)
                        # The entry cannot turn a lost or forged predecessor into success.
                        prefix=history.read_text().splitlines()[:-1]
                        history.write_text('\n'.join(prefix)+'\n')
                        predecessor=build/'ci/build-inputs/gate-check.json'
                        saved=predecessor.read_text()
                        for fault in ('missing','status','run'):
                            if fault=='missing':predecessor.unlink()
                            else:
                                damaged=json.loads(saved)
                                if fault=='status':damaged['status']=99
                                else:damaged['request']['context']['run']='old-run'
                                predecessor.write_text(json.dumps(damaged))
                            refused=run_at(root,['python3','-B',str(checker),'delegate','repeat'])
                            case.assertEqual(refused.returncode,2,refused.stdout)
                            case.assertIn(b'BUILD-GRAPH-ERROR',refused.stdout)
                            predecessor.write_text(saved)
                        # Validate freshness again at execution, not only at request creation.
                        history.write_text('')
                        bound=context(root,graph,'before')
                        req=dict(context=bound,nonce='probe',log=str(build/'probe.log'))
                        reqpath=build/'probe.json';reqpath.write_text(json.dumps(req))
                        for fault in ('run','configuration','input','source'):
                            with patch.dict(os.environ,PN_BUILDGRAPH_REQUEST=str(reqpath)):
                                saved=(root/'fixture.py').read_text()
                                if fault=='run':os.environ['PN_BUILDGRAPH_RUN']='another'
                                if fault=='configuration':os.environ['RUSTFLAGS']='--cfg changed'
                                if fault=='input':(root/'fixture.py').write_text(saved+'# changed\n')
                                if fault=='source':
                                    changed=copy.deepcopy(req);changed['context']['source']='different';reqpath.write_text(json.dumps(changed))
                                with case.assertRaises(ValueError):execute(root,build/'gate-graph.json',build/'probe-result.json')
                                (root/'fixture.py').write_text(saved);reqpath.write_text(json.dumps(req))
                        history.write_text('wrong\t0\t1\t2\n')
                        with case.assertRaises(ValueError):context(root,graph,'before')
                        if scenario=='clean':
                            # Configuration is a prerequisite until the unified entry lands.
                            # Ordinary command refusals above still allow independent commands.
                            manifest=build/'gate-graph.json';saved_graph=manifest.read_text()
                            slices=root/'docs/inputs/build-graph-slices.toml';saved_slices=slices.read_text()
                            meson_file=root/'meson.build';saved_meson=meson_file.read_text()
                            for fault in ('missing-slice','setup','regeneration'):
                                history.write_text('')
                                for name,_ in commands:
                                    (build/f'ci/build-inputs/gate-{name}.json').unlink(missing_ok=True)
                                if fault=='missing-slice':slices.write_text('[[rows]]\nname="before"\nslice=2\n')
                                elif fault=='setup':
                                    meson_file.write_text(saved_meson+"error('configuration witness')\n")
                                    failed_setup=run_at(root,[meson,'setup',str(root/'.lane/failed-setup'),str(root)])
                                    case.assertNotEqual(failed_setup.returncode,0)
                                    manifest.unlink()
                                else:meson_file.write_text(saved_meson+"error('regeneration witness')\n")
                                for name,_ in commands:
                                    refused=run_at(root,['python3','-B',str(checker),'delegate',name])
                                    case.assertEqual(refused.returncode,2,refused.stdout)
                                    case.assertIn(b'BUILD-GRAPH-ERROR',refused.stdout)
                                    case.assertNotIn(b'READ current',refused.stdout)
                                    with history.open('a') as output:output.write(f'{name}\t2\t1\t2\n')
                                print(f'GRAPH-CONFIGURATION fault={fault} structurally-refused={len(commands)} command-verdicts=0')
                                slices.write_text(saved_slices);manifest.write_text(saved_graph);meson_file.write_text(saved_meson)

                diff=run_at(root,['git','diff','--','rendered.txt']).stdout
                outcomes.append((results,diff))
                print(f'GRAPH-COMPARISON scenario={scenario} route={route} statuses={[r[1] for r in results]} wall={sum(walls):.6f}')
            case.assertEqual(outcomes[0],outcomes[1])
            expected=[0]*6 if scenario=='clean' else ([3,0,1,0,0,0] if scenario=='stale-render' else [0,0,0,0,7,0])
            case.assertEqual([row[1] for row in outcomes[1][0]],expected)
    print('GRAPH-DELEGATION fixtures=3 equal=3 stale-envelopes=refused status-seven=preserved order=preserved')


def cargo_delegation(case):
    """Real Cargo in isolated sources, with serial builds and a separate doctest."""
    import time
    import tomllib
    from build_graph import roster, selected
    repository=Path(__file__).resolve().parent.parent
    checker=repository/'ci/build_graph.py'
    expected={
        'cargo-config-measurement':'python3 -B ci/measure_rustflags.py',
        'fmt':'python3 ci/discipline.py fmt',
        'clippy':'python3 ci/discipline.py clippy',
        'nursery-advisory':'python3 ci/discipline.py nursery',
        'minimal':'python3 ci/discipline.py minimal',
        'rustdoc':'python3 ci/discipline.py rustdoc',
        'benchmarks':'python3 -B ci/benchmarks.py',
        'observation-build':'cargo build --offline --locked --profile gate -p execwrap -p pn-records -p pn-graph --features pn-records/test-support --examples',
        'host-observation-build':'python3 -B ci/host_evidence_build.py',
    }
    rows=tomllib.loads((repository/'docs/inputs/build-graph-slices.toml').read_text())['rows']
    case.assertEqual({r['name'] for r in rows if r['slice']==3},set(expected))
    case.assertEqual({n:c for n,c in roster(repository) if n in expected},expected)
    case.assertTrue(set(expected)<=set(selected(repository)))
    commands=[(n,'python3 -B fixture.py '+n) for n in ('build','tests','doctests','advisory','compile-failure','timing')]
    driver=r'''import json,os,pathlib,subprocess,sys
action=sys.argv[1]
if action=='timing':
 sys.path.insert(0,os.environ['FIXTURE_CHECKERS'])
 from devperf import main
 sys.argv=['devperf','--operation','injected-duration','--duration-s','6','--outcome','exit:0','--budget','ordinary-check','--source','fixture','--budgets',os.environ['FIXTURE_CHECKERS']+'/../docs/inputs/devperf-budgets.toml','--registry',os.environ['FIXTURE_CHECKERS']+'/../docs/inputs/devperf-registry.toml','--findings','.lane/timing.jsonl']
 status=main();finding=json.loads(pathlib.Path('.lane/timing.jsonl').read_text())
 print('FIXTURE '+json.dumps(dict(action=action,status=status,classification=finding['classification'],verdict_effect=finding['verdict_effect'])))
 sys.exit(status)
args={'build':['check','--message-format=json'],'tests':['test','--lib','--message-format=json','--','--list'],'doctests':['test','--doc','--','--list'],'advisory':['clippy','--message-format=json','--','-W','clippy::needless_return'],'compile-failure':['check','--message-format=json']}[action]
argv=['cargo',args[0],'--offline','--locked','--profile','dev']+args[1:]
source=pathlib.Path('src/lib.rs');saved=source.read_text()
try:
 if action=='compile-failure':source.write_text(saved+'\ncompile_error!("injected compile failure");\n')
 result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
finally:source.write_text(saved)
artifacts=[];diagnostics=[];tests=[]
for line in result.stdout.decode().splitlines():
 try:item=json.loads(line)
 except ValueError:
  if line.endswith(': test'):tests.append(line)
  continue
 if item.get('reason')=='compiler-artifact':
  artifacts.append(dict(name=item['target']['name'],kind=item['target']['kind'],profile=item['profile'],extensions=sorted(pathlib.Path(f).suffix for f in item['filenames'])))
 if item.get('reason')=='compiler-message':
  msg=item['message'];diagnostics.append((msg['level'],(msg.get('code') or {}).get('code'),msg['message']))
print('FIXTURE '+json.dumps(dict(action=action,status=result.returncode,argv=argv,target=os.environ['CARGO_TARGET_DIR'],artifacts=artifacts,tests=tests,diagnostics=diagnostics),sort_keys=True))
sys.exit(result.returncode)
'''
    with tempfile.TemporaryDirectory() as directory:
        base=Path(directory);source=base/'source';source.mkdir()
        (source/'src').mkdir();(source/'ci/build-inputs').mkdir(parents=True);(source/'docs/inputs').mkdir(parents=True)
        (source/'Cargo.toml').write_text('[package]\nname="composition-fixture"\nversion="0.1.0"\nedition="2021"\n')
        (source/'Cargo.lock').write_text('version = 4\n[[package]]\nname = "composition-fixture"\nversion = "0.1.0"\n')
        fence=chr(96)*3
        (source/'src/lib.rs').write_text('//! '+fence+'\n//! assert_eq!(composition_fixture::value(), 1);\n//! '+fence+'\npub fn value() -> u8 { return 1; }\n#[test] fn value_is_one() { assert_eq!(value(),1); }\n')
        (source/'fixture.py').write_text(driver)
        (source/'.gitignore').write_text('.lane/\n')
        (source/'ci/gate.sh').write_text(''.join(f'run_graph {n} {c}\n' for n,c in commands))
        (source/'docs/inputs/build-graph-slices.toml').write_text(''.join(f'[[rows]]\nname="{n}"\nslice=3\n' for n,_ in commands))
        (source/'meson.build').write_text("project('cargo-delegation')\nsubdir('ci/build-inputs')\n")
        (source/'ci/build-inputs/meson.build').write_text("python=find_program('python3')\n"+''.join("custom_target('gate-"+n+"', output:'gate-"+n+".json', command:[python, '"+str(checker)+"', 'execute', '--root', meson.project_source_root(), '--graph', meson.project_build_root() / 'gate-graph.json', '--report', '@OUTPUT@'], build_always_stale:true)\n" for n,_ in commands))
        def invoke(root,argv,env=None):
            return subprocess.run(argv,cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        for argv in (['git','init','-q'],['git','add','-A'],['git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','Cargo fixture']):
            result=invoke(source,argv);case.assertEqual(result.returncode,0,result.stdout)
        outcomes=[]
        for route in ('legacy','graph'):
            root=base/route;result=invoke(base,['git','clone','-q',str(source),str(root)]);case.assertEqual(result.returncode,0,result.stdout)
            build=root/'.lane/build-graph';build.parent.mkdir();history=root/'.lane/gate-steps.tsv';history.write_text('')
            env=dict(os.environ,PN_BUILDGRAPH_RUN='cargo-fixture',CARGO_TARGET_DIR=str(root/'.lane/target'),FIXTURE_CHECKERS=str(repository/'ci'),RUSTUP_TOOLCHAIN='nightly-2026-10-16')
            if route=='graph':
                result=invoke(root,[os.environ['PN_MESON_BIN'],'setup',str(build),str(root)],env);case.assertEqual(result.returncode,0,result.stdout)
                graph=dict(steps=[dict(name=n,command=c) for n,c in commands],inputs=[dict(path=p,consumers=[n for n,_ in commands]) for p in ('fixture.py','Cargo.toml','Cargo.lock','src/lib.rs')])
                (build/'gate-graph.json').write_text(json.dumps(graph))
            records=[];started=time.monotonic()
            for name,command in commands:
                result=invoke(root,['bash','-c',command] if route=='legacy' else ['python3','-B',str(checker),'delegate',name],env)
                values=[json.loads(line.removeprefix('FIXTURE ')) for line in result.stdout.decode().splitlines() if line.startswith('FIXTURE ')]
                case.assertEqual(len(values),1,result.stdout);value=values[0]
                case.assertEqual(result.returncode,value['status'])
                if 'target' in value:case.assertEqual(value.pop('target'),env['CARGO_TARGET_DIR'])
                records.append(value)
                with history.open('a') as stream:stream.write(f'{name}\t{result.returncode}\t1\t2\n')
            outcomes.append(records)
            case.assertEqual([r['status'] for r in records],[0,0,0,0,101,0])
            case.assertTrue(records[0]['artifacts'])
            case.assertEqual(records[1]['tests'],['value_is_one: test'])
            case.assertEqual(len(records[2]['tests']),1)
            case.assertNotIn('value_is_one: test',records[2]['tests'])
            case.assertTrue(any(d[1]=='clippy::needless_return' for d in records[3]['diagnostics']))
            case.assertTrue(any(d[0]=='error' and d[2]=='injected compile failure' for d in records[4]['diagnostics']))
            case.assertEqual(records[5]['verdict_effect'],'none')
            print(f'CARGO-DELEGATION route={route} statuses={[r["status"] for r in records]} wall={time.monotonic()-started:.6f}')
        case.assertEqual(outcomes[0],outcomes[1])
    print('CARGO-DELEGATION inventories=equal diagnostics=equal compile-failure=101 advisory=0 timing-excess=0 target=serialized doctests=separate roster=9')
