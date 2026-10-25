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
            return command([meson, 'compile', '-C', str(build), 'tracked-census'])

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
