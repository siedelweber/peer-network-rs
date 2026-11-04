"""Refusal and ordering controls for admitted index input families."""
import json
import random
import tempfile
from pathlib import Path
import subprocess
import sys
import tomllib
from unittest.mock import patch

import registry_fragments as fragments


def toml_value(value):
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return '['+', '.join(map(toml_value, value))+']'
    if isinstance(value, dict):
        return '{ '+', '.join(json.dumps(key)+' = '+toml_value(item) for key, item in value.items())+' }'
    return str(value)


def envelope_text(data):
    return ('namespace = '+toml_value(data['namespace'])+'\nversion = '+toml_value(data['version'])+'\n'+
            ''.join('\n[[rows]]\n'+''.join(key+' = '+toml_value(value)+'\n' for key, value in row.items())
                    for row in data['rows']))


def service(test, root, text, selection):
    from build_graph_evidence import SERVICE_CASE, service_selection
    data = tomllib.loads(text)
    folder = root/fragments.ROOTS['harness-registry']
    folder.mkdir()
    fields = {}
    selected = None
    for index, row in enumerate(data['rows']):
        fields.setdefault(row['kind'], set()).update(row)
        path = folder/(str(index)+'.toml')
        path.write_text(''.join(key+' = '+toml_value(value)+'\n' for key, value in row.items()))
        if SERVICE_CASE in row.get('cases', []):
            selected = path
    (folder/'schema.toml').write_text('namespace = '+toml_value(data['namespace'])+'\nversion = '+
        toml_value(data['version'])+'\nfields = '+toml_value({k:sorted(v) for k,v in fields.items()})+'\n')
    (root/'docs/inputs/harness-registry.toml').unlink()
    def stage():
        subprocess.run(['git', '-C', str(root), 'add', '-A'], check=True, capture_output=True)
    stage()
    test.assertEqual(service_selection(root), selection)
    held = next(row for row in data['rows'] if row.get('kind')=='suite' and row.get('status')=='held')
    (folder/'unrelated.toml').write_text(''.join(key+' = '+toml_value(value)+'\n'
        for key,value in dict(held, name='unrelated-fragment').items()))
    stage()
    test.assertEqual(service_selection(root), selection)
    test.assertIsNotNone(selected)
    original = selected.read_text()
    changed = original.replace('scenario_jobs = 4', 'scenario_jobs = 5')
    test.assertNotEqual(changed, original)
    selected.write_text(changed)
    test.assertTrue(service_selection(root)['run'])
    selected.write_text(original)
    test.assertEqual(service_selection(root), selection)
    row = tomllib.loads(original)
    row['tier'] = 'unresolved-tier'
    selected.write_text(''.join(key+' = '+toml_value(value)+'\n' for key,value in row.items()))
    with test.assertRaisesRegex(ValueError, 'requires one tier'):
        service_selection(root)
    selected.write_text(original)


def check(test):
    hash_carriers(test)
    owner_controls(test)
    observation_controls(test)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        def git(*args):
            subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
        git('init', '-q')
        prefix = fragments.ROOTS['claim-obligations']
        folder = root/prefix
        folder.mkdir(parents=True)
        (folder/'schema.toml').write_text('namespace="org.peer-network.claim.obligations"\nversion=[1,0,0]\n[fields]\nrow=["name","claims"]\n')
        for name in ('z', 'a'):
            (folder/(name+'.toml')).write_text('name='+json.dumps(name)+'\nclaims=[]\n')
        git('add', '.')
        monolith = root/(prefix+'.toml')
        monolith.write_text('namespace="duplicate"\n')
        with test.assertRaisesRegex(ValueError, 'dual registry authoring'):
            fragments.read(root, 'claim-obligations')
        monolith.unlink()
        expected = fragments.read(root, 'claim-obligations')
        # The batched transport uses the same reader and preserves each envelope.
        batched = subprocess.run([sys.executable, '-B', str(Path(fragments.__file__)), str(root),
                                  'claim-obligations', 'claim-obligations'],
                                 check=True, capture_output=True, text=True)
        test.assertEqual([json.loads(line) for line in batched.stdout.splitlines()], [expected, expected])
        declaration = dict(path=prefix+'/schema.toml', consumers=['census', 'claims'], producer='')
        expanded = fragments.expanded_inputs(root, [declaration])
        test.assertEqual([row['path'] for row in expanded], [prefix+'/a.toml', prefix+'/z.toml'])
        test.assertTrue(all(row['consumers']==declaration['consumers'] for row in expanded))
        with test.assertRaisesRegex(ValueError, 'lacks declared incidence'):
            fragments.expanded_inputs(root, [])
        test.assertEqual([row['name'] for row in expected['rows']], ['a', 'z'])
        # A family read does not traverse another family's files; the full
        # census still validates every root. Every call re-reads its own bytes.
        test.assertEqual(fragments.indexed(root, 'claim-obligations'), fragments.indexed(root))
        with patch.object(fragments, 'indexed', wraps=fragments.indexed) as index:
            test.assertEqual(fragments.read(root, 'claim-obligations'), expected)
            index.assert_called_once_with(root, 'claim-obligations')
        expected['rows'][0]['claims'].append('caller-mutation')
        test.assertEqual(fragments.read(root, 'claim-obligations')['rows'][0]['claims'], [])
        expected = fragments.read(root, 'claim-obligations')
        paths = list(fragments.indexed(root).items())
        rng = random.Random(7)
        for _ in range(12):
            rng.shuffle(paths)
            with patch.object(fragments, 'indexed', return_value=dict(paths)):
                test.assertEqual(json.dumps(fragments.read(root, 'claim-obligations')), json.dumps(expected))
        duplicate = folder/'duplicate.toml'
        duplicate.write_text((folder/'a.toml').read_text())
        git('add', '.')
        with test.assertRaisesRegex(ValueError, 'duplicate fragment') as caught:
            fragments.read(root, 'claim-obligations')
        test.assertIn(prefix+'/a.toml', str(caught.exception))
        test.assertIn(prefix+'/duplicate.toml', str(caught.exception))
        git('rm', '-f', str(duplicate.relative_to(root)))
        path = folder/'z.toml'
        original = path.read_text()
        path.write_text(original+'unknown=true\n')
        with test.assertRaisesRegex(ValueError, 'unknown fragment key'):
            fragments.read(root, 'claim-obligations')
        path.write_text(original)
        bad = folder/'bad.txt'
        bad.write_text('not a carrier')
        git('add', '.')
        with test.assertRaisesRegex(ValueError, 'unknown fragment suffix'):
            fragments.read(root, 'claim-obligations')
        git('rm', '-f', str(bad.relative_to(root)))
        path.unlink()
        path.symlink_to('a.toml')
        with test.assertRaisesRegex(ValueError, 'not a regular file'):
            fragments.read(root, 'claim-obligations')
        git('add', '.')
        with test.assertRaisesRegex(ValueError, 'index mode'):
            fragments.read(root, 'claim-obligations')
        path.unlink()
        path.mkdir()
        git('update-index', '--cacheinfo', '100644,'+subprocess.check_output(
            ['git', '-C', str(root), 'rev-parse', ':'+prefix+'/a.toml'], text=True).strip()+','+prefix+'/z.toml')
        with test.assertRaisesRegex(ValueError, 'not a regular file'):
            fragments.read(root, 'claim-obligations')


def observation_controls(test):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        folder = root/fragments.ROOTS['observation-registry']
        folder.mkdir(parents=True)
        fields = {key: [] for key in ('operations', 'metrics', 'reviews', 'generators',
                  'reviewed_types', 'class_decisions', 'shapes', 'assessments')}
        fields['operations'] = ['package', 'path', 'item', 'shape']
        fields['reviews'] = ['operation', 'class_decision', 'assessments']
        fields['class_decisions'] = ['name', 'membership']
        fields['shapes'] = ['metrics']
        def write(name, value):
            path = folder/(name+'.json')
            path.write_text(json.dumps(value))
            return path
        write('schema', dict(schema=2, configuration='fixture', fields=fields))
        write('class', dict(section='class_decisions', value=dict(name='class', membership=dict(explicit=['p::s::f']))))
        write('shape', dict(section='shapes', name='shape', value=dict(metrics=[])))
        operation = dict(section='operations', value=dict(package='p', path='s', item='f', shape='shape'),
                         review=dict(operation='p::s::f', class_decision='class', assessments={}))
        path = write('operation', operation)
        subprocess.run(['git', '-C', str(root), 'init', '-q'], check=True, capture_output=True)
        def stage():
            subprocess.run(['git', '-C', str(root), 'add', '-A'], check=True, capture_output=True)
        stage()
        expected = json.dumps(fragments.read(root, 'observation-registry'))
        paths = list(fragments.indexed(root).items())
        rng = random.Random(19)
        for _ in range(12):
            rng.shuffle(paths)
            with patch.object(fragments, 'indexed', return_value=dict(paths)):
                test.assertEqual(json.dumps(fragments.read(root, 'observation-registry')), expected)
        duplicate = write('duplicate', operation)
        stage()
        with test.assertRaisesRegex(ValueError, 'duplicate fragment') as caught:
            fragments.read(root, 'observation-registry')
        test.assertIn('operation.json', str(caught.exception))
        test.assertIn('duplicate.json', str(caught.exception))
        duplicate.unlink()
        stage()
        original = path.read_text()
        write('operation', dict(operation, unknown=True))
        with test.assertRaisesRegex(ValueError, 'unknown or missing fragment key'):
            fragments.read(root, 'observation-registry')
        operation['value']['shape'] = 'missing'
        write('operation', operation)
        with test.assertRaisesRegex(ValueError, 'unresolved observation shape'):
            fragments.read(root, 'observation-registry')
        path.write_text(original[:-1]+', "section": "operations"}')
        with test.assertRaisesRegex(ValueError, 'duplicate JSON object member'):
            fragments.read(root, 'observation-registry')


def owner_controls(test):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        folder = root/fragments.ROOTS['linter-owners']
        folder.mkdir(parents=True)
        def write(name, row):
            path = folder/(name+'.toml')
            path.write_text(''.join(key+' = '+toml_value(value)+'\n' for key, value in row.items()))
            return path
        write('schema', dict(namespace='org.peer-network.linter.owners', version=[1,0,0],
              declaration=dict(name='declaration', root_owner='ROOT', imports=[]),
              fields=['name', 'position', 'partitions', 'may_cite']))
        owner = dict(name='ROOT', position=0, partitions=[], may_cite=[])
        path = write('root', owner)
        subprocess.run(['git', '-C', str(root), 'init', '-q'], check=True, capture_output=True)
        def stage():
            subprocess.run(['git', '-C', str(root), 'add', '-A'], check=True, capture_output=True)
        stage()
        test.assertEqual(fragments.read(root, 'linter-owners')['rows'][0]['owners'], ['ROOT'])
        paths = list(fragments.indexed(root).items())
        expected = json.dumps(fragments.read(root, 'linter-owners'))
        rng = random.Random(23)
        for _ in range(12):
            rng.shuffle(paths)
            with patch.object(fragments, 'indexed', return_value=dict(paths)):
                test.assertEqual(json.dumps(fragments.read(root, 'linter-owners')), expected)
        duplicate = write('duplicate', owner)
        stage()
        with test.assertRaisesRegex(ValueError, 'duplicate fragment') as caught:
            fragments.read(root, 'linter-owners')
        test.assertIn('root.toml', str(caught.exception))
        test.assertIn('duplicate.toml', str(caught.exception))
        duplicate.unlink()
        stage()
        write('root', dict(owner, unknown=True))
        with test.assertRaisesRegex(ValueError, 'unknown or missing owner fragment key'):
            fragments.read(root, 'linter-owners')
        write('root', dict(owner, may_cite=[dict(position=0, value=dict(owner='ROOT', target='missing'))]))
        with test.assertRaisesRegex(ValueError, 'unresolved owner edge'):
            fragments.read(root, 'linter-owners')


def hash_carriers(test):
    script = Path(__file__).with_name('discipline.py').resolve()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root/'ci').mkdir()
        (root/'sample.rs').write_text('0xff\n')
        (root/'ci/hash-citation-families.toml').write_text(
            'namespace="org.peer-network.ci.hash-citations"\nversion=[1,0,0]\n[[rows]]\n'
            'family="bytes"\ngroup="fixture"\nmeasures="byte"\nproducer="authored"\n'
            'establishment="defined"\nreader="byte"\ndefinition="Explicit byte."\npaths=["sample.rs"]\n')
        subprocess.run(['git', '-C', str(root), 'init', '-q'], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(root), 'add', '.'], check=True, capture_output=True)
        paths = []
        for name, prefix in fragments.ROOTS.items():
            suffix = '.json' if name=='observation-registry' else '.toml'
            path = root/prefix/('unaccounted'+suffix)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('"'+('f'*64)+'"\n')
            paths.append(path.relative_to(root).as_posix())
        command = [sys.executable, '-B', str(script), 'hash-citations']
        before = subprocess.run(command, cwd=root, capture_output=True, text=True)
        test.assertEqual(before.returncode, 0, before.stdout+before.stderr)
        subprocess.run(['git', '-C', str(root), 'add', '.'], check=True, capture_output=True)
        after = subprocess.run(command, cwd=root, capture_output=True, text=True)
        test.assertEqual(after.returncode, 1, after.stdout+after.stderr)
        for path in paths:
            test.assertIn(path+':1: unaccounted', after.stdout)
