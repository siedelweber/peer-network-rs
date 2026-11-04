"""Refusal and ordering controls for admitted index input families."""
import json
import random
import tempfile
from pathlib import Path
import subprocess
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
        test.assertEqual([row['name'] for row in expected['rows']], ['a', 'z'])
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
