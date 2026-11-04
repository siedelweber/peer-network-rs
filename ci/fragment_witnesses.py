"""Refusal and ordering controls for admitted index input families."""
import json
import random
import tempfile
from pathlib import Path
import subprocess
from unittest.mock import patch

import registry_fragments as fragments


def check(test):
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
