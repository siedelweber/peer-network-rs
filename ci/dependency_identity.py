"""Resolve source-level dependency spellings through Cargo's package identities."""
import json
from pathlib import Path
import subprocess


def metadata(root=Path('.')):
    result = subprocess.run(
        ['cargo', 'metadata', '--offline', '--locked', '--no-deps', '--format-version', '1'],
        cwd=root, capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


def spellings(data, owner, identities):
    package = next(p for p in data['packages'] if p['name'] == owner)
    return {(d.get('rename') or d['name']).replace('-', '_')
            for d in package['dependencies'] if d['name'] in identities}
