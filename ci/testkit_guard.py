"""Reject normal/build edges to development-only support, including renamed edges."""

import json
from pathlib import Path
import subprocess
import sys
import tomllib

from devperf import StructuralError


def validate(metadata):
    for package in metadata['packages']:
        for dependency in package['dependencies']:
            if dependency['name'] == 'pn-testkit' and dependency.get('kind') != 'dev':
                raise StructuralError(f"{package['name']}: pn-testkit normal/build dependency forbidden")


def main():
    try:
        command = subprocess.run(['cargo', 'metadata', '--locked', '--offline', '--format-version=1'],
                                 capture_output=True, text=True, check=True)
        metadata = json.loads(command.stdout)
        validate(metadata)
        features = {node['id']: sorted(node['features']) for node in metadata['resolve']['nodes']}
        reviewed = tomllib.loads(Path('docs/inputs/harness-dependencies.toml').read_text())['rows']
        for declaration in reviewed:
            packages = [package for package in metadata['packages'] if package['name'] == declaration['name'] and package['version'] == declaration['version']]
            if len(packages) != 1 or packages[0].get('license') != declaration['license'] or features[packages[0]['id']] != sorted(declaration['features']):
                raise StructuralError('dependency review differs: '+declaration['name'])
        print('TESTKIT-GUARD production edges exclude pn-testkit')
        return 0
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f'TESTKIT-STRUCTURAL-ERROR {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
