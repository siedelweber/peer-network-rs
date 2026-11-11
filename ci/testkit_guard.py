"""Reject normal/build edges to development-only support, including renamed edges."""

import json
from pathlib import Path
import subprocess
import sys
import tomllib

from devperf import StructuralError


# Complete first-party feature classification; spelling is not a policy rule.
FEATURE_CLASSES = {
    'cli-common': {'observation-test-hook': 'development-only'},
    'documents': {}, 'execwrap': {}, 'pn-act-authentication': {}, 'pn-act-profile': {},
    'pn-epoch': {'default': 'production', 'test-support': 'development-only'},
    'pn-graph': {},
    'pn-host': {'default': 'production', 'development-network': 'production'},
    'pn-interchange': {},
    'pn-records': {'test-support': 'development-only'},
    'pn-secret-home': {}, 'pn-testkit': {}, 'pn-verification': {},
    'pn-wallet': {'default': 'production', 'fuzzing': 'development-only'},
}


def validate(metadata, feature_classes=FEATURE_CLASSES):
    first_party = {package['name']: package for package in metadata['packages']
                   if package['id'] in metadata['workspace_members'] and
                   Path(package['manifest_path']).is_relative_to(Path(metadata['workspace_root'])/'packages')}
    if set(first_party) != set(feature_classes):
        raise StructuralError('feature package inventory differs')
    for name, package in first_party.items():
        actual, declared = set(package.get('features', {})), set(feature_classes[name])
        if actual-declared:
            raise StructuralError('unclassified feature: '+name+'/'+','.join(sorted(actual-declared)))
        if declared-actual:
            raise StructuralError('absent classified feature: '+name+'/'+','.join(sorted(declared-actual)))
        if any(value not in {'production', 'development-only'} for value in feature_classes[name].values()):
            raise StructuralError('unknown feature class: '+name)
    development_features = {name: frozenset(feature for feature, kind in rows.items() if kind == 'development-only')
                            for name, rows in feature_classes.items()}
    support = {package['name']: package.get('features', {}) for package in metadata['packages']
               if package['name'] in development_features}
    def expanded(features, requested):
        pending = list(requested)
        reached = set()
        while pending:
            feature = pending.pop()
            if feature not in reached:
                reached.add(feature)
                pending.extend(features.get(feature, []))
        return reached
    for package in metadata['packages']:
        for dependency in package['dependencies']:
            if dependency['name'] == 'pn-testkit' and dependency.get('kind') != 'dev':
                raise StructuralError(f"{package['name']}: pn-testkit normal/build dependency forbidden")
            if dependency.get('kind') == 'dev' or dependency['name'] not in support:
                continue
            requested = list(dependency.get('features', []))
            if dependency.get('uses_default_features', True): requested.append('default')
            alias = dependency.get('rename') or dependency['name']
            # Any production feature may be selected. The provider's own
            # development-only test-support branch is checked at its consumers.
            for name, features in package.get('features', {}).items():
                if name in development_features.get(package['name'], ()): continue
                for feature in expanded(package['features'], features):
                    for prefix in (alias+'/', alias+'?/'):
                        if feature.startswith(prefix): requested.append(feature[len(prefix):])
            forbidden = development_features[dependency['name']] & expanded(support[dependency['name']], requested)
            if forbidden:
                raise StructuralError(f"{package['name']}: {dependency['name']}/{','.join(sorted(forbidden))} normal/build feature forbidden")


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
        counts = {kind: sum(value == kind for rows in FEATURE_CLASSES.values() for value in rows.values())
                  for kind in ('production', 'development-only')}
        print('TESTKIT-GUARD production edges exclude pn-testkit and declared development-only features classification='+json.dumps(counts, sort_keys=True))
        return 0
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f'TESTKIT-STRUCTURAL-ERROR {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
