"""Index-scoped, duplicate-refusing registry input assembly.

The declared roots are input families, not glob exclusions. Every indexed path
below one is validated and remains an exact census and citation input.
"""
import argparse
import json
from pathlib import Path
import stat
import subprocess
import tomllib


ROOTS = {
    'claim-obligations': 'docs/inputs/claim-obligations',
    'harness-registry': 'docs/inputs/harness-registry',
    'linter-owners': 'docs/inputs/linter-owners',
    'observation-registry': 'ci/observation-registry',
}


def indexed(root):
    result = subprocess.run(['git', '-C', str(root), 'ls-files', '--stage', '-z'],
                            capture_output=True, check=True)
    found = {}
    for entry in result.stdout.decode().split('\0'):
        if not entry:
            continue
        metadata, path = entry.split('\t', 1)
        if not any(path.startswith(prefix+'/') for prefix in ROOTS.values()):
            continue
        mode, _, stage = metadata.split()
        if stage != '0' or mode not in {'100644', '100755'} or path in found:
            raise ValueError('fragment index mode or stage: '+path)
        full = root/path
        if not stat.S_ISREG(full.lstat().st_mode):
            raise ValueError('fragment is not a regular file: '+path)
        for parent in full.parents:
            if parent == root:
                break
            if parent.is_symlink():
                raise ValueError('fragment symlink ancestor: '+path)
        expected = '.json' if path.startswith(ROOTS['observation-registry']+'/') else '.toml'
        if full.suffix != expected:
            raise ValueError('unknown fragment suffix: '+path)
        found[path] = full
    return found


def distinct(pairs):
    result = {}
    for key, path, value in pairs:
        if key in result:
            raise ValueError(f'duplicate fragment {key}: {result[key][0]} and {path}')
        result[key] = (path, value)
    return result



def json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON object member: '+key)
        result[key] = value
    return result


def observation_key(section, row):
    if section in {'operations', 'reviewed_types', 'generators'}:
        key = (row['package'], row['path'], row['item'])
        return key + (row['kind'], row['syntax']) if section == 'generators' else key
    if section == 'named_operations':
        if not isinstance(row, str):
            raise ValueError('named operation must be text')
        return (row,)
    return (row['name'],)


def observation(paths, prefix):
    schema_path = prefix+'/schema.json'
    if schema_path not in paths:
        raise ValueError('missing central fragment schema: '+schema_path)
    parse = lambda path: json.loads(paths[path].read_text(), object_pairs_hook=json_object)
    schema = parse(schema_path)
    sections = ('named_operations', 'operations', 'metrics', 'reviews', 'generators',
                'reviewed_types', 'class_decisions', 'shapes', 'assessments')
    if set(schema) != {'schema', 'configuration', 'fields'} or schema['schema'] != 2:
        raise ValueError('unknown observation fragment schema key or edition')
    fields = schema['fields']
    if set(fields) != set(sections)-{'named_operations'}:
        raise ValueError('observation fragment field declarations differ')
    entries = {section: [] for section in sections}
    for path in paths:
        if path == schema_path:
            continue
        fragment = parse(path)
        section = fragment.get('section')
        if section not in entries or section == 'reviews':
            raise ValueError('unknown fragment section: '+path)
        extra = {'name'} if section in {'shapes', 'assessments'} else ({'review'} if section == 'operations' else set())
        if set(fragment) != {'section', 'value'} | extra:
            raise ValueError('unknown or missing fragment key: '+path)
        value = fragment['value']
        if section != 'named_operations' and (not isinstance(value, dict) or set(value)-set(fields[section])):
            raise ValueError('unknown fragment value key: '+path)
        if section in {'shapes', 'assessments'}:
            key = (fragment['name'],)
        else:
            key = observation_key(section, value)
        entries[section].append((key, path, value))
        if section == 'operations':
            review = fragment['review']
            if (not isinstance(review, dict) or set(review)-set(fields['reviews']) or
                    review.get('operation') != '::'.join(key)):
                raise ValueError('operation and review identity differ: '+path)
            entries['reviews'].append((key, path, review))
    result = dict(schema=schema['schema'], configuration=schema['configuration'])
    for section, pairs in entries.items():
        merged = distinct(pairs)
        keys = sorted(merged)
        result[section] = ({key[0]: merged[key][1] for key in keys} if section in {'shapes', 'assessments'}
                           else [merged[key][1] for key in keys])
    operations = {'::'.join(observation_key('operations', row)) for row in result['operations']}
    classes = {row['name'] for row in result['class_decisions']}
    metrics = {row['name'] for row in result['metrics']}
    if not set(result['named_operations']) <= operations:
        raise ValueError('unresolved named observation operation')
    for row in result['operations']:
        if row.get('shape') not in result['shapes']:
            raise ValueError('unresolved observation shape')
        exception = row.get('exception')
        if exception and (exception.get('class_decision') not in classes or exception.get('boundary') not in operations):
            raise ValueError('unresolved observation exception')
    for row in result['reviews']:
        if (row.get('class_decision') not in classes or
                not set(row.get('assessments', {}).values()) <= set(result['assessments'])):
            raise ValueError('unresolved observation review')
    for row in result['generators']:
        if row.get('class_decision') not in classes:
            raise ValueError('unresolved generator class')
    for row in result['shapes'].values():
        if not set(row.get('metrics', [])) <= metrics:
            raise ValueError('unresolved observation metric')
    for row in result['class_decisions']:
        if not set(row.get('membership', {}).get('explicit', [])) <= operations:
            raise ValueError('unresolved observation membership')
    return result


def owners(paths, prefix):
    schema_path = prefix+'/schema.toml'
    if schema_path not in paths:
        raise ValueError('missing central fragment schema: '+schema_path)
    schema = tomllib.loads(paths[schema_path].read_text())
    if set(schema) != {'namespace', 'version', 'declaration', 'fields'}:
        raise ValueError('unknown owner schema key')
    declaration = schema['declaration']
    if set(declaration) != {'name', 'root_owner', 'imports'}:
        raise ValueError('unknown owner declaration key')
    entries = []
    for path, full in paths.items():
        if path == schema_path:
            continue
        row = tomllib.loads(full.read_text())
        if set(row) != set(schema['fields']) or not isinstance(row.get('name'), str):
            raise ValueError('unknown or missing owner fragment key: '+path)
        entries.append((row['name'], path, row))
    merged = distinct(entries)
    def ordered(rows):
        if any(type(row.get('position')) is not int for row in rows):
            raise ValueError('owner order is not integral')
        rows = sorted(rows, key=lambda row: row['position'])
        if [row['position'] for row in rows] != list(range(len(rows))):
            raise ValueError('owner order is not complete and unique')
        return rows
    rows = ordered([value for _, value in merged.values()])
    names = [row['name'] for row in rows]
    if declaration['root_owner'] not in names:
        raise ValueError('unresolved root owner')
    partitions, edges = [], []
    for row in rows:
        for section, target, expected in [('partitions', partitions, {'name', 'owner', 'pattern'}),
                                           ('may_cite', edges, {'owner', 'target'})]:
            for entry in row[section]:
                if set(entry) != {'position', 'value'} or set(entry['value']) != expected:
                    raise ValueError('unknown owner edge key')
                value = entry['value']
                if value['owner'] != row['name'] or value.get('target', row['name']) not in names:
                    raise ValueError('unresolved owner edge')
                target.append(entry)
    partitions = [row['value'] for row in ordered(partitions)]
    edges = [row['value'] for row in ordered(edges)]
    if len({row['name'] for row in partitions}) != len(partitions) or len({(row['owner'], row['target']) for row in edges}) != len(edges):
        raise ValueError('duplicate owner edge')
    return dict(namespace=schema['namespace'], version=schema['version'],
                rows=[dict(declaration, owners=names, partitions=partitions, may_cite=edges)])


def read(root, name):
    """Read an admitted fragment family, or its not-yet-migrated monolith."""
    root = Path(root).resolve()
    prefix = ROOTS[name]
    suffix = '.json' if name == 'observation-registry' else '.toml'
    if not (root/prefix).exists():
        text = (root/(prefix+suffix)).read_text()
        return json.loads(text) if suffix == '.json' else tomllib.loads(text)
    if (root/(prefix+suffix)).exists():
        raise ValueError('dual registry authoring: '+prefix+' and '+prefix+suffix)
    paths = {path: full for path, full in indexed(root).items() if path.startswith(prefix+'/')}
    if name == 'observation-registry':
        return observation(paths, prefix)
    if name == 'linter-owners':
        return owners(paths, prefix)
    schema_path = prefix+'/schema.toml'
    if schema_path not in paths:
        raise ValueError('missing central fragment schema: '+schema_path)
    schema = tomllib.loads(paths.pop(schema_path).read_text())
    if set(schema) != {'namespace', 'version', 'fields'}:
        raise ValueError('unknown or missing fragment schema key: '+schema_path)
    fields = schema['fields']
    pairs = []
    for path, full in paths.items():
        row = tomllib.loads(full.read_text())
        kind = row.get('kind', 'row')
        if kind not in fields or set(row)-set(fields[kind]) or not isinstance(row.get('name'), str):
            raise ValueError('unknown fragment key or missing identity: '+path)
        pairs.append(((kind, row['name']), path, row))
    rows = distinct(pairs)
    order = {'level': 0, 'implementation': 1, 'tier': 2, 'suite': 3, 'row': 0}
    keys = sorted(rows, key=lambda key: (order[key[0]], key[1].encode('utf-8')))
    return dict(namespace=schema['namespace'], version=schema['version'],
                rows=[rows[key][1] for key in keys])


def expanded_inputs(root, declared):
    """Expand exact index paths with their registry's declared incidence edges."""
    by_path = {row['path']: row for row in declared}
    result = []
    for path in sorted(indexed(Path(root).resolve())):
        name = next(name for name, prefix in ROOTS.items() if path.startswith(prefix+'/'))
        suffix = '.json' if name == 'observation-registry' else '.toml'
        carrier = ROOTS[name]+'/schema'+suffix
        if carrier not in by_path:
            raise ValueError('fragment family lacks declared incidence: '+carrier)
        if path not in by_path:
            result.append(dict(by_path[carrier], path=path, producer=''))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('registry', choices=ROOTS)
    args = parser.parse_args()
    print(json.dumps(read(args.root, args.registry), ensure_ascii=False))


if __name__ == '__main__':
    main()
