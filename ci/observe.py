"""Rust syntax census and explicit observation admission for the current build."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import tomllib
import copy
from collections import Counter

from devperf import StructuralError
from harness import source_id

OWNERS={'cli-common':'CLICOMMON','documents':'DOCUMENTS','execwrap':'EXECWRAP','interchange':'INTERCHANGE','testkit':'TESTKIT','wallet':'WALLET','host':'HOST','records':'RECORDS'}
HELPERS={
    'cli-common::packages/cli-common/src/observation.rs::observation::scope',
    'cli-common::packages/cli-common/src/observation.rs::observation::Observation::operation',
    'cli-common::packages/cli-common/src/lib.rs::run_no_stdout_command_async',
    'pn-interchange::packages/interchange/src/observe.rs::observe::scope',
}


def identity(row):
    return row['package']+'::'+row['path']+'::'+row['item']


def class_operations(decision, census):
    membership=decision.get('membership',{})
    if set(membership)=={'labelled_package'}:
        package=membership['labelled_package']
        return sorted(identity(row) for row in census['functions'] if row['package']==package and (row['boundary'] is not None or identity(row) in HELPERS))
    if set(membership)=={'explicit'} and len(membership['explicit'])==len(set(membership['explicit'])):
        return sorted(membership['explicit'])
    raise StructuralError('invalid semantic class membership rule')


def expand_registry(decisions, census):
    """Expand reviewed shapes and membership rules, preserving item-specific evidence."""
    if decisions.get('schema')!=2:raise StructuralError('compact observation input schema differs')
    result=copy.deepcopy(decisions)
    shapes=result.pop('shapes');assessments=result.pop('assessments')
    classes={row['name']:row for row in result['class_decisions']}
    if len(classes)!=len(result['class_decisions']):raise StructuralError('duplicate semantic class decision')
    for decision in classes.values():
        if 'operations' in decision:raise StructuralError('expanded class operations must be derived')
        decision['operations']=class_operations(decision,census)
    for row in result['operations']:
        if 'fields' in row or 'metrics' in row:raise StructuralError('expanded operation shape must be derived')
        row.update(copy.deepcopy(shapes[row.pop('shape')]))
        if row['mode']=='exception':
            exception=row['exception']
            if 'enclosing_operations' in exception:raise StructuralError('expanded exception list must be derived')
            exception['enclosing_operations']=classes[exception['class_decision']]['operations'].copy()
    for row in result['generators']:
        if 'boundaries' in row:raise StructuralError('expanded generator list must be derived')
        row['boundaries']=classes[row['class_decision']]['operations'].copy()
    for row in result['reviews']:
        for field,name in row.pop('assessments').items():row[field]=copy.deepcopy(assessments[name])
    result['schema']=1
    return result


def validate(census, registry, labels, claims):
    """Check syntax and declared review bindings; never infer semantic approval."""
    if census.get('schema')!=1 or registry.get('schema')!=1:
        raise StructuralError('observation schema differs')
    if census.get('types',[])!=registry.get('reviewed_types',[]):
        raise StructuralError('type declarations changed since full-content and secret-flow review')
    functions={identity(row):row for row in census['functions']}
    if len(functions)!=len(census['functions']):raise StructuralError('duplicate source operation')
    required={identity(row) for row in census['functions'] if row['public'] or row['boundary'] is not None}
    required.update(registry['named_operations'])
    rows={identity(row):row for row in registry['operations']}
    if len(rows)!=len(registry['operations']):raise StructuralError('duplicate operation mapping')
    if set(rows)!=required or not set(rows)<=set(functions):
        raise StructuralError('missing or stale operation mapping: '+str(sorted(set(rows)^required | (set(rows)-set(functions)))))
    metrics={row['name']:row for row in registry['metrics']}
    if len(metrics)!=len(registry['metrics']):raise StructuralError('duplicate metric name')
    if census.get('metric_constants'):
        constants={row['name']:row['value'] for row in census['metric_constants']}
        expected={stem+'__'+measure:(kind,unit,{'outcome':constants['OUTCOMES']} if measure=='completed_operations' else {})
                  for stem in constants['STEMS'] for measure,kind,unit in constants['MEASURES']}
        expected.update({'records__root__sig__design__records__'+measure:(kind,unit,{}) for measure,kind,unit in constants.get('RECORDS_MEASURES',[])})
        expected.update({'host__root__sig__design__storage__'+measure:(kind,unit,{}) for measure,kind,unit in constants.get('HOST_MEASURES',[])})
        for measure in ('started_operations','completed_operations'):
            name='records__root__sig__design__records__'+measure
            if name in expected:
                kind,unit,attributes=expected[name]
                expected[name]=(kind,unit,dict(attributes,operation=operation_vocabulary(registry)))
        actual={name:(row['kind'],row['unit'],row['attributes']) for name,row in metrics.items()}
        if actual!=expected:raise StructuralError('runtime metric declarations differ from registry')
    for metric in metrics.values():
        if metric['unit'] not in {'bytes','seconds','operations','count'}:raise StructuralError('undeclared metric unit')
        if metric['kind'] not in {'counter','gauge','histogram'}:raise StructuralError('undeclared metric kind')
        allowed=({},{'outcome':['success','refusal','error','cancelled','unwinding','incomplete']})
        attrs=metric['attributes'].copy()
        if 'operation' in attrs:
            if not metric['name'].startswith('records__') or attrs.pop('operation')!=operation_vocabulary(registry):
                raise StructuralError('unregistered metric operation vocabulary')
        if attrs not in allowed:
            raise StructuralError('undeclared metric attribute')
    reviews={row['operation']:row for row in registry['reviews']}
    if len(reviews)!=len(registry['reviews']) or set(reviews)!=required:raise StructuralError('missing or duplicate semantic review')
    classes={row['name']:row for row in registry.get('class_decisions',[])}
    if len(classes)!=len(registry.get('class_decisions',[])):raise StructuralError('duplicate semantic class decision')
    for decision in classes.values():
        if decision.get('operations')!=class_operations(decision,census):
            raise StructuralError('semantic class does not contain its complete operation set')
        if decision.get('status')!='reviewer-confirmed' or not decision.get('premises') or not decision.get('operations') or not set(decision['operations'])<=set(rows):
            raise StructuralError('invalid semantic class decision')
    for name,row in rows.items():
        function=functions[name]
        if row['owner']!=function['owner']:raise StructuralError('wrong operation owner')
        if row['signature']!=function['signature']:raise StructuralError('stale source item signature')
        if row['claim'] not in labels:raise StructuralError('unresolved operation label')
        if not row['fields'] or not row['metrics'] or not set(row['metrics'])<=set(metrics):raise StructuralError('undeclared fields or metric reference')
        if row['mode']=='instrumented':
            boundary=function['boundary']
            if not boundary or 'invalid' in boundary:raise StructuralError('omitted instrumentation')
            if boundary.get('helper')=='tracing::instrument':
                actual=(boundary.get('execution_owner'),boundary.get('claim_owner')+'::'+boundary.get('claim_label'),boundary.get('source_item'))
                if boundary.get('name')!=boundary.get('claim_label'):raise StructuralError('wrong primary span label')
                if not boundary.get('records_result'):raise StructuralError('unrecorded result')
            else:
                actual=(boundary.get('owner'),'ROOT::'+boundary.get('label',''),boundary.get('item'))
            if actual!=(row['owner'],row['claim'],row['item']):raise StructuralError('wrong instrumentation owner or label')
            if row['owner']=='RECORDS' and (not row.get('operation') or boundary.get('operation')!=row['operation']):raise StructuralError('missing or wrong records operation field')
        elif row['mode']=='exception':
            exception=row.get('exception',{})
            if exception.get('rule')!='ROOT::rule:observe:spans' or exception.get('kind') not in {'const','bootstrap','recursion','inherited'}:
                raise StructuralError('invalid exception rule or kind')
            reason=exception.get('justification','')
            if not reason.startswith('Justified: ') or not reason.endswith('.') or not any(reason in attribute for attribute in function['attributes']):
                raise StructuralError('exception lacks item-local justification')
            if exception.get('witness') not in claims or exception.get('boundary') not in rows:
                raise StructuralError('exception lacks enclosing boundary witness')
            decision=classes.get(exception.get('class_decision'),{})
            inherited=exception.get('enclosing_operations',[])
            if not inherited or inherited!=decision.get('operations',[]) or exception['boundary'] not in inherited:
                raise StructuralError('exception lacks enclosing class operations')
            seen={name}
            target=exception['boundary']
            while rows[target]['mode']=='exception':
                if target in seen:raise StructuralError('cyclic exception boundary')
                seen.add(target)
                target=rows[target].get('exception',{}).get('boundary')
                if target not in rows:raise StructuralError('exception lacks enclosing boundary witness')
            if target in seen:raise StructuralError('self exception boundary')
            if exception['kind']=='const' and not function['const']:raise StructuralError('const exception on runtime function')
        elif row['mode']=='reviewed-helper':
            if name not in HELPERS:raise StructuralError('unreviewed helper identity')
            if row.get('body')!=function['body']:raise StructuralError('stale reviewed helper body')
        else:raise StructuralError('unknown observation coverage mode')
        review=reviews[name]
        if review.get('body')!=function['body']:raise StructuralError('stale semantic review body')
        if review.get('class_decision') not in classes or not review.get('item_premise'):
            raise StructuralError('missing body-bound semantic class decision')
        for field in ('full_recording','secret_flow','exposure_consumers'):
            assessment=review.get(field,{})
            if assessment.get('status')!='reviewer-confirmed' or not assessment.get('premises') or assessment.get('negative_probe') not in claims:
                raise StructuralError('missing reviewer-confirmed '+field)
    generators=Counter((row['package'],row['path'],row['item'],row['kind'],row['syntax']) for row in census['generators'])
    declared=Counter((row['package'],row['path'],row['item'],row['kind'],row['syntax']) for row in registry['generators'])
    if generators!=declared:raise StructuralError('missing or stale generator mapping')
    for generator in registry['generators']:
        if not generator.get('expansion_review') or not generator.get('boundaries') or not set(generator['boundaries'])<=set(rows):
            raise StructuralError('uninspected generated entry points')
        if generator.get('boundaries')!=classes.get(generator.get('class_decision'),{}).get('operations'):
            raise StructuralError('generator does not inherit its complete class operation set')
    return {'operations':len(rows),'by_package':dict(Counter(row['package'] for row in rows.values())),
            'instrumented':sum(row['mode']=='instrumented' for row in rows.values()),
            'exceptions':sum(row['mode']=='exception' for row in rows.values()),'generators':sum(generators.values()),
            'mechanical_status':'passed','semantic_status':'reviewer-confirmed; not mechanical proof'}


def command(argv, **kwargs):
    started=time.monotonic()
    result=subprocess.run(argv,capture_output=True,text=True,**kwargs)
    print(f'OBSERVE-COMMAND {argv[0]} status={result.returncode} wall_seconds={time.monotonic()-started:.6f}',file=sys.stderr)
    if result.returncode: raise StructuralError(result.stderr)
    return result.stdout


def syntax_census():
    metadata=json.loads(command(['cargo','metadata','--offline','--locked','--no-deps','--format-version','1']))
    roots=[]
    for package in metadata['packages']:
        path=Path(package['manifest_path']).relative_to(Path.cwd()).parent
        if path.parts[0]!='packages':continue
        if path.name in {'testkit','verification'}:continue
        for target in package['targets']:
            if not set(target['kind']) & {'lib','bin'}:continue
            roots.append(dict(package=package['name'],owner=OWNERS[path.name],path=str(Path(target['src_path']).relative_to(Path.cwd()))))
    cfg=command(['rustc','--print','cfg']).splitlines()
    request=dict(roots=roots,cfg=cfg)
    output=command(['cargo','run','--offline','--locked','--profile','gate','-q','-p','cli-common','--example','observe_census'],input=json.dumps(request))
    result=json.loads(output)
    result['source']=source_id()
    result['declared_configuration']='seven production packages, host target, default and no-default features; development-only pn-testkit, pn-verification and records test-support are outside this production configuration'
    for package in metadata['packages']:
        admitted={'cli-common':{'observation-test-hook':[]},'pn-records':{'test-support':[]},'pn-host':{'default':[],'development-network':['dep:pn-wallet']},'pn-wallet':{'default':[],'fuzzing':[]}}
        if package['id'] in metadata['workspace_members'] and '/packages/' in package['manifest_path'] and package['features'] and package['features']!=admitted.get(package['name']):
            raise StructuralError('new first-party feature configuration requires census admission')
    return result


def operation_vocabulary(registry):
    return sorted({row['operation'] for row in registry['operations'] if row['package']=='pn-records' and row['mode']=='instrumented'})


def operation_source(registry):
    values=operation_vocabulary(registry)
    return '// Generated from ci/observation-registry.json by ci/observe.py --write-operation-vocabulary.\n'+'pub(super) const RECORDS_OPERATIONS: [&str; '+str(len(values))+'] = [\n'+''.join('    '+json.dumps(value)+',\n' for value in values)+'];\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--census-only',action='store_true')
    parser.add_argument('--write-operation-vocabulary',action='store_true')
    args=parser.parse_args()
    raw_registry=json.loads(Path('ci/observation-registry.json').read_text())
    vocabulary_path=Path('packages/cli-common/src/observation_operations.rs')
    if args.write_operation_vocabulary:
        vocabulary_path.write_text(operation_source(raw_registry))
        return 0
    try:
        if vocabulary_path.read_text()!=operation_source(raw_registry):
            raise StructuralError('operation vocabulary differs from registry; regenerate with --write-operation-vocabulary')
        data=syntax_census()
        Path('.lane/observation-syntax.json').write_text(json.dumps(data,indent=2)+'\n')
        if not args.census_only:
            from claims import prose, site_claim
            from source_sites import census as sites
            labels,_=prose('.')
            claims={site_claim(site)['claim'] for site in sites(Path('.'))}
            registry=expand_registry(json.loads(Path('ci/observation-registry.json').read_text()),data)
            result=validate(data,registry,set(labels)|claims,claims)
            Path('.lane/observation-registry-expanded.json').write_text(json.dumps(registry,indent=2,ensure_ascii=False)+'\n')
            summary=[]
            for package in sorted(result['by_package']):
                modes=Counter(row['mode'] for row in registry['operations'] if row['package']==package)
                summary.append(dict(name=package,operations=result['by_package'][package],instrumented=modes['instrumented'],exceptions=modes['exception'],helpers=modes['reviewed-helper'],generators=sum(row['package']==package for row in registry['generators'])))
            if tomllib.loads(Path('docs/inputs/observe-coverage.toml').read_text())['rows']!=summary:
                raise StructuralError('rendered operation census declaration differs')
            Path('.lane/observation-coverage.json').write_text(json.dumps({'source':data['source'],**result},indent=2)+'\n')
            print('OBSERVATION-COVERAGE '+json.dumps(result,sort_keys=True))
        print(f'OBSERVATION-SYNTAX functions={len(data["functions"])} generators={len(data["generators"])} artifact=.lane/observation-syntax.json')
        return 0
    except (ValueError,KeyError,TypeError,OSError) as error:
        print('OBSERVATION-STRUCTURAL-ERROR '+str(error),file=sys.stderr)
        return 2


if __name__=='__main__':sys.exit(main())
