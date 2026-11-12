"""Claim area devperf: timing observations preserve execution predicates.

Python claim sites follow the authored gloss/claim/test form; the deployed
linter does not yet scan Python. These are local test inventory labels.
"""

import copy
import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from devperf import StructuralError, assess, assessment, budgets, inclusive_ms, report, utc
from harness import CONFIGURATION
from test_harness import declarations, fixture
import run_tests


def execution(duration=1, outcome='passed'):
    return dict(operation='probe', budget='unit', duration_ms=duration,
                outcome=outcome, source='controlled fixture', configuration='injected duration',
                owner='foundation implementer')


def inventory_fixture(kind='lib', location='src/lib.rs'):
    inventory = {'rust-suites': {'example': {'package-name': 'example', 'binary-name': 'example',
                 'package-id': 'example', 'kind': kind, 'testcases': {'case': {'ignored': False}}}}}
    metadata = {'packages': [{'id': 'example', 'manifest_path': '/fixture/Cargo.toml',
                 'targets': [{'name': 'example', 'kind': [kind], 'src_path': '/fixture/' + location}]}]}
    return inventory, metadata


def written_peer(source='fixture', cpu=100, stall=.05, extra=0, instructions=None, serialized=()):
    """Feed controlled observations through the production tier record writer."""
    from contextlib import redirect_stdout
    from build_graph import tier_summary
    tiers = {'service':dict(steps=['service'], invocation_budget='fixture'),
             'fast':dict(steps=['fast'], finalize_steps=['finalize'], invocation_budget='fixture')}
    names = ['service', 'fast', 'finalize']
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); lane = root/'.lane'; lane.mkdir()
        for name in names:
            own = cpu if name == 'service' else 0
            count = str(instructions) if instructions is not None else 'unavailable'
            (lane/f'gate-{name}.log').write_text(f'OWN-TIME user={own} sys=0\nGATE-INSTRUCTIONS step={name} retired={count}\n')
            (lane/f'gate-{name}-setup.jsonl').write_text('')
        (lane/'gate-steps.tsv').write_text(''.join(f'{name}\t0\t0\t1\n' for name in names))
        cases = [('common',0)]+([('extra',extra)] if extra else [])
        (lane/'performance-events.jsonl').write_text(''.join(json.dumps(dict(scope='case', operation=name,
            step='service', outcome='passed', own_user_s=cost, own_sys_s=0))+'\n' for name,cost in cases))
        registry = SimpleNamespace(tiers=tiers, producing_step=lambda _: 'service')
        policy = dict(load_unresolved_pressure_percent=10, cpu_growth_percent=20, rebuild_steps=list(serialized))
        with patch('devperf.budgets', return_value={'fixture':dict(budget_ms=2000),'gate':policy}), \
                patch('build_graph.baseline_context', return_value=(lane/'baseline.json',None,[],lane)), \
                patch('harness.build_cache_state', return_value=dict(state='warm',compiling_steps=[])), \
                patch('gate_resources.raw_sample', return_value={'epoch_seconds':0}), \
                patch('gate_resources.joined', return_value={'node_scope':'node-wide','node_pressure_fraction':{'cpu.some':stall}}), \
                patch('gate_resources.compact', return_value='fixture'), \
                patch('build_graph.subprocess.run', return_value=SimpleNamespace(returncode=0,stdout=source)), \
                patch.dict(os.environ, PN_GATE_SOURCE=source, PN_BUILDGRAPH_RUN='fixture-run', PN_IMPORT_BASE='fixture-base'), \
                redirect_stdout(io.StringIO()):
            tier_summary(root, registry, dict.fromkeys(names,0))
        result = json.loads((lane/'gate-baseline.json').read_text())
        # Whole-run observations are not step figures or the projection.
        result['whole'] = dict(node_scope='node-wide',stall=stall,wall=1,own_user_s=cpu,own_sys_s=0)
        return result


def series_records():
    """One complete synthetic series; membership fields mirror receipt joins."""
    rows=[]
    for ordinal in range(1,6):
        entry='sample-'+str(ordinal)
        declaration=dict(plan='one-run',series='fixture',ordinal=str(ordinal),count='5',entry=entry,base='base',source='source',configuration_key='a'*64,cache='warm')
        identity=dict(PN_GATE_SERIES='fixture',PN_GATE_ORDINAL=str(ordinal),PN_GATE_ENTRY=entry)
        rows.append(dict(declaration=declaration,tree='tree',run=entry,status='complete',observed_key='a'*64,observed_cache='warm',
            host_idle_start=dict(identity=identity,boundary='start',at=ordinal*10,processes=dict(status=0,stdout=''),containers=dict(status=0,stdout='[]'),services=dict(status=0,stdout='[]')),host_idle_end=dict(identity=identity,boundary='end',at=ordinal*10+1,processes=dict(status=0,stdout=''),containers=dict(status=0,stdout='[]'),services=dict(status=0,stdout='[]')),whole=dict(stall=.05,status=0),
            compiled=dict(primary=[],lint=[]),changed_files={'input':ordinal*10-1},comparison=written_peer(cpu=100+ordinal,stall=.05),
            owners=[dict(base='base',source='source',run=entry,cold_target=False,layout_changed=False)]))
    return rows

def check_series_records(records, statuses=None, ledger_change=None, archive_change=None, plans=None):
    """Archive every supplied attempt through the terminal receipt writer."""
    from build_graph import series_close, series_check
    from contextlib import redirect_stdout
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory); archive=root/'archive';archive.mkdir()
        ledger_rows=[]
        for index,row in enumerate(records):
            entry=row['declaration']['entry']
            work=root/('work'+str(index));lane=work/'.lane';lane.mkdir(parents=True)
            for name,value in [('gate-series-host-start',row['host_idle_start']),('gate-series-host-end',row['host_idle_end']),
                               ('gate-series-end',row),('gate-declaration',row['declaration'])]:
                (lane/(name+'.json')).write_text(json.dumps(value))
            with redirect_stdout(io.StringIO()):
                series_close(work, 0 if statuses is None else statuses[index])
            ledger_rows.append(dict(series='fixture',entry=entry,ordinal=int(row['declaration']['ordinal']),
                gate_status=0 if statuses is None else statuses[index],close_status=0,archive_status=0,
                declared_identity=dict(base='base',source='source',configuration_key='a'*64,cache='warm'),
                start=row['host_idle_start']['at']))
            destination=archive/entry;destination.mkdir()
            (destination/'series-attempt.json').write_bytes((lane/'series-attempt.json').read_bytes())
        output=io.StringIO()
        ledger_rows.sort(key=lambda x:x['start'])
        if ledger_change is not None:ledger_change(ledger_rows)
        ledger=root/'ledger.jsonl';ledger.write_text(''.join(json.dumps(x)+'\n' for x in ledger_rows))
        if archive_change is not None:archive_change(archive)
        plan_path=root/'plans.jsonl'
        if plans is not None:plan_path.write_text(''.join(json.dumps(x)+'\n' for x in plans))
        with redirect_stdout(output):status=series_check('fixture',archive,ledger,plan_path if plans is not None else None)
        return status,json.loads(output.getvalue().split(' ',1)[1])


def later_series_attempt(row, index, pressure=None):
    row=copy.deepcopy(row);entry='attempt-'+str(index)
    row['declaration']['entry']=entry;row['run']=entry
    for boundary in ('start','end'):
        row['host_idle_'+boundary]['identity']['PN_GATE_ENTRY']=entry
        row['host_idle_'+boundary]['at']=index*10+(boundary=='end')
    row['changed_files']={'input':index*10-1}
    for owner in row['owners']:owner['run']=entry
    if pressure is not None:row['whole']['stall']=pressure
    return row


class Performance(unittest.TestCase):
    def setUp(self):
        import io
        from contextlib import redirect_stdout
        if self._testMethodName == 'test_gate_cancel_cleanup':
            return
        self.fixture_output = io.StringIO()
        self.fixture_capture = redirect_stdout(self.fixture_output)
        self.fixture_capture.__enter__()

    def tearDown(self):
        if self._testMethodName == 'test_gate_cancel_cleanup':
            return
        self.fixture_capture.__exit__(None,None,None)
        for line in self.fixture_output.getvalue().splitlines():
            print('TEST-FIXTURE '+line)


    def test_series_battery_patterns(self):
        """Every declared battery process family refuses an idle observation outside the collector ancestry.
        ´claim:devperf:series-battery-patterns´
        ´test:integration:test-series-battery-patterns´
        """
        from build_graph import series_idle_refusal,series_ledger
        commands=['ci/gate.sh','ci/precheck.py','ci/run_ci.py','ci/run_tests.py','cargo test','cargo nextest','cargo build','cargo check','cargo clippy','cargo fmt','cargo-nextest','focus.py','battery.py','test_fixture.py','fixture-node.py','fixture_probe.py','python3 -m unittest']
        for command in commands:
            idle=copy.deepcopy(series_records()[0]['host_idle_start']);idle['processes']['stdout']='123 1 '+command
            self.assertEqual(series_idle_refusal(idle),'other account battery at boundary','battery family refuses: '+command)
            idle['collector_ancestors']=[123]
            self.assertIsNone(series_idle_refusal(idle),'collector ancestor alone is exempt: '+command)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'ledger'
            for text in ('not-json\n',json.dumps(dict(series='fixture',entry='one',ordinal=6,gate_status=0,close_status=0,archive_status=0,declared_identity=dict(base='base',source='source',configuration_key='a'*64,cache='warm')))):
                path.write_text(text)
                with self.assertRaises(ValueError,msg='malformed or out-of-count ledger refuses'):
                    series_ledger('fixture',path)
            path.write_text('\n  \n')
            try:empty=series_ledger('fixture',path)
            except ValueError as error:self.fail('blank ledger lines must be ignored: '+str(error))
            self.assertEqual(empty,{},'blank ledger lines are ignored, never attempts')
        status,result=check_series_records(series_records())
        self.assertEqual(result['evidence_strength']['changed_files'],'observed-surviving-files','surviving-file branch names its evidence')

    def test_series_plan_join(self):
        """An optional independent plan record exposes missing attempts and refuses mismatched timing or ordinals.
        ´claim:devperf:series-plan-join´
        ´test:integration:test-series-plan-join´
        """
        plans=[dict(series='fixture',entry='sample-'+str(n),ordinal=n,start=n*10-1) for n in range(1,6)]
        self.assertEqual(check_series_records(series_records(),plans=plans)[0],0,'matching third record admits')
        extra=dict(series='fixture',entry='missing',ordinal=1,start=0)
        with self.assertRaisesRegex(ValueError,'planned attempt missing',msg='omitted archive and ledger attempt remains visible in plans'):
            check_series_records(series_records(),plans=[extra,*plans])
        for key,value in [('ordinal',2),('start',11)]:
            bad=copy.deepcopy(plans);bad[0][key]=value
            with self.assertRaisesRegex(ValueError,'plan ordinal or start',msg='plan join refuses '+key):
                check_series_records(series_records(),plans=bad)
        bad=copy.deepcopy(plans);bad[0]['start']=float('nan')
        with self.assertRaisesRegex(ValueError,'malformed',msg='plan start must be finite'):
            check_series_records(series_records(),plans=bad)
        for name,kwargs in [('plan',dict(plans=[[]])),('ledger',dict(ledger_change=lambda rows:rows.__setitem__(0,[])))]:
            try:check_series_records(series_records(),**kwargs)
            except ValueError:pass
            except Exception as error:self.fail(name+' non-object must have a protocol refusal: '+str(error))
            else:self.fail(name+' non-object was admitted')

    def test_series_policy_standing(self):
        """Sampling proposals have loader-checked boolean standing and expose their values and cap.
        ´claim:devperf:series-policy-standing´
        ´test:integration:test-series-policy-standing´
        """
        from build_graph import series_policy
        from devperf import budgets, StructuralError
        policy=series_policy()
        self.assertEqual(policy,dict(series_pressure_multiple=2.,series_absolute_pressure=.1,series_relative_floor=.08,series_attempts_per_ordinal=3,provisional=True),'reader preserves exact proposed policy')
        status,result=check_series_records(series_records())
        self.assertIs(result['policy']['provisional'],True,'output names proposal standing')
        self.assertEqual(result['attempt_cap'],3,'invoker reads cap from outcome')
        source=Path('docs/inputs/devperf-budgets.toml').read_text()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'budgets.toml'
            for value in ('"proposed"','1'):
                path.write_text(source.replace('series_policy_provisional = true','series_policy_provisional = '+value))
                with self.assertRaisesRegex(StructuralError,'boolean provisional',msg='proposal standing cannot be unchecked text'):
                    budgets(path)

    def test_series_boundary_services(self):
        """Both idle boundaries refuse unreadable services and any running service except the session bus.
        ´claim:devperf:series-boundary-services´
        ´test:integration:test-series-boundary-services´
        """
        for boundary in ('start','end'):
            for kind in ('busy','missing','status','json','shape','unit'):
                rows=series_records();idle=rows[1]['host_idle_'+boundary]
                if kind=='busy':idle['services']['stdout']='[{"unit":"fixture-battery.service"}]'
                if kind=='missing':idle.pop('services')
                if kind=='status':idle['services']['status']=1
                if kind=='json':idle['services']['stdout']='not json'
                if kind=='shape':idle['services']['stdout']='{}'
                if kind=='unit':idle['services']['stdout']='[{"unit":4}]'
                status,result=check_series_records(rows)
                self.assertEqual(status,4,'both boundaries refuse services: '+boundary+' '+kind)
                self.assertIn(boundary+' ',result['excluded'][0]['reason'],'service refusal names boundary')
                if kind in ('unit','shape'):
                    self.assertIn('malformed',result['excluded'][0]['reason'],'malformed unit data is not a busy service')
            for kind in ('process','container'):
                rows=series_records();idle=rows[1]['host_idle_'+boundary]
                if kind=='process':idle['processes']['stdout']='123 1 python3 ci/precheck.py'
                else:idle['containers']['stdout']='["other"]'
                self.assertEqual(check_series_records(rows)[0],4,'both boundaries refuse '+kind)
        rows=series_records()
        for row in rows:
            for boundary in ('start','end'):
                row['host_idle_'+boundary]['services']['stdout']='[{"unit":"dbus-broker.service"},{"unit":"dbus.service"}]'
        self.assertEqual(check_series_records(rows)[0],0,'session bus alone does not make a battery')

    def test_series_idle_writer(self):
        """The idle writer retains declared service commands, failed observations and the actual ancestor chain.
        ´claim:devperf:series-idle-writer´
        ´test:integration:test-series-idle-writer´
        """
        from build_graph import series_idle
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            env=dict(PN_GATE_SERIES='fixture',PN_GATE_ORDINAL='1',PN_GATE_ENTRY='entry',PN_GATE_CONTAINER_LIST='["containers"]',PN_GATE_SERVICE_LIST='["services","--json"]')
            def observed(argv,**kwargs):
                content='100 90 collector\n90 80 wrapper\n80 1 supervisor\n1 0 init\n' if argv[0]=='ps' else '[]'
                return SimpleNamespace(returncode=0,stdout=content,stderr='')
            with patch.dict(os.environ,env),patch('build_graph.os.getpid',return_value=100),patch('build_graph.subprocess.run',side_effect=observed) as calls:
                series_idle(root,'start')
            row=json.loads((root/'.lane/gate-series-host-start.json').read_text())
            self.assertEqual(row['collector_ancestors'],[100,90,80,1,0],'writer walks every parent exactly once')
            self.assertEqual(row['service_command'],['services','--json'],'writer retains service argv')
            self.assertEqual(calls.call_args_list[-1].args[0],['services','--json'],'writer runs declared service argv')
            self.assertEqual(row['services']['stdout'],'[]','writer retains service observation')
            with patch.dict(os.environ,env),patch('build_graph.subprocess.run',side_effect=OSError('unavailable')):
                series_idle(root,'end')
            row=json.loads((root/'.lane/gate-series-host-end.json').read_text())
            self.assertEqual(row['services']['status'],'unavailable','failed service listing is recorded, not lost')
            with patch.dict(os.environ,env),patch.dict(os.environ,PN_GATE_SERVICE_LIST='null'):
                with self.assertRaisesRegex(ValueError,'SERVICE_LIST',msg='missing command is a typed refusal'):
                    series_idle(root,'end')

    def test_series_declared_ledger_identity(self):
        """Every attempt is checked against the ledger declaration before it can anchor the label.
        ´claim:devperf:series-declared-ledger-identity´
        ´test:integration:test-series-declared-ledger-identity´
        """
        rows=series_records()
        for key,value in [('base','foreign'),('source','foreign'),('configuration_key','b'*64),('cache','cold')]:
            bad=copy.deepcopy(rows);first=bad[0];first['declaration'][key]=value
            if key in ('base','source'):first['owners'][0][key]=value
            if key=='configuration_key':first['observed_key']=value
            if key=='cache':first['observed_cache']=value
            replacement=later_series_attempt(rows[0],6)
            status,result=check_series_records([*bad,replacement])
            self.assertEqual(status,0,'foreign first attempt cannot poison declared '+key)
            self.assertEqual(result['selected']['1'],'attempt-6','correct replacement anchors declared identity')
            self.assertIn('ledger declared identity',result['excluded'][0]['reason'],'external declaration decides the refusal')
        for kind in ('missing','shape','cache','key','inconsistent'):
            def change(ledger):
                if kind=='missing':ledger[0].pop('declared_identity')
                if kind=='shape':ledger[0]['declared_identity']=[]
                if kind=='cache':
                    for row in ledger:row['declared_identity']['cache']='unknown'
                if kind=='key':
                    for row in ledger:row['declared_identity']['configuration_key']='not-key'
                if kind=='inconsistent':ledger[1]['declared_identity']['base']='different'
            with self.assertRaisesRegex(ValueError,'declared identity',msg='malformed or inconsistent ledger refuses '+kind):
                check_series_records(rows,ledger_change=change)
        # The first structurally valid loaded attempt anchors identity, never the median.
        first=copy.deepcopy(rows);first[0]['whole']['stall']=.2
        status,result=check_series_records([*first,later_series_attempt(rows[0],6,.05)])
        self.assertEqual(status,0,'loaded valid first attempt does not enter median')
        self.assertEqual(result['frozen_median'],.05,'median excludes the loaded anchor')
        first[0]['compiled']['primary']=['anchor-artifact']
        status,result=check_series_records([*first,later_series_attempt(rows[0],6,.05)])
        self.assertEqual(status,4,'loaded structurally valid anchor still fixes compiled sets')
        self.assertTrue(any('compiled sets differ' in row['reason'] for row in result['excluded']),'later sets cannot silently replace a loaded anchor')

    def test_series_membership(self):
        """Series membership checks every terminal attempt and selects the first admissible one.
        ´claim:devperf:series-membership´
        ´test:integration:test-series-membership´
        """
        rows=series_records()
        status,result=check_series_records(rows)
        self.assertEqual(status,0,'complete series admits')
        self.assertEqual(len(result['pairs']),10,'retain every two-way common-work spread with its stalls')
        self.assertTrue(all(pair['stalls']==[.05,.05] and pair['common_work_cpu_s'] is not None for pair in result['pairs']),'pair evidence uses writer records')
        for key,value in [('base','foreign'),('source','foreign'),('configuration_key','b'*64),('cache','cold'),('count','6')]:
            bad=copy.deepcopy(rows);bad[1]['declaration'][key]=value
            status,result=check_series_records(bad)
            self.assertEqual(status,4,'identity mismatch refuses '+key)
            self.assertIn('disagree',result['excluded'][0]['reason'],'identity refusal is named')
        status,result=check_series_records(rows[:-1])
        self.assertEqual(status,4,'missing ordinal is incomplete')
        self.assertIn(5,result['repeat_ordinals'],'missing ordinal is named')
        for boundary in ('start','end'):
            bad=copy.deepcopy(rows);bad[1]['host_idle_'+boundary]['boundary']='foreign'
            status,result=check_series_records(bad)
            self.assertEqual(status,4,'foreign idle boundary refuses')
            self.assertIn('both bound',result['excluded'][0]['reason'],'idle refusal is named')
        # The directory is populated out of chronological order.
        later=later_series_attempt(rows[0],6,.01)
        status,result=check_series_records([later,*reversed(rows)])
        self.assertEqual(status,0,'archive enumeration cannot change recorded attempt order')
        self.assertEqual(result['selected']['1'],'sample-1','quieter later success cannot replace first success')
        self.assertEqual(result['excluded'][0]['reason'],'earlier attempt admitted','unused attempt reason names first success')
        bad=copy.deepcopy(rows);bad[0]['whole']['status']=1
        status,result=check_series_records([*bad,later])
        self.assertEqual(result['selected']['1'],'attempt-6','red first attempt permits replacement')
        self.assertEqual(result['excluded'][0]['reason'],'functional gate was not green','red is a named refusal')
        for corruption in ('cache','partial','times'):
            bad=copy.deepcopy(rows)
            if corruption=='cache':
                bad[0]['declaration']['cache']='cold';bad[0]['status']='refused-identity'
            elif corruption=='partial':
                bad[0]['compiled']['primary']=['partial'];bad[0]['whole']['status']=1
            else:
                bad[0]['changed_files']['input']=bad[0]['host_idle_start']['at']+1
            status,result=check_series_records([*bad,later])
            self.assertEqual(status,0,'refused first receipt cannot poison identity: '+corruption)
            self.assertEqual(result['selected']['1'],'attempt-6','correct replacement completes identity')
        for field,value in [('plan','refresh-first'),('source','base')]:
            bad=copy.deepcopy(rows)
            for row in bad:row['declaration'][field]=value
            status,result=check_series_records(bad)
            self.assertEqual(status,4,'invalid sample declaration refuses '+field)
        for field,value in [('gate_status',1),('close_status',1),('archive_status',1),('gate_status',False),('ordinal',2),('entry','foreign'),('series','foreign')]:
            def change(ledger,field=field,value=value):ledger[0][field]=value
            with self.assertRaises(ValueError,msg='ledger disagreement refuses '+field):
                check_series_records(rows,ledger_change=change)
        with self.assertRaisesRegex(ValueError,'archive entry',msg='directory without ledger refuses'):
            check_series_records(rows,ledger_change=lambda ledger:ledger.pop())
        def omitted(ledger):
            ledger.append(dict(ledger[-1],entry='missing',ordinal=1))
        with self.assertRaisesRegex(ValueError,'missing from archive',msg='ledger without directory refuses'):
            check_series_records(rows,ledger_change=omitted)
        with self.assertRaisesRegex(ValueError,'order',msg='ledger order must match receipts'):
            check_series_records(rows,ledger_change=lambda ledger:ledger.reverse())
        for change in ('battery','container','listing','process-status','malformed-json','container-shape','process-shape'):
            bad=copy.deepcopy(rows);idle=bad[1]['host_idle_end']
            if change=='battery':idle['processes']['stdout']='123 1 python3 ci/precheck.py'
            if change=='container':idle['containers']['stdout']='["other"]'
            if change=='listing':idle['containers']['status']=1
            if change=='process-status':idle['processes']['status']=1
            if change=='malformed-json':idle['containers']['stdout']='not json'
            if change=='container-shape':idle['containers']['stdout']='{}'
            if change=='process-shape':idle['processes']['stdout']='not ps fields'
            status,result=check_series_records(bad)
            self.assertEqual(status,4,'end observation refuses '+change)
        own=copy.deepcopy(rows)
        own[0]['host_idle_end']['processes']['stdout']='123 1 python3 ci/precheck.py'
        own[0]['host_idle_end']['collector_ancestors']=[123]
        status,result=check_series_records(own)
        self.assertEqual(status,0,'collector ancestor chain is not another battery')
        status,result=check_series_records([*rows,later],[4,0,0,0,0,0])
        self.assertEqual(result['selected']['1'],'attempt-6','protocol refusal permits replacement')

    def test_series_structural_refusals(self):
        """Series archive structure refuses malformed identity, ordering and terminal evidence.
        ´claim:devperf:series-structural-refusals´
        ´test:integration:test-series-structural-refusals´
        """
        edits=[('foreign-label',lambda a:a['identity'].update(PN_GATE_SERIES='other')),
               ('entry-name',lambda a:a['identity'].update(PN_GATE_ENTRY='other')),
               ('ordinal',lambda a:a['identity'].update(PN_GATE_ORDINAL='0')),
               ('times',lambda a:a.update(ended=a['started']-1)),
               ('exit-type',lambda a:a.update(exit_status='0')),
               ('tied-start',lambda a:a.update(started=10))]
        for name,edit in edits:
            def change(archive,edit=edit):
                path=archive/'sample-2/series-attempt.json';data=json.loads(path.read_text());edit(data);path.write_text(json.dumps(data))
            with self.subTest(refusal=name),self.assertRaises(ValueError,msg='structural refusal '+name):
                check_series_records(series_records(),archive_change=change)
        def nondirectory(archive):(archive/'extra').write_text('not an entry')
        with self.assertRaisesRegex(ValueError,'non-entry',msg='archive files cannot masquerade as entry directories'):
            check_series_records(series_records(),archive_change=nondirectory)
        def overlap(archive):
            path=archive/'sample-2/series-attempt.json';data=json.loads(path.read_text());data['started']=10.5;path.write_text(json.dumps(data))
        status,result=check_series_records(series_records(),archive_change=overlap)
        self.assertEqual(status,4,'overlapping attempts refuse membership')
        self.assertTrue(any('overlap' in x['reason'] for x in result['excluded']),'overlap is named')
        def mismatch(archive):
            path=archive/'sample-2/series-attempt.json';data=json.loads(path.read_text());data['declaration']['source']='other';path.write_text(json.dumps(data))
        status,result=check_series_records(series_records(),archive_change=mismatch)
        self.assertEqual(status,4,'terminal and measurement declarations must agree')
        self.assertTrue(any('measurement disagree' in x['reason'] for x in result['excluded']),'disagreement is named')
        with self.assertRaisesRegex(ValueError,'duplicate',msg='duplicate ledger entry refuses'):
            check_series_records(series_records(),ledger_change=lambda rows:rows.append(rows[0]))

    def test_series_owner_targets(self):
        """Series membership refuses cold, swept and foreign owner targets.
        ´claim:devperf:series-owner-targets´
        ´test:integration:test-series-owner-targets´
        """
        for key,value in [('cold_target',True),('layout_changed',True),('cold_target',None),('run','foreign'),('base','foreign')]:
            rows=series_records();rows[1]['owners'][0][key]=value
            status,result=check_series_records(rows)
            self.assertEqual(status,4,'every owner retains its primed target: '+key)
            self.assertIn('owner target',result['excluded'][0]['reason'],'owner refusal is named')

    def test_series_outliers(self):
        """Series pressure uses an absolute bound, a frozen median and a finite attempt cap.
        ´claim:devperf:series-outliers´
        ´test:integration:test-series-outliers´
        """
        from build_graph import series_policy
        SERIES_POLICY = series_policy()
        for pressure,status,ceiling in ((.1,0,.1),(.224,4,None)):
            rows=series_records();rows[-1]['whole']['stall']=pressure
            actual,result=check_series_records(rows)
            self.assertEqual(actual,status,'pressure above a bound requires a replacement')
            self.assertEqual(result['ceiling'],ceiling,'refused pressure cannot set ceiling')
        rows=series_records()
        for row in rows:row['whole']['stall']=.2
        status,result=check_series_records(rows)
        self.assertEqual(status,4,'uniformly loaded set refuses')
        self.assertTrue(all(r['reason']=='absolute pressure bound' for r in result['excluded']),'absolute bound applies independently')
        for row,pressure in zip(rows,[.03,.03,.07,.07,.2]):row['whole']['stall']=pressure
        replacement=later_series_attempt(rows[-1],6,.03)
        status,result=check_series_records([replacement,*rows])
        self.assertEqual(status,0,'absolute refusal cannot poison the median or refuse quiet-range samples')
        self.assertEqual(result['frozen_median'],.03,'first absolute-admitted complete set fixes median')
        self.assertEqual(result['ceiling'],.07,'upper quiet-range samples remain admitted')
        low=series_records()
        for row in low:row['whole']['stall']=.02
        low[-1]['whole']['stall']=.09
        status,result=check_series_records(low)
        self.assertEqual(status,4,'relative outlier below absolute bound still refuses')
        self.assertEqual(result['excluded'][0]['reason'],'frozen median pressure bound','relative bound has its own refusal')
        low[-1]['whole']['stall']=.08
        status,result=check_series_records(low)
        self.assertEqual(status,0,'relative floor admits upper observed quiet range')
        self.assertEqual(result['frozen_median'],.02,'floor does not alter frozen median')
        rows=series_records();rows[0]['whole']['stall']=.2
        for index in range(6,6+SERIES_POLICY['series_attempts_per_ordinal']-1):
            rows.append(later_series_attempt(rows[0],index,.2))
        status,result=check_series_records(rows)
        self.assertEqual(result['outcome'],'exhausted','finite failed attempts exhaust the ordinal')
        self.assertEqual(status,4,'exhausted outcome has protocol exit four')
        rows.append(later_series_attempt(rows[0],10,.01))
        with self.assertRaisesRegex(ValueError,'cap exceeded',msg='attempt beyond cap cannot enter'):
            check_series_records(rows)

    def test_series_reset_evidence(self):
        """Series receipts require the same compiler sets and a new transition after each attempt.
        ´claim:devperf:series-reset-evidence´
        ´test:integration:test-series-reset-evidence´
        """
        rows=series_records()
        for change,reason in [('compiled','compiled sets'),('changed_files','not reset')]:
            bad=copy.deepcopy(rows)
            if change=='compiled':bad[1]['compiled']['primary']=['different']
            else:bad[1]['changed_files']['input']=bad[0]['host_idle_end']['at']
            status,result=check_series_records(bad)
            self.assertEqual(status,4,'reset evidence refuses '+change)
            self.assertIn(reason,result['excluded'][0]['reason'],'reset refusal identifies evidence')
        for kind in ('future','file-set'):
            bad=copy.deepcopy(rows)
            if kind=='future':bad[1]['changed_files']['input']=21
            else:bad[1]['changed_files']={'other':19}
            status,result=check_series_records(bad)
            self.assertEqual(status,4,'reset evidence refuses '+kind)
        for row in rows:row['changed_files']={}
        status,result=check_series_records(rows)
        self.assertEqual(result['evidence_strength']['compiled_sets'],'empty-equality-only','empty compiler evidence is named')
        self.assertEqual(result['evidence_strength']['changed_files'],'empty-no-reset-witness','deletion-only evidence is named')
        self.assertEqual(result['evidence_strength']['base_build'],'invoker-assertion-not-detected','reset cannot prove base build')
        bad=copy.deepcopy(rows);bad[1]['whole']['stall']=float('nan')
        status,result=check_series_records(bad)
        self.assertEqual(status,4,'nonfinite pressure refuses')
        self.assertIn('pressure',result['excluded'][0]['reason'],'pressure refusal is named')


    def test_series_terminal_attempt(self):
        """Terminal attempts preserve interrupted runs and refuse an unclosed entry.
        ´claim:devperf:series-terminal-attempt´
        ´test:integration:test-series-terminal-attempt´
        """
        from build_graph import series_idle, series_close, series_check
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);lane=root/'.lane';lane.mkdir()
            identity=dict(PN_GATE_SERIES='fixture',PN_GATE_ORDINAL='1',PN_GATE_ENTRY='entry')
            (lane/'gate-series-host-start.json').write_text(json.dumps(dict(identity=identity,at=1)))
            with patch.dict(os.environ,**identity,PN_GATE_CONTAINER_LIST='["fixture-list"]',PN_GATE_SERVICE_LIST='["fixture-services"]'),patch('build_graph.subprocess.run',side_effect=[SimpleNamespace(stdout='',stderr='',returncode=0),SimpleNamespace(stdout='[]',stderr='',returncode=0),SimpleNamespace(stdout='[]',stderr='',returncode=0)]):
                series_idle(root,'end')
            archived=root/'saved';archived.mkdir()
            for path in lane.iterdir():(archived/path.name).write_bytes(path.read_bytes())
            saved=json.loads((archived/'gate-series-host-end.json').read_text())
            for change in ('identity','time'):
                bad=copy.deepcopy(saved)
                if change=='identity':bad['identity']['PN_GATE_ENTRY']='foreign'
                else:bad['at']=0
                (archived/'gate-series-host-end.json').write_text(json.dumps(bad))
                with self.assertRaisesRegex(ValueError,'identities or times',msg='close refuses '+change):series_close(root,124,archived)
            (archived/'gate-series-host-end.json').write_text(json.dumps(saved))
            series_close(root,124,archived)
            self.assertTrue((archived/'series-attempt.json').exists(),'archive-root selects the archived directory')
            self.assertEqual(json.loads((archived/'series-attempt.json').read_text())['exit_status'],124,'archive close works without live checkout receipts')
            with patch.dict(os.environ,**identity,PN_GATE_CONTAINER_LIST='["fixture-list"]',PN_GATE_SERVICE_LIST='["fixture-services"]'),patch('build_graph.subprocess.run',side_effect=OSError('listing failed')):
                series_idle(root,'end')
            self.assertEqual(json.loads((lane/'gate-series-host-end.json').read_text())['containers']['status'],'unavailable','failed end listing leaves a receipt')
            series_close(root,124)
            attempt=json.loads((lane/'series-attempt.json').read_text())
            self.assertIsNone(attempt['receipt'],'container failure retains an incomplete measurement')
            self.assertEqual(attempt['exit_status'],124,'container status is preserved')
            with self.assertRaisesRegex(ValueError,'already closed',msg='an attempt cannot be overwritten'):series_close(root,0)
            archive=root/'archive';(archive/'entry').mkdir(parents=True)
            (root/'ledger.jsonl').write_text('')
            with self.assertRaisesRegex(ValueError,'incomplete',msg='unclosed attempt blocks selection'):series_check('fixture',archive,root/'ledger.jsonl')
        rows=series_records()
        status,result=check_series_records(rows[:-1])
        self.assertEqual(result['repeat_ordinals'],[5],'a partial first set requests only missing ordinal')
        self.assertEqual(result['outcome'],'incomplete','median is not sized from partial samples')

    def test_series_owner_join(self):
        """The sample joins bound transitions of its invocation and never fixture log prefixes.
        ´claim:devperf:series-owner-join´
        ´test:integration:test-series-owner-join´
        """
        from build_graph import series_owners
        from isolation import bind_setup
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);lane=root/'.lane';lane.mkdir()
            declaration=dict(source='source',base='base')
            (lane/'gate-fixture.log').write_text('ISOLATION-TRANSITION {"owner":"real","base":"foreign"}\n')
            bind_setup(lane/'gate-real-setup.jsonl','source','run','step')
            path=lane/'gate-real-transitions.jsonl'
            row=dict(source='source',base='base',run='run',step='step',owner='real')
            path.write_text(json.dumps(row)+'\n')
            self.assertEqual(series_owners(root,declaration,'run'),[row],'sample reads bound transitions, not log lines')
            self.assertEqual(series_owners(root,declaration,'other'),[],'another invocation cannot borrow transitions')
            path.write_text(json.dumps(dict(row,step='foreign'))+'\n')
            with self.assertRaisesRegex(ValueError,'foreign owner',msg='foreign row in current sidecar must refuse'):series_owners(root,declaration,'run')

    def test_reference_written_identity(self):
        """Written raw measurements remain addressable and comparable when reference margins are declared.
        ´claim:devperf:reference-written-identity´
        ´test:integration:test-reference-written-identity´
        """
        from build_graph import reference_key, peer_cost, warm_peer_replacement
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'Cargo.toml').write_text('')
            registry=SimpleNamespace(tiers={})
            with patch('build_graph.subprocess.run',return_value=SimpleNamespace(stdout='compiler')):
                before=reference_key(root,registry)
                path=root/(before+'.json');path.write_text(json.dumps(written_peer('retained',100)))
                with patch.dict(os.environ, PN_GATE_REFERENCE_STALL_CEILING='.9', PN_GATE_REFERENCE_STALL_BAND='.9', PN_GATE_REFERENCE_COUNT_MARGIN='.1', PN_GATE_REFERENCE_NOISE_MARGIN='.1',PN_GATE_REFERENCE_STALL_MARGIN='.01'):
                    after=reference_key(root,registry)
                    self.assertEqual(after,before,'comparison margins never change stored measurement identity')
                    stored=json.loads((root/(after+'.json')).read_text())
                    self.assertEqual(peer_cost(stored)[1],100,'writer raw work is available after margins are declared')
                    self.assertTrue(warm_peer_replacement(written_peer('candidate',80),stored)[0],'declared margin applies to archived raw records')

    def test_series_start_key(self):
        """The current key and host start identity refuse a sample before any step runs.
        ´claim:devperf:series-start-key´
        ´test:integration:test-series-start-key´
        """
        from build_graph import series_receipt
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);lane=root/'.lane';lane.mkdir()
            declaration=series_records()[0]['declaration'];declaration['sample']='import-transition'
            (lane/'gate-declaration.json').write_text(json.dumps(declaration))
            (lane/'instructions-probe.json').write_text('{}')
            idle=series_records()[0]['host_idle_start']
            (lane/'gate-series-host-start.json').write_text(json.dumps(idle))
            with patch.dict(os.environ,PN_BUILDGRAPH_RUN='run'),patch('harness.load'),patch('build_graph.subprocess.check_output',side_effect=lambda argv,**kw: '' if argv[1]=='diff' else 'tree'),patch('build_graph.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')):
                with patch('build_graph.reference_key',return_value='b'*64):
                    with self.assertRaisesRegex(ValueError,'key differs at start',msg='wrong key refuses before work'):series_receipt(root,'start')
                idle['identity']['PN_GATE_ENTRY']='foreign';(lane/'gate-series-host-start.json').write_text(json.dumps(idle))
                with patch('build_graph.reference_key',return_value='a'*64):
                    with self.assertRaisesRegex(ValueError,'another invocation',msg='foreign host receipt refuses before work'):series_receipt(root,'start')

    def test_series_written_observations(self):
        """Series writers preserve changed-file times and the primary and lint compiled sets.
        ´claim:devperf:series-written-observations´
        ´test:integration:test-series-written-observations´
        """
        from build_graph import series_receipt
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);lane=root/'.lane';lane.mkdir()
            copied=root/'build_graph.py';copied.write_bytes(Path(__file__).with_name('build_graph.py').read_bytes())
            import subprocess
            command=subprocess.run([sys.executable,'-B',str(copied),'--help'],cwd=root,capture_output=True,text=True)
            self.assertEqual(command.returncode,0,'non-series copied entry needs no policy file: '+command.stderr)
            row=series_records()[0];declaration=dict(row['declaration'],sample='import-transition')
            (root/'changed').write_text('changed');os.utime(root/'changed',(123,123))
            for name,value in [('gate-declaration',declaration),('instructions-probe',{}),('gate-series-host-start',row['host_idle_start']),
                               ('gate-wall',dict(stall=.05,status=0)),
                               ('gate-baseline',dict(cache=dict(state='warm',compiled=dict(primary=['primary-artifact'],lint=[dict(package='p',target='t',kind=['lib'])])),path=str(root/('a'*64)/'tree.json')))]:
                (lane/(name+'.json')).write_text(json.dumps(value))
            def output(argv,**kw):return 'changed'+chr(0) if argv[1]=='diff' else 'tree'
            with patch.dict(os.environ,PN_BUILDGRAPH_RUN='run'),patch('harness.load'),patch('build_graph.reference_key',return_value='a'*64),patch('build_graph.subprocess.check_output',side_effect=output),patch('build_graph.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')):
                series_receipt(root,'start')
                start=json.loads((lane/'gate-series-start.json').read_text())
                self.assertEqual(start['changed_files'],{'changed':123},'writer stats the nonempty tree diff')
                os.utime(root/'changed',(456,456))
                series_receipt(root,'end')
                end=json.loads((lane/'gate-series-end.json').read_text())
                self.assertEqual(end['changed_files'],{'changed':123},'end preserves start times rather than restatting')
                self.assertEqual(end['compiled'],dict(primary=['primary-artifact'],lint=[dict(package='p',target='t',kind=['lib'])]),'end joins both compiled receipts without omission')

    def test_setup_bind_completion(self):
        """A setup binding refusal writes the step completion and failure status without running its workload.
        ´claim:devperf:setup-bind-completion´
        ´test:integration:test-setup-bind-completion´
        """
        import subprocess
        source=Path(__file__).with_name('gate.sh').read_text()
        function=source[source.index('run_step() {'):source.index('run_graph() {')]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'.lane').mkdir()
            script='set -u\nfailed=0\nstatuses=()\nsource_id=fixture\nresource_root=\nPN_GATE_PARALLEL=1\ngate_resource_sample() { :; }\npython3() { if [ "$3" = bind-setup ]; then return 2; fi; return 0; }\n'+function+'\nrun_step fixture touch ran\nprintf \'FAILED=%s\\n\' "$failed"\n'
            result=subprocess.run(['bash','-c',script],cwd=root,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,'fixture shell completes refusal reporting: '+result.stderr)
            path=root/'.lane/completed-fixture.tsv'
            self.assertTrue(path.exists(),'bind refusal must publish a completion row')
            self.assertEqual(path.read_text().split('\t')[:2],['fixture','2'],'bind status must reach scheduler')
            self.assertIn('FAILED=1',result.stdout,'bind refusal must mark the child failed')
            self.assertFalse((root/'ran').exists(),'refused binding must not run its command')

    def test_largest_tier_gap(self):
        """Tier diagnostics name the steps bordering the largest union gap despite overlapping steps.
        ´claim:devperf:largest-tier-gap´
        ´test:integration:test-largest-tier-gap´
        """
        from build_graph import largest_tier_gap
        rows=[('close',8,9),('overlap',1,3),('open',0,4),('tail',10,11)]
        self.assertEqual(largest_tier_gap(rows),dict(wall_s=4,after='open',before='close'),'largest gap uses the union frontier and names both boundaries')
        self.assertEqual(largest_tier_gap([])['wall_s'],0,'empty tier has no invented gap')

    def test_series_declaration(self):
        """Series declarations refuse missing and malformed members before printing a sample declaration.
        ´claim:devperf:series-declaration´
        ´test:integration:test-series-declaration´
        """
        from build_graph import declare_run
        invoke = declare_run
        env=dict(PN_GATE_PLAN='one-run',PN_GATE_ENTRY='entry',PN_GATE_SAMPLE='import-transition',PN_GATE_SERIES='fixture',PN_GATE_ORDINAL='1',PN_IMPORT_BASE='base',PN_GATE_SERIES_KEY='a'*64,PN_GATE_SERIES_CACHE='warm',PN_GATE_SERIES_COUNT='5')
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,env),patch('build_graph.subprocess.run',return_value=SimpleNamespace(stdout='source')),patch('isolation.import_base',return_value='source'):
            with self.assertRaisesRegex(ValueError,'base equals source',msg='equal base is not a transition'):invoke(Path(directory))
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,dict(env,PN_GATE_PLAN='refresh-first')),patch('build_graph.subprocess.run',return_value=SimpleNamespace(stdout='source')),patch('isolation.import_base',return_value='base'):
            with self.assertRaisesRegex(ValueError,'one-run',msg='series rejects paired plans'):invoke(Path(directory))

        def declare_run(root):
            try:
                return invoke(root)
            except KeyError as error:
                self.fail('missing series member needs its named refusal: '+str(error))
        valid=dict(PN_GATE_PLAN='one-run',PN_GATE_ENTRY='fixture',PN_GATE_SAMPLE='import-transition',PN_GATE_SERIES='fixture',
            PN_GATE_ORDINAL='1',PN_IMPORT_BASE='base',PN_GATE_SERIES_KEY='a'*64,PN_GATE_SERIES_CACHE='warm',PN_GATE_SERIES_COUNT='5')
        with tempfile.TemporaryDirectory() as directory:
            for key in ('PN_GATE_SERIES','PN_GATE_ORDINAL','PN_IMPORT_BASE','PN_GATE_SERIES_KEY','PN_GATE_SERIES_CACHE','PN_GATE_SERIES_COUNT'):
                env=dict(valid);env.pop(key)
                with self.subTest(missing=key),patch.dict(os.environ,env,clear=True),patch('build_graph.subprocess.run',return_value=SimpleNamespace(stdout='source')):
                    with self.assertRaisesRegex(ValueError,'series requires',msg='missing member refuses: '+key):declare_run(Path(directory))
            for key,value in [('PN_GATE_SERIES','bad name'),('PN_GATE_ORDINAL','0'),('PN_GATE_ORDINAL','6'),('PN_GATE_SERIES_COUNT','bad'),('PN_GATE_SERIES_COUNT','4'),('PN_GATE_SERIES_KEY','bad'),('PN_GATE_SERIES_CACHE','unknown')]:
                with self.subTest(key=key,value=value),patch.dict(os.environ,dict(valid,**{key:value}),clear=True),patch('build_graph.subprocess.run',return_value=SimpleNamespace(stdout='source')):
                    with self.assertRaisesRegex(ValueError,'invalid series|series count',msg='malformed member refuses: '+key):declare_run(Path(directory))

    def test_counter_receipt_refusals(self):
        """Counter wrappers with incomplete or malformed receipts fail without repeating their workload.
        ´claim:devperf:counter-receipt-refusals´
        ´test:integration:test-counter-receipt-refusals´
        """
        from build_graph import measured_command
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);lane=root/'.lane';lane.mkdir();stub=root/'counter'
            stub.chmod(0o755) if stub.exists() else None
            (lane/'instructions-probe.json').write_text(json.dumps(dict(run='run',executable=str(stub))))
            for content in ('{','{"started":true}'):
                stub.write_text('#!'+sys.executable+'\nimport sys\nfrom pathlib import Path\nargs=sys.argv[sys.argv.index("--")+1:]\nPath(args[4]).write_text('+repr(content)+')\n')
                stub.chmod(0o755)
                with patch.dict(os.environ,PN_BUILDGRAPH_RUN='run',PN_GATE_STEP='fixture'):
                    try:result=measured_command(root,[sys.executable,'-c','raise SystemExit(99)'])
                    except (ValueError,OSError) as error:self.fail('malformed receipt needs its typed refusal: '+str(error))
                self.assertEqual(result.returncode,2,'started but incomplete counter receipt must fail, never fall back')
            stub.write_text('#!'+sys.executable+'\nimport os,signal\nos.kill(os.getpid(),signal.SIGTERM)\n')
            with patch.dict(os.environ,PN_BUILDGRAPH_RUN='run',PN_GATE_STEP='fixture'):
                self.assertEqual(measured_command(root,['true']).returncode,-15,'signal-ended counter must fail without fallback')

    def test_unobserved_compilation(self):
        """Exclusive-case projection conservatively omits steps with missing or unknown compilation evidence.
        ´claim:devperf:unobserved-compilation´
        ´test:integration:test-unobserved-compilation´
        """
        from build_graph import peer_intersection
        for evidence in ('absent',None,True,False):
            old,new=written_peer(),written_peer(extra=1)
            for record in (old,new):
                figure=record['tiers']['service']['step_figures']['service']
                if evidence=='absent':figure.pop('compiled')
                else:figure['compiled']=evidence
            result=peer_intersection([old,new])
            self.assertEqual(result,[100,99] if evidence is False else [0,0],'unknown compilation omits the step and retains other common work')
        record=written_peer(serialized=('service',))
        self.assertIsNone(record['tiers']['service']['step_figures']['service']['compiled'],'unobserved dedicated build is unknown, never false')

    def test_archive_trigger(self):
        """The archive prints a CPU comparison against its warning and counts retained obsolete keys.
        ´claim:devperf:archive-trigger´
        ´test:integration:test-archive-trigger´
        """
        from build_graph import baseline_context
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'Cargo.toml').write_text('');old=root/'target/gate-baselines/old/peers';old.mkdir(parents=True)
            (old/'record.json').write_text('{}')
            registry=SimpleNamespace(tiers={})
            usage=[SimpleNamespace(ru_utime=n,ru_stime=0) for n in (0,0,100,100)]
            output=io.StringIO()
            with patch.dict(os.environ,CARGO_TARGET_DIR=str(root/'target'),PN_GATE_SOURCE='source',PN_IMPORT_BASE=''),patch('build_graph.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout='source')),patch('build_graph.resource.getrusage',side_effect=usage),redirect_stdout(output):
                baseline_context(root,registry)
            row=json.loads(next(line.split(' ',1)[1] for line in output.getvalue().splitlines() if line.startswith('GATE-ARCHIVE ')))
            self.assertIn('GATE-CONFIGURATION key=',output.getvalue(),'parallel baseline route prints its configuration key')
            self.assertEqual((row['obsolete_keys'],row['obsolete_records']),(1,1),'obsolete archives must remain visible')
            self.assertEqual(row['context_own_cpu_s'],200,'trigger measures own and waited children over baseline context')
            self.assertTrue(row['review_required'],'context alone exceeding command warning requires review')
            self.assertIn('own-cpu',row['comparison'],'trigger must compare CPU with CPU')

    def test_fixture_diagnostics(self):
        """Synthetic declaration and series diagnostics cannot masquerade as the enclosing gate's lines.
        ´claim:devperf:fixture-diagnostics´
        ´test:integration:test-fixture-diagnostics´
        """
        import subprocess
        result=subprocess.run([sys.executable,'-B','-m','unittest','test_devperf.Performance.test_whole_gate_warning'],cwd=Path(__file__).parent,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,'nested diagnostic witness must complete: '+result.stderr)
        lines=result.stdout.splitlines()
        self.assertTrue(any(line.startswith('TEST-FIXTURE GATE-SERIES ') for line in lines),'fixture lines retain their evidence with an explicit prefix')
        self.assertFalse(any(line.startswith(('GATE-DECLARED ','GATE-SERIES ')) for line in lines),'fixture records must never impersonate live prefixes')

    def test_compile_progress_forwarding(self):
        """The isolation meter detects compiler progress and forwards every observed output byte.
        ´claim:devperf:compile-progress-forwarding´
        ´test:integration:test-compile-progress-forwarding´
        """
        from isolation import cargo_work
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'meter.jsonl';output=io.StringIO()
            content=b'  Compiling fixture v1\nfixture-result\n'
            with patch('isolation.subprocess.Popen',return_value=SimpleNamespace(stdout=io.BytesIO(content),stderr=io.BytesIO(),wait=lambda:0)),redirect_stdout(output):
                self.assertEqual(cargo_work(['cargo',str(path),'check']),0,'meter preserves successful child status')
            self.assertEqual(output.getvalue(),content.decode(),'meter forwards every byte without altering evidence')
            self.assertEqual(json.loads(path.read_text())['compiled'],['Compiling fixture v1'],'progress without final artifact still records compilation')

    def test_port_range_refusal(self):
        """Unreadable and malformed automatic port ranges receive the check's own refusal.
        ´claim:devperf:port-range-refusal´
        ´test:integration:test-port-range-refusal´
        """
        from host_postgresql import check_ports, POSTGRESQL_PORTS
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for text in (None,'broken'):
                if text is not None:(root/'ip_local_port_range').write_text(text)
                try:
                    with self.assertRaisesRegex(RuntimeError,'automatic port range is unavailable',msg='port range must refuse in its own vocabulary'):
                        check_ports(POSTGRESQL_PORTS,root)
                except (OSError,ValueError) as error:self.fail('raw port-range exception escaped: '+str(error))

    def test_quiet_repeat_request(self):
        """Loaded excess names a separately declared quiet repeat without scheduling or changing a verdict.
        ´claim:devperf:quiet-repeat-request´
        ´test:integration:test-quiet-repeat-request´
        """
        from build_graph import quiet_repeat
        for excess, compiled, expected in ((9,[],False),(10,[],False),(11,[],True),(1,['build'],True)):
            request = quiet_repeat('commit','tree','fast',dict(classification='load-unresolved',excess_s=excess),100,compiled)
            self.assertEqual(request['required'],expected,'repeat trigger follows excess share or compilation')
            self.assertEqual(request['transition_compiling_steps'],compiled,'trigger names transition compiles')
        self.assertIsNone(quiet_repeat('commit','tree','fast',dict(classification='within-budget'),100,[]))

    def test_repeat_transition_compiles(self):
        """Only cache compilation or owner work outside each recurring set triggers a compile repeat.
        ´claim:devperf:repeat-transition-compiles´
        ´test:integration:test-repeat-transition-compiles´
        """
        from build_graph import repeat_compilation
        rows=[dict(step='wallet-conformance',owner='wallet-conformance',cold_target=False,compiled=['Checking pn-wallet v0.1.0 (/fixture)'])]
        tiers={'service':dict(isolated_compiling_steps=rows)}
        self.assertEqual(repeat_compilation(dict(compiling_steps=[]),tiers),[],'recurring package check is not a cache rebuild')
        self.assertEqual(repeat_compilation(dict(compiling_steps=['clippy']),tiers),['clippy'],'lint cache compilation triggers')
        rows[0]['cold_target']=True
        self.assertEqual(repeat_compilation({},tiers),['wallet-conformance'],'a cold owner is not exempt as recurring work')
        rows[0]['cold_target']=False
        rows[0]['compiled'].append('Checking new-dependency v0.1.0 (/fixture)')
        self.assertEqual(repeat_compilation({},tiers),['wallet-conformance'],'a new owner artifact triggers')
        rows[0]['compiled']=[]
        self.assertEqual(repeat_compilation({},tiers),[],'fresh owner invocation is not compilation')

    def test_repeat_obligation_close(self):
        """One linked green quiet repeat discharges all scopes even over budget; foreign or loaded evidence refuses.
        ´claim:devperf:repeat-obligation-close´
        ´test:integration:test-repeat-obligation-close´
        """
        from build_graph import repeat_obligation, repeat_close, declare_run
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);lane=root/'.lane';lane.mkdir()
            declaration=dict(source='source',entry='owing',plan='one-run',sample='import')
            (lane/'gate-declaration.json').write_text(json.dumps(declaration))
            declared={'whole-gate':dict(budget_ms=100000),'fast':dict(budget_ms=50000)}
            tiers={'fast':dict(classification='load-unresolved',excess_s=10,budget='fast',steps=[],isolated_compiling_steps=[])}
            whole=dict(classification='load-unresolved',excess_s=20)
            with patch.dict(os.environ,PN_IMPORT_BASE='base'),redirect_stdout(io.StringIO()) as output:
                request=repeat_obligation(root,dict(tree='tree',cache={},path='key/tree.json'),whole,tiers,declared)
            self.assertEqual(len(output.getvalue().splitlines()),1,'one run owes one obligation for all scopes')
            self.assertEqual(len(request['scopes']),2,'whole and tier scopes join one obligation')
            self.assertEqual(request['base'],'base','request preserves import base')
            self.assertTrue(request['required'],'excess share makes the obligation required')
            obligation=lane/'gate-quiet-repeat.json'
            declaration.update(entry=request['entry'],repeat_of=request['obligation'])
            (lane/'gate-declaration.json').write_text(json.dumps(declaration))
            with redirect_stdout(io.StringIO()) as output:
                self.assertIsNone(repeat_obligation(root,{},whole,tiers,declared),'repeat must keep its original obligation')
            self.assertIn('GATE-QUIET-REPEAT-PENDING',output.getvalue(),'a repeat does not recursively owe another obligation')
            run=written_peer('source',100,.04);run.update(tree='tree',import_base='base',path='key/tree.json',load_unresolved_pressure_percent=10)
            run['quiet_windows']={phase:dict(node_scope='node-wide',node_pressure_fraction={'cpu.some':0},wall_seconds=5) for phase in ('before','after')}
            (lane/'gate-baseline.json').write_text(json.dumps(run))
            whole=dict(status=0,stall=.04,node_scope='node-wide',classification='owned-regression',started=10,ended=20)
            (lane/'gate-wall.json').write_text(json.dumps(whole))
            for phase,at in [('start',9),('end',21)]:
                idle=dict(identity={'PN_GATE_ENTRY':declaration['entry']},boundary=phase,at=at,
                          processes=dict(status=0,stdout=''),containers=dict(status=0,stdout='[]'),services=dict(status=0,stdout='[]'))
                (lane/('gate-series-host-'+phase+'.json')).write_text(json.dumps(idle))
            with redirect_stdout(io.StringIO()) as output:
                try:repeat_close(obligation,lane)
                except ValueError as error:self.fail('quiet regression must discharge: '+str(error))
            self.assertIn('GATE-QUIET-REPEAT-DISCHARGED',output.getvalue(),'quiet regression discharges, it need not be within budget')
            for key,value,reason in [('stall',.2,'pressure'),('status',1,'functionally green')]:
                bad=dict(whole);bad[key]=value;(lane/'gate-wall.json').write_text(json.dumps(bad))
                with self.assertRaisesRegex(ValueError,reason,msg='nonadmitted repeat cannot discharge '+key):repeat_close(obligation,lane)
            (lane/'gate-wall.json').write_text(json.dumps(whole))
            run['import_base']='foreign';(lane/'gate-baseline.json').write_text(json.dumps(run))
            with self.assertRaisesRegex(ValueError,'identity',msg='repeat must repay the same base transition'):repeat_close(obligation,lane)
            run['import_base']='base';(lane/'gate-baseline.json').write_text(json.dumps(run))
            admission=lane/'admission.json';admission.write_text(json.dumps(dict(outcome='admitted',frozen_median=.05,
                policy=dict(series_absolute_pressure=.1,series_relative_floor=.044,series_pressure_multiple=2))))
            whole['stall']=.07;(lane/'gate-wall.json').write_text(json.dumps(whole))
            with redirect_stdout(io.StringIO()):repeat_close(obligation,lane,admission)
            for member,value,reason in [('tree','foreign','identity'),('path','foreign/tree.json','identity')]:
                changed=dict(run);changed[member]=value;(lane/'gate-baseline.json').write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError,reason,msg='repeat refuses foreign '+member):repeat_close(obligation,lane,admission)
            (lane/'gate-baseline.json').write_text(json.dumps(run))
            valid_idle=json.loads((lane/'gate-series-host-end.json').read_text())
            for changed,reason in [(dict(valid_idle,identity={'PN_GATE_ENTRY':'foreign'}),'foreign'),(dict(valid_idle,at=19),'bracket')]:
                (lane/'gate-series-host-end.json').write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError,reason,msg='repeat refuses invalid idle join '+reason):repeat_close(obligation,lane,admission)
            (lane/'gate-series-host-end.json').write_text(json.dumps(valid_idle))
            badadmission=json.loads(admission.read_text());badadmission['policy']['series_absolute_pressure']=float('nan')
            admission.write_text(json.dumps(badadmission))
            with self.assertRaisesRegex(ValueError,'malformed',msg='nonfinite admission policy cannot discharge'):repeat_close(obligation,lane,admission)
            badadmission['policy']['series_absolute_pressure']=.1;admission.write_text(json.dumps(badadmission))
            badidle=json.loads((lane/'gate-series-host-end.json').read_text());badidle['containers']['stdout']='[{}]'
            (lane/'gate-series-host-end.json').write_text(json.dumps(badidle))
            with self.assertRaisesRegex(ValueError,'container',msg='another account container blocks discharge'):repeat_close(obligation,lane,admission)
            with patch.dict(os.environ,PN_GATE_PLAN='one-run',PN_GATE_ENTRY='next',PN_GATE_SAMPLE='import',PN_IMPORT_BASE='wrong',PN_GATE_REPEAT_OF=str(obligation)),patch('build_graph.subprocess.run',return_value=SimpleNamespace(stdout='source',returncode=0)):
                with self.assertRaisesRegex(ValueError,'repeat declaration',msg='wrong repeat base refuses before work'):declare_run(root)

    def test_reference_incumbent_tree(self):
        """Retention uses the previous reference tree even when an unrelated peer has a lower stall.
        ´claim:devperf:reference-incumbent-tree´
        ´test:integration:test-reference-incumbent-tree´
        """
        from build_graph import retain_baseline
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'.lane').mkdir()
            old, unrelated, candidate = written_peer('old',100,.05),written_peer('unrelated',1,.001),written_peer('new',90,.04)
            for row in (old,unrelated,candidate):
                row['quiet_windows']={phase:dict(node_scope='node-wide',node_pressure_fraction={'cpu.some':0},wall_seconds=5) for phase in ('before','after')}
                row['load_unresolved_pressure_percent']=10
                row.pop('previous_reference',None)
            candidate.update(path=str(root/'new.json'),context_directory=str(root),previous_baseline_tree=old['tree'],previous_peers=[unrelated,old])
            (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
            output=io.StringIO()
            with patch.dict(os.environ,{},clear=True),patch('build_graph.evidence_statuses',return_value={}),redirect_stdout(output):
                retain_baseline(root)
            self.assertIn('reason=warm-peer-noise-margin-unavailable',output.getvalue())
            self.assertFalse((root/'new.json').exists(),'no unsized-margin replacement is permitted')
            # A sized margin distinguishes using the wrong previous tree.
            (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
            with patch.dict(os.environ,PN_GATE_REFERENCE_STALL_CEILING='.1',PN_GATE_REFERENCE_STALL_BAND='.02',PN_GATE_REFERENCE_NOISE_MARGIN='.05'),patch('build_graph.evidence_statuses',return_value={}),redirect_stdout(io.StringIO()):
                retain_baseline(root)
            self.assertTrue((root/'new.json').exists(),'the candidate improves the named incumbent, not the unrelated archive minimum')
            candidate.update(previous_reference=old, previous_peers=[dict(unrelated,tree=old['tree'])])
            (root/'new.json').unlink()
            (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
            with patch.dict(os.environ,PN_GATE_REFERENCE_STALL_CEILING='.1',PN_GATE_REFERENCE_STALL_BAND='.02',PN_GATE_REFERENCE_NOISE_MARGIN='.05'),patch('build_graph.evidence_statuses',return_value={}),redirect_stdout(io.StringIO()):
                retain_baseline(root)
            self.assertTrue((root/'new.json').exists(),'the exact comparison receipt must survive a same-tree archive peer')

    def test_reference_retained_selection(self):
        """Generated rejected-run walks keep the retained ancestor ahead of closer archived observations.
        ´claim:devperf:reference-retained-selection´
        ´test:integration:test-reference-retained-selection´
        """
        from build_graph import select_incumbent, baseline_replacement
        import random
        rng=random.Random(36192); sequences=set(); records=set(); pairs=set()
        template=written_peer('retained',100,.05)
        for number in range(128):
            old=copy.deepcopy(template); old['source']='retained-'+str(number)
            eligible=[(old,9)]; rejected=[]
            for index in range(rng.randrange(2,8)):
                row=copy.deepcopy(template); row['source']=f'{number}-rejected-{index}'
                row['tiers']['service']['step_figures']['service']['own_cpu_s']=104+index
                eligible.append((row,index+1));rejected.append(row)
            rng.shuffle(eligible)
            sequences.add(json.dumps(eligible,sort_keys=True))
            for row,_ in eligible:records.add(json.dumps(row,sort_keys=True))
            selected=select_incumbent(eligible,[old],lambda value:value)
            self.assertIs(selected,old,'a rejected nearer archive cannot become incumbent')
            candidate=copy.deepcopy(template);candidate['source']='next-'+str(number)
            candidate['tiers']['service']['step_figures']['service']['own_cpu_s']=100.5
            pairs.add(json.dumps([selected,candidate],sort_keys=True))
            with patch.dict(os.environ,PN_GATE_REFERENCE_NOISE_MARGIN='.03',PN_GATE_REFERENCE_STALL_CEILING='.1',PN_GATE_REFERENCE_STALL_BAND='.01'):
                self.assertFalse(baseline_replacement(candidate,selected)[0],'alternating rejection cannot walk the retained cost upward')
                self.assertTrue(baseline_replacement(candidate,rejected[0])[0],'control exposes the rejected-record walk')
            boot=select_incumbent(eligible,[],lambda value:value)
            self.assertIs(boot,next(row for row,distance in eligible if distance==1),'archive bootstraps only without a retained file')
        self.assertEqual(len(sequences),128,'all generated orders are distinct by content')
        print(f'REFERENCE-SELECTION sequences={len(sequences)} distinct_records={len(records)} distinct_pairs={len(pairs)} order=generated-unsorted')

    def test_reference_stall_band(self):
        """CPU decisions require a sized ceiling and strict stall band; counts have their own margin.
        ´claim:devperf:reference-stall-band´
        ´test:integration:test-reference-stall-band´
        """
        from build_graph import reference_judgment, reference_provisional
        old,new=written_peer('old',100,.05),written_peer('new',50,.06)
        with patch.dict(os.environ,{},clear=True):
            legacy=dict(old,provisional=False)
            self.assertTrue(reference_provisional(legacy),'a historical false flag cannot prove a deciding comparison')
            missing=copy.deepcopy(new);missing['whole'].pop('stall')
            self.assertEqual(reference_judgment(missing,old)['reason'],'whole-gate-stall-unavailable','missing pressure cannot confirm or order a record')
            cold=copy.deepcopy(old);cold['cache']['state']='cold'
            self.assertTrue(reference_judgment(new,cold)['decidable'],'observed warmth can replace a cold provisional reference')
            self.assertFalse(reference_judgment(new,old)['decidable'],'unsized CPU margin cannot confirm')
            with patch.dict(os.environ,PN_GATE_REFERENCE_NOISE_MARGIN='.1'):
                self.assertEqual(reference_judgment(new,old)['reason'],'warm-peer-stall-policy-unavailable','CPU needs measured stall policy')
                with patch.dict(os.environ,PN_GATE_REFERENCE_STALL_CEILING='.055',PN_GATE_REFERENCE_STALL_BAND='.02'):
                    self.assertEqual(reference_judgment(new,old)['reason'],'warm-peer-stall-ceiling','both runs must meet the ceiling')
                with patch.dict(os.environ,PN_GATE_REFERENCE_STALL_CEILING='.1',PN_GATE_REFERENCE_STALL_BAND='.005'):
                    self.assertEqual(reference_judgment(new,old)['reason'],'warm-peer-stall-band','a quieter CPU figure cannot decide outside the band')
                with patch.dict(os.environ,PN_GATE_REFERENCE_STALL_CEILING='.1',PN_GATE_REFERENCE_STALL_BAND='.02'):
                    judgment=reference_judgment(new,old)
                    self.assertTrue(judgment['accepted'],'matched stalls permit improvement beyond noise')
                    self.assertEqual(judgment['costs'],[100,50],'reason reports two-way rather than whole CPU')
                    self.assertEqual(judgment['policy']['stall_band'],.02,'judgment stores policy in force')
                    new['whole']['stall']=old['whole']['stall']+.02
                    self.assertFalse(reference_judgment(new,old)['decidable'],'band boundary is strict')
            counted_old=written_peer('old',100,.05,instructions=1000)
            counted_new=written_peer('new',110,.2,instructions=500)
            with patch.dict(os.environ,PN_GATE_REFERENCE_NOISE_MARGIN='.1'):
                self.assertEqual(reference_judgment(counted_new,counted_old)['reason'],'warm-peer-count-margin-unavailable','CPU margin cannot size count spread')
            with patch.dict(os.environ,PN_GATE_REFERENCE_COUNT_MARGIN='.1'):
                self.assertTrue(reference_judgment(counted_new,counted_old)['accepted'],'complete counts need no CPU stall band')

    def test_reference_deletion_events(self):
        """Generated land, replay, revert and archive events preserve landable records and delete passed-base absences.
        ´claim:devperf:reference-deletion-events´
        ´test:integration:test-reference-deletion-events´
        """
        import random
        from contextlib import redirect_stdout
        from build_graph import prune_peer_archive
        generator=random.Random(32189)
        kinds=['archive','land','replay','move','legacy','foreign-base','revert','duplicate','dominance']
        counts=dict.fromkeys(kinds,0); distinct=set(); preserved=deleted=0
        legacy_checks=foreign_checks=duplicate_checks=dominance_checks=0
        for sequence in range(128):
            with tempfile.TemporaryDirectory() as directory:
                archive=Path(directory); history={'base-0':'commit-0'}; base='base-0'; records={}; events=[]
                for position in range(36):
                    action=generator.choice(kinds)
                    live=[name for name in records if (archive/(name+'.json')).exists()]
                    if not live and action in ('land','replay','duplicate','dominance'):
                        action='archive'
                    name=f'record-{position}'; tree=f'tree-{position}'; origin=None
                    if action in ('land','move','revert'):
                        if action=='land':
                            origin=generator.choice(live); base=records[origin]['tree']
                        elif action=='revert':
                            base=generator.choice(list(history))
                        else:
                            base=f'base-{position+1}'
                        history[base]=f'commit-{position+1}'
                    else:
                        if action in ('duplicate','dominance','replay'):
                            origin=generator.choice(live)
                        if action in ('duplicate','dominance'):
                            tree=records[origin]['tree']
                        if action=='dominance':
                            history[tree]=f'commit-{position+1}'
                        value=dict(tree=tree,source=name,cache=dict(state='warm'),
                                   whole=dict(wall=1 if action=='dominance' else 2,comparable_cpu_s=1 if action=='dominance' else 2,stall=.01),
                                   tiers={'fast':dict(selected_cases=['same'])})
                        if action!='legacy':
                            value['import_base_tree']='outside-base' if action=='foreign-base' else base
                        records[name]=value
                        (archive/(name+'.json')).write_text(json.dumps(value))
                    events.append(dict(action=action,base=base,tree=tree,origin=origin));counts[action]+=1
                    before={path.stem for path in archive.glob('*.json')}
                    legacy_checks+=sum('import_base_tree' not in records[name] for name in before)
                    foreign_checks+=sum(records[name].get('import_base_tree')=='outside-base' for name in before)
                    duplicate_checks+=sum(records[left]['tree']==records[right]['tree'] for left in before for right in before if left<right)
                    from build_graph import dominates
                    dominance_checks+=sum(records[left]['tree']==records[right]['tree'] and records[left]['tree'] in history
                                          and dominates(records[left],records[right]) for left in before for right in before if left!=right)
                    doomed={name for name in before if records[name]['tree'] not in history
                            and records[name].get('import_base_tree') in history
                            and records[name].get('import_base_tree')!=base}
                    with redirect_stdout(io.StringIO()):
                        prune_peer_archive(archive,history,base)
                    after={path.stem for path in archive.glob('*.json')}
                    self.assertEqual(after,before-doomed,'only a proven passed-base absence may be deleted')
                    preserved+=len(before-doomed);deleted+=len(doomed)
                distinct.add(json.dumps(events,sort_keys=True))
        self.assertEqual(len(distinct),128)
        self.assertTrue(all(counts.values()))
        self.assertGreater(preserved,0); self.assertGreater(deleted,0)
        self.assertTrue(all((legacy_checks,foreign_checks,duplicate_checks,dominance_checks)))
        print(f'PEER-EVENTS content_distinct={len(distinct)} kinds={json.dumps(counts,sort_keys=True)} preserved_checks={preserved} deleted_checks={deleted} legacy_checks={legacy_checks} foreign_base_checks={foreign_checks} duplicate_tree_pairs={duplicate_checks} landed_strict_dominance_pairs={dominance_checks} order=generated-unsorted')

    def test_written_peer_noise(self):
        """Written common-work receipts keep the incumbent until a measured noise margin is exceeded.
        ´claim:devperf:written-peer-noise´
        ´test:integration:test-written-peer-noise´
        """
        from build_graph import baseline_replacement, peer_intersection, reference_noise_margin
        old = written_peer('old',727.488316,.049136754226175854)
        new = written_peer('new',742.153702+15.548151,.04430517164619928,15.548151)
        self.assertEqual(peer_intersection([old,new]),[727.488316,742.153702])
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(baseline_replacement(new,old)[0], 'unsized noise must keep the incumbent')
            self.assertFalse(baseline_replacement(old,new)[0], 'a cheaper candidate is not evidence beyond an unsized margin')
        with patch.dict(os.environ, PN_GATE_REFERENCE_STALL_CEILING='.9', PN_GATE_REFERENCE_STALL_BAND='.9', PN_GATE_REFERENCE_COUNT_MARGIN='.1', PN_GATE_REFERENCE_NOISE_MARGIN='.03'):
            self.assertFalse(baseline_replacement(old,new)[0], 'two percent is inside this controlled three percent margin')
            better = written_peer('better',600,.06,10)
            self.assertTrue(baseline_replacement(better,old)[0], 'a measured common-work improvement beyond the margin replaces')
        new['tiers']['service']['step_figures']['service']['compiled'] = True
        self.assertEqual(peer_intersection([old,new]),[0,0], 'exclusive compiled cases omit their step, not unaffected common work')
        new['tiers']['service']['step_figures']['service']['compiled'] = False
        for malformed in ('nan','inf','-1','1','text'):
            with patch.dict(os.environ, PN_GATE_REFERENCE_STALL_CEILING='.9', PN_GATE_REFERENCE_STALL_BAND='.9', PN_GATE_REFERENCE_COUNT_MARGIN='.1', PN_GATE_REFERENCE_NOISE_MARGIN=malformed):
                with self.assertRaises(ValueError):
                    reference_noise_margin()

    def test_written_peer_margin(self):
        """An empty written intersection uses only a declared strict stall margin.
        ´claim:devperf:written-peer-stall-margin´
        ´test:integration:test-written-peer-margin´
        """
        from build_graph import baseline_replacement, peer_intersection
        old,new = written_peer('old',100,.05),written_peer('new',50,.04)
        for record in (old,new):
            record['tiers'] = {'service':record['tiers']['service']}
        new['tiers']['service'].update(selected_cases=['other'],case_steps={'other':'service'})
        self.assertIsNone(peer_intersection([old,new]))
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(baseline_replacement(new,old)[0], 'unset stall margin retains')
        for margin, expected in (('.02',False),('.005',True)):
            with patch.dict(os.environ, PN_GATE_REFERENCE_STALL_MARGIN=margin):
                self.assertEqual(baseline_replacement(new,old)[0],expected,'empty projection must obey the strict margin')

    def test_written_peer_instructions(self):
        """Complete matching counter scopes take precedence over load-sensitive CPU without invented deductions.
        ´claim:devperf:written-peer-instructions´
        ´test:integration:test-written-peer-instructions´
        """
        from build_graph import baseline_replacement, peer_intersection
        old,new = written_peer('old',100,instructions=1000),written_peer('new',110,instructions=800)
        self.assertEqual(peer_intersection([old,new],instructions=True),[3000,2400])
        with patch.dict(os.environ, PN_GATE_REFERENCE_STALL_CEILING='.9', PN_GATE_REFERENCE_STALL_BAND='.9', PN_GATE_REFERENCE_COUNT_MARGIN='.1', PN_GATE_REFERENCE_NOISE_MARGIN='.1'):
            self.assertEqual(baseline_replacement(new,old),(True,'warm-peer-instructions-noise-margin'))
            new['tiers']['service']['step_figures']['service']['setup_cpu_s'] = 1
            self.assertIsNone(peer_intersection([old,new],instructions=True),'a gross counter cannot invent setup deductions')
            self.assertFalse(baseline_replacement(new,old)[0])

    def test_peer_duplicate_step(self):
        """Different measurements for one step in two tiers refuse the projection.
        ´claim:devperf:peer-duplicate-step´
        ´test:integration:test-peer-duplicate-step´
        """
        from build_graph import peer_intersection
        old,new = written_peer(),written_peer()
        new['tiers']['duplicate'] = copy.deepcopy(new['tiers']['service'])
        new['tiers']['duplicate']['step_figures']['service']['own_cpu_s'] += 1
        self.assertIsNone(peer_intersection([old,new]),'different duplicate step values must refuse')

    def test_peer_serialized_mismatch(self):
        """A changed serialized-build declaration cannot turn build time into program cost.
        ´claim:devperf:peer-serialized-mismatch´
        ´test:integration:test-peer-serialized-mismatch´
        """
        from build_graph import peer_intersection
        old,new = written_peer(),written_peer()
        for value in (old,new):
            value['tiers'] = {'service':value['tiers']['service']}
        new['tiers']['service']['step_figures']['service']['serialized_build'] = True
        self.assertIsNone(peer_intersection([old,new]),'serialized-build mismatch must omit the step')

    def test_peer_removed_cost_finite(self):
        """A non-finite exclusive case charge cannot enter the common-work sum.
        ´claim:devperf:peer-removed-cost-finite´
        ´test:integration:test-peer-removed-cost-finite´
        """
        from build_graph import peer_intersection
        old,new = written_peer(),written_peer(extra=1)
        for value in (old,new):
            value['tiers'] = {'service':value['tiers']['service']}
        new['tiers']['service']['case_costs']['extra'] = float('nan')
        self.assertIsNone(peer_intersection([old,new]),'non-finite removed cost must omit the step')

    def test_peer_removed_cost_bounded(self):
        """Exclusive case charges cannot subtract more than the measured remaining program work.
        ´claim:devperf:peer-removed-cost-bounded´
        ´test:integration:test-peer-removed-cost-bounded´
        """
        from build_graph import peer_intersection
        old,new = written_peer(),written_peer(extra=101)
        for value in (old,new):
            value['tiers'] = {'service':value['tiers']['service']}
        self.assertIsNone(peer_intersection([old,new]),'over-subtraction must omit the step')

    def test_loaded_step_context(self):
        """Loaded step costs remain unattributed context, including missing and changed steps, independently of quiet baselines.
        ´claim:devperf:loaded-step-context-is-nonverdict´
        ´test:integration:test-loaded-step-context´
        """
        from build_graph import retain_baseline, retain_step_context, step_cpu_context, step_context_key
        identity=dict(configuration='same',lineage='same',node='same',accounting='old')
        self.assertEqual(step_context_key(identity), step_context_key(dict(identity,accounting='new')), 'gross CPU context must survive an accounting recipe change')
        for key in ('configuration','lineage','node'):
            self.assertNotEqual(step_context_key(identity), step_context_key(dict(identity,**{key:'other'})))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = dict(source='previous', step_cpu={'design-tests': 52.0, 'gone': 2.0}, quiet=False)
            retain_step_context(root, prior)
            self.assertFalse(list(root.glob('*.json')))
            previous = json.loads((root/'last-run.context').read_text())
            rows = step_cpu_context({'design-tests': 106.0, 'new': None}, previous)
            self.assertEqual(rows[0]['delta_cpu_s'], 54.0)
            self.assertEqual(rows[0]['previous_source'], 'previous')
            self.assertIsNone(rows[1]['delta_cpu_s'])
            self.assertTrue(all(row['verdict_effect'] == 'none' and row['attribution'] == 'unattributed-context' for row in rows))
            for malformed in ([], {}, dict(source='old', steps={'design-tests': 'bad'})):
                self.assertIsNone(step_cpu_context({'design-tests': 1.0}, malformed)[0]['previous_cpu_s'])
            retain_step_context(root, dict(source='current', step_cpu={'design-tests': 20.0}))
            self.assertEqual(json.loads((root/'last-run.context').read_text())['source'], 'current')
            (root/'.lane').mkdir()
            candidate = dict(source='loaded', path=str(root/'quiet.json'), context_directory=str(root/'context'), step_cpu={'design-tests': 30.0})
            (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
            with patch('build_graph.evidence_statuses', return_value={}), patch('build_graph.quiet_baseline', return_value=False):
                retain_baseline(root)
            self.assertFalse((root/'quiet.json').exists())
            self.assertEqual(json.loads((root/'context/last-run.context').read_text())['steps'], {'design-tests': 30.0})

    def test_calibration_identity(self):
        """A measured function retains exact standing through unrelated edits, while a changed or missing body becomes pending under its owner without changing its allowance.
        ´claim:devperf:changed-calibration-is-pending´
        ´test:integration:test-calibration-identity´
        """
        from devperf import case_identity, calibration_identities
        source = 'def probe():\n    return 1\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'case.py'
            identity = dict(path='case.py', function='probe', digest=case_identity(source, 'case.py', 'probe'), owner='fixture-owner')
            from gate_resources import node_identity
            declared = {'gate':dict(calibration_campaigns=[dict(label='fixture', node=node_identity())]),
                        'case':dict(calibration_campaign='fixture', calibration_source=identity, budget_ms=100)}
            original = copy.deepcopy(declared)
            for body, status in ((source, 'exact'), (source+'\ndef other():\n    return 2\n', 'exact'),
                                 (source.replace('return 1', 'return 2'), 'pending'), ('', 'pending')):
                path.write_text(body)
                row, = calibration_identities(declared, root)
                self.assertEqual(row['status'], status)
                self.assertEqual(row['owner'], 'fixture-owner')
                self.assertEqual(declared, original)
            path.write_text(source)
            for node, reason in ((None, 'node-identity-unavailable'), ({'cpu_models':['different']}, 'different-node-identity')):
                altered = copy.deepcopy(declared)
                altered['gate']['calibration_campaigns'][0]['node'] = node
                measured, = calibration_identities(altered, root)
                self.assertEqual(measured['status'], 'pending')
                self.assertEqual(measured['reason'], reason)
            rust = 'fn probe() { let text = "}"; /* } */ assert!(true); }'
            self.assertEqual(case_identity(rust, 'case.rs', 'probe'), case_identity(rust+'\nfn other() {}', 'case.rs', 'probe'))
            self.assertNotEqual(case_identity(rust, 'case.rs', 'probe'), case_identity(rust.replace('true','false'), 'case.rs', 'probe'))

        for path, source, changed in (
                ('case.py', 'def helper():\n    return 1\ndef probe():\n    return helper()\n', 'return 2'),
                ('case.rs', "fn helper() { let brace = '}'; } fn probe() { helper(); }", "let brace = '{'")):
            original = case_identity(source, path, 'probe')
            altered = source.replace('return 1', changed) if path.endswith('.py') else source.replace("let brace = '}'", changed)
            self.assertNotEqual(original, case_identity(altered, path, 'probe'))
        for text in ("fn probe() { let c = '}'; assert!(true); }",
                     'fn probe() { let s = r###"} fn fake() {"###; assert!(true); }',
                     'fn probe() { /* outer } /* nested { */ } */ assert!(true); }'):
            self.assertNotEqual(case_identity(text, 'case.rs', 'probe'), case_identity(text.replace('true', 'false'), 'case.rs', 'probe'))
        for path, source in (('case.py', '@marker(1)\ndef probe():\n    pass\n'),
                             ('case.rs', '#[marker(1)]\nfn probe() {}')):
            self.assertNotEqual(case_identity(source, path, 'probe'), case_identity(source.replace('marker(1)', 'marker(2)'), path, 'probe'))
        source = 'def leaf():\n    return 1\ndef helper():\n    return leaf()\ndef probe():\n    return helper()\n'
        self.assertNotEqual(case_identity(source, 'case.py', 'probe'), case_identity(source.replace('return 1', 'return 2'), 'case.py', 'probe'))
        source = 'class Fixture:\n    def leaf(self):\n        return 1\n    def probe(self):\n        def invoke():\n            return self.leaf()\n        return invoke()\n'
        self.assertNotEqual(case_identity(source, 'case.py', 'probe'), case_identity(source.replace('return 1', 'return 2'), 'case.py', 'probe'))
        source = 'fn leaf() { } fn helper() { leaf(); } fn probe() { helper(); }'
        self.assertNotEqual(case_identity(source, 'case.rs', 'probe'), case_identity(source.replace('fn leaf() { }', 'fn leaf() { return; }'), 'case.rs', 'probe'))

        source = 'fn helper(value: [u8; 2]) { let _ = value; } fn probe() { helper([0, 0]); }'
        self.assertNotEqual(case_identity(source, 'case.rs', 'probe'), case_identity(source.replace('let _ = value;', 'let _ = value[0];'), 'case.rs', 'probe'))
        for path, source in (('case.py', 'def probe():\n    pass\ndef probe():\n    pass\n'),
                             ('case.rs', 'fn probe() {} fn probe() {}')):
            with self.assertRaisesRegex(StructuralError, 'ambiguous'):
                case_identity(source, path, 'probe')
        # Own runner fixtures and named values join the closure independently;
        # unrelated values and inherited dispatch remain outside its scope.
        source = 'LIMIT = 1\nUNUSED = 1\nclass Fixture:\n    DEFAULT = 1\n    def setUp(self):\n        self.value = 1\n    def tearDown(self):\n        release()\n    def probe(self):\n        return self.value + LIMIT + self.DEFAULT\ndef release():\n    pass\n'
        for before, after in (('LIMIT = 1', 'LIMIT = 2'), ('DEFAULT = 1', 'DEFAULT = 2'),
                              ('self.value = 1', 'self.value = 2'), ('    pass', '    return')):
            self.assertNotEqual(case_identity(source, 'case.py', 'probe'),
                                case_identity(source.replace(before, after), 'case.py', 'probe'))
        self.assertEqual(case_identity(source, 'case.py', 'probe'),
                         case_identity(source.replace('UNUSED = 1', 'UNUSED = 2'), 'case.py', 'probe'))
        source = 'def helper():\n    return 1\nhelper = wrap(helper)\ndef probe():\n    return helper()\n'
        self.assertNotEqual(case_identity(source, 'case.py', 'probe'),
                            case_identity(source.replace('return 1', 'return 2'), 'case.py', 'probe'))
        source = '#[cfg(feature="one")] const LIMIT: u8 = 1; static WIDTH: u8 = 2; const ALIAS: u8 = LIMIT; const UNUSED: u8 = 3; fn probe() { let value = ALIAS + WIDTH; }'
        for before, after in (('= 1', '= 4'), ('= 2', '= 5'), ('"one"', '"two"')):
            self.assertNotEqual(case_identity(source, 'case.rs', 'probe'),
                                case_identity(source.replace(before, after), 'case.rs', 'probe'))
        self.assertEqual(case_identity(source, 'case.rs', 'probe'),
                         case_identity(source.replace('= 3', '= 6'), 'case.rs', 'probe'))

    def test_gate_target_lock(self):
        """The supervisor reports its wait and owns the target lock until gate exit, without lending it to a surviving descendant.
        ´claim:devperf:gate-target-lock-is-supervised´
        ´test:integration:test-gate-target-lock´
        """
        import fcntl
        import multiprocessing
        import signal
        import subprocess
        import sys
        from contextlib import redirect_stdout, redirect_stderr
        from isolation import gate_target
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as target:
            environment = dict(os.environ, CARGO_TARGET_DIR=target, TMPDIR=str(Path(target)/'absent'))
            environment.pop('PN_GATE_LOCK_FD', None)
            environment.pop('PN_GATE_LOCK_TOKEN', None)
            direct = subprocess.run(['bash', 'ci/gate.sh', '--gate-target-locked'], cwd=root,
                                    env=environment, capture_output=True, text=True)
            self.assertEqual(direct.returncode, 2)
            self.assertIn('requires the target supervisor token and held lock', direct.stderr)
            with patch.dict(os.environ, environment, clear=True):
                self.assertEqual(gate_target([sys.executable, '-B', 'ci/isolation.py', 'locked-entry']), 0,
                                 'the supervisor must admit its own locked entry')
        with tempfile.TemporaryDirectory() as directory:
            command = 'sleep 30 >/dev/null 2>&1 & echo $! > "$1"\nprintf "locked\\n"\nread -r release\n'
            pidfile = Path(directory)/'descendant'
            errors = Path(directory)/'stderr'
            output_read, output_write = os.pipe()
            release_read, release_write = os.pipe()
            def supervise():
                os.close(output_read)
                os.close(release_write)
                os.dup2(release_read, 0)
                os.close(release_read)
                with os.fdopen(output_write, 'w') as output, errors.open('w') as diagnostic:
                    os.dup2(output.fileno(), 1)
                    os.dup2(diagnostic.fileno(), 2)
                    with redirect_stdout(output), redirect_stderr(diagnostic):
                        os.environ['CARGO_TARGET_DIR'] = directory
                        sys.exit(gate_target(['bash', '-c', command, 'fixture', str(pidfile)]))
            child = multiprocessing.get_context('fork').Process(target=supervise)
            child.start()
            os.close(output_write)
            os.close(release_read)
            try:
                with os.fdopen(output_read) as output, os.fdopen(release_write, 'w') as release:
                    try:
                        self.assertRegex(output.readline(), r'^GATE-TARGET-LOCK wait_s=[0-9.]+ path=')
                        self.assertEqual(output.readline(), 'locked\n')
                        lock = str(Path(directory)/'.gate-target.lock')
                        with open(lock, 'a') as competing:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        release.write('release\n')
                        release.flush()
                        child.join(10)
                self.assertFalse(child.is_alive(), 'gate supervisor exceeded its exit deadline')
                self.assertEqual(child.exitcode, 0, errors.read_text())
                with open(lock, 'a') as released:
                    os.kill(int(pidfile.read_text()), 0)
                    fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                if child.is_alive():
                    child.terminate()
                    child.join(10)
                if pidfile.exists():
                    os.kill(int(pidfile.read_text()), signal.SIGTERM)

    def test_gate_cancel_cleanup(self):
        """Cancellation retains target exclusion until a slow EXIT stop and its session finish.
        ´claim:devperf:gate-cancellation-retains-exclusion´
        ´test:integration:test-gate-cancel-cleanup´
        """
        import fcntl
        import multiprocessing
        import signal
        import sys
        import time
        from isolation import gate_target
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready_read, ready_write = os.pipe()
            release_read, release_write = os.pipe()
            command = '''trap 'trap - EXIT; trap "" TERM INT; printf "stopping\\n"; read -r release; kill -KILL "$service"; wait "$service"; printf "service-stopped\\n"; kill -KILL "$session"; wait "$session"; printf "session-closed\\n"' EXIT
trap 'trap "" TERM INT; exit 143' TERM INT
bash -c 'trap "" TERM INT; printf "service-ready\\n"; exec sleep 60' & service=$!
bash -c 'trap "" TERM INT; printf "session-ready\\n"; exec sleep 60' & session=$!
printf '%s %s\\n' "$service" "$session" > "$1"
printf "ready\\n"
wait
'''
            def supervise():
                os.close(ready_read)
                os.close(release_write)
                os.dup2(release_read, 0)
                os.close(release_read)
                os.dup2(ready_write, 1)
                os.close(ready_write)
                with (root/'stderr').open('w') as errors:
                    os.dup2(errors.fileno(), 2)
                    os.environ['CARGO_TARGET_DIR'] = directory
                    sys.exit(gate_target(['bash', '-c', command, 'fixture', str(root/'pids')]))
            child = multiprocessing.get_context('fork').Process(target=supervise)
            child.start()
            os.close(ready_write)
            os.close(release_read)
            try:
                with os.fdopen(ready_read) as events, (root/'.gate-target.lock').open('a') as lock:
                    self.assertTrue(events.readline().startswith('GATE-TARGET-LOCK'))
                    self.assertEqual({events.readline() for _ in range(3)}, {'ready\n', 'service-ready\n', 'session-ready\n'})
                    pids = [int(pid) for pid in (root/'pids').read_text().split()]
                    self.assertEqual(len(pids), 2)
                    child.terminate()
                    self.assertEqual(events.readline(), 'stopping\n')
                    time.sleep(5.25)
                    self.assertTrue(child.is_alive(), 'supervisor killed the gate during EXIT stop')
                    for pid in pids:
                        os.kill(pid, 0)
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    os.write(release_write, b'release\n')
                    self.assertEqual(events.readline(), 'service-stopped\n')
                    self.assertEqual(events.readline(), 'session-closed\n')
                    child.join(10)
                    self.assertFalse(child.is_alive())
                    self.assertEqual(child.exitcode, 143)
                    for pid in pids:
                        with self.assertRaises(ProcessLookupError):
                            os.kill(pid, 0)
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(release_write)
                if child.is_alive():
                    os.kill(child.pid, signal.SIGKILL)
                    child.join(10)

    def test_target_retention(self):
        """Retention drops oversized incremental state before profile artifacts and preserves owner metadata; inclusive Cargo-and-run CPU stays apart from compile CPU.
        ´claim:devperf:target-retention-preserves-metadata´
        ´test:integration:test-target-retention´
        """
        from isolation import bound_target, cargo_work, built_executable
        artifact = dict(reason='compiler-artifact', target=dict(name='documents'), executable='/owned/target/triple/gate/documents')
        self.assertEqual(built_executable(json.dumps(artifact)), artifact['executable'])
        with self.assertRaisesRegex(ValueError, 'exactly one executable'):
            built_executable('{}')
        with self.assertRaisesRegex(ValueError, 'exactly one executable'):
            built_executable(json.dumps(artifact)+'\n'+json.dumps(dict(artifact, executable='/other/documents')))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target/'gate/incremental').mkdir(parents=True)
            (target/'gate/incremental/old').write_bytes(b'x'*32768)
            (target/'gate/dependency').write_bytes(b'x'*8192)
            (target/'gate-baselines').mkdir()
            (target/'gate-baselines/retained').write_text('baseline')
            self.assertTrue(bound_target(target, 24576, 'fixture'))
            self.assertFalse((target/'gate/incremental').exists())
            self.assertTrue((target/'gate/dependency').exists())
            self.assertFalse(bound_target(target, 24576, 'fixture'))
            self.assertTrue(bound_target(target, 1, 'fixture'))
            self.assertFalse((target/'gate').exists())
            self.assertEqual((target/'gate-baselines/retained').read_text(), 'baseline')
            (target/'triple/gate/.fingerprint').mkdir(parents=True)
            (target/'triple/CACHEDIR.TAG').write_text('Cargo cache')
            (target/'triple/gate/dependency').write_bytes(b'x'*8192)
            (target/'host-observation-runtime/gate/.fingerprint').mkdir(parents=True)
            (target/'host-observation-runtime/.rustc_info.json').write_text('{}')
            (target/'host-observation-runtime/gate/dependency').write_bytes(b'x'*8192)
            (target/'isolation/owner').mkdir(parents=True)
            (target/'isolation/owner/retained').write_text('owned')
            output = io.StringIO()
            from contextlib import redirect_stdout
            with redirect_stdout(output):
                self.assertTrue(bound_target(target, 1, 'fixture'))
            self.assertFalse((target/'triple/gate').exists())
            self.assertEqual((target/'isolation/owner/retained').read_text(), 'owned')
            self.assertIn('outside_profiles=isolation', output.getvalue())
            self.assertIn('target_layout=triple', output.getvalue())
            self.assertIn('nested_target=host-observation-runtime', output.getvalue())
            self.assertTrue((target/'host-observation-runtime/gate/dependency').exists())
            self.assertIn('scope=reported-not-profile-ceiling', output.getvalue())
            for name in ('lint-combined', 'lint-required', 'lint-nursery'):
                (target/name/'gate').mkdir(parents=True)
                (target/name/'.rustc_info.json').write_text('{}')
                (target/name/'gate/dependency').write_bytes(b'x'*8192)
            with redirect_stdout(output):
                self.assertTrue(bound_target(target, 24576, 'fixture'))
            self.assertTrue((target/'lint-combined/gate/dependency').exists(), 'retired layouts must leave before live artifacts are trimmed')
            for name in ('lint-required', 'lint-nursery'):
                self.assertFalse((target/name).exists(), 'retired lint layouts have no reader')
            self.assertIn('retired_bytes=', output.getvalue())
            with redirect_stdout(output):
                self.assertTrue(bound_target(target, 1, 'fixture'), 'live lint profiles still count inside the ceiling')
            self.assertFalse((target/'lint-combined/gate').exists())
            self.assertTrue((target/'lint-combined/.rustc_info.json').exists())
            log = target/'meter.jsonl'
            with patch('isolation.subprocess.Popen', side_effect=lambda *args, **kw: SimpleNamespace(stdout=io.BytesIO(b'{"reason":"compiler-artifact","fresh":false,"package_id":"fixture"}\n'), stderr=io.BytesIO(), wait=lambda:0)):
                for command in ('build', 'check', 'run', 'test'):
                    self.assertEqual(cargo_work(['cargo', str(log), command]), 0)
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual([row['compile_only'] for row in rows], [True, True, False, False])
            self.assertTrue(all(row['compiled'] == ['fixture'] for row in rows), 'artifact freshness must record compilation for every Cargo invocation kind')

    def test_distinct_excess_ledger(self):
        """Claim: The gate ledger counts each current-source case excess once by configuration, operation, budget and tier across owned files, retains the largest repeated measurement, and excludes stale evidence and non-budget findings while reporting other scope excesses separately.
        ´claim:devperf:distinct-excess-ledger-is-gate-evidence´
        ´test:integration:test-distinct-excess-ledger´
        """
        from devperf import excess_ledger
        declaration = declarations()
        declaration['suite'] = dict(category='suite')
        first = dict(execution(200), kind='budget-excess', tier='fast')
        second = dict(first, operation='other', tier='service')
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory)/name for name in ('parent.jsonl','child.jsonl')]
            paths[0].write_text('\n'.join(json.dumps(row) for row in [first, dict(first,source='stale'), dict(first,kind='regression'), dict(first,budget='suite')]))
            paths[1].write_text('\n'.join(json.dumps(row) for row in [dict(first,duration_ms=300), second]))
            result = excess_ledger(paths, first['source'], declaration)
            self.assertEqual(result['distinct_cases'], 2)
            self.assertEqual(result['by_budget'], {'unit':2})
            self.assertEqual(result['by_tier'], {'fast':1, 'service':1})
            self.assertEqual(result['distinct_excesses'], 3)
            self.assertEqual(next(row for row in result['entries'] if row['operation']=='probe' and row['budget']=='unit')['duration_ms'], 300)
            self.assertEqual(result['verdict_effect'], 'none')

    def test_tier_overrun(self):
        """Tier summaries keep wall overruns separate from functional verdicts and exclude foreign-source and cold-owner measurements from comparisons.
        ´claim:devperf:tier-overruns-retain-functional-verdicts´
        ´test:integration:test-tier-overrun´
        """
        from contextlib import redirect_stdout
        from build_graph import tier_summary, tier_wall_ownership
        gap = tier_wall_ownership(139.5, [(80,132.6),(0,50)])
        self.assertAlmostEqual(gap['step_wall_sum_s'],102.6)
        self.assertAlmostEqual(gap['unowned_wall_s'],36.9, msg='unowned tier wall must remain visible')
        overlap = tier_wall_ownership(10, [(4,9),(1,6),(2,3)])
        self.assertEqual(overlap, dict(step_wall_sum_s=11,step_wall_union_s=8,unowned_wall_s=2), 'overlapping steps cannot erase unowned wall')
        tiers = {name: dict(steps=[name], invocation_budget='fixture')
                 for name in ('fast', 'service', 'reference-certificate', 'extended')}
        tiers['fast']['finalize_steps'] = ['finalize']
        names = [*tiers, 'finalize']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lane = root/'.lane'
            lane.mkdir()
            for wall, expected, cold, old_cold, old_stall in ((1, False, False, False, .2), (1, False, False, True, .2), (2, False, True, False, .2), (3, True, True, False, .2), (3, True, False, False, .2), (3, True, False, False, .9)):
                baseline = dict(source="prior", provisional=True, tiers={name: dict(wall=4, selected_cases=[], resources={'node_scope':'node-wide','node_pressure_fraction':{'cpu.some':old_stall}}, step_figures={name: dict(wall=1, own_cpu_s=1, cargo_cpu_s=0.25, setup_cpu_s=0, layouts={"fixture":"fixture-layout"}, partial=old_cold)}) for name in names})
                for name in names:
                    actual = dict(owner='fixture', source='fixture', layout='fixture-layout', cargo_cpu_s=0.5, cold_target=cold, layout_changed=False)
                    synthetic = dict(actual, owner='synthetic', source='witness-source', cargo_cpu_s=100, cold_target=True)
                    (lane/f'gate-{name}-setup.jsonl').write_text('')
                    (lane/f'gate-{name}.log').write_text('   Compiling isolated-fixture v1.0\n'+'\n'.join('ISOLATION-COMPILE '+json.dumps(row) for row in (synthetic, actual)))
                for status, changed_selection in ((0, False), (1, False), (0, True), (0, 'rebuild')):
                    if changed_selection:
                        baseline["tiers"]["service"]["selected_cases"] = ["previous-case"]
                    else:
                        baseline["tiers"]["service"]["selected_cases"] = []
                    (lane/'gate-steps.tsv').write_text(''.join(f'{name}\t{status}\t0\t{wall}\n' for name in names))
                    output = io.StringIO()
                    rebuilding = changed_selection == 'rebuild'
                    with patch('devperf.budgets', return_value={'fixture': dict(budget_ms=2000), 'gate': dict(load_unresolved_pressure_percent=10, cpu_growth_percent=20, rebuild_steps=['service'] if rebuilding else [])}), patch('build_graph.baseline_context', return_value=(lane/'baseline.json', baseline, ['packages/records/src/ridge.rs'] if rebuilding else [], lane)), patch('harness.build_cache_state', return_value=dict(state='cold' if cold else 'warm', compiling_steps=['service'] if cold else [])), patch('gate_resources.raw_sample', return_value={'epoch_seconds':-10}), patch('gate_resources.joined', return_value={'node_scope':'node-wide','node_pressure_fraction':{'cpu.some':.4}}), patch('gate_resources.compact', return_value='busy=fixture stall=fixture'), patch('gate_resources.cpu_from_log', return_value=(1, 0)), patch('build_graph.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='tree')), patch.dict(os.environ, PN_GATE_SOURCE='fixture', PN_BUILDGRAPH_RUN='fixture-run', PN_IMPORT_BASE='fixture-base'), redirect_stdout(output):
                        tier_summary(root, SimpleNamespace(tiers=tiers), dict.fromkeys(names, 0))
                        measured = json.loads((lane/'gate-tiers.json').read_text())
                        if not cold:
                            with patch('build_graph.baseline_context', return_value=(lane/'baseline.json', None, [], lane)):
                                tier_summary(root, SimpleNamespace(tiers=tiers), dict.fromkeys(names, 0))
                            unreferenced = json.loads((lane/'gate-tiers.json').read_text())
                            for name in tiers:
                                self.assertIsNotNone(unreferenced[name]['comparable_cpu_s'], 'missing reference cannot erase current measured work')
                                self.assertIsNone(unreferenced[name]['baseline_comparable_cpu_s'])
                            # Exercise the actual archive writer, including every
                            # historical spelling of the retired classification.
                            from build_graph import peer_intersection
                            written = json.loads((lane/'gate-baseline.json').read_text())
                            expected_cpu = sum(row['comparable_cpu_s'] for row in unreferenced.values()
                                               if not any(figure['serialized_build'] for figure in row['step_figures'].values()))
                            for flag in ('absent', None, False, True):
                                archived = copy.deepcopy(written)
                                for row in archived['tiers'].values():
                                    for figure in row['step_figures'].values():
                                        if flag == 'absent':
                                            figure.pop('wait_dominated', None)
                                        else:
                                            figure['wait_dominated'] = flag
                                self.assertEqual(peer_intersection([written, archived]),
                                                 [expected_cpu, expected_cpu],
                                                 'written records must ignore obsolete waiting classifications')
                    self.assertEqual(json.loads((lane/'gate-baseline.json').read_text())['import_base_tree'], 'tree', 'archive provenance must name the declared base tree')
                    for name in tiers:
                        self.assertEqual(measured[name]['status'], status)
                        self.assertEqual(measured[name]['over_budget'], expected)
                        self.assertEqual(measured[name]['step_figures'][name]['partial'], cold)
                        self.assertEqual(measured[name]['step_figures'][name]['compiled'], cold and name == 'service', 'primary cache compilation reaches written step figures')
                        self.assertTrue(measured[name]['comparable_reason'], 'every unavailable comparable value names its reason')
                        self.assertEqual(measured[name]['step_figures'][name]['serialized_build'], rebuilding and name == 'service')
                        self.assertEqual(measured[name]['partial_steps'], [name] if cold else [])
                        self.assertEqual(measured[name]['step_figures'][name]['layouts'], {'fixture':'fixture-layout'})
                        self.assertEqual(measured[name]['build_cpu_s'], 0.5)
                        self.assertEqual(measured[name]['compiling_steps'], ['service'] if cold and name == 'service' else [], 'only cache receipt steps give cold precedence')
                        self.assertEqual(measured[name]['isolated_compiling_steps'], [dict(step=name, owner='fixture', cold_target=cold, compiled=None)], 'isolated compiles retain their own target state')
                        self.assertTrue(measured[name]['baseline_provisional'])
                        selection_differs = changed_selection and name == 'service'
                        self.assertEqual(measured[name]['comparable_cases'], not selection_differs)
                        self.assertEqual(measured[name]['comparable_build_cpu_s'], None if cold or old_cold else 0.5)
                        self.assertEqual(measured[name]['baseline_comparable_build_cpu_s'], None if cold or old_cold else 0.25)
                        if selection_differs:
                            self.assertIsNone(measured[name]['comparable_cpu_s'])
                            self.assertIsNone(measured[name]['baseline_comparable_cpu_s'])
                        self.assertEqual(measured[name]['excess_s'], max(0, wall-2))
                        self.assertEqual(measured[name]['baseline_stall'], old_stall)
                        if wall == 3 and not cold:
                            self.assertEqual(measured[name]['classification'], 'load-unresolved')
                    if cold and expected:
                        self.assertEqual(measured['service']['classification'], 'cold-cache', 'a compiling tier has cold precedence')
                        self.assertNotEqual(measured['fast']['classification'], 'cold-cache', 'overlap does not assign another tier its compilation')
                    self.assertFalse(measured['finalize']['over_budget'])
                    self.assertIsNone(measured['finalize']['excess_s'])
                    self.assertIn('verdict='+('red' if status else 'green'), output.getvalue())
                    self.assertIn('over_budget='+str(expected).lower(), output.getvalue())
                    self.assertIn('own_user_s=1 own_sys_s=0', output.getvalue())
                    self.assertIn('unowned_wall_s=0.000000',output.getvalue())
                    self.assertEqual(measured['fast']['step_wall_sum_s'],wall)
                    fast = next(line for line in output.getvalue().splitlines() if line.startswith('GATE-TIER tier=fast '))
                    self.assertIn('over_budget='+str(expected).lower(), fast)
                    self.assertIn('baseline_source=prior baseline_provisional=true', fast)
                    self.assertIn('isolated_compiling_steps=', fast)
                    self.assertIn('excess_s='+str(max(0.0, wall-2.0)), fast)

    def test_whole_gate_warning(self):
        """The whole critical path keeps its own warning and baseline while preserving the functional verdict.
        ´claim:devperf:whole-gate-warning-preserves-verdict´
        ´test:integration:test-whole-gate-warning´
        """
        from contextlib import redirect_stdout
        from build_graph import wall_summary, declare_run
        from devperf import whole_gate_declaration
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {}, clear=True), patch('build_graph.subprocess.run', return_value=SimpleNamespace(stdout='source\n')):
                with self.assertRaisesRegex(ValueError, 'PN_GATE_PLAN must declare'):
                    declare_run(root)
            for plan in ('one-run', 'warm-after-cold-first', 'refresh-first', 'refresh-second', 'warm-after-cold-second'):
                output = io.StringIO()
                with patch.dict(os.environ, PN_GATE_PLAN=plan, PN_GATE_FIRST_CACHE='cold', PN_GATE_ENTRY='fixture:entry'), patch('build_graph.subprocess.run', return_value=SimpleNamespace(stdout='source\n')), redirect_stdout(output):
                    declared_run = declare_run(root)
                self.assertTrue(output.getvalue().startswith('GATE-DECLARED plan='+plan+' '))
                self.assertEqual(json.loads((root/'.lane/gate-declaration.json').read_text()), declared_run)
            for cache in ('warm', 'unknown', 'unavailable'):
                with patch.dict(os.environ, PN_GATE_PLAN='warm-after-cold-second', PN_GATE_FIRST_CACHE=cache, PN_GATE_ENTRY='fixture:entry'), patch('build_graph.subprocess.run', return_value=SimpleNamespace(stdout='source\n')):
                    with self.assertRaisesRegex(ValueError, 'first observed cache to be cold'):
                        declare_run(root)
            for entry_id in ('', 'invalid space', 'a'*129):
                with patch.dict(os.environ, PN_GATE_PLAN='one-run', PN_GATE_ENTRY=entry_id), patch('build_graph.subprocess.run', return_value=SimpleNamespace(stdout='source\n')):
                    with self.assertRaisesRegex(ValueError, 'PN_GATE_ENTRY'):
                        declare_run(root)
            for first_cache in ('unknown', 'unavailable', 'invented'):
                with patch.dict(os.environ, PN_GATE_PLAN='refresh-second', PN_GATE_ENTRY='fixture:entry', PN_GATE_FIRST_CACHE=first_cache), patch('build_graph.subprocess.run', return_value=SimpleNamespace(stdout='source\n')):
                    with self.assertRaisesRegex(ValueError, 'first cache receipt|unknown form'):
                        declare_run(root)
            with patch.dict(os.environ, PN_GATE_PLAN='one-run', PN_GATE_ENTRY='fixture:entry', PN_GATE_FIRST_CACHE='invented'), patch('build_graph.subprocess.run', return_value=SimpleNamespace(stdout='source\n')):
                with self.assertRaisesRegex(ValueError, 'unknown form'):
                    declare_run(root)
            with patch.dict(os.environ, PN_GATE_PLAN='refresh-second', PN_GATE_ENTRY='fixture:entry', PN_GATE_FIRST_CACHE='warm'), patch('build_graph.subprocess.run', return_value=SimpleNamespace(stdout='source\n')):
                self.assertEqual(declare_run(root)['entry'], 'fixture:entry')
            entry = (Path(__file__).parent/'gate.sh').read_text()
            with patch.dict(os.environ, PN_GATE_PLAN='one-run', PN_GATE_ENTRY='fixture:sample', PN_GATE_SAMPLE='import-transition', PN_GATE_SERIES='fixture', PN_GATE_ORDINAL='1', PN_IMPORT_BASE='source', PN_GATE_SERIES_KEY='a'*64, PN_GATE_SERIES_CACHE='warm', PN_GATE_SERIES_COUNT='5', PN_GATE_CONTAINER_LIST='["fixture-list"]',PN_GATE_SERVICE_LIST='["fixture-services"]'), patch('build_graph.subprocess.run', return_value=SimpleNamespace(stdout='source\n')):
                with patch('isolation.import_base', return_value='base'):
                    self.assertEqual(declare_run(root)['sample'], 'import-transition')
                    from build_graph import series_receipt
                    (root/'.lane/gate-wall.json').write_text('{"stall":0.05}')
                    (root/'.lane/instructions-probe.json').write_text('{"state":"unavailable"}')
                    (root/'.lane/gate-series-host-start.json').write_text(json.dumps(dict(boundary='start', identity=dict(PN_GATE_SERIES='fixture', PN_GATE_ORDINAL='1', PN_GATE_ENTRY='fixture:sample'))))
                    (root/'.lane/gate-baseline.json').write_text(json.dumps(dict(cache=dict(state='warm',compiled=dict(primary=[],lint=[])),path=str(root/('a'*64)/'tree.json'))))
                    observed=SimpleNamespace(returncode=0,stdout='[]',stderr='')
                    with patch.dict(os.environ, PN_BUILDGRAPH_RUN='sample'), patch('build_graph.subprocess.run',return_value=observed), patch('build_graph.subprocess.check_output',side_effect=lambda argv,**kw: '' if argv[1]=='diff' else 'tree'), patch('build_graph.reference_key',return_value='a'*64), patch('harness.load'):
                        series_receipt(root,'start')
                        series_receipt(root,'end')
                        receipt=json.loads((root/'.lane/gate-series-end.json').read_text())
                        self.assertEqual(receipt['declaration']['ordinal'],'1')
                        self.assertEqual(receipt['observed_cache'],'warm')
                        self.assertIn('processes',receipt)
                        from build_graph import series_idle
                        series_idle(root,'end')
                        joined=json.loads((root/'.lane/gate-series-end.json').read_text())
                        self.assertEqual(joined['host_idle_end']['identity'],joined['host_idle_start']['identity'])
                        self.assertEqual(joined['host_idle_end']['container_command'],['fixture-list'],'host receipt records the invoker-selected listing argv')
                        with patch.dict(os.environ, PN_GATE_ENTRY='different'):
                            with self.assertRaisesRegex(ValueError,'another invocation'):
                                series_idle(root,'end')
                        (root/'.lane/gate-baseline.json').write_text(json.dumps(dict(cache=dict(state='cold',compiled=dict(primary=['p'],lint=[])),path=str(root/('a'*64)/'tree.json'))))
                        with self.assertRaisesRegex(ValueError,'differs from declared',msg='sample cache mismatch refuses membership'):
                            series_receipt(root,'end')
                        (root/'.lane/gate-baseline.json').write_text(json.dumps(dict(cache=dict(state='warm',compiled=dict(primary=[],lint=[])),path=str(root/('b'*64)/'tree.json'))))
                        with self.assertRaisesRegex(ValueError,'differs from declared',msg='sample observed key mismatch refuses membership'):
                            series_receipt(root,'end')

            with patch.dict(os.environ, PN_GATE_PLAN='one-run', PN_GATE_ENTRY='fixture:sample', PN_GATE_SAMPLE='other'):
                with self.assertRaisesRegex(ValueError, 'PN_GATE_SAMPLE'):
                    declare_run(root)
            self.assertLess(entry.index('build_graph.py declare'), entry.index('TMPDIR'))
        campaign = dict(label='campaign:devperf:whole-gate-mixed', warmup_commit='a'*40, source_commit='b'*40,
                        discarded_warmup_ms=2000, rebuild_wall_ms=1200, warm_walls_ms=[1000, 1100, 1150],
                        multiplier=1.25, round_ms=50, sample_choice='maximum-of-rebuild-and-three-warm', configuration='fixture')
        declared = {'gate':dict(warm_samples=3, allowance_multiple=2, allowance_round_ms=50),
                    'whole-gate':dict(budget_ms=1500, wall_multiple=1.25, wall_campaign=campaign)}
        whole_gate_declaration(declared)
        bad = copy.deepcopy(declared)
        bad['service-gate'] = dict(budget_ms=1501)
        with self.assertRaisesRegex(StructuralError, 'below the largest tier'):
            whole_gate_declaration(bad)
        bad = copy.deepcopy(declared)
        bad['whole-gate']['budget_ms'] -= 1
        with self.assertRaisesRegex(StructuralError, 'bound differs'):
            whole_gate_declaration(bad)
        bad = copy.deepcopy(declared)
        bad['whole-gate']['wall_campaign']['warm_walls_ms'].pop()
        with self.assertRaisesRegex(StructuralError, 'malformed'):
            whole_gate_declaration(bad)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lane = root/'.lane'
            lane.mkdir()
            measured = dict(step='gate', wall_seconds=1.2, own_user_s=1, own_sys_s=.1,
                            node_scope='node-wide', node_pressure_fraction={'cpu.some':.2}, start={'epoch_seconds':1}, end={'epoch_seconds':2.2})
            (lane/'gate-declaration.json').write_text(json.dumps(dict(source='fixture',entry='fixture-entry',plan='one-run',sample='import')))
            (lane/'gate-resources.json').write_text(json.dumps([measured]))
            (lane/'gate-steps.tsv').write_text('fixture\t0\t1.2\t1.9\n')
            figures = dict(comparable_cases=True, comparable_cpu_s=1, baseline_comparable_cpu_s=1, comparable_build_cpu_s=.5,
                           baseline_comparable_build_cpu_s=.5, compile_wall_growth_s=0,
                           own_user_s=1, own_sys_s=0, baseline_cpu_s=1,
                           changed_build_inputs=[], baseline_source='prior', baseline_provisional=True, baseline_match='import-base-tree')
            for status in (0, 1):
                pending = dict(source='fixture', tiers={'fast':figures}, previous_whole={'wall':2, 'stall':.1, 'own_user_s':1, 'own_sys_s':.1})
                (lane/'gate-baseline.json').write_text(json.dumps(pending))
                output = io.StringIO()
                with patch('devperf.budgets', return_value={'gate':{'cpu_growth_percent':20,'load_unresolved_pressure_percent':10,'series_pressure_multiple':2,'series_absolute_pressure':.1,'series_relative_floor':.08,'series_attempts_per_ordinal':3,'series_policy_provisional':True}, 'whole-gate':{'budget_ms':1000}}), patch('build_graph.subprocess.run', return_value=SimpleNamespace(returncode=0)) as run, patch.dict(os.environ, PN_GATE_SOURCE='fixture', PN_GATE_PARALLEL='1'), redirect_stdout(output):
                    self.assertEqual(wall_summary(root, status), 0)
                result = json.loads((lane/'gate-wall.json').read_text())
                self.assertEqual(result['status'], status)
                self.assertAlmostEqual(result['preparation_s'], .2)
                self.assertAlmostEqual(result['closing_s'], .3)
                self.assertAlmostEqual(result['step_span_s'], .7, msg='step span must partition the whole wall between preparation and closing')
                self.assertAlmostEqual(result['preparation_s']+result['step_span_s']+result['closing_s'], result['wall'])
                self.assertTrue(result['over_budget'])
                self.assertEqual(result['classification'], 'load-unresolved')
                requests = [line.removeprefix('GATE-QUIET-REPEAT ') for line in output.getvalue().splitlines()
                            if line.startswith('GATE-QUIET-REPEAT ')]
                self.assertTrue(requests, 'a loaded excess must print a quiet-repeat request')
                repeat = json.loads(requests[0])
                self.assertTrue(repeat['required'], 'a loaded excess must print its owed quiet repeat')
                self.assertEqual(result['baseline_stall'], .1)
                self.assertEqual(result['baseline_source'], 'prior')
                self.assertTrue(result['baseline_provisional'])
                self.assertIn('baseline_source=prior baseline_provisional=true', output.getvalue())
                self.assertAlmostEqual(result['comparable_cpu_s'], 1.1)
                self.assertAlmostEqual(result['baseline_comparable_cpu_s'], 1.1)
                self.assertIn('GATE-WALL WALL=1.200000s verdict='+('green' if status == 0 else 'red'), output.getvalue())
                retained = json.loads((lane/'gate-baseline.json').read_text())
                self.assertEqual(retained['whole'], result)
                self.assertNotIn('previous_whole', retained)
                self.assertIn('exit:'+str(status), run.call_args.args[0])
            (lane/'gate-resources.json').unlink()
            (lane/'gate-baseline.json').write_text(json.dumps(dict(source='fixture',tiers={})))
            output = io.StringIO()
            with patch('devperf.budgets', return_value={'gate':{'cpu_growth_percent':20,'load_unresolved_pressure_percent':10,'series_pressure_multiple':2,'series_absolute_pressure':.1,'series_relative_floor':.08,'series_attempts_per_ordinal':3,'series_policy_provisional':True}, 'whole-gate':{'budget_ms':1000}}), patch('build_graph.subprocess.run', return_value=SimpleNamespace(returncode=0)), patch.dict(os.environ, PN_GATE_SOURCE='fixture', PN_GATE_PARALLEL='1'), redirect_stdout(output):
                self.assertEqual(wall_summary(root, 0, (1, 2.2)), 0)
            self.assertIn('baseline_provisional=unavailable',output.getvalue())
            self.assertNotIn('baseline_provisional=null',output.getvalue())
            unavailable = json.loads((lane/'gate-wall.json').read_text())
            self.assertIsNone(unavailable['own_user_s'])
            self.assertEqual(unavailable['comparable_reason'], 'missing-or-incompatible-step-case-or-resource-measurements')
            self.assertEqual(unavailable['classification'], 'unclassified')
            self.assertEqual(unavailable['status'], 0)
            registry = root/'registry.toml'
            registry.write_text('rows = []\n')
            argv = ['devperf', '--operation', 'gate::whole', '--budget', 'whole-gate',
                    '--overrun-class', 'high-stall', '--duration-s', '1.2', '--outcome', 'exit:0',
                    '--findings', str(root/'findings.json'), '--registry', str(registry)]
            from devperf import main
            with patch('sys.argv', argv), patch('devperf.budgets', return_value=declared), patch('devperf.report', return_value=0) as report_call:
                self.assertEqual(main(), 0)
            record = report_call.call_args.args[0][0]
            self.assertEqual(record['tier'], 'whole')
            self.assertEqual(record['overrun_class'], 'high-stall')
            self.assertEqual(record['applicable_budgets'], ['whole-gate'])
            finding, = assess({**record, 'duration_ms':2500, 'outcome':'exit:1'},
                              {'whole-gate':dict(budget_ms=2400, category='aggregate')})
            self.assertEqual(finding['classification'], 'high-stall')
            self.assertEqual(finding['outcome'], 'exit:1')
            self.assertEqual(finding['verdict_effect'], 'none')
    def test_overrun_classes(self):
        """Rebuild classification requires comparable compile CPU growth and serialized compile wall growth covering the excess; changed case sets retain compile evidence but not aggregate comparisons, and load alone cannot establish rebuild work.
        ´claim:devperf:rebuild-requires-compile-cpu-and-wall´
        ´test:integration:test-overrun-classes´
        """
        from build_graph import overrun_class
        policy = dict(load_unresolved_pressure_percent=10, cpu_growth_percent=20)
        def classify(own=100, baseline=100, stall=0.09, build=40, old_build=40, changed=()):
            return overrun_class(True, own, baseline, stall, build, old_build, changed, policy, compile_wall_growth=build-old_build, excess=21, wall=210, baseline_wall=189, baseline_stall=0)
        self.assertEqual(classify(), 'plain')
        self.assertEqual(classify(own=120), 'plain')
        self.assertEqual(classify(stall=0.1), 'high-stall')
        self.assertEqual(classify(own=121), 'growth')
        self.assertEqual(classify(own=121, build=61, changed=['packages/example/src/pins.rs']), 'rebuild')
        self.assertEqual(classify(own=120, build=60, changed=['packages/example/src/pins.rs']), 'plain')
        self.assertEqual(classify(own=150, build=60, changed=['packages/example/src/pins.rs']), 'growth')
        self.assertEqual(classify(own=121, build=61), 'growth')
        self.assertEqual(classify(own=121, build=61, changed=['Cargo.lock'], stall=0.1), 'high-stall')
        self.assertEqual(classify(baseline=None), 'unclassified')
        self.assertEqual(classify(stall=None), 'unclassified')
        for invalid in (None, -1, 1, float('nan'), float('inf'), 'bad', True):
            self.assertEqual(overrun_class(True, 100, 100, .4, 40, 40, [], policy,
                wall=200, baseline_wall=100, baseline_stall=invalid, excess=80), 'load-unresolved')
            self.assertEqual(overrun_class(True, 100, 100, invalid, 40, 40, [], policy,
                wall=200, baseline_wall=100, baseline_stall=.1, excess=80), 'unclassified')
        self.assertEqual(overrun_class(True, 100, 100, .05, 12.7, 1, ['source'], policy,
            compile_wall_growth=.95, excess=19.5, wall=139.5, baseline_wall=144.5, baseline_stall=.05),
            'plain', 'compile growth must explain the whole excess')
        self.assertEqual(overrun_class(True, 100, 100, 0, 120, 100, ['Cargo.lock'], policy,
            compile_wall_growth=60, excess=21, wall=141, baseline_wall=100, baseline_stall=0), 'plain')
        # The line is continuous: 5 percent pressure can explain an overrun,
        # while 15 percent pressure cannot excuse a wall beyond its projection.
        for stall in (.05, .15):
            projected = 118*(1-.01)/(1-stall)
            for delta, expected in ((-.001, 'load-unresolved' if stall > .1 else 'high-stall'), (.001, 'load-unresolved' if stall > .1 else 'plain')):
                self.assertEqual(overrun_class(True, 100, 100, stall, 40, 40, [], policy,
                    wall=projected+delta, baseline_wall=118, baseline_stall=.01, excess=projected+delta-120), expected)
        # A previously over-budget baseline cannot turn zero or insufficient
        # stall into an explanation for an otherwise unchanged overrun.
        for stall in (0, .01):
            self.assertEqual(overrun_class(True, 100, 100, stall, 40, 40, [], policy,
                wall=130, baseline_wall=135, baseline_stall=0, excess=10), 'plain')
        for cpu in (100, 150):
            self.assertEqual(overrun_class(True, cpu, 100, .4, 40, 40, [], policy,
                wall=200, baseline_wall=100, baseline_stall=.05, excess=80), 'load-unresolved')
        self.assertEqual(overrun_class(True, 532.7, 406.1, .325, 100, 1, ['source'], policy,
            compile_wall_growth=100, wall=200, baseline_wall=150, baseline_stall=.049, excess=20),
            'load-unresolved', 'a loaded run cannot establish a cost change even with apparent compile growth')
        # Projection is slack here, so only whole-excess coverage decides.
        boundary = 120/(1-.1)
        for delta, expected in ((-.001, 'high-stall'), (.001, 'plain')):
            wall = boundary+delta
            self.assertEqual(overrun_class(True, 100, 100, .1, 40, 40, [], policy,
                wall=wall, baseline_wall=150, baseline_stall=.01, excess=wall-120), expected)
        from build_graph import status_changes
        self.assertEqual(status_changes({'case':{'selected':'passed'}, 'obligation':{'scope':'scoped-passed'}},
            {'case':{'selected':'held'}, 'obligation':{'scope':'held'}}), [
                dict(kind='case', name='selected', before='held', after='passed'),
                dict(kind='obligation', name='scope', before='held', after='scoped-passed')])
        self.assertEqual(status_changes({'case':{'same':'passed'}}, {'case':{'same':'passed'}}), [])
        self.assertEqual(overrun_class(False, None, None, None, None, None, [], policy), 'within-budget')
        from build_graph import compile_comparison
        cold = dict(wall=100, own_cpu_s=315, setup_cpu_s=0, layouts={'owner':'old'}, partial=True)
        old = {'test-build':dict(wall=3.8, own_cpu_s=103.153, setup_cpu_s=0, layouts={}, partial=False), 'isolated':cold}
        current = {'test-build':dict(wall=64.3, own_cpu_s=407.389, setup_cpu_s=0, layouts={}, partial=False),
                   'isolated':dict(cold, own_cpu_s=10, setup_cpu_s=0, layouts={'owner':'new'}, partial=False)}
        own, baseline, growth, omitted = compile_comparison(current, old, ['test-build'])
        self.assertEqual(omitted, ['isolated'])
        self.assertAlmostEqual(growth, 60.5)
        self.assertEqual(overrun_class(True, own, baseline, .0525, 407.389, 103.153,
            ['packages/epoch/src/controller.rs'], policy, compile_wall_growth=growth, excess=39.179, wall=159.179, baseline_wall=100, baseline_stall=0), 'rebuild')
        # Comparable compile CPU excludes the cold isolated baseline owner.
        self.assertEqual(overrun_class(True, 714.200, 684.486, .0525, 407.389, 103.153,
            ['packages/epoch/src/controller.rs'], policy, compile_wall_growth=growth, excess=39.179, wall=159.179, baseline_wall=100, baseline_stall=0), 'rebuild')
        self.assertEqual(overrun_class(True, 714.200, 684.486, .0525, 407.389, 418.153,
            ['packages/epoch/src/controller.rs'], policy, compile_wall_growth=growth, excess=39.179, wall=159.179, baseline_wall=100, baseline_stall=0), 'plain')
        self.assertEqual(overrun_class(True, 100, 100, .09, 40, 40,
            ['packages/example/src/pins.rs'], policy, compile_wall_growth=60, excess=21, wall=141, baseline_wall=100, baseline_stall=0), 'plain')
        # Round 149's rounded ridge extended figures: almost all extra CPU
        # compiled, including the isolated owner; serial wall cannot explain the excess.
        ridge = dict(compile_wall_growth=10.52, excess=30, wall=150,
                     baseline_wall=120, baseline_stall=0)
        self.assertAlmostEqual((182.2-87.6)/(91.8-.94), 1.0411622276)
        self.assertEqual(overrun_class(True, 182.2-87.6, 91.8-.94, .0349, 87.6, .94,
            ['packages/records/src/ridge.rs'], policy, **ridge), 'plain')
        self.assertEqual(overrun_class(True, 182.2-87.6, 91.8-.94, .0349, 87.6, .94,
            ['packages/records/src/ridge.rs'], policy, **(ridge | dict(compile_wall_growth=0))), 'plain')
        # The ridge's fast compile-CPU pair, with a controlled wall boundary:
        # a changed case set withholds aggregate CPU, not this compile evidence.
        for added in (False, True):
            self.assertEqual(overrun_class(True, None if added else 700, None if added else 300,
                .0349, 531.9, 111.2, ['packages/records/src/ridge.rs'], policy,
                **(ridge | dict(compile_wall_growth=30)), comparable_cases=not added), 'rebuild')
        self.assertEqual(overrun_class(True, None, None, .0349, 531.9, 111.2,
            ['packages/records/src/ridge.rs'], policy, **ridge, comparable_cases=False), 'unclassified')
        from build_graph import case_intersection
        from build_graph import case_producer_tier
        producer = SimpleNamespace(producing_step=lambda _: 'wallet-conformance')
        groups = {'fast':['tests'], 'service':['wallet-conformance']}
        receipt = dict(operation='fixture', tier='fast', step='wallet-conformance')
        self.assertEqual(case_producer_tier(producer, groups, receipt), 'service',
                         'case CPU follows its producing step, not its declared suite tier')
        with self.assertRaisesRegex(ValueError, 'producing step differs'):
            case_producer_tier(producer, groups, dict(receipt, step='tests'))
        with self.assertRaisesRegex(ValueError, 'no unique accounting tier'):
            case_producer_tier(producer, {'fast':['tests']}, receipt)
        own, old, comparable, evidence = case_intersection(
            ['common', 'new'], ['common', 'retained'], {'new': 80}, {'retained': 20}, 180, 120)
        self.assertEqual((own, old, comparable), (100, 100, True))
        self.assertEqual(evidence, dict(added=['new'], removed=['retained'], own_removed_s=80, baseline_removed_s=20))
        for owner, expected in (('matched', True), ('omitted', False), (None, False)):
            for adding in (True, False):
                current, previous = (['common', 'new'], ['common']) if adding else (['common'], ['common', 'new'])
                own_value, old_value = (180, 100) if adding else (100, 180)
                a, b, valid, _ = case_intersection(current, previous, {'new':80}, {'new':80}, own_value, old_value,
                    steps={'new':owner}, old_steps={'new':owner}, omitted=['omitted'])
                self.assertEqual(valid, expected, 'exclusive case must belong to a comparable step')
                self.assertEqual((a,b), (100,100) if expected else (None,None))
        self.assertEqual(overrun_class(True, own, old, .01, 40, 40, [], policy,
            **ridge, comparable_cases=comparable, comparable_wall=False), 'plain')
        # An added slow sleeper has printed CPU, but its wall is not compile
        # work. Removing that CPU cannot make aggregate walls comparable.
        own, old, comparable, _ = case_intersection(
            ['common', 'sleeper'], ['common'], {'sleeper': 1}, {}, 151-90, 100-40)
        for growth, expected in ((1, 'plain'), (30, 'rebuild')):
            self.assertEqual(overrun_class(True, own, old, .01, 90, 40,
                ['packages/example/src/lib.rs'], policy,
                **(ridge | dict(compile_wall_growth=growth)),
                comparable_cases=comparable, comparable_wall=False), expected)
        for unprinted in ({}, {'new':None}, {'new':float('nan')}, {'new':-1}):
            own, old, comparable, _ = case_intersection(['common', 'new'], ['common'], unprinted, {}, 180, 100)
            self.assertFalse(comparable)
            self.assertEqual(overrun_class(True, own, old, .01, 40, 40, [], policy,
                **ridge, comparable_cases=comparable, comparable_wall=False), 'unclassified')
        # Rebuilding either side, including an isolated owner's Cargo work,
        # cannot change the comparable non-build CPU or conceal a regression.
        def figures(build, isolated):
            return {'test-build':dict(wall=build, own_cpu_s=build, setup_cpu_s=0, layouts={}, partial=False),
                    'case':dict(wall=10, own_cpu_s=100+isolated, cargo_cpu_s=isolated,
                                setup_cpu_s=0, layouts={'owner':'same'}, partial=False)}
        for new_build, old_build in ((1,1), (238,1), (1,238), (238,238)):
            current, prior = figures(new_build, new_build), figures(old_build, old_build)
            own, old, _, omitted = compile_comparison(current, prior, ['test-build'])
            self.assertEqual((own, old, omitted), (100,100,[]))
            current['case']['own_cpu_s'] += 21
            own, old, _, _ = compile_comparison(current, prior, ['test-build'])
            self.assertEqual(overrun_class(True, own, old, 0, new_build*2, old_build*2, [], policy,
                compile_wall_growth=0, wall=150, baseline_wall=120, baseline_stall=0, excess=30), 'growth')

        # Recorded first/second-run claim-tests totals: 12.5 versus 3.3.
        # Fetch CPU was not retained historically; the 9.2 difference is a
        # controlled attribution, not a recovered measurement of that fetch.
        first = {'claim-tests':dict(wall=5, own_cpu_s=12.5, cargo_cpu_s=0,
                                   setup_cpu_s=9.2, layouts={}, partial=False)}
        second = {'claim-tests':dict(first['claim-tests'], own_cpu_s=3.3, setup_cpu_s=0)}
        for left, right in ((first,second),(second,first)):
            own, old, _, omitted = compile_comparison(left, right, [])
            self.assertAlmostEqual(own, old, places=10, msg='setup must not become program growth')
            self.assertEqual(omitted, [])
        unmetered = {'claim-tests':{k:v for k,v in first['claim-tests'].items() if k != 'setup_cpu_s'}}
        self.assertEqual(compile_comparison(first, unmetered, [])[3], ['claim-tests'])
        # Recorded serial tracker pair: assert exactly the removed component,
        # not a tolerance fitted to this pair's unexplained residual.
        first = {'tests':dict(wall=29.210007, own_cpu_s=27.405551, cargo_cpu_s=0,
                             setup_cpu_s=17.998947, layouts={}, partial=False)}
        second = {'tests':dict(first['tests'], wall=8.767859, own_cpu_s=7.486846, setup_cpu_s=.169108)}
        for left, right in ((first,second),(second,first)):
            own, old, _, _ = compile_comparison(left, right, [])
            self.assertAlmostEqual(own, left['tests']['own_cpu_s']-left['tests']['setup_cpu_s'])
            self.assertAlmostEqual(old, right['tests']['own_cpu_s']-right['tests']['setup_cpu_s'])
        from isolation import setup_receipt, bind_setup
        from build_graph import instruction_probe, measured_command, peer_cost
        for stale in (True, None, False):
            bounded = {'tests':dict(second['tests'], wait_dominated=stale, serialized_build=False)}
            self.assertAlmostEqual(compile_comparison(bounded, bounded, [])[0], 7.486846-.169108,
                                   'raw receipts must survive obsolete ratio classifications')
            archived = dict(whole=dict(wall=10, own_user_s=7.486846, own_sys_s=0, comparable_cpu_s=None),
                            tiers={'fast':dict(step_figures=bounded)})
            with patch.dict(os.environ, PN_GATE_REFERENCE_STALL_CEILING='.9', PN_GATE_REFERENCE_STALL_BAND='.9', PN_GATE_REFERENCE_COUNT_MARGIN='.1', PN_GATE_REFERENCE_NOISE_MARGIN='.2', PN_GATE_REFERENCE_STALL_MARGIN='.01'):
                self.assertIsNotNone(peer_cost(archived)[1], 'raw cost must remain available despite stored null')
                self.assertAlmostEqual(peer_cost(archived)[1], 7.486846-.169108, msg='stored classification cannot override raw cost')
        from build_graph import case_intersection
        # A case clock can include the compilation already removed from its
        # step: 29.162 - 9.655 - 9.133 - 16.466 = -6.092 seconds.
        for left, right in ((['new'], []), ([], ['new'])):
            result = case_intersection(left, right, {'new':16.466}, {'new':16.466}, 100, 100,
                steps={'new':'discipline-tests'}, old_steps={'new':'discipline-tests'},
                build_steps={'discipline-tests'}, old_build_steps={'discipline-tests'})
            self.assertFalse(result[2], 'a larger tier total must not conceal overlapping case and build clocks')
            self.assertIn('overlap removed build CPU', result[3]['reason'])


    def test_counter_execution(self):
        """The counter preserves exit and signal status and falls back only before a workload starts.
        ´claim:devperf:counter-execution´
        ´test:integration:test-counter-execution´
        """
        from build_graph import instruction_probe, measured_command
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'.lane').mkdir()
            with patch.dict(os.environ, PN_BUILDGRAPH_RUN='counter-probe'), patch('build_graph.shutil.which', return_value=None), patch('builtins.print') as printed:
                instruction_probe(root)
                with patch('build_graph.cancellable', return_value=SimpleNamespace(returncode=0)) as invoked:
                    measured_command(root, ['true'])
                invoked.assert_called_once_with(['true'], reap_tree=True)
                self.assertIn('unavailable', str(printed.call_args_list))
            stub = root/'counter'
            stub.write_text('#!'+sys.executable+'\nimport sys,subprocess\nfrom pathlib import Path\n'
                'Path(sys.argv[sys.argv.index("-o")+1]).write_text("42;;instructions;1;100.00\\n")\n'
                'subprocess.run(sys.argv[sys.argv.index("--")+1:])\nsys.exit(0)\n')
            stub.chmod(0o755)
            (root/'.lane/instructions-probe.json').write_text(json.dumps(dict(run='counter-probe', executable=str(stub))))
            with patch.dict(os.environ, PN_BUILDGRAPH_RUN='counter-probe', PN_GATE_STEP='fixture'), patch('builtins.print') as printed:
                self.assertEqual(measured_command(root, [sys.executable,'-c','raise SystemExit(7)']).returncode, 7, 'counter success cannot replace workload exit status')
                self.assertIn('retired=42', str(printed.call_args_list))
                self.assertEqual(measured_command(root, [sys.executable,'-c','import os,signal;os.kill(os.getpid(),signal.SIGTERM)']).returncode, -15,
                                 'counter success cannot hide a signal-ended workload')
                stub.write_text('#!'+sys.executable+'\nraise SystemExit(1)\n')
                once=root/'once'
                result=measured_command(root, [sys.executable,'-c','from pathlib import Path; p=Path('+repr(str(once))+'); p.write_text(p.read_text()+"x" if p.exists() else "x")'])
                self.assertEqual(result.returncode, 0, 'counter open failure must permit one uncounted run')
                self.assertEqual(once.read_text(), 'x', 'failed counter open runs the workload once')
                self.assertIn('retired=unavailable', str(printed.call_args_list))


    def test_setup_receipt_binding(self):
        """Setup accounting subtracts the bound whole owner window once and refuses legacy or foreign receipts.
        ´claim:devperf:setup-receipt-binding´
        ´test:integration:test-setup-receipt-binding´
        """
        from isolation import setup_receipt, bind_setup
        from build_graph import setup_accounting
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'setup.jsonl'
            with patch.dict(os.environ, PN_GATE_SETUP_LOG=str(path), PN_GATE_SETUP_SOURCE='gate-source',
                            PN_GATE_STEP='tests', PN_BUILDGRAPH_RUN='run', PN_GATE_CASE='ci::fixture.case'), patch('builtins.print'):
                bind_setup(path, 'gate-source', 'run', 'tests')
                setup_receipt(dict(owner='nested-tracker', source='gate-source', action='owner-window',
                                   wall=3, own_user_s=8.2, own_sys_s=1, status=0))
            self.assertEqual(setup_accounting(path, 'gate-source', 'run', 'tests'),
                             dict(setup_cpu_s=9.2, setup_wall_s=3, setup_calls=1, setup_case_cpu_s={'ci::fixture.case':9.2}, fixture_git_cpu_s=0))
            with self.assertRaisesRegex(ValueError, 'stale isolation setup receipt'):
                setup_accounting(path, 'gate-source', 'other-run', 'tests')
            data = json.loads(path.read_text());data['source'] = 'synthetic-fixture-commit'
            path.write_text(json.dumps(data)+'\n')
            self.assertEqual(setup_accounting(path, 'gate-source', 'run', 'tests'),
                             dict(setup_cpu_s=0, setup_wall_s=0, setup_calls=0, setup_case_cpu_s={}, fixture_git_cpu_s=9.2),
                             'synthetic fixture Git remains program work')
            for action in ('clone','fetch','checkout','clean'):
                stale = dict(data, action=action)
                path.write_text(json.dumps(stale)+'\n')
                with self.assertRaisesRegex(ValueError, 'invalid isolation setup receipt', msg='legacy or malformed owner accounting must refuse'):
                    setup_accounting(path, 'gate-source', 'run', 'tests')
            with patch.dict(os.environ, PN_GATE_SETUP_LOG=str(path), PN_GATE_SETUP_SOURCE='gate-source', PN_GATE_STEP='tests', PN_BUILDGRAPH_RUN='other'):
                with self.assertRaisesRegex(ValueError, 'another invocation', msg='foreign invocation must refuse'):
                    setup_receipt(data)
            path.with_suffix('.binding.json').unlink()
            with patch.dict(os.environ, PN_GATE_SETUP_LOG=str(path)):
                with self.assertRaisesRegex(ValueError, 'unbound isolation setup log'):
                    setup_receipt(data)
            data['own_user_s'] = -1
            path.write_text(json.dumps(data)+'\n')
            with self.assertRaisesRegex(ValueError, 'invalid isolation setup receipt', msg='legacy or malformed owner accounting must refuse'):
                setup_accounting(path, 'gate-source', 'run', 'tests')


    def test_benchmark_build_accounting(self):
        """Mixed benchmark accounting removes only observed no-run build CPU and keeps validation work.
        ´claim:devperf:benchmark-build-accounting´
        ´test:integration:test-benchmark-build-accounting´
        """
        from build_graph import compile_comparison, overrun_class
        policy = dict(load_unresolved_pressure_percent=10,cpu_growth_percent=20)
        # The mixed benchmark step must remove only its no-run builds, not
        # validation. Exercise the producer and its emitted accounting too.
        import benchmarks
        import contextlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'source.stdout.log').write_text('fixture-source\n')
            (root/'target/gate').mkdir(parents=True)
            command = ['cargo', 'bench', '-p', 'pn-interchange', '--bench', 'foundation',
                       '--profile', 'gate', '--no-run']
            def build(cpu):
                rows = []
                (root/'build.stdout.log').write_text(json.dumps(dict(reason='compiler-artifact',package_id='fixture',fresh=cpu == 1))+'\n')
                usage = [SimpleNamespace(ru_utime=3, ru_stime=2),
                         SimpleNamespace(ru_utime=3+cpu, ru_stime=2)]
                with patch.dict(os.environ, CARGO_TARGET_DIR=str(root/'target')), \
                     patch.object(benchmarks.resource, 'getrusage', side_effect=usage), \
                     patch.object(benchmarks, 'capture', return_value=(0, 7000)) as capture:
                    self.assertEqual(benchmarks.capture_build(command, root, 'build', rows), (0,7000))
                    capture.assert_called_once_with(command, root, 'build')
                self.assertEqual(rows[0]['cargo_cpu_s'], cpu)
                self.assertEqual(rows[0]['cargo_wall_s'], 7)
                self.assertEqual(rows[0]['compiled'], [] if cpu == 1 else ['fixture'], 'artifact freshness alone decides actual benchmark compilation')
                out, err = io.StringIO(), io.StringIO()
                def run(records):
                    records.extend(rows)
                    return {'status':'passed'}, 0
                with patch.object(benchmarks, 'run', side_effect=run), \
                     patch.object(benchmarks.sys, 'argv', ['benchmarks.py']), \
                     contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(benchmarks.main(), 0)
                self.assertEqual(json.loads(out.getvalue()), {'status':'passed'})
                line, = err.getvalue().splitlines()
                self.assertTrue(line.startswith('ISOLATION-COMPILE '))
                measured = json.loads(line.removeprefix('ISOLATION-COMPILE '))
                self.assertEqual(measured, rows[0])
                return dict(wall=10, own_cpu_s=100+cpu, cargo_cpu_s=measured['cargo_cpu_s'],
                            setup_cpu_s=0, layouts={measured['owner']:measured['layout']}, partial=measured['cold_target'])
            for current_build, previous_build in ((1,1), (53,1), (1,53), (53,53)):
                current = {'benchmarks':build(current_build)}
                prior = {'benchmarks':build(previous_build)}
                own, old, _, omitted = compile_comparison(current, prior, ['test-build'])
                self.assertEqual((own, old, omitted), (100,100,[]))
                current['benchmarks']['own_cpu_s'] += 21
                own, old, _, _ = compile_comparison(current, prior, ['test-build'])
                self.assertEqual(overrun_class(True, own, old, 0, current_build, previous_build, [], policy,
                    compile_wall_growth=0, wall=150, baseline_wall=120, baseline_stall=0, excess=30), 'growth')

    def test_reference_cache_order(self):
        """Cache rank keeps cold references provisional and refuses cold replacement of warm evidence.
        ´claim:devperf:reference-cache-order´
        ´test:integration:test-reference-cache-order´
        """
        def windows(stall=0):
            return {phase: dict(node_scope='node-wide', node_pressure_fraction={'cpu.some':stall}, wall_seconds=5)
                    for phase in ('before', 'after')}
        def recorded(cache, stall, provisional=False):
            return dict(cache=dict(state=cache), provisional=provisional, whole=dict(node_scope='node-wide',stall=stall))
        from build_graph import baseline_context, retain_baseline, baseline_replacement, baseline_rank
        from build_graph import preferred_baseline, peer_frontier, prune_peer_archive
        from harness import build_cache_state, CONFIGURATION
        slow, fast = written_peer('slow',1177.5,.102), written_peer('fast',1093.8,.147)
        quiet_fast = written_peer('quiet-fast',1000,.05)
        peers = [written_peer('A',1000,.10),written_peer('B',1100,.05),written_peer('C',1050,.20)]
        from build_graph import overrun_class
        policy={'cpu_growth_percent':10,'load_unresolved_pressure_percent':10}
        args=(True,None,None,.8,None,None,[],policy)
        self.assertEqual(overrun_class(*args, cache_state='cold'), 'cold-cache')
        self.assertEqual(overrun_class(*args, cache_state='warm'), 'load-unresolved')
        self.assertEqual(overrun_class(False,*args[1:], cache_state='cold'), 'within-budget')
        cold, warm = recorded('cold', .060), recorded('warm', .081)
        self.assertEqual(baseline_replacement(warm, cold), (True, 'warm-replaces-cold-or-unknown'))
        self.assertEqual(baseline_replacement(cold, warm), (False, 'retained-warm-cache'))
        self.assertEqual(baseline_replacement(recorded('warm', .05), warm), (False, 'warm-peer-intersection-unavailable-margin'))
        self.assertEqual(baseline_replacement(recorded('warm', .09), warm), (False, 'warm-peer-intersection-unavailable-margin'))
        self.assertEqual(baseline_replacement(warm, None), (True, 'first-compatible-run-provisional'))
        self.assertEqual(baseline_replacement(warm, recorded('warm', .01, True)), (False, 'warm-peer-intersection-unavailable-margin'))
        self.assertEqual(baseline_replacement(recorded('unknown', .001), warm), (False, 'retained-warm-cache'))
        self.assertLess(baseline_rank(warm), baseline_rank(cold))
        self.assertGreater(baseline_rank(warm), baseline_rank(recorded('warm', .01, True)))

    def test_reference_confirmation(self):
        """Malformed unrelated records cannot interrupt confirmation of the retained warm reference.
        ´claim:devperf:reference-confirmation´
        ´test:integration:test-reference-confirmation´
        """
        from build_graph import retain_baseline
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'.lane').mkdir();(root/'peers').mkdir()
            old,new=written_peer('quiet',100,.05),written_peer('new',105,.05)
            for row in (old,new):
                row.update(provisional=True,load_unresolved_pressure_percent=10)
                row['quiet_windows']={phase:dict(node_scope='node-wide',node_pressure_fraction={'cpu.some':0},wall_seconds=5) for phase in ('before','after')}
            old_path=root/'quiet.json';old_path.write_text(json.dumps(old))
            (root/'malformed.json').write_text('{invalid');(root/'peers/malformed.json').write_text('{invalid')
            new.update(path=str(root/'new.json'),previous_reference=old,previous_baseline_tree=old['tree'])
            for sized in (False,True):
                (root/'.lane/gate-baseline.json').write_text(json.dumps(new))
                env=dict(PN_GATE_REFERENCE_NOISE_MARGIN='.1',PN_GATE_REFERENCE_STALL_CEILING='.1',PN_GATE_REFERENCE_STALL_BAND='.01') if sized else {}
                with patch.dict(os.environ,env,clear=True),patch('build_graph.evidence_statuses',return_value={}),redirect_stdout(io.StringIO()) as output:
                    try:retain_baseline(root)
                    except ValueError as error:self.fail('malformed unrelated file must not break confirmation: '+str(error))
                retained=json.loads(old_path.read_text())
                self.assertEqual(retained['provisional'],not sized,'confirmation requires a comparison that could replace')
                self.assertEqual(retained['whole'],old['whole'],'confirmation cannot change observed measurements')
                self.assertFalse((root/'new.json').exists(),'more costly candidate must not replace')
                self.assertIn('candidate_archived=true',output.getvalue(),'rejected quiet candidate archival is explicit')
                self.assertIn('two_way=',output.getvalue(),'decision prints the two-way evidence')
                if sized:
                    self.assertEqual(retained.get('confirmation_judgment',{}).get('policy',{}).get('cpu_margin'),.1,'confirmation keeps the policy that decided')

    def test_reference_archive_retention(self):
        """Unselected candidates cannot displace the incumbent through archive enumeration.
        ´claim:devperf:reference-archive-retention´
        ´test:integration:test-reference-archive-retention´
        """
        def windows(stall=0):
            return {phase: dict(node_scope='node-wide', node_pressure_fraction={'cpu.some':stall}, wall_seconds=5)
                    for phase in ('before', 'after')}
        def recorded(cache, stall, provisional=False):
            return dict(cache=dict(state=cache), provisional=provisional, whole=dict(node_scope='node-wide',stall=stall))
        from build_graph import baseline_context, retain_baseline, baseline_replacement, baseline_rank
        from build_graph import preferred_baseline, peer_frontier, prune_peer_archive
        from harness import build_cache_state, CONFIGURATION
        slow, fast = written_peer('slow',1177.5,.102), written_peer('fast',1093.8,.147)
        quiet_fast = written_peer('quiet-fast',1000,.05)
        peers = [written_peer('A',1000,.10),written_peer('B',1100,.05),written_peer('C',1050,.20)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'.lane').mkdir()
            incumbent = dict(peers[0],tree='same',quiet_windows=windows(),load_unresolved_pressure_percent=10)
            path = root/'same.json';path.write_text(json.dumps(incumbent))
            original = path.read_bytes()
            with patch('build_graph.evidence_statuses',return_value={}):
                for value in (peers[2],peers[1]):
                    candidate = dict(value,path=str(path),tree='same',previous_baseline_tree='same',quiet_windows=windows(),load_unresolved_pressure_percent=10)
                    (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
                    retain_baseline(root)
                    self.assertEqual(json.loads(path.read_text())['whole'],incumbent['whole'],
                                     'an unrelated archived peer cannot replace the incumbent')
            archived = [json.loads(path.read_text()) for path in (root/'peers').glob('*.json')]
            self.assertEqual({value['source'] for value in archived}, {'B','C'}, 'retention must not prune before ancestry is known')

    def test_reference_cold_provisional(self):
        """Repeated cold records never confirm a reference.
        ´claim:devperf:reference-cold-provisional´
        ´test:integration:test-reference-cold-provisional´
        """
        def windows(stall=0):
            return {phase: dict(node_scope='node-wide', node_pressure_fraction={'cpu.some':stall}, wall_seconds=5)
                    for phase in ('before', 'after')}
        def recorded(cache, stall, provisional=False):
            return dict(cache=dict(state=cache), provisional=provisional, whole=dict(node_scope='node-wide',stall=stall))
        from build_graph import baseline_context, retain_baseline, baseline_replacement, baseline_rank
        from build_graph import preferred_baseline, peer_frontier, prune_peer_archive
        from harness import build_cache_state, CONFIGURATION
        slow, fast = written_peer('slow',1177.5,.102), written_peer('fast',1093.8,.147)
        quiet_fast = written_peer('quiet-fast',1000,.05)
        peers = [written_peer('A',1000,.10),written_peer('B',1100,.05),written_peer('C',1050,.20)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'.lane').mkdir()
            path = root/'cold.json'
            for index in range(2):
                candidate = dict(recorded('cold', .05-index*.01), path=str(path), source='cold'+str(index), tree='same',
                                 quiet_windows=windows(), load_unresolved_pressure_percent=10)
                (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
                with patch('build_graph.evidence_statuses', return_value={}):
                    retain_baseline(root)
                self.assertTrue(json.loads(path.read_text())['provisional'], 'a second cold run must not confirm a reference')

    def test_reference_archive_selection(self):
        """Generated archive orders preserve the incumbent and selection after safe pruning.
        ´claim:devperf:reference-archive-selection´
        ´test:integration:test-reference-archive-selection´
        """
        def windows(stall=0):
            return {phase: dict(node_scope='node-wide', node_pressure_fraction={'cpu.some':stall}, wall_seconds=5)
                    for phase in ('before', 'after')}
        def recorded(cache, stall, provisional=False):
            return dict(cache=dict(state=cache), provisional=provisional, whole=dict(node_scope='node-wide',stall=stall))
        from build_graph import baseline_context, retain_baseline, baseline_replacement, baseline_rank
        from build_graph import preferred_baseline, peer_frontier, prune_peer_archive
        from harness import build_cache_state, CONFIGURATION
        slow, fast = written_peer('slow',1177.5,.102), written_peer('fast',1093.8,.147)
        quiet_fast = written_peer('quiet-fast',1000,.05)
        peers = [written_peer('A',1000,.10),written_peer('B',1100,.05),written_peer('C',1050,.20)]
        from build_graph import peer_frontier, prune_peer_archive
        import random
        generator = random.Random(2718)
        distinct = set()
        next_distinct = set()
        singleton_domains = ties = older_winners = 0
        for index in range(256):
            archive = []
            for member in range(7):
                value = copy.deepcopy(fast)
                value.update(source=f'{index}:{member}', provisional=generator.choice([False, True]))
                value['cache']['state'] = generator.choice(['warm', 'warm', 'cold', 'unknown'])
                value['whole'].update(stall=generator.choice([.01,.02,.03]), wall=generator.randrange(1,5), comparable_cpu_s=generator.randrange(1,5))
                value['tiers']['fast']['selected_cases'] = [generator.choice(['first','second'])]
                archive.append(value)
            generator.shuffle(archive)
            content = [{key:value for key,value in row.items() if key not in ('source','tree')} for row in archive]
            distinct.add(json.dumps(sorted(content,key=lambda row:json.dumps(row,sort_keys=True)),sort_keys=True))
            from build_graph import peer_domain, peer_cost, dominates
            domains = [json.dumps(peer_domain(row),sort_keys=True) for row in archive]
            singleton_domains += sum(domains.count(domain) == 1 for domain in set(domains))
            ties += sum(a['whole']['stall'] == b['whole']['stall'] and peer_cost(a) == peer_cost(b)
                        for i,a in enumerate(archive) for b in archive[i+1:])
            pruned = peer_frontier(archive)
            self.assertEqual(preferred_baseline(pruned), preferred_baseline(archive), 'pruning changed the current choice')
            for next_case in range(5):
                candidate = copy.deepcopy(generator.choice(archive))
                candidate['source'] = 'next:'+str(next_case)
                candidate['whole'].update(wall=generator.randrange(1,5), comparable_cpu_s=generator.randrange(1,5))
                next_distinct.add(json.dumps({key:value for key,value in candidate.items() if key not in ('source','tree')},sort_keys=True))
                incumbent = preferred_baseline(archive)
                winner = candidate if baseline_replacement(candidate,incumbent)[0] else incumbent
                older_winners += dominates(candidate, incumbent) and winner is not candidate and winner is not incumbent
                self.assertEqual(preferred_baseline([*pruned,candidate]), preferred_baseline([*archive,candidate]),
                                 'pruning changed the next candidate choice')
        self.assertEqual(len(distinct), 256)
        self.assertGreater(singleton_domains, 0)
        self.assertGreater(ties, 0)
        self.assertEqual(older_winners, 0, 'an unrelated archived peer cannot take over a pairwise decision')
        print(f'PEER-ARCHIVES content_distinct={len(distinct)} next_candidates=1280 next_content_distinct={len(next_distinct)} singleton_domains={singleton_domains} cost_stall_ties={ties} older_frontier_wins={older_winners} order=generated-unsorted')

    def test_baseline_lineage(self):
        """Tree-keyed lineage baselines survive re-signing and unimported candidates while refusing a mismatched import tree.
        ´claim:devperf:baseline-follows-import-tree´
        ´test:integration:test-baseline-lineage´
        """
        def windows(stall=0):
            return {phase: dict(node_scope='node-wide', node_pressure_fraction={'cpu.some':stall}, wall_seconds=5)
                    for phase in ('before', 'after')}
        def recorded(cache, stall, provisional=False):
            return dict(cache=dict(state=cache), provisional=provisional, whole=dict(node_scope='node-wide',stall=stall))
        from build_graph import baseline_context, retain_baseline, baseline_replacement, baseline_rank
        from build_graph import preferred_baseline, peer_frontier, prune_peer_archive
        from harness import build_cache_state, CONFIGURATION
        slow, fast = written_peer('slow',1177.5,.102), written_peer('fast',1093.8,.147)
        quiet_fast = written_peer('quiet-fast',1000,.05)
        peers = [written_peer('A',1000,.10),written_peer('B',1100,.05),written_peer('C',1050,.20)]
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)
            for name, value in [('slow',slow),('fast',fast),('foreign',quiet_fast)]:
                (archive/(name+'.json')).write_text(json.dumps(dict(value,tree='outside' if name == 'foreign' else 'inside', import_base_tree='old-base')))
            prune_peer_archive(archive, {'inside':'public', 'old-base':'old'}, 'inside')
            self.assertEqual({path.stem for path in archive.glob('*.json')}, {'slow','fast'}, 'noise margins preserve eligible incumbents even under strict dominance')
            (archive/'near.json').write_text(json.dumps(dict(slow, tree='near', source='near')))
            prune_peer_archive(archive, {'inside':'public', 'near':'near'})
            self.assertTrue((archive/'near.json').exists(), 'a nearer warm reference must survive an older dominator')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'.lane').mkdir(); archive = root/'peers'; archive.mkdir()
            a = dict(slow, source='A', tree='landed', import_base_tree='old-base',
                     quiet_windows=windows(), load_unresolved_pressure_percent=10)
            (archive/'A.json').write_text(json.dumps(a))
            b = dict(fast, source='B', tree='pending', import_base_tree='current-base',
                     quiet_windows=windows(), load_unresolved_pressure_percent=10,
                     path=str(root/'pending.json'), previous_peers=[a])
            (root/'.lane/gate-baseline.json').write_text(json.dumps(b))
            with patch('build_graph.evidence_statuses', return_value={}): retain_baseline(root)
            self.assertTrue((archive/'A.json').exists(), 'an unlanded dominator must not delete A at retention')
            prune_peer_archive(archive, {'landed':'A', 'old-base':'old'}, 'old-base')
            self.assertEqual(len(list(archive.glob('*.json'))), 2, 'a candidate based ahead of this gate must remain pending')
            history = {'landed':'A', 'old-base':'old', 'current-base':'current'}
            prune_peer_archive(archive, history, 'current-base')
            self.assertEqual(len(list(archive.glob('*.json'))), 2, 'a candidate at the current base is still pending')
            history['next-base'] = 'next'
            prune_peer_archive(archive, history, 'next-base')
            self.assertEqual(len(list(archive.glob('*.json'))), 1, 'B never landed when its base was passed')
            remaining = [json.loads(p.read_text()) for p in archive.glob('*.json')]
            self.assertEqual(preferred_baseline(remaining)['whole'], a['whole'],
                             'base-passed deletion must preserve the retained measurement')
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)
            for name, base in [('future','future-base'), ('current','current-base'), ('legacy',None), ('passed','old-base')]:
                (archive/(name+'.json')).write_text(json.dumps(dict(fast,tree=name,import_base_tree=base)))
            prune_peer_archive(archive, {'current-base':'now','old-base':'before'})
            self.assertEqual(len(list(archive.glob('*.json'))), 4, 'without a declared base absence cannot prove obsolescence')
            prune_peer_archive(archive, {'current-base':'now','old-base':'before'}, 'current-base')
            self.assertEqual({p.stem for p in archive.glob('*.json')}, {'future','current','legacy'}, 'only a passed base permits absence pruning')
        different = copy.deepcopy(fast);different['tiers']['fast']['selected_cases'].append('new')
        self.assertEqual(baseline_replacement(different,slow), (False,'warm-peer-noise-margin-unavailable'))
        unavailable = copy.deepcopy(fast);unavailable['whole']['comparable_cpu_s'] = None
        self.assertEqual(baseline_replacement(unavailable,slow), (False,'warm-peer-noise-margin-unavailable'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root/'.lane/tier-tests'
            run.mkdir(parents=True)
            manifest = dict(source='source', configuration=CONFIGURATION, run='invocation',
                            records=[dict(operation='build', outcome='exit:0')])
            (run/'manifest.json').write_text(json.dumps(manifest))
            receipt = dict(identity=['invocation', 'source', str(root.resolve()), ['cargo']], status=0,
                           artifacts=[dict(fresh=True, package_id='package-a', target=dict(name='example', kind=['lib']))], step='clippy')
            (root/'.lane/lint-pass.json').write_text(json.dumps(receipt))
            for log, expected in [('   Compiling example v1.0\n    Finished `gate` profile [optimized]\n', 'cold'),
                                  ('    Finished `gate` profile [optimized]\n', 'warm'),
                                  (chr(27)+'[32m    Finished `gate` profile [optimized]'+chr(27)+'[0m\n', 'warm'), ('', 'unknown')]:
                (run/'build.stderr').write_text(log)
                self.assertEqual(build_cache_state(root, 'source', 'invocation')['state'], expected)
                self.assertEqual(build_cache_state(root, 'other', 'invocation')['state'], 'unknown')
                self.assertEqual(build_cache_state(root, 'source', 'other')['state'], 'unknown')
            (run/'build.stderr').write_text('    Finished `gate` profile [optimized]\n')
            receipt['artifacts'][0]['fresh'] = False
            receipt['artifacts'].append(copy.deepcopy(receipt['artifacts'][0]))
            receipt['artifacts'].extend([dict(fresh=False,package_id='package-b',target=dict(name='example',kind=['lib'])),
                                         dict(fresh=False,package_id='package-a',target=dict(name='example',kind=['test']))])
            (root/'.lane/lint-pass.json').write_text(json.dumps(receipt))
            cache = build_cache_state(root, 'source', 'invocation')
            self.assertEqual(cache['state'], 'cold', 'a rebuilt lint target is cold even when primary artifacts are fresh')
            self.assertEqual(cache['compiled'], dict(primary=[], lint=[
                dict(package='package-a',target='example',kind=['lib']),
                dict(package='package-b',target='example',kind=['lib']),
                dict(package='package-a',target='example',kind=['test'])]))
            self.assertEqual(cache['compiling_steps'], ['clippy'])
            (root/'.lane/lint-pass.json').unlink()
            self.assertEqual(build_cache_state(root, 'source', 'invocation')['state'], 'unknown')

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'Cargo.toml').write_text('[profile.gate]\nopt-level = 1\n')
            (root/'.cargo').mkdir()
            (root/'.cargo/config.toml').write_text('fixture')
            (root/'.lane').mkdir()
            (root/'.lane/performance-events.jsonl').write_text('')
            (root/'.lane/harness-benchmarks.jsonl').write_text('')
            (root/'.lane/claim-evidence.json').write_text('{"obligations":[]}')
            registry = SimpleNamespace(tiers={'fast': {'jobs': 8}})
            good = SimpleNamespace(returncode=0, stdout='compiler identity')
            with patch.dict(os.environ, CARGO_TARGET_DIR=directory, PN_GATE_SOURCE='current', PN_IMPORT_BASE=''), patch('build_graph.subprocess.run', return_value=good):
                path, old, changed, context = baseline_context(root, registry)
                self.assertIsNone(old)
                with patch.dict(os.environ, PN_GATE_REFERENCE_STALL_CEILING='.9', PN_GATE_REFERENCE_STALL_BAND='.9', PN_GATE_REFERENCE_COUNT_MARGIN='.1', PN_GATE_REFERENCE_NOISE_MARGIN='.2', PN_GATE_REFERENCE_STALL_MARGIN='.01'):
                    self.assertEqual(baseline_context(root, registry)[0], path, 'named comparison values do not change archive identity')
                candidate = dict(path=str(path), source='ancestor', tiers={}, quiet_windows=windows(), whole={'node_scope':'node-wide','stall':0}, load_unresolved_pressure_percent=10)
                (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
                retain_baseline(root)
                self.assertFalse(list(path.parent.glob('*.tmp')))
                quiet_bytes = path.read_bytes()
                self.assertTrue(json.loads(quiet_bytes)['provisional'], 'first compatible retention is provisional')
                from gate_resources import node_identity
                node = node_identity()
                for key, value in (('cpu_models',['another CPU']), ('allowed_cpus',node['allowed_cpus']+1),
                                   ('pressure_scope','container-cgroup'), ('resource_scope','shared-cgroup')):
                    with patch('gate_resources.node_identity', return_value=dict(node, **{key:value})):
                        foreign_path, foreign_baseline, _, _ = baseline_context(root, registry)
                    self.assertNotEqual(foreign_path.parent, path.parent)
                    self.assertIsNone(foreign_baseline)
                self.assertEqual(path.read_bytes(), quiet_bytes)
                from build_graph import quiet_baseline
                for scope in (None, 'gate-cgroup', 'shared'):
                    wrong=copy.deepcopy(candidate)
                    wrong['quiet_windows']['before']['node_scope']=scope
                    self.assertFalse(quiet_baseline(wrong), 'own pressure cannot establish node quiet')
                for phase in ('before','after'):
                    wrong=copy.deepcopy(candidate)
                    wrong['quiet_windows'].pop(phase)
                    self.assertFalse(quiet_baseline(wrong), 'both passive boundaries are required')
                    wrong=copy.deepcopy(candidate)
                    wrong['quiet_windows'][phase]['wall_seconds']=4.99
                    self.assertFalse(quiet_baseline(wrong), 'a shortened window cannot qualify')
                candidate['whole']['stall'] = .8
                candidate['tiers'] = {'fast':{'resources':{'node_scope':'node-wide','node_pressure_fraction':{'cpu.some':.9}}}}
                self.assertTrue(quiet_baseline(candidate), 'gate-created pressure does not disqualify passive quiet boundaries')
                candidate['quiet_windows'] = windows(.101)
                (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
                retain_baseline(root)
                self.assertEqual(path.read_bytes(), quiet_bytes)
                new_path = path.parent/'loaded.json'
                candidate['path'] = str(new_path)
                (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
                retain_baseline(root)
                self.assertFalse(new_path.exists())
                candidate['quiet_windows'] = windows(.1)
                candidate['quiet_windows']['after']['node_pressure_fraction']['cpu.some'] = .101
                (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
                retain_baseline(root)
                self.assertFalse(new_path.exists(), 'a quiet start cannot hide a loaded end')
                candidate['quiet_windows'] = windows(.1)
                candidate['tiers'] = {}
                (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
                retain_baseline(root)
                self.assertTrue(new_path.exists(), 'the threshold itself remains quiet')
                new_path.unlink()

                with patch('build_graph.subprocess.run', side_effect=[good, good, good, SimpleNamespace(stdout='packages/example/src/pins.rs\npackages/example/src/pins.toml\nvendor/example/data.bin\nREADME.md\n'), SimpleNamespace(stdout='', returncode=0)]):
                    same_path, old, changed, context = baseline_context(root, registry)
                self.assertEqual(path, same_path)
                self.assertEqual(old['source'], 'ancestor')
                self.assertEqual(changed, ['packages/example/src/pins.rs', 'packages/example/src/pins.toml', 'vendor/example/data.bin'])
                with patch('build_graph.subprocess.run', side_effect=[good, good, SimpleNamespace(returncode=1)]):
                    self.assertIsNone(baseline_context(root, registry)[1])
                (root/'Cargo.toml').write_text('[profile.gate]\nopt-level = 2\n')
                self.assertIsNone(baseline_context(root, registry)[1])
                (root/'.cargo/config.toml').unlink()
                self.assertIsNone(baseline_context(root, registry)[1])
                registry.tiers['fast']['jobs'] = 4
                self.assertIsNone(baseline_context(root, registry)[1])
        # Two commits with identical trees model re-signing without using a key.
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git = lambda *args, **kw: subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                text=True, check=True, **kw).stdout.strip()
            git('init', '-q')
            git('config', 'user.name', 'Fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (root/'Cargo.toml').write_text('[profile.gate]\nopt-level = 1\n')
            git('add', 'Cargo.toml')
            tree = git('write-tree')
            original = git('-c', 'commit.gpgsign=false', 'commit-tree', tree, input='gate source\n')
            imported = git('-c', 'commit.gpgsign=false', 'commit-tree', tree, input='imported metadata\n')
            current = git('-c', 'commit.gpgsign=false', 'commit-tree', tree, '-p', imported, input='next import\n')
            from build_graph import ancestry_trees
            from contextlib import redirect_stdout
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(ancestry_trees(root, current, {tree}), {tree:current})
            self.assertIn('visited=1 ', output.getvalue(), 'ancestry stops once every requested tree is located')
            self.assertNotEqual(original, imported)
            self.assertNotEqual(subprocess.run(['git', '-C', str(root), 'merge-base', '--is-ancestor', original, current]).returncode, 0)
            (root/'.lane').mkdir()
            (root/'.lane/performance-events.jsonl').write_text('')
            (root/'.lane/harness-benchmarks.jsonl').write_text('')
            (root/'.lane/claim-evidence.json').write_text('{"obligations":[]}')
            with patch.dict(os.environ, CARGO_TARGET_DIR=directory, PN_GATE_SOURCE=current, PN_IMPORT_BASE=imported, PN_GATE_LINEAGE='main'):
                path, _, _, _ = baseline_context(root, registry)
                (root/'.lane/gate-baseline.json').write_text(json.dumps(dict(path=str(path), source=original, tree=tree, tiers={}, quiet_windows=windows(), whole={'node_scope':'node-wide','stall':0}, load_unresolved_pressure_percent=10)))
                retain_baseline(root)
                _, retained, changed, _ = baseline_context(root, registry)
                self.assertEqual(retained['source'], original)
                self.assertEqual(retained['match'], 'import-base-tree')
                self.assertEqual(changed, [])
                saved = path.read_text()
                measured = json.loads(saved)
                measured.update(cache=dict(state='warm'),
                    whole=dict(node_scope='node-wide',stall=0,wall=10,own_user_s=10,own_sys_s=0,comparable_cpu_s=None),
                    tiers={'fast':dict(step_figures={'tests':dict(own_cpu_s=10,setup_cpu_s=2,cargo_cpu_s=0,
                        layouts={},partial=False,serialized_build=False,compiled=False,wait_dominated=None,wall=10)})})
                path.write_text(json.dumps(measured))
                with patch.dict(os.environ, PN_GATE_REFERENCE_STALL_CEILING='.9', PN_GATE_REFERENCE_STALL_BAND='.9', PN_GATE_REFERENCE_COUNT_MARGIN='.1', PN_GATE_REFERENCE_NOISE_MARGIN='.2', PN_GATE_REFERENCE_STALL_MARGIN='.01'):
                    found_path, found, _, _ = baseline_context(root, registry)
                    self.assertEqual(found_path,path,'archived samples remain under the same key')
                    from build_graph import peer_cost
                    self.assertEqual(peer_cost(found),(10,8),'archived raw costs are evaluated after policy changes')
                path.write_text(saved)
                (root/'Cargo.toml').write_text('[profile.gate]\nopt-level = 1\n# Unimported candidate\n')
                git('add', 'Cargo.toml')
                other_tree = git('write-tree')
                other = git('-c', 'commit.gpgsign=false', 'commit-tree', other_tree, '-p', imported, input='unimported candidate\n')
                with patch.dict(os.environ, PN_GATE_SOURCE=other):
                    other_path, _, _, _ = baseline_context(root, registry)
                    (root/'.lane/gate-baseline.json').write_text(json.dumps(dict(path=str(other_path), source=other, tree=other_tree, tiers={}, quiet_windows=windows(), whole={'node_scope':'node-wide','stall':0}, load_unresolved_pressure_percent=10)))
                    retain_baseline(root)
                self.assertNotEqual(path, other_path)
                self.assertTrue(path.exists())
                self.assertEqual(baseline_context(root, registry)[1]['source'], original)
                other_path.unlink()
                with patch.dict(os.environ, PN_IMPORT_BASE=other):
                    selected = baseline_context(root, registry)[1]
                    self.assertIn(other, {value['source'] for value in selected['selection_peers']},
                                  'the pending archive becomes eligible once its tree lands')
                    self.assertTrue(any(json.loads(peer.read_text())['tree'] == other_tree
                                         for peer in (path.parent/'peers').glob('*.json')))
                # The remaining controls isolate the legacy predecessor route;
                # archives have independently passed ancestry selection above.
                for archived in (path.parent/'peers').glob('*.json'):
                    archived.unlink()
                with patch.dict(os.environ, PN_IMPORT_BASE=other):
                    self.assertIsNone(baseline_context(root, registry)[1], 'a mismatched tree must refuse the comparison')
                # A rejected loaded import points only to a quiet ancestor tree.
                with patch.dict(os.environ, PN_GATE_SOURCE=other):
                    loaded = dict(path=str(other_path), source=other, tree=other_tree, tiers={},
                                  quiet_windows=windows(.101), whole={'node_scope':'node-wide','stall':.101}, load_unresolved_pressure_percent=10,
                                  previous_baseline_tree=tree)
                    (root/'.lane/gate-baseline.json').write_text(json.dumps(loaded))
                    retain_baseline(root)
                    self.assertFalse(other_path.exists())
                with patch.dict(os.environ, PN_IMPORT_BASE=other):
                    _, previous, _, _ = baseline_context(root, registry)
                    self.assertEqual(previous['source'], original)
                    self.assertEqual(previous['match'], 'previous-quiet-import-tree')
                    marker = other_path.with_suffix('.skipped.json')
                    marker.write_text(json.dumps({'previous_tree': 'f'*40}))
                    self.assertIsNone(baseline_context(root, registry)[1], 'an unrelated predecessor must refuse')
                # Quiet boundaries alone cannot replace the quieter whole run.
                quiet_bytes = path.read_bytes()
                loaded['quiet_windows'] = windows()
                loaded['whole']['stall'] = .276
                (root/'.lane/gate-baseline.json').write_text(json.dumps(loaded))
                retain_baseline(root)
                self.assertFalse(other_path.exists(), 'a noisier candidate must not replace the admitted baseline')
                self.assertEqual(path.read_bytes(), quiet_bytes)
                with patch.dict(os.environ, PN_IMPORT_BASE=other):
                    self.assertEqual(baseline_context(root, registry)[1]['source'], original)
                    # Migrate selection over a historical, already admitted
                    # noisier file without deleting its retained evidence.
                    other_path.write_text(json.dumps(loaded))
                    self.assertEqual(baseline_context(root, registry)[1]['source'], original)
                    self.assertTrue(other_path.exists())
                import contextlib
                # Unknown evidence cannot displace warmth; provisional warm
                # evidence competes by the same pressure order as its peer.
                for old_cache in ('unknown', 'warm'):
                    older=json.loads(quiet_bytes)
                    older.update(cache={'state':old_cache}, provisional=True)
                    older['whole']['stall']=.001
                    path.write_text(json.dumps(older))
                    newer=dict(loaded, cache={'state':'warm'}, provisional=False)
                    other_path.write_text(json.dumps(newer))
                    retained_bytes=other_path.read_bytes()
                    with patch.dict(os.environ, PN_IMPORT_BASE=other):
                        self.assertEqual(baseline_context(root, registry)[1]['source'], original if old_cache == 'warm' else other,
                                         'lineage must rank warm peers without a confirmation advantage')
                    candidate=dict(newer, whole={'node_scope':'node-wide','stall':.3})
                    (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
                    output=io.StringIO()
                    with contextlib.redirect_stdout(output): retain_baseline(root)
                    self.assertEqual(other_path.read_bytes(),retained_bytes,
                                     'a worse candidate must not replace the retained measurement')
                    self.assertIn('retained_provisional=true',output.getvalue(), 'historical flags without a deciding judgment remain provisional')
                # Distance takes precedence for comparison, not retention.
                older=json.loads(quiet_bytes)
                older.update(cache={'state':'warm'}, provisional=False)
                older['whole']['stall']=.001
                path.write_text(json.dumps(older))
                other_path.write_text(json.dumps(newer))
                check_output = subprocess.check_output
                def distance(argv, **kwargs):
                    if argv[:3] == ['git','rev-list','--count']:
                        return '1' if argv[3].startswith(other+'..') else '2'
                    return check_output(argv, **kwargs)
                with patch.dict(os.environ, PN_IMPORT_BASE=other), patch('build_graph.subprocess.check_output', side_effect=distance):
                    self.assertEqual(baseline_context(root, registry)[1]['source'], other, 'comparison must select the nearest warm reference')
                    archived_peer = dict(newer, source='archived-peer', whole=dict(newer['whole'],stall=.00001))
                    (path.parent/'peers/cheaper.json').write_text(json.dumps(archived_peer))
                    self.assertEqual(baseline_context(root, registry)[1]['source'], other,
                                     'a same-tree archived peer cannot re-elect the retained incumbent')
                with patch.dict(os.environ, PN_GATE_LINEAGE='lane:fixture'):
                    self.assertIsNone(baseline_context(root, registry)[1])

    def test_noisy_clock(self):
        """The reporter contract keeps injected noisy evidence inconclusive without changing a predicate or hiding an excess.
        ´claim:devperf:noisy-clock-is-nonverdict´
        ´test:integration:test-noisy-clock´
        """
        for outcome in ['passed', 'failed']:
            record = {**execution(1000, outcome), 'clock_quality': 'noisy', 'baseline_ms': 1}
            original = copy.deepcopy(record)
            self.assertEqual(assessment(record)['reason'], 'noisy-clock')
            self.assertEqual([f['kind'] for f in assess(record, declarations())], ['budget-excess'])
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'findings.jsonl'
                self.assertEqual(report([record], declarations(), path, io.StringIO()), 0)
                evidence = json.loads(path.with_name('performance-assessments.jsonl').read_text())
                self.assertEqual(evidence['assessment'], 'inconclusive')
                self.assertNotIn('assessment', json.loads(path.read_text()))
            self.assertEqual(record, original)

    def test_cold_cache(self):
        """The reporter contract keeps injected cold/warm comparisons inconclusive while their excess remains visible.
        ´claim:devperf:cold-cache-is-nonverdict´
        ´test:integration:test-cold-cache´
        """
        for outcome in ['passed', 'failed']:
            record = {**execution(1000, outcome), 'baseline_ms': 1, 'cache_state': 'cold', 'baseline_cache': 'warm'}
            self.assertEqual(assessment(record)['reason'], 'incompatible-cache')
            self.assertEqual(assess(record, declarations())[0]['outcome'], outcome)

    def test_overlapping_spans(self):
        """Inclusive suite timing never sums overlapping work, preventing inflated budget findings.
        ´claim:devperf:overlap-is-not-summed´
        ´test:integration:test-overlapping-spans´
        """
        self.assertEqual(inclusive_ms([(0, 10), (5, 15)]), 15)
        self.assertEqual(inclusive_ms([(0, 5), (10, 15)]), 15)
        self.assertIsNone(inclusive_ms([]))
        for outcome in ['passed', 'failed']:
            record = execution(inclusive_ms([(0, 100), (50, 150)]), outcome)
            with tempfile.TemporaryDirectory() as directory:
                self.assertEqual(report([record], declarations(), Path(directory)/'findings.jsonl', io.StringIO()), 0)
            self.assertEqual(record['outcome'], outcome)
        with self.assertRaises(StructuralError):
            inclusive_ms([(2, 1)])

    def test_admitted_budget(self):
        """Admission changes only the warning threshold; an excess still preserves a failing predicate.
        ´claim:devperf:admission-is-nonverdict´
        ´test:integration:test-admitted-budget´
        """
        admission = dict(name='probe', status='admitted', ordinary_budget='unit', budget_ms=200,
                         label='expt:fixture:probe', owner='fixture', reason='bounded work',
                         measurement='injected milliseconds', placement='fixture', settlement='fixture admission')
        self.assertEqual(assess(execution(150), declarations(), [admission]), [])
        finding, = assess(execution(201, 'failed'), declarations(), [admission])
        self.assertEqual((finding['budget_ms'], finding['outcome'], finding['verdict_effect']), (200, 'failed', 'none'))
        admission['status'] = 'candidate'
        self.assertEqual(assess(execution(150), declarations(), [admission])[0]['budget_ms'], 100)

    def test_budget_category(self):
        """Declared categories keep build/aggregate configuration findings distinct from case/suite performance findings.
        ´claim:devperf:category-controls-classification´
        ´test:integration:test-budget-category´
        """
        for category in ['build', 'aggregate']:
            finding, = assess(execution(101), {'unit': {'budget_ms': 100, 'category': category}})
            self.assertEqual(finding['classification'], 'build-or-aggregate-misconfiguration')
        for category in ['case', 'suite']:
            finding, = assess(execution(101), {'unit': {'budget_ms': 100, 'category': category}})
            self.assertEqual(finding['classification'], 'performance')
        for classification in ('high-stall', 'rebuild', 'plain', 'growth', 'unclassified'):
            finding, = assess(dict(execution(101), operation='tier::fast', overrun_class=classification),
                {'unit': {'budget_ms': 100, 'category': 'aggregate'}})
            self.assertEqual(finding['classification'], classification)
        whole = {'unit': {'budget_ms': 100, 'category': 'aggregate', 'measurement': 'own-cpu'}}
        with self.assertRaisesRegex(StructuralError, 'requires process-and-reaped-children CPU'):
            assess(execution(101), whole)
        self.assertEqual(assess(dict(execution(100), measurement='own-cpu', wall_ms=10000), whole), [])
        finding, = assess(dict(execution(101), measurement='own-cpu', wall_ms=10000), whole)
        self.assertEqual((finding['kind'], finding['classification'], finding['verdict_effect']),
                         ('budget-excess', 'whole-tree-cpu-growth', 'none'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'budgets.toml'
            source = '''[[rows]]
name = "whole-tree-probe"
category = "aggregate"
budget_ms = 100
scope = "fixture CPU"
reason = "fixture"
measurement = "own-cpu"
measured_cpu_ms = 80
provisional = true
measurement_source = "injected CPU"
measurement_node = "fixture"
'''
            path.write_text(source)
            self.assertEqual(budgets(path)['whole-tree-probe']['budget_ms'], 100)
            for field in ('measurement = "own-cpu"', 'provisional = true', 'measured_cpu_ms = 80'):
                path.write_text(source.replace(field, ''))
                with self.assertRaisesRegex(StructuralError, 'whole-tree budget requires'):
                    budgets(path)

    def test_version_mismatch(self):
        """An unreviewed stream version is refused before tests, preventing silent schema drift.
        ´claim:devperf:exact-runner-version´
        ´test:integration:test-version-mismatch´
        """
        with tempfile.TemporaryDirectory() as directory:
            original = Path.cwd()
            try:
                os.chdir(directory)
                def execute(argv, stdout, stderr, env=None):
                    self.assertEqual(argv, ['cargo', 'nextest', '--version'])
                    stdout.write('cargo-nextest 0.9.150')
                    return SimpleNamespace(returncode=0)
                with patch('run_tests.subprocess.check_output', return_value='fixture'), patch('run_tests.load_registry', return_value=fixture()), patch('run_tests.invoke', side_effect=execute) as invoked:
                    self.assertEqual(run_tests.main(), 2)
                    self.assertEqual(invoked.call_count, 1)
            finally:
                os.chdir(original)

    def test_predicates(self):
        """Fast and slow passing and failing results retain their predicates.
        ´claim:devperf:timing-preserves-predicates´
        ´test:integration:test-predicates´
        """
        for outcome in ['passed', 'failed']:
            for duration in [0, 1, 100, 101, 100000]:
                record = execution(duration, outcome)
                original = copy.deepcopy(record)
                findings = assess(record, declarations())
                self.assertEqual(record, original)
                self.assertEqual(len(findings), int(duration > 100))
                for finding in findings:
                    self.assertEqual(finding['outcome'], outcome)
                    self.assertEqual(finding['verdict_effect'], 'none')

    def test_roster(self):
        """Findings preserve input outcomes and order, keeping evidence attributable.
        ´claim:devperf:findings-preserve-outcome-order´
        ´test:integration:test-roster´
        """
        def run(label, outcome):
            return {**execution(1000, outcome), 'operation': label}
        records = [run('first', 'passed'), run('second', 'failed'), run('third', 'passed')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'findings.jsonl'
            warnings = io.StringIO()
            self.assertEqual(report(records, declarations(), path, warnings), 0)
            findings = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([f['outcome'] for f in findings], ['passed', 'failed', 'passed'])
            self.assertEqual(len(warnings.getvalue().splitlines()), 3)

    def test_missing(self):
        """Missing measurements are findings with null duration and baseline.
        ´claim:devperf:missing-measurement-is-explicit´
        ´test:integration:test-missing´
        """
        finding, = assess(execution(None), declarations())
        self.assertEqual(finding['kind'], 'missing-measurement')
        self.assertIsNone(finding['duration_ms'])
        self.assertIsNone(finding['baseline_ms'])
        record = execution()
        del record['duration_ms']
        self.assertEqual(assess(record, declarations())[0]['kind'], 'missing-measurement')

    def test_structural(self):
        """Missing and malformed declarations differ from an exceeded budget.
        ´claim:devperf:structural-errors-distinct´
        ´test:integration:test-structural´
        """
        for record in [{}, {**execution(), 'budget': 'absent'}, {**execution(), 'owner': ''},
                       execution(-1), execution(float('nan')), execution(True)]:
            with self.assertRaises(StructuralError):
                assess(record, declarations())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'budgets.toml'
            for source in ['', '[[rows]]\nname="unit"\nbudget_ms=-1\n']:
                path.write_text(source)
                with self.assertRaises(StructuralError):
                    budgets(path)
        self.assertEqual(assess(execution(101), declarations())[0]['kind'], 'budget-excess')
        from devperf import calibration_defaults
        registry = SimpleNamespace(cases={'public-case':{'level':'public-surface'}},
            levels={'public-surface':{'budget':'crate'}}, case_budget=lambda case:'allowance')
        defaults = {'crate':dict(budget_ms=500), 'allowance':dict(category='case', budget_ms=1550, calibration_campaign='fixture')}
        calibration_defaults(defaults, registry)
        for value in (500, 450):
            defaults['allowance']['budget_ms'] = value
            with self.assertRaisesRegex(StructuralError, 'fits default crate'):
                calibration_defaults(defaults, registry)
        from devperf import calibration_declarations
        source = tomllib.loads((Path(__file__).parents[1]/'docs/inputs/devperf-budgets.toml').read_text())
        declared = {row['name']:row for row in source['rows']}
        calibration_declarations(declared)
        name = next(name for name, row in declared.items() if row.get('calibration_campaign'))
        for changes in ({'calibration_campaign':'campaign:missing:campaign'}, {'budget_ms':1},
                        {'calibration_warm':False}, {'calibration_selected_sample':0},
                        {'calibration_walls_ms':[1]}, {'calibration_pending_owner':''}):
            broken = copy.deepcopy(declared)
            broken[name].update(changes)
            with self.subTest(changes=changes), self.assertRaises(StructuralError):
                calibration_declarations(broken)
        pending = copy.deepcopy(declared)
        pending[name].pop('calibration_campaign')
        pending[name]['calibration_pending_owner'] = 'fixture-owner'
        calibration_declarations(pending)
        broken = copy.deepcopy(declared)
        broken['gate']['calibration_campaigns'][0].pop('measured_series')
        with self.assertRaises(StructuralError):
            calibration_declarations(broken)


    def test_utc(self):
        """Naive and offset instants are refused without assigning a zone.
        ´claim:devperf:utc-is-explicit´
        ´test:integration:test-utc´
        """
        self.assertEqual(utc('2026-10-22T12:30:00.123Z'), '2026-10-22T12:30:00.123Z')
        for value in ['2026-10-22T12:30:00', '2026-10-22T12:30:00+00:00', 'badZ']:
            with self.assertRaises(StructuralError):
                utc(value)

    def test_runner_policy(self):
        """Runner execution and original failure status do not depend on durations.
        ´claim:devperf:runner-policy-is-nonverdict´
        ´test:integration:test-runner-policy´
        """
        config = (Path(__file__).parent / 'nextest.toml').read_text()
        policy = tomllib.loads(config)['profile']['default']
        self.assertEqual(policy['retries'], 0)
        self.assertFalse(policy['fail-fast'])
        self.assertNotIn('terminate-after', policy['slow-timeout'])
        self.assertNotIn('global-timeout', policy)
        inventory, metadata = inventory_fixture()
        for outcome in [0, 100]:
            for duration in [0.001, 10000]:
                with self.subTest(outcome=outcome, duration=duration), tempfile.TemporaryDirectory() as directory:
                    calls = []
                    def execute(argv, stdout, stderr, env=None):
                        calls.append(argv)
                        self.assertEqual(env['CARGO_NET_OFFLINE'], 'true')
                        if argv[1] == 'metadata':
                            stdout.write(json.dumps(metadata))
                        elif argv[1:] == ['nextest', '--version']:
                            stdout.write('cargo-nextest 0.9.149')
                        elif argv[1:3] == ['nextest', 'list']:
                            stdout.write(json.dumps(inventory))
                        elif argv[1:3] == ['nextest', 'run']:
                            (Path(env['PN_GATE_CASE_CPU'])/'fixture.cpu').write_text(
                                '\0'.join(['example::case', 'fixture', str(outcome),
                                           str(duration), '0.001', '0.002', 'tests', '']))
                            stdout.write(json.dumps({'type': 'test', 'event': 'failed' if outcome else 'ok',
                                                     'name': 'example::example$case', 'exec_time': duration,
                                                     'stdout': 'synthetic captured text'}))
                            return SimpleNamespace(returncode=outcome)
                        return SimpleNamespace(returncode=0)
                    original = Path.cwd()
                    try:
                        os.chdir(directory)
                        Path('ci').mkdir()
                        Path('ci/nextest.toml').write_text(config)
                        with patch('run_tests.subprocess.check_output', return_value='fixture'), patch('run_tests.load_registry', return_value=fixture()), patch('run_tests.invoke', side_effect=execute):
                            self.assertEqual(run_tests.main(), outcome)
                        self.assertEqual(len(calls), 6)
                        self.assertIn('binaries-only', calls[2])
                        self.assertIn('--binaries-metadata', calls[3])
                        nextest = calls[4]
                        self.assertEqual(nextest[nextest.index('--retries') + 1], '0')
                        self.assertIn('--no-fail-fast', nextest)
                        self.assertNotIn('--locked', nextest)
                        self.assertNotIn('--offline', nextest)
                        self.assertIn('--doc', calls[5])
                        records = [json.loads(line) for line in Path('.lane/performance-events.jsonl').read_text().splitlines()]
                        case, = [r for r in records if r['operation'] == 'example::case']
                        self.assertEqual(case['duration_ms'], duration * 1000)
                        self.assertEqual(case['outcome'], 'failed' if outcome else 'passed')
                        self.assertNotIn('stdout', case)
                    finally:
                        os.chdir(original)

    def test_result_accounting(self):
        """A missing case remains incomplete and unknown results are structural errors.
        ´claim:devperf:result-accounting-is-explicit´
        ´test:integration:test-result-accounting´
        """
        inventory, metadata = inventory_fixture('test', 'tests/example.rs')
        record, = run_tests.nextest_events('', inventory, metadata, 'fixture', 'test', fixture(level='integration'))
        self.assertEqual(record['outcome'], 'incomplete')
        self.assertIsNone(record['duration_ms'])
        self.assertEqual(record['budget'], 'integration')
        raw = json.dumps({'type': 'test', 'name': 'unknown', 'event': 'ok'})
        with self.assertRaises(StructuralError):
            run_tests.nextest_events(raw, inventory, metadata, 'fixture', 'test', fixture(level='integration'))

    def test_raw_duration(self):
        """Invalid raw durations cannot become valid normalized measurements.
        ´claim:devperf:raw-duration-validation´
        ´test:integration:test-raw-duration´
        """
        for value in [True, -1, float('inf'), '1']:
            with self.assertRaises(StructuralError):
                run_tests.milliseconds(value)
        self.assertIsNone(run_tests.milliseconds(None))
        self.assertEqual(run_tests.milliseconds(0.125), 125)


if __name__ == '__main__':
    unittest.main()
