"""Process comparisons using the same four-package workload and local export failure."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
import threading
import unittest


def reconcile_publication(status, captured):
    """The one reserved write may finish around the synchronous cutoff status."""
    if status['in_flight_records'] not in (0,1):
        raise AssertionError('invalid in-flight count')
    if not status['delivered_records'] <= captured <= status['delivered_records']+status['in_flight_records']:
        raise AssertionError('captured records outside cutoff interval')
    if status['attempted_records'] != sum(status[k] for k in ('delivered_records','in_flight_records','lost_records','undelivered_records')):
        raise AssertionError('attempted records do not reconcile')


def witness(argv, status, wall, stderr, injected=False):
    rows=[];records=[]
    for line in stderr.splitlines():
        try:row=json.loads(line)
        except (ValueError,UnicodeError):continue
        if isinstance(row,dict):
            records.append(row)
            if row.get('kind')=='observation_status':rows.append(row)
    prefix=f'OBSERVATION-WITNESS command={argv[0]} status={status} wall_seconds={wall:.6f} injected={str(injected).lower()}'
    if not rows:print(prefix+' delivered=unavailable lost=unavailable');return
    for row in rows:
        print(prefix+f" delivered={row.get('delivered_records','unavailable')} lost={row.get('lost_records','unavailable')} observation_status="+json.dumps(row,sort_keys=True))
        if not injected and row.get('level')=='trace':
            delivered=sum(item.get('process_id')==row['process_id'] for item in records)-1
            reconcile_publication(row,delivered)
        if not injected and row.get('level')=='trace' and row.get('lost_records',0)+row.get('undelivered_records',0)>0:
            from devperf import report_loss
            from harness import source_id
            report_loss(dict(source=source_id(),configuration='foundation trace witness',operation=argv[0],outcome=f'exit:{status}',
                             level='trace',process_id=row['process_id'],utc=row['timestamp'],delivered_records=row['delivered_records'],lost_records=row['lost_records'],undelivered_records=row.get('undelivered_records',0),loss_causes=row.get('loss_causes',{})),
                        '.lane/performance-findings.jsonl')


def run(argv, **kwargs):
    started=time.monotonic()
    result=subprocess.run(argv,capture_output=True,**kwargs)
    witness(argv,result.returncode,time.monotonic()-started,result.stderr)
    return result


def compare(argv, mode, env, deadline=60, injected=False):
    """Bound the fixture lifetime; release on final status or reader termination."""
    started=time.monotonic()
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             env={key:value for key,value in env.items() if key!='PN_TEST_OBSERVATION_RENDEZVOUS'})
    stderr=[]; stdout=[]; reader_errors=[]
    released=False
    def release():
        nonlocal released
        if released:return
        released=True
        try: process.stdin.write(b'\n'); process.stdin.flush()
        except (OSError,ValueError): pass
    def receive():
        try:
            for line in process.stderr:
                stderr.append(line)
                try: row=json.loads(line)
                except (ValueError,UnicodeError): continue
                if isinstance(row,dict) and row.get('kind')=='observation_status': release()
        except (OSError,ValueError) as error: reader_errors.append(str(error))
        finally: release()
    reader=threading.Thread(target=receive,daemon=True)
    output=threading.Thread(target=lambda: stdout.append(process.stdout.read()),daemon=True)
    reader.start(); output.start()
    timed_out=False
    try: status=process.wait(timeout=deadline)
    except subprocess.TimeoutExpired:
        timed_out=True; process.kill(); status=process.wait(timeout=5)
    finally:
        reader.join(timeout=5); output.join(timeout=5)
        if not reader.is_alive(): process.stderr.close()
        if not output.is_alive(): process.stdout.close()
        try: process.stdin.close()
        except (OSError,ValueError): pass
    witness(argv,status,time.monotonic()-started,b''.join(stderr),injected)
    if timed_out or reader.is_alive() or output.is_alive(): raise AssertionError('observation fixture deadline exceeded')
    if reader_errors: raise AssertionError('observation reader failed: '+str(reader_errors))
    return subprocess.CompletedProcess(argv,status,b''.join(stdout),b''.join(stderr))


def expanded(value):
    """Read and verify lossless JSON object references before judging measurements."""
    if isinstance(value, dict):
        if value.get('encoding') == 'json' and 'artifact' in value:
            artifact = value['artifact']
            payload = Path(artifact['path']).read_bytes()
            assert artifact['algorithm'] == 'sha256'
            assert len(payload) == artifact['length_bytes']
            assert hashlib.sha256(payload).hexdigest() == artifact['digest']
            return expanded(json.loads(payload))
        return {key: expanded(child) for key, child in value.items()}
    if isinstance(value, list):
        return [expanded(child) for child in value]
    return value


def distribution(summary):
    assert summary["counter_accuracy"] == "exact"
    assert summary["lost_counter_updates"] == 0
    result={}
    for row in summary['instruments']:
        if row['name'].endswith(('started_operations','completed_operations')) and row['counter']>0:
            key=(row['name'],row.get('outcome',''))
            result[key]=result.get(key,0)+row['counter']
    return result


class Processes(unittest.TestCase):
    def test_cutoff_capture_interval(self):
        """Claim: With one reserved write at cutoff, either capture endpoint reconciles while missing completed records, excess captures, multiple reservations and inconsistent attempted totals refuse; without a reservation the interval collapses to equality.
        ´claim:discipline:cutoff-capture-respects-single-reservation´
        ´test:integration:test-cutoff-capture-interval´
        """
        status=dict(delivered_records=4,in_flight_records=1,lost_records=2,undelivered_records=3,attempted_records=10)
        for captured in (4,5):reconcile_publication(status,captured)
        for captured in (3,6):
            with self.assertRaises(AssertionError):reconcile_publication(status,captured)
        for changed in (status|{'in_flight_records':2},status|{'attempted_records':9}):
            with self.assertRaises(AssertionError):reconcile_publication(changed,4)
        complete=status|{'in_flight_records':0,'attempted_records':9}
        reconcile_publication(complete,4)
        with self.assertRaises(AssertionError):reconcile_publication(complete,5)

    def test_numeric_entry(self):
        """Claim: Exact numeric charge and three typed refusals retain identical stdout and exit across disabled, default and trace observation; default and trace count the same numeric outcomes, trace retains public coordinate content, and immutable value reads introduce no operations.
        ´claim:discipline:numeric-carriers-are-observed-without-changing-values´
        ´test:integration:test-numeric-entry´
        """
        outputs={};outcomes={}
        for mode in ('disabled','default','trace'):
            result=compare([str(Path(os.environ['CARGO_TARGET_DIR'])/'gate/examples/numeric_observation'),mode],mode,
                           os.environ|{'PN_OBSERVE_LEVEL':'trace' if mode=='trace' else 'default'})
            self.assertEqual(result.returncode,0,result.stderr.decode())
            outputs[mode]=result.stdout
            self.assertEqual(json.loads(result.stdout),{'charged':'30','price':'6','numeraire':'public-numeraire','refused':[True,True,True]})
            if mode=='disabled':continue
            rows=[json.loads(line) for line in result.stderr.splitlines()]
            summary=expanded(next(row['metrics'] for row in rows if row.get('kind')=='metric_summary'))
            stem='records__root__sig__design__records__'
            outcomes[mode]={k:v for k,v in distribution(summary).items() if k[0].startswith(stem)}
            self.assertEqual(outcomes[mode][stem+'completed_operations','refusal'],3)
            self.assertEqual(outcomes[mode][stem+'completed_operations','success'],13)
            self.assertNotIn((stem+'completed_operations','error'),outcomes[mode])
            if mode=='trace':self.assertIn('public-numeraire',json.dumps(expanded(rows)))
            print('RECORDS-NUMERIC level='+mode+' distribution='+json.dumps({str(k):v for k,v in outcomes[mode].items()},sort_keys=True))
        self.assertEqual(outputs['disabled'],outputs['default'])
        self.assertEqual(outputs['default'],outputs['trace'])
        self.assertEqual(outcomes['default'],outcomes['trace'])

    def test_burn_entry(self):
        """Claim: A valid burn history and two invalid histories retain identical outputs at disabled, default and trace levels; all thirty carrier, declaration and content-digest boundaries are counted, two recognition refusals remain refusals, and trace preserves the public evidence.
        ´claim:discipline:burn-recognition-retains-observed-outcomes´
        ´test:integration:test-burn-entry´
        """
        outputs={};outcomes={}
        for mode in ('disabled','default','trace'):
            result=compare([str(Path(os.environ['CARGO_TARGET_DIR'])/'gate/examples/burn_observation'),mode],mode,
                           os.environ|{'PN_OBSERVE_LEVEL':'trace' if mode=='trace' else 'default'})
            self.assertEqual(result.returncode,0,result.stderr.decode())
            outputs[mode]=result.stdout
            self.assertEqual(json.loads(result.stdout),{'markers':3,'destructions':2,'refused':[True,True]})
            if mode=='disabled':continue
            rows=[json.loads(line) for line in result.stderr.splitlines()]
            summary=expanded(next(row['metrics'] for row in rows if row.get('kind')=='metric_summary'))
            stem='records__root__sig__design__records__'
            outcomes[mode]={k:v for k,v in distribution(summary).items() if k[0].startswith(stem)}
            self.assertEqual(outcomes[mode][stem+'completed_operations','refusal'],2)
            self.assertEqual(outcomes[mode][stem+'completed_operations','success'],28)
            self.assertEqual(sum(row['counter'] for row in summary['instruments'] if row['name']==stem+'completed_operations' and row['operation']=='digest-marker-policy' and row['outcome']=='success'),6)
            self.assertNotIn((stem+'completed_operations','error'),outcomes[mode])
            if mode=='trace':self.assertIn('fixture assumption, not chain evidence',json.dumps(expanded(rows)))
            print('RECORDS-BURN level='+mode+' distribution='+json.dumps({str(k):v for k,v in outcomes[mode].items()},sort_keys=True))
        self.assertEqual(outputs['disabled'],outputs['default'])
        self.assertEqual(outputs['default'],outputs['trace'])
        self.assertEqual(outcomes['default'],outcomes['trace'])

    def test_graph_partition(self):
        """Claim: The real public partition operation returns identical whole-act blocks with observation disabled, default and trace; default and trace retain two graph invocations and elapsed samples, while trace records the complete public input and graph result.
        ´claim:discipline:graph-partition-is-observed-without-changing-results´
        ´test:integration:test-graph-partition´
        """
        samples = {}; accounting = {}
        for mode in ('disabled', 'default', 'trace'):
            env = os.environ | {'PN_OBSERVE_LEVEL': 'trace' if mode == 'trace' else 'default'}
            result = compare([str(Path(os.environ['CARGO_TARGET_DIR'])/'gate/examples/partition_observation'), mode], mode, env)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            samples[mode] = result.stdout
            self.assertEqual(json.loads(result.stdout), {'partition_cases': [
                {'nodes': 2, 'edges': 0, 'blocks': [[2], [3]]},
                {'nodes': 10, 'edges': 45, 'blocks': [list(range(2, 12))]}]})
            if mode == 'disabled': continue
            rows = [json.loads(line) for line in result.stderr.splitlines()]
            summary = expanded(next(row['metrics'] for row in rows if row.get('kind') == 'metric_summary'))
            stem = 'graph__root__sig__design__graph__'
            accounting[mode] = {key: value for key, value in distribution(summary).items() if key[0].startswith(stem)}
            self.assertEqual(accounting[mode][stem+'started_operations', ''], 2)
            self.assertEqual(accounting[mode][stem+'completed_operations', 'success'], 2)
            instruments = {row['name']: row for row in summary['instruments'] if row['name'].startswith(stem)}
            self.assertEqual(instruments[stem+'elapsed_seconds']['count'], 2)
            if mode == 'trace':
                for marker in (b'partition_dependencies', b'authentication_evidence', b'asserted_parents', b'Graph'):
                    self.assertIn(marker, result.stderr)
        self.assertEqual(samples['disabled'], samples['default'])
        self.assertEqual(samples['default'], samples['trace'])
        self.assertEqual(accounting['default'], accounting['trace'])

    def test_graph_registration(self):
        """Claim: Registration projection, reconstruction and revalidation return identical complete public results with observation disabled, default and trace; the three successful operations and two explicit refusals retain their own graph accounting, and trace includes the full public history and graph.
        ´claim:discipline:registration-formation-retains-observed-results´
        ´test:integration:test-graph-registration´
        """
        samples={};accounting={}
        for mode in ('disabled','default','trace'):
            env=os.environ | {'PN_OBSERVE_LEVEL':'trace' if mode=='trace' else 'default'}
            result=compare([str(Path(os.environ['CARGO_TARGET_DIR'])/'gate/examples/registration_observation'),mode],mode,env)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            samples[mode]=result.stdout
            values=json.loads(result.stdout)
            self.assertEqual(values['valid'],'Ok(())')
            self.assertIn('Unapproved',values['denied'])
            self.assertIn('GraphMismatch',values['invalid'])
            self.assertIn('Profile',values['projection'])
            if mode=='disabled':continue
            rows=[json.loads(line) for line in result.stderr.splitlines()]
            summary=expanded(next(row['metrics'] for row in rows if row.get('kind')=='metric_summary'))
            stem='graph__root__sig__design__graph__'
            accounting[mode]={key:value for key,value in distribution(summary).items() if key[0].startswith(stem)}
            self.assertEqual(accounting[mode],{(stem+'started_operations',''):5,(stem+'completed_operations','success'):3,(stem+'completed_operations','refusal'):2})
            self.assertEqual(next(row for row in summary['instruments'] if row['name']==stem+'elapsed_seconds')['count'],5)
            if mode=='trace':
                for marker in ('authentication_evidence','logical_time','RegistrationProjection','validate_registration_graph'):
                    self.assertIn(marker,result.stderr.decode())
        self.assertEqual(samples['disabled'],samples['default'])
        self.assertEqual(samples['default'],samples['trace'])
        self.assertEqual(accounting['default'],accounting['trace'])

    def test_graph_formation(self):
        """Claim: Affinity, Publish, Owner, Participant, Review, Send, Bid, Opinion, Join Request, Tag, Leave, Reference, Invitation, De-invite, Withdraw, Rescind, Accept and Ratify projection, reconstruction, revalidation complete-act title indexing and scoped six-clause recognition return identical complete public results with observation disabled, default and trace; the twenty-seven successful operations and five explicit refusals retain their own graph accounting, and trace includes the full public history and graph.
        ´claim:discipline:affinity-formation-retains-observed-results´
        ´test:integration:test-graph-formation´
        """
        samples={};accounting={}
        for mode in ('disabled','default','trace'):
            env=os.environ | {'PN_OBSERVE_LEVEL':'trace' if mode=='trace' else 'default'}
            result=compare([str(Path(os.environ['CARGO_TARGET_DIR'])/'gate/examples/formation_observation'),mode],mode,env)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            samples[mode]=result.stdout
            values=json.loads(result.stdout)
            self.assertEqual(values['valid'],'Ok(())')
            self.assertIn('Unapproved',values['denied'])
            self.assertIn('GraphMismatch',values['invalid'])
            self.assertIn('Type',values['projection'])
            self.assertIn('Content',values['publication'])
            self.assertIn('Item',values['ownership'])
            self.assertIn('Chat',values['participant'])
            self.assertIn('Comment',values['review'])
            self.assertIn('Message',values['send'])
            self.assertIn('Offer',values['bid'])
            self.assertIn('OpinionProjection',values['opinion'])
            self.assertIn('JoinRequestProjection',values['join_request'])
            self.assertIn('TagProjection',values['tag'])
            self.assertIn('LeaveProjection',values['leave'])
            self.assertIn('ReferenceProjection',values['reference'])
            self.assertIn('InvitationProjection',values['invitation'])
            self.assertIn('DeinviteProjection',values['deinvite'])
            self.assertIn('WithdrawProjection',values['withdraw'])
            self.assertIn('RescindProjection',values['rescind'])
            self.assertIn('AcceptProjection',values['accept'])
            self.assertIn('RatifyProjection',values['ratify'])
            self.assertIn('TitleInputs',values['title'])
            self.assertIn('SettlementEvidence',values['recognition'])
            self.assertIn('Boundary',values['wrong_boundary'])
            self.assertIn('GraphMismatch',values['partial_title'])
            self.assertIn('role: A',values['tag'])
            self.assertIn('role: T',values['tag'])
            self.assertIn('role: A',values['bid'])
            self.assertIn('role: T',values['bid'])
            self.assertIn('role: A',values['send'])
            self.assertIn('role: T',values['send'])
            self.assertIn('role: A',values['review'])
            self.assertIn('role: T',values['review'])
            self.assertIn('role: A',values['participant'])
            self.assertIn('role: T',values['participant'])
            self.assertIn('LicenseQualifiers',values['publication'])
            if mode=='disabled':continue
            rows=[json.loads(line) for line in result.stderr.splitlines()]
            summary=expanded(next(row['metrics'] for row in rows if row.get('kind')=='metric_summary'))
            stem='graph__root__sig__design__graph__'
            accounting[mode]={key:value for key,value in distribution(summary).items() if key[0].startswith(stem)}
            self.assertEqual(accounting[mode],{(stem+'started_operations',''):32,(stem+'completed_operations','success'):27,(stem+'completed_operations','refusal'):5})
            self.assertEqual(next(row for row in summary['instruments'] if row['name']==stem+'elapsed_seconds')['count'],32)
            if mode=='trace':
                for marker in ('authentication_evidence','logical_time','AffinityProjection','PublishProjection','OwnerProjection','ParticipantProjection','ReviewProjection','SendProjection','BidProjection','OpinionProjection','JoinRequestProjection','TagProjection','LeaveProjection','ReferenceProjection','InvitationProjection','DeinviteProjection','WithdrawProjection','RescindProjection','AcceptProjection','RatifyProjection','settles','accepts','LicenseQualifiers','validate_formation'):
                    self.assertIn(marker,result.stderr.decode())
        self.assertEqual(samples['disabled'],samples['default'])
        self.assertEqual(samples['default'],samples['trace'])
        self.assertEqual(accounting['default'],accounting['trace'])

    def test_graph_dependency(self):
        """Claim: Every graph row matches the workspace feature union, every numeric row matches pn-records alone and every host row distinguishes its own resolved features from lock-only packages, so a dependency table cannot borrow another build's features or portray an unbuilt package as built.
        ´claim:discipline:graph-backend-retains-reviewed-identity´
        ´test:integration:test-graph-dependency´
        """
        import tomllib
        from dependency_identity import metadata, spellings
        workspace = tomllib.loads(Path('Cargo.toml').read_text())
        manifest = tomllib.loads(Path('packages/graph/Cargo.toml').read_text())
        self.assertEqual(workspace['workspace']['dependencies']['petgraph'], {'version': '0.8', 'features': ['serde-1']})
        self.assertEqual(manifest['dependencies']['petgraph'], {'workspace': True})
        data = metadata()
        self.assertEqual(spellings(data, 'pn-graph', {'petgraph'}), {'petgraph'})
        resolved = json.loads(subprocess.check_output(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1']))
        package = next(row for row in resolved['packages'] if row['name'] == 'petgraph')
        self.assertEqual(package['version'], '0.8.3')
        node = next(row for row in resolved['resolve']['nodes'] if row['id'] == package['id'])
        self.assertEqual(set(node['features']), {'default', 'std', 'graphmap', 'stable_graph', 'matrix_graph', 'serde-1', 'serde', 'serde_derive'})
        declarations = tomllib.loads(Path('docs/inputs/graph-dependencies.toml').read_text())['rows']
        locked = tomllib.loads(Path('Cargo.lock').read_text())['package']

        def feature_tree(owner):
            command = ['cargo', 'tree', '--offline', '--locked', '--prefix', 'none', '--format', '{p}|{f}', '--no-dedupe']
            command += ['--workspace'] if owner == 'workspace' else ['-p', owner]
            started = time.monotonic()
            output = subprocess.check_output(command, text=True)
            print(f'DEPENDENCY-FEATURES owner={owner} wall={time.monotonic()-started:.6f}s')
            features = {}
            for line in output.splitlines():
                if not line.strip():
                    continue
                package, enabled = line.split('|', 1)
                name, version, *_ = package.split()
                key = (name, version.removeprefix('v'))
                features.setdefault(key, set()).update(filter(None, enabled.split(',')))
            return features

        scopes = {owner: feature_tree(owner) for owner in ('workspace', 'pn-records', 'pn-host')}

        def check_row(row, owner):
            package = next(p for p in resolved['packages'] if p['name'] == row['name'] and p['version'] == row['version'])
            self.assertTrue(any(p['name'] == row['name'] and p['version'] == row['version'] for p in locked))
            features = row['features'].split(', ') if isinstance(row['features'], str) else row['features']
            if features == ['none']:
                features = []
            self.assertEqual(set(features), scopes[owner][(package['name'], package['version'])])

        for row in declarations:
            check_row(row, 'workspace')
        serde = next(row for row in declarations if row['name'] == 'serde')
        self.assertEqual(serde['version'], '1.0.229')
        self.assertEqual(set(serde['features']), {'alloc', 'default', 'derive', 'serde_derive', 'std'})
        numeric = tomllib.loads(Path('docs/inputs/numeric-dependencies.toml').read_text())['rows']
        numeric_serde = next(row for row in numeric if row['name'] == 'serde')
        for row in numeric:
            self.assertIn('pn-records built on its own', row['feature_scope'])
            check_row(row, 'pn-records')
            with self.assertRaises(AssertionError):
                check_row(row | {'features': ['unresolved-feature']}, 'pn-records')
        host = tomllib.loads(Path('docs/inputs/host-dependencies.toml').read_text())['rows']

        def check_host(row):
            name = row['name'].removesuffix(' '+row['version'])
            self.assertIn('all lock edges', row['membership_scope'])
            self.assertIn('pn-host alone', row['feature_scope'])
            actual = scopes['pn-host'].get((name, row['version']))
            self.assertEqual(row['built_for_host'], actual is not None)
            self.assertEqual(set(row['features']), actual if actual is not None else set())

        for row in host:
            check_host(row)
        criterion = next(row for row in host if row['name'] == 'criterion 0.7.0')
        self.assertFalse(criterion['built_for_host'])
        with self.assertRaises(AssertionError):
            check_host(criterion | {'built_for_host': True})
        with self.assertRaises(AssertionError):
            check_row(serde | {'features': [feature for feature in serde['features'] if feature != 'alloc']}, 'workspace')
        with self.assertRaises(AssertionError):
            check_row(numeric_serde | {'features': serde['features']}, 'pn-records')

    def test_generated_records_refusals(self):
        """Claim: Each single corruption of the same seeded records DAG retains its exact typed refusal at default and trace, and both metric distributions contain nineteen refusals and no errors.
        ´claim:discipline:generated-records-refusals-retain-outcomes´
        ´test:integration:test-generated-records-refusals´
        """
        from properties import seed
        from harness import source_id
        recorded_seed=seed(source_id())
        distributions={};outputs={}
        for mode in ('default','trace'):
            result=compare([str(Path(os.environ['CARGO_TARGET_DIR'])/'gate/examples/generated_refusals')],mode,
                           os.environ|{'PN_OBSERVE_LEVEL':mode,'PN_RECORDS_SEED':recorded_seed})
            self.assertEqual(result.returncode,0,result.stderr.decode())
            outputs[mode]=result.stdout
            rows=[json.loads(line) for line in result.stderr.splitlines()]
            summary=expanded(next(row['metrics'] for row in rows if row.get('kind')=='metric_summary'))
            distributions[mode]={k:v for k,v in distribution(summary).items() if k[0].startswith('records__')}
            stem='records__root__sig__design__records__'
            self.assertEqual(distributions[mode][stem+'completed_operations','refusal'],19)
            self.assertNotIn((stem+'completed_operations','error'),distributions[mode])
            print('RECORDS-GENERATED level='+mode+' seed='+recorded_seed+' corruptions=19 distribution='+json.dumps({str(k):v for k,v in distributions[mode].items()},sort_keys=True))
        self.assertEqual(distributions['default'],distributions['trace'])
        self.assertEqual(outputs['default'],outputs['trace'])

    def test_interchange_refusal(self):
        """Claim: Canonical value/document decode, content-key and prefix validation, routing and unheld acceptance retain their exact rejection predicates at default and trace, booking fifteen boundary refusals and no errors with identical complete outcome distributions; a truncated prefix still returns its original error.
        ´claim:discipline:interchange-refusals-have-contract-outcomes´
        ´test:integration:test-interchange-refusal´
        """
        distributions={}
        for mode in ('default','trace'):
            result=compare([str(Path(os.environ['CARGO_TARGET_DIR'])/'gate/examples/interchange_observation')],mode,os.environ|{'PN_OBSERVE_LEVEL':mode})
            self.assertEqual(result.returncode,0,result.stderr.decode())
            rows=[json.loads(line) for line in result.stderr.splitlines()]
            summary=expanded(next(row['metrics'] for row in rows if row.get('kind')=='metric_summary'))
            stem='interchange__root__rule__observe__spans__'
            distributions[mode]={k:v for k,v in distribution(summary).items() if k[0].startswith(stem)}
            self.assertEqual(distributions[mode][stem+'completed_operations','refusal'],15)
            self.assertNotIn((stem+'completed_operations','error'),distributions[mode])
            print('INTERCHANGE-OBSERVATION level='+mode+' distribution='+json.dumps({str(k):v for k,v in distributions[mode].items()},sort_keys=True))
        self.assertEqual(distributions['default'],distributions['trace'])

    def test_records_replay(self):
        """Claim: Finalized dependency violations, attached times and recurrence evidence agree with observation disabled, at default and at trace, including mismatches, unavailable openings and a cross-epoch predecessor; candidate refusals remain refusals while replay is accounted as success.
        ´claim:discipline:records-replay-retains-observed-noncompliance´
        ´test:integration:test-records-replay´
        """
        target=Path(os.environ['CARGO_TARGET_DIR'])/'gate'
        samples={};accounting={}
        for mode in ('disabled','default','trace'):
            env=os.environ | {'PN_OBSERVE_LEVEL':'trace' if mode=='trace' else 'default'}
            result=compare([str(target/'examples/replay_observation'),mode],mode,env)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            samples[mode]=result.stdout
            values=json.loads(result.stdout)
            self.assertEqual([row['violations'] for row in values],[0,1,1,0,0,0])
            self.assertEqual([row['admitted'] for row in values],[True,False,False,True,True,True])
            self.assertIn('NotEarlier',values[1]['evidence'])
            self.assertIn('Missing',values[2]['evidence'])
            self.assertIn('Matches',values[0]['time_evidence'])
            self.assertIn('NonCompliant',values[1]['time_evidence'])
            self.assertIn('Mismatch',values[3]['time_evidence'])
            self.assertIn('UnavailableOpening',values[4]['time_evidence'])
            self.assertNotIn('Mismatch',values[5]['time_evidence'])
            if mode=='disabled':continue
            rows=[json.loads(line) for line in result.stderr.splitlines()]
            summary=expanded(next(row['metrics'] for row in rows if row.get('kind')=='metric_summary'))
            stem='records__root__sig__design__records__'
            accounting[mode]={key:value for key,value in distribution(summary).items() if key[0].startswith(stem)}
            self.assertEqual(accounting[mode],{(stem+'started_operations',''):13,(stem+'completed_operations','success'):11,(stem+'completed_operations','refusal'):2})
            self.assertEqual(next(row for row in summary['instruments'] if row['name']==stem+'elapsed_seconds')['count'],13)
            if mode=='trace':
                self.assertIn('non_compliance',result.stderr.decode())
                self.assertIn('NotEarlier',result.stderr.decode())
        self.assertEqual(samples['disabled'],samples['default'])
        self.assertEqual(samples['default'],samples['trace'])
        self.assertEqual(accounting['default'],accounting['trace'])

    def test_records_entry(self):
        """Claim: The first domain entry counts and times successful validation, complete-act access, reference resolution and historical edition selection, validated history and boundary assembly, plus their typed refusals at default and trace, with identical outcome distributions and unchanged JSON stdout and exit when observation is disabled; trace carries the public act content. Repeated reads through all seventeen pure field accessors create no additional operations or series, and assembly steps remain distinct from invocation work.
        ´claim:discipline:records-entry-is-observed-without-changing-results´
        ´test:integration:test-records-entry´
        """
        target=Path(os.environ['CARGO_TARGET_DIR'])/'gate'
        artifact=Path('.lane/records-observation');artifact.mkdir(exist_ok=True)
        samples={};accounting={}
        for mode in ('disabled','default','trace'):
            env=os.environ | {'PN_OBSERVE_LEVEL':'trace' if mode=='trace' else 'default',
                              'PN_OBSERVE_ARTIFACT_DIR':str((artifact/(mode+'-objects')).resolve())}
            result=compare([str(target/'examples/records_observation'),mode],mode,env)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            samples[mode]=(result.returncode,result.stdout)
            (artifact/(mode+'.jsonl')).write_bytes(result.stderr)
            (artifact/(mode+'.stdout')).write_bytes(result.stdout)
            rows=[json.loads(line) for line in result.stderr.splitlines()]
            if mode=='disabled':continue
            summary=expanded(next(row['metrics'] for row in rows if row.get('kind')=='metric_summary'))
            accounting[mode]={key:value for key,value in distribution(summary).items() if key[0].startswith('records__')}
            stem='records__root__sig__design__records__'
            self.assertEqual(accounting[mode],{(stem+'started_operations',''):11,(stem+'completed_operations','success'):7,(stem+'completed_operations','refusal'):4})
            elapsed=next(row for row in summary['instruments'] if row['name']==stem+'elapsed_seconds')
            self.assertEqual(elapsed['count'],11)
            per_operation={(row['operation'],row['outcome']):row['counter'] for row in summary['instruments'] if row['name']==stem+'completed_operations' and row['counter']}
            expected={('dependency-status','success'):1,('validate-history','success'):1,('validate-record','success'):1,('validate-record','refusal'):1,('complete-act-access','success'):1,('resolve-public-reference','success'):1,('resolve-public-reference','refusal'):1,('select-effective-declaration','success'):1,('select-effective-declaration','refusal'):1,('assemble-boundary-inputs','success'):1,('assemble-boundary-inputs','refusal'):1}
            self.assertEqual(per_operation,expected)
            starts={row['operation']:row['counter'] for row in summary['instruments'] if row['name']==stem+'started_operations' and row['counter']}
            self.assertEqual(starts,{operation:sum(count for (name,_),count in expected.items() if name==operation) for operation,_ in expected})
            instruments={row['name']:row for row in summary['instruments']}
            for name,value in [('validated_records',2),('resolved_references',1),('refusals',4)]:
                self.assertEqual(instruments[stem+name]['counter'],value)
            for name in ('active_validation','live_carrier_bytes'):
                self.assertEqual(instruments[stem+name]['gauge'],0)
            self.assertEqual(instruments[stem+'input_bytes']['count'],3)
            self.assertEqual(instruments[stem+'records_per_boundary']['count'],1)
            self.assertEqual(instruments[stem+'records_per_boundary']['sum'],2)
            self.assertEqual(instruments[stem+'work_operations']['counter'],11)
            self.assertEqual(instruments[stem+'assembly_steps']['counter'],4)
            self.assertEqual(summary['lost_counter_updates'],0)
            status=next(row for row in rows if row.get('kind')=='observation_status')
            reconcile_publication(status,len(rows)-1)
            self.assertEqual(status['attempted_records'],status['delivered_records']+status['in_flight_records']+status['lost_records']+status['undelivered_records'])
            self.assertEqual(status['lost_records'],0)
            if mode=='default':self.assertFalse(any(row.get('kind')=='span_envelope' for row in rows))
            else:
                self.assertIn(b'authentication_evidence',result.stderr)
                for operation in (b'validate-record',b'resolve-public-reference',b'select-effective-declaration'):
                    self.assertIn(operation,result.stderr)
            print('RECORDS-OBSERVATION level='+mode+' started=11 success=7 refusal=4 error=0 timed=11 validated=2 resolved=1 refusals=4 assembled=2')
        self.assertTrue(all(value==samples['disabled'] for value in samples.values()))
        self.assertEqual(accounting['default'],accounting['trace'])

    def test_rendezvous_failures(self):
        """Claim: Non-JSON diagnostics and a final status without a summary release the fixture, reader EOF also releases it, and an injected deadline kills a wedged fixture and fails explicitly instead of hanging verification.
        ´claim:discipline:observation-rendezvous-fails-within-its-deadline´
        ´test:integration:test-rendezvous-failures´
        """
        import io
        from unittest.mock import patch
        class Process:
            def __init__(self, evidence, timeout=False):
                self.stdin=io.BytesIO();self.stdout=io.BytesIO(b'result');self.stderr=io.BytesIO(evidence)
                self.timeout=timeout;self.killed=False
            def wait(self, timeout):
                if self.timeout and not self.killed:raise subprocess.TimeoutExpired('fixture',timeout)
                return -9 if self.killed else 0
            def kill(self):self.killed=True
        for evidence in (b'not JSON\n{"kind":"observation_status"}\n',b'not JSON\n'):
            process=Process(evidence)
            # Retain writes after close for the release assertion.
            class Input(io.BytesIO):
                def close(self):self.released=self.getvalue()
            process.stdin=Input()
            with patch('subprocess.Popen',return_value=process):result=compare(['fixture'],'trace',{},injected=True)
            self.assertEqual(result.stdout,b'result'); self.assertIn(b'\n',process.stdin.released)
            process=Process(evidence,True)
            with patch('subprocess.Popen',return_value=process):
                with self.assertRaisesRegex(AssertionError,'deadline exceeded'):compare(['fixture'],'trace',{},injected=True)
            self.assertTrue(process.killed)

    def test_four_mode_results(self):
        """Claim: Disabled, default, full-trace and locally failing-export full-trace executions preserve the four-package workload's exact JSON stdout and exit; all enabled modes count the same labelled operations and terminal outcome distributions, default omits only unobserved series, and an unknown level refuses document execution before work.
        ´claim:discipline:four-observation-modes-preserve-command-results´
        ´test:integration:test-four-mode-results´
        """
        target=Path(os.environ['CARGO_TARGET_DIR'])/'gate'
        env={key:value for key,value in os.environ.items() if key!='RUST_LOG'}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'docs/inputs').mkdir(parents=True)
            (root/'docs/templates/docs').mkdir(parents=True)
            (root/'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            (root/'docs/inputs/items.toml').write_text('namespace="org.peer-network.test.items"\nversion=[1,0,0]\n[[rows]]\nname="alpha"\ncount=2\n')
            (root/'docs/templates/docs/result.md.j2').write_text("{{ row('org.peer-network.test.items', name='alpha').count | number }}\n")
            for command in (['git','init','--quiet'],[str(target/'documents'),'generate'],[str(target/'documents'),'write'],['git','add','-A']):
                result=run(command,cwd=root,env=env)
                self.assertEqual(result.returncode,0 if command[0]=='git' else 3,result.stderr.decode())
            samples={}
            accounting={}
            artifact=Path('.lane/observation-comparison');artifact.mkdir(exist_ok=True)
            for mode in ('disabled','default','trace','failing-export'):
                objects=artifact/(mode+'-objects')
                selected=env | {'PN_OBSERVE_LEVEL':'trace' if mode in ('trace','failing-export') else 'default', 'PN_OBSERVE_ARTIFACT_DIR':str(objects.resolve())}
                result=compare([str(target/'examples/observation_compare'),mode,str(root)],mode,selected)
                self.assertEqual(result.returncode,0,result.stderr.decode())
                samples[mode]=(result.returncode,result.stdout)
                (artifact/(mode+'.stdout')).write_bytes(result.stdout)
                (artifact/(mode+'.jsonl')).write_bytes(result.stderr)
                rows=[json.loads(line) for line in result.stderr.splitlines()]
                if mode!='disabled':
                    summary=expanded(next(row['metrics'] for row in rows if row.get('kind')=='metric_summary'))
                    accounting[mode]=distribution(summary)
                    for owner in ('documents','interchange','execwrap','clicommon'):
                        self.assertTrue(any(name[0].startswith(owner+'__') and count>0 for name,count in accounting[mode].items()))
                    self.assertEqual(len(summary['instruments'])+(summary['declared_but_unobserved'] if mode=='default' else 0),summary['declared_series'])
                self.assertNotIn(b'fixture-private-token',result.stdout+result.stderr)
                if mode=='disabled':
                    self.assertEqual(len(rows),1)
                    self.assertEqual(rows[0].get('availability'),'disabled')
                    self.assertEqual(rows[0].get('kind'),'observation_status')
                elif mode=='default':
                    self.assertFalse(any(row.get('kind') in ('trace','span_envelope') for row in rows))
                    status=next(row for row in rows if row.get('kind')=='observation_status')
                    self.assertEqual(status['lost_records'],0)
                    reconcile_publication(status,len(rows)-1)
                    self.assertEqual(status['attempted_records'],status['delivered_records']+status['in_flight_records']+status['lost_records']+status['undelivered_records'])
                    self.assertFalse(objects.exists())
                else:
                    self.assertTrue(any(row.get('kind')=='span_envelope' for row in rows))
                    status=next(row for row in rows if row.get('kind')=='observation_status')
                    reconcile_publication(status,len(rows)-1)
                    self.assertEqual(status['attempted_records'],status['delivered_records']+status['in_flight_records']+status['lost_records']+status['undelivered_records'])
                    self.assertEqual(status['lost_records'],0)
                    self.assertTrue(all(value==0 for value in status['loss_causes'].values()))
                if mode=='failing-export':self.assertTrue(any(row.get('kind')=='export_summary' and row['lost_exports']>0 for row in rows))
            self.assertTrue(all(sample==samples['disabled'] for sample in samples.values()))
            self.assertTrue(all(sample==accounting['default'] for sample in accounting.values()))
            document_runs={}
            document_outcomes={}
            for level in ("default","trace"):
                result=run([str(target/"documents"),"check"],cwd=root,env=env | {"PN_OBSERVE_LEVEL":level})
                self.assertEqual(result.returncode,0,result.stderr.decode())
                document_runs[level]=(result.returncode,result.stdout)
                (artifact/("documents-"+level+".jsonl")).write_bytes(result.stderr)
                rows=[json.loads(line) for line in result.stderr.splitlines()]
                summary=expanded(next(row["metrics"] for row in rows if row.get("kind")=="metric_summary"))
                document_outcomes[level]=distribution(summary)
            self.assertEqual(document_runs["default"],document_runs["trace"])
            self.assertEqual(document_outcomes["default"],document_outcomes["trace"])
            report=json.loads(samples['disabled'][1])
            self.assertEqual(report['canonical'],[130,24,42,97,120])
            self.assertEqual(report['verdict'],'AcceptedStrictly { minor: 0 }')
            self.assertEqual(report['documents']['findings'],[])
            self.assertEqual(report['child_stdout'],list(b'public\x00\xff'))
            self.assertEqual(report['child_stderr'],list(b'diagnostic'))
            self.assertEqual(report['child_exit'],7)
            self.assertFalse(report['child_loss'])
            refused=run([str(target/'documents'),'check'],cwd=root,env=env | {'PN_OBSERVE_LEVEL':'unknown'})
            self.assertEqual(refused.returncode,2)
            self.assertEqual(refused.stdout,b'')
            diagnostic=json.loads(refused.stderr)
            self.assertIn('PN_OBSERVE_LEVEL',diagnostic['message'])


if __name__=='__main__':unittest.main()
