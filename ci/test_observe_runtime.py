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
            if row['delivered_records']!=delivered:raise AssertionError('trace delivered count differs from captured records')
        if not injected and row.get('level')=='trace' and row.get('lost_records',0)>0:
            from devperf import report_loss
            from harness import source_id
            report_loss(dict(source=source_id(),configuration='foundation trace witness',operation=argv[0],outcome=f'exit:{status}',
                             level='trace',process_id=row['process_id'],utc=row['timestamp'],delivered_records=row['delivered_records'],lost_records=row['lost_records']),
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
                             env=env | {'PN_TEST_OBSERVATION_RENDEZVOUS':'1'})
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
    result={}
    for row in summary['instruments']:
        if row['name'].endswith(('started_operations','completed_operations')) and row['counter']>0:
            key=(row['name'],row.get('outcome',''))
            result[key]=result.get(key,0)+row['counter']
    return result


class Processes(unittest.TestCase):
    def test_interchange_refusal(self):
        """Claim: Canonical value/document decode, content-key and prefix validation, routing and unheld acceptance retain their exact rejection predicates at default and trace, booking fifteen boundary refusals and no errors with identical complete outcome distributions; a truncated prefix still returns its original error.
        ´claim:discipline:interchange-refusals-have-contract-outcomes´
        ´test:integration:test-interchange-refusal´
        """
        root=Path.cwd()
        with tempfile.TemporaryDirectory(prefix='interchange-outcome-') as temporary:
            fixture=Path(temporary);(fixture/'src').mkdir()
            (fixture/'src/main.rs').write_bytes((root/'ci/fixtures/interchange_observation.rs').read_bytes())
            (fixture/'Cargo.toml').write_text('[package]\nname="interchange-outcome-probe"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\ncli-common={path='+json.dumps(str(root/'packages/cli-common'))+'}\npn-interchange={path='+json.dumps(str(root/'packages/interchange'))+'}\ntracing="0.1"\n[profile.gate]\ninherits="dev"\nopt-level=1\ndebug=0\n')
            build=run(['cargo','build','--offline','--profile','gate','--manifest-path',str(fixture/'Cargo.toml')])
            self.assertEqual(build.returncode,0,build.stderr.decode())
            distributions={}
            for mode in ('default','trace'):
                result=compare([str(Path(os.environ['CARGO_TARGET_DIR'])/'gate/interchange-outcome-probe')],mode,os.environ|{'PN_OBSERVE_LEVEL':mode})
                self.assertEqual(result.returncode,0,result.stderr.decode())
                rows=[json.loads(line) for line in result.stderr.splitlines()]
                summary=expanded(next(row['metrics'] for row in rows if row.get('kind')=='metric_summary'))
                stem='interchange__root__rule__observe__spans__'
                distributions[mode]={k:v for k,v in distribution(summary).items() if k[0].startswith(stem)}
                self.assertEqual(distributions[mode][stem+'completed_operations','refusal'],15)
                self.assertNotIn((stem+'completed_operations','error'),distributions[mode])
                print('INTERCHANGE-OBSERVATION level='+mode+' distribution='+json.dumps({str(k):v for k,v in distributions[mode].items()},sort_keys=True))
            self.assertEqual(distributions['default'],distributions['trace'])

    def test_records_entry(self):
        """Claim: The first domain entry counts and times successful validation, complete-act access, reference resolution and historical edition selection, validated history and boundary assembly, plus their typed refusals at default and trace, with identical outcome distributions and unchanged JSON stdout and exit when observation is disabled; trace carries the public act content.
        ´claim:discipline:records-entry-is-observed-without-changing-results´
        ´test:integration:test-records-entry´
        """
        target=Path(os.environ['CARGO_TARGET_DIR'])/'gate'
        build=run(['cargo','build','--offline','--locked','--profile','gate','-p','pn-records','--example','records_observation'])
        self.assertEqual(build.returncode,0,build.stderr.decode())
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
            self.assertEqual(instruments[stem+'work_operations']['counter'],15)
            self.assertEqual(summary['lost_updates'],0)
            status=next(row for row in rows if row.get('kind')=='observation_status')
            self.assertEqual(status['delivered_records'],len(rows)-1)
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
        build=run(['cargo','build','--offline','--locked','--profile','gate','-p','execwrap','--example','observation_compare'])
        self.assertEqual(build.returncode,0,build.stderr.decode())
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
                    self.assertEqual(status['delivered_records'],len(rows)-1)
                    self.assertFalse(objects.exists())
                else:
                    self.assertTrue(any(row.get('kind')=='span_envelope' for row in rows))
                    status=next(row for row in rows if row.get('kind')=='observation_status')
                    self.assertEqual(status['delivered_records'],len(rows)-1)
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
