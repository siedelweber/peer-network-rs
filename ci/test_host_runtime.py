"""Real host transport observation without admitting persistence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
import tomllib
import copy
import re
import base64
import ipaddress
import tempfile
import io
import contextlib
from unittest.mock import patch

from test_observe_runtime import expanded, distribution, witness


def private_occurs(value, text):
    # A port token must not mistake an unrelated clock fraction for reachability.
    return bool(re.search(r'(?<![\d.])'+re.escape(value)+r'(?![\d.])',text)) if value.isdecimal() else value in text

def decoded_content(value):
    """Scan expanded JSON and serde-Value Debug objects, including binary frames."""
    def scalar(item):
        if isinstance(item,dict) and item.get('constructor')=='String' and len(item.get('arguments',[]))==1:
            return item['arguments'][0]
        return item
    if isinstance(value,dict):
        encoded=value
        if value.get('type')=='Object':
            entries=value.get('fields',{}).get('entries',[])
            if all(isinstance(pair,list) and len(pair)==2 and isinstance(pair[0],str) for pair in entries):
                encoded={key:scalar(item) for key,item in entries}
        decoded=''
        if encoded.get('encoding')=='base64':
            decoded=base64.b64decode(encoded['data'],validate=True).decode('utf-8',errors='replace')+'\n'
        return decoded+'\n'.join(str(k)+'\n'+decoded_content(v) for k,v in value.items())
    if isinstance(value,list):
        return '\n'.join(decoded_content(v) for v in value)
    return str(value)


def decoded_frames(value):
    """Return exact bytes, without a lossy UTF-8 conversion of binary DataRows."""
    if isinstance(value,dict):
        encoded=value
        if value.get('type')=='Object':
            entries=value.get('fields',{}).get('entries',[])
            if all(isinstance(p,list) and len(p)==2 and isinstance(p[0],str) for p in entries):
                encoded={k:(v['arguments'][0] if isinstance(v,dict) and v.get('constructor')=='String' and len(v.get('arguments',[]))==1 else v) for k,v in entries}
        if encoded.get('encoding')=='base64':yield base64.b64decode(encoded['data'],validate=True)
        elif encoded.get('encoding')=='utf-8':yield encoded['data'].encode()
        for item in value.values():yield from decoded_frames(item)
    elif isinstance(value,list):
        for item in value:yield from decoded_frames(item)


def binary_reachability(config, rows):
    frames=list(decoded_frames(rows))
    patterns={'port':int(config['port']).to_bytes(4,'big')}
    try:patterns['endpoint']=ipaddress.ip_address(config['endpoint']).packed
    except ValueError:pass  # A Unix path is already covered by the textual scan.
    return {name for name,pattern in patterns.items() if any(pattern in frame for frame in frames)}


def capture_complete(status):
    """A lossless capture is complete. A capture may count lost records, for more than one possible cause; every
    loss must then name its cause, and the capture is incomplete evidence rather than a failure of the run."""
    accounting=json.dumps({key:status.get(key) for key in ('level','attempted_records','delivered_records','lost_records',
        'undelivered_records','in_flight_records','drain_timeouts','drain_unavailable','loss_causes')},sort_keys=True)
    if status['lost_records']!=sum(status['loss_causes'].values()):
        raise AssertionError('observation loss without a named cause: '+accounting)
    return status['lost_records']==0 and status['undelivered_records']==0 and status['in_flight_records']==0, accounting


def traced_capture(test, command, env, level, validate, attempts=3, prefix='storage'):
    """The child writes observations to a file, so its delivery never waits on this reader; a capture that still
    counts loss is retaken, at most three times. Every attempt is checked and reported before selection."""
    for attempt in range(1,attempts+1):
        sink=Path(f'.lane/{prefix}-{level}.stderr.jsonl')
        started=time.monotonic()
        with sink.open('wb') as stream:
            result=subprocess.run(command,env=env,stdout=subprocess.PIPE,stderr=stream,timeout=60,check=False)
        wall=time.monotonic()-started
        stderr=sink.read_bytes()
        witness(command,result.returncode,wall,stderr)
        test.assertEqual(result.returncode,0,stderr.decode())
        rows=[expanded(json.loads(line)) for line in stderr.splitlines()]
        status=next(row for row in rows if row.get('kind')=='observation_status')
        validate(result,rows)
        complete,accounting=capture_complete(status)
        if complete:
            return result,rows,status,wall
        print(f'{prefix.upper()}-RUNTIME level={level} attempt={attempt} incomplete={accounting} wall_seconds={wall:.3f}')
    test.fail(f'no complete {level} capture in {attempts} attempts: {accounting}')


def capture_validator(test, configurations, outputs):
    """Read each attempt's fixture configuration after its child has completed."""
    def validate(result, rows):
        text=decoded_content(rows)
        test.assertNotIn('private_unread_input',text)
        test.assertNotIn('private_unread_input',result.stdout.decode())
        for config in configurations():
            test.assertFalse(binary_reachability(config,rows),'binary private reachability')
            for key,value in config.items():
                if key!='transport':
                    test.assertFalse(private_occurs(str(value),text),'private fixture content')
                    test.assertFalse(private_occurs(str(value),result.stdout.decode()),'private result content')
        public=[line for line in result.stdout.splitlines() if line.startswith(b'{')]
        test.assertEqual(len(public),1)
        if outputs:test.assertEqual(public,outputs[0],'public result differs between completed children')
        outputs.append(public)
    return validate


def storage_retake_control(test, command, env, validate, statements):
    """Discard one captured record after checking the real child's complete content.

    The injected loss selects the real retake path without generating node load.
    Real child accounting is witnessed separately; injected findings stay local.
    """
    from devperf import report_loss
    module=sys.modules[__name__]
    run=subprocess.run
    observe=witness
    calls=[]
    original=[]
    findings=Path('.lane/storage-retake-control-findings.jsonl')
    findings.unlink(missing_ok=True)
    def child(argv, **kwargs):
        # Only the control's own children count; any other subprocess, such as the witness's own
        # loss reporting, passes through uncounted and unaltered.
        if argv!=command:
            return run(argv,**kwargs)
        calls.append(argv)
        result=run(argv,**kwargs)
        if len(calls)==1 and result.returncode==0:
            stream=kwargs['stderr'];stream.flush()
            raw=Path(stream.name).read_bytes();original.append(raw)
            rows=[expanded(json.loads(line)) for line in raw.splitlines()]
            validate(result,rows)  # No delivered private content can be discarded unchecked.
            status=next(row for row in rows if row.get('kind')=='observation_status')
            victim=next(i for i,row in enumerate(rows) if row.get('kind')!='observation_status' and row.get('process_id')==status['process_id'])
            rows.pop(victim)
            status['delivered_records']-=1
            status['lost_records']+=1
            status['loss_causes']['capture_overflow']=status['loss_causes'].get('capture_overflow',0)+1
            stream.seek(0);stream.truncate()
            stream.write(b''.join(json.dumps(row).encode()+b'\n' for row in rows));stream.flush()
        return result
    def observed(argv, status, wall, stderr):
        injected=len(calls)==1 and bool(original)
        if injected:
            observe(argv,status,wall,original[0])
            row=next(json.loads(line) for line in stderr.splitlines() if json.loads(line).get('kind')=='observation_status')
            report_loss(dict(source='injected-storage-retake',configuration='injected capture discard control',operation=argv[0],outcome=f'exit:{status}',
                level='trace',process_id=row['process_id'],utc=row['timestamp'],delivered_records=row['delivered_records'],lost_records=row['lost_records'],
                undelivered_records=row['undelivered_records'],loss_causes=row['loss_causes']),findings,warnings=io.StringIO())
        observe(argv,status,wall,stderr,injected=injected)
    with patch('subprocess.run',side_effect=child),patch.object(module,'witness',side_effect=observed):
        _,rows,status,_=traced_capture(test,command,env,'trace',validate,prefix='storage-retake-control')
    test.assertGreaterEqual(len(calls),2)
    test.assertLessEqual(len(calls),3)
    test.assertTrue(all(argv==command for argv in calls))
    test.assertEqual(status['delivered_records'],len(rows)-1)
    text=decoded_content(rows)
    for statement in statements:test.assertIn(statement,text)
    retained=[json.loads(line) for line in findings.read_text().splitlines()]
    test.assertEqual(len(retained),1)
    test.assertEqual(retained[0]['classification'],'observation-completeness')
    test.assertEqual(retained[0]['outcome'],'exit:0')
    test.assertEqual(retained[0]['verdict_effect'],'none')
    print(f'STORAGE-RETAKE-CONTROL injected=capture-discard attempts={len(calls)} statements={len(statements)} catalogue=present finding=retained')


def sentinel_control(test, command, env, found, prefix, attempts=3):
    """A positive control reads its child's trace from a file, as every capture does, and selects its evidence
    by the capture's own accounting. An attempt in which the sentinel is found detects it whatever its loss, since
    a delivered record proves the value reached observation; a complete attempt without it is a detection failure;
    an attempt that counts loss without it is inconclusive, because the record carrying the value may be the one
    lost, and is reported and retaken as an independent child. Inconclusive attempts in all three report their
    counted loss, never a missing detection."""
    accounting=None
    for attempt in range(1,attempts+1):
        sink=Path(f'.lane/{prefix}.stderr.jsonl')
        started=time.monotonic()
        with sink.open('wb') as stream:
            result=subprocess.run(command,env=env,stdout=subprocess.PIPE,stderr=stream,timeout=60,check=False)
        wall=time.monotonic()-started
        stderr=sink.read_bytes()
        witness(command,result.returncode,wall,stderr)
        test.assertEqual(result.returncode,0,stderr.decode())
        rows=[expanded(json.loads(line)) for line in stderr.splitlines()]
        status=next(row for row in rows if row.get('kind')=='observation_status')
        complete,accounting=capture_complete(status)
        if found(rows):
            return rows,attempt,wall
        if complete:
            test.fail(f'{prefix}: sentinel not detected in a complete capture: {accounting}')
        print(f'{prefix.upper()} attempt={attempt} inconclusive={accounting} wall_seconds={wall:.3f}')
    test.fail(f'{prefix}: inconclusive, counted loss in all {attempts} attempts: {accounting}')


def sentinel_selection(test):
    """Synthetic children witness the selection without node load: loss without the value and then a complete
    capture with it detects on the retake; loss with the value detects at once; a complete capture without it
    fails as not detected; and three lossy captures without it fail as inconclusive loss, not as not detected."""
    module=sys.modules[__name__]
    found=lambda rows:'private_sentinel_probe' in decoded_content(rows)
    cases=(('lossy then complete with the value',[(1,False),(0,True)],2,None),
           ('lossy with the value',[(1,True)],1,None),
           ('complete without the value',[(0,False)],1,'not detected in a complete capture'),
           ('lossy without the value three times',[(1,False)]*3,3,'inconclusive, counted loss in all 3 attempts'))
    for name,plan,expected_calls,failure in cases:
        calls=[]
        def child(argv, **kwargs):
            lost,carries=plan[len(calls)]
            calls.append(argv)
            rows=[dict(kind='public',value='public_row')]+([dict(kind='public',value='private_sentinel_probe')] if carries else [])
            for row in rows:row['process_id']=1
            rows.append(dict(kind='observation_status',level='trace',process_id=1,timestamp='2026-10-29T00:00:00Z',attempted_records=len(rows)+lost,
                delivered_records=len(rows),lost_records=lost,undelivered_records=0,in_flight_records=0,loss_causes={'queue_full':lost}))
            kwargs['stderr'].write(b''.join(json.dumps(row).encode()+b'\n' for row in rows))
            return subprocess.CompletedProcess(argv,0,stdout=b'',stderr=b'')
        with patch('subprocess.run',side_effect=child),patch.object(module,'witness'),contextlib.redirect_stdout(io.StringIO()):
            if failure is None:
                _,attempt,_=sentinel_control(test,['synthetic-child'],{},found,'sentinel-selection')
                test.assertEqual(attempt,expected_calls,name)
            else:
                with test.assertRaisesRegex(AssertionError,failure):
                    sentinel_control(test,['synthetic-child'],{},found,'sentinel-selection')
        test.assertEqual(len(calls),expected_calls,name)
    print('SENTINEL-SELECTION lossy-then-complete=detected lossy-with-value=detected complete-without=not-detected lossy-thrice=inconclusive-loss')


def forced_loss_control(test, command, env, value, prefix, preparations=3):
    """Force a lost carrying record into one capture under the same accounting as every capture.

    Preparation runs children until one capture carries the value, at most `preparations` times. Each child is
    witnessed with its own accounting before anything about its content is asserted, then its exit and status are
    checked; a complete capture without the value fails as a miss, and a capture that counts loss without it is
    inconclusive and prepared again. The prepared capture loses every record carrying the value, counted as capture
    loss, and is replayed as the first attempt of the shared selection rule; it must be inconclusive, and a later
    real attempt within that rule's bound must detect the value. The replay is not witnessed again: its child was
    witnessed with its original accounting, so the forced discard is not reported as node loss."""
    module=sys.modules[__name__]
    run=subprocess.run
    observe=witness
    carries=lambda rows:private_occurs(value,decoded_content(rows))
    prepared=None
    accounting=None
    for preparation in range(1,preparations+1):
        sink=Path(f'.lane/{prefix}-preparation.stderr.jsonl')
        started=time.monotonic()
        with sink.open('wb') as stream:
            result=run(command,env=env,stdout=subprocess.PIPE,stderr=stream,timeout=60,check=False)
        wall=time.monotonic()-started
        raw=sink.read_bytes()
        observe(command,result.returncode,wall,raw)
        test.assertEqual(result.returncode,0,raw.decode())
        rows=[json.loads(line) for line in raw.splitlines()]
        status=next(row for row in rows if row.get('kind')=='observation_status')
        complete,accounting=capture_complete(status)
        carrying={index for index,row in enumerate(rows) if row.get('kind')!='observation_status' and carries([expanded(row)])}
        if carrying:
            prepared=(result,rows,carrying)
            break
        if complete:
            test.fail(f'{prefix}: sentinel not detected in a complete capture: {accounting}')
        print(f'{prefix.upper()} preparation={preparation} inconclusive={accounting} wall_seconds={wall:.3f}')
    if prepared is None:
        test.fail(f'{prefix}: no capture carried the value in {preparations} preparations: {accounting}')
    result,rows,carrying=prepared
    status=next(row for row in rows if row.get('kind')=='observation_status')
    status['delivered_records']-=len(carrying)
    status['lost_records']+=len(carrying)
    status['loss_causes']['capture_overflow']=status['loss_causes'].get('capture_overflow',0)+len(carrying)
    injected=b''.join(json.dumps(row).encode()+b'\n' for index,row in enumerate(rows) if index not in carrying)
    calls=[]
    def child(argv, **kwargs):
        # Only the control's own children count; any other subprocess, such as a real witness's own
        # loss reporting on a lossy detecting attempt, passes through uncounted and unaltered.
        if argv!=command:
            return run(argv,**kwargs)
        calls.append(argv)
        if len(calls)==1:
            kwargs['stderr'].write(injected)
            return subprocess.CompletedProcess(argv,0,stdout=result.stdout,stderr=b'')
        return run(argv,**kwargs)
    def observed(argv, status, wall, stderr):
        if len(calls)>1:
            observe(argv,status,wall,stderr)
    with patch('subprocess.run',side_effect=child),patch.object(module,'witness',side_effect=observed):
        _,attempt,_=sentinel_control(test,command,env,carries,prefix)
    test.assertGreaterEqual(attempt,2,'the capture that lost its carrying records must be inconclusive')
    test.assertEqual(len(calls),attempt)
    test.assertTrue(all(argv==command for argv in calls))
    return attempt


def synthetic_children(plan, command, statements=()):
    """Synthetic children for calls whose argv is `command`, one per plan entry of exit code, counted loss and
    whether the capture carries the value; any other subprocess passes through as a successful no-op, recorded
    apart, so a test can see that it happened without it consuming a child's plan entry."""
    children=[]
    others=[]
    def child(argv, **kwargs):
        if argv!=command:
            others.append(argv)
            return subprocess.CompletedProcess(argv,0,stdout=b'',stderr=b'')
        code,lost,carrying=plan[len(children)]
        children.append(argv)
        rows=[dict(kind='public',value=' '.join(('public_row',)+tuple(statements)))]
        rows.extend([dict(kind='public',value='private_sentinel_probe')] if carrying else [])
        for row in rows:row['process_id']=1
        rows.append(dict(kind='observation_status',level='trace',process_id=1,timestamp='2026-10-29T00:00:00Z',attempted_records=len(rows)+lost,
            delivered_records=len(rows),lost_records=lost,undelivered_records=0,in_flight_records=0,loss_causes={'queue_full':lost}))
        kwargs['stderr'].write(b''.join(json.dumps(row).encode()+b'\n' for row in rows))
        return subprocess.CompletedProcess(argv,code,stdout=b'',stderr=b'')
    return child,children,others


def reporting_witness(argv, status, wall, stderr, **kwargs):
    """A stand-in witness that, like the real one on its loss-reporting path, makes its own subprocess call when
    a capture counts loss."""
    row=next(json.loads(line) for line in stderr.splitlines() if json.loads(line).get('kind')=='observation_status')
    if row['lost_records']:
        subprocess.run(['git','rev-parse','HEAD'],capture_output=True,check=False)


def forced_loss_cases(test):
    """Synthetic children witness the forced-loss control without node load: natural loss before injection, natural
    loss on the retake, and a lossy detecting attempt whose witness makes its own subprocess call all end in
    detection on the right attempt with the right child count, while a complete miss, in preparation or on the
    retake, and a failed child stay failures."""
    module=sys.modules[__name__]
    command=['synthetic-child']
    cases=(('natural loss before injection',[(0,1,False),(0,0,True),(0,0,True)],3,2,None),
           ('natural loss on the retake',[(0,0,True),(0,1,False),(0,0,True)],3,3,None),
           ('lossy detecting attempt with a witness subprocess',[(0,0,True),(0,1,True)],2,2,None),
           ('complete miss in preparation',[(0,0,False)],1,None,'not detected in a complete capture'),
           ('complete miss on the retake',[(0,0,True),(0,0,False)],2,None,'not detected in a complete capture'),
           ('failed child',[(7,0,True)],1,None,'7 != 0'))
    for name,plan,expected_children,expected_attempt,failure in cases:
        child,children,others=synthetic_children(plan,command)
        with patch('subprocess.run',side_effect=child),patch.object(module,'witness',side_effect=reporting_witness),contextlib.redirect_stdout(io.StringIO()):
            if failure is None:
                attempt=forced_loss_control(test,command,{},'private_sentinel_probe','forced-loss-cases')
                test.assertEqual(attempt,expected_attempt,name)
            else:
                with test.assertRaisesRegex(AssertionError,failure):
                    forced_loss_control(test,command,{},'private_sentinel_probe','forced-loss-cases')
        test.assertEqual(len(children),expected_children,name)
        if name=='lossy detecting attempt with a witness subprocess':
            test.assertTrue(others,'the witness made no subprocess call of its own')
    print('FORCED-LOSS-CASES loss-before-injection=detected loss-on-retake=detected lossy-detection-with-witness-subprocess=detected '
          'complete-miss=failure retake-miss=failure failed-child=failure')


def retake_counting_cases(test):
    """The storage retake control against synthetic children: an injected first capture, a naturally lossy retake
    whose witness makes its own subprocess call and a complete third capture still select the third child, and
    only the control's three children are counted."""
    module=sys.modules[__name__]
    command=['synthetic-child']
    statements=['SELECT synthetic_statement']
    child,children,others=synthetic_children([(0,0,False),(0,1,False),(0,0,False)],command,statements)
    def report(record, findings, warnings=None):
        findings.write_text(json.dumps(dict(classification='observation-completeness',outcome=record['outcome'],verdict_effect='none'))+'\n')
    with patch('subprocess.run',side_effect=child),patch.object(module,'witness',side_effect=reporting_witness),patch('devperf.report_loss',side_effect=report),contextlib.redirect_stdout(io.StringIO()):
        storage_retake_control(test,command,{},lambda result,rows:None,statements)
    test.assertEqual(len(children),3)
    test.assertTrue(others,'the witness made no subprocess call of its own')
    print('RETAKE-COUNTING-CASES injected-then-lossy-retake-with-witness-subprocess=third-child children=3')


def sentinel_retake_control(test, command, env, value):
    """The private control against real children with a forced lost carrying record."""
    attempt=forced_loss_control(test,command,env,value,'storage-sentinel-retake')
    print(f'STORAGE-SENTINEL-RETAKE injected=lost-carrying-record detected_attempt={attempt}')


def capture_regressions(test, prefix):
    """Run both real test bodies against bad incomplete children followed by clean answers."""
    from devperf import report_loss
    module=sys.modules[__name__]
    run=subprocess.run
    config=dict(endpoint='192.0.2.31',port='42617',user='private_role_probe',password='private_password_probe',transport='tcp')
    public=b'{"store_link_case":"host-secured","persistence":"disabled","value":731}\n'
    source=Path('packages/host/src/storage.rs').read_text().split('impl Statement {',1)[1].split('// The raw driver',1)[0]
    statements=re.findall(r'Self::[A-Za-z]+\s*=>\s*(?:\{\s*)?"([^"\n]+)"',source)
    method='test_storage_statements' if prefix=='storage' else 'test_public_transport'
    with tempfile.TemporaryDirectory(dir='.lane') as directory:
        root=Path(directory).resolve();(root/'.lane').mkdir()
        (root/'.lane/host-test-binary.txt').write_text('synthetic-child')
        for name in ('storage-trace-default','storage-trace-trace','tcp'):
            (root/(name+'.json')).write_text(json.dumps(config))
        path_type=Path
        def path(value):
            value=path_type(value)
            return root/value if value.parts and value.parts[0]=='.lane' else value
        for fault in ('role','password','binary','result','exit','recovery'):
            calls=[];trace_attempts=[];findings=root/'findings.jsonl';findings.unlink(missing_ok=True)
            def child(command, **kwargs):
                # Only the synthetic test binary is a child; any other subprocess passes through unaltered.
                if command[0]!='synthetic-child':
                    return run(command,**kwargs)
                env=kwargs['env'];level=env['PN_OBSERVE_LEVEL']
                control=env.get('PN_HOST_STORAGE_PRIVATE_CONTROL')=='1'
                if level=='trace' and not control:trace_attempts.append(command)
                incomplete=level=='trace' and len(trace_attempts)==1 and not control
                rows=[dict(kind='public',value='public_storage_payload_731 public_result_sentinel_731 '+('public_row_'*3)+' SELECT division by zero',statements=statements)]
                rows.extend(dict(kind='diagnostic',level='WARN',value='MissingCase HeldCase UnknownCase RepresentationLimit Transport Protocol PrivateDiagnostic') for _ in range(13))
                rows.append(dict(kind='metric_summary',metrics=dict(counter_accuracy='exact',lost_counter_updates=0,
                    instruments=[dict(name='host__started_operations',counter=1),dict(name='host__completed_operations',outcome='success',counter=1)])))
                if control or incomplete and fault in ('role','password','binary'):
                    value=config['user'].encode() if control or fault=='role' else (config['password'].encode() if fault=='password' else int(config['port']).to_bytes(4,'big'))
                    rows.append(dict(kind='public',frame=dict(encoding='base64',data=base64.b64encode(value).decode())))
                for row in rows:row['process_id']=731
                lost=int(incomplete)
                rows.append(dict(kind='observation_status',level=level,process_id=731,timestamp='2026-10-26T00:00:00Z',
                    attempted_records=len(rows)+lost,delivered_records=len(rows),lost_records=lost,undelivered_records=0,in_flight_records=0,loss_causes={'queue_full':lost}))
                stderr=b''.join(json.dumps(row).encode()+b'\n' for row in rows)
                output=public.replace(b'731',b'732') if incomplete and fault=='result' else public
                calls.append((level,control))
                kwargs['stderr'].write(stderr)
                return subprocess.CompletedProcess(command,7 if incomplete and fault=='exit' else 0,stdout=output,stderr=stderr)
            # Keep real loss reporting, but retain synthetic findings only in this fixture.
            def loss_report(record, output):return report_loss(record,findings,warnings=io.StringIO())
            transcript=io.StringIO()
            with patch.object(module,'Path',side_effect=path), patch.object(module,'capture_regressions'), patch.object(module,'storage_retake_control'), patch.object(module,'sentinel_retake_control'), patch.object(module,'sentinel_selection'), patch.object(module,'forced_loss_cases'), patch.object(module,'retake_counting_cases'), patch('subprocess.run',side_effect=child), patch.dict(os.environ,PN_HOST_TEST_ROOT=str(root)), patch('harness.source_id',return_value='synthetic'), patch('devperf.report_loss',side_effect=loss_report) as loss, contextlib.redirect_stdout(transcript):
                operation=getattr(HostRuntime(method),method)
                if fault=='recovery':
                    operation()
                    test.assertEqual(len(trace_attempts),2)
                else:
                    message='7 != 0' if fault=='exit' else ('public result differs' if fault=='result' else ('binary private reachability' if fault=='binary' else 'private fixture content'))
                    with test.assertRaisesRegex(AssertionError,message):operation()
                    test.assertEqual(len(trace_attempts),1,'a clean retake must not erase a delivered violation')
                loss.assert_called_once()
            recorded=[json.loads(line) for line in findings.read_text().splitlines()]
            test.assertEqual(len(recorded),1)
            test.assertEqual(recorded[0]['classification'],'observation-completeness')
            test.assertEqual(recorded[0]['verdict_effect'],'none')
            test.assertEqual(recorded[0]['lost_records'],1)
            test.assertEqual(recorded[0]['outcome'],'exit:7' if fault=='exit' else 'exit:0')
            if fault=='exit':
                lines=[line for line in transcript.getvalue().splitlines() if line.startswith('OBSERVATION-WITNESS ') and 'status=7 ' in line]
                test.assertEqual(len(lines),1)
                test.assertRegex(lines[0],r'delivered=\d+ lost=1 ')
    print(f'CAPTURE-REGRESSIONS surface={prefix} whole-test=True private=refused binary=refused result=refused recovered-loss=finding failed-child=exit:7-finding-and-refusal')


class HostRuntime(unittest.TestCase):
    def test_statement_type_boundary(self):
        """Claim: Production modules cannot name a raw driver client outside its private wrapper and Session constructor; exact refusal probes cover traversal, path attributes, includes and the storage-only exemption, and inline SQL fails compilation at the wrapper's Statement parameter.
        ´claim:discipline:storage-statement-types-refuse-inline-sql´
        ´test:integration:test-statement-type-boundary´
        """
        from host_statements import check
        self.assertTrue(check())
        manifest=Path('packages/host/Cargo.toml')
        manifest_original=manifest.read_bytes()
        lib=Path('packages/host/src/lib.rs')
        lib_original=lib.read_bytes()
        try:
            manifest.write_bytes(manifest_original.replace(
                b'tokio-postgres = { version = "=0.7.18", default-features = false }',
                b'concealed-driver = { package = "tokio-postgres", version = "=0.7.18", default-features = false }'))
            self.assertNotEqual(manifest.read_bytes(),manifest_original)
            lib.write_bytes(lib_original+b'\nfn inferred_renamed_driver() { let _driver = concealed_driver::Config::new(); }\n')
            with self.assertRaisesRegex(ValueError,'driver path outside'):check()
        finally:
            manifest.write_bytes(manifest_original)
            lib.write_bytes(lib_original)
        source=Path('packages/host/src/lib.rs')
        original=source.read_bytes()
        for fixture,message in (
            (b'\nasync fn inferred_driver(stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send) { let (driver, _) = tokio_postgres::Config::new().connect_raw(stream, tokio_postgres::NoTls).await.unwrap(); let _ = driver.simple_query("SELECT current_user").await; }\n',
             'driver path outside the closed statement wrapper and Session constructor: packages/host/src/lib.rs'),
            (b'\ninclude!("hidden.rs");\n', 'production include is not an admitted module: packages/host/src/lib.rs'),
            (b'\n#[path = "config.rs"] mod concealed;\n', 'production module path needs reviewed traversal'),
        ):
            try:
                source.write_bytes(original+fixture)
                with self.assertRaisesRegex(ValueError,re.escape(message)):check()
            finally:source.write_bytes(original)
        source=Path('packages/host/src/config.rs')
        original=source.read_bytes()
        for fixture in (
            b'\nfn traversed_driver() { let _ = tokio_postgres::Config::new(); }\n',
            # A raw-driver import in config must not inherit storage's exemption.
            b'\nuse tokio_postgres::Client as ExemptedClient;\n',
        ):
            try:
                source.write_bytes(original+fixture)
                with self.assertRaisesRegex(ValueError,re.escape('driver path outside the closed statement wrapper and Session constructor: packages/host/src/config.rs')):check()
            finally:source.write_bytes(original)
        source=Path('packages/host/src/storage.rs')
        original=source.read_bytes()
        fixture=b'\n#[cfg(test)] async fn forbidden_inline_sql(t: &StatementTransaction<\'_>) { let _ = t.query("SELECT current_user", &[]).await; }\n'
        try:
            source.write_bytes(original+fixture)
            result=subprocess.run(['cargo','check','--offline','--locked','-p','pn-host','--tests'],capture_output=True,check=False,timeout=180)
        finally:
            source.write_bytes(original)
        Path('.lane/host-statement-compile-fail.log').write_bytes(result.stderr)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'E0308',result.stderr)
        self.assertIn(b'expected `Statement`, found `&str`',result.stderr)
        self.assertIn(b'forbidden_inline_sql',result.stderr)

    def test_storage_statements(self):
        """Claim: Every closed storage statement is exercised under a complete trace capture, written by the child to a file so that delivery never waits on the reader, and its decoded DataRows contain only public fixture content; every attempt resets its dedicated store before observation and checks private content and every completed child's public bytes before any retake, and counted trace loss retains its completeness finding after recovery or a failed child, with the original exit outcome witnessed before refusal; acquisition takes at most three attempts and default and trace return identical bytes, while an injected capture loss forces real-child retaking with all statements including the catalogue query present, and a test-only metadata query is caught at the private role sentinel in a file-captured trace selected by its own accounting: an attempt that delivers the value detects it, an attempt that counts loss without it is inconclusive and retaken at most three times, and loss in every attempt is reported as loss rather than a missing detection, as synthetic selection cases witness; a forced lost carrying record, prepared and retaken under the same accounting, must leave its capture inconclusive and be detected by a later attempt within that bound, with natural loss before injection or on the retake still detecting and a complete miss or failed child still failing.
        ´claim:discipline:storage-results-preserve-the-secret-boundary´
        ´test:integration:test-storage-statements´
        """
        target=Path('.lane/host-test-binary.txt').read_text().strip()
        root=Path(os.environ['PN_HOST_TEST_ROOT'])
        capture_regressions(self,'storage')
        outputs=[]
        for level in ('default','trace'):
            env=dict(os.environ,PN_OBSERVE_LEVEL=level,PN_HOST_STORAGE_FIXTURE=f'storage-trace-{level}.json')
            validate=capture_validator(self,lambda:[json.loads((root/f'storage-trace-{level}.json').read_text())],outputs)
            result,rows,status,wall=traced_capture(self,[target,'storage::tests::storage_runtime','--exact','--nocapture'],env,level,validate)
            text=decoded_content(rows)
            config=json.loads((root/f'storage-trace-{level}.json').read_text())
            self.assertFalse(binary_reachability(config,rows))
            for key,value in config.items():
                if key!='transport':self.assertFalse(private_occurs(value,text))
            self.assertEqual(status['delivered_records'],len(rows)-1,'observation delivery: '+capture_complete(status)[1])
            if level=='trace':
                self.assertIn('public_storage_payload_731',text)
                source=Path('packages/host/src/storage.rs').read_text().split('impl Statement {',1)[1].split('// The raw driver',1)[0]
                statements=re.findall(r'Self::[A-Za-z]+\s*=>\s*(?:\{\s*)?"([^"\n]+)"',source)
                self.assertEqual(len(statements),14)
                for statement in statements:self.assertIn(statement,text)
            print(f'STORAGE-RUNTIME level={level} wall_seconds={wall:.6f} delivered={status["delivered_records"]} lost={status["lost_records"]}')
        self.assertEqual(outputs[0],outputs[1])
        self.assertEqual(len(outputs[0]),1)
        # Counted loss is incomplete evidence; loss without a named cause is refused.
        lossy={'level':'trace','lost_records':2,'undelivered_records':0,'in_flight_records':0,'loss_causes':{'queue_full':2,'writer':0}}
        self.assertFalse(capture_complete(lossy)[0])
        with self.assertRaisesRegex(AssertionError,'without a named cause'):
            capture_complete(dict(lossy,loss_causes={'queue_full':1,'writer':0}))
        self.assertFalse(capture_complete(dict(lossy,lost_records=0,loss_causes={'queue_full':0},undelivered_records=3))[0])
        retake_counting_cases(self)
        storage_retake_control(self,[target,'storage::tests::storage_runtime','--exact','--nocapture'],env,validate,statements)
        env.update(PN_HOST_STORAGE_PRIVATE_CONTROL='1')
        command=[target,'storage::tests::storage_runtime','--exact','--nocapture']
        sentinel_selection(self)
        forced_loss_cases(self)
        sentinel_retake_control(self,command,env,config['user'])
        _,attempt,wall=sentinel_control(self,command,env,lambda rows:private_occurs(config['user'],decoded_content(rows)),'storage-sensitive-control')
        print(f'STORAGE-SENSITIVE-CONTROL status=detected path=DataRow attempt={attempt} wall_seconds={wall:.6f}')

    def test_storage_restart(self):
        """Claim: A real PostgreSQL restart preserves the committed public version byte for byte; the second probe reads without appending, so successful replay cannot hide lost durability by recreating the row.
        ´claim:discipline:storage-restart-preserves-committed-bytes´
        ´test:integration:test-storage-restart´
        """
        from host_postgresql import binary_directory
        root=Path(os.environ['PN_HOST_TEST_ROOT'])
        target=Path('.lane/host-test-binary.txt').read_text().strip()
        result=subprocess.run([target,'storage::tests::storage_restart','--exact'],capture_output=True,check=False,timeout=60)
        self.assertEqual(result.returncode,0)
        with (root/'fixture.log').open('ab') as log:
            result=subprocess.run([str(binary_directory()/'pg_ctl'),'-D',str(root/'data'),'-m','fast','-w','restart'],stdout=log,stderr=log,check=False,timeout=60)
        self.assertEqual(result.returncode,0)
        env=dict(os.environ,PN_HOST_STORAGE_READ_ONLY_PROBE='1')
        result=subprocess.run([target,'storage::tests::storage_restart','--exact'],env=env,capture_output=True,check=False,timeout=60)
        self.assertEqual(result.returncode,0)
        print('STORAGE-RESTART real_service=True read_without_append=True')

    def test_independent_instances(self):
        """Claim: Two gate-owned PostgreSQL instances coexist on distinct reserved ports and answer independently while a third gate may already be running, so fixture allocation does not depend on gate serialization.
        ´claim:discipline:postgresql-instances-own-distinct-ports´
        ´test:integration:test-independent-instances´
        """
        from host_postgresql import start, stop, binary_directory
        roots=[Path('.lane/host-side-a').resolve(),Path('.lane/host-side-b').resolve()]
        try:
            for root in roots:
                start(root)
            configs=[json.loads((root/'tcp.json').read_text()) for root in roots]
            self.assertNotEqual(configs[0]['port'],configs[1]['port'])
            for config in configs:
                env=dict(os.environ,PGPASSWORD=config['password'])
                result=subprocess.run([str(binary_directory()/'psql'),'-h',config['endpoint'],'-p',config['port'],'-U',config['user'],'-d',config['database'],'-Atc','SELECT 731'],env=env,capture_output=True,check=False)
                self.assertEqual(result.returncode,0)
                self.assertEqual(result.stdout,b'731\n')
            print('HOST-INSTANCE-ISOLATION instances=2 distinct_ports=True queries=2')
        finally:
            for root in reversed(roots):
                stop(root)

    def test_required_postgresql_directory(self):
        """Claim: An absent or empty PostgreSQL binary-directory declaration refuses by name before the gate runs any step, without exposing an endpoint or substituting a node path.
        ´claim:discipline:postgresql-directory-is-caller-declared´
        ´test:integration:test-required-postgresql-directory´
        """
        for value in (None, ''):
            env=dict(os.environ,LINTER_BIN=sys.executable)
            env.pop('PN_POSTGRESQL_BIN',None)
            if value is not None:
                env['PN_POSTGRESQL_BIN']=value
            result=subprocess.run(['bash','ci/gate.sh'],env=env,capture_output=True,check=False)
            self.assertEqual(result.returncode,2)
            self.assertIn(b'PN_POSTGRESQL_BIN',result.stderr)
            self.assertNotIn(b'STEP=',result.stdout)

    def test_dependency_pins(self):
        """Claim: The host storage test closure, excluding the checked disabled optional wallet edge, must match its reviewed archive pins; a changed checksum, an omitted package, a duplicate review row or an enabled wallet edge refuses before the service starts.
        ´claim:discipline:host-archive-pins-cover-the-reachable-closure´
        ´test:integration:test-dependency-pins´
        """
        from host_postgresql import dependency_pins
        packages=tomllib.loads(Path('Cargo.lock').read_text())['package']
        rows=tomllib.loads(Path('docs/inputs/host-dependencies.toml').read_text())['rows']
        self.assertEqual(dependency_pins(packages,rows),len(rows))
        changed=copy.deepcopy(rows);changed[0]['checksum']='changed archive'
        for bad in (changed,rows[1:],rows+[rows[0]]):
            with self.assertRaisesRegex(ValueError,'reviewed archive pins'):
                dependency_pins(packages,bad)
        manifest=Path('packages/host/Cargo.toml')
        original=manifest.read_bytes()
        try:
            manifest.write_bytes(original.replace(b'optional = true',b'optional = false'))
            self.assertNotEqual(manifest.read_bytes(),original)
            with self.assertRaisesRegex(ValueError,'disabled optional edge'):
                dependency_pins(packages,rows)
        finally:
            manifest.write_bytes(original)

    def test_public_transport(self):
        """Claim: After a successful-query drain barrier, complete default and trace captures against the real host-secured service retain identical public results and host operation totals, expose the declared store case, record public protocol content at trace and contain none of the fixture's private reachability or credentials; the child writes observations to a file, every attempt checks private content and completed public bytes before any retake, counted trace loss retains its completeness finding after recovery or a failed child, with the original exit outcome witnessed before refusal, and acquisition takes at most three attempts.
        ´claim:discipline:host-transport-observation-retains-the-secret-boundary´
        ´test:integration:test-public-transport´
        """
        print(flush=True)
        target=Path('.lane/host-test-binary.txt').read_text().strip()
        root=Path(os.environ['PN_HOST_TEST_ROOT'])
        capture_regressions(self,'host')
        outputs=[];counts=[]
        self.assertTrue(private_occurs('42100','{"port":42100}'))
        self.assertFalse(private_occurs('42100','{"duration":0.42100}'))
        for level in ('default','trace'):
            env=dict(os.environ,PN_OBSERVE_LEVEL=level)
            command=[str(target), "transport_evidence::public_transport", "--exact", "--nocapture"]
            validate=capture_validator(self,lambda:[json.loads(path.read_text()) for path in root.glob('*.json')],outputs)
            result,rows,status,wall=traced_capture(self,command,env,level,validate,prefix='host')
            stderr=Path(f'.lane/host-{level}.stderr.jsonl').read_bytes()
            warnings=[line for line in stderr.splitlines() if json.loads(line).get('level') in ('WARN','ERROR')]
            self.assertEqual(len(warnings),13)
            for line in warnings:
                print(line.decode(),flush=True)
            text=decoded_content(rows)
            for cause in ('MissingCase','HeldCase','UnknownCase','RepresentationLimit','Transport','Protocol','PrivateDiagnostic'):
                self.assertIn(cause,text)
            self.assertNotIn('private_unread_input',text)
            self.assertEqual(status['delivered_records'],len(rows)-1,'observation delivery: '+capture_complete(status)[1])
            summary=next(row['metrics'] for row in rows if row['kind']=='metric_summary')
            host={key:value for key,value in distribution(summary).items() if key[0].startswith('host__')}
            self.assertGreater(sum(value for key,value in host.items() if key[0].endswith('started_operations')),0)
            self.assertEqual(sum(value for key,value in host.items() if key[1]=='incomplete'),0)
            counts.append(host)
            public=[line for line in result.stdout.splitlines() if line.startswith(b'{')]
            self.assertEqual(len(public),1)
            record=json.loads(public[0])
            self.assertEqual(record['store_link_case'],'host-secured')
            self.assertEqual(record['persistence'],'disabled')
            if level=='trace':
                for public in ('public_result_sentinel_731','public_row_'*3,'SELECT','division by zero'):
                    self.assertIn(public,text)
            print(f'HOST-RUNTIME level={level} status=0 wall_seconds={wall:.6f} delivered={status["delivered_records"]} lost={status["lost_records"]} host_counts='+json.dumps({str(k):v for k,v in host.items()},sort_keys=True))
        self.assertEqual(outputs[0],outputs[1])
        self.assertEqual(counts[0],counts[1])
        print(flush=True)

    def test_sensitive_result_control(self):
        """Claim: A test-only metadata query returns the private role alongside a binary integer, forcing base64 recording; only decoded-content scanning finds the role, so the leakage control covers binary DataRows rather than outbound bind values; its file-captured trace counts as a miss only when complete, and a capture that counts loss without the role is retaken as inconclusive.
        ´claim:discipline:result-row-control-detects-private-metadata´
        ´test:integration:test-sensitive-result-control´
        """
        target=Path('.lane/host-test-binary.txt').read_text().strip()
        env=dict(os.environ,PN_OBSERVE_LEVEL='trace',PN_HOST_SENSITIVE_ROW_CONTROL='1')
        role=json.loads((Path(os.environ['PN_HOST_TEST_ROOT'])/'unix.json').read_text())['user']
        rows,attempt,wall=sentinel_control(self,[target,'transport_evidence::public_transport','--exact','--nocapture'],env,
            lambda rows:private_occurs(role,decoded_content(rows)),'host-sensitive-control')
        self.assertNotIn(role,json.dumps(rows))
        print(f'HOST-SENSITIVE-CONTROL status=detected path=DataRow attempt={attempt} wall_seconds={wall:.6f}')

    def test_binary_reachability_control(self):
        """Claim: A fixture-only binary DataRow containing the TCP server port and address is detected as four-byte port and address octets, so decoding without decimal text cannot conceal reachability; its file-captured trace counts as a miss only when complete, and a capture that counts loss without both is retaken as inconclusive.
        ´claim:discipline:binary-endpoint-results-are-detected´
        ´test:integration:test-binary-reachability-control´
        """
        target=Path('.lane/host-test-binary.txt').read_text().strip()
        env=dict(os.environ,PN_OBSERVE_LEVEL='trace',PN_HOST_BINARY_ROW_CONTROL='1')
        config=json.loads((Path(os.environ['PN_HOST_TEST_ROOT'])/'tcp.json').read_text())
        rows,attempt,wall=sentinel_control(self,[target,'transport_evidence::public_transport','--exact','--nocapture'],env,
            lambda rows:binary_reachability(config,rows)=={'port','endpoint'},'host-binary-control')
        self.assertEqual(binary_reachability(config,rows),{'port','endpoint'})
        print(f'HOST-BINARY-CONTROL port=detected endpoint=detected path=DataRow attempt={attempt} wall_seconds={wall:.6f}',flush=True)
