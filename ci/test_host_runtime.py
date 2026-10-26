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
    """A lossless capture is complete. The bounded observation queue may lose records under load; every loss
    must then name its cause, and the capture is incomplete evidence rather than a failure of the run."""
    accounting=json.dumps({key:status.get(key) for key in ('level','attempted_records','delivered_records','lost_records',
        'undelivered_records','in_flight_records','drain_timeouts','drain_unavailable','loss_causes')},sort_keys=True)
    if status['lost_records']!=sum(status['loss_causes'].values()):
        raise AssertionError('observation loss without a named cause: '+accounting)
    return status['lost_records']==0 and status['undelivered_records']==0 and status['in_flight_records']==0, accounting


def traced_capture(test, command, env, level, attempts=3):
    """The child writes observations to a file, so its delivery never waits on this reader; a capture that still
    counts loss is retaken, at most three times, and each incomplete attempt prints its accounting."""
    for attempt in range(1,attempts+1):
        sink=Path(f'.lane/storage-{level}.stderr.jsonl')
        started=time.monotonic()
        with sink.open('wb') as stream:
            result=subprocess.run(command,env=env,stdout=subprocess.PIPE,stderr=stream,timeout=60,check=False)
        wall=time.monotonic()-started
        stderr=sink.read_bytes()
        test.assertEqual(result.returncode,0,stderr.decode())
        rows=[expanded(json.loads(line)) for line in stderr.splitlines()]
        status=next(row for row in rows if row.get('kind')=='observation_status')
        complete,accounting=capture_complete(status)
        if complete:
            return result,rows,status,wall
        print(f'STORAGE-RUNTIME level={level} attempt={attempt} incomplete={accounting} wall_seconds={wall:.3f}')
    test.fail(f'no complete {level} capture in {attempts} attempts: {accounting}')


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
        """Claim: Every closed storage statement is exercised under a complete trace capture, written by the child to a file so that delivery never waits on the reader, and its decoded DataRows contain only public fixture content; a capture that counts loss must name each loss's cause and is retaken at most three times; default and trace return identical bytes, while a test-only metadata query is caught at the private role sentinel.
        ´claim:discipline:storage-results-preserve-the-secret-boundary´
        ´test:integration:test-storage-statements´
        """
        target=Path('.lane/host-test-binary.txt').read_text().strip()
        root=Path(os.environ['PN_HOST_TEST_ROOT'])
        outputs=[]
        for level in ('default','trace'):
            env=dict(os.environ,PN_OBSERVE_LEVEL=level,PN_HOST_STORAGE_FIXTURE=f'storage-trace-{level}.json')
            result,rows,status,wall=traced_capture(self,[target,'storage::tests::storage_runtime','--exact','--nocapture'],env,level)
            text=decoded_content(rows)
            config=json.loads((root/f'storage-trace-{level}.json').read_text())
            self.assertFalse(binary_reachability(config,rows))
            for key,value in config.items():
                if key!='transport':self.assertFalse(private_occurs(value,text))
            self.assertEqual(status['delivered_records'],len(rows)-1,'observation delivery: '+capture_complete(status)[1])
            outputs.append([line for line in result.stdout.splitlines() if line.startswith(b'{')])
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
        env.update(PN_HOST_STORAGE_PRIVATE_CONTROL='1')
        result=subprocess.run([target,'storage::tests::storage_runtime','--exact','--nocapture'],env=env,capture_output=True,timeout=60,check=False)
        self.assertEqual(result.returncode,0)
        text=decoded_content([expanded(json.loads(line)) for line in result.stderr.splitlines()])
        self.assertTrue(private_occurs(config['user'],text))
        print('STORAGE-SENSITIVE-CONTROL status=detected path=DataRow')

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
        """Claim: After a successful-query drain barrier, default and trace runs against the real host-secured service retain identical public results and lossless host operation totals, expose the declared store case, record public protocol content at trace and contain none of the fixture's private reachability or credentials.
        ´claim:discipline:host-transport-observation-retains-the-secret-boundary´
        ´test:integration:test-public-transport´
        """
        print(flush=True)
        target=Path('.lane/host-test-binary.txt').read_text().strip()
        root=Path(os.environ['PN_HOST_TEST_ROOT'])
        configurations=[json.loads(path.read_text()) for path in root.glob('*.json')]
        private={str(value) for config in configurations for key,value in config.items() if key!='transport'}
        outputs=[];counts=[]
        self.assertTrue(private_occurs('42100','{"port":42100}'))
        self.assertFalse(private_occurs('42100','{"duration":0.42100}'))
        for level in ('default','trace'):
            started=time.monotonic()
            env=dict(os.environ,PN_OBSERVE_LEVEL=level)
            result=subprocess.run([str(target), "transport_evidence::public_transport", "--exact", "--nocapture"],env=env,capture_output=True,timeout=60,check=False)
            wall=time.monotonic()-started
            Path(f'.lane/host-{level}.stderr.jsonl').write_bytes(result.stderr)
            witness([str(target), "transport_evidence::public_transport", "--exact", "--nocapture"],result.returncode,wall,result.stderr)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            rows=[expanded(json.loads(line)) for line in result.stderr.splitlines()]
            warnings=[line for line in result.stderr.splitlines() if json.loads(line).get('level') in ('WARN','ERROR')]
            self.assertEqual(len(warnings),13)
            for line in warnings:
                print(line.decode(),flush=True)
            text=decoded_content(rows)
            for config in configurations:self.assertFalse(binary_reachability(config,rows))
            for cause in ('MissingCase','HeldCase','UnknownCase','RepresentationLimit','Transport','Protocol','PrivateDiagnostic'):
                self.assertIn(cause,text)
            self.assertNotIn('private_unread_input',text)
            for value in private:
                self.assertFalse(private_occurs(value,text))
                self.assertFalse(private_occurs(value,result.stdout.decode()))
            status=next(row for row in rows if row['kind']=='observation_status')
            self.assertEqual(status['lost_records'],0)
            self.assertEqual(status['undelivered_records'],0)
            self.assertEqual(status['delivered_records'],len(rows)-1)
            summary=next(row['metrics'] for row in rows if row['kind']=='metric_summary')
            host={key:value for key,value in distribution(summary).items() if key[0].startswith('host__')}
            self.assertGreater(sum(value for key,value in host.items() if key[0].endswith('started_operations')),0)
            self.assertEqual(sum(value for key,value in host.items() if key[1]=='incomplete'),0)
            counts.append(host)
            public=[line for line in result.stdout.splitlines() if line.startswith(b'{')]
            self.assertEqual(len(public),1)
            outputs.append(public[0])
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
        """Claim: A test-only metadata query returns the private role alongside a binary integer, forcing base64 recording; only decoded-content scanning finds the role, so the leakage control covers binary DataRows rather than outbound bind values.
        ´claim:discipline:result-row-control-detects-private-metadata´
        ´test:integration:test-sensitive-result-control´
        """
        target=Path('.lane/host-test-binary.txt').read_text().strip()
        env=dict(os.environ,PN_OBSERVE_LEVEL='trace',PN_HOST_SENSITIVE_ROW_CONTROL='1')
        started=time.monotonic()
        result=subprocess.run([target,'transport_evidence::public_transport','--exact','--nocapture'],env=env,capture_output=True,timeout=60,check=False)
        wall=time.monotonic()-started
        self.assertEqual(result.returncode,0)
        rows=[expanded(json.loads(line)) for line in result.stderr.splitlines()]
        text=decoded_content(rows)
        self.assertNotIn(json.loads((Path(os.environ['PN_HOST_TEST_ROOT'])/'unix.json').read_text())['user'], json.dumps(rows))
        config=json.loads((Path(os.environ['PN_HOST_TEST_ROOT'])/'unix.json').read_text())
        role=config['user']
        self.assertTrue(private_occurs(role,text))
        print(f'HOST-SENSITIVE-CONTROL status=detected path=DataRow wall_seconds={wall:.6f}')

    def test_binary_reachability_control(self):
        """Claim: A fixture-only binary DataRow containing the TCP server port and address is detected as four-byte port and address octets, so decoding without decimal text cannot conceal reachability.
        ´claim:discipline:binary-endpoint-results-are-detected´
        ´test:integration:test-binary-reachability-control´
        """
        target=Path('.lane/host-test-binary.txt').read_text().strip()
        env=dict(os.environ,PN_OBSERVE_LEVEL='trace',PN_HOST_BINARY_ROW_CONTROL='1')
        result=subprocess.run([target,'transport_evidence::public_transport','--exact','--nocapture'],env=env,capture_output=True,check=False,timeout=60)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        rows=[expanded(json.loads(line)) for line in result.stderr.splitlines()]
        config=json.loads((Path(os.environ['PN_HOST_TEST_ROOT'])/'tcp.json').read_text())
        self.assertEqual(binary_reachability(config,rows),{'port','endpoint'})
        print('HOST-BINARY-CONTROL port=detected endpoint=detected path=DataRow',flush=True)
