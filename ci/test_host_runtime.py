"""Real host transport observation without admitting persistence."""
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import tomllib
import copy

from test_observe_runtime import expanded, distribution, witness


class HostRuntime(unittest.TestCase):
    def test_dependency_pins(self):
        """Claim: The host's complete reachable lock closure must match its reviewed archive pins; a changed checksum, an omitted package or a duplicate review row refuses before the service starts.
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

    def test_public_transport(self):
        """Claim: Default and trace runs against the real host-secured service retain identical public results and lossless host operation totals, expose the declared store case, record public protocol content at trace and contain none of the fixture's private reachability or credentials.
        ´claim:discipline:host-transport-observation-retains-the-secret-boundary´
        ´test:integration:test-public-transport´
        """
        target=Path(os.environ['CARGO_TARGET_DIR'])/'gate'/'examples'/'transport_evidence'
        root=Path(os.environ['PN_HOST_TEST_ROOT'])
        configurations=[json.loads(path.read_text()) for path in root.glob('*.json')]
        private={str(value) for config in configurations for key,value in config.items() if key!='transport'}
        outputs=[];counts=[]
        for level in ('default','trace'):
            started=time.monotonic()
            env=dict(os.environ,PN_OBSERVE_LEVEL=level)
            result=subprocess.run([str(target)],env=env,capture_output=True,timeout=60,check=False)
            wall=time.monotonic()-started
            Path(f'.lane/host-{level}.stderr.jsonl').write_bytes(result.stderr)
            witness([str(target)],result.returncode,wall,result.stderr)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            rows=[expanded(json.loads(line)) for line in result.stderr.splitlines()]
            text=json.dumps(rows,ensure_ascii=False)
            for value in private:
                self.assertNotIn(value,text)
                self.assertNotIn(value,result.stdout.decode())
            status=next(row for row in rows if row['kind']=='observation_status')
            self.assertEqual(status['lost_records'],0)
            self.assertEqual(status['undelivered_records'],0)
            self.assertEqual(status['delivered_records'],len(rows)-1)
            summary=next(row['metrics'] for row in rows if row['kind']=='metric_summary')
            host={key:value for key,value in distribution(summary).items() if key[0].startswith('host__')}
            self.assertGreater(sum(value for key,value in host.items() if key[0].endswith('started_operations')),0)
            counts.append(host);outputs.append(result.stdout)
            record=json.loads(result.stdout)
            self.assertEqual(record['store_link_case'],'host-secured')
            self.assertEqual(record['persistence'],'disabled')
            if level=='trace':
                for public in ('public_result_sentinel_731','SELECT','division by zero'):
                    self.assertIn(public,text)
            print(f'HOST-RUNTIME level={level} status=0 wall_seconds={wall:.6f} delivered={status["delivered_records"]} lost={status["lost_records"]} host_counts='+json.dumps({str(k):v for k,v in host.items()},sort_keys=True))
        self.assertEqual(outputs[0],outputs[1])
        self.assertEqual(counts[0],counts[1])
