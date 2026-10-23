"""Process comparisons using the same four-package workload and local export failure."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import threading
import unittest


def run(argv, **kwargs):
    started=time.monotonic()
    result=subprocess.run(argv,capture_output=True,**kwargs)
    print(f'OBSERVATION-WITNESS command={argv[0]} status={result.returncode} wall_seconds={time.monotonic()-started:.6f}')
    return result


def compare(argv, mode, env):
    """Release the fixture only after its reserved summary has been delivered."""
    started=time.monotonic()
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             env=env | {'PN_TEST_OBSERVATION_RENDEZVOUS':'1'})
    stderr=[]
    def receive():
        summary=export=released=False
        if mode=='disabled':
            process.stdin.write(b'\n'); process.stdin.flush(); released=True
        for line in process.stderr:
            stderr.append(line)
            row=json.loads(line)
            summary |= row.get('kind')=='metric_summary'
            export |= row.get('kind')=='export_summary'
            unavailable=row.get('kind')=='observation_status' and row.get('availability')=='unavailable'
            if not released and (unavailable or (summary and (mode!='failing-export' or export))):
                process.stdin.write(b'\n'); process.stdin.flush(); released=True
    reader=threading.Thread(target=receive)
    reader.start()
    stdout=process.stdout.read()
    status=process.wait()
    reader.join()
    process.stdin.close();process.stdout.close();process.stderr.close()
    print(f'OBSERVATION-WITNESS command={argv[0]} status={status} wall_seconds={time.monotonic()-started:.6f}')
    return subprocess.CompletedProcess(argv,status,stdout,b''.join(stderr))


class Processes(unittest.TestCase):
    def test_four_mode_results(self):
        """Claim: Disabled, default, full-trace and locally failing-export full-trace executions preserve the four-package workload's exact JSON stdout and exit; all enabled modes count the same labelled operations, default omits only unobserved series, and an unknown level refuses document execution before work.
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
                    summary=next(row['metrics'] for row in rows if row.get('kind')=='metric_summary')
                    accounting[mode]={row['name']:row['counter'] for row in summary['instruments'] if row['name'].endswith('started_operations') and row['counter']>0}
                    for owner in ('documents','interchange','execwrap','clicommon'):
                        self.assertTrue(any(name.startswith(owner+'__') and count>0 for name,count in accounting[mode].items()))
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
                else:self.assertTrue(any(row.get('kind')=='span_envelope' for row in rows))
                if mode=='failing-export':self.assertTrue(any(row.get('kind')=='export_summary' and row['lost_exports']>0 for row in rows))
            self.assertTrue(all(sample==samples['disabled'] for sample in samples.values()))
            self.assertTrue(all(sample==accounting['default'] for sample in accounting.values()))
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
