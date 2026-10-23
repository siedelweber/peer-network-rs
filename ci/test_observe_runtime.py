"""Process comparisons using the same four-package workload and local export failure."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


def run(argv, **kwargs):
    started=time.monotonic()
    result=subprocess.run(argv,capture_output=True,**kwargs)
    print(f'OBSERVATION-WITNESS command={argv[0]} status={result.returncode} wall_seconds={time.monotonic()-started:.6f}')
    return result


class Processes(unittest.TestCase):
    def test_four_mode_results(self):
        """Claim: Disabled, enabled, selected-out and locally failing-export executions preserve the four-package workload's exact JSON stdout and exit, including canonical bytes, acceptance, document checks and raw child NUL and invalid UTF-8 bytes.
        ´claim:discipline:four-observation-modes-preserve-command-results´
        ´test:discipline:test-four-mode-results´
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
            artifact=Path('.lane/observation-comparison');artifact.mkdir(exist_ok=True)
            for mode in ('disabled','enabled','sampled','failing-export'):
                result=run([str(target/'examples/observation_compare'),mode,str(root)],env=env)
                self.assertEqual(result.returncode,0,result.stderr.decode())
                samples[mode]=(result.returncode,result.stdout)
                (artifact/(mode+'.stdout')).write_bytes(result.stdout)
                (artifact/(mode+'.jsonl')).write_bytes(result.stderr)
                rows=[json.loads(line) for line in result.stderr.splitlines()]
                self.assertNotIn(b'fixture-private-token',result.stdout+result.stderr)
                if mode=='disabled':
                    self.assertEqual(len(rows),1)
                    self.assertEqual(rows[0].get('availability'),'disabled')
                    self.assertEqual(rows[0].get('kind'),'observation_status')
                else:self.assertTrue(any(row.get('kind')=='span_envelope' for row in rows))
                if mode=='failing-export':self.assertTrue(any(row.get('kind')=='export_summary' and row['lost_exports']>0 for row in rows))
            self.assertTrue(all(sample==samples['disabled'] for sample in samples.values()))
            report=json.loads(samples['disabled'][1])
            self.assertEqual(report['canonical'],[130,24,42,97,120])
            self.assertEqual(report['verdict'],'AcceptedStrictly { minor: 0 }')
            self.assertEqual(report['documents']['findings'],[])
            self.assertEqual(report['child_stdout'],list(b'public\x00\xff'))
            self.assertEqual(report['child_stderr'],list(b'diagnostic'))
            self.assertEqual(report['child_exit'],7)
            self.assertFalse(report['child_loss'])


if __name__=='__main__':unittest.main()
