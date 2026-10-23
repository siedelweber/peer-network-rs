"""Exercise the Rust parser on real source, independent of registry fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


class Syntax(unittest.TestCase):
    def test_parsed_boundaries(self):
        """Claim: The Rust parser follows cfg and distinguishes an uninstrumented body, a retained scoped guard, an abandoned guard and an argument-skipping attribute from actual syntax; a generator remains visible for separate admission.
        ´claim:discipline:coverage-recognition-comes-from-rust-syntax´
        ´test:integration:test-parsed-boundaries´
        """
        started=time.monotonic()
        built=subprocess.run(['cargo','build','--offline','--locked','--profile','gate','-p','cli-common','--example','observe_census'],capture_output=True)
        print(f'OBSERVE-PARSER-BUILD status={built.returncode} wall_seconds={time.monotonic()-started:.6f}')
        self.assertEqual(built.returncode,0,built.stderr.decode())
        binary=Path(os.environ['CARGO_TARGET_DIR'])/'gate/examples/observe_census'
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'lib.rs'
            def parse(text):
                source.write_text(text)
                request={'roots':[{'package':'fixture','owner':'ROOT','path':str(source)}],'cfg':['unix']}
                started=time.monotonic()
                result=subprocess.run([binary],input=json.dumps(request).encode(),capture_output=True)
                print(f'OBSERVE-PARSER status={result.returncode} wall_seconds={time.monotonic()-started:.6f}')
                return result
            result=parse('#[cfg(windows)] pub fn hidden() {}\n#[cfg(unix)] pub fn visible() {}\n#[derive(Debug)] pub struct State;')
            self.assertEqual(result.returncode,0,result.stderr.decode())
            rows=json.loads(result.stdout)
            self.assertEqual([r['item'] for r in rows['functions']],['visible'])
            self.assertIsNone(rows['functions'][0]['boundary'])
            self.assertEqual(len(rows['generators']),1)
            result=parse('pub fn run() { let guard = cli_common::observation::scope("ROOT", "rule:observe:spans", "run", &()); guard.finish(&()); }')
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertNotIn('invalid',json.loads(result.stdout)['functions'][0]['boundary'])
            result=parse('pub fn run() { cli_common::observation::scope("ROOT", "rule:observe:spans", "run", &()); work(); }')
            self.assertIn('invalid',json.loads(result.stdout)['functions'][0]['boundary'])
            result=parse('#[tracing::instrument(skip(value), ret)] pub fn run(value: u8) {}')
            self.assertEqual(result.returncode,1)
            self.assertEqual(result.stdout,b'')
            self.assertIn(b'argument skip',result.stderr)


if __name__=='__main__':unittest.main()
