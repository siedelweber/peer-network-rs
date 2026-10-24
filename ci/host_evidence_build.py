"""Build the cfg(test)-only host fixture without a production raw-client route."""
import json
from pathlib import Path
import subprocess
import sys

result = subprocess.run(['cargo', 'test', '--offline', '--locked', '--profile', 'gate',
                         '-p', 'pn-host', '--lib', '--no-run', '--message-format=json'],
                        capture_output=True, check=False)
sys.stderr.buffer.write(result.stderr)
if result.returncode:
    sys.exit(result.returncode)
binaries = []
for line in result.stdout.splitlines():
    row = json.loads(line)
    if row.get('reason') == 'compiler-artifact' and row.get('executable') and row['target']['name'] == 'pn_host':
        binaries.append(row['executable'])
if len(binaries) != 1:
    raise SystemExit('host evidence requires exactly one test binary')
Path('.lane/host-test-binary.txt').write_text(binaries[0]+'\n')
print('HOST-EVIDENCE-BUILD configuration=cfg(test) production_client=private')
