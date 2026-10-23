"""Count inline diagnostics and per-process observation status without routing bytes."""
import json
from pathlib import Path
import sys


def counts(lines):
    warn = error = 0
    processes = []
    for line in lines:
        if isinstance(line, bytes):line=line.decode('utf-8',errors='replace')
        if line.startswith('OBSERVATION-WITNESS '):
            if ' injected=true ' in line:continue
            line=line.partition(' observation_status=')[2]
        try:
            row = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(row, dict):
            continue
        warn += row.get('level') == 'WARN'
        error += row.get('level') == 'ERROR'
        if row.get('kind') == 'observation_status':
            preceding = row.get('delivered_records')
            delivered = preceding + 1 if preceding is not None else None
            processes.append(dict(process_id=row.get('process_id'), delivered=delivered, lost=row.get('lost_records'), level=row.get('level'), availability=row.get('availability')))
    return dict(warn=warn, error=error, loss=sum(p['lost'] or 0 for p in processes), processes=processes)


if __name__ == '__main__':
    result = counts(Path(sys.argv[1]).read_bytes().splitlines())
    print('warn={warn} error={error} loss={loss} processes='.format(**result) + json.dumps(result['processes'], separators=(',', ':')))
