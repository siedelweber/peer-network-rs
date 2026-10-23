"""Cgroup v2 samples; counters use kernel units, absent readings stay unavailable."""
import json
from pathlib import Path
import sys
import time


def cgroup_root(proc=Path('/proc/self/cgroup'), mount=Path('/sys/fs/cgroup')):
    for line in proc.read_text().splitlines():
        if line.startswith('0::'):
            relative = line[3:].lstrip('/')
            # Namespaced mounts expose the current cgroup at the mount root.
            candidate = mount / relative
            return candidate if (candidate / 'cgroup.procs').exists() else mount
    return None


def sample(root):
    values = {}
    def read(name):
        try:
            return (root / name).read_text() if root else None
        except (FileNotFoundError, PermissionError):
            return None
    cpu = read('cpu.stat')
    fields = dict(line.split() for line in cpu.splitlines()) if cpu else {}
    for name in ('usage_usec', 'user_usec', 'system_usec', 'nr_periods', 'nr_throttled', 'throttled_usec'):
        values['cpu.stat.' + name] = int(fields[name]) if name in fields else None
    for resource in ('cpu', 'memory', 'io'):
        pressure = read(resource + '.pressure')
        rows = {row.split()[0]: dict(pair.split('=') for pair in row.split()[1:]) for row in pressure.splitlines()} if pressure else {}
        for kind in ('some', 'full'):
            for field in ('avg10', 'avg60', 'avg300', 'total'):
                value = rows.get(kind, {}).get(field)
                values[f'{resource}.pressure.{kind}.{field}'] = (int(value) if field == 'total' else float(value)) if value is not None else None
    for name in ('memory.current', 'memory.peak'):
        value = read(name)
        values[name] = int(value) if value is not None else None
    return dict(epoch_seconds=time.time(), cgroup=str(root) if root else None, values=values)


def report(start, end):
    same = start['cgroup'] == end['cgroup']
    delta = {key: end['values'][key] - value if same and value is not None and end['values'][key] is not None else None for key, value in start['values'].items()}
    return dict(start=start, end=end, deltas=delta, unavailable='null denotes an absent or inaccessible reading, or an incomparable delta',
                units='epoch_seconds: Unix UTC seconds; *_usec and PSI total: microseconds; PSI averages: percent (deltas: percentage points); memory: bytes; periods: counts',
                scope='shared cgroup; deltas include concurrent processes; memory deltas are end minus start, not allocation totals')


def main():
    if sys.argv[1] == 'sample':
        Path(sys.argv[2]).write_text(json.dumps(sample(cgroup_root())) + '\n')
    else:
        start, end = (json.loads(Path(p).read_text()) for p in sys.argv[2:4])
        print('CGROUP=' + json.dumps(report(start, end), separators=(',', ':')))


if __name__ == '__main__':
    main()
