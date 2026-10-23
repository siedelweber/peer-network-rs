"""Cgroup v2 samples; counters use kernel units, absent readings stay unavailable."""
import json
from pathlib import Path
import sys
import os

COUNTERS=[f'cpu.stat.{k}' for k in ('usage_usec','user_usec','system_usec','nr_periods','nr_throttled','throttled_usec')]+[f'{r}.pressure.{k}.total' for r in ('cpu','memory','io') for k in ('some','full')]+['memory.current','memory.peak']
AVERAGES=[f'{r}.pressure.{k}.{a}' for r in ('cpu','memory','io') for k in ('some','full') for a in ('avg10','avg60','avg300')]


def context(resource, owned=None):
    start,end=resource['start'],resource['end']
    root=start.get('cgroup')
    if not root or root!=end.get('cgroup') or not any(v is not None for v in start['values'].values()) or not any(v is not None for v in end['values'].values()):
        return None,'unavailable'
    return root,'gate' if owned==root else 'shared'


def compact(resource, owned=None):
    _,scope=context(resource,owned)
    start,end=resource['start']['values'],resource['end']['values']
    samples=[[start.get(k),end.get(k),resource['node_load_deltas'].get(k)] for k in COUNTERS]
    averages=[[start.get(k),end.get(k)] for k in AVERAGES]
    return 'scope='+scope+' samples='+json.dumps(samples,separators=(',',':'))+' psi_avg='+json.dumps(averages,separators=(',',':'))+' psi='+json.dumps({k:round(v,6) if v is not None else None for k,v in resource['node_pressure_fraction'].items()},separators=(',',':'))


def seconds(value):
    return 'unavailable' if value is None else f'{value:.3f}'


def raw_sample(path):
    try:
        lines=Path(path).read_text().splitlines()
        epoch=float(lines[0].split('=',1)[1]); root=lines[1].split('=',1)[1]
        files={}; name=None
        for line in lines[2:]:
            if line.startswith('['): name=line[1:-1]; files[name]=[]
            elif name: files[name].append(line)
        values={f'cpu.stat.{key}':None for key in ('usage_usec','user_usec','system_usec','nr_periods','nr_throttled','throttled_usec')}
        values.update({f'{resource}.pressure.{kind}.{field}':None for resource in ('cpu','memory','io') for kind in ('some','full') for field in ('avg10','avg60','avg300','total')})
        for line in files.get('cpu.stat',[]):
            parts=line.split()
            if len(parts)==2: values['cpu.stat.'+parts[0]]=int(parts[1])
        for resource in ('cpu','memory','io'):
            for line in files.get(resource+'.pressure',[]):
                parts=line.split()
                if parts and parts[0] in ('some','full'):
                    for pair in parts[1:]:
                        field,value=pair.split('=')
                        values[f'{resource}.pressure.{parts[0]}.{field}']=float(value)
        for name in ('memory.current','memory.peak'):
            value=''.join(files.get(name,[]))
            values[name]=int(value) if value.isdigit() else None
        return dict(epoch_seconds=epoch,cgroup=root or None,values=values)
    except (OSError,ValueError,IndexError): return dict(epoch_seconds=None,cgroup=None,values={})


def joined(start,end,wall):
    keys=set(start['values'])|set(end['values'])
    delta={k:(end['values'].get(k)-start['values'][k] if start['cgroup'] and start['cgroup']==end['cgroup'] and start['values'].get(k) is not None and end['values'].get(k) is not None else None) for k in keys if '.avg' not in k}
    pressure={f'{r}.{kind}': (delta.get(f'{r}.pressure.{kind}.total')/1e6/wall if delta.get(f'{r}.pressure.{kind}.total') is not None and wall>0 else None) for r in ('cpu','memory','io') for kind in ('some','full')}
    return dict(start=start,end=end,node_load_deltas=delta,node_pressure_fraction=pressure)


def cpu_from_log(lines):
    import re
    matches=[re.fullmatch(r'OWN-TIME user=([0-9.]+) sys=([0-9.]+)',line) for line in lines]
    match=next((m for m in reversed(matches) if m),None)
    return (float(match[1]),float(match[2])) if match else (None,None)


def process_cpu(path):
    import re
    try:
        values=re.findall(r'([0-9]+)m([0-9.]+)s',Path(path).read_text())
        seconds=[60*int(m)+float(s) for m,s in values]
        return (seconds[0]+seconds[2],seconds[1]+seconds[3])
    except (OSError,ValueError,IndexError):return (None,None)


def main():
    from gate_observation_counts import counts
    root=Path(sys.argv[1])
    wall=float(sys.argv[2])
    whole=joined(raw_sample(root/'gate-resource-start.raw'),raw_sample(root/'gate-resource-end.raw'),wall)
    owned=os.environ.get('GATE_OWN_CGROUP')
    cgroup,scope=context(whole,owned)
    print('RESOURCE-LEGEND cgroup='+str(cgroup or 'unavailable')+' scope='+scope+' shared=node-load-not-gate-CPU; gate=launcher-declared-GATE_OWN_CGROUP; own_user_s/own_sys_s=process-and-child CPU seconds; samples=[start,end,delta] ordered='+json.dumps(COUNTERS,separators=(',',':'))+'; psi_avg=[start,end] percent ordered='+json.dumps(AVERAGES,separators=(',',':'))+'; psi=delta-stall-microseconds/1000000/wall-seconds; cpu.stat=microseconds/counts; memory=bytes; unavailable=null')
    reports=[]
    for line in (root/'gate-steps.tsv').read_text().splitlines():
        name,status,started,ended=line.split('\t'); wall=float(ended)-float(started)
        lines=(root/f'gate-{name}.log').read_text(errors='replace').splitlines()
        own=cpu_from_log(lines); counted=counts(lines)
        resource=joined(raw_sample(root/f'gate-{name}-resource-start.raw'),raw_sample(root/f'gate-{name}-resource-end.raw'),wall)
        reports.append(dict(step=name,wall_seconds=wall,own_user_s=own[0],own_sys_s=own[1],**resource))
        print(f'STEP={name} STATUS={status} WALL={wall:.6f}s own_user_s={seconds(own[0])} own_sys_s={seconds(own[1])} '+compact(resource,owned)+' warn={warn} error={error} loss={loss} processes='.format(**counted)+json.dumps(counted['processes'],separators=(',',':')))
    wall=float(sys.argv[2]); begin=process_cpu(root/'gate-cpu-start.raw'); end=process_cpu(root/'gate-cpu-end.raw')
    own=[b-a if a is not None and b is not None else None for a,b in zip(begin,end)]
    resource=joined(raw_sample(root/'gate-resource-start.raw'),raw_sample(root/'gate-resource-end.raw'),wall)
    reports.append(dict(step='gate',wall_seconds=wall,own_user_s=own[0],own_sys_s=own[1],**resource))
    (root/'gate-resources.json').write_text(json.dumps(reports,indent=2)+'\n')
    print(f'GATE-RESOURCES WALL={wall:.6f}s own_user_s={seconds(own[0])} own_sys_s={seconds(own[1])} '+compact(resource,owned)+' artifact=.lane/gate-resources.json')


if __name__ == '__main__':
    main()
