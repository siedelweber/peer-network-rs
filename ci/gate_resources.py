"""Separate gate-cgroup and system-wide proc counters; absence is not zero."""
import json
from pathlib import Path
import sys
import os

COUNTERS=[f'cpu.stat.{k}' for k in ('usage_usec','user_usec','system_usec','nr_periods','nr_throttled','throttled_usec')]+[f'{r}.pressure.{k}.total' for r in ('cpu','memory','io') for k in ('some','full')]+['memory.current','memory.peak']
AVERAGES=[f'{r}.pressure.{k}.{a}' for r in ('cpu','memory','io') for k in ('some','full') for a in ('avg10','avg60','avg300')]


def node_identity():
    """Machine class and observation scopes, not a login or mutable hostname."""
    models=sorted({line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                   if line.split(':',1)[0].strip() in ('model name','Hardware')})
    if not models:
        raise ValueError('node CPU model unavailable')
    return dict(cpu_models=models, allowed_cpus=len(os.sched_getaffinity(0)),
                pressure_scope='node-wide-proc', resource_scope='gate-cgroup', cpu_scope='process-and-reaped-children')


def context(resource, owned=None):
    start,end=resource['start'],resource['end']
    root=start.get('cgroup')
    if not root or root!=end.get('cgroup') or not any(v is not None for v in start['values'].values()) or not any(v is not None for v in end['values'].values()):
        return None,'unavailable'
    return root,'gate-cgroup'


def compact(resource, owned=None):
    _,scope=context(resource,owned)
    start,end=resource['start']['values'],resource['end']['values']
    samples=[[start.get(k),end.get(k),resource['cgroup_deltas'].get(k)] for k in COUNTERS]
    averages=[[start.get(k),end.get(k)] for k in AVERAGES]
    usage=resource['cgroup_deltas'].get('cpu.stat.usage_usec')
    wall=resource.get('wall_seconds')
    cores='unavailable' if usage is None or wall is None or wall<=0 else f'{usage/1e6/wall:.3f}'
    def encoded(value):
        return json.dumps(value,separators=(',',':'))
    return ('cgroup_scope='+scope+' interval_scope=gate cgroup_cores='+cores+
            ' cgroup_samples='+encoded(samples)+' cgroup_psi_avg='+encoded(averages)+
            ' cgroup_psi='+encoded(resource['cgroup_pressure_fraction'])+
            ' node_scope='+resource['node_scope']+' node_source=proc-systemwide'+
            ' node_cores='+seconds(resource['node_busy_cores'])+
            ' node_psi='+encoded(resource['node_pressure_fraction'])+
            ' node_samples='+encoded({k:[resource['start'].get('node_values',{}).get(k),resource['end'].get('node_values',{}).get(k),v] for k,v in sorted(resource['node_deltas'].items())})+
            ' node_loadavg='+encoded([resource[side].get('node_loadavg') for side in ('start','end')]))


def node_stall(resource):
    """Legacy cgroup-only reports cannot supply system-wide load evidence."""
    return resource.get('node_pressure_fraction',{}).get('cpu.some') if resource.get('node_scope')=='node-wide' else None


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
                        values[f'{resource}.pressure.{parts[0]}.{field}']=int(value) if field=='total' else float(value)
        for name in ('memory.current','memory.peak'):
            value=''.join(files.get(name,[]))
            values[name]=int(value) if value.isdigit() else None
        node={}
        for resource in ('cpu','memory','io'):
            for line in files.get('proc/pressure/'+resource,[]):
                parts=line.split()
                if parts and parts[0] in ('some','full'):
                    for pair in parts[1:]:
                        field,value=pair.split('=')
                        node[f'{resource}.pressure.{parts[0]}.{field}']=int(value) if field=='total' else float(value)
        boot=None
        for line in files.get('proc/stat',[]):
            parts=line.split()
            if parts and parts[0]=='cpu':
                # Guest ticks are already included in user and nice ticks.
                for field,value in zip(('user','nice','system','idle','iowait','irq','softirq','steal'),parts[1:9]):
                    node['cpu.ticks.'+field]=int(value)
            elif parts and parts[0]=='btime': boot=int(parts[1])
        load=files.get('proc/loadavg',[])
        load=[float(value) for value in load[0].split()[:3]] if load and load[0]!='unavailable' else None
        ticks=''.join(files.get('clock-ticks',[]))
        return dict(epoch_seconds=epoch,cgroup=root or None,values=values,node_values=node,node_boot=boot,
                    node_loadavg=load,clock_ticks=int(ticks) if ticks.isdigit() else None)
    except (OSError,ValueError,IndexError): return dict(epoch_seconds=None,cgroup=None,values={})


def joined(start,end,wall):
    keys=set(start['values'])|set(end['values'])
    delta={k:(end['values'].get(k)-start['values'][k] if start['cgroup'] and start['cgroup']==end['cgroup'] and start['values'].get(k) is not None and end['values'].get(k) is not None else None) for k in keys if '.avg' not in k}
    pressure={f'{r}.{kind}': (delta.get(f'{r}.pressure.{kind}.total')/1e6/wall if delta.get(f'{r}.pressure.{kind}.total') is not None and wall>0 else None) for r in ('cpu','memory','io') for kind in ('some','full')}
    node_start,node_end=start.get('node_values',{}),end.get('node_values',{})
    same_boot=start.get('node_boot') is not None and start.get('node_boot')==end.get('node_boot')
    node_delta={k:(node_end[k]-node_start[k] if same_boot and k in node_start and k in node_end and node_end[k]>=node_start[k] else None)
                for k in set(node_start)|set(node_end) if '.avg' not in k}
    node_pressure={f'{r}.{kind}': (node_delta[f'{r}.pressure.{kind}.total']/1e6/wall if wall>0 and node_delta.get(f'{r}.pressure.{kind}.total') is not None else None)
                  for r in ('cpu','memory','io') for kind in ('some','full')}
    busy=[node_delta.get('cpu.ticks.'+field) for field in ('user','nice','system','irq','softirq','steal')]
    ticks=start.get('clock_ticks')
    cores=sum(busy)/ticks/wall if None not in busy and ticks and ticks==end.get('clock_ticks') and wall>0 else None
    return dict(start=start,end=end,cgroup_scope=context(dict(start=start,end=end))[1],cgroup_deltas=delta,
                cgroup_pressure_fraction=pressure,node_scope='node-wide' if node_pressure['cpu.some'] is not None else 'unavailable',
                node_deltas=node_delta,node_pressure_fraction=node_pressure,node_busy_cores=cores,wall_seconds=wall)


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
    print('RESOURCE-LEGEND cgroup='+str(cgroup or 'unavailable')+' cgroup_scope='+scope+'; cgroup=gate-container-not-node; node_source=/proc/pressure,/proc/stat,/proc/loadavg; node_scope='+whole['node_scope']+'; own_user_s/own_sys_s=process-and-child CPU seconds; cgroup_samples=[start,end,delta] ordered='+json.dumps(COUNTERS,separators=(',',':'))+'; cgroup_psi_avg=[start,end] percent ordered='+json.dumps(AVERAGES,separators=(',',':'))+'; cgroup_cores=delta-usage-microseconds/1000000/wall-seconds; node_samples=counter-to-[start,end,delta]-mapping; node_cores=delta-busy-ticks/CLK_TCK/wall-seconds; node_loadavg=[start,end]-one-five-fifteen-minute-averages; psi=delta-stall-microseconds/1000000/wall-seconds; cpu.stat=microseconds/counts; memory=bytes; unavailable=null')
    reports=[]
    for line in (root/'gate-steps.tsv').read_text().splitlines():
        name,status,started,ended=line.split('\t'); wall=float(ended)-float(started)
        lines=(root/f'gate-{name}.log').read_text(errors='replace').splitlines()
        own=cpu_from_log(lines); counted=counts(lines)
        resource=joined(raw_sample(root/f'gate-{name}-resource-start.raw'),raw_sample(root/f'gate-{name}-resource-end.raw'),wall)
        reports.append(dict(step=name,own_user_s=own[0],own_sys_s=own[1],**resource))
        print(f'STEP={name} STATUS={status} WALL={wall:.6f}s own_user_s={seconds(own[0])} own_sys_s={seconds(own[1])} '+compact(resource,owned)+' warn={warn} error={error} loss={loss} processes='.format(**counted)+json.dumps(counted['processes'],separators=(',',':')))
    wall=float(sys.argv[2]); begin=process_cpu(root/'gate-cpu-start.raw'); end=process_cpu(root/'gate-cpu-end.raw')
    own=[b-a if a is not None and b is not None else None for a,b in zip(begin,end)]
    resource=joined(raw_sample(root/'gate-resource-start.raw'),raw_sample(root/'gate-resource-end.raw'),wall)
    reports.append(dict(step='gate',own_user_s=own[0],own_sys_s=own[1],**resource))
    (root/'gate-resources.json').write_text(json.dumps(reports,indent=2)+'\n')
    print(f'GATE-RESOURCES WALL={wall:.6f}s own_user_s={seconds(own[0])} own_sys_s={seconds(own[1])} '+compact(resource,owned)+' artifact=.lane/gate-resources.json')


if __name__ == '__main__':
    main()
