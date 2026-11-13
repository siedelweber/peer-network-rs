"""Run a prepared gate round under an evidence-root lock; scheduling belongs to the invoker."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import time

import build_graph


class Refusal(ValueError):
    """A protocol refusal, not a verdict on the candidate."""


class Busy(Refusal):
    """A cooperating round or import holds the evidence-root lock."""


@contextmanager
def round_lock(directory, identity):
    """Hold one stable advisory inode through preparation and evidence close."""
    directory.mkdir(parents=True, exist_ok=True)
    with (directory/'.series-round.lock').open('a+') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Busy('round or import holds the evidence-root lock') from error
        stream.seek(0)
        stream.truncate()
        stream.write(json.dumps(identity, sort_keys=True)+'\n')
        stream.flush()
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


# Closed identity ownership: an unknown member cannot be corrected by a prefix.
SOURCE_KEY_MEMBERS = frozenset(('configuration', 'tiers', 'accounting', 'profiles'))
INVOKER_KEY_MEMBERS = frozenset(('lineage', 'node', 'toolchain', 'runtime', 'cargo_home_config'))


def configuration_differences(before, after, root):
    """Name every changed identity member and who can correct it."""
    result = []
    for name in sorted(set(before) | set(after)):
        if before.get(name) == after.get(name):
            continue
        if name == 'cargo_config':
            old, new = dict(before.get(name, [])), dict(after.get(name, []))
            for path in sorted(set(old) | set(new)):
                if old.get(path) != new.get(path):
                    kind = 'source' if Path(path).resolve().is_relative_to(root.resolve()) else 'invoker'
                    result.append(dict(member=name+'['+path+']', kind=kind))
        else:
            kind = 'invoker' if name in INVOKER_KEY_MEMBERS else 'source'
            if name not in SOURCE_KEY_MEMBERS | INVOKER_KEY_MEMBERS:
                kind = 'unknown'
            result.append(dict(member=name, kind=kind))
    return result


def argv(value):
    result = json.loads(value)
    if not isinstance(result, list) or not result or any(not isinstance(x, str) or not x for x in result):
        raise Refusal('command must be a nonempty JSON argument vector')
    return result


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True)+'\n')


def append(path, value):
    with path.open('a') as stream:
        stream.write(json.dumps(value, sort_keys=True)+'\n')


def copy_manifest(manifest, destination):
    """Copy only listed regular files, checking both names and observed sizes."""
    destination.mkdir()
    seen = set()
    for row in manifest['files']:
        name = Path(row['destination'])
        if name.is_absolute() or '..' in name.parts or str(name) in seen:
            raise Refusal('unsafe or duplicate archive destination')
        seen.add(str(name))
        source = Path(row['source'])
        if any(parent.is_symlink() for parent in (source, *source.parents)):
            raise Refusal('archive source traverses a link')
        target = destination/name
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as incoming, target.open('xb') as outgoing:
            if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):
                raise Refusal('archive source is not a regular file')
            while block := incoming.read(1024*1024):
                outgoing.write(block)
        if name != Path('round.log') and target.stat().st_size != row['bytes']:
            raise Refusal('archive evidence size changed')


class Round:
    def __init__(self, root, args):
        self.root, self.args = root.resolve(), args
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', args.label):
            raise Refusal('invalid round label')
        self.store = args.directory.resolve()/args.label
        if self.store.is_relative_to(self.root) or self.root.is_relative_to(self.store):
            raise Refusal('round evidence must live outside the checkout')
        if any(path.is_symlink() for path in (args.directory, *args.directory.parents)):
            raise Refusal('round evidence directory traverses a link')
        self.store.mkdir(parents=True, exist_ok=True)
        self.count = build_graph.series_count()
        if args.mode == 'sample' and (args.ordinal is None or not 1 <= args.ordinal <= self.count):
            raise Refusal('sample ordinal outside declared count')
        if args.mode != 'sample' and args.ordinal is not None:
            raise Refusal('only a sample has an ordinal')
        if (args.mode == 'repeat') != (args.repeat_of is not None):
            raise Refusal('repeat requires its obligation and only repeat accepts one')
        self.log = None
        self.planned = None
        self.storage_token = None

    def check_store(self):
        """Reconcile label state only while the round lock is held."""
        plans = self.store/'plans.jsonl'
        ledger = self.store/'ledger.jsonl'
        completed = {row['entry'] for row in map(json.loads,ledger.read_text().splitlines())} if ledger.exists() else set()
        unfinished = [row['entry'] for row in map(json.loads,plans.read_text().splitlines())
                      if row['entry'] not in completed] if plans.exists() else []
        if unfinished or (self.store/'active.json').exists():
            write(self.store/'ended.json',dict(reason='unfinished planned round',entries=unfinished))
        if (self.store/'ended.json').exists():
            raise Refusal('ended label cannot be reused')

    def command(self, command, environment=None, build=False):
        """Each command retains its output, status, wall and reaped CPU."""
        environment = dict(environment or {})
        if self.storage_token:
            environment['PN_GATE_STORAGE_TOKEN'] = self.storage_token
        clean = {key:value for key,value in os.environ.items() if key not in build_graph.DECLARATION_VARIABLES}
        unset = [word for key in build_graph.DECLARATION_VARIABLES for word in ('-u',key)]
        full = (self.args.build_prefix+['env']+unset+[key+'='+value for key,value in (environment or {}).items()]+command
                if build else command)
        start = time.time()
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        try:
            result = build_graph.cancellable(full, cwd=self.root, env=dict(clean, **(environment or {})),
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            status, output = result.returncode, result.stdout
        except OSError as error:
            status, output = 125, str(error)+'\n'
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        if self.log:
            with self.log.open('a') as stream:
                stream.write(output)
        recorded = ['PN_GATE_STORAGE_TOKEN=[redacted]' if word.startswith('PN_GATE_STORAGE_TOKEN=') else word for word in full]
        append(self.store/'commands.jsonl', dict(argv=recorded, started=start, wall=time.time()-start,
            user=after.ru_utime-before.ru_utime, system=after.ru_stime-before.ru_stime, status=status))
        print('GATE-ROUND-COMMAND '+json.dumps(dict(argv=recorded,status=status,wall=time.time()-start)), flush=True)
        if status < 0:
            raise InterruptedError('round command interrupted by signal '+str(-status))
        return status, output

    def require(self, command, **options):
        status, output = self.command(command, **options)
        if status:
            raise Refusal('round command failed: '+repr(command)+' status='+str(status))
        return output.strip()

    def run(self):
        identity = dict(label=self.args.label, base=self.args.base, source=self.args.source)
        with round_lock(self.store.parent, identity):
            from isolation import storage_lock, StorageBusy
            status, output = self.command(['python3','-B','ci/isolation.py','storage-root'],build=True)
            if status:
                raise Busy('storage preflight refused: '+output.strip())
            directory = Path(output.strip())
            if not directory.is_absolute():
                raise Refusal('build environment storage root must be absolute')
            try:
                with storage_lock(directory, 'series', identity) as token:
                    self.storage_token = token
                    try:
                        self.check_store()
                        return self.locked_run()
                    finally:
                        self.storage_token = None
            except StorageBusy as error:
                raise Busy('storage lock '+str(error)) from error

    def locked_run(self):
        try:
            return self.execute()
        except BaseException as error:
            if self.planned:
                write(self.store/'ended.json',dict(reason='planned round interrupted: '+str(error),entry=self.planned))
            raise

    def execute(self):
        args = self.args
        # The command is loaded from the candidate before either reset occurs.
        source = self.require(['git','rev-parse','--verify',args.source+'^{commit}'])
        base = self.require(['git','rev-parse','--verify',args.base+'^{commit}'])
        if source == base:
            raise Refusal('base equals source')
        if self.require(['git','rev-parse','HEAD']) != source or self.require(['git','status','--porcelain']):
            raise Refusal('round requires the clean source checkout')
        self.require(['git','merge-base','--is-ancestor',base,source])
        priming_path = self.store/'priming.json'
        priming = json.loads(priming_path.read_text()) if priming_path.exists() else None
        if args.mode == 'priming' and priming is not None:
            raise Refusal('label already has a priming record')
        if args.mode == 'sample' and (not priming or priming.get('status') != 0 or priming.get('complete') is not True
                or priming.get('base') != base or priming.get('source') != source):
            raise Refusal('sample requires green priming of this base and source')
        obligation = None
        if args.mode == 'repeat':
            for path in (args.repeat_of,args.repeat_of.parent/'gate-baseline.json'):
                if path.resolve().is_relative_to(self.root):
                    raise Refusal('repeat obligation and sidecar must live outside checkout before reset')
                if not path.is_file():
                    raise Refusal('repeat obligation and sidecar must exist before reset')
            obligation = json.loads(args.repeat_of.read_text())
            if obligation['base'] != base or obligation['source'] != source:
                raise Refusal('repeat transition differs from obligation')
        observed = json.loads(self.require(['python3','-B','ci/build_graph.py','series-identity'],build=True))
        key, identity = observed['key'], observed['identity']
        if not isinstance(identity, dict) or not re.fullmatch('[0-9a-f]{64}',key):
            raise Refusal('configuration key is malformed')
        if args.mode == 'sample' and key != priming['configuration_key']:
            differences = configuration_differences(priming.get('identity', {}), identity, self.root)
            record = dict(reason='configuration key differs from priming', expected=priming['configuration_key'],
                          observed=key, differences=differences)
            if priming.get('identity') and differences and all(row['kind'] == 'invoker' for row in differences):
                append(self.store/'preparations.jsonl',record)
                print('GATE-ROUND-RESTARTABLE '+json.dumps(record,sort_keys=True),flush=True)
                return 5
            write(self.store/'ended.json',record)
            print('GATE-ROUND-ENDED '+json.dumps(record,sort_keys=True),flush=True)
            return 4
        if obligation and key != obligation['configuration_key']:
            raise Refusal('repeat configuration differs from obligation')
        if args.mode == 'sample':
            heads = json.loads(self.require(['python3','-B','ci/build_graph.py','series-owner-heads'],build=True))
            if any(head not in (base,source) for head in heads.values()):
                append(self.store/'preparations.jsonl',dict(reason='retained owner outside label base or source',owners=heads))
                print('GATE-ROUND-RESTARTABLE retained owner outside label base or source; prepare owners before sampling',flush=True)
                return 5
        ledger_path = self.store/'ledger.jsonl'
        previous = [json.loads(line) for line in ledger_path.read_text().splitlines()] if ledger_path.exists() else []
        if args.mode == 'sample' and sum(row['ordinal'] == args.ordinal for row in previous) >= build_graph.series_policy()['series_attempts_per_ordinal']:
            write(self.store/'ended.json',dict(reason='attempt cap exhausted',ordinal=args.ordinal))
            raise Refusal('attempt cap exhausted; use a new label with its cause')
        rounds = self.store/'rounds'
        rounds.mkdir(exist_ok=True)
        number = len(list(rounds.iterdir()))+1
        entry = args.label+'-'+str(number)
        self.log = rounds/(entry+'.log')
        self.log.touch(exist_ok=False)
        preparation = dict(PN_GATE_SAMPLE='import')
        self.require(['git','reset','--hard',base])
        try:
            self.require(['python3','-B','ci/run_tests.py','prepare'],environment=preparation,build=True)
            self.require(['python3','-B','ci/discipline.py','clippy'],environment=preparation,build=True)
        finally:
            self.require(['git','reset','--hard',source])
        print('GATE-ROUND-BASE-BUILD base='+base+' source='+source+' status=0',flush=True)
        self.require(['git','clean','-fdx','-e','/.lane/build-graph/'])
        environment = dict(PN_GATE_PLAN='one-run',PN_GATE_ENTRY=entry,PN_GATE_SAMPLE='import',
            PN_IMPORT_BASE=base,PN_GATE_SERIES=args.label,PN_GATE_ORDINAL=str(args.ordinal or 1),
            PN_GATE_CONTAINER_LIST=json.dumps(args.container_list),PN_GATE_SERVICE_LIST=json.dumps(args.service_list))
        if args.mode == 'sample':
            environment.update(PN_GATE_SAMPLE='import-transition',PN_GATE_SERIES_COUNT=str(self.count),
                PN_GATE_SERIES_KEY=key,PN_GATE_SERIES_CACHE=priming['cache'])
        if obligation:
            environment.update(PN_GATE_SAMPLE=obligation['sample'],PN_GATE_REPEAT_OF=str(args.repeat_of.resolve()))
            if obligation['sample'] == 'import-transition':
                owed = json.loads((args.repeat_of.parent/'gate-baseline.json').read_text())
                cache = owed['cache']['state']
                if cache not in ('warm','cold'):
                    raise Refusal('repeat requires the owed cache receipt')
                environment.update(PN_GATE_SERIES_COUNT=str(self.count),PN_GATE_SERIES_KEY=key,PN_GATE_SERIES_CACHE=cache)
        plan_time = time.time()
        if args.mode != 'priming':
            status, _ = self.command(['python3','-B','ci/build_graph.py','series-idle','start'],environment=environment)
            idle_path = self.root/'.lane/gate-series-host-start.json'
            try:
                reason = 'start receipt failed' if status else build_graph.series_idle_refusal(json.loads(idle_path.read_text()))
            except (OSError,ValueError,TypeError) as error:
                reason = 'start receipt unreadable: '+str(error)
            if reason:
                append(self.store/'preparations.jsonl',dict(entry=entry,reason=reason,status=status))
                print('GATE-ROUND-RESTARTABLE '+reason,flush=True)
                return 5
        plan = dict(series=args.label,entry=entry,ordinal=args.ordinal or 1,start=plan_time,mode=args.mode)
        append(self.store/('plans.jsonl' if args.mode == 'sample' else 'preparations.jsonl'),plan)
        self.planned = entry
        write(self.store/'active.json',plan)
        print('GATE-PLAN '+json.dumps(plan),flush=True)
        if args.mode == 'priming':
            status, _ = self.command(['bash','ci/gate.sh'],environment=environment,build=True)
            pending_path = self.root/'.lane/gate-baseline.json'
            pending = json.loads(pending_path.read_text()) if pending_path.exists() else {}
            cache = pending.get('cache',{})
            complete = cache.get('state') in ('warm','cold') and set(cache.get('compiled',{})) == {'primary','lint'} and all(isinstance(v,list) for v in cache.get('compiled',{}).values())
            record = dict(base=base,source=source,configuration_key=key,identity=identity,cache=cache.get('state'),
                status=status,compiled=cache.get('compiled'),complete=complete,entry=entry,log=str(self.log),
                owners=json.loads(self.require(['python3','-B','ci/build_graph.py','series-owner-heads'],build=True)))
            write(priming_path,record)
            (self.store/'active.json').unlink()
            self.planned = None
            if status or not complete:
                write(self.store/'ended.json',dict(reason='priming red or compilation receipt incomplete',entry=entry))
                return 1 if status else 4
            print('GATE-ROUND-PRIMED '+json.dumps(record),flush=True)
            return 0
        gate, _ = self.command(['bash','ci/gate.sh'],environment=environment,build=True)
        end, _ = self.command(['python3','-B','ci/build_graph.py','series-idle','end'],environment=environment)
        close, _ = self.command(['python3','-B','ci/build_graph.py','series-close',str(gate)],environment=environment)
        discharge = 0
        if obligation:
            discharge, _ = self.command(['python3','-B','ci/build_graph.py','repeat-close',str(args.repeat_of.resolve()),str(self.root/'.lane')],environment=environment)
        exclusion = None
        if args.mode == 'sample' and not end:
            try:
                attempt = json.loads((self.root/'.lane/series-attempt.json').read_text())
                receipt = attempt['receipt']
                build_graph.series_member(receipt,receipt)
                if receipt['whole']['stall'] > build_graph.series_policy()['series_absolute_pressure']:
                    raise ValueError('whole pressure exceeds absolute bound')
            except (OSError,ValueError,KeyError,TypeError) as error:
                exclusion = str(error)
        archive_status, output = self.command(['python3','-B','ci/build_graph.py','series-archive-list','--round-log',str(self.log)])
        sidecar_bytes = None
        if archive_status == 0:
            try:
                manifest = json.loads(output)
                manifests = self.store/'manifests'; manifests.mkdir(exist_ok=True)
                write(manifests/(entry+'.json'),manifest)
                archive = self.store/('archive' if args.mode == 'sample' else 'repeats')
                archive.mkdir(exist_ok=True)
                copy_manifest(manifest,archive/entry)
                sidecar_bytes = next((row['bytes'] for row in manifest['files'] if row['destination']=='gate-baseline.json'),None)
            except (OSError,ValueError,KeyError,TypeError) as error:
                archive_status = 4
                print('GATE-ROUND-ARCHIVE-REFUSED '+str(error),flush=True)
        ledger = dict(series=args.label,entry=entry,ordinal=args.ordinal or 1,gate_status=gate,
            end_status=end,close_status=close,archive_status=archive_status,sidecar_bytes=sidecar_bytes,
            discharge_status=discharge,exclusion=exclusion,
            declared_identity=dict(base=base,source=source,configuration_key=key,cache=priming['cache'] if priming else 'unknown'))
        append(self.store/('ledger.jsonl' if args.mode == 'sample' else 'repeat-ledger.jsonl'),ledger)
        if end or close or archive_status:
            write(self.store/'ended.json',dict(reason='planned round evidence failed',entry=entry,
                end_status=end,close_status=close,archive_status=archive_status))
        (self.store/'active.json').unlink()
        self.planned = None
        print('GATE-ROUND-CLOSED '+json.dumps(ledger),flush=True)
        return 4 if end or close or archive_status or discharge else (1 if gate else (4 if exclusion else 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label',required=True)
    parser.add_argument('--base',required=True)
    parser.add_argument('--source',required=True)
    parser.add_argument('--mode',choices=('priming','sample','repeat'),required=True)
    parser.add_argument('--ordinal',type=int)
    parser.add_argument('--repeat-of',type=Path)
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--container-list',type=argv,required=True)
    parser.add_argument('--service-list',type=argv,required=True)
    parser.add_argument('--build-prefix',type=argv,required=True)
    args = parser.parse_args()
    try:
        return Round(Path.cwd(),args).run()
    except Busy as error:
        print('GATE-ROUND-RESTARTABLE '+str(error),flush=True)
        return 5
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print('GATE-ROUND-REFUSED '+str(error),flush=True)
        return 4


if __name__ == '__main__':
    raise SystemExit(main())
