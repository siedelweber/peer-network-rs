"""Stage a candidate's import protocol outside its checkout before switching it."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

import build_graph
from series_round import Round, Refusal, Busy, argv, append, write, round_lock


ADAPTER_FILES = ('import_gate.py', 'isolation.py', 'build_graph.py', 'series_round.py')


def verdict(status, output, phase):
    """Only a matching terminal report makes zero or one a verdict."""
    if status not in (0, 1):
        return False
    pattern = (rf'PRECHECK-EXIT={status} wall_s=[0-9.]+ execution=not-evaluated scope=all'
               if phase == 'precheck' else rf'GATE-EXIT={status}')
    lines = output.rstrip().splitlines()
    while lines and lines[-1].startswith('GATE-STORAGE-LOCK action=released '):
        lines.pop()
    return bool(lines and re.fullmatch(pattern, lines[-1]))


def import_status(result):
    """A child exit without the import's closing verdict is uncounted."""
    print(result.stdout, end='', flush=True)
    if result.returncode in (4, 5):
        return result.returncode
    for line in reversed(result.stdout.splitlines()):
        if line.startswith('GATE-IMPORT-CLOSED '):
            row = json.loads(line.removeprefix('GATE-IMPORT-CLOSED '))
            if row.get('counted') is True and row.get('status') == result.returncode and result.returncode in (0, 1):
                return result.returncode
            break
    print('GATE-IMPORT-REFUSED status=4 counted=false child_status='+str(result.returncode)+' reason=no-completed-verdict',flush=True)
    return 4


def atomic(path, value):
    """A complete per-entry state is authoritative even if its ledger append is cut."""
    descriptor, temporary = tempfile.mkstemp(prefix='.import-',dir=path.parent)
    try:
        with os.fdopen(descriptor,'w') as stream:
            json.dump(value,stream,sort_keys=True);stream.write('\n')
            stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def stage(root, source, directory):
    """Read regular candidate objects; execute no candidate checkout file."""
    directory.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix='adapter-', dir=directory))
    for name in ADAPTER_FILES:
        member = 'ci/'+name
        mode = subprocess.check_output(['git','ls-tree',source,'--',member],cwd=root,text=True)
        if not mode.startswith('100644 blob '):
            raise Refusal('candidate adapter must be a regular object: '+member)
        content = subprocess.check_output(['git','show',source+':'+member],cwd=root)
        (staged/name).write_bytes(content)
    return staged


def validate_stage(root, source, directory):
    """The private re-entry is bound to the candidate objects, not a caller flag."""
    for name in ADAPTER_FILES:
        path = directory/name
        expected = subprocess.check_output(['git','show',source+':ci/'+name],cwd=root)
        if path.is_symlink() or path.read_bytes() != expected:
            raise Refusal('staged adapter differs from candidate: '+name)


class Import(Round):
    """Keep the switching procedure, declaration and interrupted evidence together."""
    def __init__(self, root, args):
        self.root, self.args = root.resolve(), args
        self.store = args.directory.resolve()
        if self.store.is_relative_to(self.root) or self.root.is_relative_to(self.store):
            raise Refusal('import evidence must live outside checkout')
        if any(path.is_symlink() for path in (args.directory,*args.directory.parents)):
            raise Refusal('import evidence directory traverses a link')
        self.store.mkdir(parents=True,exist_ok=True)
        self.storage_token = None
        self.log = None
        self.raw_status = True

    def census(self):
        """Collect host listings before the build prefix and keep the refusal evidence."""
        def listing(command):
            status, output = self.command(command)
            return dict(status=status,stdout=output)
        processes = listing(['ps','-u',str(os.getuid()),'-o','pid=,ppid=,args='])
        parents = {}
        for line in processes['stdout'].splitlines():
            fields = line.split(None,2)
            if len(fields)==3 and fields[0].isdigit() and fields[1].isdigit():
                parents[int(fields[0])] = int(fields[1])
        ancestors = [os.getpid()]
        while ancestors[-1] in parents and parents[ancestors[-1]] not in ancestors:
            ancestors.append(parents[ancestors[-1]])
        record = dict(processes=processes,collector_ancestors=ancestors,
            containers=listing(self.args.container_list),services=listing(self.args.service_list),at=time.time())
        write(self.store/'host.json',record)
        refusal = build_graph.series_idle_refusal(record)
        if refusal:
            raise Busy('host preflight: '+refusal)

    def reconcile(self):
        """Close a lost import as interrupted, never infer a verdict or rerun it."""
        active = self.store/'active.json'
        if active.exists():
            row = json.loads(active.read_text())
            result = self.store/row['entry']/'result.json'
            if result.exists():
                closed = json.loads(result.read_text())
            else:
                closed = dict(row,status=4,outcome='interrupted',
                    reason='previous import has no recorded completion; inspect preserved log and checkout')
                atomic(result,closed)
            append(self.store/'ledger.jsonl',dict(closed,reconciled=True))
            active.unlink()
            raise Refusal('interrupted import reconciled; no work run; review before a new invocation')

    def execute_import(self):
        source = self.require(['git','rev-parse','--verify',self.args.source+'^{commit}'])
        base = self.require(['git','rev-parse','--verify',self.args.base+'^{commit}'])
        if source == base:
            raise Refusal('import base equals source')
        self.require(['git','merge-base','--is-ancestor',base,source])
        self.reconcile()
        ledger = self.store/'ledger.jsonl'
        rows = [json.loads(path.read_text()) for path in self.store.glob('import-*/result.json')]
        if any(row.get('source')==source and row.get('outcome')=='complete' for row in rows):
            raise Refusal('completed candidate is not rerun in this import store')
        if self.require(['git','rev-parse','HEAD']) not in (base,source) or self.require(['git','status','--porcelain']):
            raise Refusal('import requires the clean base or candidate checkout')
        entry = 'import-'+uuid.uuid4().hex
        self.log = self.store/(entry+'.log')
        evidence = self.store/entry
        evidence.mkdir()
        declaration = dict(entry=entry,base=base,source=source,plan='one-run',sample='import',
            at=datetime.now(timezone.utc).isoformat(),log=str(self.log))
        atomic(self.store/'active.json',declaration)
        append(self.store/'plans.jsonl',declaration)
        print('GATE-PLAN '+' '.join(key+'='+str(value) for key,value in declaration.items()),flush=True)
        # Every executing adapter and this driver are already outside the switch.
        self.require(['git','reset','--hard',base])
        self.require(['git','reset','--hard',source])
        self.require(['git','clean','-fdx','-e','.lane/build-graph/'])
        environment = dict(PN_GATE_PLAN='one-run',PN_GATE_ENTRY=entry,PN_GATE_SAMPLE='import',PN_IMPORT_BASE=base)
        precheck = gate = None
        outcome, reason, status = 'protocol-refusal', None, 4
        try:
            precheck, output = self.command(['python3','-B','ci/precheck.py'],environment=environment,build=True)
            if verdict(precheck, output, 'precheck'):
                if precheck == 1:
                    status, outcome = 1, 'complete'
                else:
                    gate, output = self.command(['bash','ci/gate.sh'],environment=environment,build=True)
                    if verdict(gate, output, 'gate'):
                        status, outcome = gate, 'complete'
            if precheck == 5 or gate == 5:
                status, outcome = 5, 'not-run'
            elif outcome != 'complete':
                outcome = 'process-nonverdict'
                reason = 'raw status or missing closing report is not a verdict'
        except Exception as error:
            outcome, reason = 'process-exception', type(error).__name__+': '+str(error)
        for name in ('gate-declaration.json','gate-wall.json','gate-resources.json','gate-steps.tsv',
                     'gate-baseline.json','gate-quiet-repeat.json'):
            path = self.root/'.lane'/name
            if path.is_file() and not path.is_symlink():
                shutil.copyfile(path,evidence/name)
        row = dict(declaration,status=status,precheck_status=precheck,gate_status=gate,
            outcome=outcome,counted=outcome=='complete',reason=reason,evidence=str(evidence))
        atomic(evidence/'result.json',row)
        append(ledger,row)
        (self.store/'active.json').unlink()
        print('GATE-IMPORT-CLOSED '+json.dumps(row,sort_keys=True),flush=True)
        return status

    def run(self):
        with round_lock(self.store,dict(base=self.args.base,source=self.args.source,kind='import')):
            self.census()
            adapter = Path(__file__).with_name('isolation.py')
            from isolation import storage_driver, storage_lock, StorageBusy
            storage_driver(self.root,[sys.executable,str(Path(__file__).resolve())])
            storage_driver(self.root,self.args.build_prefix,prefix=True)
            status, output = self.command(['python3','-E','-s','-B',str(adapter),'storage-root'],build=True)
            if status:
                raise Busy('storage preflight: '+output.strip())
            directory = Path(output.strip())
            if not directory.is_absolute():
                raise Refusal('storage root must be absolute')
            try:
                with storage_lock(directory,'gate',dict(base=self.args.base,source=self.args.source)) as token:
                    self.storage_token = token
                    try:
                        return self.execute_import()
                    finally:
                        self.storage_token = None
            except StorageBusy as error:
                raise Busy(str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',required=True)
    parser.add_argument('--source',required=True)
    parser.add_argument('--directory',required=True,type=Path)
    parser.add_argument('--container-list',required=True,type=argv)
    parser.add_argument('--service-list',required=True,type=argv)
    parser.add_argument('--build-prefix',required=True,type=argv)
    parser.add_argument('--staged',action='store_true',help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        runner = Import(Path.cwd(),args)
        if not args.staged:
            source = subprocess.check_output(['git','rev-parse','--verify',args.source+'^{commit}'],text=True).strip()
            staged = stage(runner.root,source,runner.store)
            result = build_graph.cancellable([sys.executable,'-E','-s','-B',str(staged/'import_gate.py'),*sys.argv[1:],'--staged'],
                                             stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            return import_status(result)
        if Path(__file__).resolve().parent.is_relative_to(runner.root):
            raise Refusal('staged import driver is inside checkout')
        validate_stage(runner.root,args.source,Path(__file__).resolve().parent)
        return runner.run()
    except Busy as error:
        print('GATE-IMPORT-NOT-RUN status=5 counted=false reason='+str(error),flush=True)
        return 5
    except Exception as error:
        print('GATE-IMPORT-REFUSED status=4 reason='+str(error),flush=True)
        return 4


if __name__ == '__main__':
    raise SystemExit(main())
