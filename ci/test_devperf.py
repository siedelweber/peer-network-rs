"""Claim area devperf: timing observations preserve execution predicates.

Python claim sites follow the authored gloss/claim/test form; the deployed
linter does not yet scan Python. These are local test inventory labels.
"""

import copy
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from devperf import StructuralError, assess, assessment, budgets, inclusive_ms, report, utc
from harness import CONFIGURATION
from test_harness import declarations, fixture
import run_tests


def execution(duration=1, outcome='passed'):
    return dict(operation='probe', budget='unit', duration_ms=duration,
                outcome=outcome, source='controlled fixture', configuration='injected duration',
                owner='foundation implementer')


def inventory_fixture(kind='lib', location='src/lib.rs'):
    inventory = {'rust-suites': {'example': {'package-name': 'example', 'binary-name': 'example',
                 'package-id': 'example', 'kind': kind, 'testcases': {'case': {'ignored': False}}}}}
    metadata = {'packages': [{'id': 'example', 'manifest_path': '/fixture/Cargo.toml',
                 'targets': [{'name': 'example', 'kind': [kind], 'src_path': '/fixture/' + location}]}]}
    return inventory, metadata


class Performance(unittest.TestCase):
    def test_calibration_identity(self):
        """A measured function retains exact standing through unrelated edits, while a changed or missing body becomes pending under its owner without changing its allowance.
        ´claim:devperf:changed-calibration-is-pending´
        ´test:integration:test-calibration-identity´
        """
        from devperf import case_identity, calibration_identities
        source = 'def probe():\n    return 1\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'case.py'
            identity = dict(path='case.py', function='probe', digest=case_identity(source, 'case.py', 'probe'), owner='fixture-owner')
            declared = {'case':dict(calibration_campaign='fixture', calibration_source=identity, budget_ms=100)}
            original = copy.deepcopy(declared)
            for body, status in ((source, 'exact'), (source+'\ndef other():\n    return 2\n', 'exact'),
                                 (source.replace('return 1', 'return 2'), 'pending'), ('', 'pending')):
                path.write_text(body)
                row, = calibration_identities(declared, root)
                self.assertEqual(row['status'], status)
                self.assertEqual(row['owner'], 'fixture-owner')
                self.assertEqual(declared, original)
            rust = 'fn probe() { let text = "}"; /* } */ assert!(true); }'
            self.assertEqual(case_identity(rust, 'case.rs', 'probe'), case_identity(rust+'\nfn other() {}', 'case.rs', 'probe'))
            self.assertNotEqual(case_identity(rust, 'case.rs', 'probe'), case_identity(rust.replace('true','false'), 'case.rs', 'probe'))

        for path, source, changed in (
                ('case.py', 'def helper():\n    return 1\ndef probe():\n    return helper()\n', 'return 2'),
                ('case.rs', "fn helper() { let brace = '}'; } fn probe() { helper(); }", "let brace = '{'")):
            original = case_identity(source, path, 'probe')
            altered = source.replace('return 1', changed) if path.endswith('.py') else source.replace("let brace = '}'", changed)
            self.assertNotEqual(original, case_identity(altered, path, 'probe'))
        for text in ("fn probe() { let c = '}'; assert!(true); }",
                     'fn probe() { let s = r###"} fn fake() {"###; assert!(true); }',
                     'fn probe() { /* outer } /* nested { */ } */ assert!(true); }'):
            self.assertNotEqual(case_identity(text, 'case.rs', 'probe'), case_identity(text.replace('true', 'false'), 'case.rs', 'probe'))
        for path, source in (('case.py', '@marker(1)\ndef probe():\n    pass\n'),
                             ('case.rs', '#[marker(1)]\nfn probe() {}')):
            self.assertNotEqual(case_identity(source, path, 'probe'), case_identity(source.replace('marker(1)', 'marker(2)'), path, 'probe'))
        source = 'def leaf():\n    return 1\ndef helper():\n    return leaf()\ndef probe():\n    return helper()\n'
        self.assertNotEqual(case_identity(source, 'case.py', 'probe'), case_identity(source.replace('return 1', 'return 2'), 'case.py', 'probe'))
        source = 'class Fixture:\n    def leaf(self):\n        return 1\n    def probe(self):\n        def invoke():\n            return self.leaf()\n        return invoke()\n'
        self.assertNotEqual(case_identity(source, 'case.py', 'probe'), case_identity(source.replace('return 1', 'return 2'), 'case.py', 'probe'))
        source = 'fn leaf() { } fn helper() { leaf(); } fn probe() { helper(); }'
        self.assertNotEqual(case_identity(source, 'case.rs', 'probe'), case_identity(source.replace('fn leaf() { }', 'fn leaf() { return; }'), 'case.rs', 'probe'))

        source = 'fn helper(value: [u8; 2]) { let _ = value; } fn probe() { helper([0, 0]); }'
        self.assertNotEqual(case_identity(source, 'case.rs', 'probe'), case_identity(source.replace('let _ = value;', 'let _ = value[0];'), 'case.rs', 'probe'))
        for path, source in (('case.py', 'def probe():\n    pass\ndef probe():\n    pass\n'),
                             ('case.rs', 'fn probe() {} fn probe() {}')):
            with self.assertRaisesRegex(StructuralError, 'ambiguous'):
                case_identity(source, path, 'probe')
        # The declared syntactic closure excludes implicit runner fixtures and
        # module state; it does not pretend to resolve runtime initialization.
        source = 'LIMIT = 1\nclass Fixture:\n    def setUp(self):\n        self.value = 1\n    def probe(self):\n        return self.value + LIMIT\n'
        self.assertEqual(case_identity(source, 'case.py', 'probe'),
                         case_identity(source.replace('= 1', '= 2'), 'case.py', 'probe'))
        source = 'const LIMIT: u8 = 1; fn probe() { let value = LIMIT; }'
        self.assertEqual(case_identity(source, 'case.rs', 'probe'),
                         case_identity(source.replace('= 1', '= 2'), 'case.rs', 'probe'))

    def test_gate_target_lock(self):
        """The supervisor reports its wait and owns the target lock until gate exit, without lending it to a surviving descendant.
        ´claim:devperf:gate-target-lock-is-supervised´
        ´test:integration:test-gate-target-lock´
        """
        import fcntl
        import multiprocessing
        import signal
        import sys
        from contextlib import redirect_stdout, redirect_stderr
        from isolation import gate_target
        with tempfile.TemporaryDirectory() as directory:
            command = 'sleep 30 >/dev/null 2>&1 & echo $! > "$1"\nprintf "locked\\n"\nread -r release\n'
            pidfile = Path(directory)/'descendant'
            errors = Path(directory)/'stderr'
            output_read, output_write = os.pipe()
            release_read, release_write = os.pipe()
            def supervise():
                os.close(output_read)
                os.close(release_write)
                os.dup2(release_read, 0)
                os.close(release_read)
                with os.fdopen(output_write, 'w') as output, errors.open('w') as diagnostic:
                    os.dup2(output.fileno(), 1)
                    os.dup2(diagnostic.fileno(), 2)
                    with redirect_stdout(output), redirect_stderr(diagnostic):
                        os.environ['CARGO_TARGET_DIR'] = directory
                        sys.exit(gate_target(['bash', '-c', command, 'fixture', str(pidfile)]))
            child = multiprocessing.get_context('fork').Process(target=supervise)
            child.start()
            os.close(output_write)
            os.close(release_read)
            try:
                with os.fdopen(output_read) as output, os.fdopen(release_write, 'w') as release:
                    try:
                        self.assertRegex(output.readline(), r'^GATE-TARGET-LOCK wait_s=[0-9.]+ path=')
                        self.assertEqual(output.readline(), 'locked\n')
                        lock = str(Path(directory)/'.gate-target.lock')
                        with open(lock, 'a') as competing:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        release.write('release\n')
                        release.flush()
                        child.join(10)
                self.assertFalse(child.is_alive(), 'gate supervisor exceeded its exit deadline')
                self.assertEqual(child.exitcode, 0, errors.read_text())
                with open(lock, 'a') as released:
                    os.kill(int(pidfile.read_text()), 0)
                    fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                if child.is_alive():
                    child.terminate()
                    child.join(10)
                if pidfile.exists():
                    os.kill(int(pidfile.read_text()), signal.SIGTERM)

    def test_gate_cancel_cleanup(self):
        """Cancellation retains target exclusion until a slow EXIT stop and its session finish.
        ´claim:devperf:gate-cancellation-retains-exclusion´
        ´test:integration:test-gate-cancel-cleanup´
        """
        import fcntl
        import multiprocessing
        import signal
        import sys
        import time
        from isolation import gate_target
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready_read, ready_write = os.pipe()
            command = '''trap 'trap - EXIT; trap "" TERM INT; printf "stopping\\n"; sleep 6; kill -KILL "$service"; wait "$service"; printf "service-stopped\\n"; kill -KILL "$session"; wait "$session"; printf "session-closed\\n"' EXIT
trap 'trap "" TERM INT; exit 143' TERM INT
bash -c 'trap "" TERM INT; printf "service-ready\\n"; exec sleep 60' & service=$!
bash -c 'trap "" TERM INT; printf "session-ready\\n"; exec sleep 60' & session=$!
printf '%s %s\\n' "$service" "$session" > "$1"
printf "ready\\n"
wait
'''
            def supervise():
                os.close(ready_read)
                os.dup2(ready_write, 1)
                os.close(ready_write)
                with (root/'stderr').open('w') as errors:
                    os.dup2(errors.fileno(), 2)
                    os.environ['CARGO_TARGET_DIR'] = directory
                    sys.exit(gate_target(['bash', '-c', command, 'fixture', str(root/'pids')]))
            child = multiprocessing.get_context('fork').Process(target=supervise)
            child.start()
            os.close(ready_write)
            try:
                with os.fdopen(ready_read) as events, (root/'.gate-target.lock').open('a') as lock:
                    self.assertTrue(events.readline().startswith('GATE-TARGET-LOCK'))
                    self.assertEqual({events.readline() for _ in range(3)}, {'ready\n', 'service-ready\n', 'session-ready\n'})
                    pids = [int(pid) for pid in (root/'pids').read_text().split()]
                    self.assertEqual(len(pids), 2)
                    child.terminate()
                    self.assertEqual(events.readline(), 'stopping\n')
                    time.sleep(5.25)
                    self.assertTrue(child.is_alive(), 'supervisor killed the gate during EXIT stop')
                    for pid in pids:
                        os.kill(pid, 0)
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.assertEqual(events.readline(), 'service-stopped\n')
                    self.assertEqual(events.readline(), 'session-closed\n')
                    child.join(10)
                    self.assertFalse(child.is_alive())
                    self.assertEqual(child.exitcode, 143)
                    for pid in pids:
                        with self.assertRaises(ProcessLookupError):
                            os.kill(pid, 0)
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                if child.is_alive():
                    os.kill(child.pid, signal.SIGKILL)
                    child.join(10)

    def test_target_retention(self):
        """Retention drops oversized incremental state before profile artifacts and preserves owner metadata; inclusive Cargo-and-run CPU stays apart from compile CPU.
        ´claim:devperf:target-retention-preserves-metadata´
        ´test:integration:test-target-retention´
        """
        from isolation import bound_target, cargo_work, built_executable
        artifact = dict(reason='compiler-artifact', target=dict(name='documents'), executable='/owned/target/triple/gate/documents')
        self.assertEqual(built_executable(json.dumps(artifact)), artifact['executable'])
        with self.assertRaisesRegex(ValueError, 'exactly one executable'):
            built_executable('{}')
        with self.assertRaisesRegex(ValueError, 'exactly one executable'):
            built_executable(json.dumps(artifact)+'\n'+json.dumps(dict(artifact, executable='/other/documents')))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target/'gate/incremental').mkdir(parents=True)
            (target/'gate/incremental/old').write_bytes(b'x'*32768)
            (target/'gate/dependency').write_bytes(b'x'*8192)
            (target/'gate-baselines').mkdir()
            (target/'gate-baselines/retained').write_text('baseline')
            self.assertTrue(bound_target(target, 24576, 'fixture'))
            self.assertFalse((target/'gate/incremental').exists())
            self.assertTrue((target/'gate/dependency').exists())
            self.assertFalse(bound_target(target, 24576, 'fixture'))
            self.assertTrue(bound_target(target, 1, 'fixture'))
            self.assertFalse((target/'gate').exists())
            self.assertEqual((target/'gate-baselines/retained').read_text(), 'baseline')
            (target/'triple/gate/.fingerprint').mkdir(parents=True)
            (target/'triple/CACHEDIR.TAG').write_text('Cargo cache')
            (target/'triple/gate/dependency').write_bytes(b'x'*8192)
            (target/'host-observation-runtime/gate/.fingerprint').mkdir(parents=True)
            (target/'host-observation-runtime/.rustc_info.json').write_text('{}')
            (target/'host-observation-runtime/gate/dependency').write_bytes(b'x'*8192)
            (target/'isolation/owner').mkdir(parents=True)
            (target/'isolation/owner/retained').write_text('owned')
            output = io.StringIO()
            from contextlib import redirect_stdout
            with redirect_stdout(output):
                self.assertTrue(bound_target(target, 1, 'fixture'))
            self.assertFalse((target/'triple/gate').exists())
            self.assertEqual((target/'isolation/owner/retained').read_text(), 'owned')
            self.assertIn('outside_profiles=isolation', output.getvalue())
            self.assertIn('target_layout=triple', output.getvalue())
            self.assertIn('nested_target=host-observation-runtime', output.getvalue())
            self.assertTrue((target/'host-observation-runtime/gate/dependency').exists())
            self.assertIn('scope=reported-not-profile-ceiling', output.getvalue())
            log = target/'meter.jsonl'
            with patch('isolation.subprocess.run', return_value=SimpleNamespace(returncode=0)):
                for command in ('build', 'check', 'run', 'test'):
                    self.assertEqual(cargo_work(['cargo', str(log), command]), 0)
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual([row['compile_only'] for row in rows], [True, True, False, False])

    def test_distinct_excess_ledger(self):
        """Claim: The gate ledger counts each current-source case excess once by configuration, operation, budget and tier across owned files, retains the largest repeated measurement, and excludes stale evidence and non-budget findings while reporting other scope excesses separately.
        ´claim:devperf:distinct-excess-ledger-is-gate-evidence´
        ´test:integration:test-distinct-excess-ledger´
        """
        from devperf import excess_ledger
        declaration = declarations()
        declaration['suite'] = dict(category='suite')
        first = dict(execution(200), kind='budget-excess', tier='fast')
        second = dict(first, operation='other', tier='service')
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory)/name for name in ('parent.jsonl','child.jsonl')]
            paths[0].write_text('\n'.join(json.dumps(row) for row in [first, dict(first,source='stale'), dict(first,kind='regression'), dict(first,budget='suite')]))
            paths[1].write_text('\n'.join(json.dumps(row) for row in [dict(first,duration_ms=300), second]))
            result = excess_ledger(paths, first['source'], declaration)
            self.assertEqual(result['distinct_cases'], 2)
            self.assertEqual(result['by_budget'], {'unit':2})
            self.assertEqual(result['by_tier'], {'fast':1, 'service':1})
            self.assertEqual(result['distinct_excesses'], 3)
            self.assertEqual(next(row for row in result['entries'] if row['operation']=='probe' and row['budget']=='unit')['duration_ms'], 300)
            self.assertEqual(result['verdict_effect'], 'none')

    def test_tier_overrun(self):
        """Tier summaries keep wall overruns separate from functional verdicts and exclude foreign-source and cold-owner measurements from comparisons.
        ´claim:devperf:tier-overruns-retain-functional-verdicts´
        ´test:integration:test-tier-overrun´
        """
        from contextlib import redirect_stdout
        from build_graph import tier_summary
        tiers = {name: dict(steps=[name], invocation_budget='fixture')
                 for name in ('fast', 'service', 'reference-certificate', 'extended')}
        tiers['fast']['finalize_steps'] = ['finalize']
        names = [*tiers, 'finalize']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lane = root/'.lane'
            lane.mkdir()
            for wall, expected, cold, old_cold, old_stall in ((1, False, False, False, .2), (1, False, False, True, .2), (2, False, True, False, .2), (3, True, True, False, .2), (3, True, False, False, .2), (3, True, False, False, .9)):
                baseline = dict(source="prior", tiers={name: dict(wall=4, selected_cases=[], resources={'node_pressure_fraction':{'cpu.some':old_stall}}, step_figures={name: dict(wall=1, own_cpu_s=1, cargo_cpu_s=0.25, layouts={"fixture":"fixture-layout"}, partial=old_cold)}) for name in names})
                for name in names:
                    actual = dict(owner='fixture', source='fixture', layout='fixture-layout', cargo_cpu_s=0.5, cold_target=cold, layout_changed=False)
                    synthetic = dict(actual, owner='synthetic', source='witness-source', cargo_cpu_s=100, cold_target=True)
                    (lane/f'gate-{name}.log').write_text('\n'.join('ISOLATION-COMPILE '+json.dumps(row) for row in (synthetic, actual)))
                for status, changed_selection in ((0, False), (1, False), (0, True)):
                    if changed_selection:
                        baseline["tiers"]["service"]["selected_cases"] = ["previous-case"]
                    else:
                        baseline["tiers"]["service"]["selected_cases"] = []
                    (lane/'gate-steps.tsv').write_text(''.join(f'{name}\t{status}\t0\t{wall}\n' for name in names))
                    output = io.StringIO()
                    with patch('devperf.budgets', return_value={'fixture': dict(budget_ms=2000), 'gate': dict(load_unresolved_pressure_percent=10, cpu_growth_percent=20, rebuild_steps=[])}), patch('build_graph.baseline_context', return_value=(lane/'baseline.json', baseline, [])), patch('gate_resources.raw_sample', return_value={'epoch_seconds':0}), patch('gate_resources.joined', return_value={'node_pressure_fraction':{'cpu.some':.4}}), patch('gate_resources.compact', return_value='busy=fixture stall=fixture'), patch('gate_resources.cpu_from_log', return_value=(1, 0)), patch('build_graph.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='tree')), patch.dict(os.environ, PN_GATE_SOURCE='fixture'), redirect_stdout(output):
                        tier_summary(root, SimpleNamespace(tiers=tiers), dict.fromkeys(names, 0))
                    measured = json.loads((lane/'gate-tiers.json').read_text())
                    for name in tiers:
                        self.assertEqual(measured[name]['status'], status)
                        self.assertEqual(measured[name]['over_budget'], expected)
                        self.assertEqual(measured[name]['step_figures'][name]['partial'], cold)
                        self.assertEqual(measured[name]['partial_steps'], [name] if cold else [])
                        self.assertEqual(measured[name]['step_figures'][name]['layouts'], {'fixture':'fixture-layout'})
                        self.assertEqual(measured[name]['build_cpu_s'], 0.5)
                        selection_differs = changed_selection and name == 'service'
                        self.assertEqual(measured[name]['comparable_cases'], not selection_differs)
                        self.assertEqual(measured[name]['comparable_build_cpu_s'], None if cold or old_cold or selection_differs else 0.5)
                        self.assertEqual(measured[name]['baseline_comparable_build_cpu_s'], None if cold or old_cold or selection_differs else 0.25)
                        self.assertEqual(measured[name]['excess_s'], max(0, wall-2))
                        self.assertEqual(measured[name]['baseline_stall'], old_stall)
                        if wall == 3 and not cold:
                            self.assertEqual(measured[name]['classification'], 'unclassified' if selection_differs else ('high-stall' if old_stall == .2 else 'load-unresolved'))
                    self.assertFalse(measured['finalize']['over_budget'])
                    self.assertIsNone(measured['finalize']['excess_s'])
                    self.assertIn('verdict='+('red' if status else 'green'), output.getvalue())
                    self.assertIn('over_budget='+str(expected).lower(), output.getvalue())
                    self.assertIn('own_user_s=1 own_sys_s=0', output.getvalue())
                    fast = next(line for line in output.getvalue().splitlines() if line.startswith('GATE-TIER tier=fast '))
                    self.assertIn('over_budget='+str(expected).lower(), fast)
                    self.assertIn('excess_s='+str(max(0.0, wall-2.0)), fast)

    def test_whole_gate_warning(self):
        """The whole critical path keeps its own warning and baseline while preserving the functional verdict.
        ´claim:devperf:whole-gate-warning-preserves-verdict´
        ´test:integration:test-whole-gate-warning´
        """
        from contextlib import redirect_stdout
        from build_graph import wall_summary
        from devperf import whole_gate_declaration
        campaign = dict(label='campaign:devperf:whole-gate-mixed', warmup_commit='a'*40, source_commit='b'*40,
                        discarded_warmup_ms=2000, rebuild_wall_ms=1200, warm_walls_ms=[1000, 1100, 1150],
                        multiplier=1.25, round_ms=50, sample_choice='maximum-of-rebuild-and-three-warm', configuration='fixture')
        declared = {'gate':dict(warm_samples=3, allowance_multiple=2, allowance_round_ms=50),
                    'whole-gate':dict(budget_ms=1500, wall_multiple=1.25, wall_campaign=campaign)}
        whole_gate_declaration(declared)
        bad = copy.deepcopy(declared)
        bad['service-gate'] = dict(budget_ms=1501)
        with self.assertRaisesRegex(StructuralError, 'below the largest tier'):
            whole_gate_declaration(bad)
        bad = copy.deepcopy(declared)
        bad['whole-gate']['budget_ms'] -= 1
        with self.assertRaisesRegex(StructuralError, 'bound differs'):
            whole_gate_declaration(bad)
        bad = copy.deepcopy(declared)
        bad['whole-gate']['wall_campaign']['warm_walls_ms'].pop()
        with self.assertRaisesRegex(StructuralError, 'malformed'):
            whole_gate_declaration(bad)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lane = root/'.lane'
            lane.mkdir()
            measured = dict(step='gate', wall_seconds=1.2, own_user_s=1, own_sys_s=.1,
                            node_pressure_fraction={'cpu.some':.2}, start={'epoch_seconds':1}, end={'epoch_seconds':2.2})
            (lane/'gate-resources.json').write_text(json.dumps([measured]))
            figures = dict(comparable_cpu_s=1, baseline_comparable_cpu_s=1, comparable_build_cpu_s=.5,
                           baseline_comparable_build_cpu_s=.5, compile_wall_growth_s=0,
                           own_user_s=1, own_sys_s=0, baseline_cpu_s=1,
                           changed_build_inputs=[], baseline_source='prior', baseline_match='import-base-tree')
            for status in (0, 1):
                pending = dict(source='fixture', tiers={'fast':figures}, previous_whole={'wall':2, 'stall':.1, 'own_user_s':1, 'own_sys_s':.1})
                (lane/'gate-baseline.json').write_text(json.dumps(pending))
                output = io.StringIO()
                with patch('devperf.budgets', return_value={'gate':{'cpu_growth_percent':20}, 'whole-gate':{'budget_ms':1000}}), patch('build_graph.subprocess.run', return_value=SimpleNamespace(returncode=0)) as run, patch.dict(os.environ, PN_GATE_SOURCE='fixture', PN_GATE_PARALLEL='1'), redirect_stdout(output):
                    self.assertEqual(wall_summary(root, status), 0)
                result = json.loads((lane/'gate-wall.json').read_text())
                self.assertEqual(result['status'], status)
                self.assertTrue(result['over_budget'])
                self.assertEqual(result['classification'], 'high-stall')
                self.assertEqual(result['baseline_stall'], .1)
                self.assertEqual(result['baseline_source'], 'prior')
                self.assertAlmostEqual(result['comparable_cpu_s'], 1.1)
                self.assertAlmostEqual(result['baseline_comparable_cpu_s'], 1.1)
                self.assertIn('GATE-WALL WALL=1.200000s verdict='+('green' if status == 0 else 'red'), output.getvalue())
                retained = json.loads((lane/'gate-baseline.json').read_text())
                self.assertEqual(retained['whole'], result)
                self.assertNotIn('previous_whole', retained)
                self.assertIn('exit:'+str(status), run.call_args.args[0])
            (lane/'gate-resources.json').unlink()
            with patch('devperf.budgets', return_value={'gate':{'cpu_growth_percent':20}, 'whole-gate':{'budget_ms':1000}}), patch('build_graph.subprocess.run', return_value=SimpleNamespace(returncode=0)), patch.dict(os.environ, PN_GATE_SOURCE='fixture', PN_GATE_PARALLEL='1'), redirect_stdout(io.StringIO()):
                self.assertEqual(wall_summary(root, 0, (1, 2.2)), 0)
            unavailable = json.loads((lane/'gate-wall.json').read_text())
            self.assertIsNone(unavailable['own_user_s'])
            self.assertEqual(unavailable['classification'], 'unclassified')
            self.assertEqual(unavailable['status'], 0)
            registry = root/'registry.toml'
            registry.write_text('rows = []\n')
            argv = ['devperf', '--operation', 'gate::whole', '--budget', 'whole-gate',
                    '--overrun-class', 'high-stall', '--duration-s', '1.2', '--outcome', 'exit:0',
                    '--findings', str(root/'findings.json'), '--registry', str(registry)]
            from devperf import main
            with patch('sys.argv', argv), patch('devperf.budgets', return_value=declared), patch('devperf.report', return_value=0) as report_call:
                self.assertEqual(main(), 0)
            record = report_call.call_args.args[0][0]
            self.assertEqual(record['tier'], 'whole')
            self.assertEqual(record['overrun_class'], 'high-stall')
            self.assertEqual(record['applicable_budgets'], ['whole-gate'])
            finding, = assess({**record, 'duration_ms':2500, 'outcome':'exit:1'},
                              {'whole-gate':dict(budget_ms=2400, category='aggregate')})
            self.assertEqual(finding['classification'], 'high-stall')
            self.assertEqual(finding['outcome'], 'exit:1')
            self.assertEqual(finding['verdict_effect'], 'none')
    def test_overrun_classes(self):
        """Rebuild classification requires comparable compile CPU growth and serialized wall growth covering the excess; load alone cannot establish rebuild work.
        ´claim:devperf:rebuild-requires-compile-cpu-and-wall´
        ´test:integration:test-overrun-classes´
        """
        from build_graph import overrun_class
        policy = dict(load_unresolved_pressure_percent=10, cpu_growth_percent=20)
        def classify(own=100, baseline=100, stall=0.09, build=40, old_build=40, changed=()):
            return overrun_class(True, own, baseline, stall, build, old_build, changed, policy, compile_wall_growth=build-old_build, excess=21, wall=210, baseline_wall=189, baseline_stall=0)
        self.assertEqual(classify(), 'plain')
        self.assertEqual(classify(own=120), 'plain')
        self.assertEqual(classify(stall=0.1), 'high-stall')
        self.assertEqual(classify(own=121), 'growth')
        self.assertEqual(classify(own=121, build=61, changed=['packages/example/src/pins.rs']), 'rebuild')
        self.assertEqual(classify(own=121, build=60, changed=['packages/example/src/pins.rs']), 'growth')
        self.assertEqual(classify(own=121, build=61), 'growth')
        self.assertEqual(classify(own=121, build=61, changed=['Cargo.lock'], stall=0.1), 'high-stall')
        self.assertEqual(classify(baseline=None), 'unclassified')
        self.assertEqual(classify(stall=None), 'unclassified')
        self.assertEqual(overrun_class(True, 100, 100, 0, 120, 100, ['Cargo.lock'], policy,
            compile_wall_growth=60, excess=21, wall=141, baseline_wall=100, baseline_stall=0), 'plain')
        # The line is continuous: 5 percent pressure can explain an overrun,
        # while 15 percent pressure cannot excuse a wall beyond its projection.
        for stall in (.05, .15):
            projected = 118*(1-.01)/(1-stall)
            for delta, expected in ((-.001, 'high-stall'), (.001, 'load-unresolved' if stall > .1 else 'plain')):
                self.assertEqual(overrun_class(True, 100, 100, stall, 40, 40, [], policy,
                    wall=projected+delta, baseline_wall=118, baseline_stall=.01, excess=projected+delta-120), expected)
        # A previously over-budget baseline cannot turn zero or insufficient
        # stall into an explanation for an otherwise unchanged overrun.
        for stall in (0, .01):
            self.assertEqual(overrun_class(True, 100, 100, stall, 40, 40, [], policy,
                wall=130, baseline_wall=135, baseline_stall=0, excess=10), 'plain')
        for cpu in (100, 150):
            self.assertEqual(overrun_class(True, cpu, 100, .4, 40, 40, [], policy,
                wall=200, baseline_wall=100, baseline_stall=.05, excess=80), 'load-unresolved')
        # Projection is slack here, so only whole-excess coverage decides.
        boundary = 120/(1-.1)
        for delta, expected in ((-.001, 'high-stall'), (.001, 'plain')):
            wall = boundary+delta
            self.assertEqual(overrun_class(True, 100, 100, .1, 40, 40, [], policy,
                wall=wall, baseline_wall=150, baseline_stall=.01, excess=wall-120), expected)
        from build_graph import status_changes
        self.assertEqual(status_changes({'case':{'selected':'passed'}, 'obligation':{'scope':'scoped-passed'}},
            {'case':{'selected':'held'}, 'obligation':{'scope':'held'}}), [
                dict(kind='case', name='selected', before='held', after='passed'),
                dict(kind='obligation', name='scope', before='held', after='scoped-passed')])
        self.assertEqual(status_changes({'case':{'same':'passed'}}, {'case':{'same':'passed'}}), [])
        self.assertEqual(overrun_class(False, None, None, None, None, None, [], policy), 'within-budget')
        from build_graph import compile_comparison
        cold = dict(wall=100, own_cpu_s=315, layouts={'owner':'old'}, partial=True)
        old = {'test-build':dict(wall=3.8, own_cpu_s=103.153, layouts={}, partial=False), 'isolated':cold}
        current = {'test-build':dict(wall=64.3, own_cpu_s=407.389, layouts={}, partial=False),
                   'isolated':dict(cold, own_cpu_s=10, layouts={'owner':'new'}, partial=False)}
        own, baseline, growth, omitted = compile_comparison(current, old, ['test-build'])
        self.assertEqual(omitted, ['isolated'])
        self.assertAlmostEqual(growth, 60.5)
        self.assertEqual(overrun_class(True, own, baseline, .0525, 407.389, 103.153,
            ['packages/epoch/src/controller.rs'], policy, compile_wall_growth=growth, excess=39.179, wall=159.179, baseline_wall=100, baseline_stall=0), 'rebuild')
        # Comparable compile CPU excludes the cold isolated baseline owner.
        self.assertEqual(overrun_class(True, 714.200, 684.486, .0525, 407.389, 103.153,
            ['packages/epoch/src/controller.rs'], policy, compile_wall_growth=growth, excess=39.179, wall=159.179, baseline_wall=100, baseline_stall=0), 'rebuild')
        self.assertEqual(overrun_class(True, 714.200, 684.486, .0525, 407.389, 418.153,
            ['packages/epoch/src/controller.rs'], policy, compile_wall_growth=growth, excess=39.179, wall=159.179, baseline_wall=100, baseline_stall=0), 'plain')
        self.assertEqual(overrun_class(True, 100, 100, .09, 40, 40,
            ['packages/example/src/pins.rs'], policy, compile_wall_growth=60, excess=21, wall=141, baseline_wall=100, baseline_stall=0), 'plain')


    def test_baseline_lineage(self):
        """Tree-keyed lineage baselines survive re-signing and unimported candidates while refusing a mismatched import tree.
        ´claim:devperf:baseline-follows-import-tree´
        ´test:integration:test-baseline-lineage´
        """
        from build_graph import baseline_context, retain_baseline
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'Cargo.toml').write_text('[profile.gate]\nopt-level = 1\n')
            (root/'.cargo').mkdir()
            (root/'.cargo/config.toml').write_text('fixture')
            (root/'.lane').mkdir()
            (root/'.lane/performance-events.jsonl').write_text('')
            (root/'.lane/harness-benchmarks.jsonl').write_text('')
            (root/'.lane/claim-evidence.json').write_text('{"obligations":[]}')
            registry = SimpleNamespace(tiers={'fast': {'jobs': 8}})
            good = SimpleNamespace(returncode=0, stdout='compiler identity')
            with patch.dict(os.environ, CARGO_TARGET_DIR=directory, PN_GATE_SOURCE='current', PN_IMPORT_BASE=''), patch('build_graph.subprocess.run', return_value=good):
                path, old, changed = baseline_context(root, registry)
                self.assertIsNone(old)
                candidate = dict(path=str(path), source='ancestor', tiers={})
                (root/'.lane/gate-baseline.json').write_text(json.dumps(candidate))
                retain_baseline(root)
                self.assertFalse(list(path.parent.glob('*.tmp')))
                with patch('build_graph.subprocess.run', side_effect=[good, good, good, SimpleNamespace(stdout='packages/example/src/pins.rs\npackages/example/src/pins.toml\nvendor/example/data.bin\nREADME.md\n')]):
                    same_path, old, changed = baseline_context(root, registry)
                self.assertEqual(path, same_path)
                self.assertEqual(old['source'], 'ancestor')
                self.assertEqual(changed, ['packages/example/src/pins.rs', 'packages/example/src/pins.toml', 'vendor/example/data.bin'])
                with patch('build_graph.subprocess.run', side_effect=[good, good, SimpleNamespace(returncode=1)]):
                    self.assertIsNone(baseline_context(root, registry)[1])
                (root/'Cargo.toml').write_text('[profile.gate]\nopt-level = 2\n')
                self.assertIsNone(baseline_context(root, registry)[1])
                (root/'.cargo/config.toml').unlink()
                self.assertIsNone(baseline_context(root, registry)[1])
                registry.tiers['fast']['jobs'] = 4
                self.assertIsNone(baseline_context(root, registry)[1])
        # Two commits with identical trees model re-signing without using a key.
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git = lambda *args, **kw: subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                text=True, check=True, **kw).stdout.strip()
            git('init', '-q')
            git('config', 'user.name', 'Fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (root/'Cargo.toml').write_text('[profile.gate]\nopt-level = 1\n')
            git('add', 'Cargo.toml')
            tree = git('write-tree')
            original = git('-c', 'commit.gpgsign=false', 'commit-tree', tree, input='gate source\n')
            imported = git('-c', 'commit.gpgsign=false', 'commit-tree', tree, input='imported metadata\n')
            current = git('-c', 'commit.gpgsign=false', 'commit-tree', tree, '-p', imported, input='next import\n')
            self.assertNotEqual(original, imported)
            self.assertNotEqual(subprocess.run(['git', '-C', str(root), 'merge-base', '--is-ancestor', original, current]).returncode, 0)
            (root/'.lane').mkdir()
            (root/'.lane/performance-events.jsonl').write_text('')
            (root/'.lane/harness-benchmarks.jsonl').write_text('')
            (root/'.lane/claim-evidence.json').write_text('{"obligations":[]}')
            with patch.dict(os.environ, CARGO_TARGET_DIR=directory, PN_GATE_SOURCE=current, PN_IMPORT_BASE=imported, PN_GATE_LINEAGE='main'):
                path, _, _ = baseline_context(root, registry)
                (root/'.lane/gate-baseline.json').write_text(json.dumps(dict(path=str(path), source=original, tree=tree, tiers={})))
                retain_baseline(root)
                _, retained, changed = baseline_context(root, registry)
                self.assertEqual(retained['source'], original)
                self.assertEqual(retained['match'], 'import-base-tree')
                self.assertEqual(changed, [])
                (root/'Cargo.toml').write_text('[profile.gate]\nopt-level = 1\n# Unimported candidate\n')
                git('add', 'Cargo.toml')
                other_tree = git('write-tree')
                other = git('-c', 'commit.gpgsign=false', 'commit-tree', other_tree, '-p', imported, input='unimported candidate\n')
                with patch.dict(os.environ, PN_GATE_SOURCE=other):
                    other_path, _, _ = baseline_context(root, registry)
                    (root/'.lane/gate-baseline.json').write_text(json.dumps(dict(path=str(other_path), source=other, tree=other_tree, tiers={})))
                    retain_baseline(root)
                self.assertNotEqual(path, other_path)
                self.assertTrue(path.exists())
                self.assertEqual(baseline_context(root, registry)[1]['source'], original)
                other_path.unlink()
                with patch.dict(os.environ, PN_IMPORT_BASE=other):
                    self.assertIsNone(baseline_context(root, registry)[1], 'a mismatched tree must refuse the comparison')
                with patch.dict(os.environ, PN_GATE_LINEAGE='lane:fixture'):
                    self.assertIsNone(baseline_context(root, registry)[1])

    def test_noisy_clock(self):
        """The reporter contract keeps injected noisy evidence inconclusive without changing a predicate or hiding an excess.
        ´claim:devperf:noisy-clock-is-nonverdict´
        ´test:integration:test-noisy-clock´
        """
        for outcome in ['passed', 'failed']:
            record = {**execution(1000, outcome), 'clock_quality': 'noisy', 'baseline_ms': 1}
            original = copy.deepcopy(record)
            self.assertEqual(assessment(record)['reason'], 'noisy-clock')
            self.assertEqual([f['kind'] for f in assess(record, declarations())], ['budget-excess'])
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'findings.jsonl'
                self.assertEqual(report([record], declarations(), path, io.StringIO()), 0)
                evidence = json.loads(path.with_name('performance-assessments.jsonl').read_text())
                self.assertEqual(evidence['assessment'], 'inconclusive')
                self.assertNotIn('assessment', json.loads(path.read_text()))
            self.assertEqual(record, original)

    def test_cold_cache(self):
        """The reporter contract keeps injected cold/warm comparisons inconclusive while their excess remains visible.
        ´claim:devperf:cold-cache-is-nonverdict´
        ´test:integration:test-cold-cache´
        """
        for outcome in ['passed', 'failed']:
            record = {**execution(1000, outcome), 'baseline_ms': 1, 'cache_state': 'cold', 'baseline_cache': 'warm'}
            self.assertEqual(assessment(record)['reason'], 'incompatible-cache')
            self.assertEqual(assess(record, declarations())[0]['outcome'], outcome)

    def test_overlapping_spans(self):
        """Inclusive suite timing never sums overlapping work, preventing inflated budget findings.
        ´claim:devperf:overlap-is-not-summed´
        ´test:integration:test-overlapping-spans´
        """
        self.assertEqual(inclusive_ms([(0, 10), (5, 15)]), 15)
        self.assertEqual(inclusive_ms([(0, 5), (10, 15)]), 15)
        self.assertIsNone(inclusive_ms([]))
        for outcome in ['passed', 'failed']:
            record = execution(inclusive_ms([(0, 100), (50, 150)]), outcome)
            with tempfile.TemporaryDirectory() as directory:
                self.assertEqual(report([record], declarations(), Path(directory)/'findings.jsonl', io.StringIO()), 0)
            self.assertEqual(record['outcome'], outcome)
        with self.assertRaises(StructuralError):
            inclusive_ms([(2, 1)])

    def test_admitted_budget(self):
        """Admission changes only the warning threshold; an excess still preserves a failing predicate.
        ´claim:devperf:admission-is-nonverdict´
        ´test:integration:test-admitted-budget´
        """
        admission = dict(name='probe', status='admitted', ordinary_budget='unit', budget_ms=200,
                         label='expt:fixture:probe', owner='fixture', reason='bounded work',
                         measurement='injected milliseconds', placement='fixture', settlement='fixture admission')
        self.assertEqual(assess(execution(150), declarations(), [admission]), [])
        finding, = assess(execution(201, 'failed'), declarations(), [admission])
        self.assertEqual((finding['budget_ms'], finding['outcome'], finding['verdict_effect']), (200, 'failed', 'none'))
        admission['status'] = 'candidate'
        self.assertEqual(assess(execution(150), declarations(), [admission])[0]['budget_ms'], 100)

    def test_budget_category(self):
        """Declared categories keep build/aggregate configuration findings distinct from case/suite performance findings.
        ´claim:devperf:category-controls-classification´
        ´test:integration:test-budget-category´
        """
        for category in ['build', 'aggregate']:
            finding, = assess(execution(101), {'unit': {'budget_ms': 100, 'category': category}})
            self.assertEqual(finding['classification'], 'build-or-aggregate-misconfiguration')
        for category in ['case', 'suite']:
            finding, = assess(execution(101), {'unit': {'budget_ms': 100, 'category': category}})
            self.assertEqual(finding['classification'], 'performance')
        for classification in ('high-stall', 'rebuild', 'plain', 'growth', 'unclassified'):
            finding, = assess(dict(execution(101), operation='tier::fast', overrun_class=classification),
                {'unit': {'budget_ms': 100, 'category': 'aggregate'}})
            self.assertEqual(finding['classification'], classification)

    def test_version_mismatch(self):
        """An unreviewed stream version is refused before tests, preventing silent schema drift.
        ´claim:devperf:exact-runner-version´
        ´test:integration:test-version-mismatch´
        """
        with tempfile.TemporaryDirectory() as directory:
            original = Path.cwd()
            try:
                os.chdir(directory)
                def execute(argv, stdout, stderr, env=None):
                    self.assertEqual(argv, ['cargo', 'nextest', '--version'])
                    stdout.write('cargo-nextest 0.9.150')
                    return SimpleNamespace(returncode=0)
                with patch('run_tests.subprocess.check_output', return_value='fixture'), patch('run_tests.load_registry', return_value=fixture()), patch('run_tests.invoke', side_effect=execute) as invoked:
                    self.assertEqual(run_tests.main(), 2)
                    self.assertEqual(invoked.call_count, 1)
            finally:
                os.chdir(original)

    def test_predicates(self):
        """Fast and slow passing and failing results retain their predicates.
        ´claim:devperf:timing-preserves-predicates´
        ´test:integration:test-predicates´
        """
        for outcome in ['passed', 'failed']:
            for duration in [0, 1, 100, 101, 100000]:
                record = execution(duration, outcome)
                original = copy.deepcopy(record)
                findings = assess(record, declarations())
                self.assertEqual(record, original)
                self.assertEqual(len(findings), int(duration > 100))
                for finding in findings:
                    self.assertEqual(finding['outcome'], outcome)
                    self.assertEqual(finding['verdict_effect'], 'none')

    def test_roster(self):
        """Findings preserve input outcomes and order, keeping evidence attributable.
        ´claim:devperf:findings-preserve-outcome-order´
        ´test:integration:test-roster´
        """
        def run(label, outcome):
            return {**execution(1000, outcome), 'operation': label}
        records = [run('first', 'passed'), run('second', 'failed'), run('third', 'passed')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'findings.jsonl'
            warnings = io.StringIO()
            self.assertEqual(report(records, declarations(), path, warnings), 0)
            findings = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([f['outcome'] for f in findings], ['passed', 'failed', 'passed'])
            self.assertEqual(len(warnings.getvalue().splitlines()), 3)

    def test_missing(self):
        """Missing measurements are findings with null duration and baseline.
        ´claim:devperf:missing-measurement-is-explicit´
        ´test:integration:test-missing´
        """
        finding, = assess(execution(None), declarations())
        self.assertEqual(finding['kind'], 'missing-measurement')
        self.assertIsNone(finding['duration_ms'])
        self.assertIsNone(finding['baseline_ms'])
        record = execution()
        del record['duration_ms']
        self.assertEqual(assess(record, declarations())[0]['kind'], 'missing-measurement')

    def test_structural(self):
        """Missing and malformed declarations differ from an exceeded budget.
        ´claim:devperf:structural-errors-distinct´
        ´test:integration:test-structural´
        """
        for record in [{}, {**execution(), 'budget': 'absent'}, {**execution(), 'owner': ''},
                       execution(-1), execution(float('nan')), execution(True)]:
            with self.assertRaises(StructuralError):
                assess(record, declarations())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'budgets.toml'
            for source in ['', '[[rows]]\nname="unit"\nbudget_ms=-1\n']:
                path.write_text(source)
                with self.assertRaises(StructuralError):
                    budgets(path)
        self.assertEqual(assess(execution(101), declarations())[0]['kind'], 'budget-excess')
        from devperf import calibration_declarations
        source = tomllib.loads((Path(__file__).parents[1]/'docs/inputs/devperf-budgets.toml').read_text())
        declared = {row['name']:row for row in source['rows']}
        calibration_declarations(declared)
        name = next(name for name, row in declared.items() if row.get('calibration_campaign'))
        for changes in ({'calibration_campaign':'campaign:missing:campaign'}, {'budget_ms':1},
                        {'calibration_warm':False}, {'calibration_selected_sample':0},
                        {'calibration_walls_ms':[1]}, {'calibration_pending_owner':''}):
            broken = copy.deepcopy(declared)
            broken[name].update(changes)
            with self.subTest(changes=changes), self.assertRaises(StructuralError):
                calibration_declarations(broken)
        pending = copy.deepcopy(declared)
        pending[name].pop('calibration_campaign')
        pending[name]['calibration_pending_owner'] = 'fixture-owner'
        calibration_declarations(pending)
        broken = copy.deepcopy(declared)
        broken['gate']['calibration_campaigns'][0].pop('measured_series')
        with self.assertRaises(StructuralError):
            calibration_declarations(broken)


    def test_utc(self):
        """Naive and offset instants are refused without assigning a zone.
        ´claim:devperf:utc-is-explicit´
        ´test:integration:test-utc´
        """
        self.assertEqual(utc('2026-10-22T12:30:00.123Z'), '2026-10-22T12:30:00.123Z')
        for value in ['2026-10-22T12:30:00', '2026-10-22T12:30:00+00:00', 'badZ']:
            with self.assertRaises(StructuralError):
                utc(value)

    def test_runner_policy(self):
        """Runner execution and original failure status do not depend on durations.
        ´claim:devperf:runner-policy-is-nonverdict´
        ´test:integration:test-runner-policy´
        """
        config = (Path(__file__).parent / 'nextest.toml').read_text()
        policy = tomllib.loads(config)['profile']['default']
        self.assertEqual(policy['retries'], 0)
        self.assertFalse(policy['fail-fast'])
        self.assertNotIn('terminate-after', policy['slow-timeout'])
        self.assertNotIn('global-timeout', policy)
        inventory, metadata = inventory_fixture()
        for outcome in [0, 100]:
            for duration in [0.001, 10000]:
                with self.subTest(outcome=outcome, duration=duration), tempfile.TemporaryDirectory() as directory:
                    calls = []
                    def execute(argv, stdout, stderr, env=None):
                        calls.append(argv)
                        self.assertEqual(env['CARGO_NET_OFFLINE'], 'true')
                        if argv[1] == 'metadata':
                            stdout.write(json.dumps(metadata))
                        elif argv[1:] == ['nextest', '--version']:
                            stdout.write('cargo-nextest 0.9.149')
                        elif argv[1:3] == ['nextest', 'list']:
                            stdout.write(json.dumps(inventory))
                        elif argv[1:3] == ['nextest', 'run']:
                            stdout.write(json.dumps({'type': 'test', 'event': 'failed' if outcome else 'ok',
                                                     'name': 'example::example$case', 'exec_time': duration,
                                                     'stdout': 'synthetic captured text'}))
                            return SimpleNamespace(returncode=outcome)
                        return SimpleNamespace(returncode=0)
                    original = Path.cwd()
                    try:
                        os.chdir(directory)
                        Path('ci').mkdir()
                        Path('ci/nextest.toml').write_text(config)
                        with patch('run_tests.subprocess.check_output', return_value='fixture'), patch('run_tests.load_registry', return_value=fixture()), patch('run_tests.invoke', side_effect=execute):
                            self.assertEqual(run_tests.main(), outcome)
                        self.assertEqual(len(calls), 6)
                        self.assertIn('binaries-only', calls[2])
                        self.assertIn('--binaries-metadata', calls[3])
                        nextest = calls[4]
                        self.assertEqual(nextest[nextest.index('--retries') + 1], '0')
                        self.assertIn('--no-fail-fast', nextest)
                        self.assertNotIn('--locked', nextest)
                        self.assertNotIn('--offline', nextest)
                        self.assertIn('--doc', calls[5])
                        records = [json.loads(line) for line in Path('.lane/performance-events.jsonl').read_text().splitlines()]
                        case, = [r for r in records if r['operation'] == 'example::case']
                        self.assertEqual(case['duration_ms'], duration * 1000)
                        self.assertEqual(case['outcome'], 'failed' if outcome else 'passed')
                        self.assertNotIn('stdout', case)
                    finally:
                        os.chdir(original)

    def test_result_accounting(self):
        """A missing case remains incomplete and unknown results are structural errors.
        ´claim:devperf:result-accounting-is-explicit´
        ´test:integration:test-result-accounting´
        """
        inventory, metadata = inventory_fixture('test', 'tests/example.rs')
        record, = run_tests.nextest_events('', inventory, metadata, 'fixture', 'test', fixture(level='integration'))
        self.assertEqual(record['outcome'], 'incomplete')
        self.assertIsNone(record['duration_ms'])
        self.assertEqual(record['budget'], 'integration')
        raw = json.dumps({'type': 'test', 'name': 'unknown', 'event': 'ok'})
        with self.assertRaises(StructuralError):
            run_tests.nextest_events(raw, inventory, metadata, 'fixture', 'test', fixture(level='integration'))

    def test_raw_duration(self):
        """Invalid raw durations cannot become valid normalized measurements.
        ´claim:devperf:raw-duration-validation´
        ´test:integration:test-raw-duration´
        """
        for value in [True, -1, float('inf'), '1']:
            with self.assertRaises(StructuralError):
                run_tests.milliseconds(value)
        self.assertIsNone(run_tests.milliseconds(None))
        self.assertEqual(run_tests.milliseconds(0.125), 125)


if __name__ == '__main__':
    unittest.main()
