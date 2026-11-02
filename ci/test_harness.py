"""Claim area harness: declarations bound the evidence a passing matrix can claim."""

import copy
import unittest

from devperf import StructuralError
from harness import CONFIGURATION, Registry, passing_editions


def declarations():
    return {name: {'budget_ms': value, 'category': category} for name, value, category in
            [('unit', 100, 'case'), ('crate', 500, 'case'), ('integration', 2000, 'case'), ('pure-suite', 5000, 'suite'), ('mock-suite', 10000, 'suite')]}


def rows(runner='nextest', case='example::case', level='unit'):
    return [*[dict(kind='level', name=name, budget=budget) for name, budget in
               [('unit', 'unit'), ('public-surface', 'crate'), ('integration', 'integration'), ('doctest', 'crate')]],
            dict(kind='implementation', name='example', evidence='pure'),
            dict(kind='tier', name='fast', status='active'),
            dict(kind='tier', name='service', status='held', reason='worker unavailable'),
            dict(kind='suite', name='example', level=level, implementation='example', tier='fast',
                 status='active', runner=runner, budget='pure-suite', cases=[case])]


def fixture(runner='nextest', case='example::case', level='unit'):
    return Registry(rows(runner, case, level), declarations())


def result(registry):
    return registry.join(dict(operation=next(iter(registry.cases)), outcome='passed', duration_ms=1,
                              source='current', configuration=CONFIGURATION, owner='fixture'), 'current')


class Harness(unittest.TestCase):
    def calibration_cpu(self):
        import json
        import os
        from pathlib import Path
        import sys
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        from calibrate import case_runner, case_cpu, join_cpu, comparison, USAGE_FIELDS
        import tomllib
        inputs = tomllib.loads((Path(__file__).resolve().parent.parent/'docs/inputs/numbers.toml').read_text())['rows']
        values = {row['id']: row['value'] for row in inputs}
        def pin(name):
            return int(values['num:numbers:calibration-fixture-'+name])
        events = pin('resource-events')
        before = (pin('user-before-seconds'), pin('system-before-seconds'), *([0]*len(USAGE_FIELDS[2:])))
        after = (pin('user-after-seconds'), pin('system-after-seconds'), *([events]*len(USAGE_FIELDS[2:])))
        delta = (pin('user-delta-seconds'), pin('system-delta-seconds'))
        self.assertEqual(case_cpu(before, after), dict(own_user_s=delta[0], own_sys_s=delta[1],
                         **{key:events for key in USAGE_FIELDS[2:]},
                         cpu_scope='case-process-and-reaped-descendants'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for status in (0, pin('refusal-status')):
                env = dict(PN_CALIBRATION_CASE_CPU=directory, PN_HARNESS_SOURCE='current',
                           NEXTEST_BINARY_ID='example', NEXTEST_TEST_NAME='case')
                usage = [SimpleNamespace(**dict(zip(USAGE_FIELDS, values))) for values in (before, after)]
                with patch.dict(os.environ, env), patch('calibrate.resource.getrusage', side_effect=usage):
                    self.assertEqual(case_runner([sys.executable, '-c', f'raise SystemExit({status})']), status)
                record = dict(operation='example::case', outcome='passed' if status == 0 else 'failed', duration_ms=0)
                join_cpu([record], path, 'current')
                self.assertEqual((record['own_user_s'], record['own_sys_s']), delta)
                self.assertTrue(all(record[key] == events for key in USAGE_FIELDS[2:]))
                self.assertGreaterEqual(record['duration_ms'], 0)
                with self.assertRaisesRegex(StructuralError, 'identity'):
                    join_cpu([record], path, 'other')
                original, = path.glob('*.json')
                duplicate = path/'duplicate.json'
                duplicate.write_text(original.read_text())
                with self.assertRaisesRegex(StructuralError, 'union'):
                    join_cpu([record], path, 'current')
                duplicate.unlink()
                value = json.loads(original.read_text());value['own_user_s'] = -1
                original.write_text(json.dumps(value))
                with self.assertRaisesRegex(StructuralError, 'negative'):
                    join_cpu([record], path, 'current')
                original.unlink()
                with self.assertRaisesRegex(StructuralError, 'union'):
                    join_cpu([record], path, 'current')
        record = dict(operation='pn-epoch::solve::fixture', scope='case')
        before, after = [dict(source=source, records=[record]) for source in ('before', 'after')]
        for paths, changed in ((['packages/epoch/tests/common/joined.rs'], True),
                               (['packages/graph/src/numeric.rs'], True),
                               (['packages/documents/src/pins.rs'], True),
                               (['docs/inputs/numbers.toml'], True), (['README.md'], False)):
            result = comparison(before, after, paths)
            self.assertEqual(result['source_range'], 'before..after')
            self.assertEqual(result['cases'][0]['code_changed'], changed)

    def test_wallet_commit_isolation(self):
        """Claim: Wallet conformance reads a clean checkout of its source commit even when its parent is dirty before cloning and changes during execution; identical committed inputs yield identical result artifacts, each published by atomic replacement to a distinct step-owned path without modifying shared findings.
        ´claim:harness:wallet-inputs-are-commit-scoped´
        ´test:integration:test-wallet-commit-isolation´
        """
        self.commit_isolation(False)

    def test_host_commit_isolation(self):
        """Claim: Host observation uses a clean checkout of its source commit, its own target and service root, and atomic owned artifacts even while a tracked parent file changes; clean and moving parents produce identical evidence.
        ´claim:harness:host-inputs-are-commit-scoped´
        ´test:integration:test-host-commit-isolation´
        """
        self.commit_isolation(True)

    def commit_isolation(self, host):
        import json
        import os
        from pathlib import Path
        import socket
        import subprocess
        import tempfile
        import threading
        import time
        from unittest.mock import patch
        from run_ci import isolated_wallet, isolated_host
        operation = isolated_host if host else isolated_wallet
        module = "test_host_runtime" if host else "test_wallet_boundary"
        name = "host-observation-runtime" if host else "wallet-conformance"
        compile_log = "host-statement-compile-fail.log" if host else "wallet-rpc-compile-fail.log"
        driver = '''import json, os, pathlib, socket
root = pathlib.Path.cwd()
assert (root/'payload').read_text() == 'committed'
assert os.environ['PN_IMPORT_BASE'] == os.environ['PN_GATE_SOURCE']
assert not (root/'.git/objects/info/alternates').exists()
assert pathlib.Path(os.environ['PN_FLAKE_LEDGER']).parent == pathlib.Path(os.environ['CARGO_TARGET_DIR'])
pathlib.Path(os.environ['CARGO_TARGET_DIR']).joinpath('retained').write_text('owned cache')
with socket.socket(socket.AF_UNIX) as connection:
    connection.settimeout(30)
    connection.connect(os.environ['WALLET_WITNESS_SOCKET'])
    connection.sendall(b'ready')
    assert connection.recv(1) == b'R'
assert (root/'payload').read_text() == 'committed'
(root/'.lane/harness-ci-test_wallet_boundary.jsonl').write_text(json.dumps({'operation':'fixture::wallet', 'source':os.environ['PN_GATE_SOURCE'], 'outcome':'passed'})+'\\n')
(root/'.lane/wallet-rpc-compile-fail.log').write_text('expected compile refusal\\n')
(root/'.lane/performance-findings.jsonl').write_text('fixture finding\\n')
'''
        driver = driver.replace('test_wallet_boundary', module).replace('wallet-rpc-compile-fail.log', compile_log)
        if host:
            driver += "assert pathlib.Path(os.environ['PN_HOST_TEST_ROOT']).parent == root/'.lane'\n"
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'ci').mkdir()
            (root/'ci/run_ci.py').write_text(driver)
            (root/'payload').write_text('committed')
            (root/'.gitignore').write_text('.lane/\n')
            def git(*args):
                started = time.monotonic()
                result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, check=True)
                print(f'WALLET-WITNESS tool=git wall={time.monotonic()-started:.6f}s status={result.returncode}')
                return result.stdout.strip()
            git('init', '--quiet')
            git('add', '.')
            git('-c', 'commit.gpgsign=false', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'fixture')
            source = git('rev-parse', 'HEAD')
            from isolation import import_base
            git('update-ref', 'refs/import/base', source)
            self.assertEqual(import_base(root, source, 'refs/import/base'), source)
            self.assertEqual(import_base(root, source, source), source)
            with self.assertRaisesRegex(ValueError, 'does not resolve to a commit'):
                import_base(root, source, 'refs/import/absent')
            with self.assertRaisesRegex(ValueError, 'does not resolve to a commit'):
                import_base(root, source, source+':payload')
            unrelated = git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit-tree', source+'^{tree}', '-m', 'unrelated')
            with self.assertRaisesRegex(ValueError, 'not an ancestor'):
                import_base(root, source, unrelated)
            lane = root/'.lane'
            lane.mkdir()
            shared = lane/'performance-findings.jsonl'
            shared.write_bytes(b'sibling findings\n')
            names = (f'harness-ci-{module}.jsonl', compile_log, name+'-findings.jsonl')
            snapshots = []
            payload_stamp = None
            try:
                os.chdir(root)
                for moving in (False, True):
                    (root/'payload').write_text('dirty before clone' if moving else 'committed')
                    for name in names:
                        (lane/name).write_bytes(b'previous complete artifact')
                    address = root/'barrier.sock'
                    errors = []
                    with socket.socket(socket.AF_UNIX) as server:
                        server.bind(str(address))
                        server.listen()
                        server.settimeout(30)
                        def mutate():
                            try:
                                with server.accept()[0] as connection:
                                    connection.settimeout(30)
                                    self.assertEqual(connection.recv(5), b'ready')
                                    if moving:
                                        (root/'payload').write_text('changed during wallet execution')
                                    connection.sendall(b'R')
                            except BaseException as error:
                                errors.append(error)
                        worker = threading.Thread(target=mutate)
                        worker.start()
                        replacements = []
                        replace = os.replace
                        def publish(temporary, destination):
                            self.assertEqual(destination.parent, lane)
                            self.assertIn(destination.name, names)
                            self.assertEqual(destination.read_bytes(), b'previous complete artifact')
                            expected = temporary.read_bytes()
                            replace(temporary, destination)
                            self.assertEqual(destination.read_bytes(), expected)
                            replacements.append(destination.name)
                        try:
                            with patch.dict(os.environ, {'PN_GATE_SOURCE':source, 'PN_IMPORT_BASE':'refs/import/base' if moving else source, 'CARGO_TARGET_DIR':str(lane/'target'), 'WALLET_WITNESS_SOCKET':str(address)}), patch('run_ci.os.replace', side_effect=publish):
                                self.assertEqual(operation(module), 0)
                        finally:
                            worker.join(timeout=30)
                        self.assertFalse(worker.is_alive())
                        self.assertEqual(errors, [])
                    address.unlink()
                    self.assertCountEqual(replacements, names)
                    self.assertEqual(list(lane.glob('*.tmp')), [])
                    self.assertEqual(shared.read_bytes(), b'sibling findings\n')
                    self.assertEqual((root/'payload').read_text(), 'changed during wallet execution' if moving else 'committed')
                    snapshots.append({name:(lane/name).read_bytes() for name in names})
                    payload, = (root/'target/i').glob('*/s/payload')
                    if payload_stamp is not None:
                        self.assertEqual(payload.stat().st_mtime_ns, payload_stamp)
                    payload_stamp = payload.stat().st_mtime_ns
                    retained, = (root/'target/i').glob('*/c/*/retained')
                    self.assertEqual(retained.read_text(), 'owned cache')
                self.assertEqual(snapshots[0], snapshots[1])
                from isolation import workspace
                original_target = retained.parent
                owner = 'host-observation-runtime' if host else 'wallet-conformance'
                with workspace(root, owner, unrelated) as (isolated, target):
                    self.assertEqual(target, original_target)
                git('reflog', 'expire', '--expire=now', '--all')
                git('gc', '--prune=now')
                missing = subprocess.run(['git', '-C', str(root), 'cat-file', '-e', unrelated], capture_output=True)
                self.assertNotEqual(missing.returncode, 0)
                present = subprocess.run(['git', '-C', str(isolated), 'cat-file', '-e', unrelated], capture_output=True)
                self.assertEqual(present.returncode, 0)
                with workspace(root, owner, source) as (_, target):
                    self.assertEqual((target/'retained').read_text(), 'owned cache')
                with patch.dict(os.environ, RUSTFLAGS='--cfg isolation_key_witness'):
                    with workspace(root, 'host-observation-runtime' if host else 'wallet-conformance', source) as (_, target):
                        self.assertNotEqual(target, original_target)
                        self.assertFalse((target/'retained').exists())
            finally:
                os.chdir(original)
        print(f'COMMIT-ISOLATION-WITNESS suite={module} clean=passed moving=passed results=identical handback=atomic sibling-findings=unchanged')

    def test_flake_ledger(self):
        """Claim: Required failures retain commit, case, error and node load; a later required execution reports its retry and result, a repeated failure is a recurrence, and a passing slow call remains a finding without becoming a failed test.
        ´claim:harness:flake-ledger-retains-recurrences´
        ´test:integration:test-flake-ledger´
        """
        import io
        import json
        import tempfile
        from contextlib import redirect_stdout
        from pathlib import Path
        from unittest.mock import patch
        from flake_ledger import Session
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()) as output, patch('os.getloadavg', return_value=(1, 2, 3)):
            path = Path(directory)/'ledger.jsonl'
            first = Session('before', path)
            self.assertIsNone(first.begin('fixture::case'))
            first.finish('fixture::case', 'failed', 'socket timeout')
            later = Session('after', path)
            retry = later.begin('fixture::case')
            self.assertEqual((retry['commit'], retry['previous_commit'], retry['case'], retry['error'], retry['node_load']),
                             ('after', 'before', 'fixture::case', 'socket timeout', [1, 2, 3]))
            self.assertEqual(later.finish('fixture::case', 'failed', 'socket timeout')['finding'], 'recurrence')
            passing = Session('fixed', path)
            self.assertIsNotNone(passing.begin('fixture::case'))
            self.assertEqual(passing.finish('fixture::case', 'passed')['outcome'], 'passed')
            self.assertIsNone(Session('next', path).begin('fixture::case'))
            slow = passing.record('slow-success', 'fixture::setup', 'steady bound exceeded', outcome='success', finding='recurrence')
            self.assertEqual(slow['outcome'], 'success')
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([row['event'] for row in records],
                             ['failure', 'retry', 'failure', 'retry', 'retry-result', 'slow-success'])
            self.assertEqual(len(output.getvalue().splitlines()), len(records))

    def ci_case_budget_emission(self):
        import io
        import json
        import os
        from contextlib import chdir, redirect_stderr, redirect_stdout
        from pathlib import Path
        import tempfile
        from unittest.mock import patch
        from build_graph_evidence import SERVICE_CASE
        import run_ci
        for held in (False, True):
            operation = SERVICE_CASE if held else 'ci::fixture.case'
            data = rows(runner='ci', case=operation)
            data[-1].update(name='ci::fixture', case_budgets={operation: 'integration'},
                            case_budget_reasons={operation: 'Retained fixture work.'})
            registry = Registry(data, declarations())
            case = unittest.FunctionTestCase(lambda: None)
            case.id = lambda: operation.removeprefix('ci::')
            suite = unittest.TestSuite([case])
            with tempfile.TemporaryDirectory() as directory, chdir(directory), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                Path('docs/inputs').mkdir(parents=True)
                Path('docs/inputs/devperf-registry.toml').write_text('rows = []\n')
                with patch.dict(os.environ, {'PN_GATE_PARALLEL': '0', 'PN_CALIBRATION': '0', 'PN_FLAKE_LEDGER': str(Path(directory)/'ledger.jsonl')}), patch('run_ci.load', return_value=registry), patch('run_ci.source_id', return_value='current'), patch.object(unittest.defaultTestLoader, 'loadTestsFromName', return_value=suite), patch('run_ci.budgets', return_value=declarations()), patch('run_ci.report'), patch('build_graph_evidence.service_selection', return_value=dict(run=False, hold='rule:buildgraph:service-selection', reason='unchanged', inputs=[])):
                    self.assertEqual(run_ci.main('fixture'), 0)
                record = json.loads(Path('.lane/harness-ci-fixture.jsonl').read_text().splitlines()[0])
                self.assertEqual((record['operation'], record['budget'], record['outcome']),
                                 (operation, 'integration', 'held' if held else 'passed'))

    def calibrated_case_budgets(self):
        self.ci_case_budget_emission()
        data = rows(case='example::fast')
        data[-1]['cases'].append('example::calibrated')
        data[-1]['case_budgets'] = {'example::calibrated': 'integration'}
        data[-1]['case_budget_reasons'] = {'example::calibrated': 'Cold independent Work boundaries.'}
        registry = Registry(data, declarations())
        self.assertEqual(registry.case_budget('example::fast'), 'unit')
        self.assertEqual(registry.case_budget('example::calibrated'), 'integration')
        result = registry.join(dict(operation='example::calibrated', outcome='passed'), 'current')
        self.assertEqual((result['tier'], result['level'], result['implementation']), ('fast', 'unit', 'example'))
        with self.assertRaisesRegex(StructuralError, 'budget'):
            registry.join(dict(result, budget='unit'), 'current')
        for mutation in ('missing-cost', 'empty-cost', 'unknown-case', 'category', 'unknown-budget', 'tier-policy'):
            invalid = copy.deepcopy(data)
            suite = invalid[-1]
            if mutation == 'missing-cost':
                suite['case_budget_reasons'] = {}
            elif mutation == 'empty-cost':
                suite['case_budget_reasons']['example::calibrated'] = ' '
            elif mutation == 'unknown-case':
                suite['case_budgets']['example::absent'] = 'integration'
                suite['case_budget_reasons']['example::absent'] = 'Absent case.'
            elif mutation == 'category':
                suite['case_budgets']['example::calibrated'] = 'pure-suite'
            elif mutation == 'unknown-budget':
                suite['case_budgets']['example::calibrated'] = 'absent'
            else:
                next(row for row in invalid if row.get('kind') == 'tier')['case_budget_policy'] = 'declared-suite'
                next(row for row in invalid if row.get('kind') == 'tier')['reason'] = 'Dedicated fixture.'
                suite['case_budget'] = 'integration'
            with self.assertRaises(StructuralError):
                Registry(invalid, declarations())

    def test_reference_tier(self):
        """Claim: Explicit reference-tier groups retain case identity, level, implementation and outcome while applying declared case budgets. Unchanged cases retain their level budgets; independently declared case allowances require an exact case and named cost, preserve the tier, level and implementation, and cannot override a tier-declared suite budget. Absent policies, invalid budgets, changed result budgets and missing or duplicate grouped completions refuse. Interleaved case arrivals bound each group's own wall envelope. Calibration joins each measured nextest case's CPU and wall to its source and outcome, refuses missing, duplicate, negative or stale CPU evidence, and names the source range and conservative code-change flags in comparisons.
        ´claim:harness:reference-tier-retains-required-case-evidence´
        ´test:integration:test-reference-tier´
        """
        from run_tests import nextest_events, suite_events
        data = rows(case='example::fast')
        data[-1]['case_span'] = True
        slow = dict(data[-1], name='reference', tier='reference',
                    case_budget='integration', cases=['example::slow'])
        policy = dict(kind='tier', name='reference', status='active',
                      case_budget_policy='declared-suite', reason='Exact reference fixture.')
        data.extend([policy, slow])
        registry = Registry(data, declarations())
        self.assertEqual(registry.case_budget('example::fast'), 'unit')
        self.assertEqual(registry.case_budget('example::slow'), 'integration')
        joined = registry.join(dict(operation='example::slow', outcome='passed'), 'current')
        self.assertEqual((joined['level'], joined['implementation'], joined['tier'], joined['outcome']),
                         ('unit', 'example', 'reference', 'passed'))
        with self.assertRaisesRegex(StructuralError, 'budget'):
            registry.join(dict(joined, budget='unit'), 'current')
        for mutation in ('policy', 'missing', 'category'):
            invalid = copy.deepcopy(data)
            if mutation == 'policy':
                del invalid[-2]['case_budget_policy']
            elif mutation == 'missing':
                del invalid[-1]['case_budget']
            else:
                invalid[-1]['case_budget'] = 'pure-suite'
            with self.assertRaises(StructuralError):
                Registry(invalid, declarations())
        inventory = {'rust-suites': {'example': {'package-name': 'example',
                     'binary-name': 'example', 'kind': 'lib',
                     'testcases': {'fast': {'ignored': False}, 'slow': {'ignored': False}}}}}
        from calibrate import selection, complete, alone, owning_package
        self.assertEqual(owning_package('example::slow', 'different-rust', inventory,
                                        {'example': {}, 'different': {}}), 'example')
        self.assertEqual(selection(inventory, {'example::slow'}),
                         '(binary_id(=example) & test(=slow))')
        with self.assertRaisesRegex(StructuralError, 'selection'):
            selection(inventory, {'example::absent'})
        calibrated = [registry.join(dict(operation=case, outcome='passed'), 'current')
                      for case in ('example::fast', 'example::slow')]
        self.assertEqual(complete(registry, calibrated), 0)
        self.assertIsNone(alone([dict(name='a', start=1, end=2), dict(name='b', start=2, end=3)]))
        for second in (dict(name='b', start=1, end=3), dict(name='a', start=2, end=3),
                       dict(name='b', start=3, end=2)):
            with self.assertRaisesRegex(StructuralError, 'calibration suites'):
                alone([dict(name='a', start=1, end=2), second])
        for invalid in (calibrated[:1], calibrated+calibrated[:1],
                        [dict(calibrated[0], outcome='held'), calibrated[1]]):
            with self.assertRaises(StructuralError):
                complete(registry, invalid)
        self.calibration_cpu()
        self.calibrated_case_budgets()
        thresholds = declarations()
        start = thresholds['unit']['budget_ms']
        fast_end = thresholds['crate']['budget_ms']
        slow_end = thresholds['integration']['budget_ms']
        def observation(case, event, offset):
            return dict(offset_ms=offset, item=dict(type='test', event=event,
                        name=f'example::example${case}', exec_time=(offset-start)/1000))
        observations = [observation('fast', 'started', start),
                        observation('slow', 'started', start),
                        observation('fast', 'ok', fast_end),
                        observation('slow', 'ok', slow_end)]
        import json
        records = nextest_events('\n'.join(json.dumps(row['item']) for row in observations),
                                 inventory, {}, 'current', CONFIGURATION, registry)
        self.assertEqual({r['operation']: r['budget'] for r in records},
                         {'example::fast': 'unit', 'example::slow': 'integration'})
        # Separate invocations preserve the union and reject a foreign result.
        tier_records = []
        for selected in ({'example::fast'}, {'example::slow'}):
            subset = [row for row in observations if 'example::'+row['item']['name'].split('$')[1] in selected]
            stream = '\n'.join(json.dumps(row['item']) for row in subset)
            tier_records += nextest_events(stream, inventory, {}, 'current', CONFIGURATION, registry, selected)
            measured = suite_events(subset, inventory, registry, 'current', 'nextest', selected)
            self.assertEqual(len(measured), 1)
            with self.assertRaisesRegex(StructuralError, 'unknown test result'):
                nextest_events('\n'.join(json.dumps(row['item']) for row in observations),
                               inventory, {}, 'current', CONFIGURATION, registry, selected)
        registry.roster('nextest', [row['operation'] for row in tier_records])
        self.assertEqual(sorted(({k:v for k,v in row.items() if k != 'utc'} for row in tier_records), key=lambda row: row['operation']),
                         sorted(({k:v for k,v in row.items() if k != 'utc'} for row in records), key=lambda row: row['operation']))
        for invalid in (tier_records[:-1], tier_records+tier_records[:1]):
            with self.assertRaisesRegex(StructuralError, 'inventory differs'):
                registry.roster('nextest', [row['operation'] for row in invalid])
        spans = suite_events(observations, inventory, registry, 'current', 'nextest')
        self.assertEqual({r['suite']: r['duration_ms'] for r in spans},
                         {'example': fast_end-start, 'reference': slow_end-start})
        self.assertTrue(all(row['status']=='passed' for row in registry.matrix(records+spans, 'current')
                            if row['suite'] is not None))
        for invalid in (observations[:-1], observations+[observations[-1]]):
            with self.assertRaises(StructuralError):
                suite_events(invalid, inventory, registry, 'current', 'nextest')

    def test_case_level_declaration(self):
        """Claim: An explicit integration case retains its binary suite and implementation while receiving the integration budget; undeclared case identities, absent levels and missing premises cannot create overrides.
        ´claim:harness:case-levels-are-explicit-within-binaries´
        ´test:integration:test-case-level-declaration´
        """
        data=rows()
        data[-1]['case_levels']={'example::case':'integration'}
        data[-1]['case_level_reasons']={'example::case':'The fixture composes local components.'}
        registry=Registry(data,declarations())
        joined=registry.join(dict(operation='example::case',outcome='passed',duration_ms=1),'current')
        self.assertEqual((joined['suite'],joined['implementation'],joined['level'],joined['budget']),('example','example','integration','integration'))
        for mutation in ('identity','level','premise'):
            invalid=copy.deepcopy(data)
            if mutation=='identity':invalid[-1]['case_levels']['unknown']='unit'
            elif mutation=='level':invalid[-1]['case_levels']['example::case']='absent'
            else:invalid[-1]['case_level_reasons']={}
            with self.assertRaises(StructuralError):Registry(invalid,declarations())

    def test_interchange_manifest(self):
        """Claim: The current shared interchange library has no feature or binary branch and no unreviewed production dependency; its source-bound Value enum remains exhaustive, keeping one declared public configuration.
        ´claim:harness:interchange-structure-is-declared´
        ´test:integration:test-interchange-manifest´
        """
        import json
        import tomllib
        from pathlib import Path
        root=Path(__file__).resolve().parents[1]
        manifest=tomllib.loads((root/'packages/interchange/Cargo.toml').read_text())
        self.assertEqual(manifest['package']['name'],'pn-interchange')
        self.assertFalse(manifest.get('features'))
        self.assertFalse(manifest.get('bin'))
        self.assertTrue((root/'packages/interchange/src/lib.rs').is_file())
        self.assertNotRegex((root/'packages/interchange/src/lib.rs').read_text(), r'\bno_std\b')
        self.assertFalse((root/'packages/interchange/src/main.rs').exists())
        self.assertEqual(set(manifest['dependencies']),{'regexml','thiserror','tracing','secrecy'})
        self.assertTrue(manifest['lints']['workspace'])
        self.assertNotIn('rust-version',manifest['package'])
        register=json.loads((root/'ci/observation-registry.json').read_text())
        declaration,=[row for row in register['reviewed_types'] if row['package']=='pn-interchange' and row['item']=='value::Value']
        self.assertIn('pub enum Value',declaration['syntax'])
        self.assertNotIn('non_exhaustive',declaration['syntax'])
        # The observation gate separately refuses a stale type declaration.

    def test_nextest_suite_span(self):
        """Interleaved suite arrivals retain their own envelope, never summed case work.
        ´claim:harness:nextest-suite-arrival-envelope´
        ´test:integration:test-nextest-suite-span´
        """
        from run_tests import suite_events
        registry = fixture()
        inventory = {'rust-suites': {'example': {'package-name': 'example',
                     'binary-name': 'example', 'kind': 'lib'}}}
        meta = dict(crate='example', test_binary='example', kind='lib')
        for outcome in ['ok', 'failed']:
            observations = [dict(offset_ms=10, item=dict(type='suite', event='started', nextest=meta)),
                            dict(offset_ms=20, item=dict(type='test', event='ok', name='other', exec_time=9)),
                            dict(offset_ms=30, item=dict(type='suite', event=outcome, exec_time=15, nextest=meta))]
            record, = suite_events(observations, inventory, registry, 'current', 'nextest')
            self.assertEqual(record['duration_ms'], 20)
            self.assertEqual(record['outcome'], 'passed' if outcome == 'ok' else 'failed')

    def test_missing_level(self):
        """A missing level is structural, preventing an undeclared scope from borrowing evidence.
        ´claim:harness:missing-level-refused´
        ´test:integration:test-missing-level´
        """
        declared = rows()
        del declared[-1]['level']
        with self.assertRaisesRegex(StructuralError, 'missing level'):
            Registry(declared, declarations())

    def test_unregistered_implementation(self):
        """An unknown implementation cannot supply evidence under an admitted identity.
        ´claim:harness:unregistered-implementation-refused´
        ´test:integration:test-unregistered-implementation´
        """
        declared = rows()
        declared[-1]['implementation'] = 'unknown'
        with self.assertRaisesRegex(StructuralError, 'unregistered implementation'):
            Registry(declared, declarations())

    def test_dropped_case(self):
        """Both inventory and result joins refuse a missing case, preserving the whole suite contract.
        ´claim:harness:dropped-case-refused´
        ´test:integration:test-dropped-case´
        """
        registry = fixture()
        with self.assertRaisesRegex(StructuralError, 'inventory differs'):
            registry.roster('nextest', [])
        with self.assertRaisesRegex(StructuralError, 'dropped'):
            registry.matrix([], 'current')

    def test_ignored_case(self):
        """An ignored required case cannot make its suite pass without executing its predicate.
        ´claim:harness:ignored-case-refused´
        ´test:integration:test-ignored-case´
        """
        registry = fixture()
        record = result(registry)
        record['outcome'] = 'ignored'
        with self.assertRaisesRegex(StructuralError, 'ignored'):
            registry.matrix([record], 'current')

    def test_mock_as_real(self):
        """Mock evidence cannot be relabelled as real service evidence and discharge its hold.
        ´claim:harness:mock-is-not-real´
        ´test:integration:test-mock-as-real´
        """
        declared = rows()
        declared[4]['evidence'] = 'mock'
        declared[-1]['budget'] = 'mock-suite'
        registry = Registry(declared, declarations())
        record = result(registry)
        record['evidence'] = 'real'
        with self.assertRaisesRegex(StructuralError, 'misreported evidence'):
            registry.matrix([record], 'current')

    def test_stale_source(self):
        """A result for another source cannot certify the current tree.
        ´claim:harness:stale-source-refused´
        ´test:integration:test-stale-source´
        """
        registry = fixture()
        record = result(registry)
        with self.assertRaisesRegex(StructuralError, 'misreported source'):
            registry.matrix([record], 'new-source')
        changed = copy.deepcopy(record)
        changed['configuration'] = 'different-features'
        with self.assertRaisesRegex(StructuralError, 'misreported configuration'):
            registry.matrix([changed], 'current')
        suite = registry.suite_event('example', None, 'passed', 'old-source')
        with self.assertRaisesRegex(StructuralError, 'misreported source'):
            registry.matrix([record, suite], 'current')

    def test_service_hold(self):
        """An unavailable service tier remains visibly held even when all fast cases pass.
        ´claim:harness:service-hold-visible´
        ´test:integration:test-service-hold´
        """
        registry = fixture()
        registry.suites['example']['contract_edition'] = 'example-contract'
        matrix = registry.matrix([result(registry)], 'current')
        self.assertEqual([r['status'] for r in matrix], ['passed', 'held'])
        self.assertIsNone(matrix[-1]['implementation'])
        self.assertEqual(matrix[0]['contract_edition'], 'example-contract')
        self.assertIsNone(matrix[-1]['contract_edition'])
        self.assertEqual(passing_editions(matrix), {'example-contract': {matrix[0]['implementation']: 1}})
        companion = dict(matrix[0], implementation='independent-implementation')
        self.assertEqual(passing_editions([*matrix, companion, matrix[0]]),
                         {'example-contract': {matrix[0]['implementation']: 2, 'independent-implementation': 1}})
        companion['implementation'] = None
        with self.assertRaisesRegex(StructuralError, 'lacks implementation'):
            passing_editions([companion])

    def test_doctest_inventory(self):
        """A never-started or unfinished doctest remains missing, preventing a partial run from passing.
        ´claim:harness:doctest-inventory-complete´
        ´test:integration:test-doctest-inventory´
        """
        from run_tests import doctest_events
        registry = fixture('doctest', 'doctest::src/lib.rs - fixture [example 1]', 'doctest')
        selected = {'doctest::src/lib.rs - fixture [example 1]'}
        self.assertEqual(doctest_events('', 'current', CONFIGURATION, registry, selected)[0]['outcome'], 'incomplete')
        for invalid in (set(), {'doctest::absent'}):
            with self.assertRaisesRegex(StructuralError, 'selection'):
                doctest_events('', 'current', CONFIGURATION, registry, invalid)
        for text in ['', '{"type":"test","event":"started","name":"src/lib.rs - fixture (line 1)"}']:
            records = doctest_events(text, 'current', CONFIGURATION, registry)
            self.assertEqual(records[0]['outcome'], 'incomplete')
            self.assertIsNone(records[0]['duration_ms'])
            with self.assertRaisesRegex(StructuralError, 'incomplete'):
                registry.matrix(records, 'current')

    def test_doctest_identity(self):
        """Unrelated line shifts preserve item/example identity; ambiguous source positions refuse.
        ´claim:harness:doctest-identity-survives-line-shifts´
        ´test:integration:test-doctest-identity´
        """
        from doctest_identity import identities
        from run_tests import doctest_events
        import json
        names = ['src/../README.md - (line 10)', 'src/../README.md - (line 20)',
                 'src/lib.rs - item (line 30)']
        shifted = [n.replace('10', '110').replace('20', '120').replace('30', '130') for n in names]
        expected = ['doctest::README.md - <module> [example 1]',
                    'doctest::README.md - <module> [example 2]',
                    'doctest::src/lib.rs - item [example 1]']
        self.assertEqual(list(identities(names).values()), expected)
        self.assertEqual(identities(reversed(shifted)), identities(shifted))
        declared = rows('doctest', expected[0], 'doctest')
        declared[-1]['cases'] = expected
        registry = Registry(declared, declarations())
        for raw in [names, shifted]:
            stream = '\n'.join(json.dumps(dict(type='test', event=event, name=name, exec_time=0.01))
                               for event in ['started', 'ok'] for name in reversed(raw))
            records = doctest_events(stream, 'current', CONFIGURATION, registry)
            self.assertEqual({r['operation'] for r in records}, set(expected))
            self.assertTrue(all(r['outcome'] == 'passed' for r in records))
        for bad in [[names[0], names[0]], [names[0], 'README.md - (line 10)'], ['no location']]:
            with self.assertRaises(StructuralError):
                identities(bad)


if __name__ == '__main__':
    unittest.main()
