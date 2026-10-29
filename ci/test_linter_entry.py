"""Entry evidence from the deployed checker over isolated, tracked fixture trees."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


POLICIES=['labels.mints-well-formed','labels.mints-unique','labels.citations-local-resolve',
          'labels.citations-imported-resolve','labels.citations-import-form','labels.generated-regions-conform']


class Tree:
    def __init__(self, policies=POLICIES):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.write('.linter/owners.toml', '''namespace="org.example.linter.owners"
version=[1,0,0]
owners=["ROOT","PEER"]
partitions=[{name="root",owner="ROOT",pattern='(%s"root/" *VCHAR / %s"Cargo.toml")'},{name="peer",owner="PEER",pattern='%s"peer/" *VCHAR'},{name="data",owner="ROOT",pattern='%s".linter/" *VCHAR'}]
may_cite=[{owner="PEER",target="ROOT"}]
''')
        self.write('.linter/environments.toml','namespace="org.example.linter.environments"\nversion=[1,0,0]\nenvironments=[{environment="Section",kind="sec"},{environment="Claim",kind="claim"}]\nreserved_kinds=["test"]\n')
        self.write('.linter/shape.toml','namespace="org.example.linter.shape"\nversion=[1,0,0]\nuniverse="git-tracked"\nignore=[]\n')
        self.write('.linter/lists.toml','namespace="class.linter.lists"\nversion=[1,0,0]\n'+''.join('['+owner+'.'+json.dumps(policy)+']\nallowances=[]\n' for owner in ('ROOT','PEER') for policy in policies))
        self.write('.linter/policies.toml','namespace="org.example.linter.policies"\nversion=[1,0,0]\npolicies=['+','.join('{owner='+json.dumps(owner)+',policy='+json.dumps(policy)+'}' for owner in ('ROOT','PEER') for policy in policies)+']\n')
        self.command(['git','init','--quiet'])
        self.write('root/README.md','Fixture root.\n')
        self.write('peer/README.md','Fixture peer.\n')
        self.write('Cargo.toml','[workspace]\nmembers=["root","peer"]\n')
        for name in ('root','peer'):self.write(name+'/Cargo.toml','[package]\nname="'+name+'"\nversion="0.1.0"\n')

    def write(self,path,text):
        path=self.root/path;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)

    def command(self,args):
        start=time.monotonic();result=subprocess.run(args,cwd=self.root,capture_output=True)
        print(f'LINTER-FIXTURE command={args[0]} exit={result.returncode} wall_seconds={time.monotonic()-start:.6f}')
        return result

    def check(self):
        tracked=self.command(['git','add','-A'])
        if tracked.returncode:raise AssertionError(tracked.stderr)
        result=self.command([os.environ['LINTER_BIN'],'check','--root',str(self.root)])
        if not result.stdout:raise AssertionError(result.stderr.decode())
        row=json.loads(result.stdout)
        print('LINTER-FIXTURE-RESULT '+json.dumps(dict(exit=result.returncode,mints=row['mints'],citations=row['citations_resolved'],covered=row['profile']['covered'],labelled=row['profile']['labelled'],findings=[f['code'] for f in row['findings']]),sort_keys=True))
        return result.returncode,row

    def close(self):self.temp.cleanup()


class Conformance(unittest.TestCase):
    def tree(self,policies=POLICIES):
        tree=Tree(policies);self.addCleanup(tree.close);return tree

    def test_resolution(self):
        """Claim: A deployed checker resolves one local and one imported citation in an isolated corpus and refuses a missing target, so current-corpus cleanliness cannot hide a resolver that accepts dangling evidence.
        ´claim:discipline:fixture-resolution-requires-a-mint´
        ´test:integration:test-resolution´
        """
        tree=self.tree();tree.write('peer/a.md','## One · `sec:fixture:one`\n\n(`sec:fixture:one`) (`[ROOT-sec:fixture:two]`).\n')
        tree.write('root/b.md','## Two · `sec:fixture:two`\n')
        code,row=tree.check();self.assertEqual((code,row['mints'],row['citations_resolved'],row['findings']),(0,2,2,[]))
        tree.write('root/b.md','## Other · `sec:fixture:other`\n')
        code,row=tree.check();self.assertEqual(code,3);self.assertEqual([f['code'] for f in row['findings']],['unresolved_citation'])

    def test_duplicate_locations(self):
        """Claim: Duplicate fixture mints fail with both physical locations in either owner, preserving the information needed to reconcile ownership rather than silently choosing one definition.
        ´claim:discipline:duplicate-fixtures-name-both-sites´
        ´test:integration:test-duplicate-locations´
        """
        for owner in ('root','peer'):
            tree=self.tree()
            for name in ('a','b'):tree.write(owner+'/'+name+'.md','## One · `sec:fixture:one`\n')
            code,row=tree.check();self.assertEqual(code,3)
            self.assertEqual([f['code'] for f in row['findings']],['duplicate_mint'])
            self.assertIn(owner+'/a.md',json.dumps(row['findings']));self.assertIn(owner+'/b.md',json.dumps(row['findings']))

    def test_traversal_order(self):
        """Claim: Swapping mint and citation paths and reversing their creation order leaves deployed resolution counts and findings unchanged, so a forward reference has the same meaning as a backward one.
        ´claim:discipline:fixture-traversal-order-does-not-select-meaning´
        ´test:integration:test-traversal-order´
        """
        results=[]
        for reverse in (False,True):
            tree=self.tree();items=[('root/a.md','## One · `sec:fixture:one`\n'),('root/z.md','## Two · `sec:fixture:two`\n\n(`sec:fixture:one`).\n')]
            if reverse:items=[(items[1][0],items[0][1]),(items[0][0],items[1][1])]
            for path,text in items:tree.write(path,text)
            code,row=tree.check();results.append((code,row['mints'],row['citations_resolved'],row['findings']))
        self.assertEqual(results,[(0,2,1,[])]*2)

    def test_occurrence_forms(self):
        """Claim: Markdown backticks and Rust-comment acute delimiters each mint and resolve local and imported forms while ordinary prose contributes no occurrence, preserving the carrier boundary in a constructed corpus.
        ´claim:discipline:fixture-carriers-separate-text-from-evidence´
        ´test:integration:test-occurrence-forms´
        """
        for extension,body in [('md','## Head · `sec:fixture:local`\n\n(`sec:fixture:local`) (`[ROOT-sec:fixture:target]`).\nPlain prose.\n'),('rs','/// (´test:unit:fixture´) (´[ROOT-sec:fixture:target]´).\n/// Plain prose.\n/// ´test:unit:fixture´\n#[test]\nfn fixture() {}\n')]:
            tree=self.tree(POLICIES+['profile.tests-conform']);tree.write('root/target.md','## Target · `sec:fixture:target`\n')
            tree.write('peer/src/body.'+extension,body)
            code,row=tree.check();self.assertEqual((code,row['mints'],row['citations_resolved'],row['findings']),(0,2 if extension=='md' else 1,2,[]))
            if extension=='rs':self.assertEqual((row['profile']['covered'],row['profile']['labelled']),(1,1))

    def test_import_forms(self):
        """Claim: Invalid owner qualification fails and a local citation whose sole mint belongs elsewhere names the required import, so ownership cannot be repaired silently by lookup order.
        ´claim:discipline:fixture-imports-preserve-owner-boundaries´
        ´test:integration:test-import-forms´
        """
        cases=[('(`[PEER-sec:fixture:local]`)','self_qualified_import'),('(`sec:fixture:target`)','unresolved_citation_wanting_import')]
        for citation,expected in cases:
            tree=self.tree();tree.write('root/target.md','## Target · `sec:fixture:target`\n')
            tree.write('peer/body.md','## Local · `sec:fixture:local`\n\n'+citation+'\n')
            code,row=tree.check();self.assertEqual(code,3,(citation,row));self.assertEqual([f['code'] for f in row['findings']],[expected])
            if expected=='unresolved_citation_wanting_import':self.assertIn('ROOT',json.dumps(row['findings']))

    def test_reserved_warrant(self):
        """Claim: A reserved test kind without an activated deriving profile cannot mint in prose, preventing an authored name from substituting for the asset inventory.
        ´claim:discipline:fixture-reserved-kinds-require-a-profile´
        ´test:integration:test-reserved-warrant´
        """
        tree=self.tree();tree.write('root/reserved.md','## Test · `test:unit:invented`\n')
        code,row=tree.check();self.assertEqual(code,3);self.assertEqual([f['code'] for f in row['findings']],['unwarranted_reserved_kind'])

    def test_unregistered_prefix(self):
        """Claim: An import naming an undeclared owner fails with unregistered_prefix, so a missing owner cannot be mistaken for a local resolution or ignored text.
        ´claim:discipline:fixture-import-owner-must-be-registered´
        ´test:integration:test-unregistered-prefix´
        """
        tree=self.tree();tree.write('peer/body.md','(`[UNKNOWN-sec:fixture:target]`)\n')
        code,row=tree.check();self.assertEqual(code,3)
        self.assertEqual([f['code'] for f in row['findings']],['unregistered_prefix'])

    def test_non_parenthesized_import(self):
        """Claim: A bracketed import without citation parentheses fails with non_parenthesized_import even when its target exists, preserving the distinction between a citation and a bare imported form.
        ´claim:discipline:fixture-import-requires-citation-parentheses´
        ´test:integration:test-non-parenthesized-import´
        """
        tree=self.tree();tree.write('root/target.md','## Target · `sec:fixture:target`\n')
        tree.write('peer/body.md','`[ROOT-sec:fixture:target]`\n')
        code,row=tree.check();self.assertEqual(code,3)
        self.assertEqual([f['code'] for f in row['findings']],['non_parenthesized_import'])

    def test_no_form_span(self):
        """Claim: A parenthesized prefix-label pair without import brackets contributes no occurrence and never fails resolution; only a near-miss warning may accompany this ordinary text.
        ´claim:discipline:fixture-no-form-span-is-text´
        ´test:integration:test-no-form-span´
        """
        tree=self.tree();tree.write('peer/body.md','(`ROOT-sec:fixture:target`)\n')
        code,row=tree.check();self.assertEqual((code,row['mints'],row['citations_resolved']),(0,0,0))
        self.assertTrue(all(f['code']=='near_miss' for f in row['findings']))

    def test_near_misses(self):
        """Claim: A label-shaped backtick in a Rust comment produces a warning without minting or resolving anything, keeping mistaken delimiters visible without granting them evidential authority.
        ´claim:discipline:fixture-near-misses-are-not-occurrences´
        ´test:integration:test-near-misses´
        """
        tree=self.tree(POLICIES+['profile.tests-conform']);tree.write('root/src/comment.rs','/// `sec:fixture:mistyped`\npub fn fixture() {}\n')
        code,row=tree.check();self.assertEqual((code,row['mints'],row['citations_resolved']),(0,0,0));self.assertEqual([f['code'] for f in row['findings']],['near_miss'])

    def test_asset_inventory(self):
        """Claim: Removing or renaming a Rust fixture test invalidates its old citation and a misplaced derived label fails, so inventory evidence cannot survive departure or rename of its asset.
        ´claim:discipline:fixture-inventory-follows-the-asset´
        ´test:integration:test-asset-inventory´
        """
        tree=self.tree(POLICIES+['profile.tests-conform'])
        tree.write('root/src/lib.rs','/// ´test:unit:fixture´\n#[test]\nfn fixture() {}\n')
        tree.write('root/cite.md','## Cite · `sec:fixture:cite`\n\n(`test:unit:fixture`).\n')
        code,row=tree.check();self.assertEqual((code,row['profile']['labelled'],row['citations_resolved']),(0,1,1))
        tree.write('root/src/lib.rs','')
        code,row=tree.check();self.assertEqual((code,[f['code'] for f in row['findings']]),(3,['unresolved_citation']))
        tree.write('root/src/lib.rs','/// ´test:unit:fixture´\n#[test]\nfn renamed() {}\n')
        code,row=tree.check();self.assertEqual(code,3);self.assertEqual(row['profile']['wrong'],1)
        tree.write('root/src/lib.rs','/// ´test:unit:fixture´\n/// Text after the standard place.\n#[test]\nfn fixture() {}\n')
        code,row=tree.check();self.assertEqual(code,3);self.assertEqual(row['profile']['misplaced'],1)

    def test_generated_citations(self):
        """Claim: A generated Rust index resolves its citation without minting it, and a deleted target or a bare index label fails, preventing the index from sustaining its own membership.
        ´claim:discipline:fixture-index-cannot-supply-its-target´
        ´test:integration:test-generated-citations´
        """
        tree=self.tree(POLICIES+['profile.tests-conform'])
        prefix='//! # Test index\n//!\n//! | Test | Area | Claim |\n//! |---|---|---|\n'
        tree.write('root/target.md','## Target · `sec:fixture:target`\n')
        tree.write('root/src/lib.rs',prefix+'//! | fixture | unit | (´sec:fixture:target´) |\n')
        code,row=tree.check();self.assertEqual((code,row['mints'],row['citations_resolved'],row['findings']),(0,1,1,[]))
        tree.write('root/target.md','No target.\n')
        code,row=tree.check();self.assertEqual((code,[f['code'] for f in row['findings']]),(3,['dangling_generated_citation']))
        tree.write('root/src/lib.rs',prefix+'//! | fixture | unit | ´sec:fixture:target´ |\n')
        code,row=tree.check();self.assertEqual((code,row['mints'],[f['code'] for f in row['findings']]),(3,0,['bare_generated_occurrence']))

    def test_projection_fixed_point(self):
        """Claim: The deployed projector derives a missing Rust test index and writes identical bytes on a second pass, so the submitted generated register is checked as a fixed point rather than trusted because it exists.
        ´claim:discipline:fixture-projection-reaches-a-fixed-point´
        ´test:integration:test-projection-fixed-point´
        """
        tree=self.tree(POLICIES+['profile.tests-conform','projection.test-indexes-current'])
        tree.write('root/src/lib.rs','/// ´test:unit:fixture´\n#[test]\nfn fixture() {}\n')
        tree.check()
        args=[os.environ['LINTER_BIN'],'project','--root',str(tree.root),'--write']
        result=tree.command(args[:-1]);self.assertEqual(result.returncode,0,result.stdout)
        self.assertEqual(json.loads(result.stdout)['index']['bootstrapped'],1)
        result=tree.command(args);self.assertEqual(result.returncode,0,result.stderr)
        before=(tree.root/'root/src/lib.rs').read_bytes()
        result=tree.command(args);self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(before,(tree.root/'root/src/lib.rs').read_bytes())
        code,row=tree.check();self.assertEqual((code,row['index']['stale'],row['index']['unindexed']),(0,0,0))
        tree.write('root/src/lib.rs',before.decode().replace('fn fixture()', 'fn changed()').replace('´test:unit:fixture´','´test:unit:changed´'))
        code,row=tree.check();self.assertEqual(code,3);self.assertEqual(row['index']['stale'],1)

    def test_missing_tracked_source(self):
        """Claim: A tracked Rust source removed from the fixture checkout produces a corpus diagnostic instead of silently shrinking the evidence carrier, so traversal loss is visible before resolution.
        ´claim:discipline:fixture-traversal-loss-is-diagnostic´
        ´test:integration:test-missing-tracked-source´
        """
        tree=self.tree(POLICIES+['profile.tests-conform']);tree.write('root/src/lib.rs','pub fn fixture() {}\n')
        code,row=tree.check();self.assertEqual(code,0)
        (tree.root/'root/src/lib.rs').unlink()
        result=tree.command([os.environ['LINTER_BIN'],'check','--root',str(tree.root)])
        row=json.loads(result.stdout)
        self.assertEqual(result.returncode,3);self.assertEqual([f['code'] for f in row['findings']],['traversal_failure']*4)
        self.assertTrue(all('root/src/lib.rs' in json.dumps(f) for f in row['findings']))

    def test_build_graph_census(self):
        """Claim: The Meson census and incidence checks refuse unaccounted, stale, duplicate, unconnected or excluded tracked inputs and incomplete step reports, including tracked additions without reconfiguration, while explicitly declared vendor and generated files pass; a matching configuring Meson version is reused and a mismatched version requires fresh setup.
        ´claim:discipline:build-graph-census-accounts-for-tracked-inputs´
        ´test:integration:test-build-graph-census´
        """
        from build_graph_witnesses import exercise
        exercise(self)

    def test_build_graph_delegation(self):
        """Claim: Isolated clean, stale-render and failing-check sequences preserve legacy command statuses, diagnostics and generated bytes through Meson, including status seven and repeated reads, while stale source, configuration, run, input and result envelopes are refused; failed graph configuration structurally refuses all delegated commands, and entry reports separate command wall from inclusive overhead without changing command logs.
        ´claim:discipline:build-graph-delegation-preserves-results´
        ´test:integration:test-build-graph-delegation´
        """
        from build_graph_witnesses import delegation
        delegation(self)

    def test_cargo_delegation(self):
        """Claim: Serial Cargo fixture commands preserve artifact and test inventories, compile-error refusal, advisory warnings and nonverdict timing excess through the Meson adapter, using the same target directory and a separate doctest command; the nine slice-three roster commands retain their exact arguments.
        ´claim:discipline:cargo-delegation-preserves-build-evidence´
        ´test:integration:test-cargo-delegation´
        """
        from build_graph_witnesses import cargo_delegation
        cargo_delegation(self)

    def test_runtime_delegation(self):
        """Claim: Serial runtime fixtures preserve command statuses, current-source and configuration refusals, sibling failures, held claims and nonverdict missing measurements through Meson; graph-refused execution still reaches shell stops, and SIGTERM during a Ninja command reaps its command tree and performs root-keyed exit cleanup without touching a sibling root; all eleven runtime roster commands retain their text.
        ´claim:discipline:runtime-delegation-preserves-evidence´
        ´test:integration:test-runtime-delegation´
        """
        from build_graph_runtime_witnesses import runtime_delegation
        runtime_delegation(self)

    def test_service_ownership(self):
        """Claim: Concurrent startups in two isolated checkouts obtain distinct ports, directories and processes for each real PostgreSQL and Elements pair on both routes; stopping either owned instance leaves its sibling serving until its own stop, with both shut down before return; pre-stop CPU samples are rooted at their pidfiles and include only that process tree and already waited children, with known-tick and absent-root controls.
        ´claim:discipline:service-delegation-preserves-ownership´
        ´test:integration:test-service-ownership´
        """
        from build_graph_runtime_witnesses import service_instances
        service_instances(self)

    def test_build_graph_completion(self):
        """Claim: The entry takes its complete serial roster from Meson, retaining only census and service shutdown outside delegation; fresh and reused target executions preserve fixture cases, features, document bytes and statuses, execute each step once, and refuse missing targets, missing final reports, duplicate completions and stale run or configuration joins.
        ´claim:discipline:build-graph-completion-is-current-and-exact´
        ´test:integration:test-build-graph-completion´
        """
        from build_graph_runtime_witnesses import completion
        completion(self)

    def test_service_selection(self):
        """Claim: The real service ownership witness is selected when any declared input differs from its parent or admission is requested; configured service-tool paths bind the selection fingerprint and its single runner line names source and flag; unchanged inputs produce only a standing selection hold that holds the composition decision without reopening the admitted gate, while admission execution supports both rows; another case, a stale input binding or a selected execution cannot reuse that hold.
        ´claim:discipline:service-selection-keeps-unexecuted-evidence-held´
        ´test:integration:test-service-selection´
        """
        from unittest.mock import patch
        from contextlib import redirect_stdout, redirect_stderr
        import io
        from build_graph_evidence import SERVICE_INPUTS, SERVICE_CASE, service_selection, held_service
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in SERVICE_INPUTS:
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'unchanged')
            def previous(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, b'unchanged', b'')
            with patch('build_graph_evidence.subprocess.run', side_effect=previous), patch.dict(os.environ, {'PN_BUILDGRAPH_ADMISSION': '0'}):
                selection = service_selection(root)
                self.assertFalse(selection['run'])
                for tool in ('PN_POSTGRESQL_BIN', 'PN_ELEMENTS_BIN', 'PN_MESON_BIN'):
                    with patch.dict(os.environ, {tool: 'different-configured-tool'}):
                        self.assertNotEqual(service_selection(root)['inputs'], selection['inputs'])
                record = dict(operation=SERVICE_CASE, outcome='held', hold=selection['hold'], reason=selection['reason'], selection_inputs=selection['inputs'])
                self.assertTrue(held_service(record, root))
                self.assertTrue(service_selection(root, admission=True)['run'])
                for field in ('operation', 'hold', 'reason', 'selection_inputs'):
                    self.assertFalse(held_service(record | {field: 'other'}, root))
                for name in SERVICE_INPUTS:
                    (root/name).write_bytes(b'changed')
                    self.assertEqual(service_selection(root)['changed'], [name])
                    self.assertFalse(held_service(record, root))
                    (root/name).write_bytes(b'unchanged')

        from test_harness import fixture, result
        from test_claims import fixture as claim_fixture
        from claims import evaluate
        from devperf import StructuralError
        registry = fixture(case=SERVICE_CASE)
        record = result(registry) | dict(outcome='held', hold=selection['hold'], reason=selection['reason'], selection_inputs=selection['inputs'])
        with patch('build_graph_evidence.service_selection', return_value=selection):
            matrix = registry.matrix([record], 'current')
            self.assertEqual((matrix[0]['status'], matrix[0]['observed']), ('held', 0))
            data = claim_fixture()
            data['sites'][0]['operation'] = SERVICE_CASE
            data['expected_sites'] = {SERVICE_CASE, 'sibling'}
            data['results'][0] = record | dict(configuration='fixture')
            evidence = evaluate(**data)
            self.assertEqual(evidence['claims'][0]['status'], 'held')
            self.assertEqual(evidence['obligations'][0]['status'], 'held')
            import run_ci
            runner_registry = fixture(case=SERVICE_CASE)
            runner_registry.suites['ci::test_linter_entry'] = runner_registry.suites.pop('example')
            forbidden = unittest.FunctionTestCase(lambda: self.fail('held service executed'))
            forbidden.id = lambda: SERVICE_CASE.removeprefix('ci::')
            with patch.object(run_ci, 'load', return_value=runner_registry), patch.object(run_ci, 'source_id', return_value='current'), \
                    patch.object(unittest.defaultTestLoader, 'loadTestsFromName', return_value=unittest.TestSuite([forbidden])), \
                    patch.object(Path, 'write_text') as written, patch.object(run_ci, 'report'):
                captured = io.StringIO()
                with redirect_stdout(captured), redirect_stderr(io.StringIO()):
                    self.assertEqual(run_ci.main('test_linter_entry'), 0)
                lines = [line for line in captured.getvalue().splitlines() if line.startswith('BUILD-SERVICE-SELECTION ')]
                self.assertEqual(len(lines), 1)
                decision = json.loads(lines[0].split(' ', 1)[1])
                self.assertEqual(decision['source'], 'current')
                self.assertFalse(decision['run'])
                self.assertEqual(decision['admission'], os.environ.get('PN_BUILDGRAPH_ADMISSION', '0'))
                emitted = [json.loads(line) for line in written.call_args.args[0].splitlines()]
                self.assertEqual(emitted[0]['outcome'], 'held')
                self.assertIsNone(emitted[0]['duration_ms'])
                self.assertFalse(any(row['outcome']=='passed' for row in emitted))
            passed = unittest.FunctionTestCase(lambda: None)
            passed.id = lambda: SERVICE_CASE.removeprefix('ci::')
            with patch('build_graph_evidence.service_selection', return_value=selection | dict(run=True, reason='admission requested')), \
                    patch.dict(os.environ, {'PN_BUILDGRAPH_ADMISSION': '1'}), \
                    patch.object(run_ci, 'load', return_value=runner_registry), patch.object(run_ci, 'source_id', return_value='current'), \
                    patch.object(unittest.defaultTestLoader, 'loadTestsFromName', return_value=unittest.TestSuite([passed])), \
                    patch.object(Path, 'write_text') as written, patch.object(run_ci, 'report'), \
                    redirect_stdout(io.StringIO()) as captured, redirect_stderr(io.StringIO()):
                self.assertEqual(run_ci.main('test_linter_entry'), 0)
                emitted = [json.loads(line) for line in written.call_args.args[0].splitlines()]
                service = next(row for row in emitted if row['operation'] == SERVICE_CASE)
                self.assertEqual((service['outcome'], service['reason'], service['selection_admission']), ('passed', 'admission requested', '1'))
                decision = json.loads(next(line for line in captured.getvalue().splitlines() if line.startswith('BUILD-SERVICE-SELECTION ')).split(' ', 1)[1])
                self.assertEqual((decision['source'], decision['admission'], decision['run']), ('current', '1', True))
            for field in ('operation', 'hold', 'reason', 'selection_inputs'):
                bad = record | {field: 'unknown-or-stale'}
                with self.subTest(field=field), self.assertRaises(StructuralError):
                    registry.matrix([bad], 'current')
                invalid = dict(data, results=[bad | dict(configuration='fixture'), data['results'][1]])
                with self.assertRaises(StructuralError):
                    evaluate(**invalid)
            data['results'][1]['outcome'] = 'failed'
            self.assertEqual(evaluate(**data)['claims'][0]['status'], 'failed')
        with patch('build_graph_evidence.service_selection', return_value=selection | dict(run=True)):
            with self.assertRaises(StructuralError):
                registry.matrix([record], 'current')
            with self.assertRaises(StructuralError):
                evaluate(**data)

        # Exercise the actual registered edges, not a duplicate of their policy.
        import copy
        import tomllib
        from build_graph_evidence import SERVICE_HOLD
        self.assertEqual(SERVICE_HOLD, 'ROOT::rule:buildgraph:service-selection')
        names = ('ROOT::dec:buildgraph:composition', 'ROOT::gate:buildgraph:implementation')
        rows = [row for row in tomllib.loads(Path('docs/inputs/claim-obligations.toml').read_text())['rows'] if row['name'] in names]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['status'] == 'scoped-supported' for row in rows))
        self.assertTrue(all(row['hold'] == 'ROOT::open:testing:obligation-evidence' for row in rows))
        service_claim = 'ROOT::claim:discipline:service-delegation-preserves-ownership'
        self.assertIn(service_claim, next(row['claims'] for row in rows if row['name'] == names[0]))
        self.assertNotIn(service_claim, next(row['claims'] for row in rows if row['name'] == names[1]))
        graph = claim_fixture()
        graph['paragraphs'].pop('ROOT::amend:testing:fixture-evidence')
        all_claims = sorted({claim for row in rows for claim in row['claims']})
        graph['sites'] = [dict(operation=SERVICE_CASE if claim == service_claim else 'fixture-'+str(i), owner='ROOT', area='testing', claim=claim, mint=True, language='python') for i, claim in enumerate(all_claims)]
        graph['expected_sites'] = {site['operation'] for site in graph['sites']}
        graph['declared'] = rows
        graph['obligations'] = {row['name']: dict(path=row['path'], citations=set()) for row in rows}
        for row in rows:
            paragraph = graph['paragraphs'].setdefault(row['evidence_paragraph'], dict(text='', citations=set()))
            paragraph['citations'].update([row['name'], *row['claims']])
        for admission in (False, True):
            observed = copy.deepcopy(graph)
            observed['results'] = [dict(operation=site['operation'], source='current', configuration='fixture', outcome='passed') for site in observed['sites']]
            if not admission:
                next(result for result in observed['results'] if result['operation'] == SERVICE_CASE).update(outcome='held', hold=selection['hold'], reason=selection['reason'], selection_inputs=selection['inputs'])
            with patch('build_graph_evidence.service_selection', return_value=selection | dict(run=admission)):
                states = {row['name']: row['status'] for row in evaluate(**observed)['obligations']}
            self.assertEqual(states[names[0]], 'scoped-passed' if admission else 'held')
            self.assertEqual(states[names[1]], 'scoped-passed')

    def test_retained_gate_equivalence(self):
        """Claim: Retention refuses dirty trees, inconsistent rosters and logs, missing final joins, stale or corrupt reports, duplicate or stale cases and multiple Meson actions; retained fresh and reused evidence compares full roster, features, cases, documents, claims and statuses, while checked admission additionally requires service passes explicitly requested for admission; changed fields, missing reports, repeated completions, reused nonces or runs and replaced setup refuse.
        ´claim:discipline:retained-gates-preserve-complete-evidence´
        ´test:integration:test-retained-gate-equivalence´
        """
        import copy
        from build_graph_evidence import compare, stable, case_projection, SERVICE_CASE
        from build_graph_runtime_witnesses import capture_evidence
        capture_evidence(self)
        first = dict(schema=1, source='fixture', roster=[['check', 'command']], statuses=[['check', '0']],
                     verdict=0, configuration={'features': 'default'}, documents={'README.md': 'bytes'},
                     features={'Cargo.toml': 'feature declarations'}, matrix={'cases': ['one']}, claims={'claim': 'passed'}, cases=[{'operation': 'one', 'outcome': 'passed'}],
                     reports={'check': dict(nonce='first', status=0, context=dict(run='first', history='first-prefix', source='fixture', command='command'))},
                     setup=dict(action='setup', stamp=1, directory='same-directory', information={'version': 'same'}))
        second = copy.deepcopy(first)
        second['setup']['action'] = 'reuse'
        second['reports']['check'].update(nonce='second', context=dict(run='second', history='second-prefix', source='fixture', command='command'))
        self.assertIn('statuses=equal', compare(first, second))
        with self.assertRaisesRegex(ValueError, 'admission comparison'):
            compare(first, second, admission=True)
        admitted = [copy.deepcopy(first), copy.deepcopy(second)]
        for snapshot in admitted:
            snapshot['cases'].append(dict(operation=SERVICE_CASE, outcome='passed', reason='admission requested', selection_admission='1'))
        self.assertIn('admission=true service=passed', compare(*admitted, admission=True))
        for field, value in (('outcome', 'held'), ('reason', 'service inputs changed'), ('selection_admission', '0')):
            bad = copy.deepcopy(admitted)
            for snapshot in bad:
                snapshot['cases'][-1][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'admission comparison'):
                compare(*bad, admission=True)
        for field in ('source', 'roster', 'statuses', 'verdict', 'configuration', 'documents', 'features', 'matrix', 'claims', 'cases'):
            bad = copy.deepcopy(second)
            bad[field] = None
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                compare(first, bad)
        for fault in ('missing', 'nonce', 'run', 'command', 'status', 'setup', 'stamp'):
            bad = copy.deepcopy(second)
            if fault == 'missing': bad['reports'] = {}
            elif fault == 'setup': bad['setup']['action'] = 'setup'
            elif fault == 'stamp': bad['setup']['stamp'] = 2
            elif fault in ('run', 'command'): bad['reports']['check']['context'][fault] = 'first' if fault == 'run' else 'different'
            else: bad['reports']['check'][fault] = 'first' if fault == 'nonce' else 1
            with self.subTest(fault=fault), self.assertRaises(ValueError): compare(first, bad)
        repeated = copy.deepcopy(first)
        repeated['roster'] *= 2
        repeated['statuses'] *= 2
        with self.assertRaisesRegex(ValueError, 'exactly once'): compare(repeated, repeated)
        self.assertEqual(stable({'duration_ms': 1, 'utc': 'one', 'outcome': 'failed'}),
                         stable({'duration_ms': 2, 'utc': 'two', 'outcome': 'failed'}))
        self.assertNotEqual(stable({'outcome': 'failed'}), stable({'outcome': 'passed'}))
        measured = dict(operation='benchmark::fixture', outcome='passed', iterations=10, throughput_operations_per_s=5, invocation_ms=2)
        later = measured | dict(iterations=20, throughput_operations_per_s=6, invocation_ms=3)
        self.assertEqual(case_projection(measured), case_projection(later))
        self.assertNotEqual(case_projection(measured), case_projection(later | dict(outcome='failed')))
        self.assertNotEqual(case_projection(measured | dict(operation='test::fixture')), case_projection(later | dict(operation='test::fixture')))

    def test_build_graph_slice_assignment(self):
        """Claim: Every live gate step has exactly one delegation slice and the record roster agrees with that set; each record group stays in one slice unless its exceptional rows explicitly name the split, so missing, repeated, unknown, invalid or unexplained assignments refuse before final migration.
        ´claim:discipline:build-graph-slices-cover-roster´
        ´test:integration:test-build-graph-slice-assignment´
        """
        from collections import Counter
        import tomllib
        from build_graph import roster
        steps = [name for name, _ in roster(Path.cwd())]
        rows = tomllib.loads(Path('docs/inputs/build-graph-slices.toml').read_text())['rows']
        record = next(row for row in tomllib.loads(Path('docs/inputs/records.toml').read_text())['rows'] if row['label'] == 'rec:buildgraph:decision')
        self.assertEqual(Counter(record['step_names']), Counter(steps))

        def check(assignments):
            self.assertEqual(Counter(row['name'] for row in assignments), Counter(steps))
            self.assertTrue(all(type(row['slice']) is int and row['slice'] in {2, 3, 4, 5} and row['reason'] for row in assignments))
            by_name = {row['name']: row for row in assignments}
            for group in record['step_groups']:
                members = [by_name[name] for name in group['steps']]
                ordinary = [row for row in members if not row['reason'].startswith('Split from '+group['name']+':')]
                self.assertLessEqual(len({row['slice'] for row in ordinary}), 1, group['name'])

        check(rows)
        for fault in (rows[1:], rows+[rows[0]], rows+[dict(name='unknown', slice=2, reason='Unknown step')],
                      [rows[0] | {'slice': 1}]+rows[1:],
                      [row | {'reason': 'Generic checker reason'} if row['name'] == 'observation-syntax' else row for row in rows],
                      [row | {'slice': 3} if row['name'] == 'toolchain' else row for row in rows]):
            with self.assertRaises(AssertionError):
                check(fault)
        print(f'BUILD-SLICES steps={len(rows)} slice2={sum(r["slice"] == 2 for r in rows)} slice3={sum(r["slice"] == 3 for r in rows)} slice4={sum(r["slice"] == 4 for r in rows)} slice5={sum(r["slice"] == 5 for r in rows)}')

    def test_scoped_projection(self):
        """Claim: An unrelated owner's duplicate prose does not prevent regeneration of the active Rust test projection, so scoped maintenance remains possible without concealing the separate corpus failure.
        ´claim:discipline:fixture-projection-is-scoped-to-its-inputs´
        ´test:integration:test-scoped-projection´
        """
        tree=self.tree(POLICIES+['profile.tests-conform','projection.test-indexes-current'])
        tree.write('root/src/lib.rs','/// ´test:unit:fixture´\n#[test]\nfn fixture() {}\n')
        for name in ('a','b'):tree.write('peer/'+name+'.md','## Duplicate · `sec:fixture:duplicate`\n')
        code,row=tree.check();self.assertEqual((code,[f['code'] for f in row['findings']]),(3,['duplicate_mint']))
        result=tree.command([os.environ['LINTER_BIN'],'project','--root',str(tree.root),'--write'])
        self.assertEqual(result.returncode,0,result.stdout)
        self.assertIn('//! # Test index',(tree.root/'root/src/lib.rs').read_text())

    def test_warrant_species(self):
        """Claim: Reserving a kind prevents its registered environment head from warranting an authored mint, so adding an environment does not bypass the derivation requirement.
        ´claim:discipline:fixture-kind-warrants-cannot-overlap´
        ´test:integration:test-warrant-species´
        """
        tree=self.tree()
        path=tree.root/'.linter/environments.toml'
        path.write_text(path.read_text().replace('reserved_kinds=["test"]','reserved_kinds=["test","sec"]'))
        tree.write('root/head.md','## Head · `sec:fixture:head`\n')
        code,row=tree.check()
        self.assertEqual((code,row['mints'],[f['code'] for f in row['findings']]),(3,0,['unwarranted_reserved_kind']))


if __name__=='__main__':unittest.main()
