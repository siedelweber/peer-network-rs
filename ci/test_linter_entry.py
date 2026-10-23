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
