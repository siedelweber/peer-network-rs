"""Controlled evidence graphs exercise structural and predicate failures."""

from copy import deepcopy
from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from claims import evaluate, main, prose, respells, reconcile_mints, reviewed_sites, site_claim
from devperf import StructuralError
from harness import CONFIGURATION


def fixture():
    claim = 'ROOT::claim:testing:fixture'
    obligation = 'ROOT::gate:testing:fixture'
    area = 'ROOT::sec:testing:fixture-area'
    evidence = 'ROOT::amend:testing:fixture-evidence'
    sites = [dict(operation=n, owner='ROOT', area='testing', claim=claim, mint=i==0, language='rust')
             for i,n in enumerate(('first', 'sibling'))]
    paragraphs = {area: dict(text='Losing cases hides failures.', citations=set()),
                  evidence: dict(text='', citations={claim,obligation})}
    return dict(sites=sites, expected_sites={'first','sibling'},
                areas=[dict(owner='ROOT', area='testing', stake='Losing cases hides failures.', register=area, contract=area)],
                obligations={obligation:dict(path='fixture.md',citations=set())},
                declared=[dict(name=obligation,path='fixture.md',status='scoped-supported',claims=[claim],realizers=[],evidence_paragraph=evidence,premises='Both declared fixture executions in the fixed configuration.')],
                paragraphs=paragraphs,
                results=[dict(operation=n,source='current',configuration='fixture',outcome='passed') for n in ('first','sibling')],
                source='current',configuration='fixture')


class Evidence(unittest.TestCase):
    def test_shared_failure(self):
        """A failing sibling defeats the shared claim and its obligation despite another passing execution.
        ´claim:testing:sibling-failure-dominates´
        ´test:testing:test-shared-failure´
        """
        data=fixture()
        self.assertEqual(evaluate(**data)['obligations'][0]['status'],'scoped-passed')
        data['results'][1]['outcome']='failed'
        result=evaluate(**data)
        self.assertEqual(result['claims'][0]['status'],'failed')
        self.assertEqual(result['obligations'][0]['status'],'failed')

    def test_stale_result(self):
        """A passing execution from another source or configuration cannot evidence the checked tree.
        ´claim:testing:execution-identity-required´
        ´test:testing:test-stale-result´
        """
        for key in ('source','configuration'):
            data=fixture(); data['results'][0][key]='other'
            with self.assertRaisesRegex(StructuralError,'stale result'): evaluate(**data)

    def test_missing_area(self):
        """Removing an owner's risk register leaves its minted claims structurally unaccounted.
        ´claim:testing:area-stakes-required´
        ´test:testing:test-missing-area´
        """
        data=fixture(); data['areas']=[]
        with self.assertRaisesRegex(StructuralError,'missing or stale claim area'): evaluate(**data)

    def test_removed_obligation(self):
        """Deleting a register row cannot erase an obligation still minted in checked prose.
        ´claim:testing:source-obligations-cannot-disappear´
        ´test:testing:test-removed-obligation´
        """
        data=fixture(); data['declared']=[]
        with self.assertRaisesRegex(StructuralError,'source obligation'): evaluate(**data)

    def test_planned_name(self):
        """A planned claim name with no test-site mint cannot support a passing obligation.
        ´claim:testing:planned-names-are-not-evidence´
        ´test:testing:test-planned-name´
        """
        data=fixture(); data['declared'][0]['claims']=['ROOT::claim:testing:future']
        with self.assertRaisesRegex(StructuralError,'planned name'): evaluate(**data)

    def test_undeclared_site(self):
        """An executable source site omitted from the harness inventory is a structural error.
        ´claim:testing:every-source-site-is-declared´
        ´test:testing:test-undeclared-site´
        """
        data=fixture(); data['expected_sites'].remove('sibling')
        with self.assertRaisesRegex(StructuralError,'undeclared or omitted source site'): evaluate(**data)

    def test_missing_results_and_mints(self):
        """Missing executions and unresolved or duplicate claim mints cannot pass coverage.
        ´claim:testing:complete-executions-and-unique-mints´
        ´test:testing:test-missing-results-and-mints´
        """
        data=fixture(); data['results'].pop()
        with self.assertRaisesRegex(StructuralError,'missing test results'): evaluate(**data)
        for value in (False,True):
            data=fixture(); data['sites'][0 if not value else 1]['mint']=value
            with self.assertRaisesRegex(StructuralError,'unresolved or duplicate'): evaluate(**data)

    def test_uncited_evidence_and_holds(self):
        """A data-only coverage edge and an unowned hold both refuse invented completion.
        ´claim:testing:cited-evidence-or-owned-holds´
        ´test:testing:test-uncited-evidence-and-holds´
        """
        data=fixture(); data['paragraphs']['ROOT::amend:testing:fixture-evidence']['citations']=set()
        with self.assertRaisesRegex(StructuralError,'uncited evidence'): evaluate(**data)
        data=fixture(); data['declared'][0].update(status='held',claims=[])
        with self.assertRaisesRegex(StructuralError,'hold lacks owner'): evaluate(**data)

    def test_requirement_edges(self):
        """A requirement retains every source-cited realizer and inherits a failing realizer's verdict.
        ´claim:testing:requirement-edges-are-complete´
        ´test:testing:test-requirement-edges´
        """
        data=fixture(); requirement='ROOT::req:testing:fixture'
        gate=data['declared'][0]['name']
        data['obligations'][requirement]=dict(path='fixture.md',citations=set())
        data['obligations'][gate]['citations'].add(requirement)
        data['paragraphs']['ROOT::amend:testing:fixture-evidence']['citations'].add(requirement)
        row=deepcopy(data['declared'][0]); row.update(name=requirement,realizers=[gate]); data['declared'].append(row)
        data['results'][0]['outcome']='failed'
        self.assertTrue(all(r['status']=='failed' for r in evaluate(**data)['obligations']))
        row['realizers']=[]
        with self.assertRaisesRegex(StructuralError,'missing requirement edges'): evaluate(**data)

    def test_respellings(self):
        """Mechanical identifier respellings are listed while a proposition with an asserted consequence is retained.
        ´claim:testing:identifier-respellings-are-reported´
        ´test:testing:test-respellings´
        """
        self.assertTrue(respells(dict(function='test_retains_identity',gloss='Claim: Retains identity.')))
        self.assertFalse(respells(dict(function='test_retains_identity',gloss='A renamed implementation retains its identity in every joined result.')))

    def test_orphan_mint(self):
        """A source claim detached from all executable sites cannot disappear from the reverse coverage query.
        ´claim:testing:orphan-mints-are-refused´
        ´test:testing:test-orphan-mint´
        """
        from collections import Counter
        data=fixture()
        mints=Counter({'ROOT::claim:testing:fixture':1})
        reconcile_mints(data['sites'],mints)
        mints['ROOT::claim:testing:orphan']=1
        with self.assertRaisesRegex(StructuralError,'orphan'): reconcile_mints(data['sites'],mints)

    def test_enforcement_switch(self):
        """An otherwise passing fixture exits zero in reporting mode and one with --fail-respellings while retaining its offender artifact.
        ´claim:testing:respelling-switch-controls-exit´
        ´test:testing:test-enforcement-switch´
        """
        data=fixture()
        evidence=data['paragraphs']['ROOT::amend:testing:fixture-evidence']
        evidence['citations'].remove('ROOT::claim:testing:fixture')
        evidence['exhibits']={'ROOT::claim:testing:fixture'}
        sites=[]
        for i,name in enumerate(('first','sibling')):
            carrier='´claim:testing:fixture´' if i==0 else '(´claim:testing:fixture´)'
            gloss='Claim: First.' if i==0 else 'Claim: The second execution checks the same fixture predicate.'
            sites.append(dict(operation=name,owner='ROOT',function=name,path='ci/test_claims.py',
                              line=i+1,language='python',property=False,
                              doc=gloss+'\n'+carrier+'\n´test:testing:'+name+'´'))
        records=[dict(r,scope='case',configuration=CONFIGURATION) for r in data['results']]
        registry=SimpleNamespace(cases={n:dict(runner='ci') for n in ('first','sibling')},matrix=lambda *_:None)
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            previous=Path.cwd()
            stack.callback(os.chdir,previous)
            os.chdir(directory)
            for name in ('.lane','ci','docs/inputs'): Path(name).mkdir(parents=True,exist_ok=True)
            for name,rows in (('claim-areas',data['areas']),('claim-obligations',data['declared'])):
                Path('docs/inputs/'+name+'.toml').write_text('\n'.join(
                    '[[rows]]\n'+'\n'.join(key+' = '+json.dumps(value) for key,value in row.items()) for row in rows))
            Path('.lane/performance-events.jsonl').write_text('\n'.join(json.dumps(r) for r in records)+'\n')
            Path('.lane/harness-benchmarks.jsonl').write_text('')
            Path('ci/claim_review.json').write_text('{"schema":1,"sites":[]}')
            Path('ci/claim_gloss_baseline.json').write_text(json.dumps({'schema':1,'glosses':{s['operation']:site_claim(s)['gloss'] for s in sites}}))
            Path('ci/observe-core.json').write_text('{"schema":1,"operations":[]}')
            for name,value in (('load_registry',registry),('census',sites),
                               ('claim_mints',{'ROOT::claim:testing:fixture':1}),('checked_linter',None),
                               ('prose',(data['paragraphs'],data['obligations'])),('source_id','current')):
                stack.enter_context(patch('claims.'+name,return_value=value))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([]),0)
                self.assertEqual(main(['--fail-respellings']),1)
            self.assertEqual(len(json.loads(Path('.lane/claim-respellings.json').read_text())['offenders']),1)

    def test_review_binding(self):
        """A review must identify an existing unique site and its current claim and gloss, preventing stale audit entries from being counted.
        ´claim:testing:review-is-bound-to-current-site´
        ´test:testing:test-review-binding´
        """
        site=dict(operation='first',path='fixture.rs',claim='ROOT::claim:testing:fixture',gloss='The asserted fixture consequence.')
        row=dict(operation='first',path=site['path'],claim=site['claim'],before='First.',after=site['gloss'],review='Compared the fixture assertion and premise.')
        self.assertEqual(reviewed_sites([site],dict(schema=1,sites=[row])),[row])
        for key,value in (('operation','missing'),('path','other.rs'),('claim','ROOT::claim:testing:other'),('after','Old wording.')):
            with self.assertRaises(StructuralError): reviewed_sites([site],dict(schema=1,sites=[dict(row,**{key:value})]))
        with self.assertRaises(StructuralError): reviewed_sites([site],dict(schema=1,sites=[row,row]))

    def test_python_exhibits(self):
        """Designated evidence exhibits resolve only to Python-minted claims; unknown or Rust names refuse while unrelated planned names remain outside support.
        ´claim:testing:python-exhibits-resolve-to-source´
        ´test:testing:test-python-exhibits´
        """
        data=fixture()
        claim='ROOT::claim:testing:fixture'
        for site in data['sites']: site['language']='python'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'README.md').write_text(
                '**Amendment (Evidence)** · `amend:testing:fixture-evidence` '
                '(`gate:testing:fixture`) uses ``claim:testing:fixture``.\n\n'
                '**Model (Plan)** · `model:testing:future` Planned ``claim:testing:future``.\n')
            paragraphs,_=prose(root)
        data['paragraphs'].update(paragraphs)
        self.assertEqual(evaluate(**data)['obligations'][0]['status'],'scoped-passed')
        evidence=data['paragraphs']['ROOT::amend:testing:fixture-evidence']
        evidence['exhibits'].add('ROOT::claim:testing:unknown')
        with self.assertRaisesRegex(StructuralError,'exhibit does not resolve'): evaluate(**data)
        evidence['exhibits']={claim}
        for site in data['sites']: site['language']='rust'
        with self.assertRaisesRegex(StructuralError,'exhibit does not resolve'): evaluate(**data)
        evidence['exhibits']=set(); evidence['citations'].add(claim)
        self.assertEqual(evaluate(**data)['obligations'][0]['status'],'scoped-passed')
        for site in data['sites']: site['language']='python'
        with self.assertRaisesRegex(StructuralError,'Python claim requires exhibition'): evaluate(**data)

    def test_unknown_evidence_edge(self):
        """An unknown data edge refuses even beside valid Python evidence, and removing the matching exhibit cannot leave a supported row.
        ´claim:testing:python-edges-require-known-claims´
        ´test:testing:test-unknown-evidence-edge´
        """
        data=fixture(); claim='ROOT::claim:testing:fixture'
        for site in data['sites']: site['language']='python'
        evidence=data['paragraphs']['ROOT::amend:testing:fixture-evidence']
        evidence['citations'].remove(claim); evidence['exhibits']={claim}
        self.assertEqual(evaluate(**data)['obligations'][0]['status'],'scoped-passed')
        data['declared'][0]['claims'].append('ROOT::claim:testing:unknown')
        with self.assertRaisesRegex(StructuralError,'unresolved claim presented as evidence'): evaluate(**data)
        data['declared'][0]['claims']=[claim]; evidence['exhibits']=set()
        with self.assertRaisesRegex(StructuralError,'uncited evidence'): evaluate(**data)

    def test_source_carriers(self):
        """Strings cannot invent Rust tests, and unattached Python docstrings remain visible to mint reconciliation.
        ´claim:testing:source-carriers-are-lexically-checked´
        ´test:testing:test-source-carriers´
        """
        from source_sites import claim_mints,rust_sites
        source='const TEXT: &str = r###"#[test] fn invented() {}"###; #[test] fn actual() {}'
        sites=rust_sites('packages/example/src/lib.rs',source,'example','ROOT')
        self.assertEqual([s['operation'] for s in sites],['example::actual'])
        generated='proptest! {\n/// Generated integers preserve the asserted bound.\n#[doc = "´claim:testing:generated-bound´"]\n#[doc = "´test:integration:bounded´"]\n#[test]\nfn bounded(value in 0..8) { assert!(value<8); }\n}'
        sites=rust_sites('packages/example/tests/property.rs',generated,'example','ROOT')
        self.assertEqual(site_claim(sites[0])['claim'],'ROOT::claim:testing:generated-bound')
        self.assertTrue(sites[0]['property'])
        narrated=dict(sites[0],doc='Narrative with extra words.\nClaim: Bounded.\n´claim:testing:generated-bound´\n´test:integration:bounded´')
        self.assertEqual(site_claim(narrated)['gloss'],'Claim: Bounded.')
        self.assertTrue(respells(site_claim(narrated)))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'ci').mkdir()
            (root/'ci/orphan.py').write_text('"""Detached.\n´claim:testing:detached´\n"""\n')
            self.assertEqual(claim_mints(root),{'ROOT::claim:testing:detached':1})
            with self.assertRaisesRegex(StructuralError,'orphan'): reconcile_mints([],claim_mints(root))

    def test_planned_census(self):
        """An exhibited future name in a design paragraph is neither a minted claim nor a new obligation.
        ´claim:testing:exhibited-names-stay-out-of-census´
        ´test:testing:test-planned-census´
        """
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'README.md').write_text('**Model (Plan)** · `model:testing:future` Planned ``claim:testing:future``.\n')
            paragraphs,obligations=prose(root)
            self.assertEqual(set(paragraphs),{'ROOT::model:testing:future'})
            self.assertEqual(obligations,{})

    def test_reverse_evidence_edges(self):
        """A valid extra claim in a designated paragraph must also be an edge of one of its rows; merely passing its test cannot supply that missing relation.
        ´claim:testing:evidence-paragraphs-have-exact-edges´
        ´test:testing:test-reverse-evidence-edges´
        """
        data=fixture()
        other='ROOT::claim:testing:extra'
        data['sites'][1].update(claim=other,mint=True)
        paragraph=data['paragraphs']['ROOT::amend:testing:fixture-evidence']
        paragraph['citations'].add(other)
        with self.assertRaisesRegex(StructuralError,'paragraph and row edges differ'): evaluate(**data)
        data['declared'][0]['claims'].append(other)
        self.assertEqual(evaluate(**data)['obligations'][0]['status'],'scoped-passed')

    def test_required_gloss_reviews(self):
        """Removing a rewritten site's review or changing its retained before wording refuses, while an unchanged site needs no invented rewrite review.
        ´claim:testing:every-rewritten-gloss-has-review´
        ´test:testing:test-required-gloss-reviews´
        """
        site=dict(operation='first',path='fixture.rs',claim='ROOT::claim:testing:fixture',gloss='The fixture rejects the invalid input.')
        baseline=dict(schema=1,glosses={'first':'First.'})
        manifest=dict(schema=1,sites=[])
        with self.assertRaisesRegex(StructuralError,'rewritten site lacks review'): reviewed_sites([site],manifest,baseline)
        row=dict(operation='first',path=site['path'],claim=site['claim'],before='First.',after=site['gloss'],review='Read the refusal assertion and its invalid input.')
        manifest['sites']=[row]
        self.assertEqual(reviewed_sites([site],manifest,baseline),[row])
        row['before']='Other.'
        with self.assertRaisesRegex(StructuralError,'before gloss'): reviewed_sites([site],manifest,baseline)
        self.assertEqual(reviewed_sites([site],dict(schema=1,sites=[]),dict(schema=1,glosses={'first':site['gloss']})),[])
        with self.assertRaisesRegex(StructuralError,'baseline omits'): reviewed_sites([site],dict(schema=1,sites=[]),dict(schema=1,glosses={}))


if __name__=='__main__':
    unittest.main()
