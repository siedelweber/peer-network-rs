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
    def test_entry_basis_matches_authored_source(self):
        """Claim: Changing an executed entry to review cannot bypass current execution support, because its basis must match the independently authored paragraph; duplicate and omitted classifications also refuse.
        ´claim:testing:entry-basis-is-bound-to-authored-source´
        ´test:integration:test-entry-basis-matches-authored-source´
        """
        from claims import entry_bases, enforce_entry
        name='ROOT::gate:xchg:implementation'
        review='ROOT::amend:decomposition:entry-review-basis'
        executed='ROOT::amend:decomposition:entry-executed-basis'
        paragraphs={review:dict(citations=set()),executed:dict(citations={name})}
        bases=entry_bases(paragraphs,{name})
        self.assertEqual(bases,{name:'executed'})
        row=dict(name=name,entry_gate='ROOT::gate:design:bite-1',admission_basis='review')
        with self.assertRaisesRegex(StructuralError,'differs from authored'):
            enforce_entry([row],False,bases=bases)
        paragraphs[review]['citations']={name}
        with self.assertRaisesRegex(StructuralError,'duplicate authored'):
            entry_bases(paragraphs,{name})
        paragraphs[review]['citations']=set(); paragraphs[executed]['citations']=set()
        with self.assertRaisesRegex(StructuralError,'omit an entry'):
            entry_bases(paragraphs,{name})

    def test_bite_one_entry(self):
        """Claim: Either a records directory or a renamed pn-records member activates the complete entry register; missing owner, evidence kind, basis or admission cannot be bypassed by a passing test status.
        ´claim:testing:bite-one-entry-holds-block-implementation´
        ´test:integration:test-bite-one-entry´
        """
        from claims import enforce_entry, bite_one_started
        row=dict(name='ROOT::req:testing:fixture',entry_gate='ROOT::gate:design:bite-1',status='scoped-passed',owner='reviewer',admission_basis='executed',admission=dict(owner='reviewer',evidence_kind='contract review',status='held'))
        enforce_entry([row],False)
        with self.assertRaisesRegex(StructuralError,'bite-1 entry evidence remains held'):
            enforce_entry([row],True)
        for key in ('owner','evidence_kind'):
            invalid=deepcopy(row);invalid['admission'].pop(key)
            with self.assertRaises(StructuralError):enforce_entry([invalid],False)
        for basis in (None,'inferred'):
            invalid=deepcopy(row);invalid['admission_basis']=basis
            with self.assertRaisesRegex(StructuralError,'declared admission basis'):enforce_entry([invalid],False)
        with self.assertRaisesRegex(StructuralError,'entry register differs'):
            enforce_entry([],False,{row['name']})
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'Cargo.toml').write_text('[workspace]\nmembers=["renamed"]\n')
            (root/'renamed').mkdir()
            (root/'renamed/Cargo.toml').write_text('[package]\nname="pn-records"\n')
            self.assertTrue(bite_one_started(root))
            (root/'renamed/Cargo.toml').write_text('[package]\nname="other"\n')
            self.assertFalse(bite_one_started(root))
            (root/'packages/records').mkdir(parents=True)
            self.assertTrue(bite_one_started(root))

    def test_review_admission(self):
        """Claim: A review-basis entry clears only with its owner's admitted, resolving amendment, without inventing executable claims for a review fact; absent admission or an unrelated evidence label refuses entry.
        ´claim:testing:review-admission-requires-resolving-evidence´
        ´test:integration:test-review-admission´
        """
        from claims import enforce_entry
        name='ROOT::gate:testing:fixture';label='ROOT::amend:testing:admission'
        paragraphs={label:dict(citations={name})}
        row=dict(name=name,entry_gate='ROOT::gate:design:bite-1',status="held",claims=[],owner='reviewer',admission_basis='review',admission=dict(owner='reviewer',evidence_kind='fixture evidence',status='admitted',evidence=label))
        self.assertEqual(enforce_entry([row],True,paragraphs=paragraphs)[0]['status'],'clear')
        for status in ('held','submitted'):
            invalid=deepcopy(row);invalid['admission']['status']=status
            with self.assertRaisesRegex(StructuralError,'remains held'):enforce_entry([invalid],True,paragraphs=paragraphs)
        for evidence in ('ROOT::amend:testing:missing','review round outside the tree',''):
            invalid=deepcopy(row);invalid['admission']['evidence']=evidence
            with self.assertRaises(StructuralError):enforce_entry([invalid],True,paragraphs=paragraphs)
        with self.assertRaisesRegex(StructuralError,'does not resolve'):
            enforce_entry([row],True,paragraphs={label:dict(citations=set())})

    def test_executed_admission(self):
        """Claim: An executed-basis entry clears only with its owner's admitted, resolving amendment, and current scoped execution support; absent admission or an unrelated evidence label refuses entry.
        ´claim:testing:executed-admission-requires-resolving-evidence´
        ´test:integration:test-executed-admission´
        """
        from claims import enforce_entry
        name='ROOT::gate:testing:fixture';label='ROOT::amend:testing:admission'
        paragraphs={label:dict(citations={name})}
        row=dict(name=name,entry_gate='ROOT::gate:design:bite-1',status="scoped-passed",claims=[],owner='reviewer',admission_basis='executed',admission=dict(owner='reviewer',evidence_kind='fixture evidence',status='admitted',evidence=label))
        self.assertEqual(enforce_entry([row],True,paragraphs=paragraphs)[0]['status'],'clear')
        for status in ('held','submitted'):
            invalid=deepcopy(row);invalid['admission']['status']=status
            with self.assertRaisesRegex(StructuralError,'remains held'):enforce_entry([invalid],True,paragraphs=paragraphs)
        for evidence in ('ROOT::amend:testing:missing','review round outside the tree',''):
            invalid=deepcopy(row);invalid['admission']['evidence']=evidence
            with self.assertRaises(StructuralError):enforce_entry([invalid],True,paragraphs=paragraphs)
        with self.assertRaisesRegex(StructuralError,'does not resolve'):
            enforce_entry([row],True,paragraphs={label:dict(citations=set())})
        for status in ('held','failed'):
            invalid=deepcopy(row);invalid['status']=status
            with self.assertRaisesRegex(StructuralError,'remains held'):enforce_entry([invalid],True,paragraphs=paragraphs)

    def test_shared_failure(self):
        """A failing sibling defeats the shared claim and its obligation despite another passing execution.
        ´claim:testing:sibling-failure-dominates´
        ´test:integration:test-shared-failure´
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
        ´test:integration:test-stale-result´
        """
        for key in ('source','configuration'):
            data=fixture(); data['results'][0][key]='other'
            with self.assertRaisesRegex(StructuralError,'stale result'): evaluate(**data)

    def test_missing_area(self):
        """Removing an owner's risk register leaves its minted claims structurally unaccounted.
        ´claim:testing:area-stakes-required´
        ´test:integration:test-missing-area´
        """
        data=fixture(); data['areas']=[]
        with self.assertRaisesRegex(StructuralError,'missing or stale claim area'): evaluate(**data)

    def test_removed_obligation(self):
        """Deleting a register row cannot erase an obligation still minted in checked prose.
        ´claim:testing:source-obligations-cannot-disappear´
        ´test:integration:test-removed-obligation´
        """
        data=fixture(); data['declared']=[]
        with self.assertRaisesRegex(StructuralError,'source obligation'): evaluate(**data)

    def test_planned_name(self):
        """A planned claim name with no test-site mint cannot support a passing obligation.
        ´claim:testing:planned-names-are-not-evidence´
        ´test:integration:test-planned-name´
        """
        data=fixture(); data['declared'][0]['claims']=['ROOT::claim:testing:future']
        with self.assertRaisesRegex(StructuralError,'planned name'): evaluate(**data)

    def test_undeclared_site(self):
        """An executable source site omitted from the harness inventory is a structural error.
        ´claim:testing:every-source-site-is-declared´
        ´test:integration:test-undeclared-site´
        """
        data=fixture(); data['expected_sites'].remove('sibling')
        with self.assertRaisesRegex(StructuralError,'undeclared or omitted source site'): evaluate(**data)

    def test_missing_results_and_mints(self):
        """Missing executions and unresolved or duplicate claim mints cannot pass coverage.
        ´claim:testing:complete-executions-and-unique-mints´
        ´test:integration:test-missing-results-and-mints´
        """
        data=fixture(); data['results'].pop()
        with self.assertRaisesRegex(StructuralError,'missing test results'): evaluate(**data)
        for value in (False,True):
            data=fixture(); data['sites'][0 if not value else 1]['mint']=value
            with self.assertRaisesRegex(StructuralError,'unresolved or duplicate'): evaluate(**data)

    def test_uncited_evidence_and_holds(self):
        """A data-only coverage edge and an unowned hold both refuse invented completion.
        ´claim:testing:cited-evidence-or-owned-holds´
        ´test:integration:test-uncited-evidence-and-holds´
        """
        data=fixture(); data['paragraphs']['ROOT::amend:testing:fixture-evidence']['citations']=set()
        with self.assertRaisesRegex(StructuralError,'uncited evidence'): evaluate(**data)
        data=fixture(); data['declared'][0].update(status='held',claims=[])
        with self.assertRaisesRegex(StructuralError,'hold lacks owner'): evaluate(**data)

    def test_requirement_edges(self):
        """A requirement retains every source-cited realizer and inherits a failing realizer's verdict.
        ´claim:testing:requirement-edges-are-complete´
        ´test:integration:test-requirement-edges´
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
        ´test:integration:test-respellings´
        """
        self.assertTrue(respells(dict(function='test_retains_identity',gloss='Claim: Retains identity.')))
        self.assertFalse(respells(dict(function='test_retains_identity',gloss='A renamed implementation retains its identity in every joined result.')))

    def test_orphan_mint(self):
        """A source claim detached from all executable sites cannot disappear from the reverse coverage query.
        ´claim:testing:orphan-mints-are-refused´
        ´test:integration:test-orphan-mint´
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
        ´test:integration:test-enforcement-switch´
        """
        data=fixture()
        evidence=data['paragraphs']['ROOT::amend:testing:fixture-evidence']
        evidence['citations'].remove('ROOT::claim:testing:fixture')
        evidence['citations'].add('ROOT::claim:testing:fixture'); evidence['exhibits']=set()
        sites=[]
        for i,name in enumerate(('first','sibling')):
            carrier='´claim:testing:fixture´' if i==0 else '(´claim:testing:fixture´)'
            gloss='Claim: First.' if i==0 else 'Claim: The second execution checks the same fixture predicate.'
            sites.append(dict(operation=name,owner='ROOT',function=name,path='ci/test_claims.py',
                              line=i+1,language='python',property=False,
                              doc=gloss+'\n'+carrier+'\n´test:integration:'+name+'´'))
        records=[dict(r,scope='case',configuration=CONFIGURATION) for r in data['results']]
        registry=SimpleNamespace(cases={n:dict(runner='ci') for n in ('first','sibling')},matrix=lambda *_:None)
        data['paragraphs']['ROOT::amend:decomposition:bite-one-entry-evidence']={'citations':set()}
        for basis in ('review','executed'):
            data['paragraphs']['ROOT::amend:decomposition:entry-'+basis+'-basis']={'citations':set()}
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            previous=Path.cwd()
            stack.callback(os.chdir,previous)
            os.chdir(directory)
            for name in ('.lane','ci','docs/inputs'): Path(name).mkdir(parents=True,exist_ok=True)
            for name,rows in (('claim-areas',data['areas']),('claim-obligations',data['declared'])):
                Path('docs/inputs/'+name+'.toml').write_text('\n'.join(
                    '[[rows]]\n'+'\n'.join(key+' = '+json.dumps(value) for key,value in row.items()) for row in rows))
            Path('Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            Path('.lane/performance-events.jsonl').write_text('\n'.join(json.dumps(r) for r in records)+'\n')
            Path('.lane/harness-benchmarks.jsonl').write_text('')
            Path('ci/claim_review.json').write_text('{"schema":1,"sites":[]}')
            Path('ci/claim_gloss_baseline.json').write_text(json.dumps({'schema':1,'glosses':{s['operation']:site_claim(s)['gloss'] for s in sites}}))
            Path('.lane/observation-coverage.json').write_text('{"source":"current","mechanical_status":"passed"}')
            for name,value in (('load_registry',registry),('census',sites),
                               ('claim_mints',{}),('checked_linter',None),
                               ('prose',(data['paragraphs'],data['obligations'])),('source_id','current')):
                stack.enter_context(patch('claims.'+name,return_value=value))
            with redirect_stdout(io.StringIO()):
                with patch('wallet_cases.repository_check', return_value=None):
                    self.assertEqual(main([]),0)
                    self.assertEqual(main(['--fail-respellings']),1)
            self.assertEqual(len(json.loads(Path('.lane/claim-respellings.json').read_text())['offenders']),1)

    def test_review_binding(self):
        """A review must identify an existing unique site and its current claim and gloss, preventing stale audit entries from being counted.
        ´claim:testing:review-is-bound-to-current-site´
        ´test:integration:test-review-binding´
        """
        site=dict(operation='first',path='fixture.rs',claim='ROOT::claim:testing:fixture',gloss='The asserted fixture consequence.')
        row=dict(operation='first',path=site['path'],claim=site['claim'],before='First.',after=site['gloss'],review='Compared the fixture assertion and premise.')
        self.assertEqual(reviewed_sites([site],dict(schema=1,sites=[row])),[row])
        for key,value in (('operation','missing'),('path','other.rs'),('claim','ROOT::claim:testing:other'),('after','Old wording.')):
            with self.assertRaises(StructuralError): reviewed_sites([site],dict(schema=1,sites=[dict(row,**{key:value})]))
        with self.assertRaises(StructuralError): reviewed_sites([site],dict(schema=1,sites=[row,row]))

    def test_python_exhibits(self):
        """Evidence requires checked citations for both carriers; an exhibited known or unknown claim cannot establish support, while planned names outside evidence remain harmless.
        ´claim:testing:evidence-exhibits-cannot-claim-support´
        ´test:integration:test-python-exhibits´
        """
        for language in ('rust','python'):
            data=fixture()
            for site in data['sites']:site['language']=language
            self.assertEqual(evaluate(**data)['obligations'][0]['status'],'scoped-passed')
            evidence=data['paragraphs']['ROOT::amend:testing:fixture-evidence']
            for name in ('ROOT::claim:testing:fixture','ROOT::claim:testing:unknown'):
                evidence['exhibits']={name}
                with self.assertRaisesRegex(StructuralError,'evidence exhibits cannot claim support'):evaluate(**data)

    def test_unknown_evidence_edge(self):
        """An unknown data edge refuses even beside valid Python evidence, and removing the matching citation cannot leave a supported row.
        ´claim:testing:python-edges-require-known-claims´
        ´test:integration:test-unknown-evidence-edge´
        """
        data=fixture(); claim='ROOT::claim:testing:fixture'
        for site in data['sites']: site['language']='python'
        evidence=data['paragraphs']['ROOT::amend:testing:fixture-evidence']
        self.assertEqual(evaluate(**data)['obligations'][0]['status'],'scoped-passed')
        data['declared'][0]['claims'].append('ROOT::claim:testing:unknown')
        with self.assertRaisesRegex(StructuralError,'unresolved claim presented as evidence'): evaluate(**data)
        data['declared'][0]['claims']=[claim]; evidence['citations'].remove(claim)
        with self.assertRaisesRegex(StructuralError,'uncited evidence'): evaluate(**data)

    def test_source_carriers(self):
        """Strings cannot invent Rust tests, while property macro doc attributes retain their claim and review bindings outside the deployed Rust profile.
        ´claim:testing:source-carriers-are-lexically-checked´
        ´test:integration:test-source-carriers´
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
    def test_planned_census(self):
        """An exhibited future name in a design paragraph is neither a minted claim nor a new obligation.
        ´claim:testing:exhibited-names-stay-out-of-census´
        ´test:integration:test-planned-census´
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
        ´test:integration:test-reverse-evidence-edges´
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
        ´test:integration:test-required-gloss-reviews´
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
