"""Controlled evidence graphs exercise structural and predicate failures."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from claims import evaluate, prose, respells, reconcile_mints, site_claim
from devperf import StructuralError


def fixture():
    claim = 'ROOT::claim:testing:fixture'
    obligation = 'ROOT::gate:testing:fixture'
    area = 'ROOT::sec:testing:fixture-area'
    evidence = 'ROOT::amend:testing:fixture-evidence'
    sites = [dict(operation=n, owner='ROOT', area='testing', claim=claim, mint=i==0)
             for i,n in enumerate(('first', 'sibling'))]
    paragraphs = {area: dict(text='Losing cases hides failures.', citations=set()),
                  evidence: dict(text='', citations={claim,obligation})}
    return dict(sites=sites, expected_sites={'first','sibling'},
                areas=[dict(owner='ROOT', area='testing', stake='Losing cases hides failures.', register=area, contract=area)],
                obligations={obligation:dict(path='fixture.md',citations=set())},
                declared=[dict(name=obligation,path='fixture.md',status='supported',claims=[claim],realizers=[],evidence_paragraph=evidence,premises='Both declared fixture executions in the fixed configuration.')],
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
        self.assertEqual(evaluate(**data)['obligations'][0]['status'],'passed')
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


if __name__=='__main__':
    unittest.main()
