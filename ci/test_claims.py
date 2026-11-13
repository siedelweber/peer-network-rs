"""Controlled evidence graphs exercise structural and predicate failures."""

from copy import deepcopy
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from claims import check_register, register_form, evaluate, main, prose, respells, reconcile_mints, reviewed_sites, site_claim
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
    def test_register_canonical_form(self):
        """Claim: Unsorted, duplicate or non-canonical claim registers refuse before evidence evaluation without rewriting, while the explicit canonicalizer preserves entries, reaches a byte-stable form and reports its wall time on success and refusal.
        ´claim:testing:register-order-and-form-are-checked´
        ´test:integration:test-register-canonical-form´
        """
        first = dict(operation='alpha', path='fixture.py', claim='ROOT::claim:testing:fixture', before='Before.', after='An accented é remains intact.', review='Read the assertion.')
        second = first | {'operation': 'zeta'}
        review = dict(schema=1, sites=[first, second])
        baseline = dict(schema=1, glosses={'alpha': 'Before.', 'zeta': 'Before.'})
        formatted = {name: register_form(json.dumps(data), field)[2] for name, field, data in (
            ('ci/claim_review.json', 'sites', review), ('ci/claim_gloss_baseline.json', 'glosses', baseline))}
        self.assertEqual(check_register(formatted['ci/claim_review.json'], 'sites'), review)
        witnessed = deepcopy(review)
        witnessed['sites'][0]['witness_identity'] = dict(recipe='same-file-case-closure/v1', function='alpha', digest='a'*64)
        witnessed['sites'][0]['paper_witnesses'] = {'def:testing:fixture': 'The independent expected output changes when the tested rule fails.'}
        canonical = register_form(json.dumps(witnessed), 'sites')[2]
        self.assertEqual(check_register(canonical, 'sites'), witnessed)
        witnessed['sites'][0]['paper_witnesses']['def:testing:fixture'] = ''
        with self.assertRaisesRegex(StructuralError, 'failure assessment'):
            register_form(json.dumps(witnessed), 'sites')
        self.assertEqual(check_register(formatted['ci/claim_gloss_baseline.json'], 'glosses'), baseline)
        invalid = [
            ('ci/claim_review.json', json.dumps(review | {'sites': [second, first]}), 'order: entry zeta'),
            ('ci/claim_gloss_baseline.json', json.dumps(dict(schema=1, glosses={'zeta': 'Before.', 'alpha': 'Before.'})), 'order: entry zeta'),
            ('ci/claim_review.json', json.dumps(review | {'sites': [first, second, first | {'path': 'other.py'}]}), 'duplicate register operation: alpha'),
            ('ci/claim_review.json', json.dumps(review), 'serialization: entry <root>'),
            ('ci/claim_review.json', formatted['ci/claim_review.json'].replace('      "path"', '       "path"'), 'serialization: entry alpha'),
            ('ci/claim_review.json', json.dumps(review, ensure_ascii=True, indent=2)+'\n', 'serialization: entry alpha'),
            ('ci/claim_review.json', formatted['ci/claim_review.json'].replace('\n', '\r\n'), 'serialization'),
            ('ci/claim_review.json', formatted['ci/claim_review.json'].rstrip('\n'), 'serialization'),
            ('ci/claim_review.json', json.dumps({'sites': review['sites'], 'schema': 1}, ensure_ascii=False, indent=2)+'\n', 'serialization'),
            ('ci/claim_review.json', json.dumps(review | {'sites': [dict(reversed(list(first.items()))), second]}, ensure_ascii=False, indent=2)+'\n', 'serialization: entry alpha'),
            ('ci/claim_gloss_baseline.json', '{"schema":1,"glosses":{"alpha":"one","alpha":"two"}}', 'duplicate register member: alpha'),
            ('ci/claim_review.json', '{"schema":1,"sites":[],}', 'ci/claim_review.json:'),
        ]
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            previous = Path.cwd()
            stack.callback(os.chdir, previous)
            os.chdir(directory)
            Path('ci').mkdir()
            for path, text in formatted.items():
                Path(path).write_bytes(text.encode('utf-8'))
            for path, text, diagnostic in invalid:
                with self.subTest(path=path, diagnostic=diagnostic):
                    Path(path).write_bytes(text.encode('utf-8'))
                    before = {name: Path(name).read_bytes() for name in formatted}
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors), patch('claims.load_registry') as downstream:
                        self.assertEqual(main(['--fail-respellings']), 2)
                        downstream.assert_not_called()
                    self.assertIn(diagnostic, errors.getvalue())
                    self.assertEqual(before, {name: Path(name).read_bytes() for name in formatted})
                    Path(path).write_bytes(formatted[path].encode('utf-8'))
            # A valid but differently ordered/formatted pair is edited only by
            # the explicit command, with all semantic entries preserved.
            Path('ci/claim_review.json').write_text(json.dumps(review | {'sites': [second, first]}))
            Path('ci/claim_gloss_baseline.json').write_text(json.dumps(dict(schema=1, glosses={'zeta': 'Before.', 'alpha': 'Before.'})))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(['canonicalize', 'ci/claim_review.json']), 0)
                self.assertEqual(main(['canonicalize']), 0)
            for path, text in formatted.items():
                self.assertEqual(Path(path).read_bytes(), text.encode('utf-8'))
            stamps = {path: Path(path).stat().st_mtime_ns for path in formatted}
            output = io.StringIO()
            with redirect_stdout(output), patch('claims.time.monotonic', side_effect=[10.0, 10.25]):
                self.assertEqual(main(['canonicalize']), 0)
            self.assertIn('CLAIM-CANONICALIZE wall=0.250000s', output.getvalue())
            self.assertEqual(stamps, {path: Path(path).stat().st_mtime_ns for path in formatted})
            # A later invalid file prevents any earlier selected write.
            Path('ci/claim_review.json').write_text(json.dumps(review))
            Path('ci/claim_gloss_baseline.json').write_text('{"schema":1,"glosses":{"alpha":"one","alpha":"two"}}')
            before = {path: Path(path).read_bytes() for path in formatted}
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()), patch('claims.time.monotonic', side_effect=[20.0, 20.5]):
                self.assertEqual(main(['canonicalize']), 2)
            self.assertIn('CLAIM-CANONICALIZE wall=0.500000s', output.getvalue())
            self.assertEqual(before, {path: Path(path).read_bytes() for path in formatted})

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

    def test_portion_citations(self):
        """Claim: A declared paper portion or premise retains its clause as attention without lifting a held or unassigned statement, while an independent plain citation still designs it and malformed or unknown attention citations refuse.
        ´claim:testing:portion-citations-cannot-design´
        ´test:integration:test-portion-citations´
        """
        from claims import tracker_rows, tracker_sentences
        label = 'def:testing:fixture'
        record = 'ROOT::alg:testing:fixture'
        hold = 'ROOT::open:testing:fixture'
        inventory = [dict(label=label, crate='pn-records', kind='type')]
        evidence = dict(claims=[], obligations=[])
        text = 'The local rule covers portion{``'+label+'``; local admission, e.g. ordering}.'
        partial = {record: dict(text=text, citations=set())}
        row = tracker_rows(inventory, partial, evidence, [])[0]
        self.assertEqual(row['status'], 'unassigned')
        self.assertEqual(row['records'], [])
        self.assertEqual(row['routes'], [])
        self.assertEqual(row['portions'], [dict(record=record, clause='local admission, e.g. ordering')])
        self.assertEqual(list(tracker_sentences(text)), [text])
        for form in ('relies', 'realizes'):
            marked = form+'{``'+label+'``; the precisely named part}'
            projected = tracker_rows(inventory, {record: dict(text=marked, citations=set())}, evidence, [])[0]
            self.assertEqual(projected['status'], 'unassigned')
            self.assertEqual(projected['records'], [])
            self.assertEqual(projected['routes'], [])
            self.assertEqual(list(tracker_sentences(marked)), [marked])
        partial[hold] = dict(text='``'+label+'``', citations=set())
        held = dict(claims=[], obligations=[dict(name=hold, status='held', claims=[], hold=hold)])
        attention = tracker_rows(inventory, {hold: dict(text=text, citations=set())}, held, [])[0]
        self.assertEqual(attention['status'], 'unassigned')
        self.assertEqual(attention['holds'], [])
        self.assertEqual(attention['records'], [])
        self.assertEqual(attention['portions'], [dict(record=hold, clause='local admission, e.g. ordering')])
        self.assertEqual(tracker_rows(inventory, partial, held, [])[0]['status'], 'held')
        partial[record]['text'] += ' The whole ``'+label+'`` is designed separately.'
        self.assertEqual(tracker_rows(inventory, partial, held, [])[0]['status'], 'designed')
        claim = 'ROOT::claim:testing:fixture'
        scope = 'ROOT::gate:testing:fixture'
        executed = dict(claims=[dict(name=claim, status='passed')],
                        obligations=[dict(name=scope, status='scoped-passed', claims=[claim])])
        whole = {record: dict(text='Design the whole ``'+label+'``. The narrower consumer is checked by ``claim:testing:fixture``.', citations=set())}
        designed = tracker_rows(inventory, whole, executed, [])[0]
        self.assertEqual(designed['status'], 'designed')
        self.assertEqual(designed['portions'], [])
        self.assertEqual(designed['routes'], [])
        self.assertEqual(designed['record_routes'], [dict(kind='record', record=record, scope=scope)])
        for malformed in ('portion{``'+label+'``}', 'portion{``'+label+'``; }',
                          'portion{``def:testing:absent``; local admission}'):
            with self.subTest(malformed=malformed), self.assertRaises(StructuralError):
                tracker_rows(inventory, {record: dict(text=malformed, citations=set())}, evidence, [])
        premise = 'Rely on premise{``'+label+'``; the consumer needs this, e.g. ordering} with ``claim:testing:fixture``.'
        for support in (evidence, executed):
            records = {record: dict(text=premise, citations=set())}
            row = tracker_rows(inventory, records, support, [])[0]
            self.assertEqual(row['status'], 'unassigned')
            self.assertEqual(row['records'], [])
            self.assertEqual(row['routes'], [])
            self.assertEqual(row['record_routes'], [])
            self.assertEqual(row['portions'], [dict(record=record, clause='Premise only: the consumer needs this, e.g. ordering')])
            self.assertEqual(list(tracker_sentences(premise)), [premise])
            records[hold] = dict(text='``'+label+'``', citations=set())
            held_support = deepcopy(support)
            held_support['obligations'].append(dict(name=hold, status='held', claims=[], hold=hold))
            self.assertEqual(tracker_rows(inventory, records, held_support, [])[0]['status'], 'held')
            records[record]['text'] += ' Independently design ``'+label+'``.'
            self.assertEqual(tracker_rows(inventory, records, held_support, [])[0]['status'], 'designed')
        for malformed in ('premise{``'+label+'``}', 'premise{``'+label+'``; }',
                          'premise{``def:testing:absent``; assumed ordering}'):
            with self.subTest(malformed=malformed), self.assertRaises(StructuralError):
                tracker_rows(inventory, {record: dict(text=malformed, citations=set())}, evidence, [])

    def test_executed_admission(self):
        """Claim: An executed-basis entry clears only with its owner's admitted, resolving amendment, and current scoped execution support; absent admission or an unrelated evidence label refuses entry.
        ´claim:testing:executed-admission-requires-resolving-evidence´
        ´test:integration:test-executed-admission´
        """
        from claims import enforce_entry
        from claims import tracker_rows
        record = 'ROOT::alg:testing:fixture'
        claim = 'ROOT::claim:testing:fixture'
        scope = 'ROOT::gate:testing:fixture'
        hold = 'ROOT::open:testing:fixture'
        inventory = [dict(label='def:testing:fixture', crate='pn-records', kind='type')]
        records = {record: dict(text='``def:testing:fixture``', citations=set())}
        execution = dict(claims=[dict(name=claim, status='passed')],
                         obligations=[dict(name=scope, status='scoped-passed', claims=[claim])],
                         sites=[dict(claim=claim, owner='ROOT', doc='(´alg:testing:fixture´)')])
        bites = [dict(ordinal=1, contracts=['alg:testing:fixture'], requirements=[])]
        projected = tracker_rows(inventory, records, execution, bites)[0]
        self.assertEqual(projected['status'], 'realized')
        self.assertEqual(projected['routes'], [dict(kind='site-claim', record=record, claim=claim, scope=scope)])
        self.assertEqual(projected['bites'], [1])
        removed = deepcopy(execution)
        removed['sites'] = []
        self.assertEqual(tracker_rows(inventory, records, removed, bites)[0]['status'], 'designed')
        failed = deepcopy(execution)
        failed['claims'][0]['status'] = 'failed'
        self.assertEqual(tracker_rows(inventory, records, failed, bites)[0]['status'], 'designed')
        execution['obligations'].append(dict(name=record, status='held', claims=[], hold=hold))
        self.assertEqual(tracker_rows(inventory, records, execution, bites)[0]['status'], 'realized')
        execution['sites'] = []
        self.assertEqual(tracker_rows(inventory, records, execution, bites)[0]['status'], 'held')
        records['ROOT::alg:testing:other'] = dict(text='``def:testing:fixture``', citations=set())
        self.assertEqual(tracker_rows(inventory, records, execution, bites)[0]['status'], 'designed')
        self.assertEqual(tracker_rows(inventory, {}, execution, bites)[0]['status'], 'unassigned')
        paper = {record: dict(text='', citations={'PAPER::def:testing:fixture'})}
        self.assertEqual(tracker_rows(inventory, paper, dict(claims=[], obligations=[]), bites)[0]['status'], 'designed')
        paper[record]['citations'] = {'PAPER::def:testing:fixture-extra'}
        self.assertEqual(tracker_rows(inventory, paper, dict(claims=[], obligations=[]), bites)[0]['status'], 'unassigned')
        paper[record] = dict(path='docs/design/progress.md', text='``def:testing:fixture``', citations=set())
        self.assertEqual(tracker_rows(inventory, paper, dict(claims=[], obligations=[]), bites)[0]['status'], 'unassigned')
        named_hold = {hold: dict(text='``def:testing:fixture``', citations=set())}
        self.assertEqual(tracker_rows(inventory, named_hold, execution, bites)[0]['status'], 'held')
        short = [dict(label='sec:testing', crate='none', kind='none')]
        paper = {record: dict(text='(`[PAPER-sec:testing]`)', citations=set())}
        self.assertEqual(tracker_rows(short, paper, dict(claims=[], obligations=[]), bites)[0]['status'], 'designed')
        obligation_records = {scope: dict(text='``def:testing:fixture``', citations=set())}
        edge = dict(claims=[dict(name=claim, status='passed')],
                    obligations=[dict(name=scope, status='scoped-passed', claims=[claim], witnessed_labels=['def:testing:fixture'])])
        witnesses = {claim: {'def:testing:fixture': 'The fixture assertion detects a changed output, not its retained premise.'}}
        self.assertEqual(tracker_rows(inventory, obligation_records, edge, bites, witnesses=witnesses)[0]['routes'],
                         [dict(kind='obligation', record=scope, scope=scope)])
        both = {scope: dict(text='``def:testing:fixture`` uses the premise ``def:testing:premise``.', citations=set())}
        pair = inventory+[dict(inventory[0], label='def:testing:premise')]
        self.assertEqual([row['status'] for row in tracker_rows(pair, both, edge, bites, witnesses=witnesses)],
                         ['realized', 'designed'])
        overclaim = deepcopy(edge)
        overclaim['obligations'][0]['witnessed_labels'].append('def:testing:premise')
        with self.assertRaisesRegex(StructuralError, 'lacks reviewed failure-sensitive claim'):
            tracker_rows(pair, both, overclaim, bites, witnesses=witnesses)
        with self.assertRaisesRegex(StructuralError, 'lacks reviewed failure-sensitive claim'):
            tracker_rows(inventory, obligation_records, edge, bites)
        extra = deepcopy(edge)
        extra['claims'].append(dict(name=claim+'-other', status='passed'))
        extra['obligations'][0]['claims'].append(claim+'-other')
        self.assertEqual(tracker_rows(inventory, obligation_records, edge, bites, witnesses=witnesses),
                         tracker_rows(inventory, obligation_records, extra, bites, witnesses=witnesses))
        extra['claims'][1]['status'] = 'failed'
        self.assertEqual(tracker_rows(inventory, obligation_records, extra, bites, witnesses=witnesses)[0]['status'], 'designed')
        extra['obligations'][0].update(status='held', hold=hold)
        self.assertEqual(tracker_rows(inventory, obligation_records, extra, bites, witnesses=witnesses)[0]['status'], 'held')
        edge['obligations'][0]['witnessed_labels'] = []
        mentions = {record: dict(text='``def:testing:fixture`` is witnessed by (`claim:testing:fixture`).', citations={claim})}
        self.assertEqual(tracker_rows(inventory, mentions, edge, bites)[0]['routes'],
                         [dict(kind='record-claim', record=record, claim=claim, scope=scope)])
        mentions[record].update(citations=set(), exhibits={claim}, text='``def:testing:fixture`` is witnessed by ``claim:testing:fixture``.')
        self.assertEqual(tracker_rows(inventory, mentions, edge, bites)[0]['status'], 'realized')
        for boundary in ('. ', '? ', '! ', '\n', ', e.g. ', ', i.e. '):
            separate = {record: dict(text='Design ``def:testing:fixture``'+boundary+'Evidence ``claim:testing:fixture``.', citations=set())}
            row = tracker_rows(inventory, separate, edge, bites)[0]
            self.assertEqual(row['status'], 'designed')
            self.assertEqual(row['routes'], [])
            self.assertEqual(row['record_routes'], [dict(kind='record', record=record, scope=scope)])
            self.assertEqual(row['record_granular'], 1)
        shared = {record: dict(text='``def:testing:fixture`` uses `x. y` with ``claim:testing:fixture``.', citations=set())}
        self.assertEqual(tracker_rows(inventory, shared, edge, bites)[0]['status'], 'realized')
        retained = {record: dict(text='The consumer retains ``def:testing:fixture`` as a premise. Endpoint composition is checked by ``claim:testing:fixture``.', citations=set())}
        premise = tracker_rows(inventory, retained, edge, bites)[0]
        self.assertEqual(premise['status'], 'designed')
        self.assertEqual(premise['routes'], [])
        self.assertEqual(premise['record_routes'], [dict(kind='record', record=record, scope=scope)])
        attention_support = {'ROOT::open:testing:fixture': separate[record]}
        attention_row = tracker_rows(inventory, attention_support, edge, bites)[0]
        self.assertEqual(attention_row['status'], 'designed')
        self.assertEqual((attention_row['tentative'], attention_row['record_granular']), (1, 1))
        self.assertEqual(attention_row['routes'], [])
        self.assertEqual(len(attention_row['record_routes']), 1)
        two = deepcopy(edge)
        two['claims'].append(dict(name=claim+'-other', status='passed'))
        two['obligations'][0]['claims'].append(claim+'-other')
        paired = {record: dict(text='``def:testing:fixture`` has ``claim:testing:fixture``. ``def:testing:other`` has ``claim:testing:fixture-other``.', citations=set())}
        rows = tracker_rows(inventory+[dict(inventory[0], label='def:testing:other')], paired, two, bites)
        self.assertEqual([row['routes'][0]['claim'] for row in rows], [claim, claim+'-other'])
        self.assertTrue(all(row['status'] == 'realized' and row['record_granular'] == 0 for row in rows))
        from build_graph_evidence import SERVICE_CASE
        for state in ('passed', 'held'):
            selected = deepcopy(two)
            selected['claims'][1]['status'] = state
            selected['obligations'][0]['status'] = 'scoped-passed' if state == 'passed' else 'held'
            selected['sites'] = [dict(operation=SERVICE_CASE, claim=claim+'-other', owner='ROOT', doc='')]
            with self.assertRaisesRegex(StructuralError, 'selectable service evidence'):
                tracker_rows(inventory, shared, selected, bites)
            selected['obligations'].append(dict(name=record, status='held', claims=[], realizers=[scope]))
            with self.assertRaisesRegex(StructuralError, 'selectable service evidence'):
                tracker_rows(inventory, records, selected, bites)
        checklist = {record: dict(text='Outstanding ``def:testing:fixture``.', citations={'ROOT::conv:progress:outstanding-work'})}
        self.assertEqual(tracker_rows(inventory, checklist, edge, bites)[0]['tentative'], 1)
        checklist[scope] = dict(text='``def:testing:fixture``', citations=set())
        held_edge = deepcopy(edge)
        held_edge['obligations'][0].update(status='held', hold=hold)
        self.assertEqual(tracker_rows(inventory, checklist, held_edge, bites)[0]['status'], 'held')
        mentions[record].update(exhibits=set(), text='``def:testing:fixture`` ``claim:testing:fixture``')
        remote = deepcopy(edge)
        remote['claims'][0]['name'] = 'GRAPH::claim:testing:fixture'
        remote['obligations'][0]['claims'] = ['GRAPH::claim:testing:fixture']
        self.assertEqual(tracker_rows(inventory, mentions, remote, bites)[0]['routes'][0]['claim'],
                         'GRAPH::claim:testing:fixture')
        remote['claims'].append(dict(name=claim, status='passed'))
        with self.assertRaisesRegex(StructuralError, 'ambiguous tracker claim exhibit'):
            tracker_rows(inventory, mentions, remote, bites)
        for state in ('failed', 'held'):
            unavailable = deepcopy(edge)
            unavailable['claims'][0]['status'] = state
            self.assertEqual(tracker_rows(inventory, mentions, unavailable, bites)[0]['status'], 'designed')
        constants = [dict(id='const.fixture.value', cites=inventory[0]['label'])]
        plan = [dict(ordinal=2, labels=[inventory[0]['label']])]
        carried = tracker_rows(inventory, {}, edge, bites, constants, plan)[0]
        self.assertEqual(carried['records'], ['CONSTANTS::const.fixture.value'])
        self.assertEqual(carried['status'], 'designed')
        self.assertEqual(carried['bites'], [2])
        constants[0]['cites'] += '-other'
        self.assertEqual(tracker_rows(inventory, {}, edge, bites, constants, plan)[0]['status'], 'unassigned')
        for kind in ('open', 'obs'):
            tentative = {'ROOT::'+kind+':testing:fixture': dict(text='``def:testing:fixture``', citations=set())}
            self.assertEqual(tracker_rows(inventory, tentative, edge, bites)[0]['tentative'], 1)
            tentative.update(mentions)
            self.assertEqual(tracker_rows(inventory, tentative, edge, bites)[0]['tentative'], 0)
        from claims import tracker_elsewhere
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = root/'other.txt'
            unassigned = [dict(label='def:testing:fixture', status='unassigned')]
            with patch('build_graph.tracked', return_value=['other.txt']):
                for spelling in ('def:testing:fixture', '[PAPER-def:testing:fixture]', 'PAPER::def:testing:fixture'):
                    text.write_text(spelling)
                    self.assertEqual(tracker_elsewhere(root, unassigned), {'def:testing:fixture': ['other.txt']})
                text.write_text('def:testing:fixture-extra')
                self.assertEqual(tracker_elsewhere(root, unassigned), {})
            with patch('build_graph.tracked', return_value=['docs/design/inventory.md', 'docs/design/progress.md']):
                self.assertEqual(tracker_elsewhere(root, unassigned), {})
            (root/'docs/inputs').mkdir(parents=True)
            (root/'docs/datasets').mkdir()
            (root/'adr').mkdir()
            carrier = root/'docs/inputs/deployment-claims.toml'
            carrier.write_text('rows=[{name="def:testing:fixture", reason="Scope only"}]')
            dataset = root/'docs/datasets/org.peer-network.testing.deployment-claims.json'
            dataset.write_text('{"rows":[{"name":"def:testing:fixture"}]}')
            rendered = root/'adr/017-claim-based-testing.md'
            rendered.write_text('| ``def:testing:fixture`` | scope only |\n')
            paths = [str(p.relative_to(root)) for p in (carrier,dataset,rendered)]
            with patch('build_graph.tracked', return_value=paths):
                self.assertEqual(tracker_elsewhere(root, unassigned), {})
                self.assertEqual(tracker_elsewhere(root, unassigned, classification=True), {'def:testing:fixture': sorted(paths)})
                self.assertEqual(tracker_elsewhere(root, unassigned, both=True), ({}, {'def:testing:fixture': sorted(paths)}))
                rendered.write_text(rendered.read_text()+'An independent mention: ``def:testing:fixture``.\n')
                self.assertEqual(tracker_elsewhere(root, unassigned), {'def:testing:fixture': [str(rendered.relative_to(root))]})
                self.assertEqual(tracker_elsewhere(root, unassigned, classification=True), {})
                self.assertEqual(tracker_elsewhere(root, unassigned, both=True), ({'def:testing:fixture': [str(rendered.relative_to(root))]}, {}))
        from claims import tracker_changes
        old = dict(category='statement', **carried)
        new = dict(old, records=['ROOT::alg:testing:other'], bites=[3])
        self.assertEqual(tracker_changes([old], [new], ('records', 'bites')),
                         [dict(label=old['label'], fields=dict(records=dict(before=old['records'], after=new['records']),
                                                             bites=dict(before=[2], after=[3])))])
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
        self.combined_members()
        data=fixture()
        self.assertEqual(evaluate(**data)['obligations'][0]['status'],'scoped-passed')
        data['results'][1]['outcome']='failed'
        result=evaluate(**data)
        self.assertEqual(result['claims'][0]['status'],'failed')
        self.assertEqual(result['obligations'][0]['status'],'failed')

    def combined_members(self):
        data = fixture()
        own = data['sites'][0]['claim']
        member = 'ROOT::claim:testing:member'
        data['sites'].append(dict(data['sites'][0], operation='member', claim=member))
        data['expected_sites'].add('member')
        data['results'].append(dict(data['results'][0], operation='member'))
        row = data['declared'][0]
        row['claims'].append(member)
        row['combined_claim'] = own
        data['paragraphs'][row['evidence_paragraph']]['citations'].add(member)
        self.assertTrue(all(r['status']=='passed' for r in evaluate(**data)['claims']))
        # A citation contributes evidence to the member but is not another mint.
        data['sites'].append(dict(data['sites'][-1], operation='citation', mint=False))
        data['expected_sites'].add('citation')
        data['results'].append(dict(data['results'][-1], operation='citation', outcome='failed'))
        result = evaluate(**data)
        self.assertTrue(all(r['status']=='failed' for r in result['claims']))
        self.assertEqual(result['obligations'][0]['status'], 'failed')
        self.assertEqual(next(r for r in result['claims'] if r['name']==own)['members'], [member])
        absent = deepcopy(data)
        absent['results'].pop()
        with self.assertRaisesRegex(StructuralError, 'missing test results'):
            evaluate(**absent)
        absent = deepcopy(data)
        absent['declared'][0]['claims'].append('ROOT::claim:testing:absent')
        with self.assertRaisesRegex(StructuralError, 'unresolved combined claim member'):
            evaluate(**absent)
        absent = deepcopy(data)
        absent['sites'][-2]['mint'] = False
        with self.assertRaisesRegex(StructuralError, 'unresolved or duplicate claim mint'):
            evaluate(**absent)
        cycle = deepcopy(data)
        cycle['declared'].append(dict(row, name='cycle', combined_claim=member))
        with self.assertRaisesRegex(StructuralError, 'cyclic combined claim members'):
            evaluate(**cycle)

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
        from claims import registrations
        from precheck import commands
        stages = dict(commands(Path('/prepared'), '/deployed/linter'))
        self.assertEqual(set(stages), {'census', 'deployment-claims', 'linter', 'claims', 'observations', 'datasets', 'documents'})
        self.assertEqual(stages['claims'][-2:], ['ci/claims.py', 'registration'])
        self.assertEqual(stages['linter'], ['/deployed/linter', 'check', '--root', '.'])
        self.assertEqual(stages['datasets'], ['/prepared/gate/documents', 'generate', '--check'])
        self.assertEqual(stages['documents'], ['/prepared/gate/documents', 'check'])
        self.prepared_checker_control()
        for level, label in (('unit', 'test:integration:fixture'), ('public-surface', 'test:unit:fixture')):
            control = fixture()
            control['sites'][0].update(path='packages/example/tests/public.rs', test_label=label)
            control['expected_sites'] = {name:dict(level=level) for name in control['expected_sites']}
            arguments = {key:control[key] for key in ('sites', 'expected_sites', 'areas', 'obligations', 'declared', 'paragraphs')}
            with self.assertRaisesRegex(StructuralError, 'public carrier mapping differs') as early:
                registrations(**arguments)
            with self.assertRaises(StructuralError) as full:
                evaluate(**control)
            self.assertEqual(str(early.exception), str(full.exception))
        for mutation in ('citation', 'site', 'area', 'obligation', 'edge'):
            control = fixture()
            if mutation == 'citation':
                control['paragraphs']['ROOT::amend:testing:fixture-evidence']['citations'].clear()
            elif mutation == 'site':
                control['expected_sites'].remove('sibling')
            elif mutation == 'area':
                control['areas'].clear()
            elif mutation == 'obligation':
                control['declared'].clear()
            else:
                control['declared'][0]['claims'] = ['ROOT::claim:testing:unknown']
            arguments = {key: control[key] for key in ('sites', 'expected_sites', 'areas', 'obligations', 'declared', 'paragraphs')}
            with self.assertRaises(StructuralError) as early:
                registrations(**arguments)
            with self.assertRaises(StructuralError) as full:
                evaluate(**control)
            self.assertEqual(str(early.exception), str(full.exception))
        data=fixture(); data['paragraphs']['ROOT::amend:testing:fixture-evidence']['citations']=set()
        with self.assertRaisesRegex(StructuralError,'uncited evidence'): evaluate(**data)
        data=fixture(); data['declared'][0].update(status='held',claims=[])
        with self.assertRaisesRegex(StructuralError,'hold lacks owner'): evaluate(**data)

    def prepared_checker_control(self):
        import subprocess
        import precheck
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root/'target'
            binary = target/'gate/documents'
            binary.parent.mkdir(parents=True)
            source = root/'checker.rs'
            source.write_text('checked source')
            binary.write_text('prepared executable')
            binary.with_suffix('.d').write_text(str(binary)+': '+str(source)+'\n')
            subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(root), 'add', 'checker.rs'], check=True, capture_output=True)
            original = precheck.prepared_state(root, target, 'documents')
            binding = binary.with_suffix('.prepared.json')
            binding.write_text(json.dumps(original))
            self.assertEqual(precheck.check_prepared(root, target, 'documents'), binary)
            for path, value in ((source, 'changed checker source'), (binary, 'different executable')):
                before = path.read_text()
                path.write_text(value)
                diagnostics = []
                for args in (['--only', 'datasets'], ['--run-checker', 'documents', '--', 'generate', '--check']):
                    output = io.StringIO()
                    with patch('sys.argv', ['ci/precheck.py', '--storage-locked', *args]), patch('isolation.storage_entry'), patch('precheck.Path.cwd', return_value=root), patch.dict(os.environ, CARGO_TARGET_DIR=str(target), LINTER_BIN='/fixture/linter'), patch('precheck.prepare_checker', return_value=binary), patch('precheck.subprocess.run', wraps=subprocess.run) as run, redirect_stderr(output), redirect_stdout(io.StringIO()):
                        self.assertEqual(precheck.main(), 2)
                    self.assertFalse(any(call.args[0][0] == str(binary) for call in run.call_args_list))
                    diagnostics.append(next(line for line in output.getvalue().splitlines() if line.startswith('CHECKER-STRUCTURAL-ERROR')))
                self.assertEqual(diagnostics[0], diagnostics[1])
                self.assertIn('sources or executable differ', diagnostics[0])
                path.write_text(before)
            self.assertEqual(precheck.check_prepared(root, target, 'documents'), binary)
            binding.unlink()
            with redirect_stderr(io.StringIO()), self.assertRaises(ValueError):
                precheck.check_prepared(root, target, 'documents')

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
        for paragraph in data['paragraphs'].values():
            paragraph.setdefault('text', '')
            paragraph.setdefault('path', 'docs/design/fixture.md')
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            previous=Path.cwd()
            stack.callback(os.chdir,previous)
            os.chdir(directory)
            for name in ('.lane','ci','docs/inputs'): Path(name).mkdir(parents=True,exist_ok=True)
            for name in ('design-inventory', 'implementation-bites', 'design-constants', 'design-bites'):
                Path('docs/inputs/'+name+'.toml').write_text('rows = []\n')
            for name,rows in (('claim-areas',data['areas']),('claim-obligations',data['declared'])):
                Path('docs/inputs/'+name+'.toml').write_text('\n'.join(
                    '[[rows]]\n'+'\n'.join(key+' = '+json.dumps(value) for key,value in row.items()) for row in rows))
            Path('Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            Path('ci/vendor-packages.toml').write_text('packages=[]\n')
            Path('.lane/performance-events.jsonl').write_text('\n'.join(json.dumps(r) for r in records)+'\n')
            Path('.lane/harness-benchmarks.jsonl').write_text('')
            Path('ci/claim_review.json').write_text(register_form('{"schema":1,"sites":[]}', 'sites')[2])
            Path('ci/claim_gloss_baseline.json').write_text(register_form(json.dumps({'schema':1,'glosses':{s['operation']:site_claim(s)['gloss'] for s in sites}}), 'glosses')[2])
            Path('.lane/observation-coverage.json').write_text('{"source":"current","mechanical_status":"passed"}')
            for name,value in (('load_registry',registry),('census',sites),
                               ('claim_mints',{}),('checked_linter',None),
                               ('prose',(data['paragraphs'],data['obligations'])),('source_id','current'),('tracker_selection_sites',[])):
                stack.enter_context(patch('claims.'+name,return_value=value))
            with redirect_stdout(io.StringIO()):
                with patch('wallet_cases.repository_check', return_value=None):
                    from claims import tracker_input
                    Path('docs/inputs/specification-progress.toml').write_text(tracker_input('.', dict(claims=[], obligations=[])))
                    self.assertEqual(main(['registration']), 0)
                    import precheck
                    with patch('sys.argv', ['ci/precheck.py', '--storage-locked', '--only', 'linter']), patch('isolation.storage_entry'), patch.dict(os.environ, {'LINTER_BIN': '/fixture/linter'}), patch('precheck.cancellable', return_value=SimpleNamespace(returncode=-15)):
                        self.assertEqual(precheck.main(), 143)

                    # Every static refusal is identical before and after the
                    # execution join; missing results cannot mask it anymore.
                    review_path = Path('ci/claim_review.json')
                    gloss_path = Path('ci/claim_gloss_baseline.json')
                    for fault in ('citation', 'review-form', 'gloss-site'):
                        original_review = review_path.read_text()
                        original_gloss = gloss_path.read_text()
                        original_citations = set(evidence['citations'])
                        if fault == 'citation':
                            evidence['citations'].remove('ROOT::gate:testing:fixture')
                        elif fault == 'review-form':
                            review_path.write_text(original_review+'\n')
                        else:
                            glossary = json.loads(original_gloss)
                            del glossary['glosses']['sibling']
                            gloss_path.write_text(register_form(json.dumps(glossary), 'glosses')[2])
                        early, full = io.StringIO(), io.StringIO()
                        with redirect_stderr(early):
                            self.assertEqual(main(['registration']), 2)
                        with redirect_stderr(full):
                            self.assertEqual(main([]), 2)
                        self.assertEqual(early.getvalue(), full.getvalue())
                        evidence['citations'] = original_citations
                        review_path.write_text(original_review)
                        gloss_path.write_text(original_gloss)
                    self.assertEqual(main([]),0)
                    self.assertEqual(main(['--fail-respellings']),1)
                    self.assertEqual(main(['tracker']), 0)
                    carrier = Path('docs/inputs/specification-progress.toml')
                    original = carrier.read_text()
                    carrier.write_text(original+'\n')
                    with redirect_stderr(io.StringIO()), patch('claims.tracker_artifacts') as artifacts:
                        self.assertEqual(main([]), 2)
                        artifacts.assert_called_once_with(Path('.'), original)
                    self.assertTrue(Path('.lane/specification-tracker-moved.json').is_file())
                    self.assertEqual(main(['tracker']), 0)
                    self.assertEqual(carrier.read_text(), original)
                    from claims import tracker_structure
                    tracker_structure(Path('.'))
                    carrier.write_text('rows = [{ category = "statement", label = "def:testing:removed", records = ["ROOT::alg:testing:fixture"], bites = [1] }]\n')
                    with self.assertRaisesRegex(StructuralError, 'records or bites are stale'):
                        tracker_structure(Path('.'))
                    moved = json.loads(Path('.lane/specification-tracker-structure.json').read_text())
                    self.assertEqual(moved['evidence'], 'structural-only')
                    self.assertEqual(moved['changes'][0]['label'], 'def:testing:removed')
                    carrier.write_text(original)
                    execution = Path('.lane/claim-evidence.json')
                    stale = json.loads(execution.read_text())
                    stale['source'] = 'previous'
                    execution.write_text(json.dumps(stale))
                    with redirect_stderr(io.StringIO()):
                        self.assertEqual(main(['tracker']), 2)
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

        from claims import REVIEW_RECIPE, tracker_witnesses, tracker_rows, witness_currency
        from devperf import case_identity
        from hash_citations import establish
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = 'def probe():\n    """Unchanged claim text."""\n    assert 1 == 1\n'
            path = root/'case.py'
            path.write_text(source)
            for args in (['init', '-q'], ['add', '.'], ['-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                         '-c', 'commit.gpgsign=false', 'commit', '-qm', 'reviewed assertions']):
                subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
            public = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
            label = 'def:testing:fixture'
            claim = 'ROOT::claim:testing:fixture'
            reviewed = dict(operation='probe', path='case.py', claim=claim, before='', after='Unchanged claim text.', review='Read assertions.',
                            paper_witnesses={label: 'The equality assertion detects the wrong result.'},
                            witness_identity=dict(recipe=REVIEW_RECIPE, function='probe', digest=case_identity(source, 'case.py', 'probe')))
            register = root/'ci/claim_review.json'
            register.parent.mkdir()
            inventory = root/'docs/inputs/design-inventory.toml'
            inventory.parent.mkdir(parents=True)
            inventory.write_text('[[rows]]\nlabel = "'+label+'"\n')
            sites = [dict(operation='probe', path='case.py', claim=claim, gloss=reviewed['after'])]
            def save():
                register.write_text(register_form(json.dumps(dict(schema=1, sites=[reviewed])), 'sites')[2])
            family = dict(reader='assertion-reviews', establishment='recomputable', source='ci/claim_review.json', paths=['ci/claim_review.json'])
            save()
            check = establish(root, family)
            digest = reviewed['witness_identity']['digest']
            self.assertTrue(check(digest, '        "digest": "'+digest+'"'))
            self.assertFalse(check(digest, '        "review": "'+digest+'"'))
            self.assertTrue(witness_currency(root, reviewed))
            self.assertTrue(tracker_witnesses(root, sites)[claim][label])
            path.write_text(source.replace('assert 1 == 1', 'assert 1 == 2'))
            with self.assertRaisesRegex(StructuralError, 'unrecomputable'):
                establish(root, family)
            reviewed['witness_identity']['public_commit'] = public
            save()
            self.assertFalse(witness_currency(root, reviewed))
            self.assertTrue(establish(root, family)(digest, '        "digest": "'+digest+'"'))
            witnesses = tracker_witnesses(root, sites)
            self.assertIsNone(witnesses[claim][label])
            obligation = 'ROOT::dec:testing:fixture'
            data = dict(claims=[dict(name=claim, status='passed')], obligations=[dict(name=obligation,
                        claims=[claim], status='scoped-passed', witnessed_labels=[label])])
            records = {obligation: dict(text='``'+label+'``', citations=set())}
            self.assertEqual(tracker_rows([dict(label=label, crate='fixture', kind='def')], records, data, [], witnesses=witnesses)[0]['status'], 'designed')
            path.write_text(source)
            self.assertEqual(tracker_rows([dict(label=label, crate='fixture', kind='def')], records, data, [],
                             witnesses=tracker_witnesses(root, sites))[0]['status'], 'realized')
            for key, value in (('recipe', 'unknown'), ('function', 'other'), ('digest', 'bad'), ('extra', 'ignored')):
                invalid = deepcopy(reviewed)
                invalid['witness_identity'][key] = value
                with self.assertRaises(StructuralError):
                    witness_currency(root, invalid)
            invalid = deepcopy(reviewed)
            invalid['witness_identity']['digest'] = 'b'*64
            with self.assertRaisesRegex(StructuralError, 'unrecomputable'):
                witness_currency(root, invalid)
            with self.assertRaisesRegex(ValueError, 'exact register path'):
                establish(root, family | dict(paths=['other.json']))

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
